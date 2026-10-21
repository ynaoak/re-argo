
use reargo_core::pcode::OpCode;

use crate::ssa::SsaFunction;

const CONST_SPACE: reargo_core::address::SpaceId = reargo_core::address::SpaceId::CONST;

/// Rewrite `func.ops[i]` if every input is a constant. Returns true
/// if the op was folded into a `Copy const`. Pulled out of
/// `constant_fold` so the fused walk in `const_alg_strength` can
/// share it.
fn try_constant_fold_op(func: &mut SsaFunction, i: usize) -> bool {
    if func.ops[i].inputs.is_empty() {
        return false;
    }
    let all_const = func.ops[i]
        .inputs
        .iter()
        .all(|&id| func.varnodes[id as usize].data.space == CONST_SPACE);
    if !all_const {
        return false;
    }

    let inputs = &func.ops[i].inputs;
    let result = match func.ops[i].opcode {
        OpCode::IntAdd => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a.wrapping_add(b))
        }
        OpCode::IntSub => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a.wrapping_sub(b))
        }
        OpCode::IntAnd => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a & b)
        }
        OpCode::IntOr => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a | b)
        }
        OpCode::IntXor => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a ^ b)
        }
        OpCode::IntEqual => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(if a == b { 1 } else { 0 })
        }
        OpCode::IntMult => {
            if inputs.len() < 2 { return false; }
            let a = func.varnodes[inputs[0] as usize].data.offset;
            let b = func.varnodes[inputs[1] as usize].data.offset;
            Some(a.wrapping_mul(b))
        }
        // WS83: `mov edi, 5` writes `rdi = zext(edi)`; folded, the argument reads `5`
        OpCode::IntZExt | OpCode::IntSExt => {
            let v = &func.varnodes[inputs[0] as usize].data;
            let bits = v.size * 8;
            let a = if bits >= 64 { v.offset } else { v.offset & ((1u64 << bits) - 1) };
            Some(if func.ops[i].opcode == OpCode::IntSExt && bits < 64 && a >> (bits - 1) & 1 == 1 { a | !((1u64 << bits) - 1) } else { a })
        }
        // the upper half of a zero-extended constant (`xmm1 = 0; … (uint64_t)(xmm1 >> 64)`);
        // a constant holds at most 64 bits
        OpCode::Subpiece if inputs.len() == 2 => {
            let v = func.varnodes[inputs[0] as usize].data.offset;
            let k = func.varnodes[inputs[1] as usize].data.offset;
            Some(if k >= 8 { 0 } else { v >> (k * 8) })
        }
        _ => None,
    };

    let Some(val) = result else { return false; };
    let out_id = func.ops[i].output.unwrap();
    let out_size = func.varnodes[out_id as usize].data.size;
    let masked = if out_size >= 8 {
        val
    } else {
        val & ((1u64 << (out_size * 8)) - 1)
    };
    let const_id = func.varnodes.len() as u32;
    func.varnodes.push(crate::ssa::SsaVarnode {
        id: const_id,
        data: reargo_core::pcode::VarnodeData::new(CONST_SPACE, masked, out_size),
        version: 0,
        def_op: None,
        uses: smallvec::smallvec![i],
    });
    func.ops[i].opcode = OpCode::Copy;
    func.ops[i].inputs = smallvec::smallvec![const_id];
    true
}

/// Apply identity-style rewrites to `func.ops[i]` (`x+0=x`, `x*1=x`,
/// `x*0=0`, `x&0=0`, `x|0=x`, `x-x=0`, `x^x=0`). Returns true on
/// rewrite. Extracted from `algebraic_simplification` for fusion.
fn try_algebraic_simplify_op(func: &mut SsaFunction, i: usize) -> bool {
    if func.ops[i].inputs.len() < 2 {
        return false;
    }
    let in0 = func.ops[i].inputs[0];
    let in1 = func.ops[i].inputs[1];

    let rewrite_to_zero = |func: &mut SsaFunction, i: usize| {
        let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
        let zero_id = func.varnodes.len() as u32;
        func.varnodes.push(crate::ssa::SsaVarnode {
            id: zero_id,
            data: reargo_core::pcode::VarnodeData::new(CONST_SPACE, 0, out_size),
            version: 0,
            def_op: None,
            uses: smallvec::smallvec![i],
        });
        func.ops[i].opcode = OpCode::Copy;
        func.ops[i].inputs = smallvec::smallvec![zero_id];
    };

    match func.ops[i].opcode {
        OpCode::IntSub | OpCode::IntXor if in0 == in1 => {
            rewrite_to_zero(func, i);
            true
        }
        OpCode::IntAdd | OpCode::IntOr => {
            for side in 0..2 {
                let id = if side == 0 { in0 } else { in1 };
                let vn = &func.varnodes[id as usize];
                if vn.data.space == CONST_SPACE && vn.data.offset == 0 {
                    let keep = func.ops[i].inputs[1 - side];
                    func.ops[i].opcode = OpCode::Copy;
                    func.ops[i].inputs = smallvec::smallvec![keep];
                    return true;
                }
            }
            false
        }
        OpCode::IntMult => {
            for side in 0..2 {
                let id = if side == 0 { in0 } else { in1 };
                let vn = &func.varnodes[id as usize];
                if vn.data.space == CONST_SPACE {
                    if vn.data.offset == 1 {
                        let keep = func.ops[i].inputs[1 - side];
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = smallvec::smallvec![keep];
                        return true;
                    } else if vn.data.offset == 0 {
                        rewrite_to_zero(func, i);
                        return true;
                    }
                }
            }
            false
        }
        OpCode::IntAnd => {
            for side in 0..2 {
                let id = if side == 0 { in0 } else { in1 };
                let vn = &func.varnodes[id as usize];
                if vn.data.space == CONST_SPACE && vn.data.offset == 0 {
                    rewrite_to_zero(func, i);
                    return true;
                }
            }
            false
        }
        // the low part of a zero / sign extension as wide as what was extended is that value:
        // `movzx eax, byte [rdi]; test al, al` reads the loaded byte (`al = (uint8_t)eax;`
        // before). Only when the extension's value is a temporary read here alone, so the
        // extension dies and the value is still read once (WS99).
        OpCode::Subpiece => {
            let (Some(out), ext) = (func.ops[i].output, func.varnodes[in0 as usize].def_op) else { return false };
            let Some(e) = ext else { return false };
            let k = &func.varnodes[in1 as usize];
            if k.data.space != CONST_SPACE || k.data.offset != 0 {
                return false;
            }
            let eop = &func.ops[e];
            if eop.dead || !matches!(eop.opcode, OpCode::IntZExt | OpCode::IntSExt) || eop.inputs.len() != 1 {
                return false;
            }
            let x = eop.inputs[0];
            let xd = func.varnodes[x as usize].data;
            if xd.space != reargo_core::address::SpaceId::UNIQUE
                || xd.size != func.varnodes[out as usize].data.size
                || func.varnodes[in0 as usize].uses.iter().any(|&u| u != i && !func.ops[u].dead)
            {
                return false;
            }
            func.varnodes[in0 as usize].uses.clear();
            func.varnodes[x as usize].uses.push(i);
            func.ops[i].opcode = OpCode::Copy;
            func.ops[i].inputs = smallvec::smallvec![x];
            true
        }
        _ => false,
    }
}

/// Convert `IntMult x, p2_const` / `IntDiv x, p2_const` into a left
/// or right shift. Returns true on rewrite. Extracted from
/// `strength_reduction` for fusion.
fn try_strength_reduce_op(func: &mut SsaFunction, i: usize) -> bool {
    match func.ops[i].opcode {
        OpCode::IntMult => {
            if func.ops[i].inputs.len() < 2 { return false; }
            for side in 0..2 {
                let other = 1 - side;
                let id = func.ops[i].inputs[side];
                let vn = &func.varnodes[id as usize];
                if vn.data.space != CONST_SPACE { continue; }
                let val = vn.data.offset;
                if val != 0 && val.is_power_of_two() {
                    let shift_amt = val.trailing_zeros() as u64;
                    let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                    let shift_id = func.varnodes.len() as u32;
                    func.varnodes.push(crate::ssa::SsaVarnode {
                        id: shift_id,
                        data: reargo_core::pcode::VarnodeData::new(CONST_SPACE, shift_amt, out_size),
                        version: 0,
                        def_op: None,
                        uses: smallvec::smallvec![i],
                    });
                    let kept = func.ops[i].inputs[other];
                    func.ops[i].opcode = OpCode::IntLeft;
                    func.ops[i].inputs = smallvec::smallvec![kept, shift_id];
                    return true;
                }
            }
            false
        }
        OpCode::IntDiv => {
            if func.ops[i].inputs.len() < 2 { return false; }
            let id = func.ops[i].inputs[1];
            let vn = &func.varnodes[id as usize];
            if vn.data.space != CONST_SPACE { return false; }
            let val = vn.data.offset;
            if val == 0 || !val.is_power_of_two() { return false; }
            let shift_amt = val.trailing_zeros() as u64;
            let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
            let shift_id = func.varnodes.len() as u32;
            func.varnodes.push(crate::ssa::SsaVarnode {
                id: shift_id,
                data: reargo_core::pcode::VarnodeData::new(CONST_SPACE, shift_amt, out_size),
                version: 0,
                def_op: None,
                uses: smallvec::smallvec![i],
            });
            let dividend = func.ops[i].inputs[0];
            func.ops[i].opcode = OpCode::IntRight;
            func.ops[i].inputs = smallvec::smallvec![dividend, shift_id];
            true
        }
        _ => false,
    }
}

/// Fused walk that runs constant-fold, algebraic-simplify, and
/// strength-reduce in priority order on every op in a single pass.
///
/// The three were previously three separate `for i in 0..ops.len()`
/// walks; each iteration of the outer optimizer fixpoint scanned the
/// op array three times. Since each rewrite changes the op's opcode
/// away from the next pass's matchable set (a folded op becomes
/// `Copy`, an algebraic identity becomes `Copy`, a strength-reduced
/// op becomes `IntLeft/Right`), it's safe to try them in sequence on
/// each op: on rewrite, the next pass's predicate won't match anyway.
///
/// Returns `(folded, simplified, reduced)` so the outer fixpoint can
/// still update its per-pass counters.
pub fn const_alg_strength(func: &mut SsaFunction) -> (usize, usize, usize) {
    const_alg_strength_in(func, None)
}

/// [`const_alg_strength`], marking in `changed` the block of each op it rewrites (an op's
/// rewrite changes that op alone: its opcode and inputs).
fn const_alg_strength_in(func: &mut SsaFunction, mut changed: Option<&mut [bool]>) -> (usize, usize, usize) {
    let mut mark = |func: &SsaFunction, i: usize| {
        if let Some(c) = changed.as_deref_mut() {
            c[func.ops[i].block] = true;
        }
    };
    let (mut folded, mut simplified, mut reduced) = (0usize, 0usize, 0usize);
    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }
        // (the opcodes one of the three rewrites)
        if !matches!(
            func.ops[i].opcode,
            OpCode::IntAdd
                | OpCode::IntSub
                | OpCode::IntAnd
                | OpCode::IntOr
                | OpCode::IntXor
                | OpCode::IntEqual
                | OpCode::IntMult
                | OpCode::IntZExt
                | OpCode::IntSExt
                | OpCode::Subpiece
                | OpCode::IntDiv
        ) {
            continue;
        }
        if try_constant_fold_op(func, i) {
            folded += 1;
            mark(func, i);
            continue;
        }
        if try_algebraic_simplify_op(func, i) {
            simplified += 1;
            mark(func, i);
            continue;
        }
        if try_strength_reduce_op(func, i) {
            reduced += 1;
            mark(func, i);
        }
    }
    (folded, simplified, reduced)
}

fn is_side_effecting(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Call
            | OpCode::CallInd
            | OpCode::CallOther
            | OpCode::Store
            | OpCode::Return
            | OpCode::Branch
            | OpCode::CBranch
            | OpCode::BranchInd
    )
}

/// Worklist-driven dead-code elimination.
///
/// The previous implementation ran an outer `while changed` fixpoint
/// over a full N-op scan. For deeply-cascading dead chains (an
/// algebraic-simplification pass tends to produce long ones) it
/// re-scanned the whole op array once per chain link, costing
/// O(N * depth).
///
/// A worklist visits each op O(1) times on average:
///   1. Seed the queue with every candidate op (live, has output,
///      not side-effecting).
///   2. Pop one; if all its uses are dead, mark it dead and enqueue
///      the *defining* ops of its inputs -- they just lost a use and
///      may have become dead themselves.
///   3. Terminate when the queue drains.
///
/// Total work is O(N + dead_ops) instead of O(N * depth), and the
/// observable behaviour (set of dead ops, count returned) is
/// identical to the fixpoint version.
pub fn dead_code_elimination(func: &mut SsaFunction) -> usize {
    // (the definitions left out would be removed here: no longer writes of their slots)
    func.phantom_writes.clear();
    let n = func.ops.len();
    let candidate = |o: &crate::ssa::SsaOp| !o.dead && o.output.is_some() && !is_side_effecting(o.opcode);
    // The queue starts with every candidate in index order and takes the defining ops of a
    // dead op's inputs at its end: the candidates are visited in one sweep first (`i`, each
    // one still queued while the sweep has not reached it), then the ops queued again, in
    // order (`queue[head..]`, those of them `on_queue`).
    let mut on_queue = vec![false; n];
    let mut queue: Vec<usize> = Vec::new();
    let mut head = 0usize;
    let mut removed = 0;
    let mut sweep = 0usize;
    // (for the phi cycles below: the live ops with side effects or no output, which this loop
    // never kills, and how many phis live)
    let mut roots: Vec<usize> = Vec::new();
    let mut live_phis = 0usize;
    let mut dead_before = 0usize;
    loop {
        let i = if sweep < n {
            let i = sweep;
            sweep += 1;
            let o = &func.ops[i];
            if !candidate(o) {
                if !o.dead {
                    roots.push(i);
                } else {
                    dead_before += 1;
                }
                continue;
            }
            live_phis += usize::from(o.opcode == OpCode::MultiEqual);
            i
        } else if head < queue.len() {
            let i = queue[head];
            head += 1;
            on_queue[i] = false;
            if func.ops[i].dead {
                continue;
            }
            i
        } else {
            break;
        };

        let out_id = func.ops[i].output.expect("output checked above");
        let has_live_use = func.varnodes[out_id as usize]
            .uses
            .iter()
            .any(|&use_idx| !func.ops[use_idx].dead);

        if has_live_use {
            continue;
        }

        func.ops[i].dead = true;
        removed += 1;
        live_phis -= usize::from(func.ops[i].opcode == OpCode::MultiEqual);

        // The newly-dead op's inputs each just lost a use. Re-queue
        // the defining op of any input that itself is a DCE
        // candidate -- it may now have no live uses either.
        // (a candidate the sweep has not reached yet is still queued)
        let (ops, varnodes) = (&func.ops, &func.varnodes);
        for &inp_id in &ops[i].inputs {
            if let Some(def_idx) = varnodes[inp_id as usize].def_op
                && candidate(&ops[def_idx])
                && def_idx < sweep
                && !on_queue[def_idx]
            {
                queue.push(def_idx);
                on_queue[def_idx] = true;
            }
        }
    }

    // Cycles through phi nodes (a loop counter nothing outside the loop
    // reads) keep each other "used" above. Mark what the side-effecting ops
    // actually need and drop the rest.
    if live_phis > 0 {
        let mut stack = roots;
        let mut live = vec![false; n];
        for &i in &stack {
            live[i] = true;
        }
        let mut marked = stack.len();
        while let Some(i) = stack.pop() {
            for &inp in &func.ops[i].inputs {
                if let Some(d) = func.varnodes[inp as usize].def_op
                    && !live[d]
                    && !func.ops[d].dead
                {
                    live[d] = true;
                    marked += 1;
                    stack.push(d);
                }
            }
        }
        // (every op living marked: none to drop)
        let living = n - dead_before - removed;
        for (i, alive) in live.iter().enumerate().take(if marked < living { n } else { 0 }) {
            if !alive && !func.ops[i].dead {
                func.ops[i].dead = true;
                removed += 1;
            }
        }
    }

    removed
}

pub fn constant_fold(func: &mut SsaFunction) -> usize {
    let mut folded = 0;
    for i in 0..func.ops.len() {
        if !func.ops[i].dead && func.ops[i].output.is_some() && try_constant_fold_op(func, i) {
            folded += 1;
        }
    }
    folded
}

pub fn copy_propagation(func: &mut SsaFunction) -> usize {
    copy_propagation_in(func, None)
}

/// [`copy_propagation`], marking in `changed` the block of each op whose inputs it rewrites.
fn copy_propagation_in(func: &mut SsaFunction, mut changed: Option<&mut [bool]>) -> usize {
    let mut propagated = 0;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].opcode != OpCode::Copy {
            continue;
        }
        if func.ops[i].output.is_none() || func.ops[i].inputs.is_empty() {
            continue;
        }

        let out_id = func.ops[i].output.expect("output checked above");
        let src_id = func.ops[i].inputs[0];

        let src_is_const =
            func.varnodes[src_id as usize].data.space == reargo_core::address::SpaceId::CONST;
        if !src_is_const {
            continue;
        }

        // Iterate the uses list by index instead of cloning it. The
        // inner block needs `&mut func.ops[use_idx]` which conflicts
        // with holding `&func.varnodes[out_id].uses`; re-indexing
        // `uses[k]` on every step releases the immutable borrow
        // each time and saves one heap allocation per Copy-const op.
        let uses_len = func.varnodes[out_id as usize].uses.len();
        for k in 0..uses_len {
            let use_idx = func.varnodes[out_id as usize].uses[k];
            // A phi operand names the register on its edge; replacing it would
            // leave the copy without a use and drop the assignment from the output.
            if func.ops[use_idx].dead || func.ops[use_idx].opcode == OpCode::MultiEqual {
                continue;
            }
            let op = &mut func.ops[use_idx];
            for inp in &mut op.inputs {
                if *inp == out_id {
                    *inp = src_id;
                    propagated += 1;
                    if let Some(c) = changed.as_deref_mut() {
                        c[op.block] = true;
                    }
                }
            }
        }
        // the readers rewritten no longer read the copy (WS83): dead code elimination can
        // drop it once nothing else does
        let ops = &func.ops;
        func.varnodes[out_id as usize].uses.retain(|&mut u| ops[u].dead || ops[u].inputs.contains(&out_id));
    }
    propagated
}

/// SSA value identity: the simplified SSA allocates a fresh varnode per read,
/// so the same value is correlated by (space, offset, size, version).
type ValueKey = (u32, u64, u32, u32);

fn value_key(func: &SsaFunction, var_id: u32) -> ValueKey {
    let vn = &func.varnodes[var_id as usize];
    (vn.data.space.0, vn.data.offset, vn.data.size, vn.version)
}

fn is_cse_pure(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult
            | OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor
            | OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight
            | OpCode::IntNegate | OpCode::Int2Comp
            | OpCode::IntEqual | OpCode::IntNotEqual
            | OpCode::IntLess | OpCode::IntLessEqual
            | OpCode::IntSLess | OpCode::IntSLessEqual
            | OpCode::IntZExt | OpCode::IntSExt
            | OpCode::IntDiv | OpCode::IntSDiv | OpCode::IntRem | OpCode::IntSRem
    )
}

fn is_commutative(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::IntAdd | OpCode::IntMult | OpCode::IntAnd
            | OpCode::IntOr | OpCode::IntXor
            | OpCode::IntEqual | OpCode::IntNotEqual
    )
}

/// One of 64 bits for a value key: a filter of a few keys that most others miss.
fn key_bit(k: ValueKey) -> u64 {
    // (offsets step by 8 / 0x10; the version tells a slot's values apart)
    1u64 << (((k.1 >> 3) ^ (k.1 >> 9) ^ u64::from(k.3)) & 63)
}

/// Follow a chain of redirects to the canonical target. Caps the
/// chain length defensively so a cyclic redirect map (which the CSE
/// loop is structured not to produce) can't loop forever.
fn resolve_redirect(
    redirects: &rustc_hash::FxHashMap<ValueKey, ValueKey>,
    mut k: ValueKey,
) -> ValueKey {
    let mut steps = 0;
    while let Some(&next) = redirects.get(&k) {
        if next == k || steps > 64 {
            break;
        }
        k = next;
        steps += 1;
    }
    k
}

/// Local common subexpression elimination.
///
/// Within each basic block, a pure op that recomputes a value already produced
/// by an earlier pure op (same opcode and inputs by value identity) is removed,
/// and its uses are redirected to the earlier result. Restricting to a single
/// block keeps the rewrite safe without dominator analysis.
///
/// Previously each CSE hit called `redirect_value`, which linearly scanned
/// every varnode in the function and rewrote any matching one. For a
/// function with N CSE eliminations and V varnodes that was O(N*V).
/// We now collect the redirects into a BTreeMap during the loop and
/// apply them in a single linear pass over varnodes at the end --
/// O(N + V). Subsequent ops in the same pass consult the in-progress
/// redirect map via `resolve_redirect` so cascading eliminations
/// (the result of one CSE feeding into another) still fire.
pub fn common_subexpression_elimination(func: &mut SsaFunction) -> usize {
    cse_with_hits(func).0
}

/// [`common_subexpression_elimination`], with how many ops matched an earlier one's key (each
/// removed or kept): with none, the pass changed nothing and finds nothing again until an op's
/// opcode or inputs change.
fn cse_with_hits(func: &mut SsaFunction) -> (usize, usize) {
    cse_in_blocks(func, None, None)
}

/// [`cse_with_hits`] looking only at the ops of the blocks `scan` marks (all for `None`), and
/// marking in `rescan` the blocks the next pass has to look at (when it runs after only
/// [`dead_code_elimination`], or after rewrites whose blocks are marked too).
///
/// A pass finds a match only within a block (the block is part of the key), and an op's key
/// is that of its opcode and inputs' values. So after a pass, a block can only have matches
/// in a later pass if it had one in this pass (removed or kept) or an op of it has another key
/// by then: one reading a value this pass redirected (its varnode is renamed at the end, and
/// a reader later in this same pass already reads it redirected: its block is looked at from
/// then on, every op of it — a block's ops follow each other, after the redirecting op) or one
/// a fold / copy propagation rewrote. Dead code elimination only kills ops: the live ops left
/// in a block without a match have distinct keys still. The ops of the other blocks add only
/// their own blocks' keys and nothing else (the checks of a match read the whole function
/// themselves), so the pass removes, keeps and counts exactly what the whole pass would.
fn cse_in_blocks(func: &mut SsaFunction, scan: Option<&[bool]>, mut rescan: Option<&mut [bool]>) -> (usize, usize) {
    // (grows with the readers of the values redirected)
    let mut scan: Option<Vec<bool>> = scan.map(<[bool]>::to_vec);
    let mut hits = 0;
    use smallvec::SmallVec;
    let mut eliminated = 0;
    // Pre-size both hash maps. Without this they started at zero
    // capacity and rehashed N/4 -> N/2 -> N as ops were inserted.
    // For a ~1000-op function CSE typically inserts a few hundred
    // pure ops into `seen`; oversizing to N/2 lands snug and avoids
    // the per-rehash copy of every existing entry.
    let approx = func.ops.len() / 2 + 16;
    // The CSE key holds an input-key vector. Most P-code ops have
    // 1-3 inputs (lifters use SmallVec<[VarnodeData; 3]> on the
    // upstream side), so a `SmallVec<[ValueKey; 3]>` inline-stores
    // the entire key for the typical case and skips the heap alloc
    // that a plain `Vec<ValueKey>` paid for every candidate op.
    type InKeys = SmallVec<[ValueKey; 3]>;
    // The key includes the output size: ZEXT(x:4)->8 and ZEXT(x:4)->16 have
    // identical opcode+inputs but are different values; merging them
    // redirected a 16-byte XMM use to the 8-byte view.
    // (the opcode itself: its names are distinct)
    // (the ops with at most two inputs — every pure op of the lifters — by a key of fixed size,
    // the unused input left at its default: no key of the other map is equal to one of these)
    let mut seen: rustc_hash::FxHashMap<(u32, OpCode, u32, u8, [ValueKey; 2]), ValueKey> =
        rustc_hash::FxHashMap::with_capacity_and_hasher(approx, Default::default());
    let mut seen_wide: rustc_hash::FxHashMap<(usize, OpCode, u32, InKeys), ValueKey> = Default::default();
    let mut redirects: rustc_hash::FxHashMap<ValueKey, ValueKey> =
        rustc_hash::FxHashMap::with_capacity_and_hasher(approx / 2, Default::default());

    // The C output names a value by its register / temporary, not its SSA
    // version, so a use may only be redirected to an earlier value whose slot
    // has not been written since: `tmp_600 = rsp + 0xc; ...; tmp_600 = rsp + 4;
    // ...; load [rsp + 0xc]` printed the last load as `*(tmp_600)` = rsp + 4.
    // The version a slot holds before op `i`: that of the last live op before it writing the
    // slot (0 when none). Asked only of the slots of the duplicates found: each one's writers
    // are scanned forward as the loop goes (`(scanned up to, version)`). (An op before `i`
    // keeps its dead flag from here on: only the op visited dies.)
    // (`(scanned up to, version, its position)`; the definitions left out by the pipeline
    // write their slots too, at their positions: `SsaFunction::phantom_writes`)
    let mut latest: rustc_hash::FxHashMap<(u32, u64, u32), (usize, u32, usize)> = Default::default();
    let phantom_writes = std::mem::take(&mut func.phantom_writes);
    let phantom_regs = std::mem::take(&mut func.phantom_regs);
    let phantom_reg = |slot: &(u32, u64, u32)| if phantom_writes.is_empty() { None } else { phantom_regs.iter().position(|s| s == slot) };
    // (whether a write left out of `slot` is in `(lo, hi)`)
    let phantom_between = |slot: &(u32, u64, u32), lo: usize, hi: usize| {
        phantom_reg(slot).is_some_and(|r| {
            phantom_writes[phantom_writes.partition_point(|w| w.0 <= lo)..].iter().take_while(|w| w.0 < hi).any(|w| w.1 >> r & 1 != 0)
        })
    };
    let version_before = |func: &SsaFunction, latest: &mut rustc_hash::FxHashMap<(u32, u64, u32), (usize, u32, usize)>, slot: (u32, u64, u32), i: usize| {
        let e = latest.entry(slot).or_insert((0, 0, 0));
        for (k, op) in func.ops[e.0.min(i)..i].iter().enumerate() {
            if let Some(o) = op.output
                && !op.dead
            {
                let vn = &func.varnodes[o as usize];
                if (vn.data.space.0, vn.data.offset, vn.data.size) == slot {
                    e.1 = vn.version;
                    e.2 = 4 * (e.0.min(i) + k) + 2;
                }
            }
        }
        e.0 = e.0.max(i);
        // a write left out after the last op writing the slot: a version no op made
        match phantom_reg(&slot) {
            Some(r) if phantom_writes[..phantom_writes.partition_point(|w| w.0 < 4 * i + 2)].iter().rev().take_while(|w| w.0 > e.2).any(|w| w.1 >> r & 1 != 0) => u32::MAX,
            _ => e.1,
        }
    };
    // WS84: ... and still holds it at every reader of the removed value, not only where the
    // duplicate is (`rax = rdi + 12; rbx = rdi + 12; rax = 5; rcx = rbx + 1` read `rax` for
    // `rbx`). The readers of each value, and how many live ops write each slot.
    // (built when a duplicate is first found: no op has died in this pass yet then, and most
    // passes find none)
    type Readers = crate::condition::Readers;
    type Writers = rustc_hash::FxHashMap<(u32, u64, u32), u32>;
    let build = |func: &SsaFunction| -> (Readers, Writers) {
        // (a constant is never a duplicate's value: not listed)
        let readers = crate::condition::Readers::build(func);
        // (sized once from the live ops)
        let live = func.ops.iter().filter(|o| !o.dead).count();
        let mut writers: Writers = rustc_hash::FxHashMap::with_capacity_and_hasher(live / 2, Default::default());
        for op in &func.ops {
            if op.dead {
                continue;
            }
            if let Some(o) = op.output {
                let d = &func.varnodes[o as usize].data;
                *writers.entry((d.space.0, d.offset, d.size)).or_default() += 1;
            }
        }
        for &(_, regs) in &phantom_writes {
            let mut m = regs;
            while m != 0 {
                let r = m.trailing_zeros() as usize;
                m &= m - 1;
                *writers.entry(phantom_regs[r]).or_default() += 1;
            }
        }
        (readers, writers)
    };
    let mut maps: Option<(Readers, Writers)> = None;
    // the slot of `existing` is not written after op `i` before any reader of `dup`: a reader
    // later in the block is checked op by op; one elsewhere (another block, or back around a
    // loop) needs `existing` to be the slot's only definition (the block runs it, then the
    // duplicate, without leaving)
    let holds_at_readers = |func: &SsaFunction, (readers, writers): &(Readers, Writers), i: usize, dup: ValueKey, existing: ValueKey| {
        let slot = (existing.0, existing.1, existing.2);
        let writes_slot = |o: &crate::ssa::SsaOp| {
            !o.dead
                && o.output.is_some_and(|w| {
                    let d = &func.varnodes[w as usize].data;
                    (d.space.0, d.offset, d.size) == slot
                })
        };
        readers.of_key(&dup).iter().all(|&r| {
            let ro = &func.ops[r];
            if ro.dead {
                return true;
            }
            if ro.block == func.ops[i].block && r > i {
                !func.ops[i + 1..r].iter().any(writes_slot) && !phantom_between(&slot, 4 * i + 2, 4 * r + 2)
            } else {
                writers.get(&slot).copied().unwrap_or(0) <= 1
            }
        })
    };
    for i in 0..func.ops.len() {
        if func.ops[i].dead || scan.as_ref().is_some_and(|s| !s[func.ops[i].block]) {
            continue;
        }
        let opcode = func.ops[i].opcode;
        if !is_cse_pure(opcode) || func.ops[i].inputs.is_empty() {
            continue;
        }
        let Some(out_id) = func.ops[i].output else { continue };

        let out_size = func.varnodes[out_id as usize].data.size;
        let out_key = resolve_redirect(&redirects, value_key(func, out_id));
        let n_in = func.ops[i].inputs.len();
        let (slot, existing) = if n_in <= 2 {
            let mut in_keys = [(0u32, 0u64, 0u32, 0u32); 2];
            for (j, &id) in func.ops[i].inputs.iter().enumerate() {
                in_keys[j] = resolve_redirect(&redirects, value_key(func, id));
            }
            if is_commutative(opcode) && n_in == 2 && in_keys[1] < in_keys[0] {
                in_keys.swap(0, 1);
            }
            let block = u32::try_from(func.ops[i].block).expect("block id");
            match seen.entry((block, opcode, out_size, n_in as u8, in_keys)) {
                std::collections::hash_map::Entry::Occupied(o) => {
                    let e = *o.get();
                    (o.into_mut(), Some(e))
                }
                std::collections::hash_map::Entry::Vacant(v) => (v.insert(out_key), None),
            }
        } else {
            let mut in_keys: InKeys = func.ops[i]
                .inputs
                .iter()
                .map(|&id| resolve_redirect(&redirects, value_key(func, id)))
                .collect();
            if is_commutative(opcode) {
                in_keys.sort();
            }
            match seen_wide.entry((func.ops[i].block, opcode, out_size, in_keys)) {
                std::collections::hash_map::Entry::Occupied(o) => {
                    let e = *o.get();
                    (o.into_mut(), Some(e))
                }
                std::collections::hash_map::Entry::Vacant(v) => (v.insert(out_key), None),
            }
        };

        // A value a phi reads keeps its own name (the phi prints as nothing).
        let feeds_phi =
            |func: &SsaFunction| func.varnodes[out_id as usize].uses.iter().any(|&u| func.ops[u].opcode == OpCode::MultiEqual);
        let mut name_still_holds = |k: ValueKey| version_before(func, &mut latest, (k.0, k.1, k.2), i) == k.3;
        // (one lookup: the earlier value, or the slot this one takes)
        if let Some(existing) = existing {
            hits += 1;
            if let Some(r) = rescan.as_deref_mut() {
                r[func.ops[i].block] = true;
            }
            if !feeds_phi(func)
                && name_still_holds(existing)
                && holds_at_readers(func, maps.get_or_insert_with(|| build(func)), i, value_key(func, out_id), existing)
            {
                // (the readers of the value redirected read another key from now on: their
                // blocks are looked at, in this pass from here on and in the next)
                if let Some((readers, _)) = &maps {
                    for k in [value_key(func, out_id), out_key] {
                        for &r in readers.of_key(&k) {
                            let b = func.ops[r].block;
                            if let Some(s) = scan.as_mut() {
                                s[b] = true;
                            }
                            if let Some(n) = rescan.as_deref_mut() {
                                n[b] = true;
                            }
                        }
                    }
                }
                redirects.insert(out_key, existing);
                func.ops[i].dead = true;
                eliminated += 1;
                continue;
            }
        }
        *slot = out_key;
    }

    // Apply all redirects in a single pass over the varnode arena.
    if !redirects.is_empty() {
        // (only a key redirected changes: one of an output, never a constant's; `bloom` has the
        // bit of each redirected key, so most varnodes are passed over without a lookup)
        let bloom = redirects.keys().fold(0u64, |m, &k| m | key_bit(k));
        // WS86: the kept definition's output gains the removed one's readers — else dead code
        // elimination sees no reader of it once its own die (`sete [rsi+0x18]` loads and stores
        // through two copies of the address: the load died, so did the address the store read)
        let targets: rustc_hash::FxHashSet<ValueKey> = redirects.values().map(|&k| resolve_redirect(&redirects, k)).collect();
        let target_bloom = targets.iter().fold(0u64, |m, &k| m | key_bit(k));
        // (in the same pass: the varnodes then holding a target's key, and the one of them each
        // live definition of a target writes — the last, by id)
        let mut defined: rustc_hash::FxHashMap<ValueKey, u32> = Default::default();
        let mut holding: Vec<(usize, ValueKey)> = Vec::new();
        let (ops, varnodes) = (&func.ops, &mut func.varnodes);
        for (i, vn) in varnodes.iter_mut().enumerate() {
            if vn.data.space == reargo_core::address::SpaceId::CONST {
                continue;
            }
            let mut key = (vn.data.space.0, vn.data.offset, vn.data.size, vn.version);
            if bloom & key_bit(key) != 0 {
                let to = resolve_redirect(&redirects, key);
                if to != key {
                    vn.data = reargo_core::pcode::VarnodeData::new(
                        reargo_core::address::SpaceId(to.0),
                        to.1,
                        to.2,
                    );
                    vn.version = to.3;
                    key = to;
                }
            }
            if target_bloom & key_bit(key) != 0 && targets.contains(&key) {
                holding.push((i, key));
                // (the removed duplicate's output now carries the kept key too: not that one)
                if vn.def_op.is_some_and(|d| !ops[d].dead && ops[d].output == Some(vn.id)) {
                    defined.insert(key, vn.id);
                }
            }
        }
        for &(i, key) in &holding {
            if let Some(&d) = defined.get(&key)
                && d as usize != i
            {
                // (and the definition is the kept op: the liveness walk through phis follows
                // `def_op` from the readers' inputs)
                // (a varnode a live op still writes keeps its readers)
                let own = func.varnodes[i].def_op.is_some_and(|o| !func.ops[o].dead && func.ops[o].output == Some(i as u32));
                func.varnodes[i].def_op = func.varnodes[d as usize].def_op;
                // WS98: ... and they read the kept output itself: the passes after this one
                // find a value's readers by its varnode id (copy propagation rewrote only the
                // inputs equal to the copy's output and dropped the other readers from its
                // uses: `xor edx, edx; mov eax, edx; ret` — `rdx = ZEXT 0` kept, `rax = ZEXT 0`
                // removed — returned the `rax` varnode, now named `rdx` with no definition)
                let extra = if own { func.varnodes[i].uses.clone() } else { std::mem::take(&mut func.varnodes[i].uses) };
                let (vi, vd) = (i as u32, d);
                for &u in extra.iter().filter(|_| !own) {
                    for inp in &mut func.ops[u].inputs {
                        if *inp == vi {
                            *inp = vd;
                        }
                    }
                }
                let uses = &mut func.varnodes[d as usize].uses;
                for u in extra {
                    if !uses.contains(&u) {
                        uses.push(u);
                    }
                }
            }
        }
    }

    (eliminated, hits)
}

pub fn strength_reduction(func: &mut SsaFunction) -> usize {
    let mut reduced = 0;
    let const_space = reargo_core::address::SpaceId::CONST;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }

        match func.ops[i].opcode {
            OpCode::IntMult => {
                if func.ops[i].inputs.len() < 2 { continue; }
                for side in 0..2 {
                    let other = 1 - side;
                    let vn = &func.varnodes[func.ops[i].inputs[side] as usize];
                    if vn.data.space != const_space { continue; }
                    let val = vn.data.offset;
                    if val != 0 && val.is_power_of_two() {
                        let shift_amt = val.trailing_zeros() as u64;
                        let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                        let shift_id = func.varnodes.len() as u32;
                        func.varnodes.push(crate::ssa::SsaVarnode {
                            id: shift_id,
                            data: reargo_core::pcode::VarnodeData::new(const_space, shift_amt, out_size),
                            version: 0,
                            def_op: None,
                            uses: smallvec::smallvec![i],
                        });
                        func.ops[i].opcode = OpCode::IntLeft;
                        func.ops[i].inputs = smallvec::smallvec![func.ops[i].inputs[other], shift_id];
                        reduced += 1;
                        break;
                    }
                }
            }
            OpCode::IntDiv | OpCode::IntSDiv => {
                if func.ops[i].inputs.len() < 2 { continue; }
                let divisor_vn = &func.varnodes[func.ops[i].inputs[1] as usize];
                if divisor_vn.data.space != const_space { continue; }
                let val = divisor_vn.data.offset;
                if val != 0 && val.is_power_of_two() && func.ops[i].opcode == OpCode::IntDiv {
                    let shift_amt = val.trailing_zeros() as u64;
                    let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                    let shift_id = func.varnodes.len() as u32;
                    func.varnodes.push(crate::ssa::SsaVarnode {
                        id: shift_id,
                        data: reargo_core::pcode::VarnodeData::new(const_space, shift_amt, out_size),
                        version: 0,
                        def_op: None,
                        uses: smallvec::smallvec![i],
                    });
                    func.ops[i].opcode = OpCode::IntRight;
                    func.ops[i].inputs = smallvec::smallvec![func.ops[i].inputs[0], shift_id];
                    reduced += 1;
                }
            }
            _ => {}
        }
    }
    reduced
}

pub fn algebraic_simplification(func: &mut SsaFunction) -> usize {
    let mut simplified = 0;
    let const_space = reargo_core::address::SpaceId::CONST;

    for i in 0..func.ops.len() {
        if func.ops[i].dead || func.ops[i].output.is_none() {
            continue;
        }
        if func.ops[i].inputs.len() < 2 {
            continue;
        }

        let in0 = func.ops[i].inputs[0];
        let in1 = func.ops[i].inputs[1];
        let vn0 = &func.varnodes[in0 as usize];
        let vn1 = &func.varnodes[in1 as usize];

        match func.ops[i].opcode {
            OpCode::IntSub | OpCode::IntXor if in0 == in1 => {
                let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                let zero_id = func.varnodes.len() as u32;
                func.varnodes.push(crate::ssa::SsaVarnode {
                    id: zero_id,
                    data: reargo_core::pcode::VarnodeData::new(const_space, 0, out_size),
                    version: 0, def_op: None, uses: smallvec::smallvec![i],
                });
                func.ops[i].opcode = OpCode::Copy;
                func.ops[i].inputs = smallvec::smallvec![zero_id];
                simplified += 1;
            }
            OpCode::IntAdd => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let keep = func.ops[i].inputs[1 - side];
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = smallvec::smallvec![keep];
                        simplified += 1;
                        break;
                    }
                }
            }
            OpCode::IntMult => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space {
                        if vn.data.offset == 1 {
                            let keep = func.ops[i].inputs[1 - side];
                            func.ops[i].opcode = OpCode::Copy;
                            func.ops[i].inputs = smallvec::smallvec![keep];
                            simplified += 1;
                            break;
                        } else if vn.data.offset == 0 {
                            let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                            let zero_id = func.varnodes.len() as u32;
                            func.varnodes.push(crate::ssa::SsaVarnode {
                                id: zero_id,
                                data: reargo_core::pcode::VarnodeData::new(const_space, 0, out_size),
                                version: 0, def_op: None, uses: smallvec::smallvec![i],
                            });
                            func.ops[i].opcode = OpCode::Copy;
                            func.ops[i].inputs = smallvec::smallvec![zero_id];
                            simplified += 1;
                            break;
                        }
                    }
                }
            }
            OpCode::IntAnd => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let out_size = func.varnodes[func.ops[i].output.unwrap() as usize].data.size;
                        let zero_id = func.varnodes.len() as u32;
                        func.varnodes.push(crate::ssa::SsaVarnode {
                            id: zero_id,
                            data: reargo_core::pcode::VarnodeData::new(const_space, 0, out_size),
                            version: 0, def_op: None, uses: smallvec::smallvec![i],
                        });
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = smallvec::smallvec![zero_id];
                        simplified += 1;
                        break;
                    }
                }
            }
            OpCode::IntOr => {
                for side in 0..2 {
                    let vn = if side == 0 { vn0 } else { vn1 };
                    if vn.data.space == const_space && vn.data.offset == 0 {
                        let keep = func.ops[i].inputs[1 - side];
                        func.ops[i].opcode = OpCode::Copy;
                        func.ops[i].inputs = smallvec::smallvec![keep];
                        simplified += 1;
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    simplified
}

/// What an argument register holds at a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgValue {
    /// a value the function computed
    SetUp,
    /// the function's own incoming register (or a mix of that and computed values)
    Incoming,
}

/// Classify the value `v` an argument register holds at a call; `None` when it
/// holds nothing a callee could use (a call's clobber).
fn arg_value(func: &SsaFunction, v: crate::ssa::VarId, depth: u32) -> Option<ArgValue> {
    let Some(d) = func.varnodes[v as usize].def_op else {
        // (a call's clobber left out holds nothing either)
        return func.is_incoming(&func.varnodes[v as usize]).then_some(ArgValue::Incoming);
    };
    let op = &func.ops[d];
    if op.opcode == OpCode::Indirect {
        let ins: Vec<_> = op.inputs.iter().map(|&i| func.varnodes[i as usize].data).collect();
        return (!crate::pipeline::is_call_clobber(&op.opcode, &ins)).then_some(ArgValue::SetUp);
    }
    if op.opcode == OpCode::MultiEqual {
        if depth >= 4 || op.inputs.is_empty() {
            return None;
        }
        let mut all_set_up = true;
        for &x in &op.inputs {
            match arg_value(func, x, depth + 1)? {
                ArgValue::SetUp => {}
                ArgValue::Incoming => all_set_up = false,
            }
        }
        return Some(if all_set_up { ArgValue::SetUp } else { ArgValue::Incoming });
    }
    Some(ArgValue::SetUp)
}

/// Is every use of `v` — looking through the lifter's register-view syncs
/// (`rsi = zext(esi)`, `ecx = subpiece(rcx)`) — a call? Such a value was computed to be passed.
fn only_calls_use(func: &SsaFunction, v: crate::ssa::VarId) -> bool {
    let same_reg = |a: &reargo_core::pcode::VarnodeData, b: &reargo_core::pcode::VarnodeData| {
        a.space == reargo_core::address::SpaceId::REGISTER && a.space == b.space && a.offset == b.offset
    };
    let is_view = |op: &crate::ssa::SsaOp| {
        matches!(op.opcode, OpCode::IntZExt | OpCode::IntSExt | OpCode::Subpiece | OpCode::Piece)
            && op.output.is_some_and(|o| {
                let od = func.varnodes[o as usize].data;
                op.inputs.iter().any(|&x| same_reg(&func.varnodes[x as usize].data, &od))
            })
    };
    // the family of views of this value: walk view defs up and view uses down
    let mut seen: Vec<crate::ssa::VarId> = vec![v];
    let mut work = vec![v];
    while let Some(x) = work.pop() {
        if seen.len() > 16 {
            return false;
        }
        let vn = &func.varnodes[x as usize];
        let mut next: Vec<crate::ssa::VarId> = Vec::new();
        if let Some(d) = vn.def_op
            && is_view(&func.ops[d])
        {
            next.extend(
                func.ops[d].inputs.iter().copied().filter(|&y| same_reg(&func.varnodes[y as usize].data, &vn.data)),
            );
        }
        for &u in &vn.uses {
            let op = &func.ops[u];
            if op.dead || op.output.is_some_and(|o| !feeds_anything(func, o, 0)) {
                // e.g. the ZF/SF the ALU op that computed `v` also derives from it
                continue;
            }
            if is_view(op) {
                next.extend(op.output);
            } else if !matches!(op.opcode, OpCode::Call | OpCode::CallInd) {
                return false;
            }
        }
        for y in next {
            if !seen.contains(&y) {
                seen.push(y);
                work.push(y);
            }
        }
    }
    true
}

/// Is `v` a register only partly written (`setne sil` merges a byte into `rsi`) whose narrow
/// part the function reads itself (`and al, sil`, a compare)? The byte was computed for the
/// function's own use, so the full register is no argument set up for a call (WS82). A byte
/// written only to be passed (`setne sil; call f(bool)`) is still one.
fn narrow_write_used_locally(func: &SsaFunction, v: crate::ssa::VarId) -> bool {
    let Some(d) = func.varnodes[v as usize].def_op else { return false };
    let op = &func.ops[d];
    if op.opcode != OpCode::Piece || op.inputs.len() != 2 {
        return false;
    }
    let lo = op.inputs[1];
    if func.varnodes[lo as usize].data.size > 2 {
        return false;
    }
    func.varnodes[lo as usize].uses.iter().any(|&u| {
        let r = &func.ops[u];
        !r.dead
            && !matches!(
                r.opcode,
                OpCode::Piece | OpCode::IntZExt | OpCode::IntSExt | OpCode::Subpiece | OpCode::Call | OpCode::CallInd
            )
    })
}

/// Does `v` reach anything with an effect (a store, call, branch, return, ...)? Before DCE
/// runs, a value's flag computations are still uses; this sees through them. Conservative
/// (`true`) past a small depth.
fn feeds_anything(func: &SsaFunction, v: crate::ssa::VarId, depth: u32) -> bool {
    if depth > 4 {
        return true;
    }
    func.varnodes[v as usize].uses.iter().any(|&u| {
        let op = &func.ops[u];
        !op.dead
            && match op.output {
                Some(o) if op.opcode != OpCode::Indirect => feeds_anything(func, o, depth + 1),
                _ => true,
            }
    })
}

/// Is call `i` a virtual call on the object `v` (`call [[v] + off]`)? Then `v` is its
/// `this`, also when passed through unchanged.
fn op_is_vcall_on(func: &SsaFunction, i: usize, v: crate::ssa::VarId) -> bool {
    let op = &func.ops[i];
    if op.opcode != OpCode::CallInd {
        return false;
    }
    // follow COPYs to the value they copy
    let root = |mut x: crate::ssa::VarId| {
        for _ in 0..8 {
            match func.varnodes[x as usize].def_op.map(|d| &func.ops[d]) {
                Some(o) if o.opcode == OpCode::Copy && o.inputs.len() == 1 => x = o.inputs[0],
                _ => break,
            }
        }
        x
    };
    let load_addr = |x: crate::ssa::VarId| -> Option<crate::ssa::VarId> {
        let o = &func.ops[func.varnodes[root(x) as usize].def_op?];
        if o.opcode == OpCode::Load { o.inputs.last().copied() } else { None }
    };
    let Some(slot) = op.inputs.first().and_then(|&t| load_addr(t)) else { return false };
    // slot = vtable (+ offset)
    let slot = root(slot);
    let vtable = match func.varnodes[slot as usize].def_op.map(|d| &func.ops[d]) {
        Some(o) if o.opcode == OpCode::IntAdd && o.inputs.len() == 2 => {
            let c = o
                .inputs
                .iter()
                .position(|&x| func.varnodes[x as usize].data.space == reargo_core::address::SpaceId::CONST);
            match c {
                Some(c) => o.inputs[1 - c],
                None => return false,
            }
        }
        _ => slot,
    };
    load_addr(vtable).is_some_and(|obj| root(obj) == root(v))
}

/// Keep only the argument registers a call actually set up.
///
/// The pipeline gives every call all of the convention's argument registers
/// (see `pipeline::apply_call_convention`); a register counts as an argument
/// of this call when its reaching definition is in the call's own block and
/// after the previous call there (the usual "argument setup" window). The
/// rest are dropped, so they neither print nor keep stale values alive.
/// Returns the number of inputs removed.
pub fn prune_call_args(func: &mut SsaFunction) -> usize {
    if !func.implicit_call_args {
        return 0;
    }
    // WS76: the window is no longer "this block, after the previous call". Calls clobber the
    // caller-saved registers (`INDIRECT(target, CLOBBER_MARK)`), so an argument register still
    // holding a value from before an earlier call reads that clobber and is dropped here, while
    // one set up in a block that dominates the call (`mov edi, 5; test ..; jcc; call f`) — or
    // on every path into it (a phi of such values) — is kept.
    let idom = if func.cfg.block_count() > 0 {
        crate::dominator::compute_idom(&func.cfg)
    } else {
        Vec::new()
    };
    let dominates = |a: usize, b: usize| crate::dominator::dominates(&idom, a, b);
    let mut removed = 0;
    for i in 0..func.ops.len() {
        let op = &func.ops[i];
        if !matches!(op.opcode, OpCode::Call | OpCode::CallInd) || op.dead {
            continue;
        }
        let block = op.block;
        // WS78: the callee's own parameter set, when its code could be analysed
        // (an indirect call has one when its target was resolved, `vcall`)
        let params = func.call_params.get(&op.address).copied();
        let inputs = func.ops[i].inputs.clone();
        // what each argument register holds at the call (`None`: nothing usable)
        let values: Vec<Option<ArgValue>> = inputs
            .iter()
            .enumerate()
            .map(|(k, &v)| {
                if k == 0 || func.varnodes[v as usize].data.space == reargo_core::address::SpaceId::CONST {
                    return Some(ArgValue::SetUp);
                }
                arg_value(func, v, 0).filter(|_| {
                    // a computed value must reach the call: defined before it in its block, or
                    // in a block that dominates it
                    func.varnodes[v as usize].def_op.is_none_or(|d| {
                        let db = func.ops[d].block;
                        if db == block { d < i } else { dominates(db, block) }
                    })
                })
            })
            .collect();
        // WS78: without a complete answer from the callee, take each register class's
        // contiguous prefix (System V) up to the last register clearly set up *for this
        // call* — a value only calls use (`mov esi, 0x50`, `mov rdi, r14`). A value other
        // code also uses (a loop's counter in rcx, a pointer the function keeps working
        // with in r8) is a leftover unless a later argument needs its slot.
        let in_prefix: Vec<bool> = if params.is_some_and(|p| p.complete) || inputs.len() < 2 {
            Vec::new()
        } else {
            let arg_data: Vec<_> = inputs[1..].iter().map(|&v| func.varnodes[v as usize].data).collect();
            let (class_of, members) = crate::callee_params::arg_classes(&arg_data);
            let pos_in_class = |a: usize| members[class_of[a]].iter().position(|&m| m == a).unwrap_or(0);
            let mut arity = vec![0usize; members.len()];
            for (a, &c) in class_of.iter().enumerate() {
                let k = a + 1;
                let v = inputs[k];
                let set_up_here = values[k] == Some(ArgValue::SetUp) && only_calls_use(func, v) && !narrow_write_used_locally(func, v);
                let strong = set_up_here
                    || params.is_some_and(|p| p.mask & (1 << a) != 0)
                    || (pos_in_class(a) == 0 && values[k].is_some() && op_is_vcall_on(func, i, v));
                if strong {
                    arity[c] = arity[c].max(pos_in_class(a) + 1);
                }
            }
            (0..class_of.len()).map(|a| pos_in_class(a) < arity[class_of[a]]).collect()
        };
        let mut kept: crate::ssa::InputVec = crate::ssa::InputVec::new();
        for (k, &v) in inputs.iter().enumerate() {
            let in_mask = k > 0 && params.is_some_and(|p| p.mask & (1 << (k - 1)) != 0);
            let keep = k == 0
                || match (params, values[k]) {
                    (_, None) => false,
                    // the callee reads it: an argument, also when passed through unchanged
                    (Some(_), Some(_)) if in_mask => true,
                    // the callee does not read it: a leftover, not an argument
                    (Some(p), Some(_)) if p.complete => false,
                    // no (complete) answer: the set-up prefix of its class
                    (_, Some(_)) => in_prefix[k - 1],
                };
            if keep {
                kept.push(v);
            } else {
                let uses = &mut func.varnodes[v as usize].uses;
                if let Some(p) = uses.iter().position(|&u| u == i) {
                    uses.swap_remove(p);
                }
                removed += 1;
            }
        }
        func.ops[i].inputs = kept;
    }
    func.implicit_call_args = false;
    removed
}

pub fn run_optimization_passes(func: &mut SsaFunction) -> OptimizationStats {
    let mut stats = OptimizationStats::default();
    prune_call_args(func);

    // A pass that found nothing to do, run again before any other pass changed what it reads,
    // finds nothing again and changes nothing: it is not run. What each one reads: the fold
    // (constant folding, algebra, strength) an op's opcode and input varnodes; copy
    // propagation the copies of constants and their readers' inputs (and their `uses`, which
    // it already pruned); CSE the keys of the live pure ops (with no two alike, `hits` is 0).
    // Dead code elimination only kills ops: a dead op is passed over by all three, and fewer
    // live ops give no more matches. It runs every round (killing in another order can kill
    // more).
    let (mut fold_quiet, mut copies_quiet, mut cse_quiet) = (false, false, false);
    // The blocks CSE has to look at (`cse_in_blocks`): after its first pass, those it marked
    // and those whose ops the fold or copy propagation rewrote since.
    let mut scan: Option<Vec<bool>> = None;
    let mut changed = vec![false; func.cfg.blocks.len()];
    for round in 0..10 {
        // (none of them runs: nothing changed since the last dead code elimination, which
        // would find nothing again)
        if round > 0 && fold_quiet && copies_quiet && cse_quiet {
            break;
        }
        // Three passes (constant_fold, algebraic_simplification,
        // strength_reduction) are fused into a single walk. See
        // `const_alg_strength` for the ordering argument.
        //
        // We tried also fusing copy_propagation into the same walk
        // (an earlier revision pipelined `cf -> cp` inside each op
        // visit). Microbenched and the fused form was consistently
        // ~40% slower end-to-end -- the per-fold inner cp call
        // paid an extra Vec clone + iteration that standalone
        // `copy_propagation`'s single batched walk amortises better.
        // The fused variant has been removed; this comment is the
        // only record so the next person reaching for the same
        // optimisation doesn't re-do it without knowing the result.
        let (cf, alg, sr) = if fold_quiet { (0, 0, 0) } else { const_alg_strength_in(func, Some(&mut changed)) };
        let folded = cf + alg + sr > 0;
        fold_quiet = !folded;
        copies_quiet &= !folded;
        cse_quiet &= !folded;
        let cp = if copies_quiet { 0 } else { copy_propagation_in(func, Some(&mut changed)) };
        copies_quiet = cp == 0;
        fold_quiet &= cp == 0;
        cse_quiet &= cp == 0;
        let (cse, hits) = if cse_quiet {
            (0, 0)
        } else {
            if let Some(s) = scan.as_mut() {
                for (s, c) in s.iter_mut().zip(&changed) {
                    *s |= *c;
                }
            }
            let mut rescan = vec![false; changed.len()];
            let r = cse_in_blocks(func, scan.as_deref(), Some(&mut rescan));
            scan = Some(rescan);
            changed.fill(false);
            r
        };
        cse_quiet = hits == 0;
        fold_quiet &= cse == 0;
        copies_quiet &= cse == 0;
        let dce = dead_code_elimination(func);
        stats.constants_folded += cf;
        stats.copies_propagated += cp;
        stats.strength_reduced += sr;
        stats.algebraic_simplified += alg;
        stats.cse_eliminated += cse;
        stats.dead_ops_removed += dce;
        if cf == 0 && cp == 0 && dce == 0 && sr == 0 && alg == 0 && cse == 0 {
            break;
        }
    }
    stats
}

#[derive(Debug, Default)]
pub struct OptimizationStats {
    pub dead_ops_removed: usize,
    pub constants_folded: usize,
    pub copies_propagated: usize,
    pub strength_reduced: usize,
    pub algebraic_simplified: usize,
    pub cse_eliminated: usize,
}

impl std::fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "folded={}, propagated={}, dce={}, strength={}, algebra={}, cse={}",
            self.constants_folded, self.copies_propagated, self.dead_ops_removed,
            self.strength_reduced, self.algebraic_simplified, self.cse_eliminated
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use crate::ssa::SsaFunction;
    use reargo_core::address::{Address, SpaceId};
    use reargo_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use reargo_lift::LiftedInstruction;
    use smallvec::SmallVec;

    /// [`run_optimization_passes`] with CSE looking at every block each time it runs (as before
    /// `cse_in_blocks`).
    fn run_optimization_passes_whole(func: &mut SsaFunction) -> OptimizationStats {
        let mut stats = OptimizationStats::default();
        prune_call_args(func);
        let (mut fold_quiet, mut copies_quiet, mut cse_quiet) = (false, false, false);
        for round in 0..10 {
            if round > 0 && fold_quiet && copies_quiet && cse_quiet {
                break;
            }
            let (cf, alg, sr) = if fold_quiet { (0, 0, 0) } else { const_alg_strength(func) };
            let folded = cf + alg + sr > 0;
            fold_quiet = !folded;
            copies_quiet &= !folded;
            cse_quiet &= !folded;
            let cp = if copies_quiet { 0 } else { copy_propagation(func) };
            copies_quiet = cp == 0;
            fold_quiet &= cp == 0;
            cse_quiet &= cp == 0;
            let (cse, hits) = if cse_quiet { (0, 0) } else { cse_with_hits(func) };
            cse_quiet = hits == 0;
            fold_quiet &= cse == 0;
            copies_quiet &= cse == 0;
            let dce = dead_code_elimination(func);
            stats.constants_folded += cf;
            stats.copies_propagated += cp;
            stats.strength_reduced += sr;
            stats.algebraic_simplified += alg;
            stats.cse_eliminated += cse;
            stats.dead_ops_removed += dce;
            if cf == 0 && cp == 0 && dce == 0 && sr == 0 && alg == 0 && cse == 0 {
                break;
            }
        }
        stats
    }

    /// CSE restricted to the blocks that can match again gives every function of this test's
    /// own executable (by its `.eh_frame_hdr`) the same ops, values and statistics as CSE over
    /// the whole function each time.
    #[test]
    fn cse_in_marked_blocks_matches_whole_passes() {
        let (mut checked, mut cse_seen) = (0usize, 0usize);
        for (start, body) in crate::ssa::test_executable_bodies(3000) {
            let ssa = |body: Vec<LiftedInstruction>| SsaFunction::from_cfg(String::new(), start, ControlFlowGraph::build_owned(body));
            let (mut a, mut b) = (ssa(body.clone()), ssa(body));
            let (sa, sb) = (run_optimization_passes(&mut a), run_optimization_passes_whole(&mut b));
            assert_eq!(format!("{sa:?}"), format!("{sb:?}"), "statistics of {start:#x}");
            assert_eq!(format!("{:?}", a.ops), format!("{:?}", b.ops), "ops of {start:#x}");
            assert_eq!(format!("{:?}", a.varnodes), format!("{:?}", b.varnodes), "values of {start:#x}");
            checked += 1;
            cse_seen += usize::from(sa.cse_eliminated > 0);
        }
        assert!(checked > 500 && cse_seen > 20, "{checked} functions, {cse_seen} with CSE");
    }

    fn make_lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "test".into(),
            ops,
        }
    }

    #[test]
    fn dead_code_elimination_removes_unused() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(0x1000, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                },
            ]),
            make_lifted(0x1001, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1001),
                    output: Some(reg_rcx),
                    inputs: SmallVec::from_slice(&[imm]),
                },
            ]),
            make_lifted(0x1002, vec![
                PcodeOp {
                    opcode: OpCode::Return,
                    seq: seq(0x1002),
                    output: None,
                    inputs: SmallVec::from_slice(&[reg_rax]),
                },
            ]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);

        let before = ssa.op_count();
        let removed = dead_code_elimination(&mut ssa);
        assert!(removed > 0);
        assert!(ssa.live_op_count() < before);
    }

    #[test]
    fn constant_folding() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm_a = VarnodeData::new(SpaceId(0), 10, 8);
        let imm_b = VarnodeData::new(SpaceId(0), 20, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[imm_a, imm_b]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let folded = constant_fold(&mut ssa);
        assert!(folded > 0);
    }

    /// WS83: `INT_ZEXT` / `INT_SEXT` / `SUBPIECE` of a constant fold, so `mov edi, 5`'s
    /// `rdi = zext(edi)` passes `5`, and the upper half of a zeroed `xmm` is `0`.
    #[test]
    fn constant_folding_extensions_and_pieces() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let fold = |opcode: OpCode, inputs: &[VarnodeData], out_size: u32| {
            let out = VarnodeData::new(SpaceId(2), 0x00, out_size);
            let insns = vec![
                make_lifted(0x1000, vec![PcodeOp { opcode, seq: seq(0x1000), output: Some(out), inputs: SmallVec::from_slice(inputs) }]),
                make_lifted(0x1001, vec![PcodeOp { opcode: OpCode::Return, seq: seq(0x1001), output: None, inputs: SmallVec::from_slice(&[out]) }]),
            ];
            let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, ControlFlowGraph::build(&insns));
            assert!(constant_fold(&mut ssa) > 0, "{opcode:?}");
            let op = ssa.ops.iter().find(|o| o.opcode == OpCode::Copy && !o.dead).unwrap();
            ssa.varnodes[op.inputs[0] as usize].data.offset
        };
        let c = |v: u64, size: u32| VarnodeData::new(SpaceId(0), v, size);
        assert_eq!(fold(OpCode::IntZExt, &[c(5, 4)], 8), 5);
        assert_eq!(fold(OpCode::IntSExt, &[c(0xff, 1)], 4), 0xffff_ffff);
        assert_eq!(fold(OpCode::IntSExt, &[c(0x7f, 1)], 8), 0x7f);
        assert_eq!(fold(OpCode::Subpiece, &[c(0, 16), c(8, 4)], 8), 0);
        assert_eq!(fold(OpCode::Subpiece, &[c(0x1122_3344_5566_7788, 8), c(4, 4)], 4), 0x1122_3344);
    }

    #[test]
    fn constant_folding_truncates_to_operand_width() {
        // 32-bit 0xFFFFFFFF + 1 must fold to 0, not 0x1_0000_0000.
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg = VarnodeData::new(SpaceId(2), 0x00, 4); // 4-byte result
        let a = VarnodeData::new(SpaceId(0), 0xFFFF_FFFF, 4);
        let b = VarnodeData::new(SpaceId(0), 1, 4);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg),
                inputs: SmallVec::from_slice(&[a, b]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        assert!(constant_fold(&mut ssa) > 0);
        // The folded op is now a Copy of a CONST whose value is masked to 4 bytes.
        let folded_const = ssa.ops.iter()
            .find(|o| o.opcode == OpCode::Copy && !o.dead)
            .and_then(|o| o.inputs.first().copied())
            .map(|id| ssa.varnodes[id as usize].data.offset)
            .expect("expected a folded Copy of a constant");
        assert_eq!(folded_const, 0, "0xFFFFFFFF + 1 at 4 bytes must wrap to 0");
    }

    #[test]
    fn strength_reduce_multiply_by_power_of_two() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm_8 = VarnodeData::new(SpaceId(0), 8, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntMult,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[reg_rcx, imm_8]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let reduced = strength_reduction(&mut ssa);
        assert!(reduced > 0);
        let mult_op = ssa.ops.iter().find(|op| !op.dead && op.opcode == OpCode::IntLeft);
        assert!(mult_op.is_some());
    }

    #[test]
    fn algebraic_simplify_xor_self_via_ssa() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        // xor eax, eax is the canonical "zero register" idiom
        // In SSA: copy rax <- 42; then xor rax, rax (same SSA def)
        let insns = vec![
            make_lifted(0x1000, vec![
                PcodeOp {
                    opcode: OpCode::Copy,
                    seq: seq(0x1000, 0),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[imm]),
                },
                PcodeOp {
                    opcode: OpCode::IntXor,
                    seq: seq(0x1000, 1),
                    output: Some(reg_rax),
                    inputs: SmallVec::from_slice(&[reg_rax, reg_rax]),
                },
            ]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001, 0),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let xor_ops: Vec<_> = ssa.ops.iter()
            .filter(|op| !op.dead && op.opcode == OpCode::IntXor)
            .collect();
        if let Some(xor_op) = xor_ops.first()
            && xor_op.inputs.len() == 2 && xor_op.inputs[0] == xor_op.inputs[1]
        {
            let simplified = algebraic_simplification(&mut ssa);
            assert!(simplified > 0);
        }
        // If SSA renamed them differently, the optimization correctly doesn't fire
    }

    #[test]
    fn algebraic_simplify_add_zero() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg_rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let reg_rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let imm_0 = VarnodeData::new(SpaceId(0), 0, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000),
                output: Some(reg_rax),
                inputs: SmallVec::from_slice(&[reg_rcx, imm_0]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[reg_rax]),
            }]),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let simplified = algebraic_simplification(&mut ssa);
        assert!(simplified > 0);
        let copy_op = ssa.ops.iter().find(|op| !op.dead && op.opcode == OpCode::Copy);
        assert!(copy_op.is_some());
    }

    #[test]
    fn cse_eliminates_duplicate_expression() {
        // rax = rdi + rsi; rbx = rdi + rsi (duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 1, "duplicate add should be eliminated");
        let live_adds = ssa.ops.iter().filter(|op| !op.dead && op.opcode == OpCode::IntAdd).count();
        assert_eq!(live_adds, 1);
    }

    /// WS75: `rax = rdi + 12; rax = rdi + 4; rbx = rdi + 12` — the third add
    /// must not become `rbx = rax`-by-name: `rax` no longer holds rdi + 12.
    #[test]
    fn cse_does_not_redirect_to_an_overwritten_name() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let c = |v| VarnodeData::new(SpaceId(0), v, 8);
        let add = |o, out, k| PcodeOp {
            opcode: OpCode::IntAdd,
            seq: seq(0x1000, o),
            output: Some(out),
            inputs: SmallVec::from_slice(&[rdi, c(k)]),
        };
        let insns = vec![make_lifted(0x1000, vec![add(0, rax, 12), add(1, rax, 4), add(2, rbx, 12)])];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        assert_eq!(common_subexpression_elimination(&mut ssa), 0);
        // with the name intact the duplicate still goes
        let insns = vec![make_lifted(0x1000, vec![add(0, rax, 12), add(1, rbx, 12)])];
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, ControlFlowGraph::build(&insns));
        assert_eq!(common_subexpression_elimination(&mut ssa), 1);
    }

    /// WS84: the name of the earlier value must still hold it at every reader of the removed
    /// one, not only where the duplicate is: `rax = rdi + 12; rbx = rdi + 12; rax = 5;
    /// rcx = rbx + 1` must not read `rax` for `rbx`.
    #[test]
    fn cse_checks_the_name_at_each_reader() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let (rax, rbx, rcx, rdi) = (
            VarnodeData::new(SpaceId(2), 0x00, 8),
            VarnodeData::new(SpaceId(2), 0x18, 8),
            VarnodeData::new(SpaceId(2), 0x08, 8),
            VarnodeData::new(SpaceId(2), 0x38, 8),
        );
        let c = |v| VarnodeData::new(SpaceId(0), v, 8);
        let op = |o, opcode, out, a, b| PcodeOp { opcode, seq: seq(0x1000, o), output: Some(out), inputs: SmallVec::from_slice(&[a, b]) };
        let ret = |o, v| PcodeOp { opcode: OpCode::Return, seq: seq(0x1000, o), output: None, inputs: SmallVec::from_slice(&[v]) };
        let copy = |o, out, v| PcodeOp { opcode: OpCode::Copy, seq: seq(0x1000, o), output: Some(out), inputs: SmallVec::from_slice(&[v]) };
        let insns = vec![make_lifted(
            0x1000,
            vec![
                op(0, OpCode::IntAdd, rax, rdi, c(12)),
                op(1, OpCode::IntAdd, rbx, rdi, c(12)),
                copy(2, rax, c(5)),
                op(3, OpCode::IntAdd, rcx, rbx, c(1)),
                op(4, OpCode::IntAdd, rcx, rcx, rax),
                ret(5, rcx),
            ],
        )];
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, ControlFlowGraph::build(&insns));
        assert_eq!(common_subexpression_elimination(&mut ssa), 0, "rax is 5 when rbx is read");
        // read before the overwrite: the duplicate still goes
        let insns = vec![make_lifted(
            0x1000,
            vec![
                op(0, OpCode::IntAdd, rax, rdi, c(12)),
                op(1, OpCode::IntAdd, rbx, rdi, c(12)),
                op(2, OpCode::IntAdd, rcx, rbx, c(1)),
                copy(3, rax, c(5)),
                op(4, OpCode::IntAdd, rcx, rcx, rax),
                ret(5, rcx),
            ],
        )];
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, ControlFlowGraph::build(&insns));
        assert_eq!(common_subexpression_elimination(&mut ssa), 1);
    }

    #[test]
    fn cse_keeps_extensions_of_different_width() {
        // xmm0_q = zext(xmm0_d); xmm0 = zext(xmm0_d): same input, different
        // output size -> NOT the same value.
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let d = VarnodeData::new(SpaceId(2), 0x1200, 4);
        let q = VarnodeData::new(SpaceId(2), 0x1200, 8);
        let x = VarnodeData::new(SpaceId(2), 0x1200, 16);
        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp { opcode: OpCode::IntZExt, seq: seq(0x1000, 0), output: Some(q),
                inputs: SmallVec::from_slice(&[d]) },
            PcodeOp { opcode: OpCode::IntZExt, seq: seq(0x1000, 1), output: Some(x),
                inputs: SmallVec::from_slice(&[d]) },
        ])];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        assert_eq!(common_subexpression_elimination(&mut ssa), 0);
    }

    #[test]
    fn cse_commutative_match() {
        // rax = rdi + rsi; rbx = rsi + rdi (commutative duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rsi, rdi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 1, "commutative duplicate should be eliminated");
    }

    #[test]
    fn cse_keeps_distinct_expressions() {
        // rax = rdi + rsi; rbx = rdi - rsi (different opcode, not a duplicate)
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let rdi = VarnodeData::new(SpaceId(2), 0x38, 8);
        let rsi = VarnodeData::new(SpaceId(2), 0x30, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::IntAdd,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
            PcodeOp {
                opcode: OpCode::IntSub,
                seq: seq(0x1000, 1),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rdi, rsi]),
            },
        ])];

        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let eliminated = common_subexpression_elimination(&mut ssa);
        assert_eq!(eliminated, 0, "different opcodes must not be merged");
    }

    /// DCE must not delete a Copy that defines a register subsequently
    /// read by Return. Pre-fix the SSA builder minted a fresh varnode for
    /// every read, so the def-side `uses` list stayed empty and DCE
    /// flagged the live Copy as dead.
    #[test]
    fn dce_keeps_live_def_used_by_return() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1001),
                output: None,
                inputs: SmallVec::from_slice(&[rax]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let removed = dead_code_elimination(&mut ssa);
        assert_eq!(removed, 0, "Copy of rax is live (Return reads rax)");
        let copy_live = ssa.ops.iter().any(|op| !op.dead && op.opcode == OpCode::Copy);
        assert!(copy_live, "the live Copy must survive DCE: {:?}", ssa.ops);
    }

    /// WS75: a value carried round a loop must survive. Layout:
    ///   0x1000 rax = 0
    ///   0x1001 [0x2000] = rax          <- loop head reads the carried rax
    ///   0x1002 rax = rax + 8           <- latch def, read only by the head
    ///   0x1003 rcx = rcx + 1; if (rcx != 8) goto 0x1001
    ///   0x1004 return
    /// Without phi nodes the head read the entry's rax and the latch add had
    /// no use, so DCE deleted it (the `add r14, 0x818` of BDS's octave loop).
    #[test]
    fn loop_carried_value_survives_dce() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rcx = VarnodeData::new(SpaceId(2), 0x08, 8);
        let zf = VarnodeData::new(SpaceId(2), 0x206, 1);
        let c = |v: u64, sz: u32| VarnodeData::new(SpaceId(0), v, sz);
        let op = |a: u64, opcode, output, inputs: &[VarnodeData]| PcodeOp {
            opcode,
            seq: seq(a),
            output,
            inputs: SmallVec::from_slice(inputs),
        };
        let insns = vec![
            make_lifted(0x1000, vec![op(0x1000, OpCode::Copy, Some(rax), &[c(0, 8)])]),
            make_lifted(0x1001, vec![op(0x1001, OpCode::Store, None, &[c(1, 4), c(0x2000, 8), rax])]),
            make_lifted(0x1002, vec![op(0x1002, OpCode::IntAdd, Some(rax), &[rax, c(8, 8)])]),
            make_lifted(0x1003, vec![
                op(0x1003, OpCode::IntAdd, Some(rcx), &[rcx, c(1, 8)]),
                op(0x1003, OpCode::IntNotEqual, Some(zf), &[rcx, c(8, 8)]),
                op(0x1003, OpCode::CBranch, None, &[VarnodeData::new(SpaceId(1), 0x1001, 8), zf]),
            ]),
            make_lifted(0x1004, vec![op(0x1004, OpCode::Return, None, &[c(0, 8)])]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("loop".into(), 0x1000, cfg);
        run_optimization_passes(&mut ssa);
        let add = ssa.ops.iter().find(|o| o.opcode == OpCode::IntAdd && o.address == 0x1002).expect("add");
        assert!(!add.dead, "latch add removed: {}", ssa.display_ssa());
        // the store reads the phi, whose operands are the entry copy and the add
        let store = ssa.ops.iter().find(|o| o.opcode == OpCode::Store).unwrap();
        let v = store.inputs[2];
        let phi = &ssa.ops[ssa.varnodes[v as usize].def_op.expect("phi def")];
        assert_eq!(phi.opcode, OpCode::MultiEqual, "{}", ssa.display_ssa());
        assert!(phi.inputs.iter().any(|&i| ssa.varnodes[i as usize].def_op == Some(add.index)));
    }

    /// copy_propagation pushes a constant Copy's value through to the
    /// consuming op. Pre-fix the input ids never coincided with the
    /// output id, so the `*inp == out_id` substitution never fired.
    #[test]
    fn copy_propagation_replaces_const_use_downstream() {
        let seq = |a| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let rbx = VarnodeData::new(SpaceId(2), 0x18, 8);
        let imm_99 = VarnodeData::new(SpaceId(0), 99, 8);
        let imm_2 = VarnodeData::new(SpaceId(0), 2, 8);

        let insns = vec![
            make_lifted(0x1000, vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm_99]),
            }]),
            make_lifted(0x1001, vec![PcodeOp {
                opcode: OpCode::IntMult,
                seq: seq(0x1001),
                output: Some(rbx),
                inputs: SmallVec::from_slice(&[rax, imm_2]),
            }]),
            make_lifted(0x1002, vec![PcodeOp {
                opcode: OpCode::Return,
                seq: seq(0x1002),
                output: None,
                inputs: SmallVec::from_slice(&[rbx]),
            }]),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let propagated = copy_propagation(&mut ssa);
        assert!(propagated > 0, "rax=99 should propagate into the IntMult");
        let mult_op = ssa
            .ops
            .iter()
            .find(|op| !op.dead && op.opcode == OpCode::IntMult)
            .expect("IntMult op must still be present");
        let all_const = mult_op
            .inputs
            .iter()
            .all(|&id| ssa.varnodes[id as usize].data.space == SpaceId::CONST);
        assert!(
            all_const,
            "after propagation, IntMult inputs must all be CONST: {:?}",
            mult_op
        );
    }

    /// Same SSA value read twice (e.g., `xor rax, rax` after rax is set)
    /// must yield matching input VarIds so algebraic_simplification can
    /// fold `x ^ x` to 0. Pre-fix the two reads minted distinct varnodes
    /// and the optimization was silently skipped.
    #[test]
    fn xor_self_simplifies_after_def() {
        let seq = |a, o| SeqNum::new(Address::new(SpaceId(1), a), o);
        let rax = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId(0), 42, 8);

        let insns = vec![make_lifted(0x1000, vec![
            PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(0x1000, 0),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[imm]),
            },
            PcodeOp {
                opcode: OpCode::IntXor,
                seq: seq(0x1000, 1),
                output: Some(rax),
                inputs: SmallVec::from_slice(&[rax, rax]),
            },
        ])];
        let cfg = ControlFlowGraph::build(&insns);
        let mut ssa = SsaFunction::from_cfg("test".into(), 0x1000, cfg);
        let xor = ssa
            .ops
            .iter()
            .find(|op| op.opcode == OpCode::IntXor)
            .expect("IntXor op present");
        assert_eq!(
            xor.inputs[0], xor.inputs[1],
            "both reads of rax at the same version must share a VarId: {:?}",
            xor
        );
        let simplified = algebraic_simplification(&mut ssa);
        assert!(simplified > 0, "x ^ x should fold to 0");
    }
}
