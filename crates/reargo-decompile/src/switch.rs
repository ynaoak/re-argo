//! Jump tables (WS83): `cmp r, N; ja default; …; jmp rax` -> `switch (r)`.
//!
//! A compiler lowers a dense `switch` to a bounds check and an indirect jump through a table:
//!
//! ```text
//! cmp   r13d, 6            ; 7 cases
//! ja    default
//! mov   eax, r13d
//! lea   rcx, [table]       ; PIE: 32-bit entries relative to the table
//! movsxd rax, [rcx+rax*4]
//! add   rax, rcx
//! jmp   rax                ; (non-PIE: jmp [table+rax*8])
//! ```
//!
//! The `jmp` used to be a block without successors (`goto *rax;`): the cases' code was never
//! reached, so it was not printed at all. [`recover_jump_tables`] evaluates the instructions
//! between the bounds check and the `jmp` symbolically, reads the table from memory and,
//! when every entry is an instruction of the function, rewrites the `BRANCHIND` to read the
//! index register (`r13d`) and carry the case targets as extra inputs (`RAM` addresses, case
//! `i` = input `i + 1`). The CFG takes them as the block's successors; the pipeline strips them
//! before SSA. The table computation then has no reader and dead code elimination drops it.
//!
//! WS84 widened the shapes: the bounds check may jump to the dispatch with the default falling
//! through (`cmp r, N; jbe dispatch`), be signed (`jg` / `jle`, emitted when the index is known
//! not to be negative), the window may reuse the compared register (`movsxd rsi,
//! [rdi+rsi*4]`: the index is then copied at the window's start, [`INDEX_TMP`]), a byte /
//! word table may pick the slot (`movzx eax, byte [B + i]`: case `i` jumps to `T[B[i]]`), and
//! a target out of the function (a `.cold` part) becomes a tail-call stub like a conditional
//! jump out of the code.

use rustc_hash::FxHashMap;

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::LiftedInstruction;
use reargo_loader::Memory;

/// A recovered jump table: the `jmp`'s address, the case targets in table order (case `i`
/// jumps to `targets[i]`) and the bounds check's target for the other values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    pub jmp: u64,
    pub targets: Vec<u64>,
    pub default: Option<u64>,
}

/// Most entries read from one table.
const MAX_ENTRIES: u64 = 1024;
/// Most instructions between the bounds check's jump and the `jmp`.
const MAX_WINDOW: usize = 8;
/// The temporary holding a dispatch's index as its window starts.
pub(crate) const INDEX_TMP: u64 = 0x6f00;
/// The x86 carry flag's register offset (`CF = a <u b` of a `cmp`).
const CF_OFFSET: u64 = 0x201;

#[derive(Debug, Clone, PartialEq)]
enum E {
    Reg(VarnodeData),
    Const(u64),
    Add(Box<E>, Box<E>),
    Mul(Box<E>, u64),
    Load(Box<E>, u32),
    Ext(Box<E>),
    Other,
}

type Key = (u32, u64, u32);

fn key(v: &VarnodeData) -> Key {
    (v.space.0, v.offset, v.size)
}

fn overlaps(x: &VarnodeData, w: &VarnodeData) -> bool {
    x.space == w.space && x.offset < w.offset + w.size as u64 && w.offset < x.offset + x.size as u64
}

/// Evaluate the ops of `insns` symbolically; the value each storage holds at the end.
fn evaluate(insns: &[LiftedInstruction]) -> FxHashMap<Key, E> {
    let mut env: FxHashMap<Key, E> = FxHashMap::default();
    let val = |env: &FxHashMap<Key, E>, v: &VarnodeData| -> E {
        if v.space == SpaceId::CONST {
            return E::Const(v.offset);
        }
        env.get(&key(v)).cloned().unwrap_or(E::Reg(*v))
    };
    for insn in insns {
        for op in &insn.ops {
            let Some(out) = op.output else { continue };
            let i = |k: usize| op.inputs.get(k).map(|v| val(&env, v));
            let e = match (op.opcode, i(0), i(1)) {
                (OpCode::Copy, Some(a), _) => a,
                (OpCode::IntAdd, Some(a), Some(b)) => E::Add(Box::new(a), Box::new(b)),
                (OpCode::IntMult, Some(a), Some(E::Const(c))) | (OpCode::IntMult, Some(E::Const(c)), Some(a)) => {
                    E::Mul(Box::new(a), c)
                }
                (OpCode::IntLeft, Some(a), Some(E::Const(c))) if c < 8 => E::Mul(Box::new(a), 1 << c),
                (OpCode::Load, _, Some(addr)) => E::Load(Box::new(addr), out.size),
                // a constant widened is a constant (`lea edx, [T]` then `add rax, rdx`, WS84)
                (OpCode::IntZExt, Some(E::Const(c)), _) => E::Const(c),
                (OpCode::IntSExt, Some(E::Const(c)), _) => {
                    let bits = op.inputs[0].size.min(8) * 8;
                    E::Const(if bits >= 64 { c } else { (((c << (64 - bits)) as i64) >> (64 - bits)) as u64 })
                }
                (OpCode::IntSExt | OpCode::IntZExt, Some(a), _) => E::Ext(Box::new(a)),
                _ => E::Other,
            };
            // (the x86 lifter writes every view of a register it changes — `mov eax, r13d` also
            // writes `rax = zext(eax)` and the narrower ones — so each view is tracked apart)
            env.insert(key(&out), e);
        }
    }
    env
}

/// `e` with each register the function sets once, to a constant, replaced by that constant (a
/// table base hoisted out of a loop: `lea r9, [T]` before it, `movsxd r14, [r9+r14*4]` in it).
fn with_bases(e: &E, bases: &FxHashMap<u64, u64>) -> E {
    match e {
        E::Reg(r) if r.space == SpaceId::REGISTER && r.size >= 4 => bases.get(&r.offset).map_or(E::Reg(*r), |&c| E::Const(c)),
        E::Add(a, b) => E::Add(Box::new(with_bases(a, bases)), Box::new(with_bases(b, bases))),
        E::Mul(a, c) => E::Mul(Box::new(with_bases(a, bases)), *c),
        E::Load(a, sz) => E::Load(Box::new(with_bases(a, bases)), *sz),
        E::Ext(a) => match with_bases(a, bases) {
            E::Const(c) => E::Const(c),
            x => E::Ext(Box::new(x)),
        },
        x => x.clone(),
    }
}

/// `e` with the registers of `loose` that are added to something (a table base: `r12 +
/// rdi*4`, `rdi + r12`) replaced by their constant; an index (under a scale) keeps its name.
fn with_loose_bases(e: &E, loose: &FxHashMap<u64, u64>) -> E {
    let base = |x: &E| match x {
        E::Reg(r) if r.space == SpaceId::REGISTER && r.size == 8 => loose.get(&r.offset).map_or_else(|| x.clone(), |&c| E::Const(c)),
        x => with_loose_bases(x, loose),
    };
    match e {
        E::Add(a, b) => E::Add(Box::new(base(a)), Box::new(base(b))),
        E::Load(a, sz) => E::Load(Box::new(with_loose_bases(a, loose)), *sz),
        E::Ext(a) => E::Ext(Box::new(with_loose_bases(a, loose))),
        x => x.clone(),
    }
}

/// Instructions looked back for [`nearest_constants`].
const MAX_BACK: usize = 4096;

/// For each general register: the constant the closest instruction before `start` (in address
/// order, `pop`s skipped) that writes it puts there, when that write is a constant.
fn nearest_constants(insns: &[LiftedInstruction], start: usize) -> FxHashMap<u64, u64> {
    let mut seen = rustc_hash::FxHashSet::default();
    let mut out = FxHashMap::default();
    for insn in insns[start.saturating_sub(MAX_BACK)..start].iter().rev() {
        if insn.mnemonic.starts_with("pop ") {
            continue;
        }
        for op in insn.ops.iter().rev() {
            let Some(o) = op.output else { continue };
            if o.space != SpaceId::REGISTER || o.offset >= 0xC0 {
                continue;
            }
            let base = o.offset & !7;
            if !seen.insert(base) {
                continue;
            }
            // (the lifter writes the narrow views after the full register: take the 8-byte one)
            if let (OpCode::Copy, Some(c), 8) = (op.opcode, op.inputs.first().filter(|v| v.space == SpaceId::CONST), o.size) {
                out.insert(base, c.offset);
            } else if o.size != 8 {
                seen.remove(&base);
            }
        }
    }
    out
}

/// The general registers the function writes in exactly one instruction, with a constant
/// (`lea r9, [T]`): offset -> value. The registers it writes one constant (in one or more
/// instructions) besides other values (WS85: `lea r12, [T]` twice and a `mov r12, r14` swap
/// in between), offset -> value. And every constant address an instruction puts in a register
/// (the bases of other tables).
type Constants = (FxHashMap<u64, u64>, FxHashMap<u64, u64>, rustc_hash::FxHashSet<u64>);

fn constant_registers(insns: &[LiftedInstruction]) -> Constants {
    let mut writes: FxHashMap<u64, (u32, Option<u64>)> = FxHashMap::default();
    // per register: the constants written (`None` once two differ)
    let mut consts: FxHashMap<u64, Option<u64>> = FxHashMap::default();
    let mut loaded = rustc_hash::FxHashSet::default();
    for insn in insns {
        // (a `pop` restores the caller's value on the way out: no write the dispatch sees, WS85)
        if insn.mnemonic.starts_with("pop ") {
            continue;
        }
        let mut here: Vec<(u64, Option<u64>)> = Vec::new();
        for op in &insn.ops {
            let Some(out) = op.output else { continue };
            if out.space != SpaceId::REGISTER || out.offset >= 0xC0 {
                continue;
            }
            let base = out.offset & !7;
            let c = (op.opcode == OpCode::Copy && out.size >= 4)
                .then(|| op.inputs.first().filter(|v| v.space == SpaceId::CONST).map(|v| v.offset))
                .flatten();
            if let Some(c) = c {
                loaded.insert(c);
            }
            match here.iter_mut().find(|h| h.0 == base) {
                Some(h) => h.1 = h.1.or(c),
                None => here.push((base, c)),
            }
        }
        for (base, c) in here {
            let w = writes.entry(base).or_insert((0, None));
            w.0 += 1;
            w.1 = c;
            if let Some(c) = c {
                consts.entry(base).and_modify(|k| *k = k.filter(|&k| k == c)).or_insert(Some(c));
            }
        }
    }
    let once: FxHashMap<u64, u64> = writes.into_iter().filter_map(|(r, (n, c))| (n == 1).then_some((r, c?))).collect();
    let loose = consts.into_iter().filter_map(|(r, c)| Some((r, c?))).filter(|(r, _)| !once.contains_key(r)).collect();
    (once, loose, loaded)
}

/// `(T, I)` when `addr` is `T + I * scale` (`T + I` for a byte table).
fn table_slot(addr: &E, scale: u64) -> Option<(u64, &E)> {
    let E::Add(a, b) = addr else { return None };
    match (&**a, &**b) {
        (E::Const(t), E::Mul(i, s)) | (E::Mul(i, s), E::Const(t)) if *s == scale => Some((*t, i)),
        (E::Const(t), i) | (i, E::Const(t)) if scale == 1 && !matches!(i, E::Const(_)) => Some((*t, i)),
        _ => None,
    }
}

/// `(table, relative, index)`: the jump target is `table + sext(int32 table[i])` (PIE) or
/// `uint64 table[i]`.
fn dispatch(target: &E) -> Option<(u64, bool, &E)> {
    match target {
        E::Add(a, b) => {
            let (t2, x) = match (&**a, &**b) {
                (E::Const(t), x) | (x, E::Const(t)) => (*t, x),
                _ => return None,
            };
            let E::Ext(l) = x else { return None };
            let E::Load(addr, 4) = &**l else { return None };
            let (t, i) = table_slot(addr, 4)?;
            (t == t2).then_some((t, true, i))
        }
        E::Load(addr, 8) => {
            let (t, i) = table_slot(addr, 8)?;
            Some((t, false, i))
        }
        _ => None,
    }
}

/// The index of a two-level table (WS84): `movzx eax, byte [T1 + i]` picks the slot of the
/// target table, so case `i` jumps to `targets[T1[i]]`. `(T1, entry size, i)`.
fn index_table(index: &E) -> Option<(u64, u32, &E)> {
    let mut x = index;
    while let E::Ext(inner) = x {
        x = inner;
    }
    let E::Load(addr, sz @ (1 | 2)) = x else { return None };
    let (t1, i) = table_slot(addr, u64::from(*sz))?;
    Some((t1, *sz, i))
}

fn has(insn: &LiftedInstruction, opcode: OpCode) -> bool {
    insn.ops.iter().any(|o| o.opcode == opcode)
}

/// Recover the jump tables of `insns` (see the module doc) and rewrite their `BRANCHIND`s.
pub fn recover_jump_tables(insns: &mut [LiftedInstruction], memory: &Memory) -> Vec<JumpTable> {
    let mut out = Vec::new();
    if !insns.iter().any(|i| has(i, OpCode::BranchInd)) {
        return out;
    }
    let addrs: rustc_hash::FxHashSet<u64> = insns.iter().map(|i| i.address).collect();
    let (bases, loose, loaded) = constant_registers(insns);
    for k in 0..insns.len() {
        let Some(found) = recover_one(insns, k, &addrs, (&bases, &loose), &loaded, memory) else { continue };
        let (index, start, table) = found;
        // the index as the window starts, when the window reuses its register (WS84: `movsxd
        // rax, [rcx+rax*4]`; the BRANCHIND reads at the window's end)
        let reused = insns[start..=k].iter().flat_map(|i| i.ops.iter()).any(|o| o.output.is_some_and(|w| overlaps(&index, &w)));
        if !reused {
            let op = insns[k].ops.iter_mut().find(|o| o.opcode == OpCode::BranchInd).expect("checked");
            op.inputs = std::iter::once(index)
                .chain(table.targets.iter().map(|&t| VarnodeData::new(SpaceId::RAM, t, 8)))
                .collect();
            out.push(table);
            continue;
        }
        let at_start = VarnodeData::new(SpaceId::UNIQUE, INDEX_TMP, index.size);
        let first = &mut insns[start].ops;
        let seq = first.first().map(|o| o.seq).unwrap_or(reargo_core::pcode::SeqNum::new(
            reargo_core::address::Address::new(SpaceId::RAM, insns[start].address),
            0,
        ));
        first.insert(
            0,
            reargo_core::pcode::PcodeOp { opcode: OpCode::Copy, seq, output: Some(at_start), inputs: smallvec::smallvec![index] },
        );
        for (i, op) in first.iter_mut().enumerate() {
            op.seq.order = i as u32;
        }
        let op = insns[k].ops.iter_mut().find(|o| o.opcode == OpCode::BranchInd).expect("checked");
        op.inputs = std::iter::once(at_start)
            .chain(table.targets.iter().map(|&t| VarnodeData::new(SpaceId::RAM, t, 8)))
            .collect();
        out.push(table);
    }
    out
}

/// The number of cases a bounds check `cmp r, N` lets through.
type CaseCount = fn(u64) -> Option<u64>;

/// The bounds check before a dispatch, as the mnemonic of its conditional jump says it:
/// `(cases for "cmp r, N", jumps to the dispatch)`. `ja`/`jae` (`jg`/`jge`) jump to the
/// default and fall into the dispatch; `jbe`/`jb` (`jle`/`jl`) jump to the dispatch and fall
/// into the default (WS84). A signed check is one the compiler emits when the index is known
/// not to be negative.
fn bounds_kind(mnemonic: &str) -> Option<(CaseCount, bool)> {
    let plus1: CaseCount = |n| n.checked_add(1);
    let same: CaseCount = Some;
    Some(match mnemonic.split_whitespace().next()? {
        "ja" | "jnbe" | "jg" | "jnle" => (plus1, false),
        "jae" | "jnb" | "jnc" | "jge" | "jnl" => (same, false),
        "jbe" | "jna" | "jle" | "jng" => (plus1, true),
        "jb" | "jnae" | "jc" | "jl" | "jnge" => (same, true),
        _ => return None,
    })
}

fn cbranch_target(insn: &LiftedInstruction) -> Option<u64> {
    insn.ops.iter().find(|o| o.opcode == OpCode::CBranch)?.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset)
}

fn recover_one(
    insns: &[LiftedInstruction],
    k: usize,
    addrs: &rustc_hash::FxHashSet<u64>,
    (bases, loose): (&FxHashMap<u64, u64>, &FxHashMap<u64, u64>),
    loaded: &rustc_hash::FxHashSet<u64>,
    memory: &Memory,
) -> Option<(VarnodeData, usize, JumpTable)> {
    let jmp = &insns[k];
    let target_vn = *jmp.ops.iter().find(|o| o.opcode == OpCode::BranchInd)?.inputs.first()?;
    // the straight-line run before the `jmp`: from the bounds check's fall-through, or from
    // the target of a jump to the dispatch (after an unconditional jump / return / call)
    let mut start = k;
    while start > 0 && k - start < MAX_WINDOW {
        let p = &insns[start - 1];
        let control = [OpCode::CBranch, OpCode::Branch, OpCode::Return, OpCode::Call, OpCode::CallInd, OpCode::BranchInd]
            .iter()
            .any(|&o| has(p, o));
        if control || p.address + p.length as u64 != insns[start].address {
            break;
        }
        start -= 1;
    }
    // the window, the `jmp` included (`jmp [table+rax*8]` loads in the instruction itself);
    // started later when the index is computed in it (`mov eax, [rdi]` of an enum switch):
    // the index is then the register holding it
    // the bases set once first; then those set to one constant among other writes, then the
    // constant last written before the window in address order (two tables through one
    // register, WS85) — a table found these ways must hold only instructions of the function
    let found = [0, 1, 2].into_iter().find_map(|mode| {
        let is_loose = mode > 0;
        (start..=k).find_map(|st| {
        let env = evaluate(&insns[st..=k]);
        let target = env.get(&key(&target_vn)).cloned().unwrap_or(E::Reg(target_vn));
        let target = with_bases(&target, bases);
        let target = match mode {
            0 => target,
            1 => with_loose_bases(&target, loose),
            // (the constants before this start: the window's own `lea` before it counts)
            _ => with_loose_bases(&target, &nearest_constants(insns, st)),
        };
        let (table, relative, index) = dispatch(&target)?;
        let (index, level1) = match index_table(index) {
            Some((t1, sz, i)) => (i, Some((t1, sz))),
            None => (index, None),
        };
        let mut index = index;
        while let E::Ext(x) = index {
            index = x;
        }
        let E::Reg(r) = index else { return None };
        Some((st, table, relative, level1, *r, is_loose))
        })
    });
    let window_start = start;
    let (start, table, relative, level1, r, is_loose) = found?;
    // the bounds check: `cmp r, N` and a conditional jump into the window (falling into it, or
    // jumping to its start)
    let at = insns[start].address;
    let falls = start.checked_sub(1).filter(|&j| {
        has(&insns[j], OpCode::CBranch)
            && insns[j].address + insns[j].length as u64 == at
            && bounds_kind(&insns[j].mnemonic).is_some_and(|(_, to)| !to)
    });
    let jumps = || {
        insns.iter().position(|i| {
            cbranch_target(i) == Some(at) && bounds_kind(&i.mnemonic).is_some_and(|(_, to)| to)
        })
    };
    let read = |slot: u64| -> Option<u64> {
        Some(if relative {
            let e = memory.read_u32(table + 4 * slot).ok()? as i32 as i64;
            table.wrapping_add(e as u64)
        } else {
            memory.read_u64(table + 8 * slot).ok()?
        })
    };
    let Some(j) = falls.or_else(jumps) else {
        // no bounds check: a switch over an enum the compiler knows the range of (`default:
        // __builtin_unreachable()`). The table runs while its entries are instructions of the
        // function, up to the next table the function loads (WS84).
        if level1.is_some() || insns[start..k].iter().any(|i| has(i, OpCode::CBranch)) {
            return None;
        }
        let width = if relative { 4 } else { 8 };
        // the index's range when the code shows it: a shift / mask computing it right before
        // (`shr edi, 30`: 4 cases, WS85)
        let limit = index_range(insns, window_start, k, &r).filter(|&n| n >= 2).unwrap_or(MAX_ENTRIES);
        let mut targets = Vec::new();
        for i in 0..limit.min(MAX_ENTRIES) {
            if i > 0 && loaded.contains(&(table + width * i)) {
                break;
            }
            match read(i) {
                Some(t) if addrs.contains(&t) => targets.push(t),
                _ => break,
            }
        }
        if targets.len() < 2 {
            return None;
        }
        return Some((r, start, JumpTable { jmp: jmp.address, targets, default: None }));
    };
    let jcc = &insns[j];
    let (count, to_dispatch) = bounds_kind(&jcc.mnemonic)?;
    let default = if to_dispatch {
        Some(jcc.address + jcc.length as u64)
    } else {
        cbranch_target(jcc)
    };
    let cases = {
        let cmp = (j.saturating_sub(3)..j).rev().find_map(|c| {
            insns[c].ops.iter().find_map(|o| {
                let out = o.output?;
                (o.opcode == OpCode::IntLess && out.space == SpaceId::REGISTER && out.offset == CF_OFFSET && o.inputs.len() == 2)
                    .then(|| (c, o.inputs[0], o.inputs[1]))
            })
        });
        let (c, x, n) = cmp?;
        if n.space != SpaceId::CONST || x.space != r.space || x.offset != r.offset {
            return None;
        }
        // the compared register keeps its value up to the window, whose evaluation reads it
        // (the window itself may reuse it: `movsxd rsi, [rdi+rsi*4]`)
        let written = insns[c + 1..=j].iter().flat_map(|i| i.ops.iter()).any(|o| o.output.is_some_and(|w| overlaps(&r, &w)));
        if written {
            return None;
        }
        count(n.offset)?
    };
    if cases == 0 || cases > MAX_ENTRIES {
        return None;
    }
    // a target outside the function (a `.cold` part) jumps out: a tail-call stub, as a
    // conditional jump out of the code is (`pipeline::rewrite_tail_calls`); it must be code
    let executable = |t: u64| memory.find_block(t).is_some_and(|b| b.flags.contains(reargo_loader::memory::MemoryFlags::EXECUTE));
    let mut targets = Vec::with_capacity(cases as usize);
    for i in 0..cases {
        let slot = match level1 {
            Some((t1, 1)) => u64::from(memory.read_byte(t1 + i)?),
            Some((t1, _)) => u64::from(memory.read_u16(t1 + 2 * i).ok()?),
            None => i,
        };
        if slot > MAX_ENTRIES {
            return None;
        }
        let t = read(slot)?;
        if addrs.contains(&t) {
            targets.push(t);
        } else if executable(t) && !is_loose {
            targets.push(crate::pipeline::TAIL_STUB_BASE + t);
        } else {
            return None;
        }
    }
    // a default out of the function (WS85): the bounds check's jump is a tail call there
    let default = match default {
        Some(d) if !addrs.contains(&d) => {
            if !executable(d) {
                return None;
            }
            Some(crate::pipeline::TAIL_STUB_BASE + d)
        }
        d => d,
    };
    Some((r, start, JumpTable { jmp: jmp.address, targets, default }))
}

/// The number of values the index register `r` can hold at the dispatch `k` when the
/// straight line from `from` computes it with a shift right or a low mask (`shr edi, 30` -> 4).
fn index_range(insns: &[LiftedInstruction], from: usize, k: usize, r: &VarnodeData) -> Option<u64> {
    let mut range = None;
    // up to the table read (`movsxd rax, [r12+rax*4]` may reuse the index register)
    let read = insns[from..k].iter().position(|i| ["*4]", "*8]", "*4+", "*8+"].iter().any(|s| i.mnemonic.contains(s)));
    let end = read.map_or(k, |p| from + p);
    for op in insns[from..end].iter().flat_map(|i| i.ops.iter()) {
        let Some(out) = op.output else { continue };
        if !(out.space == r.space && out.offset == r.offset) {
            continue;
        }
        let c = op.inputs.get(1).filter(|v| v.space == SpaceId::CONST).map(|v| v.offset);
        range = match (op.opcode, c) {
            (OpCode::IntRight, Some(s)) if s > 0 && s < u64::from(out.size) * 8 => Some(1u64 << (u64::from(out.size) * 8 - s).min(63)),
            (OpCode::IntAnd, Some(m)) if m < MAX_ENTRIES && (m + 1).is_power_of_two() => Some(m + 1),
            // the wider view of the value just computed
            (OpCode::IntZExt, _) if op.inputs.first().is_some_and(|i| i.space == r.space && i.offset == r.offset) => range,
            // a narrower view the lifter derives from the register
            (OpCode::Subpiece, _) if out.size < r.size => range,
            _ => None,
        };
    }
    range
}

