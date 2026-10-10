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

/// `(T, I)` when `addr` is `T + I * scale`.
fn table_slot(addr: &E, scale: u64) -> Option<(u64, &E)> {
    let E::Add(a, b) = addr else { return None };
    match (&**a, &**b) {
        (E::Const(t), E::Mul(i, s)) | (E::Mul(i, s), E::Const(t)) if *s == scale => Some((*t, i)),
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
    for k in 0..insns.len() {
        let Some(found) = recover_one(insns, k, &addrs, memory) else { continue };
        let (index, table) = found;
        let op = insns[k].ops.iter_mut().find(|o| o.opcode == OpCode::BranchInd).expect("checked");
        op.inputs = std::iter::once(index)
            .chain(table.targets.iter().map(|&t| VarnodeData::new(SpaceId::RAM, t, 8)))
            .collect();
        out.push(table);
    }
    out
}

fn recover_one(
    insns: &[LiftedInstruction],
    k: usize,
    addrs: &rustc_hash::FxHashSet<u64>,
    memory: &Memory,
) -> Option<(VarnodeData, JumpTable)> {
    let jmp = &insns[k];
    let target_vn = *jmp.ops.iter().find(|o| o.opcode == OpCode::BranchInd)?.inputs.first()?;
    // the straight-line run from the bounds check's jump to the `jmp`
    let mut start = k;
    while start > 0 && k - start < MAX_WINDOW {
        let p = &insns[start - 1];
        if has(p, OpCode::CBranch) {
            break;
        }
        if has(p, OpCode::Branch) || has(p, OpCode::Return) || has(p, OpCode::Call) || has(p, OpCode::CallInd) || has(p, OpCode::BranchInd) {
            return None;
        }
        start -= 1;
    }
    let jcc = start.checked_sub(1).map(|j| &insns[j])?;
    if !has(jcc, OpCode::CBranch) || jcc.address + jcc.length as u64 != insns[start].address {
        return None;
    }
    // the window, the `jmp` included (`jmp [table+rax*8]` loads in the instruction itself)
    let env = evaluate(&insns[start..=k]);
    let target = env.get(&key(&target_vn)).cloned().unwrap_or(E::Reg(target_vn));
    let (table, relative, index) = dispatch(&target)?;
    let mut index = index;
    while let E::Ext(x) = index {
        index = x;
    }
    let E::Reg(r) = index else { return None };
    let r = *r;
    // the bounds check: `cmp r, N` (CF = r <u N) then `ja` (N + 1 cases) / `jae` (N)
    let cases = {
        let ja = match jcc.mnemonic.split_whitespace().next()? {
            "ja" | "jnbe" => true,
            "jae" | "jnb" | "jnc" => false,
            _ => return None,
        };
        let j = start - 1;
        let cmp = (j.saturating_sub(3)..=j).rev().find_map(|c| {
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
        // the compared register keeps its value up to the `jmp`
        let written = insns[c + 1..k].iter().flat_map(|i| i.ops.iter()).any(|o| o.output.is_some_and(|w| overlaps(&r, &w)));
        if written {
            return None;
        }
        if ja { n.offset.checked_add(1)? } else { n.offset }
    };
    if cases == 0 || cases > MAX_ENTRIES {
        return None;
    }
    let default = jcc.ops.iter().find(|o| o.opcode == OpCode::CBranch)?.inputs.first().filter(|t| t.space == SpaceId::RAM).map(|t| t.offset);
    let mut targets = Vec::with_capacity(cases as usize);
    for i in 0..cases {
        let t = if relative {
            let e = memory.read_u32(table + 4 * i).ok()? as i32 as i64;
            table.wrapping_add(e as u64)
        } else {
            memory.read_u64(table + 8 * i).ok()?
        };
        if !addrs.contains(&t) {
            return None;
        }
        targets.push(t);
    }
    if default.is_some_and(|d| !addrs.contains(&d)) {
        return None;
    }
    Some((r, JumpTable { jmp: jmp.address, targets, default }))
}
