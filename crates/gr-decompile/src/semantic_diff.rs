//! Semantic function diff: compare functions by SSA structure
//! rather than raw bytes.
//!
//! The CLI `diff` command compares two binaries at the byte /
//! symbol-table level. That catches "the linker moved this section
//! to a new address," "the timestamp embedded in `.note.ABI-tag`
//! changed," and similar noise; it does NOT catch "this function's
//! behaviour changed" vs "this function was renamed but the body is
//! identical."
//!
//! This module fills the gap by hashing each function's optimized
//! SSA in a canonical, address-independent way:
//!
//!   * `structural_hash(ssa)` -- captures the op-sequence shape
//!     (opcode + input arity + output presence) and the CFG block
//!     count. Ignores varnode IDs, addresses, and constant *values*.
//!     Two functions with the same structural hash do the same kind
//!     of work in the same order.
//!
//!   * `exact_hash(ssa)` -- includes constant values and varnode
//!     types (space + size). Two functions with the same exact hash
//!     are byte-for-byte equivalent at the optimized-SSA level.
//!
//! `compare_programs` runs `decompile_all` on both inputs, hashes
//! each function with both schemes, and classifies the pairwise
//! matches:
//!
//! * `Identical` -- exact hash matches, name matches.
//! * `Renamed`   -- exact hash matches, name differs.
//! * `Tweaked`   -- structural hash matches but exact differs
//!   (same code shape, different constants).
//! * `Modified`  -- name matches but structural hash differs.
//! * `Added`     -- only in binary B.
//! * `Removed`   -- only in binary A.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use rustc_hash::FxHashMap;

use crate::ssa::SsaFunction;

/// Address-independent, varnode-id-independent hash of the optimized
/// SSA. Captures op-sequence shape and CFG block count; ignores
/// addresses, varnode IDs, and constant *values* (so "mov eax, 1"
/// and "mov eax, 2" hash the same, but "add then mov" and "mov then
/// add" do not).
pub fn structural_hash(ssa: &SsaFunction) -> u64 {
    let mut h = DefaultHasher::new();
    ssa.cfg.blocks.len().hash(&mut h);
    for op in &ssa.ops {
        if op.dead {
            continue;
        }
        (op.opcode as u32).hash(&mut h);
        op.output.is_some().hash(&mut h);
        op.inputs.len().hash(&mut h);
    }
    h.finish()
}

/// Stricter form of `structural_hash` that also includes constant
/// values and varnode type fingerprints (space + size). Two
/// functions sharing an exact hash are equivalent at the optimized-
/// SSA level; sharing a structural hash but not exact means they
/// have the same shape with different operand values (e.g., the
/// same function compiled against a different magic constant).
pub fn exact_hash(ssa: &SsaFunction) -> u64 {
    let mut h = DefaultHasher::new();
    ssa.cfg.blocks.len().hash(&mut h);
    for op in &ssa.ops {
        if op.dead {
            continue;
        }
        (op.opcode as u32).hash(&mut h);
        if let Some(out_id) = op.output {
            let vn = &ssa.varnodes[out_id as usize];
            vn.data.space.0.hash(&mut h);
            vn.data.size.hash(&mut h);
        } else {
            0u32.hash(&mut h);
        }
        op.inputs.len().hash(&mut h);
        for &inp_id in &op.inputs {
            let vn = &ssa.varnodes[inp_id as usize];
            vn.data.space.0.hash(&mut h);
            vn.data.size.hash(&mut h);
            if vn.data.space == gr_core::address::SpaceId::CONST {
                vn.data.offset.hash(&mut h);
            }
        }
    }
    h.finish()
}

/// Classification of a function pair across two binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionDiffKind {
    /// Same name AND exact hash match. Functionally and syntactically equivalent.
    Identical,
    /// Different name, same exact hash. Likely a rename across builds.
    Renamed,
    /// Same name (or rename-matched), same structural hash, different exact hash.
    /// The function's *shape* is unchanged but at least one constant /
    /// operand type differs.
    Tweaked,
    /// Same name, different structural hash. Behaviour change.
    Modified,
    /// Only present in binary A.
    Removed,
    /// Only present in binary B.
    Added,
}

/// One entry in a semantic diff report.
#[derive(Debug, Clone)]
pub struct FunctionDiff {
    /// Function name (preferring `a`'s name when both sides exist).
    pub name_a: Option<String>,
    /// Function name from `b` (when different from `name_a`).
    pub name_b: Option<String>,
    /// Entry-point address in `a`, if present.
    pub addr_a: Option<u64>,
    /// Entry-point address in `b`, if present.
    pub addr_b: Option<u64>,
    pub kind: FunctionDiffKind,
}

/// Compute a complete semantic diff between two programs.
///
/// Both inputs must have already been analyzed (so
/// `program.listing.functions()` returns the discovered functions).
/// The caller supplies a closure that, given an entry-point address,
/// returns the optimized SSA -- typically `|prog, ep| {
/// gr_decompile::decompile_function(...).map(|r| r.ssa) }`-like.
///
/// This signature avoids tying the diff module to the
/// `decompile_function` entry point shape, so a future "diff using
/// cached SSA" call site can reuse it.
pub fn compare_programs<F, G>(
    funcs_a: &[(u64, String)],
    funcs_b: &[(u64, String)],
    mut hash_a: F,
    mut hash_b: G,
) -> Vec<FunctionDiff>
where
    F: FnMut(u64) -> Option<(u64, u64)>,
    G: FnMut(u64) -> Option<(u64, u64)>,
{
    // Materialise both sides' hashes once. Owned Strings here keep
    // the lifetime story simple: the diff loop borrows from the
    // local maps, not from the input slices.
    let a_entries: Vec<(u64, String, u64, u64)> = funcs_a
        .iter()
        .filter_map(|(addr, name)| hash_a(*addr).map(|(s, e)| (*addr, name.clone(), s, e)))
        .collect();
    let b_entries: Vec<(u64, String, u64, u64)> = funcs_b
        .iter()
        .filter_map(|(addr, name)| hash_b(*addr).map(|(s, e)| (*addr, name.clone(), s, e)))
        .collect();

    let b_by_name: FxHashMap<&str, (u64, u64, u64)> = b_entries
        .iter()
        .map(|(addr, name, s, e)| (name.as_str(), (*addr, *s, *e)))
        .collect();
    let b_by_exact: FxHashMap<u64, (&str, u64)> = b_entries
        .iter()
        .map(|(addr, name, _, e)| (*e, (name.as_str(), *addr)))
        .collect();

    let mut out: Vec<FunctionDiff> = Vec::new();
    let mut matched_b: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (addr_a, name_a, a_struct, a_exact) in &a_entries {
        if let Some(&(b_addr, b_struct, b_exact)) = b_by_name.get(name_a.as_str()) {
            matched_b.insert(name_a.clone());
            let kind = if *a_exact == b_exact {
                FunctionDiffKind::Identical
            } else if *a_struct == b_struct {
                FunctionDiffKind::Tweaked
            } else {
                FunctionDiffKind::Modified
            };
            out.push(FunctionDiff {
                name_a: Some(name_a.clone()),
                name_b: None,
                addr_a: Some(*addr_a),
                addr_b: Some(b_addr),
                kind,
            });
        } else if let Some(&(b_name, b_addr)) = b_by_exact.get(a_exact) {
            matched_b.insert(b_name.to_string());
            out.push(FunctionDiff {
                name_a: Some(name_a.clone()),
                name_b: Some(b_name.to_string()),
                addr_a: Some(*addr_a),
                addr_b: Some(b_addr),
                kind: FunctionDiffKind::Renamed,
            });
        } else {
            out.push(FunctionDiff {
                name_a: Some(name_a.clone()),
                name_b: None,
                addr_a: Some(*addr_a),
                addr_b: None,
                kind: FunctionDiffKind::Removed,
            });
        }
    }

    for (addr_b, name_b, _, _) in &b_entries {
        if matched_b.contains(name_b) {
            continue;
        }
        out.push(FunctionDiff {
            name_a: None,
            name_b: Some(name_b.clone()),
            addr_a: None,
            addr_b: Some(*addr_b),
            kind: FunctionDiffKind::Added,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::ControlFlowGraph;
    use crate::ssa::SsaFunction;
    use gr_core::address::{Address, SpaceId};
    use gr_core::pcode::{PcodeOp, SeqNum, VarnodeData};
    use gr_lift::LiftedInstruction;
    use gr_core::pcode::OpCode;
    use smallvec::SmallVec;

    fn make_lifted(addr: u64, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address: addr,
            length: 1,
            mnemonic: "test".into(),
            ops,
        }
    }

    fn ssa_with(addr_offset: u64, const_val: u64) -> SsaFunction {
        let seq = |a: u64| SeqNum::new(Address::new(SpaceId(1), a), 0);
        let reg = VarnodeData::new(SpaceId(2), 0x00, 8);
        let imm = VarnodeData::new(SpaceId::CONST, const_val, 8);
        let entry = 0x1000 + addr_offset;
        let insns = vec![make_lifted(
            entry,
            vec![PcodeOp {
                opcode: OpCode::Copy,
                seq: seq(entry),
                output: Some(reg),
                inputs: SmallVec::from_slice(&[imm]),
            }],
        )];
        let cfg = ControlFlowGraph::build(&insns);
        SsaFunction::from_cfg("f".into(), entry, cfg)
    }

    #[test]
    fn identical_functions_share_both_hashes() {
        let a = ssa_with(0, 7);
        let b = ssa_with(0, 7);
        assert_eq!(structural_hash(&a), structural_hash(&b));
        assert_eq!(exact_hash(&a), exact_hash(&b));
    }

    #[test]
    fn different_load_address_keeps_both_hashes_stable() {
        let a = ssa_with(0, 7);
        let b = ssa_with(0x1_0000, 7);
        // Address is folded out of the hash.
        assert_eq!(structural_hash(&a), structural_hash(&b));
        assert_eq!(exact_hash(&a), exact_hash(&b));
    }

    #[test]
    fn changed_constant_breaks_exact_but_not_structural() {
        let a = ssa_with(0, 7);
        let b = ssa_with(0, 42);
        assert_eq!(structural_hash(&a), structural_hash(&b));
        assert_ne!(exact_hash(&a), exact_hash(&b));
    }
}
