//! What the callers of a function do with its result (WS80): the return type of a function
//! whose own code does not show it (`return g();` with `g` unknown).
//!
//! The direct call sites are found by a byte scan of the executable blocks for `E8 rel32`
//! landing on the function (no analysis; a random `E8` hit that is not a real call is
//! improbable for one 32-bit target). After each call, a few instructions are lifted until
//! the caller first reads the return registers, overwrites them or leaves the straight line.

use reargo_core::address::SpaceId;
use reargo_core::pcode::{OpCode, VarnodeData};
use reargo_lift::PcodeLift;
use reargo_loader::{Memory, MemoryFlags};

/// What callers do with a function's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnHint {
    /// They read `rax` (`test eax, eax`, `mov rdi, rax`).
    Int,
    /// They read the low lanes of `xmm0` (`addss xmm1, xmm0`, `movss [m], xmm0`): a `float`
    /// (4) or `double` (8).
    Float(u32),
    /// They overwrite `rax` (or call on) without reading it or `xmm0`: nothing is returned.
    Void,
}

/// Most call sites looked at.
const MAX_SITES: usize = 16;
/// Instructions lifted after a call.
const WINDOW: usize = 12;

/// Addresses of the `call rel32` instructions (`E8`) that target `target`, at most `cap`.
pub fn direct_call_sites(memory: &Memory, target: u64, cap: usize) -> Vec<u64> {
    let mut out = Vec::new();
    for block in memory.blocks() {
        if !block.flags.contains(MemoryFlags::EXECUTE) {
            continue;
        }
        let Some(data) = block.data.as_ref() else { continue };
        if data.len() < 5 {
            continue;
        }
        // rel32 = target - (site + 5): only sites within ±2 GiB can reach it
        let start = block.start;
        for i in memchr_iter(0xe8, &data[..data.len() - 4]) {
            let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let site = start + i as u64;
            if (site as i64).wrapping_add(5).wrapping_add(rel as i64) as u64 == target {
                out.push(site);
                if out.len() >= cap {
                    return out;
                }
            }
        }
    }
    out
}

/// Positions of `needle` in `hay`, 8 bytes at a time (a word with no such byte is skipped
/// with one test).
fn memchr_iter(needle: u8, hay: &[u8]) -> impl Iterator<Item = usize> + '_ {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    let pat = LO * needle as u64;
    let words = hay.len() / 8;
    (0..words)
        .filter(move |&w| {
            let x = u64::from_le_bytes(hay[w * 8..w * 8 + 8].try_into().unwrap()) ^ pat;
            x.wrapping_sub(LO) & !x & HI != 0
        })
        .flat_map(move |w| (w * 8..w * 8 + 8).filter(move |&i| hay[i] == needle))
        .chain((words * 8..hay.len()).filter(move |&i| hay[i] == needle))
}

/// The verdict of one call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    Int,
    Float(u32),
    Void,
    Unknown,
}

fn overlaps(v: &VarnodeData, reg: &VarnodeData, len: u64) -> bool {
    v.space == reg.space && v.offset < reg.offset + len && reg.offset < v.offset + v.size as u64
}

/// What the code after the call at `site` does with `rax` / `xmm0`.
fn site_verdict(lifter: &dyn PcodeLift, memory: &Memory, site: u64, rax: &VarnodeData, xmm0: &VarnodeData) -> Site {
    let Ok(insns) = lifter.lift_range(memory, site, WINDOW + 1) else { return Site::Unknown };
    let mut iter = insns.iter();
    // the call itself
    match iter.next() {
        Some(c) if c.ops.iter().any(|o| o.opcode == OpCode::Call) => {}
        _ => return Site::Unknown,
    }
    // the result is decided by `rax`: read -> `Int`; overwritten, or a call clobbers it,
    // with `xmm0`'s low lanes not read before -> `Void`; `xmm0` read first -> `Float`
    let (mut rax_dead, mut xmm_dead) = (false, false);
    for insn in iter {
        for op in &insn.ops {
            match op.opcode {
                OpCode::Call | OpCode::CallInd => return Site::Void,
                OpCode::Branch | OpCode::CBranch | OpCode::BranchInd | OpCode::Return | OpCode::CallOther => {
                    return if rax_dead { Site::Void } else { Site::Unknown };
                }
                _ => {}
            }
            // `xor eax, eax` / `sub eax, eax` / `pxor xmm0, xmm0` read nothing
            let self_op = op.inputs.len() == 2
                && op.inputs[0] == op.inputs[1]
                && matches!(op.opcode, OpCode::IntXor | OpCode::IntSub);
            if !self_op {
                for (k, v) in op.inputs.iter().enumerate() {
                    if v.space != SpaceId::REGISTER {
                        continue;
                    }
                    if !rax_dead && overlaps(v, rax, 8) {
                        return Site::Int;
                    }
                    // the upper lanes a scalar write keeps (`SUBPIECE(xmm0, 4)`) are no read
                    let upper = op.opcode == OpCode::Subpiece && k == 0 && op.inputs.get(1).is_some_and(|c| c.offset > 0);
                    if !xmm_dead && !upper && overlaps(v, xmm0, 8) {
                        return Site::Float(if v.size == 4 { 4 } else { 8 });
                    }
                }
            }
            if let Some(out) = &op.output {
                if out.space == rax.space && out.offset == rax.offset && out.size >= 4 {
                    rax_dead = true;
                }
                if out.space == xmm0.space && out.offset == xmm0.offset && out.size >= 4 {
                    xmm_dead = true;
                }
            }
        }
    }
    if rax_dead { Site::Void } else { Site::Unknown }
}

/// What the direct callers of `target` do with its result: `Int` / `Float` when some read
/// that register and none the other, `Void` when every caller that decides ignores it.
/// `None` without callers, a calling convention, or a consistent answer.
pub fn return_hint(lifter: &dyn PcodeLift, memory: &Memory, target: u64) -> Option<ReturnHint> {
    let cc = lifter.call_convention()?;
    let (rax, xmm0) = match cc.returns.as_slice() {
        [(r, _), (x, _), ..] => (*r, *x),
        _ => return None,
    };
    let (mut int, mut float, mut void, mut size) = (0, 0, 0, 0);
    for site in direct_call_sites(memory, target, MAX_SITES) {
        match site_verdict(lifter, memory, site, &rax, &xmm0) {
            Site::Int => int += 1,
            Site::Float(s) => {
                float += 1;
                size = size.max(s);
            }
            Site::Void => void += 1,
            Site::Unknown => {}
        }
    }
    match (int, float, void) {
        (i, 0, _) if i > 0 => Some(ReturnHint::Int),
        (0, f, _) if f > 0 => Some(ReturnHint::Float(size)),
        (0, 0, v) if v > 0 => Some(ReturnHint::Void),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reargo_loader::MemoryBlock;
    use std::sync::Arc;

    #[test]
    fn finds_rel32_calls_to_the_target() {
        // 0x1000: call 0x1010 ; 0x1005: e8 that lands elsewhere ; 0x100a: call 0x1010
        let code: Vec<u8> = vec![
            0xe8, 0x0b, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x90,
        ];
        let mut mem = Memory::new(SpaceId::RAM, reargo_core::address::Endian::Little);
        mem.add_block(MemoryBlock {
            name: ".text".into(),
            start: 0x1000,
            size: code.len() as u64,
            flags: MemoryFlags::READ | MemoryFlags::EXECUTE,
            data: Some(Arc::from(code)),
        });
        assert_eq!(direct_call_sites(&mem, 0x1010, 8), vec![0x1000, 0x100a]);
        assert_eq!(direct_call_sites(&mem, 0x1010, 1), vec![0x1000]);
    }
}
