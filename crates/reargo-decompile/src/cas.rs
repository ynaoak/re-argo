//! `lock cmpxchg` as one compare-and-swap (WS89).
//!
//! The lifter models `cmpxchg [m], src` exactly: `t = *m; ZF = acc == t; *m = ZF ? src : t;
//! acc = ZF ? acc : t` (for a 32-bit operand `rax = ZF ? rax : (uint64_t)t`, the CPU keeps the
//! upper half when equal). Printed op by op that is five statements and a temporary:
//!
//! ```text
//! tmp_510 = *(uint64_t*)(r14 + 0x28);
//! var_206 = rax == tmp_510;
//! tmp_2030 = (rax == tmp_510) ? r13 : tmp_510;
//! rax = (rax == tmp_510) ? rax : tmp_510;
//! *(uint64_t*)(r14 + 0x28) = tmp_2030;
//! ```
//!
//! [`find`] recognises the group, and the emitters print it as the GCC builtin it is,
//! `var_206 = __atomic_compare_exchange((uint64_t*)(r14 + 0x28), &rax, r13);` — true and `*m =
//! src` when `*m` held `rax`, else false and `rax = *m` — at the store, the other ops hidden.
//! [`fold_into_conditions`] then moves a flag read only by the next `if` / `while` into it:
//! `if (__atomic_compare_exchange(…))`, `} while (!__atomic_compare_exchange(…));`.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::ssa::{OpIdx, SsaFunction, VarId};
use reargo_core::address::SpaceId;
use reargo_core::pcode::OpCode;

/// One `cmpxchg` on memory.
#[derive(Debug, Clone)]
pub(crate) struct Cas {
    /// the address (the store's)
    pub addr: VarId,
    /// the accumulator compared (`rax` / `eax`), before
    pub expected: VarId,
    /// the flag (ZF), when something reads it
    pub flag: Option<VarId>,
    /// the flag is read only by its block's branch, after the store (the statement may fold
    /// into the condition)
    pub branch: bool,
    /// the access width
    pub size: u32,
}

/// The `cmpxchg` groups of `func` by their store op, and the ops they hide.
pub(crate) fn find(func: &SsaFunction, noise: &FxHashSet<OpIdx>) -> (FxHashMap<OpIdx, Cas>, FxHashSet<OpIdx>) {
    let mut groups = FxHashMap::default();
    let mut hidden = FxHashSet::default();
    let def = |v: VarId| func.varnodes[v as usize].def_op.map(|d| &func.ops[d]).filter(|o| !o.dead);
    // (by value: every name of a value counts)
    let readers = crate::condition::Readers::new(func);
    let live_uses = |v: VarId| -> Vec<OpIdx> { readers.of(func, v).iter().copied().filter(|u| !noise.contains(u)).collect() };
    let same = |a: VarId, b: VarId| crate::condition::value_key(func, a) == crate::condition::value_key(func, b);
    for store in func.ops.iter().filter(|o| !o.dead && o.opcode == OpCode::Store && o.inputs.len() == 3) {
        let (addr, val) = (store.inputs[1], store.inputs[2]);
        // *m = ZF ? src : t
        let Some(sel) = def(val).filter(|o| o.opcode == OpCode::Select && o.address == store.address && o.inputs.len() == 3) else {
            continue;
        };
        let (flag, t) = (sel.inputs[0], sel.inputs[2]);
        // t = *m (the same address value)
        let Some(load) = def(t).filter(|o| o.opcode == OpCode::Load && o.address == store.address && o.inputs.get(1).is_some_and(|&a| same(a, addr))) else {
            continue;
        };
        let size = func.varnodes[t as usize].data.size;
        if !matches!(size, 4 | 8) {
            continue;
        }
        // ZF = acc == t
        let Some(eq) = def(flag).filter(|o| o.opcode == OpCode::IntEqual && o.address == store.address) else {
            continue;
        };
        let expected = match eq.inputs.as_slice() {
            [a, b] if same(*b, t) => *a,
            [a, b] if same(*a, t) => *b,
            _ => continue,
        };
        let acc = func.varnodes[expected as usize].data;
        if acc.space != SpaceId::REGISTER || acc.offset != 0 || acc.size != size {
            continue;
        }
        // rax = ZF ? rax : t  (32-bit: ZF ? rax : (uint64_t)t)
        let mut group = vec![store.index, sel.index, load.index, eq.index];
        let update = func.ops.iter().find(|o| {
            !o.dead
                && o.address == store.address
                && o.opcode == OpCode::Select
                && o.index != sel.index
                && o.inputs.first().is_some_and(|&f| same(f, flag))
                && o.output.is_some_and(|r| {
                    let d = func.varnodes[r as usize].data;
                    d.space == SpaceId::REGISTER && d.offset == 0 && d.size == 8
                })
        });
        let Some(update) = update else { continue };
        let old = update.inputs[2];
        if !same(old, t) {
            match def(old) {
                Some(z) if z.opcode == OpCode::IntZExt && z.inputs.first().is_some_and(|&x| same(x, t)) && live_uses(old) == [update.index] => {
                    group.push(z.index)
                }
                _ => continue,
            }
        }
        group.push(update.index);
        // nothing else reads the loaded value or the selected one
        if !live_uses(t).iter().all(|u| group.contains(u)) || live_uses(val) != [store.index] {
            continue;
        }
        // (a phi that nothing but phis reads is no reader: the flag around a loop)
        let flag_readers: Vec<OpIdx> =
            live_uses(flag).into_iter().filter(|u| !group.contains(u) && !unread_phi(func, &readers, *u, 0)).collect();
        // (a jump on `!ZF` reads it through a BOOL_NEGATE)
        let to_branch = |u: OpIdx| {
            let op = &func.ops[u];
            let here = op.block == store.block && u > store.index;
            here && (op.opcode == OpCode::CBranch
                || (op.opcode == OpCode::BoolNegate
                    && op.output.is_some_and(|o| matches!(live_uses(o).as_slice(), [b] if func.ops[*b].opcode == OpCode::CBranch && func.ops[*b].block == store.block))))
        };
        let branch = matches!(flag_readers.as_slice(), [b] if to_branch(*b));
        hidden.extend(group.iter().copied().filter(|&o| o != store.index));
        groups.insert(store.index, Cas { addr, expected, flag: (!flag_readers.is_empty()).then_some(flag), branch, size });
    }
    (groups, hidden)
}

/// Is op `u` a phi whose value only phis read (up to a depth)?
fn unread_phi(func: &SsaFunction, readers: &crate::condition::Readers, u: OpIdx, depth: u32) -> bool {
    let op = &func.ops[u];
    op.opcode == OpCode::MultiEqual
        && depth < 4
        && op.output.is_some_and(|o| readers.of(func, o).iter().all(|&r| r == u || unread_phi(func, readers, r, depth + 1)))
}

/// The builtin's call, from the texts of its operands.
pub(crate) fn call_text(ptr: &str, expected: &str, desired: &str) -> String {
    format!("__atomic_compare_exchange({ptr}, &{expected}, {desired})")
}

/// The condition lines a flag folds into, in C (`X` = the flag, then the call): as read, as
/// printed with the call.
pub(crate) const C_FORMS: &[(&str, &str)] =
    &[("if (X) {", "if (X) {"), ("if (!X) {", "if (!X) {"), ("} while (X);", "} while (X);"), ("} while (!X);", "} while (!X);")];
/// … and in the Rust output (where a `u8` flag reads `!= 0`).
pub(crate) const RUST_FORMS: &[(&str, &str)] =
    &[("if X {", "if X {"), ("if !X {", "if !X {"), ("if X != 0 {", "if X {"), ("if X == 0 {", "if !X {")];

/// Marks the end of a statement whose flag [`fold_into_conditions`] may move into the next
/// line's condition ([`Cas::branch`]); never left in the output.
pub(crate) const FOLDABLE: char = '\u{1}';

/// Move `x = __atomic_compare_exchange(…);` (marked [`FOLDABLE`]) into the condition of the
/// line after it when that line is one of `forms` (`if (x) {`, `} while (!x);`), and drop the
/// declaration of `x` (`decl`) when nothing else names it.
pub(crate) fn fold_into_conditions(text: &str, decl: &dyn Fn(&str) -> String, forms: &[(&str, &str)]) -> String {
    if !text.contains(FOLDABLE) {
        return text.to_string();
    }
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut folded_names: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(line) = lines[i].strip_suffix(FOLDABLE).map(str::to_string) else {
            i += 1;
            continue;
        };
        lines[i] = line.clone();
        let parsed = line.trim_start().split_once(" = ").map(|(n, c)| (n.to_string(), c.trim_end_matches(';').to_string()));
        let folded = parsed.as_ref().zip(lines.get(i + 1)).and_then(|((name, call), next)| {
            forms
                .iter()
                .map(|(from, to)| (from.replace('X', name), to.replace('X', call)))
                .find(|(from, _)| next.trim_start() == from)
                .map(|(_, to)| format!("{}{to}", &next[..next.len() - next.trim_start().len()]))
        });
        match (folded, parsed) {
            (Some(to), Some((name, _))) => {
                lines[i + 1] = to;
                lines.remove(i);
                folded_names.push(name);
            }
            _ => i += 1,
        }
    }
    for name in folded_names {
        let declaration = decl(&name);
        let named = lines.iter().filter(|l| names(l, &name)).count();
        let declared = lines.iter().position(|l| l.trim() == declaration);
        if let Some(d) = declared.filter(|_| named == 1) {
            lines.remove(d);
        }
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Does `line` name `name` (as a whole identifier)?
fn names(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(i, _)| {
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !ident(line[..i].chars().next_back()) && !ident(line[i + name.len()..].chars().next())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_read_by_the_next_condition_folds_into_it() {
        let decl = |n: &str| format!("uint8_t {n};");
        let text = "{\n    uint8_t var_206;\n    do {\n        var_206 = __atomic_compare_exchange((uint64_t*)rdi, &rax, rcx);\u{1}\n    } while (!var_206);\n}\n";
        let out = fold_into_conditions(text, &decl, C_FORMS);
        assert_eq!(out, "{\n    do {\n    } while (!__atomic_compare_exchange((uint64_t*)rdi, &rax, rcx));\n}\n");
        // another use of the register elsewhere keeps the declaration
        let text = "    uint8_t var_206;\n    var_206 = __atomic_compare_exchange((uint64_t*)rdi, &rax, rcx);\u{1}\n    if (var_206) {\n    var_206 = al == 0;\n";
        assert_eq!(
            fold_into_conditions(text, &decl, C_FORMS),
            "    uint8_t var_206;\n    if (__atomic_compare_exchange((uint64_t*)rdi, &rax, rcx)) {\n    var_206 = al == 0;\n"
        );
        // not followed by its condition: the statement stays (unmarked)
        let text = "    var_206 = __atomic_compare_exchange((uint64_t*)rdi, &rax, rcx);\u{1}\n    rax = 1;\n";
        assert_eq!(fold_into_conditions(text, &decl, C_FORMS), text.replace('\u{1}', ""));
        let decl = |n: &str| format!("let mut {n}: u8;");
        let text = "    let mut var_206: u8;\n    var_206 = __atomic_compare_exchange(rdi as *mut u64, &mut rax, rcx);\u{1}\n    if !var_206 {\n";
        assert_eq!(fold_into_conditions(text, &decl, RUST_FORMS), "    if !__atomic_compare_exchange(rdi as *mut u64, &mut rax, rcx) {\n");
        let text = "    var_206 = __atomic_compare_exchange(rdi as *mut u64, &mut rax, rcx);\u{1}\n    if var_206 != 0 {\n";
        assert_eq!(fold_into_conditions(text, &decl, RUST_FORMS), "    if __atomic_compare_exchange(rdi as *mut u64, &mut rax, rcx) {\n");
    }
}
