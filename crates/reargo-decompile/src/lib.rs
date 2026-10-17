/// `format!` of string pieces only (`{}` of `String` / `&str`), built at its final length:
/// `cat!(dst, " = ", a, ";")`.
macro_rules! cat {
    ($($e:expr),+ $(,)?) => {
        match [$(::core::convert::AsRef::<str>::as_ref(&$e)),+] {
            parts => {
                let mut s = String::with_capacity(parts.iter().map(|p| p.len()).sum::<usize>());
                for p in parts {
                    s.push_str(p);
                }
                s
            }
        }
    };
}

pub mod action;
pub mod callee_params;
pub mod callers;
pub mod classfields;
pub mod cas;
pub mod cast;
pub mod cfg;
pub mod condition;
pub mod copyprop;
pub mod comments_gen;
pub mod dataflow;
pub mod dominator;
pub mod effects;
pub mod emit;
pub mod exception;
pub mod flags;
pub mod fparity;
pub mod frame;
pub mod inline;
pub mod rust_emit;
pub mod noreturn;
pub mod optimize;
pub mod pipeline;
pub mod ranges;
pub mod rotate;
pub mod prototypes;
pub mod printer;
pub mod scope;
pub mod select;
pub mod semantic_diff;
pub mod swap;
pub mod switch;
pub mod ssa;
pub mod structs;
pub mod structure;
pub mod taint;
pub mod token;
pub mod typeinfer;
pub mod varrecovery;
pub mod thisclass;
pub mod vcall;

pub use pipeline::{
    analyze_taint, decompile, decompile_all, decompile_all_with_options, decompile_function, decompile_function_with_options, DecompileOptions, DecompileResult,
    DecompileStats, TaintReport,
};
pub use semantic_diff::{compare_programs, structural_hash, exact_hash, FunctionDiff, FunctionDiffKind};
pub use taint::{TaintEngine, TaintSink, TaintSinkKind};
pub use token::{Token, TokenDocument, TokenLine, TokenType};
pub use typeinfer::{InferredType, TypeInferenceEngine};
