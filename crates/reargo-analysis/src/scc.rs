//! Strongly-connected-component analysis over the call graph.
//!
//! Same idea as IDA's "Find recursive calls" view: collapse the call
//! graph into its strongly-connected components using Tarjan's
//! algorithm, then surface any SCC with more than one node (mutual
//! recursion) or one node with a self-loop (direct recursion). These
//! are the only call-graph cycles, so finding them is equivalent to
//! finding every recursive cluster in the binary.
//!
//! For each non-trivial component we emit:
//!
//! * A plate comment at every entry in the cluster:
//!   `recursive cluster: 3 funcs (with: foo, bar, baz)`.
//! * A `scc_<id>_funcs` property in `program.metadata` enumerating
//!   the cluster's members — useful for tooling that wants the
//!   structured form without re-walking the listing.
//!
//! Cost is O(V + E) on the call graph (≤ N_funcs); negligible
//! compared to the analyses that produced the graph in the first place.

use reargo_program::comments::CommentType;
use reargo_program::Program;

use crate::analyzer::{AnalysisError, AnalysisResult, Analyzer};
use crate::callgraph::CallGraph;

pub struct CallGraphSccAnalyzer;

impl Analyzer for CallGraphSccAnalyzer {
    fn name(&self) -> &str {
        "Call-Graph SCC"
    }
    fn description(&self) -> &str {
        "Finds strongly-connected components in the call graph (mutual / direct recursion)"
    }
    fn priority(&self) -> u32 {
        // After everything that affects function names / call_targets:
        // CRT recovery (~710), SignatureApplier (~700), CallSiteAnnotator
        // (~750). Same band as Complexity (900) so the post-analysis
        // metadata block is contiguous.
        910
    }
    fn analyze(&self, program: &mut Program) -> Result<AnalysisResult, AnalysisError> {
        let cg = CallGraph::build(program);
        // Filter to *cyclic* components only — a 1-node SCC is cyclic
        // only when the node has an edge to itself; the helper on
        // CallGraph handles that gate.
        let clusters = cg.recursive_clusters();

        let mut emitted_plates = 0usize;
        for (scc_id, members) in clusters.iter().enumerate() {
            let others_summary: String = members
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            for (addr, _name) in members {
                if program.comments.get(*addr, CommentType::Plate).is_some() {
                    continue;
                }
                program.comments.set(
                    *addr,
                    CommentType::Plate,
                    format!(
                        "recursive cluster: {} func{} (with: {})",
                        members.len(),
                        if members.len() == 1 { "" } else { "s" },
                        others_summary
                    ),
                );
                emitted_plates += 1;
            }
            program.metadata.set_property(
                format!("scc_{}_funcs", scc_id),
                others_summary,
            );
        }

        Ok(AnalysisResult {
            analyzer_name: self.name().into(),
            functions_found: clusters.len(),
            references_found: 0,
            instructions_decoded: emitted_plates,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_compiles() {
        let _ = CallGraphSccAnalyzer;
    }
}
