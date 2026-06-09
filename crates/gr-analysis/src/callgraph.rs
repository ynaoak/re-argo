use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};

use gr_program::Program;

pub struct CallGraph {
    pub graph: DiGraph<CallNode, ()>,
    addr_to_node: HashMap<u64, NodeIndex>,
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub address: u64,
    pub name: String,
}

impl CallGraph {
    pub fn build(program: &Program) -> Self {
        let mut graph = DiGraph::new();
        let mut addr_to_node: HashMap<u64, NodeIndex> = HashMap::new();

        for func in program.listing.functions() {
            let idx = graph.add_node(CallNode {
                address: func.entry_point,
                name: func.name.clone(),
            });
            addr_to_node.insert(func.entry_point, idx);
        }

        for func in program.listing.functions() {
            if let Some(&caller_idx) = addr_to_node.get(&func.entry_point) {
                for &target in &func.call_targets {
                    if let Some(&callee_idx) = addr_to_node.get(&target)
                        && !graph.contains_edge(caller_idx, callee_idx) {
                            graph.add_edge(caller_idx, callee_idx, ());
                        }
                }
            }
        }

        Self {
            graph,
            addr_to_node,
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn callers_of(&self, address: u64) -> Vec<&CallNode> {
        let Some(&idx) = self.addr_to_node.get(&address) else {
            return Vec::new();
        };
        self.graph
            .neighbors_directed(idx, petgraph::Direction::Incoming)
            .map(|n| &self.graph[n])
            .collect()
    }

    pub fn callees_of(&self, address: u64) -> Vec<&CallNode> {
        let Some(&idx) = self.addr_to_node.get(&address) else {
            return Vec::new();
        };
        self.graph
            .neighbors_directed(idx, petgraph::Direction::Outgoing)
            .map(|n| &self.graph[n])
            .collect()
    }

    /// Strongly-connected components — Tarjan, one Vec per SCC,
    /// each entry a `(address, name)` pair. Trivial single-node
    /// components without self-loops are filtered out so callers
    /// get only the cyclic clusters.
    pub fn recursive_clusters(&self) -> Vec<Vec<(u64, String)>> {
        let mut out: Vec<Vec<(u64, String)>> = Vec::new();
        for component in petgraph::algo::tarjan_scc(&self.graph) {
            let cyclic = if component.len() == 1 {
                self.graph.contains_edge(component[0], component[0])
            } else {
                component.len() > 1
            };
            if !cyclic {
                continue;
            }
            let mut members: Vec<(u64, String)> = component
                .iter()
                .map(|&n| {
                    let node = &self.graph[n];
                    (node.address, node.name.clone())
                })
                .collect();
            members.sort_by_key(|(a, _)| *a);
            out.push(members);
        }
        out.sort_by_key(|m| m[0].0);
        out
    }

    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph callgraph {\n    rankdir=LR;\n    node [shape=box];\n");
        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            out.push_str(&format!(
                "    n{} [label=\"{}\"];\n",
                idx.index(),
                node.name
            ));
        }
        for edge in self.graph.edge_indices() {
            let Some((src, dst)) = self.graph.edge_endpoints(edge) else { continue };
            out.push_str(&format!("    n{} -> n{};\n", src.index(), dst.index()));
        }
        out.push_str("}\n");
        out
    }
}
