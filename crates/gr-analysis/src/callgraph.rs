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
