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

    /// Walk every path from any entry-point-like node to `target`,
    /// up to depth `max_depth`. An "entry-point-like node" here is
    /// any node with zero incoming edges (root of the callgraph
    /// for-est). Returns paths as a Vec of `(address, name)` pairs,
    /// target-first so the caller can print them as
    /// `target ← caller ← caller ← root`.
    ///
    /// Used by the `backtrace` CLI to answer "every way this
    /// function can be reached". DFS-style walk with a visited
    /// set per path to avoid cycles, and a hard cap on path count
    /// so a binary with a hub function doesn't blow up output.
    pub fn paths_to(&self, target: u64, max_depth: usize) -> Vec<Vec<(u64, String)>> {
        let Some(&tgt_idx) = self.addr_to_node.get(&target) else {
            return Vec::new();
        };
        const MAX_PATHS: usize = 256;
        let mut out: Vec<Vec<(u64, String)>> = Vec::new();
        let mut stack: Vec<(NodeIndex, Vec<NodeIndex>)> =
            vec![(tgt_idx, vec![tgt_idx])];
        while let Some((cur, path)) = stack.pop() {
            if out.len() >= MAX_PATHS {
                break;
            }
            let preds: Vec<NodeIndex> = self
                .graph
                .neighbors_directed(cur, petgraph::Direction::Incoming)
                .filter(|p| !path.contains(p))
                .collect();
            if preds.is_empty() || path.len() > max_depth {
                let owned: Vec<(u64, String)> = path
                    .iter()
                    .map(|i| {
                        let n = &self.graph[*i];
                        (n.address, n.name.clone())
                    })
                    .collect();
                out.push(owned);
                continue;
            }
            for p in preds {
                let mut next = path.clone();
                next.push(p);
                stack.push((p, next));
            }
        }
        out
    }

    /// Collect every node within `max_depth` (BFS hops, undirected)
    /// of `center`. Used by `callgraph --around <addr> --depth N`
    /// to slice a giant callgraph down to a navigable neighbourhood.
    pub fn neighborhood(&self, center: u64, max_depth: usize) -> Vec<(u64, String)> {
        let Some(&start) = self.addr_to_node.get(&center) else {
            return Vec::new();
        };
        let mut seen: std::collections::BTreeSet<NodeIndex> =
            std::collections::BTreeSet::new();
        let mut frontier: Vec<(NodeIndex, usize)> = vec![(start, 0)];
        while let Some((idx, depth)) = frontier.pop() {
            if !seen.insert(idx) {
                continue;
            }
            if depth >= max_depth {
                continue;
            }
            for n in self
                .graph
                .neighbors_directed(idx, petgraph::Direction::Outgoing)
                .chain(
                    self.graph
                        .neighbors_directed(idx, petgraph::Direction::Incoming),
                )
            {
                frontier.push((n, depth + 1));
            }
        }
        let mut out: Vec<(u64, String)> = seen
            .iter()
            .map(|i| {
                let n = &self.graph[*i];
                (n.address, n.name.clone())
            })
            .collect();
        out.sort_by_key(|(a, _)| *a);
        out
    }

    /// DOT export filtered to the given node set. Mirrors `to_dot`
    /// but only emits nodes / edges where both endpoints appear in
    /// `keep`. `keep` is a slice of `(address, name)` produced by
    /// `neighborhood`.
    pub fn to_dot_filtered(&self, keep: &[(u64, String)]) -> String {
        let keep_set: std::collections::BTreeSet<u64> =
            keep.iter().map(|(a, _)| *a).collect();
        let mut out =
            String::from("digraph callgraph_slice {\n    rankdir=LR;\n    node [shape=box];\n");
        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            if !keep_set.contains(&node.address) {
                continue;
            }
            out.push_str(&format!(
                "    n{} [label=\"{}\"];\n",
                idx.index(),
                node.name
            ));
        }
        for edge in self.graph.edge_indices() {
            let Some((src, dst)) = self.graph.edge_endpoints(edge) else {
                continue;
            };
            let src_addr = self.graph[src].address;
            let dst_addr = self.graph[dst].address;
            if !keep_set.contains(&src_addr) || !keep_set.contains(&dst_addr) {
                continue;
            }
            out.push_str(&format!("    n{} -> n{};\n", src.index(), dst.index()));
        }
        out.push_str("}\n");
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
