use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};

use reargo_program::Program;

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

    /// Walk every reverse-reachable path to `target`, up to depth
    /// `max_depth`, capped at `max_paths` complete paths. Each
    /// returned path terminates either at a zero-in-degree node
    /// (genuine callgraph root — entry point, library export,
    /// indirectly-called callback) or at the depth limit.
    ///
    /// Used by the `backtrace` CLI to answer "every way this
    /// function can be reached". DFS-style walk with a visited
    /// set per path so cycles can't blow the search up, and the
    /// caller-supplied `max_paths` cap so a hub function doesn't
    /// flood the output. Paths are returned target-first so the
    /// printer can render `target ← caller ← caller ← root` in
    /// reverse without re-allocating.
    pub fn paths_to(
        &self,
        target: u64,
        max_depth: usize,
        max_paths: usize,
    ) -> Vec<Vec<(u64, String)>> {
        let Some(&tgt_idx) = self.addr_to_node.get(&target) else {
            return Vec::new();
        };
        let mut out: Vec<Vec<(u64, String)>> = Vec::new();
        let mut stack: Vec<(NodeIndex, Vec<NodeIndex>)> =
            vec![(tgt_idx, vec![tgt_idx])];
        while let Some((cur, path)) = stack.pop() {
            if out.len() >= max_paths {
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

    /// Collect every node within `max_depth` hops of `center`, walking
    /// the call graph as undirected (both outgoing and incoming edges
    /// followed). Real BFS — VecDeque + pop_front so closer-hop nodes
    /// are explored before farther ones and the depth-cutoff is
    /// per-frontier-level rather than per-DFS-branch. The earlier
    /// implementation used a Vec + pop and was DFS in BFS clothing;
    /// the resulting set was identical but the walk order disagreed
    /// with the doc.
    pub fn neighborhood(&self, center: u64, max_depth: usize) -> Vec<(u64, String)> {
        let Some(&start) = self.addr_to_node.get(&center) else {
            return Vec::new();
        };
        let mut seen: std::collections::BTreeSet<NodeIndex> =
            std::collections::BTreeSet::new();
        let mut frontier: std::collections::VecDeque<(NodeIndex, usize)> =
            std::collections::VecDeque::new();
        frontier.push_back((start, 0));
        while let Some((idx, depth)) = frontier.pop_front() {
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
                frontier.push_back((n, depth + 1));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a hand-rolled CallGraph for testing without going through
    /// a full Program. The graph has the shape:
    ///
    ///   root1 → mid1 → leaf
    ///   root2 → mid2 → leaf
    ///   root2 → leaf            (skip-mid shortcut)
    ///   self_rec → self_rec     (self-loop)
    fn build_fixture() -> CallGraph {
        let mut graph: DiGraph<CallNode, ()> = DiGraph::new();
        let mut addr_to_node = HashMap::new();
        for (addr, name) in [
            (0x100u64, "root1"),
            (0x200, "mid1"),
            (0x300, "leaf"),
            (0x400, "root2"),
            (0x500, "mid2"),
            (0x600, "self_rec"),
        ] {
            let idx = graph.add_node(CallNode {
                address: addr,
                name: name.into(),
            });
            addr_to_node.insert(addr, idx);
        }
        let edge = |graph: &mut DiGraph<CallNode, ()>, a: u64, b: u64| {
            let ai = *addr_to_node.get(&a).unwrap();
            let bi = *addr_to_node.get(&b).unwrap();
            graph.add_edge(ai, bi, ());
        };
        edge(&mut graph, 0x100, 0x200);
        edge(&mut graph, 0x200, 0x300);
        edge(&mut graph, 0x400, 0x500);
        edge(&mut graph, 0x500, 0x300);
        edge(&mut graph, 0x400, 0x300);
        edge(&mut graph, 0x600, 0x600);
        CallGraph { graph, addr_to_node }
    }

    #[test]
    fn paths_to_leaf_includes_both_roots() {
        let cg = build_fixture();
        let paths = cg.paths_to(0x300, 6, 64);
        // Target-first: every path starts with the leaf.
        assert!(paths.iter().all(|p| p[0].0 == 0x300));
        // At least three distinct paths: root1→mid1→leaf,
        // root2→mid2→leaf, root2→leaf.
        let path_addrs: Vec<Vec<u64>> = paths
            .iter()
            .map(|p| p.iter().map(|(a, _)| *a).collect())
            .collect();
        assert!(path_addrs.contains(&vec![0x300, 0x200, 0x100]));
        assert!(path_addrs.contains(&vec![0x300, 0x500, 0x400]));
        assert!(path_addrs.contains(&vec![0x300, 0x400]));
    }

    #[test]
    fn paths_to_respects_max_depth() {
        let cg = build_fixture();
        let shallow = cg.paths_to(0x300, 1, 64);
        // depth=1 means we only walk one hop back from the target,
        // so paths_to either terminates at a direct caller (length 2)
        // or returns the standalone target (length 1).
        assert!(shallow.iter().all(|p| p.len() <= 2));
    }

    #[test]
    fn paths_to_respects_max_paths() {
        let cg = build_fixture();
        let paths = cg.paths_to(0x300, 6, 1);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn paths_to_handles_self_loop_without_infinite_recursion() {
        let cg = build_fixture();
        let paths = cg.paths_to(0x600, 6, 64);
        // The visited-set-per-path rule cuts the self-loop on the
        // first revisit, so the only path returned is the trivial
        // [target] one.
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 1);
    }

    #[test]
    fn paths_to_unknown_address_returns_empty() {
        let cg = build_fixture();
        assert!(cg.paths_to(0xdeadbeef, 6, 64).is_empty());
    }

    #[test]
    fn neighborhood_depth_zero_returns_only_center() {
        let cg = build_fixture();
        let n = cg.neighborhood(0x200, 0);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].0, 0x200);
    }

    #[test]
    fn neighborhood_depth_one_includes_immediate_neighbors() {
        let cg = build_fixture();
        let n = cg.neighborhood(0x200, 1);
        let addrs: Vec<u64> = n.iter().map(|(a, _)| *a).collect();
        // 0x200's direct neighbours: 0x100 (in) + 0x300 (out) + itself.
        assert!(addrs.contains(&0x100));
        assert!(addrs.contains(&0x200));
        assert!(addrs.contains(&0x300));
    }

    #[test]
    fn neighborhood_sorted_by_address() {
        let cg = build_fixture();
        let n = cg.neighborhood(0x300, 6);
        let addrs: Vec<u64> = n.iter().map(|(a, _)| *a).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted);
    }

    #[test]
    fn neighborhood_unknown_center_returns_empty() {
        let cg = build_fixture();
        assert!(cg.neighborhood(0xdeadbeef, 5).is_empty());
    }

    #[test]
    fn to_dot_filtered_omits_nodes_and_edges_outside_keep_set() {
        let cg = build_fixture();
        // Keep only leaf + root2 + mid2 — the shortcut edge
        // root2→leaf should appear; root1 should not.
        let keep = vec![
            (0x300u64, "leaf".into()),
            (0x400, "root2".into()),
            (0x500, "mid2".into()),
        ];
        let dot = cg.to_dot_filtered(&keep);
        assert!(dot.contains("digraph callgraph_slice"));
        assert!(dot.contains("\"leaf\""));
        assert!(dot.contains("\"root2\""));
        assert!(dot.contains("\"mid2\""));
        assert!(!dot.contains("\"root1\""));
        assert!(!dot.contains("\"mid1\""));
    }
}
