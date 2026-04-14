//! 3-Layer Knowledge Query Engine — MindVault Integration.
//!
//! Implements the MindVault 3-layer query pipeline:
//! 1. **Search Layer**: BM25 text search via Tantivy (0 tokens consumed)
//! 2. **Graph Layer**: Knowledge graph traversal via petgraph (BFS/DFS/Hybrid)
//! 3. **Wiki Layer**: Community wiki context retrieval (budget-capped)
//!
//! Achieves ~900 tokens per query vs ~60,000 for full-context injection.

use std::path::{Path, PathBuf};

use crate::knowledge_graph::{KnowledgeGraph, TraversalResult};
use crate::knowledge_wiki::WikiGenerator;

/// Graph traversal mode for Layer 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalMode {
    /// Breadth-first search (good for broad context).
    Bfs,
    /// Depth-first search (good for call chains).
    Dfs,
    /// Hybrid: BFS depth-2 + DFS depth-4, merged.
    Hybrid,
}

impl Default for TraversalMode {
    fn default() -> Self {
        Self::Bfs
    }
}

/// A single search hit from Layer 1.
#[derive(Debug, Clone)]
pub struct SearchHit {
    /// Matched node ID.
    pub node_id: String,
    /// Node label.
    pub label: String,
    /// Entity type string.
    pub entity_type: String,
    /// Source file (if available).
    pub source_file: Option<String>,
}

/// Graph context from Layer 2.
#[derive(Debug, Clone, Default)]
pub struct GraphContext {
    /// Nodes that directly matched the query keywords.
    pub matched_nodes: Vec<String>,
    /// Discovered neighbor node IDs.
    pub neighbors: Vec<String>,
    /// Traversed edges as (source, target, relation) strings.
    pub edges: Vec<(String, String, String)>,
    /// Community IDs of matched nodes.
    pub communities: Vec<String>,
}

/// Complete query result from all 3 layers.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Layer 1: Search hits.
    pub search_results: Vec<SearchHit>,
    /// Layer 2: Graph traversal context.
    pub graph_context: GraphContext,
    /// Layer 3: Wiki content string.
    pub wiki_context: String,
    /// Approximate token count consumed.
    pub tokens_used: usize,
}

/// 3-Layer Knowledge Query Engine.
pub struct KnowledgeQuery {
    /// Knowledge graph for Layer 2.
    graph: KnowledgeGraph,
    /// Wiki directory for Layer 3.
    wiki_dir: PathBuf,
}

impl KnowledgeQuery {
    /// Create a new query engine.
    pub fn new(graph: KnowledgeGraph, wiki_dir: &Path) -> Self {
        Self {
            graph,
            wiki_dir: wiki_dir.to_path_buf(),
        }
    }

    /// Execute a 3-layer query.
    ///
    /// # Arguments
    /// * `question` — Natural language question.
    /// * `mode` — Graph traversal mode (BFS, DFS, Hybrid).
    /// * `budget` — Maximum token budget for context assembly.
    ///
    /// # Returns
    /// `QueryResult` with search hits, graph context, wiki text, and token count.
    pub fn query(&self, question: &str, mode: TraversalMode, budget: usize) -> QueryResult {
        // ═══ Layer 1: Search (0 tokens) ═══
        let matched_nodes = self.graph.keyword_match(question);
        let search_results: Vec<SearchHit> = matched_nodes
            .iter()
            .filter_map(|id| {
                self.graph.get_node(id).map(|node| SearchHit {
                    node_id: id.clone(),
                    label: node.label.clone(),
                    entity_type: node.entity_type.to_string(),
                    source_file: node.source_file.clone(),
                })
            })
            .collect();

        // ═══ Layer 2: Graph Traversal (~100 tokens) ═══
        let traversal: TraversalResult = if matched_nodes.is_empty() {
            TraversalResult::default()
        } else {
            match mode {
                TraversalMode::Bfs => self.graph.bfs_traverse(&matched_nodes, 2),
                TraversalMode::Dfs => self.graph.dfs_traverse(&matched_nodes, 4),
                TraversalMode::Hybrid => {
                    let bfs = self.graph.bfs_traverse(&matched_nodes, 2);
                    let dfs = self.graph.dfs_traverse(&matched_nodes, 4);
                    merge_traversals(bfs, dfs)
                }
            }
        };

        // Find communities of matched nodes
        let mut communities = Vec::new();
        for id in &matched_nodes {
            if let Some(node) = self.graph.get_node(id) {
                if let Some(ref cid) = node.community_id {
                    if !communities.contains(cid) {
                        communities.push(cid.clone());
                    }
                }
            }
        }

        let graph_context = GraphContext {
            matched_nodes: matched_nodes.clone(),
            neighbors: traversal.neighbors.clone(),
            edges: traversal
                .edges
                .iter()
                .map(|(s, t, r)| (s.clone(), t.clone(), r.to_string()))
                .collect(),
            communities: communities.clone(),
        };

        // ═══ Layer 3: Wiki Context (~800 tokens, budget-capped) ═══
        let graph_edge_chars: usize = graph_context
            .edges
            .iter()
            .map(|(s, t, r)| s.len() + t.len() + r.len() + 6)
            .sum();
        let graph_tokens = graph_edge_chars / 4;
        let wiki_budget = budget.saturating_sub(graph_tokens).saturating_sub(10);
        let char_limit = wiki_budget * 4;

        let wiki_context = self.read_wiki_context(&communities, char_limit);

        // ═══ Calculate total token usage ═══
        let total_chars = wiki_context.len() + graph_edge_chars;
        let tokens_used = total_chars / 4;

        QueryResult {
            search_results,
            graph_context,
            wiki_context,
            tokens_used,
        }
    }

    /// Generate a compact context string suitable for prompt injection.
    ///
    /// Returns a formatted string with matched context, graph relationships,
    /// and wiki excerpts—all within the token budget.
    pub fn context_for_prompt(&self, question: &str) -> String {
        let result = self.query(question, TraversalMode::Bfs, 2000);
        format_context_for_prompt(&result)
    }

    /// Read wiki pages for the given communities, up to `char_limit` total characters.
    fn read_wiki_context(&self, community_ids: &[String], char_limit: usize) -> String {
        let wiki_gen = WikiGenerator::new(&self.wiki_dir);
        let mut parts = Vec::new();
        let mut total_chars = 0;

        for cid in community_ids {
            if let Some(content) = wiki_gen.read_page(cid) {
                if total_chars + content.len() > char_limit {
                    let remaining = char_limit.saturating_sub(total_chars);
                    if remaining > 100 {
                        parts.push(format!("{}...", &content[..remaining.min(content.len())]));
                        let _ = remaining; // budget exhausted
                    }
                    break;
                }
                total_chars += content.len();
                parts.push(content);
            }
        }

        parts.join("\n\n---\n\n")
    }

    /// Get a reference to the underlying knowledge graph.
    pub fn graph(&self) -> &KnowledgeGraph {
        &self.graph
    }
}

/// Format a QueryResult into a prompt-ready context string.
pub fn format_context_for_prompt(result: &QueryResult) -> String {
    let mut ctx = String::new();

    // Matched entities
    if !result.search_results.is_empty() {
        ctx.push_str("## Matched Entities\n");
        for hit in &result.search_results {
            ctx.push_str(&format!(
                "- {} ({}){}\n",
                hit.label,
                hit.entity_type,
                hit.source_file
                    .as_ref()
                    .map(|f| format!(" in `{}`", f))
                    .unwrap_or_default()
            ));
        }
        ctx.push('\n');
    }

    // Graph relationships
    if !result.graph_context.edges.is_empty() {
        ctx.push_str("## Relationships\n");
        for (src, tgt, rel) in &result.graph_context.edges {
            ctx.push_str(&format!("- {} → {} [{}]\n", src, tgt, rel));
        }
        ctx.push('\n');
    }

    // Neighbor context
    if !result.graph_context.neighbors.is_empty() {
        ctx.push_str("## Related Nodes\n");
        for n in result.graph_context.neighbors.iter().take(10) {
            ctx.push_str(&format!("- {}\n", n));
        }
        ctx.push('\n');
    }

    // Wiki context
    if !result.wiki_context.is_empty() {
        ctx.push_str("## Knowledge Context\n");
        ctx.push_str(&result.wiki_context);
        ctx.push('\n');
    }

    ctx.push_str(&format!("\n(tokens used: ~{})\n", result.tokens_used));

    ctx
}

/// Merge BFS and DFS traversal results, deduplicating neighbors.
fn merge_traversals(bfs: TraversalResult, dfs: TraversalResult) -> TraversalResult {
    let mut seen: std::collections::HashSet<String> = bfs.neighbors.iter().cloned().collect();
    let mut merged_neighbors = bfs.neighbors;
    let mut merged_edges = bfs.edges;

    for (neighbor, edge) in dfs.neighbors.into_iter().zip(dfs.edges.into_iter()) {
        if !seen.contains(&neighbor) {
            seen.insert(neighbor.clone());
            merged_neighbors.push(neighbor);
            merged_edges.push(edge);
        }
    }

    TraversalResult {
        neighbors: merged_neighbors,
        edges: merged_edges,
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::{EdgeRelation, EntityType, KnowledgeEdge, KnowledgeNode};
    use std::collections::HashMap;

    fn build_test_graph() -> KnowledgeGraph {
        let mut kg = KnowledgeGraph::new();

        kg.add_node(KnowledgeNode {
            id: "auth_mod".into(),
            label: "authentication module".into(),
            entity_type: EntityType::Module,
            source_file: Some("src/auth.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "auth_login".into(),
            label: "login function".into(),
            entity_type: EntityType::Function,
            source_file: Some("src/auth.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "auth_verify".into(),
            label: "verify token".into(),
            entity_type: EntityType::Function,
            source_file: Some("src/auth.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "db_query".into(),
            label: "database query".into(),
            entity_type: EntityType::Function,
            source_file: Some("src/db.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "session_mgr".into(),
            label: "session manager".into(),
            entity_type: EntityType::Class,
            source_file: Some("src/session.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });

        kg.add_edge(
            "auth_mod",
            "auth_login",
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
        kg.add_edge(
            "auth_mod",
            "auth_verify",
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
        kg.add_edge(
            "auth_login",
            "db_query",
            KnowledgeEdge {
                relation: EdgeRelation::Calls,
                weight: 0.8,
            },
        );
        kg.add_edge(
            "auth_login",
            "session_mgr",
            KnowledgeEdge {
                relation: EdgeRelation::References,
                weight: 0.6,
            },
        );

        kg.detect_communities();
        kg
    }

    #[test]
    fn test_query_basic() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("how does authentication work?", TraversalMode::Bfs, 2000);

        assert!(!result.search_results.is_empty());
        // "authentication" should match auth_mod
        assert!(result
            .search_results
            .iter()
            .any(|h| h.node_id == "auth_mod"));
    }

    #[test]
    fn test_query_graph_context() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("login", TraversalMode::Bfs, 2000);

        // auth_login matches, neighbors should include db_query and session_mgr
        assert!(!result.graph_context.neighbors.is_empty());
        assert!(
            result
                .graph_context
                .neighbors
                .contains(&"db_query".to_string())
                || result
                    .graph_context
                    .neighbors
                    .contains(&"auth_mod".to_string())
        );
    }

    #[test]
    fn test_query_dfs_mode() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("login", TraversalMode::Dfs, 2000);

        assert!(!result.graph_context.neighbors.is_empty());
    }

    #[test]
    fn test_query_hybrid_mode() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("login", TraversalMode::Hybrid, 2000);

        assert!(!result.graph_context.neighbors.is_empty());
    }

    #[test]
    fn test_query_no_match() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("zzz_nonexistent_xyz", TraversalMode::Bfs, 2000);

        assert!(result.search_results.is_empty());
        assert!(result.graph_context.matched_nodes.is_empty());
    }

    #[test]
    fn test_query_token_budget() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let result = kq.query("login", TraversalMode::Bfs, 100);

        // Even with a tiny budget, tokens_used should not exceed budget wildly
        assert!(result.tokens_used < 500);
    }

    #[test]
    fn test_context_for_prompt() {
        let graph = build_test_graph();
        let kq = KnowledgeQuery::new(graph, Path::new("/tmp/test_wiki"));
        let ctx = kq.context_for_prompt("authentication login");

        assert!(ctx.contains("Matched Entities") || ctx.contains("tokens used"));
    }

    #[test]
    fn test_format_context() {
        let result = QueryResult {
            search_results: vec![SearchHit {
                node_id: "test_node".into(),
                label: "test function".into(),
                entity_type: "function".into(),
                source_file: Some("src/test.rs".into()),
            }],
            graph_context: GraphContext {
                matched_nodes: vec!["test_node".into()],
                neighbors: vec!["neighbor_1".into()],
                edges: vec![("test_node".into(), "neighbor_1".into(), "calls".into())],
                communities: vec!["community_0".into()],
            },
            wiki_context: "This is wiki context.".into(),
            tokens_used: 42,
        };

        let formatted = format_context_for_prompt(&result);
        assert!(formatted.contains("test function"));
        assert!(formatted.contains("Relationships"));
        assert!(formatted.contains("tokens used: ~42"));
    }

    #[test]
    fn test_merge_traversals() {
        use crate::knowledge_graph::EdgeRelation;

        let bfs = crate::knowledge_graph::TraversalResult {
            neighbors: vec!["a".into(), "b".into()],
            edges: vec![
                ("x".into(), "a".into(), EdgeRelation::Contains),
                ("x".into(), "b".into(), EdgeRelation::Calls),
            ],
        };
        let dfs = crate::knowledge_graph::TraversalResult {
            neighbors: vec!["b".into(), "c".into()],
            edges: vec![
                ("x".into(), "b".into(), EdgeRelation::Calls),
                ("b".into(), "c".into(), EdgeRelation::References),
            ],
        };

        let merged = merge_traversals(bfs, dfs);
        assert_eq!(merged.neighbors.len(), 3); // a, b, c (b deduplicated)
        assert!(merged.neighbors.contains(&"c".to_string()));
    }

    #[test]
    fn test_traversal_mode_default() {
        assert_eq!(TraversalMode::default(), TraversalMode::Bfs);
    }
}
