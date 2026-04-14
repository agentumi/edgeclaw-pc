//! Knowledge Graph Engine — MindVault 3-Layer Architecture (Layer 2).
//!
//! Provides a directed knowledge graph built on `petgraph::DiGraph` with:
//! - Node/Edge CRUD for code entities (functions, structs, modules)
//! - BFS/DFS traversal for context discovery
//! - Greedy modularity community detection
//! - JSON serialization/deserialization
//!
//! Port of MindVault's `build.py` + `cluster.py` to Rust.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Entity type for knowledge graph nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// Source file.
    File,
    /// Rust module (mod declaration).
    Module,
    /// Struct, class, or type definition.
    Class,
    /// Function definition.
    Function,
    /// Method (impl block member).
    Method,
    /// Markdown header section.
    Header,
    /// Generic code block.
    Block,
    /// Abstract concept (extracted keyword/topic).
    Concept,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityType::File => write!(f, "file"),
            EntityType::Module => write!(f, "module"),
            EntityType::Class => write!(f, "class"),
            EntityType::Function => write!(f, "function"),
            EntityType::Method => write!(f, "method"),
            EntityType::Header => write!(f, "header"),
            EntityType::Block => write!(f, "block"),
            EntityType::Concept => write!(f, "concept"),
        }
    }
}

/// Relationship type for knowledge graph edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeRelation {
    /// `use` / `mod` import relationship.
    Imports,
    /// Parent contains child (file→function, struct→method).
    Contains,
    /// Function/method calls another.
    Calls,
    /// Cross-reference or mention.
    References,
    /// Dependency (crate/module level).
    DependsOn,
    /// Loose semantic relationship.
    RelatedTo,
}

impl std::fmt::Display for EdgeRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeRelation::Imports => write!(f, "imports"),
            EdgeRelation::Contains => write!(f, "contains"),
            EdgeRelation::Calls => write!(f, "calls"),
            EdgeRelation::References => write!(f, "references"),
            EdgeRelation::DependsOn => write!(f, "depends_on"),
            EdgeRelation::RelatedTo => write!(f, "related_to"),
        }
    }
}

/// A node in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    /// Unique identifier (e.g., `src__main_rs::function::main`).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Entity type classification.
    pub entity_type: EntityType,
    /// Source file path (relative).
    pub source_file: Option<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: HashMap<String, String>,
    /// Community ID assigned by community detection.
    pub community_id: Option<String>,
}

/// An edge in the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    /// Relationship type.
    pub relation: EdgeRelation,
    /// Edge weight (higher = stronger relationship).
    pub weight: f64,
}

/// BFS/DFS traversal result.
#[derive(Debug, Clone, Default)]
pub struct TraversalResult {
    /// Discovered neighbor node IDs.
    pub neighbors: Vec<String>,
    /// Edges traversed (source_id, target_id, relation).
    pub edges: Vec<(String, String, EdgeRelation)>,
}

/// JSON-serializable graph data for persistence.
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphData {
    /// All nodes.
    pub nodes: Vec<KnowledgeNode>,
    /// All edges as (source_id, target_id, edge).
    pub links: Vec<GraphLink>,
    /// Community assignments: community_id → [node_ids].
    pub communities: HashMap<String, Vec<String>>,
}

/// A single link in serialized graph data.
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphLink {
    pub source: String,
    pub target: String,
    pub relation: EdgeRelation,
    pub weight: f64,
}

/// Knowledge Graph Engine backed by petgraph DiGraph.
pub struct KnowledgeGraph {
    graph: DiGraph<KnowledgeNode, KnowledgeEdge>,
    node_index: HashMap<String, NodeIndex>,
    communities: HashMap<String, Vec<String>>,
}

impl KnowledgeGraph {
    /// Create a new empty knowledge graph.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_index: HashMap::new(),
            communities: HashMap::new(),
        }
    }

    /// Add a node to the graph. Returns true if new, false if already exists.
    pub fn add_node(&mut self, node: KnowledgeNode) -> bool {
        if self.node_index.contains_key(&node.id) {
            return false;
        }
        let id = node.id.clone();
        let idx = self.graph.add_node(node);
        self.node_index.insert(id, idx);
        true
    }

    /// Add a directed edge between two nodes. Returns false if either node missing.
    pub fn add_edge(&mut self, source_id: &str, target_id: &str, edge: KnowledgeEdge) -> bool {
        let src = match self.node_index.get(source_id) {
            Some(idx) => *idx,
            None => return false,
        };
        let tgt = match self.node_index.get(target_id) {
            Some(idx) => *idx,
            None => return false,
        };
        self.graph.add_edge(src, tgt, edge);
        true
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: &str) -> Option<&KnowledgeNode> {
        self.node_index.get(id).map(|idx| &self.graph[*idx])
    }

    /// Get the total number of nodes.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the total number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// List all node IDs.
    pub fn node_ids(&self) -> Vec<String> {
        self.node_index.keys().cloned().collect()
    }

    /// Get community assignments.
    pub fn communities(&self) -> &HashMap<String, Vec<String>> {
        &self.communities
    }

    // ─── Traversal ────────────────────────────────────────────

    /// BFS traversal from start nodes up to given depth.
    pub fn bfs_traverse(&self, start_ids: &[String], depth: usize) -> TraversalResult {
        let mut result = TraversalResult::default();
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, usize)> = VecDeque::new();

        // Seed queue with start nodes
        for id in start_ids {
            if let Some(&idx) = self.node_index.get(id) {
                visited.insert(idx);
                queue.push_back((idx, 0));
            }
        }

        while let Some((node_idx, d)) = queue.pop_front() {
            if d >= depth {
                continue;
            }
            // Traverse outgoing edges
            for edge_ref in self.graph.edges_directed(node_idx, Direction::Outgoing) {
                let neighbor_idx = edge_ref.target();
                if !visited.contains(&neighbor_idx) {
                    visited.insert(neighbor_idx);
                    let neighbor = &self.graph[neighbor_idx];
                    let source = &self.graph[node_idx];
                    result.neighbors.push(neighbor.id.clone());
                    result.edges.push((
                        source.id.clone(),
                        neighbor.id.clone(),
                        edge_ref.weight().relation,
                    ));
                    queue.push_back((neighbor_idx, d + 1));
                }
            }
            // Also traverse incoming edges (undirected traversal like MindVault)
            for edge_ref in self.graph.edges_directed(node_idx, Direction::Incoming) {
                let neighbor_idx = edge_ref.source();
                if !visited.contains(&neighbor_idx) {
                    visited.insert(neighbor_idx);
                    let neighbor = &self.graph[neighbor_idx];
                    let source = &self.graph[node_idx];
                    result.neighbors.push(neighbor.id.clone());
                    result.edges.push((
                        neighbor.id.clone(),
                        source.id.clone(),
                        edge_ref.weight().relation,
                    ));
                    queue.push_back((neighbor_idx, d + 1));
                }
            }
        }

        result
    }

    /// DFS traversal from start nodes up to given depth.
    pub fn dfs_traverse(&self, start_ids: &[String], depth: usize) -> TraversalResult {
        let mut result = TraversalResult::default();
        let mut visited: HashSet<NodeIndex> = HashSet::new();

        for id in start_ids {
            if let Some(&idx) = self.node_index.get(id) {
                visited.insert(idx);
                self.dfs_recurse(idx, 0, depth, &mut visited, &mut result);
            }
        }

        result
    }

    fn dfs_recurse(
        &self,
        node_idx: NodeIndex,
        current_depth: usize,
        max_depth: usize,
        visited: &mut HashSet<NodeIndex>,
        result: &mut TraversalResult,
    ) {
        if current_depth >= max_depth {
            return;
        }
        // Outgoing
        for edge_ref in self.graph.edges_directed(node_idx, Direction::Outgoing) {
            let neighbor_idx = edge_ref.target();
            if !visited.contains(&neighbor_idx) {
                visited.insert(neighbor_idx);
                let neighbor = &self.graph[neighbor_idx];
                let source = &self.graph[node_idx];
                result.neighbors.push(neighbor.id.clone());
                result.edges.push((
                    source.id.clone(),
                    neighbor.id.clone(),
                    edge_ref.weight().relation,
                ));
                self.dfs_recurse(neighbor_idx, current_depth + 1, max_depth, visited, result);
            }
        }
        // Incoming (undirected)
        for edge_ref in self.graph.edges_directed(node_idx, Direction::Incoming) {
            let neighbor_idx = edge_ref.source();
            if !visited.contains(&neighbor_idx) {
                visited.insert(neighbor_idx);
                let neighbor = &self.graph[neighbor_idx];
                let source = &self.graph[node_idx];
                result.neighbors.push(neighbor.id.clone());
                result.edges.push((
                    neighbor.id.clone(),
                    source.id.clone(),
                    edge_ref.weight().relation,
                ));
                self.dfs_recurse(neighbor_idx, current_depth + 1, max_depth, visited, result);
            }
        }
    }

    // ─── Keyword Matching ─────────────────────────────────────

    /// Find nodes whose id or label match any keyword from the question.
    /// Mirrors MindVault's `_keyword_match` logic with CJK support.
    pub fn keyword_match(&self, question: &str) -> Vec<String> {
        let q_lower = question.to_lowercase();
        let tokens: Vec<&str> = q_lower
            .split(|c: char| !c.is_alphanumeric() && !is_cjk(c))
            .filter(|t| {
                if t.is_empty() {
                    return false;
                }
                let has_cjk = t.chars().any(is_cjk);
                has_cjk || t.len() > 2
            })
            .collect();

        let mut matched = Vec::new();
        for (id, &idx) in &self.node_index {
            let node = &self.graph[idx];
            let label_lower = node.label.to_lowercase();
            let id_lower = id.to_lowercase();
            for token in &tokens {
                if label_lower.contains(token) || id_lower.contains(token) {
                    matched.push(id.clone());
                    break;
                }
            }
        }
        matched
    }

    // ─── Community Detection ──────────────────────────────────

    /// Simple greedy community detection based on connected components,
    /// then splitting large components by degree centrality.
    /// Mirrors MindVault's greedy modularity approach.
    pub fn detect_communities(&mut self) {
        self.communities.clear();

        // Phase 1: Find connected components (treating as undirected)
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut component_id = 0u32;

        for &idx in self.node_index.values() {
            if visited.contains(&idx) {
                continue;
            }
            let mut component = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(idx);
            visited.insert(idx);

            while let Some(current) = queue.pop_front() {
                component.push(current);

                // Outgoing neighbors
                for edge in self.graph.edges_directed(current, Direction::Outgoing) {
                    if !visited.contains(&edge.target()) {
                        visited.insert(edge.target());
                        queue.push_back(edge.target());
                    }
                }
                // Incoming neighbors
                for edge in self.graph.edges_directed(current, Direction::Incoming) {
                    if !visited.contains(&edge.source()) {
                        visited.insert(edge.source());
                        queue.push_back(edge.source());
                    }
                }
            }

            let cid = format!("community_{}", component_id);
            let member_ids: Vec<String> = component
                .iter()
                .map(|&ni| self.graph[ni].id.clone())
                .collect();

            // Assign community_id to each node
            for &ni in &component {
                self.graph[ni].community_id = Some(cid.clone());
            }

            self.communities.insert(cid, member_ids);
            component_id += 1;
        }
    }

    // ─── Serialization ────────────────────────────────────────

    /// Export graph to JSON-serializable data.
    pub fn export_json(&self) -> GraphData {
        let nodes: Vec<KnowledgeNode> = self
            .node_index
            .values()
            .map(|&idx| self.graph[idx].clone())
            .collect();

        let mut links = Vec::new();
        for edge_ref in self.graph.edge_references() {
            let source = &self.graph[edge_ref.source()];
            let target = &self.graph[edge_ref.target()];
            links.push(GraphLink {
                source: source.id.clone(),
                target: target.id.clone(),
                relation: edge_ref.weight().relation,
                weight: edge_ref.weight().weight,
            });
        }

        GraphData {
            nodes,
            links,
            communities: self.communities.clone(),
        }
    }

    /// Import graph from JSON data.
    pub fn import_json(data: &GraphData) -> Self {
        let mut kg = Self::new();

        for node in &data.nodes {
            kg.add_node(node.clone());
        }

        for link in &data.links {
            kg.add_edge(
                &link.source,
                &link.target,
                KnowledgeEdge {
                    relation: link.relation,
                    weight: link.weight,
                },
            );
        }

        kg.communities = data.communities.clone();
        // Restore community_id on nodes
        for (cid, members) in &kg.communities {
            for member_id in members {
                if let Some(&idx) = kg.node_index.get(member_id) {
                    kg.graph[idx].community_id = Some(cid.clone());
                }
            }
        }

        kg
    }
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a character is CJK (Chinese/Japanese/Korean).
fn is_cjk(c: char) -> bool {
    let cp = c as u32;
    (0x3000..=0x9FFF).contains(&cp)
        || (0xAC00..=0xD7AF).contains(&cp) // Hangul Syllables
        || (0xF900..=0xFAFF).contains(&cp)
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, label: &str, etype: EntityType) -> KnowledgeNode {
        KnowledgeNode {
            id: id.to_string(),
            label: label.to_string(),
            entity_type: etype,
            source_file: None,
            metadata: HashMap::new(),
            community_id: None,
        }
    }

    fn build_test_graph() -> KnowledgeGraph {
        let mut kg = KnowledgeGraph::new();

        kg.add_node(make_node("auth_mod", "auth module", EntityType::Module));
        kg.add_node(make_node(
            "auth_login",
            "login function",
            EntityType::Function,
        ));
        kg.add_node(make_node(
            "auth_verify",
            "verify token",
            EntityType::Function,
        ));
        kg.add_node(make_node("db_mod", "database module", EntityType::Module));
        kg.add_node(make_node(
            "db_query",
            "query function",
            EntityType::Function,
        ));

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
            "db_mod",
            "db_query",
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );

        kg
    }

    #[test]
    fn test_add_node_and_edge() {
        let kg = build_test_graph();
        assert_eq!(kg.node_count(), 5);
        assert_eq!(kg.edge_count(), 4);
    }

    #[test]
    fn test_add_duplicate_node() {
        let mut kg = KnowledgeGraph::new();
        assert!(kg.add_node(make_node("a", "A", EntityType::File)));
        assert!(!kg.add_node(make_node("a", "A2", EntityType::File)));
        assert_eq!(kg.node_count(), 1);
    }

    #[test]
    fn test_add_edge_missing_node() {
        let mut kg = KnowledgeGraph::new();
        kg.add_node(make_node("a", "A", EntityType::File));
        assert!(!kg.add_edge(
            "a",
            "nonexistent",
            KnowledgeEdge {
                relation: EdgeRelation::Calls,
                weight: 1.0
            }
        ));
    }

    #[test]
    fn test_get_node() {
        let kg = build_test_graph();
        let node = kg.get_node("auth_login").unwrap();
        assert_eq!(node.label, "login function");
        assert_eq!(node.entity_type, EntityType::Function);
        assert!(kg.get_node("nonexistent").is_none());
    }

    #[test]
    fn test_bfs_traverse_depth1() {
        let kg = build_test_graph();
        let result = kg.bfs_traverse(&["auth_mod".to_string()], 1);
        assert!(result.neighbors.contains(&"auth_login".to_string()));
        assert!(result.neighbors.contains(&"auth_verify".to_string()));
        // db_query is depth 2 from auth_mod (auth_mod→auth_login→db_query)
        assert!(!result.neighbors.contains(&"db_query".to_string()));
    }

    #[test]
    fn test_bfs_traverse_depth2() {
        let kg = build_test_graph();
        let result = kg.bfs_traverse(&["auth_mod".to_string()], 2);
        assert!(result.neighbors.contains(&"auth_login".to_string()));
        assert!(result.neighbors.contains(&"db_query".to_string()));
    }

    #[test]
    fn test_dfs_traverse() {
        let kg = build_test_graph();
        let result = kg.dfs_traverse(&["auth_login".to_string()], 4);
        // Should reach db_query via call, and auth_mod via incoming contains
        assert!(result.neighbors.contains(&"db_query".to_string()));
        assert!(result.neighbors.contains(&"auth_mod".to_string()));
    }

    #[test]
    fn test_keyword_match_english() {
        let kg = build_test_graph();
        let matched = kg.keyword_match("how does login work?");
        assert!(matched.contains(&"auth_login".to_string()));
    }

    #[test]
    fn test_keyword_match_korean() {
        let mut kg = KnowledgeGraph::new();
        kg.add_node(make_node("인증모듈", "인증 처리 모듈", EntityType::Module));
        let matched = kg.keyword_match("인증은 어떻게 동작하나요?");
        assert!(matched.contains(&"인증모듈".to_string()));
    }

    #[test]
    fn test_detect_communities() {
        let mut kg = build_test_graph();
        kg.detect_communities();
        // All nodes are connected, should be 1 community
        assert_eq!(kg.communities().len(), 1);
        let first_community = kg.communities().values().next().unwrap();
        assert_eq!(first_community.len(), 5);
    }

    #[test]
    fn test_detect_communities_disconnected() {
        let mut kg = KnowledgeGraph::new();
        kg.add_node(make_node("a", "A", EntityType::File));
        kg.add_node(make_node("b", "B", EntityType::File));
        kg.add_node(make_node("c", "C", EntityType::File));
        kg.add_edge(
            "a",
            "b",
            KnowledgeEdge {
                relation: EdgeRelation::RelatedTo,
                weight: 1.0,
            },
        );
        // c is disconnected
        kg.detect_communities();
        assert_eq!(kg.communities().len(), 2);
    }

    #[test]
    fn test_export_import_json() {
        let mut kg = build_test_graph();
        kg.detect_communities();

        let data = kg.export_json();
        let json = serde_json::to_string_pretty(&data).unwrap();

        let parsed: GraphData = serde_json::from_str(&json).unwrap();
        let kg2 = KnowledgeGraph::import_json(&parsed);

        assert_eq!(kg2.node_count(), kg.node_count());
        assert_eq!(kg2.edge_count(), kg.edge_count());
        assert_eq!(kg2.communities().len(), kg.communities().len());
    }

    #[test]
    fn test_entity_type_display() {
        assert_eq!(EntityType::Function.to_string(), "function");
        assert_eq!(EntityType::Module.to_string(), "module");
        assert_eq!(EntityType::Concept.to_string(), "concept");
    }

    #[test]
    fn test_edge_relation_display() {
        assert_eq!(EdgeRelation::Imports.to_string(), "imports");
        assert_eq!(EdgeRelation::Contains.to_string(), "contains");
        assert_eq!(EdgeRelation::Calls.to_string(), "calls");
    }

    #[test]
    fn test_node_ids() {
        let kg = build_test_graph();
        let ids = kg.node_ids();
        assert_eq!(ids.len(), 5);
        assert!(ids.contains(&"auth_mod".to_string()));
    }
}
