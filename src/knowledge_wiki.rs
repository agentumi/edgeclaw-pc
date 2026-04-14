//! Wiki Auto-Generator — MindVault 3-Layer Architecture (Layer 3 Support).
//!
//! Generates Markdown wiki pages from Knowledge Graph communities.
//! Each community gets a summary page with key facts, member nodes,
//! and cross-references (wikilinks). Also builds a concept index
//! for fast lookup.
//!
//! Port of MindVault's `wiki.py` to Rust.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::knowledge_graph::{EntityType, KnowledgeGraph};

/// A generated wiki page for a knowledge graph community.
#[derive(Debug, Clone)]
pub struct WikiPage {
    /// Page title (typically the community's dominant entity).
    pub title: String,
    /// Community ID from the knowledge graph.
    pub community_id: String,
    /// Full Markdown content.
    pub content: String,
    /// Extracted key facts from community members.
    pub key_facts: Vec<String>,
    /// Related page IDs (wikilinks).
    pub related_pages: Vec<String>,
}

/// Wiki generator that produces community-level Markdown pages.
pub struct WikiGenerator {
    /// Output directory for wiki files.
    output_dir: PathBuf,
    /// Concept → list of page filenames.
    concepts_index: HashMap<String, Vec<String>>,
}

impl WikiGenerator {
    /// Create a new wiki generator with the given output directory.
    pub fn new(output_dir: &Path) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
            concepts_index: HashMap::new(),
        }
    }

    /// Generate wiki pages for all communities in the knowledge graph.
    pub fn generate_wiki(&mut self, graph: &KnowledgeGraph) -> Vec<WikiPage> {
        let mut pages = Vec::new();

        for (community_id, member_ids) in graph.communities() {
            let page = self.generate_community_page(graph, community_id, member_ids);
            pages.push(page);
        }

        // Build concepts index
        self.concepts_index = Self::build_concepts_index(&pages);

        pages
    }

    /// Generate a wiki page for a single community.
    fn generate_community_page(
        &self,
        graph: &KnowledgeGraph,
        community_id: &str,
        member_ids: &[String],
    ) -> WikiPage {
        // Find the most prominent entity for the title
        let title = self.derive_title(graph, member_ids);

        // Categorize members by type
        let mut files = Vec::new();
        let mut functions = Vec::new();
        let mut structs = Vec::new();
        let mut modules = Vec::new();
        let mut concepts = Vec::new();
        let mut headers = Vec::new();

        for id in member_ids {
            if let Some(node) = graph.get_node(id) {
                match node.entity_type {
                    EntityType::File => files.push(node.label.clone()),
                    EntityType::Function | EntityType::Method => functions.push(node.label.clone()),
                    EntityType::Class => structs.push(node.label.clone()),
                    EntityType::Module => modules.push(node.label.clone()),
                    EntityType::Concept => concepts.push(node.label.clone()),
                    EntityType::Header => headers.push(node.label.clone()),
                    EntityType::Block => {}
                }
            }
        }

        // Build key facts
        let mut key_facts = Vec::new();
        if !files.is_empty() {
            key_facts.push(format!("{} source files", files.len()));
        }
        if !functions.is_empty() {
            key_facts.push(format!("{} functions/methods", functions.len()));
        }
        if !structs.is_empty() {
            key_facts.push(format!("{} types (struct/enum)", structs.len()));
        }
        if !modules.is_empty() {
            key_facts.push(format!("{} modules", modules.len()));
        }

        // Build Markdown content
        let mut content = String::new();
        content.push_str(&format!("# {}\n\n", title));
        content.push_str(&format!("Community: `{}`\n\n", community_id));

        // Key Facts section
        content.push_str("## Key Facts\n\n");
        for fact in &key_facts {
            content.push_str(&format!("- {}\n", fact));
        }
        content.push('\n');

        // Files section
        if !files.is_empty() {
            content.push_str("## Source Files\n\n");
            for f in &files {
                content.push_str(&format!("- `{}`\n", f));
            }
            content.push('\n');
        }

        // Types section
        if !structs.is_empty() {
            content.push_str("## Types\n\n");
            for s in &structs {
                content.push_str(&format!("- {}\n", s));
            }
            content.push('\n');
        }

        // Functions section
        if !functions.is_empty() {
            content.push_str("## Functions\n\n");
            for f in &functions {
                content.push_str(&format!("- {}\n", f));
            }
            content.push('\n');
        }

        // Modules section
        if !modules.is_empty() {
            content.push_str("## Modules\n\n");
            for m in &modules {
                content.push_str(&format!("- {}\n", m));
            }
            content.push('\n');
        }

        // Concepts / References
        let mut related_pages = Vec::new();
        if !concepts.is_empty() {
            content.push_str("## Related Concepts\n\n");
            for c in &concepts {
                content.push_str(&format!("- [[{}]]\n", c));
                related_pages.push(c.clone());
            }
            content.push('\n');
        }

        // Headers (if from markdown files)
        if !headers.is_empty() {
            content.push_str("## Sections\n\n");
            for h in &headers {
                content.push_str(&format!("- {}\n", h));
            }
            content.push('\n');
        }

        WikiPage {
            title,
            community_id: community_id.to_string(),
            content,
            key_facts,
            related_pages,
        }
    }

    /// Derive a title for a community from its members.
    fn derive_title(&self, graph: &KnowledgeGraph, member_ids: &[String]) -> String {
        // Prefer the first file node, then module, then anything
        for id in member_ids {
            if let Some(node) = graph.get_node(id) {
                if node.entity_type == EntityType::File {
                    return node.label.clone();
                }
            }
        }
        for id in member_ids {
            if let Some(node) = graph.get_node(id) {
                if node.entity_type == EntityType::Module {
                    return node.label.clone();
                }
            }
        }
        member_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "Unknown Community".to_string())
    }

    /// Build a concept cross-reference index: concept → [page filenames].
    pub fn build_concepts_index(pages: &[WikiPage]) -> HashMap<String, Vec<String>> {
        let mut index: HashMap<String, Vec<String>> = HashMap::new();

        for page in pages {
            let filename = format!("{}.md", slugify_id(&page.community_id));

            // Index by key facts keywords
            for fact in &page.key_facts {
                for word in fact.split_whitespace() {
                    let word_lower = word.to_lowercase();
                    if word_lower.len() > 2 {
                        index.entry(word_lower).or_default().push(filename.clone());
                    }
                }
            }

            // Index by related concepts
            for concept in &page.related_pages {
                index
                    .entry(concept.to_lowercase())
                    .or_default()
                    .push(filename.clone());
            }

            // Index by title
            for word in page.title.split_whitespace() {
                let w = word.to_lowercase();
                if w.len() > 2 {
                    index.entry(w).or_default().push(filename.clone());
                }
            }
        }

        index
    }

    /// Generate an INDEX.md entry page linking to all wiki pages.
    pub fn generate_index_page(&self, pages: &[WikiPage]) -> String {
        let mut content = String::from("# Knowledge Wiki Index\n\n");
        content.push_str(&format!("Generated from {} communities.\n\n", pages.len()));

        content.push_str("## Communities\n\n");
        for page in pages {
            let filename = slugify_id(&page.community_id);
            content.push_str(&format!(
                "- [{}]({}.md) — {}\n",
                page.title,
                filename,
                page.key_facts.join(", ")
            ));
        }

        content.push_str("\n## Concept Index\n\n");
        let mut concepts: Vec<_> = self.concepts_index.keys().collect();
        concepts.sort();
        for concept in concepts.iter().take(50) {
            if let Some(pages_list) = self.concepts_index.get(*concept) {
                content.push_str(&format!("- **{}**: {}\n", concept, pages_list.join(", ")));
            }
        }

        content
    }

    /// Write all wiki pages to disk.
    pub fn write_to_disk(&self, pages: &[WikiPage]) -> Result<usize, std::io::Error> {
        let wiki_dir = &self.output_dir;
        std::fs::create_dir_all(wiki_dir)?;

        for page in pages {
            let filename = format!("{}.md", slugify_id(&page.community_id));
            let filepath = wiki_dir.join(&filename);
            std::fs::write(&filepath, &page.content)?;
        }

        // Write INDEX.md
        let index_content = self.generate_index_page(pages);
        std::fs::write(wiki_dir.join("INDEX.md"), index_content)?;

        Ok(pages.len())
    }

    /// Get a reference to the concepts index.
    pub fn concepts_index(&self) -> &HashMap<String, Vec<String>> {
        &self.concepts_index
    }

    /// Read a wiki page content from disk by community ID.
    pub fn read_page(&self, community_id: &str) -> Option<String> {
        let filename = format!("{}.md", slugify_id(community_id));
        let filepath = self.output_dir.join(filename);
        std::fs::read_to_string(filepath).ok()
    }
}

/// Convert a community ID to a filename-safe slug.
fn slugify_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::{EdgeRelation, KnowledgeEdge, KnowledgeNode};

    fn build_test_graph() -> KnowledgeGraph {
        let mut kg = KnowledgeGraph::new();

        kg.add_node(KnowledgeNode {
            id: "file_main".into(),
            label: "src/main.rs".into(),
            entity_type: EntityType::File,
            source_file: Some("src/main.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "fn_main".into(),
            label: "fn main".into(),
            entity_type: EntityType::Function,
            source_file: Some("src/main.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "struct_config".into(),
            label: "struct Config".into(),
            entity_type: EntityType::Class,
            source_file: Some("src/main.rs".into()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_node(KnowledgeNode {
            id: "concept_auth".into(),
            label: "authentication".into(),
            entity_type: EntityType::Concept,
            source_file: None,
            metadata: HashMap::new(),
            community_id: None,
        });

        kg.add_edge(
            "file_main",
            "fn_main",
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
        kg.add_edge(
            "file_main",
            "struct_config",
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
        kg.add_edge(
            "fn_main",
            "concept_auth",
            KnowledgeEdge {
                relation: EdgeRelation::References,
                weight: 0.5,
            },
        );

        kg.detect_communities();
        kg
    }

    #[test]
    fn test_generate_wiki_pages() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);

        assert!(!pages.is_empty());
        let page = &pages[0];
        assert!(!page.title.is_empty());
        assert!(!page.content.is_empty());
        assert!(page.content.contains("# "));
        assert!(page.content.contains("Key Facts"));
    }

    #[test]
    fn test_wiki_page_contains_members() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);

        let page = &pages[0];
        // Should contain function and struct info
        assert!(page.content.contains("fn main") || page.content.contains("struct Config"));
    }

    #[test]
    fn test_concepts_index() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);

        let index = WikiGenerator::build_concepts_index(&pages);
        assert!(!index.is_empty());
    }

    #[test]
    fn test_generate_index_page() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);
        let index = gen.generate_index_page(&pages);

        assert!(index.contains("Knowledge Wiki Index"));
        assert!(index.contains("Communities"));
    }

    #[test]
    fn test_key_facts_populated() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);

        let page = &pages[0];
        // Graph has 1 file, 1 function, 1 struct → should have key facts
        assert!(!page.key_facts.is_empty());
    }

    #[test]
    fn test_slugify_id() {
        assert_eq!(slugify_id("community_0"), "community_0");
        assert_eq!(slugify_id("hello world!"), "hello_world_");
    }

    #[test]
    fn test_related_pages() {
        let graph = build_test_graph();
        let mut gen = WikiGenerator::new(Path::new("/tmp/test_wiki"));
        let pages = gen.generate_wiki(&graph);

        // concept_auth should appear in related pages
        let page = &pages[0];
        // authentication is a concept node, should be in related_pages
        assert!(
            page.related_pages.contains(&"authentication".to_string())
                || page.content.contains("authentication")
        );
    }
}
