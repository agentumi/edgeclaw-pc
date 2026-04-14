//! Source Code & Document Ingestion Pipeline — MindVault Integration.
//!
//! Extracts structural information from Rust source files, Markdown documents,
//! and TOML configs to build the Knowledge Graph. Uses regex-based parsing
//! (no dependency on `syn` for compilation simplicity).
//!
//! Features:
//! - Rust: fn, struct, enum, impl, mod, use extraction
//! - Markdown: header hierarchy, wikilinks, code blocks
//! - TOML: dependency and key extraction
//! - SHA256-based incremental cache

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::AgentError;
use crate::knowledge_graph::{
    EdgeRelation, EntityType, KnowledgeEdge, KnowledgeGraph, KnowledgeNode,
};

/// Ingestion pipeline for building a knowledge graph from source files.
pub struct IngestPipeline {
    cache: IngestCache,
}

/// SHA256-based cache to skip unchanged files.
#[derive(Debug, Default)]
pub struct IngestCache {
    /// file path → SHA256 hex digest.
    file_hashes: HashMap<PathBuf, String>,
}

impl IngestCache {
    /// Check if a file has changed since last ingestion.
    pub fn is_changed(&self, path: &Path, content: &str) -> bool {
        let hash = sha256_hex(content);
        match self.file_hashes.get(path) {
            Some(old_hash) => old_hash != &hash,
            None => true,
        }
    }

    /// Record the hash for a file.
    pub fn record(&mut self, path: PathBuf, content: &str) {
        self.file_hashes.insert(path, sha256_hex(content));
    }

    /// Number of cached files.
    pub fn len(&self) -> usize {
        self.file_hashes.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.file_hashes.is_empty()
    }
}

impl IngestPipeline {
    /// Create a new ingestion pipeline.
    pub fn new() -> Self {
        Self {
            cache: IngestCache::default(),
        }
    }

    /// Ingest all supported files from a directory recursively.
    /// Returns the built knowledge graph.
    pub fn ingest_directory(&mut self, dir: &Path) -> Result<KnowledgeGraph, AgentError> {
        let mut kg = KnowledgeGraph::new();

        let entries = collect_files(dir)?;

        for path in &entries {
            let content = std::fs::read_to_string(path)
                .map_err(|e| AgentError::IoError(format!("read {}: {}", path.display(), e)))?;

            if !self.cache.is_changed(path, &content) {
                continue;
            }

            let rel_path = path
                .strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            match path.extension().and_then(|e| e.to_str()) {
                Some("rs") => ingest_rust_file(&rel_path, &content, &mut kg),
                Some("md") => ingest_markdown_file(&rel_path, &content, &mut kg),
                Some("toml") => ingest_toml_file(&rel_path, &content, &mut kg),
                _ => {}
            }

            self.cache.record(path.to_path_buf(), &content);
        }

        // Run community detection after full ingestion
        kg.detect_communities();

        Ok(kg)
    }

    /// Incremental update: only re-process changed files.
    /// Returns the number of files re-processed.
    pub fn incremental_update(
        &mut self,
        dir: &Path,
        kg: &mut KnowledgeGraph,
    ) -> Result<usize, AgentError> {
        let entries = collect_files(dir)?;
        let mut updated = 0;

        for path in &entries {
            let content = std::fs::read_to_string(path)
                .map_err(|e| AgentError::IoError(format!("read {}: {}", path.display(), e)))?;

            if !self.cache.is_changed(path, &content) {
                continue;
            }

            let rel_path = path
                .strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            match path.extension().and_then(|e| e.to_str()) {
                Some("rs") => ingest_rust_file(&rel_path, &content, kg),
                Some("md") => ingest_markdown_file(&rel_path, &content, kg),
                Some("toml") => ingest_toml_file(&rel_path, &content, kg),
                _ => {}
            }

            self.cache.record(path.to_path_buf(), &content);
            updated += 1;
        }

        if updated > 0 {
            kg.detect_communities();
        }

        Ok(updated)
    }

    /// Get a reference to the ingestion cache.
    pub fn cache(&self) -> &IngestCache {
        &self.cache
    }
}

impl Default for IngestPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Rust File Ingestion ─────────────────────────────────────

/// Extract knowledge nodes from a Rust source file via regex.
fn ingest_rust_file(rel_path: &str, content: &str, kg: &mut KnowledgeGraph) {
    let file_id = path_to_id(rel_path);

    // Add file node
    kg.add_node(KnowledgeNode {
        id: file_id.clone(),
        label: rel_path.to_string(),
        entity_type: EntityType::File,
        source_file: Some(rel_path.to_string()),
        metadata: HashMap::new(),
        community_id: None,
    });

    let fn_re =
        regex::Regex::new(r"(?m)^\s*(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+(\w+)").unwrap();
    let struct_re = regex::Regex::new(r"(?m)^\s*(?:pub(?:\(crate\))?\s+)?struct\s+(\w+)").unwrap();
    let enum_re = regex::Regex::new(r"(?m)^\s*(?:pub(?:\(crate\))?\s+)?enum\s+(\w+)").unwrap();
    let impl_re = regex::Regex::new(r"(?m)^\s*impl(?:<[^>]*>)?\s+(\w+)").unwrap();
    let mod_re = regex::Regex::new(r"(?m)^\s*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)").unwrap();
    let use_re = regex::Regex::new(r"(?m)^\s*use\s+([\w:]+)").unwrap();

    // Functions
    for cap in fn_re.captures_iter(content) {
        let name = &cap[1];
        let fn_id = format!("{}::fn::{}", file_id, name);
        kg.add_node(KnowledgeNode {
            id: fn_id.clone(),
            label: format!("fn {}", name),
            entity_type: EntityType::Function,
            source_file: Some(rel_path.to_string()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &fn_id,
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
    }

    // Structs
    for cap in struct_re.captures_iter(content) {
        let name = &cap[1];
        let struct_id = format!("{}::struct::{}", file_id, name);
        kg.add_node(KnowledgeNode {
            id: struct_id.clone(),
            label: format!("struct {}", name),
            entity_type: EntityType::Class,
            source_file: Some(rel_path.to_string()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &struct_id,
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
    }

    // Enums
    for cap in enum_re.captures_iter(content) {
        let name = &cap[1];
        let enum_id = format!("{}::enum::{}", file_id, name);
        kg.add_node(KnowledgeNode {
            id: enum_id.clone(),
            label: format!("enum {}", name),
            entity_type: EntityType::Class,
            source_file: Some(rel_path.to_string()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &enum_id,
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
    }

    // Impl blocks → References (struct ← impl)
    for cap in impl_re.captures_iter(content) {
        let name = &cap[1];
        let struct_id = format!("{}::struct::{}", file_id, name);
        // If the struct node exists, add a References edge from file
        if kg.get_node(&struct_id).is_some() {
            kg.add_edge(
                &file_id,
                &struct_id,
                KnowledgeEdge {
                    relation: EdgeRelation::References,
                    weight: 0.6,
                },
            );
        }
    }

    // Mod declarations
    for cap in mod_re.captures_iter(content) {
        let name = &cap[1];
        if name == "tests" {
            continue; // Skip test modules
        }
        let mod_id = format!("{}::mod::{}", file_id, name);
        kg.add_node(KnowledgeNode {
            id: mod_id.clone(),
            label: format!("mod {}", name),
            entity_type: EntityType::Module,
            source_file: Some(rel_path.to_string()),
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &mod_id,
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
    }

    // Use declarations → Imports edges
    for cap in use_re.captures_iter(content) {
        let path = &cap[1];
        let parts: Vec<&str> = path.split("::").collect();
        if parts.len() >= 2 {
            let import_label = parts.last().unwrap_or(&"");
            let import_id = format!("{}::import::{}", file_id, import_label);
            kg.add_node(KnowledgeNode {
                id: import_id.clone(),
                label: format!("use {}", path),
                entity_type: EntityType::Concept,
                source_file: Some(rel_path.to_string()),
                metadata: HashMap::new(),
                community_id: None,
            });
            kg.add_edge(
                &file_id,
                &import_id,
                KnowledgeEdge {
                    relation: EdgeRelation::Imports,
                    weight: 0.5,
                },
            );
        }
    }
}

// ─── Markdown File Ingestion ─────────────────────────────────

/// Extract knowledge nodes from a Markdown file.
fn ingest_markdown_file(rel_path: &str, content: &str, kg: &mut KnowledgeGraph) {
    let file_id = path_to_id(rel_path);

    kg.add_node(KnowledgeNode {
        id: file_id.clone(),
        label: rel_path.to_string(),
        entity_type: EntityType::File,
        source_file: Some(rel_path.to_string()),
        metadata: HashMap::new(),
        community_id: None,
    });

    let header_re = regex::Regex::new(r"(?m)^(#{1,6})\s+(.+)$").unwrap();
    let link_re = regex::Regex::new(r"\[\[([^\]]+)\]\]").unwrap();

    // Headers → section nodes
    for cap in header_re.captures_iter(content) {
        let level = cap[1].len();
        let title = cap[2].trim();
        let slug = slugify(title);
        let header_id = format!("{}::h{}::{}", file_id, level, slug);

        kg.add_node(KnowledgeNode {
            id: header_id.clone(),
            label: title.to_string(),
            entity_type: EntityType::Header,
            source_file: Some(rel_path.to_string()),
            metadata: {
                let mut m = HashMap::new();
                m.insert("level".to_string(), level.to_string());
                m
            },
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &header_id,
            KnowledgeEdge {
                relation: EdgeRelation::Contains,
                weight: 1.0,
            },
        );
    }

    // Wiki links → references
    for cap in link_re.captures_iter(content) {
        let target = &cap[1];
        let target_id = slugify(target);
        // Create a concept node for the linked target
        let concept_id = format!("concept::{}", target_id);
        kg.add_node(KnowledgeNode {
            id: concept_id.clone(),
            label: target.to_string(),
            entity_type: EntityType::Concept,
            source_file: None,
            metadata: HashMap::new(),
            community_id: None,
        });
        kg.add_edge(
            &file_id,
            &concept_id,
            KnowledgeEdge {
                relation: EdgeRelation::References,
                weight: 0.7,
            },
        );
    }
}

// ─── TOML File Ingestion ─────────────────────────────────────

/// Extract knowledge nodes from a TOML config file (dependencies, features).
fn ingest_toml_file(rel_path: &str, content: &str, kg: &mut KnowledgeGraph) {
    let file_id = path_to_id(rel_path);

    kg.add_node(KnowledgeNode {
        id: file_id.clone(),
        label: rel_path.to_string(),
        entity_type: EntityType::File,
        source_file: Some(rel_path.to_string()),
        metadata: HashMap::new(),
        community_id: None,
    });

    // Extract [dependencies] entries
    let dep_re = regex::Regex::new(r"(?m)^(\w[\w-]*)\s*=").unwrap();
    let in_deps = content.contains("[dependencies]");

    if in_deps {
        // Simple: extract key names after [dependencies]
        let deps_section = content
            .split("[dependencies]")
            .nth(1)
            .unwrap_or("")
            .split("\n[")
            .next()
            .unwrap_or("");

        for cap in dep_re.captures_iter(deps_section) {
            let dep_name = &cap[1];
            let dep_id = format!("dep::{}", dep_name);
            kg.add_node(KnowledgeNode {
                id: dep_id.clone(),
                label: format!("crate {}", dep_name),
                entity_type: EntityType::Concept,
                source_file: Some(rel_path.to_string()),
                metadata: HashMap::new(),
                community_id: None,
            });
            kg.add_edge(
                &file_id,
                &dep_id,
                KnowledgeEdge {
                    relation: EdgeRelation::DependsOn,
                    weight: 0.8,
                },
            );
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────

/// Collect all supported files (.rs, .md, .toml) recursively.
fn collect_files(dir: &Path) -> Result<Vec<PathBuf>, AgentError> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Err(AgentError::IoError(format!(
            "directory not found: {}",
            dir.display()
        )));
    }
    collect_files_recursive(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), AgentError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| AgentError::IoError(format!("read_dir {}: {}", dir.display(), e)))?;

    for entry in entries {
        let entry = entry.map_err(|e| AgentError::IoError(format!("dir entry: {}", e)))?;
        let path = entry.path();

        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip hidden dirs, target, node_modules, .git
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            collect_files_recursive(&path, files)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "rs" | "md" | "toml") {
                files.push(path);
            }
        }
    }
    Ok(())
}

/// Convert file path to a graph node ID.
fn path_to_id(path: &str) -> String {
    path.replace('/', "__")
        .replace('.', "_")
        .replace('\\', "__")
}

/// Convert text to a filesystem-safe slug.
fn slugify(text: &str) -> String {
    let lower = text.to_lowercase();
    let cleaned: String = lower
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_string();
    if trimmed.len() > 60 {
        trimmed[..60].to_string()
    } else {
        trimmed
    }
}

/// SHA256 hex digest of a string.
fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_rust_file() {
        let mut kg = KnowledgeGraph::new();
        let content = r#"
use std::collections::HashMap;

pub struct Config {
    name: String,
}

pub fn load_config() -> Config {
    Config { name: "test".into() }
}

pub async fn process(data: &[u8]) -> Result<(), Error> {
    Ok(())
}

mod helper {
    pub fn trim(s: &str) -> &str { s.trim() }
}
"#;
        ingest_rust_file("src/config.rs", content, &mut kg);

        // File node
        assert!(kg.get_node("src__config_rs").is_some());
        // Struct
        assert!(kg.get_node("src__config_rs::struct::Config").is_some());
        // Functions
        assert!(kg.get_node("src__config_rs::fn::load_config").is_some());
        assert!(kg.get_node("src__config_rs::fn::process").is_some());
        // Module
        assert!(kg.get_node("src__config_rs::mod::helper").is_some());
        // Import
        assert!(kg.get_node("src__config_rs::import::HashMap").is_some());

        assert!(kg.edge_count() > 0);
    }

    #[test]
    fn test_ingest_markdown_file() {
        let mut kg = KnowledgeGraph::new();
        let content = "# EdgeClaw Guide\n\n## Architecture\n\nSee [[auth module]] for auth.\n\n### Security\n\nZero trust.";
        ingest_markdown_file("docs/guide.md", content, &mut kg);

        assert!(kg.get_node("docs__guide_md").is_some());
        assert!(kg.get_node("docs__guide_md::h1::edgeclaw_guide").is_some());
        assert!(kg.get_node("docs__guide_md::h2::architecture").is_some());
        assert!(kg.get_node("docs__guide_md::h3::security").is_some());
        assert!(kg.get_node("concept::auth_module").is_some());
    }

    #[test]
    fn test_ingest_toml_file() {
        let mut kg = KnowledgeGraph::new();
        let content = r#"
[package]
name = "test"

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = "1"
"#;
        ingest_toml_file("Cargo.toml", content, &mut kg);

        assert!(kg.get_node("Cargo_toml").is_some());
        assert!(kg.get_node("dep::tokio").is_some());
        assert!(kg.get_node("dep::serde").is_some());
    }

    #[test]
    fn test_ingest_cache() {
        let mut cache = IngestCache::default();
        let content = "fn main() {}";
        let path = PathBuf::from("test.rs");

        assert!(cache.is_changed(&path, content));
        cache.record(path.clone(), content);
        assert!(!cache.is_changed(&path, content));
        assert!(cache.is_changed(&path, "fn main() { panic!() }"));
    }

    #[test]
    fn test_path_to_id() {
        assert_eq!(path_to_id("src/main.rs"), "src__main_rs");
        assert_eq!(path_to_id("Cargo.toml"), "Cargo_toml");
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Hello World!"), "hello_world_");
        assert_eq!(slugify("인증 모듈"), "인증_모듈");
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex("hello");
        assert_eq!(hash.len(), 64);
        // Deterministic
        assert_eq!(hash, sha256_hex("hello"));
        assert_ne!(hash, sha256_hex("world"));
    }

    #[test]
    fn test_ingest_directory_nonexistent() {
        let mut pipeline = IngestPipeline::new();
        let result = pipeline.ingest_directory(Path::new("/nonexistent/path/xyz"));
        assert!(result.is_err());
    }
}
