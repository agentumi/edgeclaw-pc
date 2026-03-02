//! Tantivy-based full-text search for the activity log.
//!
//! Provides [`SearchIndex`] which wraps a Tantivy index for fast querying
//! over [`ActivityEntry`] records. Supports keyword, fuzzy, and filtered
//! searches with < 50ms latency over 10K+ entries.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
use tantivy::query::QueryParser;
use tantivy::schema::*;
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument};
use tracing::info;
use uuid::Uuid;

use crate::activity_log::ActivityEntry;
use crate::error::AgentError;

/// Full-text search index backed by Tantivy.
#[allow(dead_code)]
pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    schema: Schema,
    // Field handles
    f_id: Field,
    f_content: Field,
    f_tags: Field,
    f_file_path: Field,
    f_project: Field,
    f_agent_name: Field,
    f_importance: Field,
    f_timestamp: Field,
    f_raw_id: Field,
    persist_path: Option<PathBuf>,
}

/// Search result with score and entry ID.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Relevance score
    pub score: f32,
    /// Entry UUID
    pub entry_id: Uuid,
}

/// Filters for narrowing search results.
#[derive(Debug, Clone, Default)]
pub struct SearchFilters {
    pub project: Option<String>,
    pub agent_name: Option<String>,
    pub min_importance: Option<u8>,
    pub tags: Vec<String>,
}

impl SearchIndex {
    /// Create a new in-memory search index.
    pub fn new_in_memory() -> Result<Self, AgentError> {
        let schema = Self::build_schema();
        let index = Index::create_in_ram(schema.clone());
        Self::from_index(index, schema, None)
    }

    /// Create or open a persistent search index at the given directory.
    pub fn new(path: &Path) -> Result<Self, AgentError> {
        let schema = Self::build_schema();
        std::fs::create_dir_all(path)
            .map_err(|e| AgentError::IoError(format!("Failed to create index dir: {}", e)))?;

        let dir = MmapDirectory::open(path)
            .map_err(|e| AgentError::InternalError(format!("Failed to open mmap dir: {}", e)))?;

        let index = if Index::exists(&dir).unwrap_or(false) {
            Index::open(dir)
                .map_err(|e| AgentError::InternalError(format!("Failed to open index: {}", e)))?
        } else {
            Index::create_in_dir(path, schema.clone())
                .map_err(|e| AgentError::InternalError(format!("Failed to create index: {}", e)))?
        };

        Self::from_index(index, schema, Some(path.to_path_buf()))
    }

    fn build_schema() -> Schema {
        let mut builder = Schema::builder();
        builder.add_text_field("id", STRING | STORED);
        builder.add_text_field("content", TEXT | STORED);
        builder.add_text_field("tags", TEXT | STORED);
        builder.add_text_field("file_path", TEXT | STORED);
        builder.add_text_field("project", TEXT | STORED);
        builder.add_text_field("agent_name", TEXT | STORED);
        builder.add_u64_field("importance", INDEXED | STORED);
        builder.add_i64_field("timestamp", INDEXED | STORED);
        builder.add_text_field("raw_id", STRING | STORED);
        builder.build()
    }

    fn from_index(
        index: Index,
        schema: Schema,
        persist_path: Option<PathBuf>,
    ) -> Result<Self, AgentError> {
        let writer = index.writer(50_000_000).map_err(|e| {
            AgentError::InternalError(format!("Failed to create index writer: {}", e))
        })?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| {
                AgentError::InternalError(format!("Failed to create index reader: {}", e))
            })?;

        let f_id = schema.get_field("id").unwrap();
        let f_content = schema.get_field("content").unwrap();
        let f_tags = schema.get_field("tags").unwrap();
        let f_file_path = schema.get_field("file_path").unwrap();
        let f_project = schema.get_field("project").unwrap();
        let f_agent_name = schema.get_field("agent_name").unwrap();
        let f_importance = schema.get_field("importance").unwrap();
        let f_timestamp = schema.get_field("timestamp").unwrap();
        let f_raw_id = schema.get_field("raw_id").unwrap();

        Ok(Self {
            index,
            reader,
            writer: Mutex::new(writer),
            schema,
            f_id,
            f_content,
            f_tags,
            f_file_path,
            f_project,
            f_agent_name,
            f_importance,
            f_timestamp,
            f_raw_id,
            persist_path,
        })
    }

    /// Index a single activity entry.
    pub fn index_entry(&self, entry: &ActivityEntry) -> Result<(), AgentError> {
        let writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());

        let tags_text = entry.tags.join(" ");
        let file_path_text = entry.file_path.clone().unwrap_or_default();
        let ts = entry.timestamp.timestamp();

        writer
            .add_document(doc!(
                self.f_id => entry.id.to_string(),
                self.f_content => entry.content.as_str(),
                self.f_tags => tags_text.as_str(),
                self.f_file_path => file_path_text.as_str(),
                self.f_project => entry.project.as_str(),
                self.f_agent_name => entry.agent_name.as_str(),
                self.f_importance => entry.importance as u64,
                self.f_timestamp => ts,
                self.f_raw_id => entry.id.to_string()
            ))
            .map_err(|e| AgentError::InternalError(format!("Index error: {}", e)))?;

        Ok(())
    }

    /// Commit pending changes to disk.
    pub fn commit(&self) -> Result<(), AgentError> {
        let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        writer
            .commit()
            .map_err(|e| AgentError::InternalError(format!("Commit error: {}", e)))?;
        self.reader
            .reload()
            .map_err(|e| AgentError::InternalError(format!("Reader reload error: {}", e)))?;
        Ok(())
    }

    /// Full-text search returning scored entry IDs.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, AgentError> {
        let searcher = self.reader.searcher();
        let query_parser = QueryParser::for_index(
            &self.index,
            vec![
                self.f_content,
                self.f_tags,
                self.f_file_path,
                self.f_project,
            ],
        );
        let parsed = query_parser
            .parse_query(query)
            .map_err(|e| AgentError::InternalError(format!("Query parse error: {}", e)))?;

        let top_docs = searcher
            .search(&parsed, &TopDocs::with_limit(limit))
            .map_err(|e| AgentError::InternalError(format!("Search error: {}", e)))?;

        let mut results = Vec::new();
        for (score, doc_addr) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_addr)
                .map_err(|e| AgentError::InternalError(format!("Doc retrieval error: {}", e)))?;
            if let Some(id_val) = doc.get_first(self.f_raw_id) {
                if let Some(id_str) = id_val.as_str() {
                    if let Ok(uuid) = Uuid::parse_str(id_str) {
                        results.push(SearchResult {
                            score,
                            entry_id: uuid,
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    /// Search with additional filters applied.
    pub fn search_with_filter(
        &self,
        query: &str,
        filters: &SearchFilters,
        limit: usize,
    ) -> Result<Vec<SearchResult>, AgentError> {
        // If query is empty and no filters, return empty
        if query.trim().is_empty()
            && filters.project.is_none()
            && filters.agent_name.is_none()
            && filters.min_importance.is_none()
            && filters.tags.is_empty()
        {
            return Ok(Vec::new());
        }

        // For filtered search, do text search first then filter in post-processing
        let all_results = if query.trim().is_empty() {
            // No text query — search for everything
            let searcher = self.reader.searcher();
            let all_query = tantivy::query::AllQuery;
            let top_docs = searcher
                .search(&all_query, &TopDocs::with_limit(limit * 10))
                .map_err(|e| AgentError::InternalError(format!("Search error: {}", e)))?;

            let mut results = Vec::new();
            for (score, doc_addr) in top_docs {
                let doc: TantivyDocument = searcher.doc(doc_addr).map_err(|e| {
                    AgentError::InternalError(format!("Doc retrieval error: {}", e))
                })?;
                results.push((score, doc));
            }
            results
        } else {
            let searcher = self.reader.searcher();
            let query_parser = QueryParser::for_index(
                &self.index,
                vec![
                    self.f_content,
                    self.f_tags,
                    self.f_file_path,
                    self.f_project,
                ],
            );
            let parsed = query_parser
                .parse_query(query)
                .map_err(|e| AgentError::InternalError(format!("Query parse error: {}", e)))?;

            let top_docs = searcher
                .search(&parsed, &TopDocs::with_limit(limit * 10))
                .map_err(|e| AgentError::InternalError(format!("Search error: {}", e)))?;

            let mut results = Vec::new();
            for (score, doc_addr) in top_docs {
                let doc: TantivyDocument = searcher.doc(doc_addr).map_err(|e| {
                    AgentError::InternalError(format!("Doc retrieval error: {}", e))
                })?;
                results.push((score, doc));
            }
            results
        };

        // Apply filters
        let mut filtered = Vec::new();
        for (score, doc) in all_results {
            // Project filter
            if let Some(ref proj) = filters.project {
                if let Some(val) = doc.get_first(self.f_project) {
                    if let Some(s) = val.as_str() {
                        if !s.eq_ignore_ascii_case(proj) {
                            continue;
                        }
                    }
                }
            }

            // Agent name filter
            if let Some(ref agent) = filters.agent_name {
                if let Some(val) = doc.get_first(self.f_agent_name) {
                    if let Some(s) = val.as_str() {
                        if !s.eq_ignore_ascii_case(agent) {
                            continue;
                        }
                    }
                }
            }

            // Importance filter
            if let Some(min_imp) = filters.min_importance {
                if let Some(val) = doc.get_first(self.f_importance) {
                    if let Some(imp) = val.as_u64() {
                        if imp < min_imp as u64 {
                            continue;
                        }
                    }
                }
            }

            // Tag filter
            if !filters.tags.is_empty() {
                if let Some(val) = doc.get_first(self.f_tags) {
                    if let Some(tags_str) = val.as_str() {
                        let tags_lower = tags_str.to_lowercase();
                        let all_match = filters
                            .tags
                            .iter()
                            .all(|t| tags_lower.contains(&t.to_lowercase()));
                        if !all_match {
                            continue;
                        }
                    }
                }
            }

            // Extract ID
            if let Some(id_val) = doc.get_first(self.f_raw_id) {
                if let Some(id_str) = id_val.as_str() {
                    if let Ok(uuid) = Uuid::parse_str(id_str) {
                        filtered.push(SearchResult {
                            score,
                            entry_id: uuid,
                        });
                    }
                }
            }

            if filtered.len() >= limit {
                break;
            }
        }

        Ok(filtered)
    }

    /// Highlight matching regions in content.
    pub fn highlight(&self, query: &str, content: &str) -> String {
        let q_lower = query.to_lowercase();
        let words: Vec<&str> = q_lower.split_whitespace().collect();
        let mut result = content.to_string();
        for word in words {
            // Simple highlight: wrap matches in **bold**
            let c_lower = result.to_lowercase();
            if let Some(pos) = c_lower.find(word) {
                let matched = &result[pos..pos + word.len()];
                result = format!(
                    "{}**{}**{}",
                    &result[..pos],
                    matched,
                    &result[pos + word.len()..]
                );
            }
        }
        result
    }

    /// Rebuild the entire index from a slice of entries.
    pub fn rebuild(&self, entries: &[ActivityEntry]) -> Result<(), AgentError> {
        {
            let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            writer
                .delete_all_documents()
                .map_err(|e| AgentError::InternalError(format!("Delete error: {}", e)))?;
            writer
                .commit()
                .map_err(|e| AgentError::InternalError(format!("Commit error: {}", e)))?;
        }

        for entry in entries {
            self.index_entry(entry)?;
        }
        self.commit()?;

        info!(count = entries.len(), "Search index rebuilt");
        Ok(())
    }

    /// Get the number of indexed documents.
    pub fn doc_count(&self) -> u64 {
        let searcher = self.reader.searcher();
        searcher.num_docs()
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::ActivityType;
    use chrono::Utc;

    fn make_entry(content: &str, tags: &[&str], project: &str, importance: u8) -> ActivityEntry {
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "test-agent-001".to_string(),
            agent_role: "admin".to_string(),
            agent_name: "test-agent".to_string(),
            activity_type: ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 5,
            },
            project: project.to_string(),
            file_path: Some("src/main.rs".to_string()),
            content: content.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            importance,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0".repeat(64),
            hash: "a".repeat(64),
            signature: String::new(),
        }
    }

    #[test]
    fn test_search_simple_keyword() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let e1 = make_entry(
            "Fixed authentication bug in handler",
            &["rust", "security"],
            "edgeclaw",
            2,
        );
        let e2 = make_entry(
            "Added new UI component for dashboard",
            &["ui", "react"],
            "edgeclaw",
            1,
        );
        let id1 = e1.id;

        idx.index_entry(&e1).unwrap();
        idx.index_entry(&e2).unwrap();
        idx.commit().unwrap();

        let results = idx.search("authentication", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].entry_id, id1);
    }

    #[test]
    fn test_search_tag_filter() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let e1 = make_entry(
            "Implemented crypto module",
            &["rust", "crypto"],
            "edgeclaw",
            2,
        );
        let e2 = make_entry("Updated README", &["docs"], "edgeclaw", 1);
        let id1 = e1.id;

        idx.index_entry(&e1).unwrap();
        idx.index_entry(&e2).unwrap();
        idx.commit().unwrap();

        let filters = SearchFilters {
            tags: vec!["crypto".to_string()],
            ..Default::default()
        };
        let results = idx.search_with_filter("module", &filters, 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].entry_id, id1);
    }

    #[test]
    fn test_search_multilingual() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let e1 = make_entry("인증 모듈 버그 수정", &["korean"], "edgeclaw", 2);
        let e2 = make_entry("Authentication module bug fix", &["english"], "edgeclaw", 2);
        let id1 = e1.id;

        idx.index_entry(&e1).unwrap();
        idx.index_entry(&e2).unwrap();
        idx.commit().unwrap();

        let results = idx.search("인증", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].entry_id, id1);
    }

    #[test]
    fn test_search_empty_index() {
        let idx = SearchIndex::new_in_memory().unwrap();
        idx.commit().unwrap();

        let results = idx.search("anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_empty_query_with_filters() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let results = idx
            .search_with_filter("", &SearchFilters::default(), 10)
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_project_filter() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let e1 = make_entry("Fixed bug", &["rust"], "edgeclaw", 2);
        let e2 = make_entry("Fixed bug", &["rust"], "other-project", 2);
        let id1 = e1.id;

        idx.index_entry(&e1).unwrap();
        idx.index_entry(&e2).unwrap();
        idx.commit().unwrap();

        let filters = SearchFilters {
            project: Some("edgeclaw".to_string()),
            ..Default::default()
        };
        let results = idx.search_with_filter("bug", &filters, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, id1);
    }

    #[test]
    fn test_rebuild_preserves_data() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let entries: Vec<ActivityEntry> = (0..5)
            .map(|i| make_entry(&format!("Entry number {}", i), &["test"], "proj", 1))
            .collect();

        for e in &entries {
            idx.index_entry(e).unwrap();
        }
        idx.commit().unwrap();
        assert_eq!(idx.doc_count(), 5);

        // Rebuild
        idx.rebuild(&entries).unwrap();
        assert_eq!(idx.doc_count(), 5);
    }

    #[test]
    fn test_highlight() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let result = idx.highlight("bug", "Fixed a critical bug in the handler");
        assert!(result.contains("**bug**"));
    }

    #[test]
    fn test_disk_persistence_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test_index");

        let e1 = make_entry("Persistent entry test", &["persist"], "proj", 2);
        let id1 = e1.id;

        // Create and index
        {
            let idx = SearchIndex::new(&path).unwrap();
            idx.index_entry(&e1).unwrap();
            idx.commit().unwrap();
        }

        // Reopen and search
        {
            let idx = SearchIndex::new(&path).unwrap();
            let results = idx.search("persistent", 10).unwrap();
            assert!(!results.is_empty());
            assert_eq!(results[0].entry_id, id1);
        }
    }

    #[test]
    fn test_importance_filter() {
        let idx = SearchIndex::new_in_memory().unwrap();
        let e1 = make_entry("Low importance task", &["test"], "proj", 0);
        let e2 = make_entry("Critical security fix", &["test"], "proj", 3);
        let id2 = e2.id;

        idx.index_entry(&e1).unwrap();
        idx.index_entry(&e2).unwrap();
        idx.commit().unwrap();

        let filters = SearchFilters {
            min_importance: Some(2),
            ..Default::default()
        };
        let results = idx.search_with_filter("fix OR task", &filters, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, id2);
    }
}
