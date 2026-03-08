use crate::memory_engine::MemoryEngine;
use crate::search::SearchResult;
use std::collections::HashMap;
use uuid::Uuid;

/// Mock Vector Database interface for Agent Memory
/// 추후 Sqlite-vss 내지 외부 vector DB(Qdrant 등) 연동을 위한 Trait/Struct
pub struct VectorStore {
    // [Memory ID -> Vector(Mock as String/Keywords for demo, actual would be Vec<f32>)]
    mock_store: HashMap<Uuid, String>,
}

impl Default for VectorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorStore {
    pub fn new() -> Self {
        Self {
            mock_store: HashMap::new(),
        }
    }

    pub fn insert_vector(&mut self, id: Uuid, _text: &str) {
        // 실제로는 임베딩 API (e.g., text-embedding-3-small) 를 호출해 벡터를 저장해야 함.
        self.mock_store.insert(id, _text.to_string());
    }

    /// Return mock similarity search result: (Uuid, vector_score (0.0~1.0))
    pub fn similarity_search(&self, _query: &str, _limit: usize) -> Vec<(Uuid, f32)> {
        // 실제 Vector Cosine Similarity 스코어 모의 반환
        let mut mock_results = Vec::new();
        // Return dummy data if mock_store is empty for test, else just some logic
        for (i, (id, _)) in self.mock_store.iter().enumerate().take(_limit) {
            let score = 1.0 - (i as f32 * 0.1);
            mock_results.push((*id, score.max(0.1)));
        }
        mock_results
    }
}

/// HybridSearchResult
#[derive(Debug, Clone, PartialEq)]
pub struct HybridSearchResult {
    pub id: Uuid,
    pub fts_score: f32,
    pub vector_score: f32,
    pub hybrid_score: f32,
}

/// 하이브리드 검색기 (FTS + Vector)
pub struct HybridSearch {
    pub vector_store: VectorStore,
    weight_fts: f32,
    weight_vec: f32,
}

impl Default for HybridSearch {
    fn default() -> Self {
        Self::new(0.6, 0.4)
    }
}

impl HybridSearch {
    pub fn new(weight_fts: f32, weight_vec: f32) -> Self {
        Self {
            vector_store: VectorStore::new(),
            weight_fts,
            weight_vec,
        }
    }

    /// FTS 점수(ActivityLog SearchIndex에서 나온)와 Vector 점수를 합산하여 정렬
    pub fn search(
        &self,
        query: &str,
        fts_raw_results: &[SearchResult],
        limit: usize,
    ) -> Vec<HybridSearchResult> {
        let fts_map: HashMap<Uuid, f32> = fts_raw_results
            .iter()
            .map(|r| (r.entry_id, r.score))
            .collect();

        // 1. Vector Search
        let vec_results = self
            .vector_store
            .similarity_search(query, fts_raw_results.len().max(10));
        let vec_map: HashMap<Uuid, f32> = vec_results.into_iter().collect();

        // 2. FTS와 Vector 유니온 ID 도출
        let mut unique_ids = Vec::new();
        for id in fts_map.keys() {
            if !unique_ids.contains(id) {
                unique_ids.push(*id);
            }
        }
        for id in vec_map.keys() {
            if !unique_ids.contains(id) {
                unique_ids.push(*id);
            }
        }

        // 3. FTS Normalize (max score 기준 정규화)
        let max_fts = fts_raw_results
            .iter()
            .map(|r| r.score)
            .fold(0.0_f32, |a, b| a.max(b));

        let mut hybrid_results = Vec::new();

        for id in unique_ids {
            let mut fts_norm_score = 0.0;
            if let Some(fs) = fts_map.get(&id) {
                if max_fts > 0.0 {
                    fts_norm_score = fs / max_fts; // 0.0 ~ 1.0 normalization
                }
            }

            let vec_score = vec_map.get(&id).copied().unwrap_or(0.0);

            let hybrid_score = (fts_norm_score * self.weight_fts) + (vec_score * self.weight_vec);
            hybrid_results.push(HybridSearchResult {
                id,
                fts_score: fts_norm_score,
                vector_score: vec_score,
                hybrid_score,
            });
        }

        hybrid_results.sort_by(|a, b| {
            b.hybrid_score
                .partial_cmp(&a.hybrid_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hybrid_results.into_iter().take(limit).collect()
    }
}

/// BootRitual: 에이전트 시작 시 주입되는 기억 컨텍스트 통합 로더
pub struct BootRitual;

impl BootRitual {
    pub fn execute(engine: &MemoryEngine) -> String {
        let mut context = String::new();

        // TIER 1: 항상 로드되는 Core Soul & 강력한 규칙들
        context.push_str("=== TIER 1: Core Identity ===\n");
        context.push_str(&engine.core.soul.content);
        context.push('\n');
        for rule in &engine.core.absolute_rules {
            context.push_str(&format!("- RULE: {}\n", rule));
        }

        // TIER 2: 주요 Lessons
        context.push_str("\n=== TIER 2: Active Lessons ===\n");
        for lesson in engine.lessons.lessons.iter().take(5) {
            context.push_str(&format!("- Remember: {}\n", lesson.pattern));
        }

        // TIER 3: 최신 M30 등 컨텍스트 (간략화)
        context.push_str("\n=== TIER 3: Recent Context ===\n");
        if let Some(latest) = engine.tiers.m30.last() {
            context.push_str(&format!("Last important memory: {}\n", latest.content));
        }

        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_search_scoring() {
        let mut hs = HybridSearch::new(0.6, 0.4);
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        // insert mock vectors
        hs.vector_store.insert_vector(id1, "doc 1 vector");
        hs.vector_store.insert_vector(id2, "doc 2 vector");

        let fts_results = vec![
            SearchResult {
                entry_id: id1,
                score: 10.0,
            },
            SearchResult {
                entry_id: id2,
                score: 5.0,
            },
        ];

        let results = hs.search("query", &fts_results, 5);
        assert_eq!(results.len(), 2);

        // id1 fts_norm = 10.0/10.0 = 1.0 -> 1.0 * 0.6 = 0.6
        // id1 vec_score (mocked) = 1.0 -> 1.0 * 0.4 = 0.4
        // total id1 = 1.0
        assert_eq!(results[0].id, id1);
        assert!(results[0].hybrid_score > results[1].hybrid_score);
    }

    #[test]
    fn test_boot_ritual() {
        let mut engine = MemoryEngine::default();
        engine.core.update_soul("I am EdgeClaw.");
        engine.core.add_rule("Do no harm.");

        let ctx = BootRitual::execute(&engine);
        assert!(ctx.contains("I am EdgeClaw."));
        assert!(ctx.contains("Do no harm."));
        assert!(ctx.contains("TIER 1"));
        assert!(ctx.contains("TIER 2"));
    }
}
