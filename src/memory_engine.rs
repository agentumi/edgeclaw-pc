use crate::activity_log::{ActivityEntry, ActivityType};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// 에이전트의 성향 및 자아 (M0 CoreMemory)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SoulDefinition {
    pub content: String,
}

/// 사용자와의 관계 정의
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relationship {
    pub name: String,
    pub description: String,
}

/// 사용자 프로필 (M0 CoreMemory)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct UserProfile {
    pub name: String,
    pub preferences: HashMap<String, String>,
}

/// Phase 0: CoreMemory (M0)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CoreMemory {
    pub soul: SoulDefinition,
    pub user_profile: UserProfile,
    pub absolute_rules: Vec<String>,
    pub relationships: HashMap<String, Relationship>,
}

impl CoreMemory {
    pub fn update_soul(&mut self, content: &str) {
        self.soul.content = content.to_string();
    }

    pub fn set_user_profile(&mut self, name: &str, preferences: HashMap<String, String>) {
        self.user_profile.name = name.to_string();
        self.user_profile.preferences = preferences;
    }

    pub fn add_rule(&mut self, rule: &str) {
        if !self.absolute_rules.contains(&rule.to_string()) {
            self.absolute_rules.push(rule.to_string());
        }
    }

    pub fn remove_rule(&mut self, rule: &str) {
        self.absolute_rules.retain(|r| r != rule);
    }
}

/// Phase 0: 기억 계층 지정
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryTier {
    M30,
    M90,
    M365,
}

/// 시한성 기억 단위
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimedMemory {
    pub id: Uuid,
    pub content: String,
    pub source_activity_id: Option<Uuid>,
    pub tier: MemoryTier,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reference_count: u32,
    pub importance: u8,
}

impl TimedMemory {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now && self.reference_count == 0
    }

    pub fn increment_ref(&mut self) {
        self.reference_count += 1;
    }
}

/// Phase 0: TieredMemory (M30/M90/M365)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TieredMemory {
    pub m30: Vec<TimedMemory>,
    pub m90: Vec<TimedMemory>,
    pub m365: Vec<TimedMemory>,
}

impl TieredMemory {
    pub fn add_memory(&mut self, mem: TimedMemory) {
        match mem.tier {
            MemoryTier::M30 => self.m30.push(mem),
            MemoryTier::M90 => self.m90.push(mem),
            MemoryTier::M365 => self.m365.push(mem),
        }
    }

    pub fn clean_expired(&mut self, now: DateTime<Utc>) {
        self.m30.retain(|m| !m.is_expired(now));
        self.m90.retain(|m| !m.is_expired(now));
        self.m365.retain(|m| !m.is_expired(now));
    }

    pub fn promote_memories(&mut self) {
        // Promote M30 -> M90
        let mut to_promote_m90 = Vec::new();
        self.m30.retain(|m| {
            if m.reference_count >= 3 {
                let mut p = m.clone();
                p.tier = MemoryTier::M90;
                p.expires_at = Utc::now() + Duration::days(90);
                p.reference_count = 0; // reset
                to_promote_m90.push(p);
                false
            } else {
                true
            }
        });
        self.m90.extend(to_promote_m90);

        // Promote M90 -> M365
        let mut to_promote_m365 = Vec::new();
        self.m90.retain(|m| {
            if m.reference_count >= 5 {
                let mut p = m.clone();
                p.tier = MemoryTier::M365;
                p.expires_at = Utc::now() + Duration::days(365);
                p.reference_count = 0; // reset
                to_promote_m365.push(p);
                false
            } else {
                true
            }
        });
        self.m365.extend(to_promote_m365);
    }
}

/// Phase 0: 교훈 정의
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lesson {
    pub id: Uuid,
    pub pattern: String,
    pub source_errors: Vec<Uuid>,
    pub applied_count: u32,
    pub effectiveness: f64,
    /// P3-04: Domain this lesson applies to
    #[serde(default)]
    pub domain: String,
    /// P3-04: Success count when this lesson was applied
    #[serde(default)]
    pub success_count: u32,
    /// P3-04: Failure count when this lesson was applied
    #[serde(default)]
    pub failure_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LessonStore {
    pub lessons: Vec<Lesson>,
}

impl LessonStore {
    /// Add a new lesson to the store
    pub fn add_lesson(&mut self, lesson: Lesson) {
        self.lessons.push(lesson);
    }

    /// P3-04: Record a lesson application outcome (success or failure)
    /// Recalculates effectiveness = success_count / (success_count + failure_count)
    pub fn record_outcome(&mut self, lesson_id: &Uuid, success: bool) -> Option<f64> {
        if let Some(lesson) = self.lessons.iter_mut().find(|l| l.id == *lesson_id) {
            lesson.applied_count += 1;
            if success {
                lesson.success_count += 1;
            } else {
                lesson.failure_count += 1;
            }
            let total = lesson.success_count + lesson.failure_count;
            if total > 0 {
                lesson.effectiveness = lesson.success_count as f64 / total as f64;
            }
            Some(lesson.effectiveness)
        } else {
            None
        }
    }

    /// P3-04: Get top N most effective lessons, optionally filtered by domain
    pub fn top_effective(&self, n: usize, domain: Option<&str>) -> Vec<&Lesson> {
        let mut filtered: Vec<&Lesson> = self
            .lessons
            .iter()
            .filter(|l| {
                domain.is_none_or(|d| l.domain.eq_ignore_ascii_case(d) || l.domain.is_empty())
            })
            .collect();
        filtered.sort_by(|a, b| {
            b.effectiveness
                .partial_cmp(&a.effectiveness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        filtered.into_iter().take(n).collect()
    }

    /// P3-04: Decay old lessons with low application count and low effectiveness
    /// Removes lessons that have been applied >= min_trials times with effectiveness < threshold
    pub fn prune_ineffective(&mut self, threshold: f64, min_trials: u32) -> usize {
        let before = self.lessons.len();
        self.lessons
            .retain(|l| l.applied_count < min_trials || l.effectiveness >= threshold);
        before - self.lessons.len()
    }
}

/// Phase 6: Knowledge Base Item (Docs 학습용)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeItem {
    pub title: String,
    pub keywords: Vec<String>,
    pub summary: String,
    pub content: String,
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct KnowledgeBase {
    pub items: Vec<KnowledgeItem>,
}

impl KnowledgeBase {
    pub fn add_item(&mut self, item: KnowledgeItem) {
        self.items.push(item);
    }

    pub fn search(&self, input: &str) -> Vec<KnowledgeItem> {
        let input_lower = input.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.title.to_lowercase().contains(&input_lower)
                    || item
                        .keywords
                        .iter()
                        .any(|kw| input_lower.contains(&kw.to_lowercase()))
            })
            .cloned()
            .collect()
    }

    pub fn search_by_group(&self, group_id: &str) -> Vec<KnowledgeItem> {
        self.items
            .iter()
            .filter(|item| item.group_id.as_deref() == Some(group_id))
            .cloned()
            .collect()
    }
}

/// Phase 0: MemoryEngine 메인 구조체
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MemoryEngine {
    pub core: CoreMemory,
    pub tiers: TieredMemory,
    pub lessons: LessonStore,
    pub knowledge: KnowledgeBase,
}

// ─── P3-02: Memory Diff for P2P Synchronization ──────────────────────────────

/// A compact diff of memory changes for peer-to-peer sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiff {
    /// New memories added since last sync
    pub added_memories: Vec<TimedMemory>,
    /// IDs of memories deleted since last sync
    pub deleted_memory_ids: Vec<Uuid>,
    /// New lessons added since last sync
    pub added_lessons: Vec<Lesson>,
    /// Updated lesson effectiveness scores (lesson_id -> new_effectiveness)
    pub updated_effectiveness: Vec<(Uuid, f64)>,
    /// Timestamp of the diff generation
    pub generated_at: DateTime<Utc>,
    /// Source agent ID
    pub source_agent: String,
}

impl MemoryDiff {
    /// Create an empty diff
    pub fn empty(source_agent: &str) -> Self {
        Self {
            added_memories: Vec::new(),
            deleted_memory_ids: Vec::new(),
            added_lessons: Vec::new(),
            updated_effectiveness: Vec::new(),
            generated_at: Utc::now(),
            source_agent: source_agent.to_string(),
        }
    }

    /// Check if the diff has any changes
    pub fn is_empty(&self) -> bool {
        self.added_memories.is_empty()
            && self.deleted_memory_ids.is_empty()
            && self.added_lessons.is_empty()
            && self.updated_effectiveness.is_empty()
    }
}

// ─── P1-05: Persona ↔ Memory Bridge ───────────────────────────────────────────

/// Bridge data extracted from MemoryEngine for Persona synchronization
#[derive(Debug, Clone, Default)]
pub struct PersonaMemoryBridgeData {
    /// Domain → (completed_tasks, lessons_applied) mapping
    pub domain_stats: HashMap<String, (u32, u32)>,
    /// Top effective lesson patterns for system prompt enrichment
    pub top_lessons: Vec<String>,
}

impl MemoryEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// ActivityEntry -> TimedMemory 변환 및 중요도 자동 판별
    pub fn ingest_activity(&mut self, entry: &ActivityEntry) {
        let mut importance = entry.importance;
        let mut content = entry.content.clone();

        match &entry.activity_type {
            ActivityType::FileEdit { .. } => {
                if importance == 0 {
                    importance = 1;
                }
            }
            ActivityType::Decision { rationale, .. } => {
                importance = importance.max(2);
                content = format!("Decision: {}\nRationale: {}", entry.content, rationale);
            }
            ActivityType::Error { .. } => {
                importance = importance.max(2);
            }
            ActivityType::AiChat { .. } => {
                importance = importance.max(1);
            }
            _ => {}
        }

        if importance >= 2 {
            let expiration = if importance == 3
                || matches!(entry.activity_type, ActivityType::Decision { .. })
            {
                MemoryTier::M90
            } else {
                MemoryTier::M30
            };

            let expires_at = match expiration {
                MemoryTier::M30 => Utc::now() + Duration::days(30),
                MemoryTier::M90 => Utc::now() + Duration::days(90),
                MemoryTier::M365 => Utc::now() + Duration::days(365),
            };

            let mem = TimedMemory {
                id: Uuid::new_v4(),
                content,
                source_activity_id: Some(entry.id),
                tier: expiration,
                created_at: Utc::now(),
                expires_at,
                reference_count: 0,
                importance,
            };

            self.tiers.add_memory(mem);
        }
    }

    // ─── P3-02: Memory Diff Generation & Application ──────────

    /// Generate a diff of memories added after `since` timestamp
    pub fn generate_diff(&self, since: &DateTime<Utc>, source_agent: &str) -> MemoryDiff {
        let mut diff = MemoryDiff::empty(source_agent);

        // Collect memories created after `since`
        let collect = |mems: &[TimedMemory]| -> Vec<TimedMemory> {
            mems.iter()
                .filter(|m| m.created_at > *since)
                .cloned()
                .collect()
        };

        diff.added_memories.extend(collect(&self.tiers.m30));
        diff.added_memories.extend(collect(&self.tiers.m90));
        diff.added_memories.extend(collect(&self.tiers.m365));

        // Collect lesson effectiveness updates
        for lesson in &self.lessons.lessons {
            if lesson.applied_count > 0 {
                diff.updated_effectiveness
                    .push((lesson.id, lesson.effectiveness));
            }
        }

        diff
    }

    /// Apply a received diff from another agent
    pub fn apply_diff(&mut self, diff: &MemoryDiff) -> (usize, usize) {
        let mut memories_added = 0usize;
        let mut lessons_updated = 0usize;

        // Add new memories (skip duplicates by ID)
        let existing_ids: std::collections::HashSet<Uuid> = self
            .tiers
            .m30
            .iter()
            .chain(self.tiers.m90.iter())
            .chain(self.tiers.m365.iter())
            .map(|m| m.id)
            .collect();

        for mem in &diff.added_memories {
            if !existing_ids.contains(&mem.id) {
                self.tiers.add_memory(mem.clone());
                memories_added += 1;
            }
        }

        // Remove deleted memories
        for del_id in &diff.deleted_memory_ids {
            self.tiers.m30.retain(|m| m.id != *del_id);
            self.tiers.m90.retain(|m| m.id != *del_id);
            self.tiers.m365.retain(|m| m.id != *del_id);
        }

        // Merge lesson effectiveness (take higher value)
        for (lesson_id, new_eff) in &diff.updated_effectiveness {
            if let Some(lesson) = self.lessons.lessons.iter_mut().find(|l| l.id == *lesson_id) {
                if *new_eff > lesson.effectiveness {
                    lesson.effectiveness = *new_eff;
                    lessons_updated += 1;
                }
            }
        }

        // Add new lessons from diff
        let existing_lesson_ids: std::collections::HashSet<Uuid> =
            self.lessons.lessons.iter().map(|l| l.id).collect();
        for lesson in &diff.added_lessons {
            if !existing_lesson_ids.contains(&lesson.id) {
                self.lessons.add_lesson(lesson.clone());
                lessons_updated += 1;
            }
        }

        (memories_added, lessons_updated)
    }

    // ─── P1-05: Persona ↔ Memory Bridge ──────────────────────

    /// Extract domain statistics from lessons for Persona auto-sync
    pub fn extract_persona_bridge_data(&self) -> PersonaMemoryBridgeData {
        let mut data = PersonaMemoryBridgeData::default();

        // Aggregate domain stats from lessons
        for lesson in &self.lessons.lessons {
            let domain = if lesson.domain.is_empty() {
                "general"
            } else {
                &lesson.domain
            };
            let entry = data
                .domain_stats
                .entry(domain.to_string())
                .or_insert((0, 0));
            // Each lesson application counts as a "task" in that domain
            entry.0 += lesson.success_count;
            entry.1 += lesson.applied_count;
        }

        // Top 5 most effective lessons for system prompt enrichment
        data.top_lessons = self
            .lessons
            .top_effective(5, None)
            .iter()
            .map(|l| format!("{} (eff: {:.0}%)", l.pattern, l.effectiveness * 100.0))
            .collect();

        data
    }

    /// MEMORY.md 직렬화
    pub fn serialize_to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# EdgeClaw Agent Memory\n\n");
        md.push_str("## [M0] Core Soul\n");
        md.push_str(&format!("{}\n\n", self.core.soul.content));

        md.push_str("## [M0] Absolute Rules\n");
        for rule in &self.core.absolute_rules {
            md.push_str(&format!("- {}\n", rule));
        }
        md.push('\n');

        md.push_str("## Lessons\n");
        for lesson in &self.lessons.lessons {
            md.push_str(&format!(
                "- Pattern: {} (eff: {})\n",
                lesson.pattern, lesson.effectiveness
            ));
        }
        md.push('\n');

        md.push_str("## JSON Dump\n```json\n");
        if let Ok(json) = serde_json::to_string_pretty(&self) {
            md.push_str(&json);
        }
        md.push_str("\n```\n");
        md
    }

    /// MEMORY.md 역직렬화
    pub fn deserialize_from_markdown(md: &str) -> Option<Self> {
        let mut in_json = false;
        let mut json_str = String::new();

        for line in md.lines() {
            if line.starts_with("```json") {
                in_json = true;
                continue;
            } else if line.starts_with("```") && in_json {
                break;
            }
            if in_json {
                json_str.push_str(line);
                json_str.push('\n');
            }
        }

        serde_json::from_str(&json_str).ok()
    }

    /// Save the memory state to a markdown file.
    pub fn save_to_markdown_file(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.serialize_to_markdown())
    }

    /// Load the memory state from a markdown file.
    pub fn load_from_markdown_file(path: &Path) -> std::io::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path)?;
        Ok(Self::deserialize_from_markdown(&content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::ActivityType;

    fn make_lesson(pattern: &str, domain: &str, eff: f64, applied: u32) -> Lesson {
        Lesson {
            id: Uuid::new_v4(),
            pattern: pattern.to_string(),
            source_errors: vec![],
            applied_count: applied,
            effectiveness: eff,
            domain: domain.to_string(),
            success_count: (eff * applied as f64) as u32,
            failure_count: applied - (eff * applied as f64) as u32,
        }
    }

    #[test]
    fn test_core_memory_crud() {
        let mut core = CoreMemory::default();
        core.update_soul("I am EdgeClaw");
        assert_eq!(core.soul.content, "I am EdgeClaw");

        core.add_rule("Do no harm");
        assert!(core.absolute_rules.contains(&"Do no harm".to_string()));
        core.remove_rule("Do no harm");
        assert!(core.absolute_rules.is_empty());
    }

    #[test]
    fn test_tiered_memory_expiration() {
        let now = Utc::now();
        let mut tiers = TieredMemory::default();
        tiers.add_memory(TimedMemory {
            id: Uuid::new_v4(),
            content: "Temp".to_string(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: now,
            expires_at: now - Duration::days(1), // Past expiration
            reference_count: 0,
            importance: 2,
        });

        tiers.clean_expired(now);
        assert!(tiers.m30.is_empty());
    }

    #[test]
    fn test_tiered_memory_promotion() {
        let now = Utc::now();
        let mut tiers = TieredMemory::default();
        tiers.add_memory(TimedMemory {
            id: Uuid::new_v4(),
            content: "Promote me".to_string(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: now,
            expires_at: now + Duration::days(30),
            reference_count: 3,
            importance: 2,
        });

        tiers.promote_memories();
        assert!(tiers.m30.is_empty());
        assert_eq!(tiers.m90.len(), 1);
        assert_eq!(tiers.m90[0].content, "Promote me");
    }

    #[test]
    fn test_ingest_activity() {
        let mut engine = MemoryEngine::new();
        let entry = ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "agent".to_string(),
            agent_role: "admin".to_string(),
            agent_name: "name".to_string(),
            activity_type: ActivityType::Decision {
                title: "Refactor".into(),
                chosen: "Yes".into(),
                rationale: "Better perf".into(),
                alternatives: vec![],
            },
            project: "proj".to_string(),
            file_path: None,
            content: "Refactor".to_string(),
            tags: vec![],
            importance: 2,
            timestamp: Utc::now(),
            lamport_clock: 0,
            prev_hash: "".to_string(),
            hash: "".to_string(),
            signature: "".to_string(),
        };

        engine.ingest_activity(&entry);
        assert_eq!(engine.tiers.m90.len(), 1);
        assert!(engine.tiers.m90[0].content.contains("Better perf"));
    }

    #[test]
    fn test_markdown_serialization() {
        let mut engine = MemoryEngine::new();
        engine.core.update_soul("Testing Soul");
        engine.core.add_rule("Rule 1");
        engine.lessons.add_lesson(Lesson {
            id: Uuid::new_v4(),
            pattern: "Regex".to_string(),
            source_errors: vec![],
            applied_count: 1,
            effectiveness: 1.0,
            domain: String::new(),
            success_count: 1,
            failure_count: 0,
        });

        let md = engine.serialize_to_markdown();
        assert!(md.contains("Testing Soul"));
        assert!(md.contains("Rule 1"));
        assert!(md.contains("Regex"));

        let deserialized = MemoryEngine::deserialize_from_markdown(&md).unwrap();
        assert_eq!(deserialized.core.soul.content, "Testing Soul");
    }

    #[test]
    fn test_markdown_persistence_roundtrip() {
        let mut engine = MemoryEngine::new();
        engine.core.update_soul("Persisted Soul");
        engine.core.add_rule("Persisted Rule");
        engine.lessons.add_lesson(Lesson {
            id: Uuid::new_v4(),
            pattern: "Persisted Pattern".to_string(),
            source_errors: vec![],
            applied_count: 2,
            effectiveness: 0.9,
            domain: String::new(),
            success_count: 2,
            failure_count: 0,
        });

        let path = std::env::temp_dir().join(format!("edgeclaw_memory_{}.md", Uuid::new_v4()));
        engine.save_to_markdown_file(&path).unwrap();
        let loaded = MemoryEngine::load_from_markdown_file(&path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.core.soul.content, "Persisted Soul");
        assert!(loaded
            .core
            .absolute_rules
            .contains(&"Persisted Rule".to_string()));
        assert_eq!(loaded.lessons.lessons.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    // ─── P3-04: Lesson Effectiveness Tracking Tests ──────────

    #[test]
    fn test_lesson_record_outcome_success() {
        let mut store = LessonStore::default();
        let id = Uuid::new_v4();
        store.add_lesson(Lesson {
            id,
            pattern: "Retry on timeout".to_string(),
            source_errors: vec![],
            applied_count: 0,
            effectiveness: 0.0,
            domain: "devops".to_string(),
            success_count: 0,
            failure_count: 0,
        });

        // 3 successes, 1 failure → effectiveness = 3/4 = 0.75
        store.record_outcome(&id, true);
        store.record_outcome(&id, true);
        store.record_outcome(&id, true);
        store.record_outcome(&id, false);

        let lesson = &store.lessons[0];
        assert_eq!(lesson.applied_count, 4);
        assert_eq!(lesson.success_count, 3);
        assert_eq!(lesson.failure_count, 1);
        assert!((lesson.effectiveness - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_lesson_top_effective() {
        let mut store = LessonStore::default();
        store.add_lesson(make_lesson("Low", "rust", 0.3, 10));
        store.add_lesson(make_lesson("High", "rust", 0.95, 20));
        store.add_lesson(make_lesson("Mid", "python", 0.7, 15));

        let top = store.top_effective(2, Some("rust"));
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].pattern, "High");
        assert_eq!(top[1].pattern, "Low");
    }

    #[test]
    fn test_lesson_prune_ineffective() {
        let mut store = LessonStore::default();
        store.add_lesson(make_lesson("Bad", "general", 0.1, 20));
        store.add_lesson(make_lesson("Good", "general", 0.9, 20));
        store.add_lesson(make_lesson("New", "general", 0.0, 2)); // Too few trials

        let pruned = store.prune_ineffective(0.3, 10);
        assert_eq!(pruned, 1); // Only "Bad" removed
        assert_eq!(store.lessons.len(), 2);
        assert!(store.lessons.iter().any(|l| l.pattern == "Good"));
        assert!(store.lessons.iter().any(|l| l.pattern == "New"));
    }

    // ─── P3-02: Memory Diff Sync Tests ──────────

    #[test]
    fn test_generate_diff_filters_by_time() {
        let mut engine = MemoryEngine::new();
        let old_time = Utc::now() - Duration::hours(2);
        let recent_time = Utc::now();

        // Add an "old" memory
        engine.tiers.m30.push(TimedMemory {
            id: Uuid::new_v4(),
            content: "Old memory".to_string(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: old_time - Duration::hours(1),
            expires_at: Utc::now() + Duration::days(30),
            reference_count: 0,
            importance: 2,
        });

        // Add a "new" memory
        engine.tiers.m30.push(TimedMemory {
            id: Uuid::new_v4(),
            content: "New memory".to_string(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: recent_time,
            expires_at: Utc::now() + Duration::days(30),
            reference_count: 0,
            importance: 2,
        });

        let diff = engine.generate_diff(&old_time, "agent-a");
        assert_eq!(diff.added_memories.len(), 1);
        assert_eq!(diff.added_memories[0].content, "New memory");
    }

    #[test]
    fn test_apply_diff_merges_correctly() {
        let mut engine_a = MemoryEngine::new();
        let mut engine_b = MemoryEngine::new();

        // Agent A has a memory
        let mem_id = Uuid::new_v4();
        engine_a.tiers.m30.push(TimedMemory {
            id: mem_id,
            content: "Shared insight".to_string(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
            reference_count: 0,
            importance: 2,
        });

        // Generate diff and apply to B
        let since = Utc::now() - Duration::hours(1);
        let diff = engine_a.generate_diff(&since, "agent-a");
        let (added, _) = engine_b.apply_diff(&diff);
        assert_eq!(added, 1);
        assert_eq!(engine_b.tiers.m30.len(), 1);

        // Applying same diff again should not duplicate
        let (added2, _) = engine_b.apply_diff(&diff);
        assert_eq!(added2, 0);
    }

    #[test]
    fn test_diff_is_empty() {
        let diff = MemoryDiff::empty("test");
        assert!(diff.is_empty());
    }

    // ─── P1-05: Persona ↔ Memory Bridge Tests ──────────

    #[test]
    fn test_extract_persona_bridge_data() {
        let mut engine = MemoryEngine::new();
        engine
            .lessons
            .add_lesson(make_lesson("CI Pattern", "devops", 0.85, 20));
        engine
            .lessons
            .add_lesson(make_lesson("API Pattern", "devops", 0.70, 10));
        engine
            .lessons
            .add_lesson(make_lesson("Market Pattern", "marketing", 0.90, 15));

        let bridge = engine.extract_persona_bridge_data();
        assert!(bridge.domain_stats.contains_key("devops"));
        assert!(bridge.domain_stats.contains_key("marketing"));
        assert!(!bridge.top_lessons.is_empty());
    }
}
