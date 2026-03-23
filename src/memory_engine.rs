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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LessonStore {
    pub lessons: Vec<Lesson>,
}

impl LessonStore {
    pub fn add_lesson(&mut self, lesson: Lesson) {
        self.lessons.push(lesson);
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
}
