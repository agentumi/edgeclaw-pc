use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::activity_log::{ActivityEntry, ActivityType};
use crate::memory_engine::{Lesson, MemoryEngine};

/// MemoryDistiller config
#[derive(Debug, Clone)]
pub struct DistillerConfig {
    pub max_daily_memories: usize,
    pub repeat_error_threshold: usize,
}

impl Default for DistillerConfig {
    fn default() -> Self {
        Self {
            max_daily_memories: 50,
            repeat_error_threshold: 2, // 2번 이상 발생한 에러를 레슨으로 승격
        }
    }
}

/// 야간 증류기 (Nightly Distiller) 및 교훈 추출 기능 담당
pub struct NightlyDistiller {
    config: DistillerConfig,
}

impl NightlyDistiller {
    pub fn new(config: DistillerConfig) -> Self {
        Self { config }
    }

    /// 일일 이벤트를 분석하여 메모리 엔진에 `TimedMemory` 삽입 및 메모리 계층 승급/만료(distill) 실행
    pub fn distill_daily(
        &self,
        engine: &mut MemoryEngine,
        today_activities: &[ActivityEntry],
        now: DateTime<Utc>,
    ) {
        info!(
            "Starting nightly distillation for {} activities",
            today_activities.len()
        );

        // 1. 오래된/만료된 메모리 정리
        engine.tiers.clean_expired(now);

        // 2. 많이 활용된 메모리 승급 판정
        engine.tiers.promote_memories();

        // 3. 오늘의 이벤트 중 의미 있는 것만 추출하여 메모리에 넣기
        self.ingest_important_activities(engine, today_activities);

        // 4. 교훈(Lesson) 추출 (반복된 에러 패턴)
        self.extract_lessons(engine, today_activities);

        info!("Nightly distillation completed.");
    }

    /// ActivityEntry 중 importance 필터링 후 잉제스트
    fn ingest_important_activities(&self, engine: &mut MemoryEngine, activities: &[ActivityEntry]) {
        let mut count = 0;
        for activity in activities {
            if activity.importance >= 2 {
                engine.ingest_activity(activity);
                count += 1;

                if count >= self.config.max_daily_memories {
                    break;
                }
            }
        }
    }

    /// 며칠 간의(혹은 일일) 에러 로그를 분석하여 반복되는 에러인지 확인 후 교훈으로 만듦
    fn extract_lessons(&self, engine: &mut MemoryEngine, activities: &[ActivityEntry]) {
        // [Error Message -> (Count, Vec<Activity_ID>)]
        let mut error_counts: HashMap<String, (usize, Vec<Uuid>)> = HashMap::new();

        for activity in activities {
            if let ActivityType::Error { message, .. } = &activity.activity_type {
                // 단순화를 위해 에러 메시지 첫 50글자를 키로 사용 (정규화 가정)
                let key = if message.len() > 50 {
                    &message[..50]
                } else {
                    message.as_str()
                };
                let key_safe = key.to_string();

                let entry = error_counts.entry(key_safe).or_insert((0, Vec::new()));
                entry.0 += 1;
                entry.1.push(activity.id);
            }
        }

        for (pattern, (count, ids)) in error_counts {
            if count >= self.config.repeat_error_threshold {
                // 이미 동일 패턴의 레슨이 있는지 확인 (간단하게 포함 여부만 확인)
                let exists = engine
                    .lessons
                    .lessons
                    .iter()
                    .any(|l| l.pattern.contains(&pattern));

                if !exists {
                    let new_lesson = Lesson {
                        id: Uuid::new_v4(),
                        pattern: format!("Repeated Error: {}", pattern),
                        source_errors: ids,
                        applied_count: 0,
                        effectiveness: 1.0, // base effectiveness
                    };
                    engine.lessons.add_lesson(new_lesson);
                    info!("New lesson extracted: {}", pattern);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_engine::{MemoryTier, TimedMemory};
    use chrono::Duration;

    #[test]
    fn test_distill_cleans_and_promotes() {
        let mut engine = MemoryEngine::default();
        let now = Utc::now();

        engine.tiers.add_memory(TimedMemory {
            id: Uuid::new_v4(),
            content: "expired data".into(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: now,
            expires_at: now - Duration::days(1),
            reference_count: 0,
            importance: 1,
        });

        engine.tiers.add_memory(TimedMemory {
            id: Uuid::new_v4(),
            content: "good data".into(),
            source_activity_id: None,
            tier: MemoryTier::M30,
            created_at: now,
            expires_at: now + Duration::days(10),
            reference_count: 5, // ready to promote to M90
            importance: 1,
        });

        let distiller = NightlyDistiller::new(DistillerConfig::default());
        distiller.distill_daily(&mut engine, &[], now);

        assert_eq!(engine.tiers.m30.len(), 0);
        assert_eq!(engine.tiers.m90.len(), 1);
        assert_eq!(engine.tiers.m90[0].content, "good data");
    }

    #[test]
    fn test_extract_lessons() {
        let mut engine = MemoryEngine::default();
        let mut activities = vec![];

        // 3 duplicated errors
        for _ in 0..3 {
            activities.push(ActivityEntry {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                agent_id: "agent".into(),
                agent_role: "admin".into(),
                agent_name: "name".into(),
                activity_type: ActivityType::Error {
                    severity: 3,
                    message: "Connection Timeout to DB".into(),
                    stack_trace: None,
                    resolved: false,
                },
                project: "proj".into(),
                file_path: None,
                content: "error".into(),
                tags: vec![],
                importance: 2,
                timestamp: Utc::now(),
                lamport_clock: 0,
                prev_hash: "".into(),
                hash: "".into(),
                signature: "".into(),
            });
        }

        let distiller = NightlyDistiller::new(DistillerConfig::default());
        distiller.extract_lessons(&mut engine, &activities);

        assert_eq!(engine.lessons.lessons.len(), 1);
        assert!(engine.lessons.lessons[0]
            .pattern
            .contains("Connection Timeout"));
        assert_eq!(engine.lessons.lessons[0].source_errors.len(), 3);
    }
}
