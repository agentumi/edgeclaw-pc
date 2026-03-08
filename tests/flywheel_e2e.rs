#[cfg(test)]
mod tests {
    use edgeclaw_agent::memory_engine::{MemoryEngine};
    use edgeclaw_agent::identity_passport::{AgentPassport};
    use edgeclaw_agent::reputation::{ReputationEngine, TaskResult};
    use edgeclaw_agent::activity_log::{ActivityEntry, ActivityType};
    use chrono::{Utc};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_flywheel_e2e_flow() {
        // --- 1. SETUP ---
        let mut engine = MemoryEngine::new();
        let mut passport = AgentPassport::new(
            "pubkey_abc_123".to_string(),
            "Flywheel Agent".to_string(),
            "test-os".to_string(),
            vec!["shell_exec".into()],
            true,
            true,
        );
        let mut rep_engine = ReputationEngine::new();

        // --- 2. ACTIVITY & MEMORY GENERATION ---
        // Simulate a decision-making activity
        let entry = ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "agent_001".to_string(),
            agent_role: "admin".to_string(),
            agent_name: "Flywheel Agent".to_string(),
            activity_type: ActivityType::Decision {
                title: "Use Async".into(),
                chosen: "Yes".into(),
                rationale: "Better performance for concurrent tasks".into(),
                alternatives: vec!["Sync".into()],
            },
            project: "EdgeClaw".to_string(),
            file_path: None,
            content: "Decided to use async for executor".to_string(),
            tags: vec!["async".into()],
            importance: 3,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0000".into(),
            hash: "abcd".into(),
            signature: "sig".into(),
        };

        engine.ingest_activity(&entry);
        
        // Importance 3 decisions go to M90
        assert_eq!(engine.tiers.m90.len(), 1, "Should have 1 memory in M90 after ingestion");
        assert!(engine.tiers.m90[0].content.contains("Better performance"));

        // --- 3. DISTILLATION (LESSON EXTRACTION) ---
        // Simulate a lesson being added to the engine
        use edgeclaw_agent::memory_engine::Lesson;
        let lesson = Lesson {
            id: Uuid::new_v4(),
            pattern: "Prefer async for IO-bound work".to_string(),
            source_errors: vec![],
            applied_count: 5,
            effectiveness: 0.95,
        };
        engine.lessons.add_lesson(lesson);
        assert_eq!(engine.lessons.lessons.len(), 1, "Should have 1 distilled lesson");

        // --- 4. REPUTATION & PASSPORT UPDATE ---
        // Record a successful task execution based on the lesson
        rep_engine.add_task_result(TaskResult {
            task_id: Uuid::new_v4(),
            counterparty_id: "client_X".to_string(),
            task_weight: 1.0,
            quality_score: 1.0,
            pop_verified: true,
            amount_usd: 100.0,
            timestamp: Utc::now(),
        });

        let new_score = rep_engine.calculate_score();
        passport.update_reputation(new_score);

        assert!(passport.reputation_score > 90.0, "Reputation should be high for successful execution");
        
        // --- 5. FINALIZE ---
        println!("Flywheel Cycle Complete for Agent: {}", passport.metadata.name);
        println!("- Memory: {} items stored", engine.tiers.m90.len());
        println!("- Lessons learned: {}", engine.lessons.lessons[0].pattern);
        println!("- Reputation: {:.2}", passport.reputation_score);
    }
}
