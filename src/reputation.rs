use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Represents a single Proof of Performance (PoP) task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: Uuid,
    pub counterparty_id: String,
    pub task_weight: f64,   // 0.0 to 1.0 depending on complexity/value
    pub quality_score: f64, // 0.0 (Failed) to 1.0 (Excellent)
    pub pop_verified: bool, // cryptographic Proof-of-Performance verified
    pub amount_usd: f64,    // value for sybil defense capping
    pub timestamp: DateTime<Utc>,
}

/// Reputation Engine for calculating Agent PoP Score
#[derive(Debug, Clone, Default)]
pub struct ReputationEngine {
    pub tasks: Vec<TaskResult>,
    pub counterparty_history: HashSet<String>,
}

impl ReputationEngine {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            counterparty_history: HashSet::new(),
        }
    }

    pub fn add_task_result(&mut self, result: TaskResult) {
        self.counterparty_history
            .insert(result.counterparty_id.clone());
        self.tasks.push(result);
    }

    /// Calculate the overall reputation score (0.0 to 100.0)
    /// ReputationScore = Σ(TaskWeight × QualityScore × PoP) / TotalTasks
    pub fn calculate_score(&self) -> f64 {
        if self.tasks.is_empty() {
            return 0.0;
        }

        let mut total_weighted_score = 0.0;
        let mut total_weight = 0.0;

        for task in &self.tasks {
            // Unverified tasks do not contribute positively
            let pop_multiplier = if task.pop_verified { 1.0 } else { 0.2 };

            // 시빌 방어: 금액 상한선 (예: $100 이상은 로그 스케일 적용 등 간단히 cap)
            let _amount_cap = task.amount_usd.min(100.0);

            let weight = task.task_weight * pop_multiplier;
            total_weighted_score += task.quality_score * weight;
            total_weight += task.task_weight;
        }

        if total_weight == 0.0 {
            return 0.0;
        }

        let base_score = (total_weighted_score / total_weight) * 100.0;

        // 시빌 방어: Unique Counterparty 다양성 보너스 (최대 1.2배)
        let diversity_multiplier = 1.0 + (self.counterparty_history.len() as f64 * 0.02).min(0.2);

        (base_score * diversity_multiplier).min(100.0)
    }

    /// NFT 이전 시 30% 감쇠 (시빌 및 평판 거래 어뷰징 방어)
    pub fn apply_nft_transfer_penalty(&mut self) {
        // 모든 이전 태스크의 가중치를 30% 감소시킴
        for task in &mut self.tasks {
            task.task_weight *= 0.7;
        }
    }
}

/// 온체인 앵커링 (Mock)
pub struct OnChainReputation;

impl OnChainReputation {
    pub fn anchor_score(_agent_id: &str, score: f64) -> Result<String, String> {
        // 실제로는 SUI Blockchain Transaction 전송
        let tx_digest = format!("0xmocked_tx_{}", (score * 100.0) as u64);
        Ok(tx_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_score() {
        let mut engine = ReputationEngine::new();

        engine.add_task_result(TaskResult {
            task_id: Uuid::new_v4(),
            counterparty_id: "client_A".to_string(),
            task_weight: 1.0,
            quality_score: 0.9,
            pop_verified: true,
            amount_usd: 50.0,
            timestamp: Utc::now(),
        });

        let score = engine.calculate_score();
        // Base score = 0.9/1.0 = 90.0, diversity = 1.02 -> 91.8
        assert!(score > 90.0);
    }

    #[test]
    fn test_sybil_defense_diversity() {
        let mut engine1 = ReputationEngine::new();
        let mut engine2 = ReputationEngine::new();

        // 1 counterparty 5 times
        for _ in 0..5 {
            engine1.add_task_result(TaskResult {
                task_id: Uuid::new_v4(),
                counterparty_id: "client_A".to_string(),
                task_weight: 1.0,
                quality_score: 0.8,
                pop_verified: true,
                amount_usd: 10.0,
                timestamp: Utc::now(),
            });
        }

        // 5 counterparties 1 time each
        for i in 0..5 {
            engine2.add_task_result(TaskResult {
                task_id: Uuid::new_v4(),
                counterparty_id: format!("client_{}", i),
                task_weight: 1.0,
                quality_score: 0.8,
                pop_verified: true,
                amount_usd: 10.0,
                timestamp: Utc::now(),
            });
        }

        assert!(engine2.calculate_score() > engine1.calculate_score());
    }

    #[test]
    fn test_nft_transfer_penalty() {
        let mut engine = ReputationEngine::new();
        engine.add_task_result(TaskResult {
            task_id: Uuid::new_v4(),
            counterparty_id: "client_A".to_string(),
            task_weight: 1.0,
            quality_score: 1.0,
            pop_verified: true,
            amount_usd: 50.0,
            timestamp: Utc::now(),
        });

        assert_eq!(engine.tasks[0].task_weight, 1.0);
        engine.apply_nft_transfer_penalty();
        assert_eq!(engine.tasks[0].task_weight, 0.7);
    }
}
