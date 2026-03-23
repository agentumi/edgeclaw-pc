//! # Quantum Type Memory Process (V3)
//!
//! EdgeClaw V3 — 양자 시뮬레이션 기반 집단 지성 메모리 엔진
//!
//! ## 설계 철학
//! 물리적 양자 컴퓨터 없이 클래식 하드웨어에서 양자역학 원리를 소프트웨어로 시뮬레이션:
//! - **중첩(Superposition)**: 여러 에이전트 접근법 동시 고려
//! - **얽힘(Entanglement)**: 에이전트 간 상태 즉각 연동
//! - **간섭(Interference)**: 최적 경로 진폭 증폭, 틀린 경로 상쇄
//! - **나비효과(Butterfly Effect)**: 작은 실패가 전체 시스템 재정렬 트리거
//!
//! ## 공식
//! |Ψ(t+1)⟩ = N[U(t)|Ψ(t)⟩ + λ·e^(γΔE)(P_fail|Ψ(t)⟩)]

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::ai::MissionMetadata;

// ─── Virtual Qubit ─────────────────────────────────────────────────────────────

/// 가상 큐비트 — 에이전트/전략의 확률 진폭 표현
/// |ψ⟩ = α|0⟩ + β|1⟩ 에서 α, β는 복소수지만 여기서는 f64로 근사
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualQubit {
    /// 실수 진폭 알파 (|0⟩ 상태 — 아직 결정 안 됨/실패)
    pub alpha: f64,
    /// 실수 진폭 베타 (|1⟩ 상태 — 결정됨/성공)
    pub beta: f64,
    /// 큐비트 레이블 (에이전트 ID 또는 전략 이름)
    pub label: String,
    /// 이 큐비트가 나타내는 접근법 설명
    pub approach: String,
}

impl VirtualQubit {
    /// 새 큐비트 생성 (동일 중첩 상태로 시작)
    pub fn new(label: &str, approach: &str) -> Self {
        let amplitude = 1.0 / 2.0_f64.sqrt(); // 1/√2
        Self {
            alpha: amplitude,
            beta: amplitude,
            label: label.to_string(),
            approach: approach.to_string(),
        }
    }

    /// 상태 벡터 정규화 |α|² + |β|² = 1
    pub fn normalize(&mut self) {
        let norm = (self.alpha * self.alpha + self.beta * self.beta).sqrt();
        if norm > f64::EPSILON {
            self.alpha /= norm;
            self.beta /= norm;
        }
    }

    /// 성공 확률 반환 |β|²
    pub fn success_probability(&self) -> f64 {
        self.beta * self.beta
    }

    /// 실패 확률 반환 |α|²
    pub fn failure_probability(&self) -> f64 {
        self.alpha * self.alpha
    }

    /// Hadamard 게이트 적용 — 중첩 상태로 변환
    /// H = (1/√2) [[1, 1], [1, -1]]
    pub fn apply_hadamard(&mut self) {
        let sqrt2_inv = 1.0 / 2.0_f64.sqrt();
        let new_alpha = sqrt2_inv * (self.alpha + self.beta);
        let new_beta = sqrt2_inv * (self.alpha - self.beta);
        self.alpha = new_alpha;
        self.beta = new_beta;
        self.normalize();
    }

    /// Pauli-X 게이트 (NOT 게이트) — 상태 반전
    pub fn apply_pauli_x(&mut self) {
        std::mem::swap(&mut self.alpha, &mut self.beta);
    }

    /// 성공 편향 적용 (Grover-like 진폭 증폭)
    pub fn amplify_success(&mut self, factor: f64) {
        self.beta = (self.beta * (1.0 + factor)).min(1.0);
        self.normalize();
    }

    /// 실패 패널티 적용
    pub fn penalize_failure(&mut self, factor: f64) {
        self.alpha = (self.alpha * (1.0 + factor)).min(1.0);
        self.normalize();
    }

    /// 큐비트 측정 (붕괴) — 0 또는 1 반환
    /// 실제로는 확률적이지만, 여기서는 결정론적으로 최대 진폭 선택
    pub fn measure(&self) -> u8 {
        if self.success_probability() > 0.5 { 1 } else { 0 }
    }
}

// ─── Quantum Gate ─────────────────────────────────────────────────────────────

/// 에이전트 쌍 간의 CNOT 얽힘 연산
/// 제어 큐비트가 |1⟩이면 타겟 큐비트에 Pauli-X 적용
pub fn apply_cnot(control: &VirtualQubit, target: &mut VirtualQubit) {
    if control.success_probability() > 0.5 {
        target.apply_pauli_x();
    }
}

// ─── Quantum Mission State ────────────────────────────────────────────────────

/// 미션을 양자 상태로 표현하는 그래프
/// 각 노드가 에이전트/전략을 나타내는 큐비트
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumMissionState {
    /// 모든 참여 에이전트/전략의 큐비트
    pub qubits: Vec<VirtualQubit>,
    /// 얽힘 관계: (control_idx, target_idx)
    pub entanglements: Vec<(usize, usize)>,
    /// 미션 메타데이터
    pub mission_id: String,
    /// 현재 사이클 수
    pub cycle: u32,
    /// 나비효과 파라미터
    pub butterfly_gamma: f64,
    /// 나비효과 확산 계수
    pub butterfly_lambda: f64,
}

impl QuantumMissionState {
    /// 새 양자 미션 상태 초기화
    pub fn new(mission_id: &str) -> Self {
        Self {
            qubits: Vec::new(),
            entanglements: Vec::new(),
            mission_id: mission_id.to_string(),
            cycle: 0,
            butterfly_gamma: 0.5,  // 리아프노프 파라미터
            butterfly_lambda: 0.1, // 확산 계수
        }
    }

    /// 에이전트/전략 큐비트 추가
    pub fn add_agent_qubit(&mut self, agent_id: &str, approach: &str) -> usize {
        let mut qubit = VirtualQubit::new(agent_id, approach);
        qubit.apply_hadamard(); // 중첩 상태로 초기화
        let idx = self.qubits.len();
        self.qubits.push(qubit);
        idx
    }

    /// 두 에이전트 큐비트를 얽힘 관계로 연결
    pub fn entangle(&mut self, control_idx: usize, target_idx: usize) {
        if control_idx < self.qubits.len() && target_idx < self.qubits.len() {
            self.entanglements.push((control_idx, target_idx));
        }
    }

    /// Grover-like 진폭 증폭 실행
    /// 성공한 에이전트의 진폭을 boost하고 실패한 에이전트의 진폭을 낮춤
    pub fn apply_grover_amplification(&mut self, winner_idx: usize) {
        let qubit_len = self.qubits.len();
        if winner_idx >= qubit_len {
            return;
        }

        // 평균 진폭 계산
        let avg_success: f64 = self.qubits.iter()
            .map(|q| q.success_probability())
            .sum::<f64>() / qubit_len.max(1) as f64;

        // 승자 증폭, 나머지 감쇠
        for (idx, qubit) in self.qubits.iter_mut().enumerate() {
            if idx == winner_idx {
                qubit.amplify_success(0.3);
            } else {
                let damping = (qubit.success_probability() - avg_success).abs() * 0.1;
                qubit.penalize_failure(damping);
            }
        }
    }

    /// 나비효과 적용 — 실패 이벤트가 전체 시스템에 파급
    /// |Ψ(t+1)⟩ = N[U(t)|Ψ(t)⟩ + λ·e^(γΔE)(P_fail|Ψ(t)⟩)]
    pub fn apply_butterfly_effect(&mut self, failed_agent_idx: usize, delta_e: f64) {
        if failed_agent_idx >= self.qubits.len() {
            return;
        }

        // λ·e^(γΔE) 계산
        let butterfly_factor = self.butterfly_lambda
            * (self.butterfly_gamma * delta_e).exp();

        // 실패 에이전트의 정보를 다른 얽힌 큐비트에 피드포워드
        let entanglements = self.entanglements.clone();
        for (control_idx, target_idx) in &entanglements {
            if *control_idx == failed_agent_idx {
                // 실패 정보를 타겟에 전파
                if let Some(target) = self.qubits.get_mut(*target_idx) {
                    // 타겟 큐비트가 실패 정보를 활용해 전략 조정
                    target.alpha = (target.alpha + butterfly_factor * 0.1).min(1.0);
                    target.normalize();
                }
            }
        }

        self.cycle += 1;
    }

    /// 모든 큐비트 측정 — 최선의 에이전트/전략 선택
    pub fn measure_all(&self) -> Vec<(String, f64)> {
        self.qubits.iter()
            .map(|q| (q.label.clone(), q.success_probability()))
            .collect()
    }

    /// 가장 높은 성공 확률의 에이전트 선택
    pub fn select_best_agent(&self) -> Option<&VirtualQubit> {
        self.qubits.iter()
            .max_by(|a, b| a.success_probability()
                .partial_cmp(&b.success_probability())
                .unwrap_or(std::cmp::Ordering::Equal))
    }

    /// 현재 상태의 전체 시스템 엔트로피 (불확실성 지표)
    pub fn system_entropy(&self) -> f64 {
        if self.qubits.is_empty() {
            return 0.0;
        }
        let n = self.qubits.len() as f64;
        -self.qubits.iter().map(|q| {
            let p = q.success_probability();
            let q_val = q.failure_probability();
            let h_p = if p > f64::EPSILON { -p * p.ln() } else { 0.0 };
            let h_q = if q_val > f64::EPSILON { -q_val * q_val.ln() } else { 0.0 };
            (h_p + h_q) / n
        }).sum::<f64>()
    }
}

// ─── Quantum Memory Hub ───────────────────────────────────────────────────────

/// V3 양자 메모리 허브 — 집단 지성의 비선형 메모리 저장소
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumMemoryHub {
    /// E-Max 패턴 저장소 (효율 극대화)
    pub e_max_patterns: Vec<QuantumPattern>,
    /// C-Max 패턴 저장소 (창의성 극대화)
    pub c_max_patterns: Vec<QuantumPattern>,
    /// 실패 → 혁신 인사이트 저장소
    pub failure_insights: Vec<FailureInsight>,
    /// 현재 활성 미션 상태들
    pub active_missions: HashMap<String, QuantumMissionState>,
    /// 총 사이클 수
    pub total_cycles: u64,
}

/// 양자 확률 기반 작업 패턴
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumPattern {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub description: String,
    /// 이 패턴이 성공한 확률 분포 (다양한 상황에서 측정)
    pub success_distribution: Vec<f64>,
    /// 평균 성공 확률
    pub avg_success_rate: f64,
    /// 적용 횟수
    pub application_count: u32,
    /// E-Max(효율) vs C-Max(창의) 분류
    pub pattern_type: PatternType,
    /// 이 패턴을 통해 이룩한 혁신 수
    pub innovation_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PatternType {
    /// 속도 & 자원 효율 극대화 — 정석 패턴
    EMax,
    /// 창의성 & 혁신 극대화 — 파괴적 패턴
    CMax,
}

/// 실패에서 추출한 혁신 인사이트
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureInsight {
    pub id: String,
    pub original_failure: String,
    pub extracted_insight: String,
    pub potential_business_value: String,
    pub diffusion_count: u32,
    pub created_at: String,
    pub viral_score: f64, // 다른 에이전트들에게 얼마나 유용한지
}

impl QuantumMemoryHub {
    pub fn new() -> Self {
        Self {
            e_max_patterns: Vec::new(),
            c_max_patterns: Vec::new(),
            failure_insights: Vec::new(),
            active_missions: HashMap::new(),
            total_cycles: 0,
        }
    }

    /// 새 미션을 양자 상태로 등록
    pub fn register_mission(&mut self, mission_id: &str) -> &mut QuantumMissionState {
        let state = QuantumMissionState::new(mission_id);
        self.active_missions.insert(mission_id.to_string(), state);
        self.active_missions.get_mut(mission_id).unwrap()
    }

    /// 실패를 혁신 인사이트로 자산화 (Failure-to-Pivot)
    pub fn pivot_from_failure(&mut self, failure_desc: &str, context: &str) -> FailureInsight {
        let insight = FailureInsight {
            id: format!("insight-{}", self.failure_insights.len() + 1),
            original_failure: failure_desc.to_string(),
            extracted_insight: format!(
                "실패 분석: '{}' 상황에서 발생한 실패는 다음 기회를 시사합니다 — {}",
                context, failure_desc
            ),
            potential_business_value: format!(
                "이 실패 패턴은 유사 상황에서 선제적 방지 또는 대안 접근법으로 활용 가능"
            ),
            diffusion_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            viral_score: 0.5,
        };

        self.failure_insights.push(insight.clone());
        insight
    }

    /// 성공 패턴을 E-Max 또는 C-Max 저장소에 등록
    pub fn register_pattern(
        &mut self,
        name: &str,
        domain: &str,
        success_rate: f64,
        pattern_type: PatternType,
    ) -> String {
        let pattern = QuantumPattern {
            id: format!("ptn-{}", self.e_max_patterns.len() + self.c_max_patterns.len() + 1),
            name: name.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            success_distribution: vec![success_rate],
            avg_success_rate: success_rate,
            application_count: 1,
            pattern_type: pattern_type.clone(),
            innovation_count: 0,
        };

        let id = pattern.id.clone();
        match pattern_type {
            PatternType::EMax => self.e_max_patterns.push(pattern),
            PatternType::CMax => self.c_max_patterns.push(pattern),
        }

        id
    }

    /// Grover Search — O(√N) 복잡도로 최적 패턴 검색
    pub fn search_best_pattern(&self, domain: &str, prefer_creative: bool) -> Option<&QuantumPattern> {
        let pool: Vec<&QuantumPattern> = if prefer_creative {
            self.c_max_patterns.iter()
                .filter(|p| p.domain == domain || domain == "general")
                .collect()
        } else {
            self.e_max_patterns.iter()
                .filter(|p| p.domain == domain || domain == "general")
                .collect()
        };

        // 가장 높은 성공률 패턴 선택 (실제 Grover는 √N 스텝이지만 여기선 선형)
        pool.into_iter()
            .max_by(|a, b| a.avg_success_rate
                .partial_cmp(&b.avg_success_rate)
                .unwrap_or(std::cmp::Ordering::Equal))
    }

    /// 전체 허브 통계
    pub fn stats(&self) -> QuantumHubStats {
        QuantumHubStats {
            e_max_count: self.e_max_patterns.len(),
            c_max_count: self.c_max_patterns.len(),
            failure_insights_count: self.failure_insights.len(),
            active_missions: self.active_missions.len(),
            total_cycles: self.total_cycles,
        }
    }
}

impl Default for QuantumMemoryHub {
    fn default() -> Self {
        Self::new()
    }
}

/// 허브 통계 스냅샷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumHubStats {
    pub e_max_count: usize,
    pub c_max_count: usize,
    pub failure_insights_count: usize,
    pub active_missions: usize,
    pub total_cycles: u64,
}

// ─── Quantum Orchestrator ─────────────────────────────────────────────────────

/// V3 Quantum Type Process — 미션 실행 오케스트레이터
pub struct QuantumOrchestrator {
    pub hub: QuantumMemoryHub,
}

impl QuantumOrchestrator {
    pub fn new() -> Self {
        Self {
            hub: QuantumMemoryHub::new(),
        }
    }

    /// 미션을 양자 그래프로 초기화하고 최선 전략 선택
    /// 에이전트들의 접근법을 큐비트로 변환 → 얽힘 → Grover 증폭
    pub fn initialize_mission_graph(
        &mut self,
        mission: &MissionMetadata,
        agent_ids: &[String],
    ) -> QuantumMissionState {
        let mut state = QuantumMissionState::new(&mission.id);

        // 각 에이전트를 큐비트로 추가
        for (idx, agent_id) in agent_ids.iter().enumerate() {
            let approach = mission.tasks.get(idx)
                .map(|t| t.desc.as_str())
                .unwrap_or("general_approach");
            state.add_agent_qubit(agent_id, approach);
        }

        // 순서 기반 얽힘 구성 (이전 태스크 성공 → 다음 태스크 활성화)
        for i in 0..agent_ids.len().saturating_sub(1) {
            state.entangle(i, i + 1);
        }

        state
    }

    /// 실패 이벤트 처리 → 나비효과 트리거 → 전략 재정렬
    pub fn handle_failure(
        &mut self,
        mission_id: &str,
        failed_task_desc: &str,
        error_magnitude: f64,
    ) -> Option<FailureInsight> {
        // 실패를 혁신 인사이트로 자산화
        let insight = self.hub.pivot_from_failure(failed_task_desc, mission_id);

        // 해당 미션의 양자 상태에 나비효과 적용
        if let Some(state) = self.hub.active_missions.get_mut(mission_id) {
            // 실패한 큐비트 찾기
            let failed_idx = state.qubits.iter()
                .enumerate()
                .find(|(_, q)| q.approach.contains(failed_task_desc) || q.failure_probability() > 0.7)
                .map(|(idx, _)| idx);

            if let Some(idx) = failed_idx {
                state.apply_butterfly_effect(idx, error_magnitude);
            }
        }

        Some(insight)
    }

    /// 양자 확률을 기반으로 다음 최선 에이전트/전략 선택
    pub fn select_next_strategy(&self, mission_id: &str) -> Option<String> {
        self.hub.active_missions.get(mission_id)
            .and_then(|state| state.select_best_agent())
            .map(|q| q.label.clone())
    }
}

impl Default for QuantumOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_qubit_normalization() {
        let q = VirtualQubit::new("agent-1", "approach-a");
        // 중첩 상태에서 |α|² + |β|² = 1
        let prob_sum = q.success_probability() + q.failure_probability();
        assert!((prob_sum - 1.0).abs() < 1e-10, "Normalization failed: {}", prob_sum);
    }

    #[test]
    fn test_hadamard_creates_superposition() {
        let mut q = VirtualQubit { alpha: 1.0, beta: 0.0, label: "test".to_string(), approach: "a".to_string() };
        q.apply_hadamard();
        // H|0⟩ = (|0⟩+|1⟩)/√2 → 50/50 확률
        let p0 = q.failure_probability();
        let p1 = q.success_probability();
        assert!((p0 - 0.5).abs() < 1e-10);
        assert!((p1 - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_pauli_x_flips_state() {
        let mut q = VirtualQubit { alpha: 1.0, beta: 0.0, label: "test".to_string(), approach: "b".to_string() };
        q.apply_pauli_x();
        assert!((q.success_probability() - 1.0).abs() < 1e-10);
        assert!((q.failure_probability() - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_grover_amplification() {
        let mut state = QuantumMissionState::new("test-mission");
        state.add_agent_qubit("agent-a", "approach-a");
        state.add_agent_qubit("agent-b", "approach-b");

        // 에이전트 0이 승자
        state.apply_grover_amplification(0);
        let winner_prob = state.qubits[0].success_probability();
        let loser_prob = state.qubits[1].success_probability();

        // 승자의 확률이 패자보다 높아야 함
        assert!(winner_prob >= loser_prob, "winner: {}, loser: {}", winner_prob, loser_prob);
    }

    #[test]
    fn test_butterfly_effect_increments_cycle() {
        let mut state = QuantumMissionState::new("test-mission");
        state.add_agent_qubit("agent-a", "approach-a");
        state.add_agent_qubit("agent-b", "approach-b");
        state.entangle(0, 1);

        let initial_cycle = state.cycle;
        state.apply_butterfly_effect(0, 0.1);
        assert_eq!(state.cycle, initial_cycle + 1);
    }

    #[test]
    fn test_quantum_hub_failure_pivot() {
        let mut hub = QuantumMemoryHub::new();
        let insight = hub.pivot_from_failure(
            "API 연결 실패로 데이터 수집 중단",
            "mission-001"
        );
        assert!(!insight.id.is_empty());
        assert!(!insight.extracted_insight.is_empty());
        assert_eq!(hub.failure_insights.len(), 1);
    }

    #[test]
    fn test_quantum_hub_register_pattern() {
        let mut hub = QuantumMemoryHub::new();
        let id = hub.register_pattern(
            "주간 보고서 자동화 정석",
            "business",
            0.92,
            PatternType::EMax
        );
        assert!(!id.is_empty());
        assert_eq!(hub.e_max_patterns.len(), 1);
        assert_eq!(hub.e_max_patterns[0].avg_success_rate, 0.92);
    }

    #[test]
    fn test_grover_search_returns_best() {
        let mut hub = QuantumMemoryHub::new();
        hub.register_pattern("Pattern A", "business", 0.6, PatternType::EMax);
        hub.register_pattern("Pattern B", "business", 0.9, PatternType::EMax);

        let best = hub.search_best_pattern("business", false);
        assert!(best.is_some());
        assert_eq!(best.unwrap().avg_success_rate, 0.9);
    }

    #[test]
    fn test_system_entropy() {
        let mut state = QuantumMissionState::new("entropy-test");
        state.add_agent_qubit("a1", "approach1");
        state.add_agent_qubit("a2", "approach2");

        let entropy = state.system_entropy();
        // 동등 중첩 상태에서 엔트로피는 최대 (0보다 커야 함)
        assert!(entropy >= 0.0, "Entropy should be non-negative: {}", entropy);
    }

    #[test]
    fn test_quantum_orchestrator_initialize() {
        let mut orchestrator = QuantumOrchestrator::new();
        let mission = crate::ai::MissionMetadata {
            id: "test-mission".to_string(),
            name: "Test".to_string(),
            tasks: vec![
                crate::ai::TaskUnit { desc: "Task 1".to_string(), capability: "SYSTEM_INFO".to_string(), args: vec![], order: 1 },
            ],
            ..Default::default()
        };
        let agents = vec!["agent-a".to_string(), "agent-b".to_string()];
        let state = orchestrator.initialize_mission_graph(&mission, &agents);

        assert_eq!(state.qubits.len(), 2);
        assert_eq!(state.entanglements.len(), 1);
    }

    #[test]
    fn test_measure_all_returns_probabilities() {
        let mut state = QuantumMissionState::new("measure-test");
        state.add_agent_qubit("agent-a", "approach-a");
        state.add_agent_qubit("agent-b", "approach-b");

        let measurements = state.measure_all();
        assert_eq!(measurements.len(), 2);

        // 각 확률이 0~1 사이
        for (_, prob) in &measurements {
            assert!(*prob >= 0.0 && *prob <= 1.0);
        }
    }

    #[test]
    fn test_select_best_agent() {
        let mut state = QuantumMissionState::new("best-test");
        // 에이전트 A: 성공 확률 낮음
        state.qubits.push(VirtualQubit { alpha: 0.9, beta: 0.1, label: "low-agent".to_string(), approach: "a".to_string() });
        // 에이전트 B: 성공 확률 높음  
        state.qubits.push(VirtualQubit { alpha: 0.1, beta: 0.9, label: "high-agent".to_string(), approach: "b".to_string() });

        let best = state.select_best_agent().unwrap();
        assert_eq!(best.label, "high-agent");
    }
}
