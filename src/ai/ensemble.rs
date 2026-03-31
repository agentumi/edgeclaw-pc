//! # Fleet Process: Parallel Ensemble Consensus Engine
//!
//! V2.x "Fleet Type Process" — 낮은 성능의 로컬 AI 모델들을 병렬로 오케스트레이션하여
//! 고성능 LLM 수준의 전문가 작업을 달성하는 핵심 엔진.
//!
//! ## 설계 원칙
//! - 여러 로컬 모델을 병렬 실행 (tokio::spawn)
//! - 각 모델이 다른 역할(logic/code/verify/domain)을 담당
//! - 결과를 합의 알고리즘으로 통합 (가중 투표 + 최선 응답 선택)
//! - 할루시네이션 감지 및 제거

#![allow(clippy::field_reassign_with_default)]

use crate::ai::{AiResponse, MissionMetadata};
use serde::{Deserialize, Serialize};

// ─── Domain Expert Roles ───────────────────────────────────────────────────────

/// 전문가 역할 — 각 역할은 다른 로컬 모델에 배정됨
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpertRole {
    /// 비즈니스 전략 & 분석 전문가
    BusinessAnalyst,
    /// 소프트웨어 엔지니어링 & CI/CD 전문가
    SoftwareEngineer,
    /// 마케팅 & 성장 전문가
    GrowthMarketer,
    /// QA & 보안 테스트 전문가
    QaGuardian,
    /// 논리 검증자 — 다른 모델의 결과를 검증
    LogicVerifier,
    /// 통합자 — 모든 결과를 통합하여 최종 답변 생성
    Synthesizer,
}

impl ExpertRole {
    pub fn label(&self) -> &'static str {
        match self {
            ExpertRole::BusinessAnalyst => "Business Analyst",
            ExpertRole::SoftwareEngineer => "Software Engineer",
            ExpertRole::GrowthMarketer => "Growth Marketer",
            ExpertRole::QaGuardian => "QA Guardian",
            ExpertRole::LogicVerifier => "Logic Verifier",
            ExpertRole::Synthesizer => "Synthesizer",
        }
    }

    /// 이 역할에 최적화된 시스템 프롬프트를 반환
    pub fn expert_system_prompt(&self, domain_context: &str) -> String {
        match self {
            ExpertRole::BusinessAnalyst => format!(
                "당신은 세계 최고 수준의 비즈니스 전략 및 분석 전문가입니다. McKinsey, BCG 수준의 분석 능력을 보유하고 있습니다.\n\
                전문 영역: 시장 분석, KPI 설계, 재무 모델링, 경쟁사 분석, 비즈니스 인텔리전스\n\
                응답 원칙:\n\
                - 데이터 기반의 통찰력을 제공하라\n\
                - 구체적인 수치와 지표를 포함하라\n\
                - 실행 가능한 권고사항을 제시하라\n\
                - Executive Summary 형식으로 구조화하라\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라:\n\
                {{\"message\": \"[전문가 분석 결과]\", \"confidence\": 0.9, \"intent\": {{\"capability\": \"[능력]\", \"command\": \"[명령]\", \"args\": []}}, \"expert_role\": \"business_analyst\"}}",
                domain_context
            ),
            ExpertRole::SoftwareEngineer => format!(
                "당신은 세계 최고 수준의 소프트웨어 엔지니어입니다. Google, Netflix 수준의 시스템 설계 능력을 보유하고 있습니다.\n\
                전문 영역: CI/CD 파이프라인, 코드 아키텍처, 성능 최적화, 보안 강화, DevOps\n\
                응답 원칙:\n\
                - 구체적이고 실행 가능한 코드/명령을 제공하라\n\
                - 잠재적 버그와 엣지 케이스를 지적하라\n\
                - 확장성과 유지보수성을 고려하라\n\
                - 테스트 가능한 솔루션을 제안하라\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라:\n\
                {{\"message\": \"[엔지니어링 솔루션]\", \"confidence\": 0.9, \"intent\": {{\"capability\": \"[능력]\", \"command\": \"[명령]\", \"args\": []}}, \"expert_role\": \"software_engineer\"}}",
                domain_context
            ),
            ExpertRole::GrowthMarketer => format!(
                "당신은 세계 최고 수준의 성장 마케팅 전문가입니다. Airbnb, Uber 수준의 그로스 해킹 능력을 보유하고 있습니다.\n\
                전문 영역: 콘텐츠 전략, 소셜 미디어 마케팅, SEO, 캠페인 최적화, 고객 획득/유지\n\
                응답 원칙:\n\
                - 창의적이고 데이터 기반의 마케팅 전략을 제시하라\n\
                - A/B 테스트 가능한 가설을 포함하라\n\
                - ROI와 KPI를 명시하라\n\
                - 즉시 실행 가능한 전술을 제공하라\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라:\n\
                {{\"message\": \"[마케팅 전략]\", \"confidence\": 0.9, \"intent\": {{\"capability\": \"[능력]\", \"command\": \"[명령]\", \"args\": []}}, \"expert_role\": \"growth_marketer\"}}",
                domain_context
            ),
            ExpertRole::QaGuardian => format!(
                "당신은 세계 최고 수준의 QA 및 보안 전문가입니다. 모든 취약점과 엣지 케이스를 찾아내는 능력을 보유하고 있습니다.\n\
                전문 영역: 보안 취약점 분석, 테스트 자동화, 버그 추적, 인시던트 대응, 컴플라이언스\n\
                응답 원칙:\n\
                - 잠재적 위험과 취약점을 식별하라\n\
                - 체계적인 테스트 케이스를 설계하라\n\
                - 보안 강화 방안을 제시하라\n\
                - 위험 우선순위를 분류하라\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라:\n\
                {{\"message\": \"[QA/보안 분석]\", \"confidence\": 0.9, \"intent\": {{\"capability\": \"[능력]\", \"command\": \"[명령]\", \"args\": []}}, \"expert_role\": \"qa_guardian\"}}",
                domain_context
            ),
            ExpertRole::LogicVerifier => format!(
                "당신은 논리적 일관성 검증 전문가입니다. 다른 전문가들의 결과물에서 모순, 오류, 할루시네이션을 찾아내야 합니다.\n\
                검증 기준:\n\
                - 사실 확인: 주장이 검증 가능한가?\n\
                - 논리 일관성: 전제와 결론이 맞는가?\n\
                - 실행 가능성: 제안이 실제로 실행될 수 있는가?\n\
                - 완전성: 중요한 내용이 누락되지 않았는가?\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라:\n\
                {{\"message\": \"[검증 결과]\", \"confidence\": 0.95, \"verification_score\": 0.8, \"issues\": [], \"expert_role\": \"logic_verifier\"}}",
                domain_context
            ),
            ExpertRole::Synthesizer => format!(
                "당신은 여러 전문가의 의견을 통합하여 최종 권고안을 만드는 통합 전문가입니다.\n\
                통합 원칙:\n\
                - 모든 전문가 의견에서 핵심 인사이트를 추출하라\n\
                - 상충되는 의견은 증거 기반으로 조정하라\n\
                - 최종 결과물은 즉시 실행 가능해야 한다\n\
                - 전문가 수준의 포괄적 답변을 제공하라\n\n\
                현재 컨텍스트: {}\n\n\
                반드시 아래 JSON 형식으로 응답하라 (미션을 포함할 경우):\n\
                {{\"message\": \"[최종 통합 답변]\", \"confidence\": 0.95, \"intent\": {{\"capability\": \"create_mission\", \"command\": \"[명령]\", \"args\": [], \"mission\": {{\"id\": \"msn-[uuid]\", \"name\": \"[미션명]\", \"description\": \"[설명]\", \"category\": \"[카테고리]\", \"tasks\": [{{\"desc\": \"[작업 설명]\", \"capability\": \"[능력]\", \"args\": [], \"order\": 1}}], \"status\": \"Proposed\", \"progress\": 0, \"created_at\": \"[ISO8601]\"}}}}, \"expert_role\": \"synthesizer\"}}",
                domain_context
            ),
        }
    }
}

// ─── Ensemble Response ─────────────────────────────────────────────────────────

/// 단일 전문가 모델의 응답
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertResponse {
    pub role: String,
    pub model: String,
    pub response: AiResponse,
    pub latency_ms: u64,
    pub hallucination_score: f64, // 0.0 = clean, 1.0 = likely hallucination
}

/// 앙상블 전체 결과
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsembleResult {
    pub final_response: AiResponse,
    pub expert_responses: Vec<ExpertResponse>,
    pub consensus_confidence: f64,
    pub dissent_count: u32,
    pub process_type: ProcessType,
}

/// 프로세스 타입 선택자
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum ProcessType {
    /// Fleet Type — 병렬 로컬 모델 앙상블
    #[default]
    Fleet,
    /// Quantum Type — 양자 확률 기반 추론 (V3)
    Quantum,
    /// Auto — 작업 복잡도에 따라 자동 선택
    Auto,
}

// ─── Domain Detector ───────────────────────────────────────────────────────────

/// 사용자 입력에서 도메인을 감지하여 적절한 전문가 역할을 선택
pub struct DomainDetector;

impl DomainDetector {
    /// 입력 텍스트에서 주요 도메인을 감지
    pub fn detect_domain(input: &str) -> &'static str {
        let input_lower = input.to_lowercase();

        // 개발/기술 도메인
        if input_lower.contains("코드")
            || input_lower.contains("code")
            || input_lower.contains("개발")
            || input_lower.contains("dev")
            || input_lower.contains("테스트")
            || input_lower.contains("test")
            || input_lower.contains("ci")
            || input_lower.contains("cd")
            || input_lower.contains("배포")
            || input_lower.contains("deploy")
            || input_lower.contains("디버그")
            || input_lower.contains("bug")
            || input_lower.contains("빌드")
            || input_lower.contains("build")
        {
            return "development";
        }

        // 마케팅 도메인
        if input_lower.contains("마케팅")
            || input_lower.contains("marketing")
            || input_lower.contains("콘텐츠")
            || input_lower.contains("content")
            || input_lower.contains("sns")
            || input_lower.contains("소셜")
            || input_lower.contains("캠페인")
            || input_lower.contains("campaign")
            || input_lower.contains("광고")
            || input_lower.contains("ad")
        {
            return "marketing";
        }

        // 비즈니스/분석 도메인
        if input_lower.contains("분석")
            || input_lower.contains("analysis")
            || input_lower.contains("보고서")
            || input_lower.contains("report")
            || input_lower.contains("투자")
            || input_lower.contains("invest")
            || input_lower.contains("시장")
            || input_lower.contains("market")
            || input_lower.contains("매출")
            || input_lower.contains("revenue")
            || input_lower.contains("kpi")
            || input_lower.contains("지표")
        {
            return "business";
        }

        // QA/보안 도메인
        if input_lower.contains("보안")
            || input_lower.contains("security")
            || input_lower.contains("취약점")
            || input_lower.contains("vulnerability")
            || input_lower.contains("감사")
            || input_lower.contains("audit")
            || input_lower.contains("버그")
        {
            return "qa";
        }

        // 기본값
        "general"
    }

    /// 도메인에 따라 우선 전문가 역할 목록 반환
    pub fn get_expert_roles(domain: &str) -> Vec<ExpertRole> {
        match domain {
            "development" => vec![
                ExpertRole::SoftwareEngineer,
                ExpertRole::QaGuardian,
                ExpertRole::LogicVerifier,
            ],
            "marketing" => vec![
                ExpertRole::GrowthMarketer,
                ExpertRole::BusinessAnalyst,
                ExpertRole::LogicVerifier,
            ],
            "business" => vec![
                ExpertRole::BusinessAnalyst,
                ExpertRole::GrowthMarketer,
                ExpertRole::LogicVerifier,
            ],
            "qa" => vec![
                ExpertRole::QaGuardian,
                ExpertRole::SoftwareEngineer,
                ExpertRole::LogicVerifier,
            ],
            _ => vec![
                ExpertRole::BusinessAnalyst,
                ExpertRole::SoftwareEngineer,
                ExpertRole::LogicVerifier,
            ],
        }
    }
}

// ─── Mission Quality Evaluator ────────────────────────────────────────────────

/// 미션 기획 품질을 평가하는 컴포넌트
pub struct MissionQualityEvaluator;

impl MissionQualityEvaluator {
    /// 미션 기획의 품질 점수 계산 (0.0 ~ 1.0)
    pub fn evaluate(mission: &MissionMetadata) -> f64 {
        let mut score = 0.0;
        let mut checks = 0u32;

        // 미션 이름 존재 여부
        checks += 1;
        if !mission.name.is_empty() && mission.name.len() > 5 {
            score += 1.0;
        }

        // ATU(원자 작업 단위) 수량
        checks += 1;
        let task_count = mission.tasks.len();
        if (3..=15).contains(&task_count) {
            score += 1.0;
        } else if task_count > 0 {
            score += 0.5;
        }

        // 각 ATU에 의미 있는 설명이 있는지
        checks += 1;
        let meaningful_tasks = mission.tasks.iter().filter(|t| t.desc.len() > 10).count();
        if meaningful_tasks == task_count && task_count > 0 {
            score += 1.0;
        } else if meaningful_tasks > 0 {
            score += meaningful_tasks as f64 / task_count.max(1) as f64;
        }

        // Capability 태그가 있는지
        checks += 1;
        let tagged_tasks = mission
            .tasks
            .iter()
            .filter(|t| !t.capability.is_empty() && t.capability != "unknown")
            .count();
        if tagged_tasks == task_count && task_count > 0 {
            score += 1.0;
        } else if tagged_tasks > 0 {
            score += tagged_tasks as f64 / task_count.max(1) as f64;
        }

        // 설명(description) 존재 여부
        checks += 1;
        if !mission.description.is_empty() && mission.description.len() > 20 {
            score += 1.0;
        }

        if checks == 0 {
            return 0.0;
        }
        score / checks as f64
    }

    /// 미션 기획에서 할루시네이션 징후 감지
    pub fn detect_hallucination(response_text: &str) -> f64 {
        let mut score = 0.0;
        let text_lower = response_text.to_lowercase();

        // 반복 패턴 감지
        let words: Vec<&str> = response_text.split_whitespace().collect();
        let total_words = words.len();
        if total_words > 0 {
            let unique_words: std::collections::HashSet<_> = words.iter().collect();
            let repetition_ratio = 1.0 - (unique_words.len() as f64 / total_words as f64);
            score += repetition_ratio * 0.3;
        }

        // 확신 없는 표현 패턴
        let vague_patterns = ["maybe", "possibly", "might", "아마", "혹시", "불확실"];
        let vague_count = vague_patterns
            .iter()
            .filter(|p| text_lower.contains(*p))
            .count();
        score += (vague_count as f64 * 0.05).min(0.2);

        // 극단적 주장 패턴
        let extreme_patterns = ["100%", "완벽", "무조건", "항상", "never", "always"];
        let extreme_count = extreme_patterns
            .iter()
            .filter(|p| text_lower.contains(*p))
            .count();
        score += (extreme_count as f64 * 0.05).min(0.15);

        score.min(1.0)
    }
}

// ─── Ensemble Config ──────────────────────────────────────────────────────────

/// 앙상블 설정
#[derive(Debug, Clone)]
pub struct EnsembleConfig {
    /// 사용할 모델 목록 (model_name -> role)
    pub models: Vec<(String, ExpertRole)>,
    /// 최소 합의 임계값 (이 이하면 재시도)
    pub consensus_threshold: f64,
    /// 최대 재시도 횟수
    pub max_retries: u32,
    /// 타임아웃 (밀리초)
    pub timeout_ms: u64,
}

impl EnsembleConfig {
    /// Ollama에 설치된 모델들로 기본 앙상블 설정 생성
    pub fn from_available_models(available: &[String]) -> Self {
        let mut models = Vec::new();

        // 사용 가능한 모델에서 역할 배정
        // 대형 모델은 종합 역할, 소형 모델은 특화 역할
        for (idx, model) in available.iter().take(4).enumerate() {
            let role = match idx {
                0 => ExpertRole::BusinessAnalyst,
                1 => ExpertRole::SoftwareEngineer,
                2 => ExpertRole::QaGuardian,
                3 => ExpertRole::LogicVerifier,
                _ => ExpertRole::Synthesizer,
            };
            models.push((model.clone(), role));
        }

        // 모델이 없으면 기본값
        if models.is_empty() {
            models.push(("llama3.2:3b".to_string(), ExpertRole::Synthesizer));
        }

        Self {
            models,
            consensus_threshold: 0.7,
            max_retries: 2,
            timeout_ms: 600_000,
        }
    }
}

// ─── Consensus Algorithm ──────────────────────────────────────────────────────

/// 다중 모델 응답에서 최선 응답을 선택하는 합의 알고리즘
pub struct ConsensusAlgorithm;

impl ConsensusAlgorithm {
    /// 가중 투표 방식으로 최선 응답 선택
    /// - confidence가 높은 응답에 더 많은 가중치
    /// - 할루시네이션 점수가 낮은 응답에 더 많은 가중치
    /// - LogicVerifier가 검증한 응답에 보너스
    pub fn select_best(responses: &[ExpertResponse]) -> Option<usize> {
        if responses.is_empty() {
            return None;
        }

        let weights: Vec<f64> = responses
            .iter()
            .map(|r| {
                let confidence_weight = r.response.confidence;
                let hallucination_penalty = r.hallucination_score;
                let verifier_bonus = if r.role.contains("verifier") {
                    0.1
                } else {
                    0.0
                };

                (confidence_weight * (1.0 - hallucination_penalty) + verifier_bonus).max(0.0)
            })
            .collect();

        weights
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx)
    }

    /// 응답들 사이의 합의 수준 계산 (0.0 ~ 1.0)
    pub fn calculate_consensus_level(responses: &[ExpertResponse]) -> f64 {
        if responses.len() < 2 {
            return responses
                .first()
                .map(|r| r.response.confidence)
                .unwrap_or(0.0);
        }

        let avg_confidence: f64 =
            responses.iter().map(|r| r.response.confidence).sum::<f64>() / responses.len() as f64;

        let avg_hallucination: f64 =
            responses.iter().map(|r| r.hallucination_score).sum::<f64>() / responses.len() as f64;

        // 평균 신뢰도에서 할루시네이션 패널티 차감
        (avg_confidence - avg_hallucination * 0.5).clamp(0.0, 1.0)
    }

    /// 여러 전문가 응답을 통합한 최종 메시지 생성
    pub fn synthesize_messages(responses: &[ExpertResponse], user_input: &str) -> String {
        if responses.is_empty() {
            return format!("요청을 처리할 수 없습니다: {}", user_input);
        }

        // Synthesizer 역할의 응답이 있으면 우선 사용
        if let Some(syn) = responses
            .iter()
            .find(|r| r.role.contains("synthesizer") || r.role.contains("verifier"))
        {
            return syn.response.message.clone();
        }

        // 없으면 가장 높은 confidence의 응답 사용
        responses
            .iter()
            .max_by(|a, b| {
                a.response
                    .confidence
                    .partial_cmp(&b.response.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|r| r.response.message.clone())
            .unwrap_or_default()
    }
}

// ─── P0-02: Parallel Ensemble Executor ────────────────────────────────────────

/// 병렬 LLM 앙상블 실행 엔진 — Fleet Process의 핵심
///
/// 여러 로컬 AI 모델을 동시에 호출하고, 각 모델이 다른 전문가 역할을 수행하여
/// 결과를 합의 알고리즘으로 통합합니다.
pub struct EnsembleExecutor;

impl EnsembleExecutor {
    /// 병렬 앙상블 실행 — tokio::spawn으로 여러 모델을 동시 호출
    ///
    /// # Arguments
    /// * `config` — 사용할 모델과 역할 매핑
    /// * `user_input` — 사용자 원본 입력
    /// * `domain` — 감지된 도메인 (development, marketing, etc.)
    /// * `provider_fn` — AI 모델 호출 함수 (테스트 시 mock 가능)
    ///
    /// # Returns
    /// `EnsembleResult` — 합의된 최종 응답 + 개별 전문가 응답들
    pub async fn run_parallel<F, Fut>(
        config: &EnsembleConfig,
        user_input: &str,
        domain: &str,
        provider_fn: F,
    ) -> EnsembleResult
    where
        F: Fn(String, String, String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<AiResponse, String>> + Send + 'static,
    {
        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let mut handles = Vec::new();

        // Spawn parallel tasks for each expert model
        for (model_name, role) in &config.models {
            let model = model_name.clone();
            let role_clone = role.clone();
            let input = user_input.to_string();
            let domain_ctx = domain.to_string();
            let system_prompt = role.expert_system_prompt(&domain_ctx);
            let pf = provider_fn.clone();

            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();

                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(300_000), // 5 min per model
                    pf(model.clone(), system_prompt, input.clone()),
                )
                .await;

                let latency_ms = start.elapsed().as_millis() as u64;

                match result {
                    Ok(Ok(response)) => {
                        let hallucination_score =
                            MissionQualityEvaluator::detect_hallucination(&response.message);
                        ExpertResponse {
                            role: role_clone.label().to_string(),
                            model,
                            response,
                            latency_ms,
                            hallucination_score,
                        }
                    }
                    Ok(Err(err)) => ExpertResponse {
                        role: role_clone.label().to_string(),
                        model,
                        response: AiResponse {
                            message: format!("[Error] {}", err),
                            confidence: 0.0,
                            ..Default::default()
                        },
                        latency_ms,
                        hallucination_score: 1.0,
                    },
                    Err(_timeout) => ExpertResponse {
                        role: role_clone.label().to_string(),
                        model,
                        response: AiResponse {
                            message: "[Timeout] Model did not respond in time".to_string(),
                            confidence: 0.0,
                            ..Default::default()
                        },
                        latency_ms,
                        hallucination_score: 1.0,
                    },
                }
            });

            handles.push(handle);
        }

        // Collect all results with global timeout
        let mut expert_responses = Vec::new();
        let global_deadline = tokio::time::timeout(timeout, async {
            for handle in handles {
                if let Ok(resp) = handle.await {
                    expert_responses.push(resp);
                }
            }
        })
        .await;

        if global_deadline.is_err() {
            // Global timeout hit — use whatever we collected so far
            tracing::warn!("Ensemble global timeout reached. Proceeding with partial results.");
        }

        // Apply consensus algorithm
        let consensus_confidence = ConsensusAlgorithm::calculate_consensus_level(&expert_responses);
        let final_message = ConsensusAlgorithm::synthesize_messages(&expert_responses, user_input);

        // Select best response for intent extraction
        let best_intent = ConsensusAlgorithm::select_best(&expert_responses)
            .and_then(|idx| expert_responses.get(idx))
            .and_then(|r| r.response.intent.clone());

        let dissent_count = expert_responses
            .iter()
            .filter(|r| r.hallucination_score > 0.5 || r.response.confidence < 0.3)
            .count() as u32;

        EnsembleResult {
            final_response: AiResponse {
                message: final_message,
                intent: best_intent,
                confidence: consensus_confidence,
                provider: "fleet_ensemble".to_string(),
                is_local: true,
                sub_responses: expert_responses
                    .iter()
                    .map(|r| r.response.clone())
                    .collect(),
            },
            expert_responses,
            consensus_confidence,
            dissent_count,
            process_type: ProcessType::Fleet,
        }
    }
}

// ─── P0-13: Mission Comparison Engine ─────────────────────────────────────────

/// 두 미션 결과물을 비교하여 품질·비용·속도 분석
pub struct MissionComparisonEngine;

/// 미션 비교 결과
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionComparison {
    pub mission_a_id: String,
    pub mission_b_id: String,
    pub quality_score_a: f64,
    pub quality_score_b: f64,
    pub speed_ratio: f64,        // A의 속도 / B의 속도 (>1 = A가 빠름)
    pub task_overlap_ratio: f64, // 공통 Capability 비율
    pub winner: String,          // "A", "B", or "TIE"
    pub recommendation: String,
}

impl MissionComparisonEngine {
    /// 두 미션 메타데이터를 비교 분석
    pub fn compare(mission_a: &MissionMetadata, mission_b: &MissionMetadata) -> MissionComparison {
        let quality_a = MissionQualityEvaluator::evaluate(mission_a);
        let quality_b = MissionQualityEvaluator::evaluate(mission_b);

        // Speed: fewer tasks = faster (simplified heuristic)
        let tasks_a = mission_a.tasks.len().max(1) as f64;
        let tasks_b = mission_b.tasks.len().max(1) as f64;
        let speed_ratio = tasks_b / tasks_a;

        // Task capability overlap
        let caps_a: std::collections::HashSet<_> = mission_a
            .tasks
            .iter()
            .map(|t| t.capability.to_uppercase())
            .collect();
        let caps_b: std::collections::HashSet<_> = mission_b
            .tasks
            .iter()
            .map(|t| t.capability.to_uppercase())
            .collect();
        let intersection = caps_a.intersection(&caps_b).count() as f64;
        let union = caps_a.union(&caps_b).count().max(1) as f64;
        let task_overlap_ratio = intersection / union;

        // Determine winner
        let score_a =
            quality_a * 0.6 + speed_ratio.min(2.0) * 0.2 + task_overlap_ratio * 0.2;
        let score_b = quality_b * 0.6
            + (1.0 / speed_ratio.max(0.01)).min(2.0) * 0.2
            + task_overlap_ratio * 0.2;

        let (winner, recommendation) = if (score_a - score_b).abs() < 0.05 {
            (
                "TIE".to_string(),
                "Both missions are comparable. Choose based on domain preference.".to_string(),
            )
        } else if score_a > score_b {
            ("A".to_string(), format!(
                "Mission '{}' is recommended: higher quality ({:.0}% vs {:.0}%) with {} fewer tasks.",
                mission_a.name, quality_a * 100.0, quality_b * 100.0,
                if tasks_b > tasks_a { (tasks_b - tasks_a) as u32 } else { 0 }
            ))
        } else {
            (
                "B".to_string(),
                format!(
                    "Mission '{}' is recommended: higher quality ({:.0}% vs {:.0}%).",
                    mission_b.name,
                    quality_b * 100.0,
                    quality_a * 100.0
                ),
            )
        };

        MissionComparison {
            mission_a_id: mission_a.id.clone(),
            mission_b_id: mission_b.id.clone(),
            quality_score_a: quality_a,
            quality_score_b: quality_b,
            speed_ratio,
            task_overlap_ratio,
            winner,
            recommendation,
        }
    }
}

// ─── Fleet Mission Planner ────────────────────────────────────────────────────

/// Fleet Process 전용 미션 기획 도우미
pub struct FleetMissionPlanner;

impl FleetMissionPlanner {
    /// 사용자 입력에서 전문가 수준 미션 ATU를 자동 생성
    /// few-shot 예제 기반으로 고품질 미션 분해
    pub fn build_mission_planning_prompt(
        user_input: &str,
        domain: &str,
        peer_count: usize,
    ) -> String {
        let domain_examples = Self::get_domain_examples(domain);
        let peer_info = if peer_count > 1 {
            format!("{} 에이전트가 병렬로 작업을 수행합니다.", peer_count)
        } else {
            "단일 에이전트가 순차적으로 작업을 수행합니다.".to_string()
        };

        format!(
            r#"당신은 EdgeClaw Fleet의 CIO(Chief Intelligence Orchestrator)입니다.
사용자의 요청을 분석하여 전문가 수준의 실행 계획을 수립하세요.

## Fleet 정보
{}

## 미션 기획 원칙
1. 작업을 1분 내에 완료 가능한 원자 단위(ATU)로 분해하라
2. 각 ATU에 명확한 Capability 태그를 부여하라
3. 병렬 실행 가능한 작업은 분리하라
4. 의존 관계가 있는 작업은 순서를 명시하라
5. 소형 로컬 모델도 실행 가능할 정도로 구체적으로 작성하라

## 도메인 예시
{}

## 사용자 요청
"{}"

## 응답 형식 (반드시 준수)
{{
  "message": "미션 기획 완료. [N]개의 원자 작업으로 분해했습니다.",
  "confidence": 0.9,
  "intent": {{
    "capability": "create_mission",
    "command": "orchestrate",
    "args": [],
    "needs_confirmation": true,
    "mission": {{
      "id": "msn-PLACEHOLDER",
      "name": "[구체적인 미션명]",
      "description": "[미션의 목적과 기대 결과]",
      "category": "{}",
      "tags": ["tag1", "tag2"],
      "role": "orchestrator",
      "owner": "ai-agent",
      "goals": ["목표1", "목표2"],
      "status": "Proposed",
      "progress": 0,
      "tasks": [
        {{
          "desc": "[구체적인 작업 설명 — 5W1H 포함]",
          "capability": "SYSTEM_INFO|SHELL_EXEC|NETWORK_SCAN|POLICY_SYNC|PEER_LIST",
          "args": ["인자1", "인자2"],
          "order": 1
        }}
      ],
      "created_at": ""
    }}
  }}
}}"#,
            peer_info, domain_examples, user_input, domain
        )
    }

    fn get_domain_examples(domain: &str) -> &'static str {
        match domain {
            "development" => {
                r#"
예시 — CI/CD 파이프라인 자동화 요청:
tasks:
  - desc: "현재 Git 저장소 상태 확인 (변경된 파일, 브랜치 정보)",  capability: SHELL_EXEC
  - desc: "단위 테스트 실행 및 결과 레포트 생성", capability: SHELL_EXEC
  - desc: "정적 분석(Clippy/ESLint) 실행 및 경고 항목 집계", capability: SHELL_EXEC
  - desc: "보안 취약점 스캔 (cargo audit / npm audit)", capability: SHELL_EXEC
  - desc: "빌드 결과물 생성 및 아티팩트 저장", capability: SHELL_EXEC"#
            }
            "marketing" => {
                r#"
예시 — 소셜 미디어 캠페인 요청:
tasks:
  - desc: "경쟁사 최근 30일 소셜 미디어 게시물 분석 및 트렌드 파악", capability: NETWORK_SCAN
  - desc: "타겟 키워드 30개 해시태그 성과 데이터 수집", capability: NETWORK_SCAN
  - desc: "브랜드 톤앤매너에 맞는 LinkedIn 포스트 초안 3개 생성", capability: SYSTEM_INFO
  - desc: "최적 게시 시간대 분석 및 스케줄 수립", capability: SYSTEM_INFO"#
            }
            "business" => {
                r#"
예시 — 주간 판매 보고서 요청:
tasks:
  - desc: "이번 주 판매 데이터 CSV 추출 (날짜, 제품, 금액, 고객)", capability: SHELL_EXEC
  - desc: "전주 대비 매출 증감율 및 TOP5 제품 계산", capability: SYSTEM_INFO
  - desc: "고객 세그먼트별 구매 패턴 분석", capability: SYSTEM_INFO
  - desc: "Markdown 양식으로 주간 보고서 초안 생성", capability: SHELL_EXEC
  - desc: "보고서를 PDF로 변환하여 지정 폴더에 저장", capability: SHELL_EXEC"#
            }
            _ => {
                r#"
예시 — 일반 자동화 요청:
tasks:
  - desc: "시스템 현재 상태 수집 (CPU, 메모리, 디스크, 네트워크)", capability: SYSTEM_INFO
  - desc: "이전 실행 결과와 비교 분석", capability: SYSTEM_INFO
  - desc: "결과 보고서 생성 및 저장", capability: SHELL_EXEC"#
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_detection_development() {
        assert_eq!(
            DomainDetector::detect_domain("CI/CD 파이프라인 자동화"),
            "development"
        );
        assert_eq!(
            DomainDetector::detect_domain("코드 리뷰해줘"),
            "development"
        );
        assert_eq!(
            DomainDetector::detect_domain("배포 자동화 setup"),
            "development"
        );
    }

    #[test]
    fn test_domain_detection_marketing() {
        assert_eq!(
            DomainDetector::detect_domain("소셜 미디어 캠페인"),
            "marketing"
        );
        assert_eq!(
            DomainDetector::detect_domain("콘텐츠 전략 수립"),
            "marketing"
        );
    }

    #[test]
    fn test_domain_detection_business() {
        assert_eq!(
            DomainDetector::detect_domain("주간 판매 보고서"),
            "business"
        );
        assert_eq!(
            DomainDetector::detect_domain("시장 분석 리포트"),
            "business"
        );
    }

    #[test]
    fn test_expert_roles_for_development() {
        let roles = DomainDetector::get_expert_roles("development");
        assert!(roles.contains(&ExpertRole::SoftwareEngineer));
        assert!(roles.contains(&ExpertRole::QaGuardian));
    }

    #[test]
    fn test_mission_quality_evaluator_empty() {
        let mission = MissionMetadata::default();
        let score = MissionQualityEvaluator::evaluate(&mission);
        assert!(score < 0.5);
    }

    #[test]
    fn test_mission_quality_evaluator_good_mission() {
        use crate::ai::TaskUnit;
        let mut mission = MissionMetadata::default();
        mission.name = "주간 판매 보고서 자동화".to_string();
        mission.description = "판매 데이터를 수집하여 자동으로 보고서를 생성합니다".to_string();
        mission.tasks = vec![
            TaskUnit {
                desc: "판매 데이터 CSV 추출하기".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 1,
            },
            TaskUnit {
                desc: "매출 증감률 계산 및 분석".to_string(),
                capability: "SYSTEM_INFO".to_string(),
                args: vec![],
                order: 2,
            },
            TaskUnit {
                desc: "마크다운 보고서 초안 작성".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 3,
            },
        ];
        let score = MissionQualityEvaluator::evaluate(&mission);
        assert!(score > 0.7, "Expected quality score > 0.7, got {}", score);
    }

    #[test]
    fn test_hallucination_detection_repetitive() {
        let repetitive = "아마 아마 아마 아마 불확실 불확실 불확실";
        let score = MissionQualityEvaluator::detect_hallucination(repetitive);
        assert!(
            score > 0.1,
            "Should detect hallucination in repetitive text"
        );
    }

    #[test]
    fn test_consensus_select_best() {
        let responses = vec![
            ExpertResponse {
                role: "business_analyst".to_string(),
                model: "llama3.2:3b".to_string(),
                response: AiResponse {
                    message: "Low confidence".to_string(),
                    confidence: 0.3,
                    ..Default::default()
                },
                latency_ms: 100,
                hallucination_score: 0.1,
            },
            ExpertResponse {
                role: "software_engineer".to_string(),
                model: "qwen2.5:7b".to_string(),
                response: AiResponse {
                    message: "High confidence".to_string(),
                    confidence: 0.9,
                    ..Default::default()
                },
                latency_ms: 200,
                hallucination_score: 0.0,
            },
        ];
        let best = ConsensusAlgorithm::select_best(&responses);
        assert_eq!(best, Some(1)); // 두 번째가 더 높은 신뢰도
    }

    #[test]
    fn test_fleet_mission_planner_prompt() {
        let prompt = FleetMissionPlanner::build_mission_planning_prompt(
            "주간 판매 보고서 만들어줘",
            "business",
            3,
        );
        assert!(prompt.contains("주간 판매 보고서 만들어줘"));
        assert!(prompt.contains("3 에이전트"));
        assert!(prompt.contains("create_mission"));
    }

    #[test]
    fn test_process_type_default() {
        assert_eq!(ProcessType::default(), ProcessType::Fleet);
    }

    // ─── P0-02: EnsembleExecutor Tests ────────────────────────

    #[tokio::test]
    async fn test_ensemble_executor_parallel_mock() {
        let config = EnsembleConfig {
            models: vec![
                ("model-a".to_string(), ExpertRole::BusinessAnalyst),
                ("model-b".to_string(), ExpertRole::SoftwareEngineer),
            ],
            consensus_threshold: 0.7,
            max_retries: 1,
            timeout_ms: 5000,
        };

        // Mock provider — immediately returns based on model name
        let mock_provider = |model: String, _sys: String, input: String| async move {
            Ok(AiResponse {
                message: format!("[{}] Analyzed: {}", model, input),
                confidence: if model.contains("-a") { 0.85 } else { 0.92 },
                provider: model,
                is_local: true,
                ..Default::default()
            })
        };

        let result =
            EnsembleExecutor::run_parallel(&config, "분석해줘", "business", mock_provider).await;

        assert_eq!(result.expert_responses.len(), 2);
        assert!(result.consensus_confidence > 0.5);
        assert_eq!(result.process_type, ProcessType::Fleet);
        assert!(result.final_response.message.contains("Analyzed"));
    }

    #[tokio::test]
    async fn test_ensemble_executor_handles_errors() {
        let config = EnsembleConfig {
            models: vec![
                ("good-model".to_string(), ExpertRole::Synthesizer),
                ("bad-model".to_string(), ExpertRole::QaGuardian),
            ],
            consensus_threshold: 0.5,
            max_retries: 0,
            timeout_ms: 3000,
        };

        let mock_provider = |model: String, _sys: String, _input: String| async move {
            if model == "bad-model" {
                Err("Connection refused".to_string())
            } else {
                Ok(AiResponse {
                    message: "Good response".to_string(),
                    confidence: 0.9,
                    provider: model,
                    is_local: true,
                    ..Default::default()
                })
            }
        };

        let result =
            EnsembleExecutor::run_parallel(&config, "test", "general", mock_provider).await;

        // Should still produce a result even with one failure
        assert_eq!(result.expert_responses.len(), 2);
        assert!(result.dissent_count >= 1); // bad-model should be counted as dissent
    }

    // ─── P0-13: Mission Comparison Tests ──────────────────────

    #[test]
    fn test_mission_comparison_different_quality() {
        use crate::ai::TaskUnit;

        let mut mission_a = MissionMetadata::default();
        mission_a.id = "msn-a".to_string();
        mission_a.name = "High Quality Mission".to_string();
        mission_a.description =
            "A well-defined mission with clear objectives and deliverables".to_string();
        mission_a.tasks = vec![
            TaskUnit {
                desc: "Collect sales data from CRM".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 1,
            },
            TaskUnit {
                desc: "Generate revenue analysis report".to_string(),
                capability: "SYSTEM_INFO".to_string(),
                args: vec![],
                order: 2,
            },
            TaskUnit {
                desc: "Export results as PDF document".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 3,
            },
        ];

        let mut mission_b = MissionMetadata::default();
        mission_b.id = "msn-b".to_string();
        mission_b.name = "Low Quality".to_string();
        mission_b.tasks = vec![TaskUnit {
            desc: "do it".to_string(),
            capability: "".to_string(),
            args: vec![],
            order: 1,
        }];

        let comparison = MissionComparisonEngine::compare(&mission_a, &mission_b);
        assert!(comparison.quality_score_a > comparison.quality_score_b);
        assert_eq!(comparison.winner, "A");
        assert!(!comparison.recommendation.is_empty());
    }

    #[test]
    fn test_mission_comparison_similar() {
        use crate::ai::TaskUnit;

        let tasks = vec![
            TaskUnit {
                desc: "Analyze market trends from data".to_string(),
                capability: "SYSTEM_INFO".to_string(),
                args: vec![],
                order: 1,
            },
            TaskUnit {
                desc: "Generate competitive analysis".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 2,
            },
            TaskUnit {
                desc: "Create executive summary PDF".to_string(),
                capability: "SHELL_EXEC".to_string(),
                args: vec![],
                order: 3,
            },
        ];

        let mut a = MissionMetadata::default();
        a.name = "Market Analysis A".to_string();
        a.description = "Comprehensive market analysis with competitor benchmarking".to_string();
        a.tasks = tasks.clone();

        let mut b = MissionMetadata::default();
        b.name = "Market Analysis B".to_string();
        b.description = "Thorough market analysis with competitive intelligence".to_string();
        b.tasks = tasks;

        let comparison = MissionComparisonEngine::compare(&a, &b);
        // Identical missions should result in TIE
        assert_eq!(comparison.winner, "TIE");
    }
}
