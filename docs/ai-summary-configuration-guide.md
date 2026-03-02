# AI Summary Configuration Guide

> EdgeClaw V4.0 — 세션 자동 요약 + 컨텍스트 인젝션

## 개요

EdgeClaw는 에이전트 세션 종료 시 AI를 사용하여 활동 로그를 자동 요약합니다. 로컬 Ollama를 우선 사용하며, 실패 시 OpenAI → Claude 순으로 폴백합니다.

**기능:**
- 세션별 자동 요약 생성 (`SessionSummarizer`)
- Provider 폴백 체인 (Ollama → OpenAI → Claude)
- 비용 추적 (`estimated_cost()`)
- 컨텍스트 인젝션 (MEMORY.md, 반복 에러, 크로스 세션 인사이트)

---

## 설정

### TOML 설정 (`config/default.toml`)

```toml
[ai_summary]
enabled = true
provider = "ollama"          # "ollama" | "openai" | "claude"
model = "llama3.2"           # 모델명
api_key = ""                 # OpenAI/Claude API 키 (Ollama는 불필요)
ollama_url = "http://localhost:11434"
```

### Provider별 설정 예시

#### Ollama (로컬, 무료)

```toml
[ai_summary]
enabled = true
provider = "ollama"
model = "llama3.2:3b"
ollama_url = "http://localhost:11434"
```

**장점:** 무료, 오프라인 사용 가능, 데이터가 외부로 나가지 않음
**설치:** `curl -fsSL https://ollama.ai/install.sh | sh && ollama pull llama3.2:3b`

#### OpenAI (클라우드)

```toml
[ai_summary]
enabled = true
provider = "openai"
model = "gpt-4o-mini"
api_key = "sk-..."
```

**비용:** ~$0.00015 per 1,000 input tokens (gpt-4o-mini)

#### Claude (클라우드)

```toml
[ai_summary]
enabled = true
provider = "claude"
model = "claude-3-haiku-20240307"
api_key = "sk-ant-..."
```

**비용:** ~$0.00025 per 1,000 input tokens (claude-3-haiku)

---

## 동작 방식

### 세션 자동 요약 흐름

```
세션 종료 (end_session)
    ↓
활동 로그에서 해당 세션의 엔트리 수집
    ↓
build_summary_prompt() → 구조화된 프롬프트 생성
    ↓
SessionSummarizer.summarize_session()
    ↓ (Primary provider 시도)
    ↓ (실패 시 fallback_chain 순회)
    ↓
요약 → AgentSession.summary에 저장
    ↓
SessionMetrics 계산 (files_changed, total_tokens, total_cost)
```

### 폴백 체인

Primary provider가 실패하면 자동으로 다음 provider를 시도합니다:

| Primary  | 폴백 순서                    |
|----------|------------------------------|
| `ollama` | Ollama → OpenAI → Claude     |
| `openai` | OpenAI → Ollama → Claude     |
| `claude` | Claude → Ollama → OpenAI     |

API 키가 없는 클라우드 provider는 체인에서 자동 제외됩니다.

### 프롬프트 구조

```
Summarize the following agent session activities:
- Total activities: 42
- Duration: 3h 15m
- Files changed: 8

Activities:
1. [file_edit] Updated src/webhook.rs (importance: 2)
2. [command] cargo test (importance: 1)
3. [error] Connection refused (importance: 3)
...

Provide a concise summary covering:
1. Key accomplishments
2. Files modified
3. Issues encountered
4. Decisions made
```

---

## 컨텍스트 인젝션

새 세션 시작 시, 이전 세션의 인사이트가 자동으로 주입됩니다:

### 데이터 구조

```rust
pub struct ContextInjection {
    /// 최근 세션 요약 (최대 10개)
    pub recent_summaries: Vec<ActivityBrief>,
    /// 중요 활동 (importance ≥ 2, 최대 20개)
    pub important_activities: Vec<ActivityBrief>,
    /// 최근 에러 (최대 10개)
    pub recent_errors: Vec<ActivityBrief>,
    /// 활성 의사 결정 (최대 20개)
    pub active_decisions: Vec<ActivityBrief>,
    /// MEMORY.md 파일 내용 (4KB 제한)
    pub memory_md: Option<String>,
    /// 반복 에러 (3회 이상 동일 에러)
    pub repeated_errors: Vec<RepeatedError>,
    /// 크로스 세션 인사이트 (최근 5개 세션 하이라이트)
    pub cross_session_insights: Vec<String>,
}
```

### MEMORY.md 로드

프로젝트 루트 또는 작업 디렉토리에 `MEMORY.md` 파일을 두면 자동으로 로드됩니다:

```
검색 순서:
1. ./MEMORY.md (현재 디렉토리)
2. ./memory.md (소문자)
3. ~/.edgeclaw/MEMORY.md (홈 디렉토리)
```

최대 4KB까지만 로드 (초과 시 잘림 + `…[truncated]`).

### 반복 에러 감지

동일한 에러 메시지가 3회 이상 발생하면 `repeated_errors`에 자동 등록됩니다. 에러 메시지는 정규화하여 비교합니다 (파일 경로, 줄 번호 제거).

```json
{
  "message": "connection refused at host",
  "count": 5,
  "last_seen": "2026-03-01T14:30:00Z"
}
```

---

## 비용 추적

각 AI provider의 `estimated_cost()` 메서드로 비용을 추정합니다:

| Provider | 비용 (per 1K tokens) |
|----------|---------------------|
| Ollama   | $0.00 (로컬)        |
| OpenAI   | ~$0.00015           |
| Claude   | ~$0.00025           |

비용은 `AgentSession.total_cost_usd`에 누적되며, `/api/sessions` API에서 조회 가능합니다.

---

## CLI 사용

```bash
# 에이전트 시작 (AI 요약 자동 활성화)
edgeclaw-agent start

# 세션 상태 확인 (요약 포함)
edgeclaw-agent activity stats

# 수동 컨텍스트 조회
# GET /api/sessions/:id/context
curl http://localhost:9444/api/sessions/<session-id>/context
```

---

## 테스트

```bash
# AI 요약 전체 테스트 (12개)
cargo test ai_summary::tests

# 개별 테스트
cargo test test_prompt_generation
cargo test test_session_metrics_extraction
cargo test test_fallback_chain_order
cargo test test_mock_provider_success
cargo test test_session_end_summary_trigger
cargo test test_cost_tracking_estimation
```

---

## 트러블슈팅

| 문제 | 해결 |
|------|------|
| "AI summary is disabled" | `[ai_summary] enabled = true` 설정 |
| Ollama 연결 실패 | `ollama serve` 실행 확인, URL 확인 |
| OpenAI 401 에러 | API 키 확인 (`api_key` 필드) |
| 요약이 생성되지 않음 | 세션에 활동이 충분한지 확인 |
| 비용이 0으로 표시 | Ollama는 무료, 클라우드 provider 전환 필요 |

---

> 참고: [Activity Log API](activity-log-api-reference.md) · [Webhook Guide](webhook-integration-guide.md)
