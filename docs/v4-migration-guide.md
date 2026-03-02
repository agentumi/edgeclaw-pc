# V4.0 Migration Guide (V3.0 → V4.0)

> EdgeClaw V3.0 Nexus → V4.0 Insight 마이그레이션 가이드

## 개요

V4.0 **Insight**는 V3.0 Nexus 위에 팀 활동 가시화, 검색, 분석을 추가한 릴리스입니다. V3.0과 완전한 하위 호환성을 유지하며, 기존 설정과 데이터를 그대로 사용할 수 있습니다.

| 항목 | V3.0 Nexus | V4.0 Insight |
|------|-----------|-------------|
| 테스트 | 686 | 700+ |
| 모듈 | 24 | 30+ |
| ECNP 메시지 | 0x01–0x26 | 0x01–0x2A |
| 바이너리 | 6.31MB | ~6.5MB |

---

## 마이그레이션 단계

### 1. 바이너리 업데이트

```bash
cd edgeclaw_desktop
git pull origin main
cargo build --release

# 바이너리 교체
cp target/release/edgeclaw-agent /usr/local/bin/
```

### 2. 설정 파일 업데이트

V4.0에서 추가된 TOML 섹션을 `config/default.toml`에 추가합니다. 누락된 섹션은 자동으로 기본값이 적용됩니다.

```toml
# === V4.0 신규 설정 ===

[activity_anchor]
enabled = true
interval_secs = 3600     # 앵커링 간격 (초)
min_entries = 10          # 최소 엔트리 수

[webhooks]
enabled = false
max_retries = 3
# [[webhooks.endpoints]] 로 Webhook 추가

[ai_summary]
enabled = false
provider = "ollama"
model = "llama3.2"
api_key = ""
ollama_url = "http://localhost:11434"

[git]
enabled = true
auto_commit = false
attribution_prefix = "[edgeclaw"
```

> **참고:** 기존 V3.0 설정은 그대로 유지됩니다. 새 섹션이 없으면 V4.0 기본값이 자동 적용됩니다.

### 3. 활동 로그 마이그레이션

V4.0은 기존 `activities.jsonl` 파일과 완전 호환됩니다:

- `signature` 필드: `#[serde(default)]` — 없으면 빈 문자열로 자동 처리
- `lamport_clock` 필드: `#[serde(default)]` — 없으면 0으로 시작
- Tantivy 인덱스: 첫 실행 시 `rebuild()` 자동 수행

**추가 조치 불필요** — 기존 JSONL 파일이 그대로 로드됩니다.

### 4. ECNP 프로토콜 호환성

V4.0은 ECNP v1.1을 유지하며 추가 메시지 타입만 확장합니다:

| 코드 범위 | V3.0 | V4.0 |
|----------|------|------|
| 0x01–0x06 | 핵심 메시지 | 변경 없음 |
| 0x20–0x26 | Team Sync | 변경 없음 |
| 0x27–0x2A | — | **신규** Task 메시지 |

V3.0 에이전트는 알 수 없는 메시지 타입(0x27–0x2A)을 자동으로 무시합니다.

### 5. Mobile 앱 업데이트

UniFFI 바인딩에 새 함수가 추가되었지만, 기존 API와 호환됩니다:

```bash
# Rust 코어 재빌드
cd edgeclaw-core
cargo build --target aarch64-linux-android --release

# Android 재빌드
cd ../android
./gradlew assembleDebug

# iOS 재빌드 (macOS)
cd ../ios
./build-rust.sh
./generate-bindings.sh
```

---

## 새로운 기능

### A. Tantivy 전문 검색

기존 in-memory 검색 + Tantivy FTS 인덱스:

```bash
edgeclaw-agent activity search "authentication failure"
```

- 하이라이트 출력 (매칭 컨텍스트 ±40자)
- 복합 필터: 프로젝트, 최소 중요도
- 10K 엔트리 < 50ms 응답

### B. CBOR 직렬화

P2P 메시지 CBOR 인코딩으로 20–30% 크기 절감:

```rust
use edgeclaw::cbor_encoding::{encode_activity_cbor, decode_activity_cbor};

let bytes = encode_activity_cbor(&entry)?;
let decoded = decode_activity_cbor(&bytes)?;
```

JSON 폴백 자동 감지 (`decode_auto()`).

### C. Ed25519 활동 서명

모든 활동 엔트리에 Ed25519 서명 추가:

```bash
# 서명 검증
edgeclaw-agent activity verify
```

### D. 실시간 대시보드

9개의 WebUI 페이지:

| 페이지 | URL | 설명 |
|--------|-----|------|
| Chat | `/` | AI 대화 인터페이스 |
| Dashboard | `/dashboard` | 에이전트 상태 대시보드 |
| Activity Feed | `/activity` | 실시간 활동 타임라인 |
| Sessions | `/sessions` | 세션 목록 |
| Session Detail | `/session/:id` | 세션 상세 |
| Search | `/search` | 전문 검색 |
| Stats | `/stats` | 통계 차트 |
| Team Map | `/team` | P2P 피어 네트워크 맵 |
| Task Board | `/tasks` | 칸반 보드 |

### E. 블록체인 앵커링

Merkle proof 기반 활동 로그 앵커링:

```bash
edgeclaw-agent anchor status
edgeclaw-agent anchor verify <entry-id>
```

### F. Webhook 연동

Slack/Discord 자동 감지 + HMAC 서명:

```bash
edgeclaw-agent webhook add "https://hooks.slack.com/..." --secret "key"
```

### G. AI 요약

세션 자동 요약 (Ollama/OpenAI/Claude):

```toml
[ai_summary]
enabled = true
provider = "ollama"
```

### H. Git 연동

에이전트 변경 자동 커밋 + attribution:

```
[edgeclaw:dev-001:session-123] Refactored session manager
```

### I. Task Kanban

P2P 분산 작업 관리:

```bash
edgeclaw-agent task create "Fix auth bug" --priority critical
edgeclaw-agent task list
edgeclaw-agent task move <id> done
```

---

## 호환성 매트릭스

| 구성요소 | V3.0 → V4.0 | 비고 |
|---------|-------------|------|
| `config/default.toml` | ✅ 호환 | 신규 섹션 자동 기본값 |
| `activities.jsonl` | ✅ 호환 | `signature`, `lamport_clock` serde(default) |
| ECNP 프로토콜 | ✅ 호환 | 미인식 메시지 자동 무시 |
| RBAC 정책 | ✅ 호환 | 기존 5 역할 유지 |
| UniFFI 바인딩 | ✅ 호환 | 신규 함수 추가, 기존 API 유지 |
| Docker 이미지 | ✅ 호환 | 바이너리 교체만 필요 |
| K8s Helm chart | ✅ 호환 | `values.yaml` 동일 |

---

## 롤백

V4.0에서 문제 발생 시 V3.0으로 롤백:

```bash
# V3.0 바이너리로 교체
git checkout v3.0
cargo build --release
cp target/release/edgeclaw-agent /usr/local/bin/

# V4.0 전용 설정 섹션은 자동 무시됨
```

> **주의:** V4.0에서 생성된 `tasks.jsonl`, Tantivy 인덱스 파일은 V3.0에서 무시됩니다 (데이터 손실 없음, 기능만 비활성).

---

## 체크리스트

- [ ] `cargo build --release` 성공
- [ ] `cargo test` 전체 통과
- [ ] `cargo clippy --all-targets -- -D warnings` 0 warnings
- [ ] `config/default.toml` V4.0 섹션 추가
- [ ] WebUI 접속 확인 (`http://localhost:9444`)
- [ ] 기존 활동 로그 로드 확인
- [ ] P2P 연결 확인 (V3.0 에이전트와 혼합 환경)

---

> 참고: [Activity Log API](activity-log-api-reference.md) · [Mobile SDK Guide](mobile-sdk-guide.md) · [Webhook Guide](webhook-integration-guide.md)
