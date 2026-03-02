# Webhook Integration Guide

> EdgeClaw V4.0 — Slack / Discord / 범용 Webhook 연동

## 개요

EdgeClaw는 활동 이벤트 발생 시 외부 서비스로 HTTP POST Webhook을 전송합니다. Slack, Discord 플랫폼은 자동 감지되어 네이티브 메시지 포맷으로 변환됩니다.

**기능:**
- HMAC-SHA256 페이로드 서명 (`X-EdgeClaw-Signature` 헤더)
- 이벤트 필터링 (활동 유형, 최소 중요도, 프로젝트)
- 지수 백오프 재시도 (3회: 1s → 2s → 4s)
- 배치 전송 (5개 이상 묶음)
- Slack Block Kit / Discord Embed 자동 포맷

---

## 설정

### TOML 설정 (`config/default.toml`)

```toml
[webhooks]
enabled = true
max_retries = 3

[[webhooks.endpoints]]
url = "https://hooks.slack.com/services/T00/B00/xxxx"
secret = "my-hmac-secret"
events = ["error", "decision", "session_end"]

[[webhooks.endpoints]]
url = "https://discord.com/api/webhooks/12345/abcdef"
events = []  # 빈 배열 = 모든 이벤트
```

### CLI 관리

```bash
# Webhook 목록 조회
edgeclaw-agent webhook list

# Webhook 추가
edgeclaw-agent webhook add "https://hooks.slack.com/services/T00/B00/xxxx" \
  --secret "my-secret" \
  --events "error,decision"

# Webhook 제거
edgeclaw-agent webhook remove "https://hooks.slack.com/services/T00/B00/xxxx"
```

---

## 페이로드 형식

### 범용 JSON (Generic)

```json
{
  "event": "activity_recorded",
  "timestamp": "2026-03-01T14:30:00Z",
  "agent_id": "dev-001",
  "project": "edgeclaw",
  "activity": {
    "id": "a1b2c3d4-...",
    "type": "error",
    "content": "Connection refused at host:8080",
    "importance": 3,
    "tags": ["network", "critical"]
  }
}
```

### Slack Block Kit

URL에 `hooks.slack.com`이 포함되면 자동 감지됩니다:

```json
{
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*🔴 Error* in `edgeclaw` by `dev-001`\nConnection refused at host:8080"
      }
    },
    {
      "type": "context",
      "elements": [
        { "type": "mrkdwn", "text": "Importance: 3 | 2026-03-01 14:30 UTC" }
      ]
    }
  ]
}
```

### Discord Embed

URL에 `discord.com/api/webhooks`가 포함되면 자동 감지됩니다:

```json
{
  "embeds": [
    {
      "title": "🔴 Error — edgeclaw",
      "description": "Connection refused at host:8080",
      "color": 15158332,
      "fields": [
        { "name": "Agent", "value": "dev-001", "inline": true },
        { "name": "Importance", "value": "3", "inline": true }
      ],
      "timestamp": "2026-03-01T14:30:00Z"
    }
  ]
}
```

---

## HMAC 서명 검증

Webhook 요청에 `secret`이 설정되어 있으면, 모든 페이로드는 HMAC-SHA256으로 서명됩니다.

### 헤더

```
X-EdgeClaw-Signature: sha256=a1b2c3d4e5f6...
Content-Type: application/json
```

### 검증 (예: Node.js)

```javascript
const crypto = require('crypto');

function verifySignature(payload, signature, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

// Express middleware
app.post('/webhook', (req, res) => {
  const sig = req.headers['x-edgeclaw-signature'];
  const body = JSON.stringify(req.body);
  if (!verifySignature(body, sig, process.env.WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  // Process webhook...
  res.sendStatus(200);
});
```

### 검증 (예: Python)

```python
import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

---

## 이벤트 필터링

`events` 배열로 수신할 이벤트 유형을 지정합니다. 빈 배열 (`[]`)은 모든 이벤트를 수신합니다.

| 이벤트 이름      | 트리거 조건                        |
|-----------------|-----------------------------------|
| `file_edit`     | 파일 수정 활동                      |
| `command`       | 커맨드 실행                         |
| `error`         | 에러 발생                          |
| `decision`      | 의사 결정 기록                      |
| `ai_chat`       | AI 대화 활동                        |
| `session_start` | 세션 시작                          |
| `session_end`   | 세션 종료                          |

`min_importance` 필터도 설정 가능합니다 (WebhookConfig 코드 수준):

```rust
WebhookConfig {
    url: "https://...".into(),
    secret: Some("hmac-key".into()),
    events: vec!["error".into()],
    min_importance: 2,  // importance 2 이상만
    batch_mode: false,
}
```

---

## 배치 전송

5개 이상의 이벤트가 단시간에 발생하면 자동으로 배치 처리됩니다:

```json
{
  "event": "activity_batch",
  "count": 7,
  "entries": [ ... ],
  "digest": "sha256:abc123..."
}
```

---

## 재시도 정책

| 시도   | 대기 시간 | 설명                     |
|--------|----------|--------------------------|
| 1차    | 즉시      | 최초 전송                 |
| 2차    | 1초       | HTTP 4xx/5xx 또는 timeout |
| 3차    | 2초       | 지수 백오프               |
| 4차    | 4초       | 최종 재시도               |

3회 재시도 후에도 실패하면 이벤트가 드롭되고 로그에 기록됩니다.

---

## 테스트

```bash
# Webhook 전체 테스트 (13개)
cargo test webhook::tests

# 개별 테스트
cargo test test_webhook_register_unregister
cargo test test_hmac_sign_and_verify
cargo test test_event_filtering
cargo test test_slack_format
cargo test test_discord_format
cargo test test_batch_queue_drain
```

---

> 참고: [Activity Log API](activity-log-api-reference.md) · [AI Summary Guide](ai-summary-configuration-guide.md)
