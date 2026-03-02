# Task Kanban User Guide

> EdgeClaw V4.0 — P2P 분산 작업 관리 (CLI + WebUI)

## 개요

EdgeClaw Task Board는 팀 에이전트 간 작업(Task)을 P2P로 공유하는 분산 칸반 보드입니다. 모든 변경은 ECNP 바이너리 프로토콜로 전파되고, LWW-Register CRDT로 충돌을 자동 해결합니다.

**기능:**
- 4열 칸반: Backlog → In Progress → Review → Done (+ Archived)
- SHA-256 해시체인 무결성
- P2P ECNP 동기화 (TASK_CREATE/UPDATE/QUERY/RESPONSE)
- RBAC 역할별 접근 제어
- JSONL 파일 영구 저장
- WebUI 드래그앤드롭 보드

---

## CLI 사용법

### 작업 목록 조회

```bash
edgeclaw-agent task list
```

출력:

```
Task Board (12 tasks)

[Backlog] (3)
  #a1b2  Low    — Set up CI/CD pipeline
  #c3d4  Medium — Write webhook docs
  #e5f6  High   — Fix memory leak

[In Progress] (2)
  #g7h8  Critical — Implement RBAC filter    (assignee: dev-001)
  #i9j0  High     — Add CBOR benchmarks      (assignee: dev-002)

[Review] (1)
  #k1l2  Medium — Refactor session manager   (assignee: dev-001)

[Done] (6)
  ...
```

### 작업 생성

```bash
edgeclaw-agent task create "Implement webhook retry logic"
```

옵션:

```bash
edgeclaw-agent task create "Fix auth bug" \
  --priority critical \
  --assignee dev-001 \
  --tags "security,auth" \
  --description "JWT token validation fails on expired tokens"
```

### 상태 변경

```bash
# Backlog → In Progress
edgeclaw-agent task move <task-id> in_progress

# In Progress → Review
edgeclaw-agent task move <task-id> review

# Review → Done
edgeclaw-agent task move <task-id> done

# Archived (완료 후 보관)
edgeclaw-agent task move <task-id> archived
```

### 담당자 배정

```bash
edgeclaw-agent task assign <task-id> dev-002
```

---

## WebUI 칸반 보드

브라우저에서 `http://localhost:9444/tasks` 접속:

```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│  Backlog    │ In Progress │   Review    │    Done     │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ ┌─────────┐ │ ┌─────────┐ │ ┌─────────┐ │ ┌─────────┐ │
│ │ Fix bug │ │ │ Webhook │ │ │ Session │ │ │ CBOR    │ │
│ │ High    │ │ │ Critical│ │ │ refactor│ │ │ encode  │ │
│ │ dev-001 │ │ │ dev-002 │ │ │ dev-001 │ │ │ dev-002 │ │
│ └─────────┘ │ └─────────┘ │ └─────────┘ │ └─────────┘ │
│ ┌─────────┐ │             │             │ ┌─────────┐ │
│ │ CI/CD   │ │             │             │ │ Tests   │ │
│ │ Low     │ │             │             │ │ done    │ │
│ └─────────┘ │             │             │ └─────────┘ │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

**조작:**
- **드래그앤드롭**: 카드를 열 사이로 드래그하여 상태 변경
- **카드 클릭**: 상세 정보 (설명, 태그, 담당자, 이력)
- **"+ New Task" 버튼**: 작업 생성 모달
- **자동 새로고침**: 10초마다 최신 데이터 로드

---

## 데이터 구조

### TaskEntry

```json
{
  "id": "a1b2c3d4-...",
  "title": "Implement webhook retry",
  "description": "Add 3-retry exponential backoff",
  "status": "InProgress",
  "assignee": "dev-001",
  "priority": "High",
  "due_date": null,
  "tags": ["webhook", "reliability"],
  "created_at": "2026-03-01T09:00:00Z",
  "updated_at": "2026-03-01T14:30:00Z",
  "hash": "sha256:abc123..."
}
```

### 상태 (TaskStatus)

| 상태         | 설명                |
|-------------|---------------------|
| `Backlog`   | 대기 중             |
| `InProgress`| 진행 중             |
| `Review`    | 리뷰 대기           |
| `Done`      | 완료                |
| `Archived`  | 보관 (보드에서 숨김)  |

### 우선순위 (TaskPriority)

| 우선순위    | 표시 |
|-----------|------|
| `Low`     | 🟢   |
| `Medium`  | 🟡   |
| `High`    | 🟠   |
| `Critical`| 🔴   |

---

## P2P 동기화

### ECNP 메시지 타입

| 메시지 | 코드 | 설명 |
|--------|------|------|
| `TASK_CREATE`   | 0x27 | 작업 생성 브로드캐스트 |
| `TASK_UPDATE`   | 0x28 | 상태/담당자 변경 전파 |
| `TASK_QUERY`    | 0x29 | 작업 목록 요청 |
| `TASK_RESPONSE` | 0x2A | 작업 목록 응답 |

### 충돌 해결 (LWW-Register)

동시에 두 에이전트가 같은 작업을 수정하면, **Last-Writer-Wins** 전략으로 충돌을 해결합니다:

```
Agent A: task.move(#123, "review")  at T=100
Agent B: task.move(#123, "done")    at T=102
→ Result: Task #123 = "done" (T=102 wins)
```

`updated_at` 타임스탬프가 기준이며, 동일 시각인 경우 agent_id 사전순으로 결정합니다.

---

## RBAC 접근 제어

| 역할     | 작업 생성 | 상태 변경 | 담당자 배정 | 조회 |
|---------|----------|----------|-----------|------|
| Owner   | ✅       | ✅       | ✅        | ✅   |
| Admin   | ✅       | ✅       | ✅        | ✅   |
| Operator| ✅       | ✅       | ❌        | ✅   |
| Viewer  | ❌       | ❌       | ❌        | ✅   |

---

## 영구 저장

작업 데이터는 JSONL 형식으로 저장됩니다:

```
~/.edgeclaw/tasks.jsonl
```

- 각 줄: 하나의 `TaskEntry` JSON 객체
- 로드 시 자동 해시체인 검증
- SHA-256 체인: `hash = SHA256(prev_hash + id + title + status + updated_at)`

---

## 테스트

```bash
# Task Board 테스트 (14개)
cargo test task_board::tests

# Team Sync 테스트 (24개, TASK_* 메시지 포함)
cargo test team_sync::tests

# 개별 테스트
cargo test test_create_task
cargo test test_update_task_status
cargo test test_task_hash_chain
cargo test test_filter_tasks_for_role
```

---

> 참고: [Activity Log API](activity-log-api-reference.md) · [Webhook Guide](webhook-integration-guide.md)
