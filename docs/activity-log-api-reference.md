# Activity Log API Reference

> EdgeClaw V4.0 — REST API + WebSocket 실시간 스트리밍

## Base URL

```
REST:      http://127.0.0.1:9444
WebSocket: ws://127.0.0.1:9445
```

Ports are configurable via `config/default.toml`:

```toml
[webui]
port = 9444
bind = "127.0.0.1"

[websocket]
port = 9445
bind = "127.0.0.1"
```

---

## Authentication

All API endpoints require RBAC authentication via the `Authorization` header:

```
Authorization: Bearer <token>
```

- **Owner / Admin**: Full API access
- **Operator**: Read/write activities and sessions
- **Viewer**: Read-only access
- **Guest**: `GET /api/health` only

---

## REST API Endpoints

### Activities

#### `GET /api/activities`

List activity entries with pagination and filtering.

**Query Parameters:**

| Parameter    | Type     | Default | Description                                   |
|-------------|----------|---------|-----------------------------------------------|
| `offset`    | integer  | `0`     | Pagination offset                             |
| `limit`     | integer  | `50`    | Page size (max 500)                           |
| `project`   | string   | —       | Filter by project name (case-insensitive)     |
| `agent`     | string   | —       | Filter by agent ID                            |
| `type`      | string   | —       | Filter by activity type tag                   |
| `importance`| integer  | —       | Minimum importance level (0–3)                |
| `since`     | RFC 3339 | —       | Entries after this timestamp                  |
| `until`     | RFC 3339 | —       | Entries before this timestamp                 |

**Response:**

```json
{
  "count": 20,
  "total": 1542,
  "offset": 0,
  "limit": 50,
  "entries": [
    {
      "id": "a1b2c3d4-...",
      "session_id": "e5f6g7h8-...",
      "agent_id": "dev-001",
      "agent_role": "admin",
      "agent_name": "agent-1",
      "activity_type": { "FileEdit": { "lines_changed": 42, ... } },
      "project": "edgeclaw",
      "file_path": "src/lib.rs",
      "content": "Refactored session manager",
      "tags": ["refactor", "session"],
      "importance": 2,
      "timestamp": "2026-03-01T14:30:00Z",
      "lamport_clock": 127,
      "prev_hash": "abc123...",
      "hash": "def456...",
      "signature": "hex-encoded-ed25519-sig"
    }
  ]
}
```

**Pagination:** `Link` header is included with `rel="next"` and `rel="prev"` URLs.

---

#### `POST /api/activities/search`

Full-text search across all activity entries using Tantivy.

**Request Body:**

```json
{
  "query": "authentication failure",
  "limit": 20
}
```

**Response:**

```json
{
  "query": "authentication failure",
  "count": 3,
  "entries": [ ... ]
}
```

The search spans `content`, `tags`, `file_path`, `project`, and `agent_name` fields.

---

#### `GET /api/activities/stats`

Aggregate statistics across all activity entries.

**Response:**

```json
{
  "total_entries": 4521,
  "by_type": {
    "file_edit": 1200,
    "command": 800,
    "error": 150,
    "decision": 90,
    "ai_chat": 2281
  },
  "by_project": {
    "edgeclaw": 3000,
    "edgeclaw-core": 1521
  },
  "by_importance": { "0": 500, "1": 2000, "2": 1500, "3": 521 },
  "total_tokens": 1250000,
  "total_cost_usd": 12.50
}
```

---

#### `GET /api/activities/:id`

Get a single activity entry by UUID.

**Response (200):**

```json
{
  "id": "a1b2c3d4-...",
  "activity_type": { "Decision": { "title": "...", "chosen": "...", ... } },
  ...
}
```

**Error (404):**

```json
{ "error": "entry not found" }
```

---

### Sessions

#### `GET /api/sessions`

List all sessions (active + completed) with pagination.

**Query Parameters:**

| Parameter | Type    | Default | Description                    |
|-----------|---------|---------|--------------------------------|
| `offset`  | integer | `0`     | Pagination offset              |
| `limit`   | integer | `50`    | Page size (max 200)            |
| `agent`   | string  | —       | Filter by agent ID             |
| `status`  | string  | —       | Filter by status (`active` / `completed`) |

**Response:**

```json
{
  "count": 10,
  "total": 45,
  "offset": 0,
  "limit": 50,
  "total_cost_usd": 25.30,
  "total_tokens": 3500000,
  "sessions": [ ... ]
}
```

---

#### `GET /api/sessions/:id`

Get session details by UUID.

**Response:**

```json
{
  "session": {
    "id": "e5f6g7h8-...",
    "agent_id": "dev-001",
    "agent_name": "agent-1",
    "project": "edgeclaw",
    "started_at": "2026-03-01T09:00:00Z",
    "ended_at": "2026-03-01T17:30:00Z",
    "status": "Completed",
    "summary": "Implemented webhook system with 13 tests.",
    "total_cost_usd": 2.15,
    "files_changed": ["src/webhook.rs", "src/config.rs"]
  },
  "entry_count": 127
}
```

---

#### `GET /api/sessions/:id/timeline`

Get the activity timeline for a specific session.

**Response:**

```json
{
  "session_id": "e5f6g7h8-...",
  "count": 127,
  "entries": [ ... ]
}
```

---

#### `GET /api/sessions/:id/context`

Get context injection data for a session's project.

**Response:**

```json
{
  "session_id": "e5f6g7h8-...",
  "project": "edgeclaw",
  "context": {
    "recent_summaries": [ ... ],
    "important_activities": [ ... ],
    "recent_errors": [ ... ],
    "active_decisions": [ ... ],
    "memory_md": "# MEMORY.md contents...",
    "repeated_errors": [
      { "message": "connection refused", "count": 5, "last_seen": "..." }
    ],
    "cross_session_insights": [
      "[2026-03-01] agent-1: Implemented CBOR encoding with 15 tests"
    ]
  }
}
```

---

### Health & Metrics

#### `GET /api/health`

```json
{ "status": "ok", "uptime_secs": 3600 }
```

#### `GET /metrics`

Prometheus-format metrics endpoint.

---

## WebSocket API

### Connection

```
ws://127.0.0.1:9445
```

**Authentication** (if `auth_token` is configured):

```json
{ "auth": "your-secret-token" }
```

**Response:**

```json
{ "status": "authenticated" }
```

### Activity Subscription

Subscribe to real-time activity events with optional filters:

```json
{
  "subscribe": {
    "project": "edgeclaw",
    "min_importance": 2,
    "agent": "dev-001"
  }
}
```

All filter fields are optional. With no subscription, the client receives **all** events.

### Event Format

Events are broadcast as JSON:

```json
{
  "ActivityRecorded": {
    "entry_id": "a1b2c3d4-...",
    "project": "edgeclaw",
    "agent_id": "dev-001",
    "importance": 2,
    "activity_type": "file_edit",
    "content": "Updated session manager"
  }
}
```

Other event types: `SessionStarted`, `SessionEnded`, `PeerConnected`, `PeerDisconnected`, `TaskCreated`, `TaskUpdated`.

### Heartbeat

The server sends WebSocket Ping frames every 30 seconds. Clients must respond with Pong within 10 seconds or they are disconnected.

### Connection Limits

- Maximum concurrent clients: **50** (configurable)
- Authentication timeout: **10 seconds**
- Heartbeat interval: **30 seconds**
- Pong timeout: **10 seconds**

---

## Activity Types

| Type Tag     | Fields                                                   |
|-------------|----------------------------------------------------------|
| `file_edit` | `before_snippet`, `after_snippet`, `lines_changed`       |
| `command`   | `command`, `exit_code`, `output_snippet`                 |
| `error`     | `severity`, `message`, `stack_trace`, `resolved`         |
| `decision`  | `title`, `chosen`, `rationale`, `alternatives`           |
| `ai_chat`   | `model`, `input_tokens`, `output_tokens`, `cost_usd`, `role` |
| `custom`    | `category`, `data` (arbitrary JSON)                      |

---

## Error Responses

All errors follow the format:

```json
{ "error": "description of the problem" }
```

| HTTP Status | Meaning                    |
|------------|----------------------------|
| 400        | Bad request / invalid JSON |
| 401        | Unauthorized               |
| 403        | Forbidden (RBAC)           |
| 404        | Not found                  |
| 500        | Internal server error      |

---

## Rate Limits

No rate limiting is enforced at the application level. Deploy behind a reverse proxy (nginx, Caddy) for production rate limiting.

---

> See also: [Webhook Integration Guide](webhook-integration-guide.md) · [Task Kanban User Guide](task-kanban-user-guide.md)
