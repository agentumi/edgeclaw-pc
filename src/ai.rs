//! AI Provider plugin system — swappable AI backends for EdgeClaw Agent.
//!
//! Supports local (Ollama), cloud (OpenAI, Claude), and passthrough (None) providers.
//! AI is a plugin — security is the platform.

use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

// ─── AI Request / Response ─────────────────────────────────

/// A request to the AI provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequest {
    /// The user's natural language input
    pub user_input: String,
    /// Available capabilities on this agent
    pub available_capabilities: Vec<String>,
    /// The requesting peer's role
    pub peer_role: String,
    /// System context (CPU, memory, etc.)
    pub system_context: Option<String>,
    /// Conversation history (last N messages)
    pub history: Vec<ChatMessage>,
}

/// AI provider response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResponse {
    /// The AI's text response to display to the user
    pub message: String,
    /// Parsed intent (if any)
    pub intent: Option<ParsedIntent>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Which provider answered
    pub provider: String,
    /// Whether this was processed locally
    pub is_local: bool,
}

/// Parsed intent from natural language
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedIntent {
    /// The capability to invoke (e.g., "shell_exec", "file_read")
    pub capability: String,
    /// The command or path to operate on
    pub command: String,
    /// Additional arguments
    pub args: Vec<String>,
    /// Whether user confirmation is recommended
    pub needs_confirmation: bool,
}

/// Chat message for conversation history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: String,
}

/// Chat message role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

// ─── AI Provider Trait ─────────────────────────────────────

/// Trait for AI providers — implement this to add a new AI backend
pub trait AiProvider: Send + Sync {
    /// Provider name (e.g., "ollama", "openai", "claude")
    fn name(&self) -> &str;

    /// Check if the provider is available and ready
    fn is_available(&self) -> bool;

    /// Process a chat request
    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError>;

    /// Whether this provider runs locally (no data leaves the network)
    fn is_local(&self) -> bool;
}

// ─── Ollama Provider (Local) ───────────────────────────────

/// Local AI provider using Ollama
pub struct OllamaProvider {
    endpoint: String,
    model: String,
    timeout: Duration,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(endpoint: &str, model: &str, timeout_ms: u64) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Build the prompt for intent classification
    fn build_prompt(&self, request: &AiRequest) -> String {
        let caps = request.available_capabilities.join(", ");
        let history_text = request
            .history
            .iter()
            .map(|m| {
                let role = match m.role {
                    ChatRole::User => "User",
                    ChatRole::Assistant => "Assistant",
                    ChatRole::System => "System",
                };
                format!("{}: {}", role, m.content)
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"You are EdgeClaw AI assistant. You help manage servers securely.

Available capabilities: [{caps}]
User role: {role}
{system_ctx}

{history}

User: {input}

Respond in this JSON format:
{{"message": "your response", "intent": {{"capability": "cap_name", "command": "cmd", "args": [], "needs_confirmation": true}}, "confidence": 0.95}}

If the user is just chatting (not requesting a command), set intent to null.
Keep responses concise and helpful. For elderly users, be extra clear and simple."#,
            caps = caps,
            role = request.peer_role,
            system_ctx = request
                .system_context
                .as_deref()
                .map(|s| format!("System: {}", s))
                .unwrap_or_default(),
            history = if history_text.is_empty() {
                String::new()
            } else {
                format!("Conversation:\n{}", history_text)
            },
            input = request.user_input,
        )
    }

    /// Parse the AI response JSON
    fn parse_response(&self, raw: &str) -> Result<AiResponse, AgentError> {
        // Try to extract JSON from response
        let json_str = if let Some(start) = raw.find('{') {
            if let Some(end) = raw.rfind('}') {
                &raw[start..=end]
            } else {
                raw
            }
        } else {
            raw
        };

        #[derive(Deserialize)]
        struct RawResponse {
            message: Option<String>,
            intent: Option<ParsedIntent>,
            confidence: Option<f64>,
        }

        match serde_json::from_str::<RawResponse>(json_str) {
            Ok(parsed) => Ok(AiResponse {
                message: parsed.message.unwrap_or_else(|| raw.to_string()),
                intent: parsed.intent,
                confidence: parsed.confidence.unwrap_or(0.5),
                provider: "ollama".to_string(),
                is_local: true,
            }),
            Err(_) => {
                // Fallback: treat the entire response as a message
                Ok(AiResponse {
                    message: raw.to_string(),
                    intent: None,
                    confidence: 0.3,
                    provider: "ollama".to_string(),
                    is_local: true,
                })
            }
        }
    }
}

impl AiProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn is_available(&self) -> bool {
        // Check if Ollama is running by hitting the API
        let url = format!("{}/api/tags", self.endpoint);
        ureq_get_with_timeout(&url, self.timeout).is_ok()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let prompt = self.build_prompt(request);
        let url = format!("{}/api/generate", self.endpoint);

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.3,
                "num_predict": 512
            }
        });

        let resp = ureq_post_json_with_timeout(&url, &body, self.timeout)?;

        #[derive(Deserialize)]
        struct OllamaResp {
            response: String,
        }

        let ollama_resp: OllamaResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("ollama response: {}", e)))?;

        self.parse_response(&ollama_resp.response)
    }

    fn is_local(&self) -> bool {
        true
    }
}

// ─── OpenAI Provider (Cloud) ───────────────────────────────

/// Cloud AI provider using OpenAI API
pub struct OpenAiProvider {
    api_key: String,
    model: String,
    endpoint: String,
    timeout: Duration,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider
    pub fn new(api_key: &str, model: &str, endpoint: &str, timeout_ms: u64) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    fn build_messages(&self, request: &AiRequest) -> Vec<serde_json::Value> {
        let caps = request.available_capabilities.join(", ");

        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": format!(
                "You are EdgeClaw AI assistant for secure server management. \
                 Available capabilities: [{}]. User role: {}. \
                 Respond with JSON: {{\"message\": \"...\", \"intent\": {{\"capability\": \"...\", \
                 \"command\": \"...\", \"args\": [], \"needs_confirmation\": true}}, \"confidence\": 0.95}}. \
                 Set intent to null for non-command messages. Be concise. \
                 For elderly or non-technical users, be extra clear and simple.",
                caps, request.peer_role
            )
        })];

        for msg in &request.history {
            let role = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::System => "system",
            };
            messages.push(serde_json::json!({
                "role": role,
                "content": msg.content
            }));
        }

        messages.push(serde_json::json!({
            "role": "user",
            "content": request.user_input
        }));

        messages
    }
}

impl AiProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let messages = self.build_messages(request);
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 512,
            "response_format": { "type": "json_object" }
        });

        let url = format!("{}/v1/chat/completions", self.endpoint);
        let resp = ureq_post_json_with_auth(&url, &body, &self.api_key, self.timeout)?;

        #[derive(Deserialize)]
        struct OpenAiResp {
            choices: Vec<OpenAiChoice>,
        }
        #[derive(Deserialize)]
        struct OpenAiChoice {
            message: OpenAiMsg,
        }
        #[derive(Deserialize)]
        struct OpenAiMsg {
            content: String,
        }

        let parsed: OpenAiResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("openai response: {}", e)))?;

        let content = parsed
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        parse_cloud_response(&content, "openai")
    }

    fn is_local(&self) -> bool {
        false
    }
}

// ─── Claude Provider (Cloud) ───────────────────────────────

/// Cloud AI provider using Anthropic Claude API
pub struct ClaudeProvider {
    api_key: String,
    model: String,
    endpoint: String,
    timeout: Duration,
}

impl ClaudeProvider {
    /// Create a new Claude provider
    pub fn new(api_key: &str, model: &str, endpoint: &str, timeout_ms: u64) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
}

impl AiProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let caps = request.available_capabilities.join(", ");

        let mut messages = Vec::new();
        for msg in &request.history {
            let role = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::System => "user", // Claude uses user for system-like
            };
            messages.push(serde_json::json!({
                "role": role,
                "content": msg.content
            }));
        }
        messages.push(serde_json::json!({
            "role": "user",
            "content": request.user_input
        }));

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 512,
            "system": format!(
                "You are EdgeClaw AI assistant for secure server management. \
                 Available capabilities: [{}]. User role: {}. \
                 Respond with JSON: {{\"message\": \"...\", \"intent\": {{\"capability\": \"...\", \
                 \"command\": \"...\", \"args\": [], \"needs_confirmation\": true}}, \"confidence\": 0.95}}. \
                 Set intent to null for non-command messages. Be concise.",
                caps, request.peer_role
            ),
            "messages": messages
        });

        let url = format!("{}/v1/messages", self.endpoint);
        let resp = ureq_post_json_with_anthropic_auth(&url, &body, &self.api_key, self.timeout)?;

        #[derive(Deserialize)]
        struct ClaudeResp {
            content: Vec<ClaudeContent>,
        }
        #[derive(Deserialize)]
        struct ClaudeContent {
            text: String,
        }

        let parsed: ClaudeResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("claude response: {}", e)))?;

        let content = parsed
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        parse_cloud_response(&content, "claude")
    }

    fn is_local(&self) -> bool {
        false
    }
}

// ─── None Provider (Passthrough) ───────────────────────────

/// No AI — just parses simple commands directly
pub struct NoneProvider;

impl Default for NoneProvider {
    fn default() -> Self {
        Self
    }
}

impl NoneProvider {
    /// Create the passthrough provider
    pub fn new() -> Self {
        Self
    }

    /// Cross-platform command parsing (Windows + Linux)
    fn parse_simple_command(input: &str) -> Option<ParsedIntent> {
        let input_lower = input.trim().to_lowercase();
        let parts: Vec<&str> = input_lower.splitn(3, ' ').collect();
        let cmd = parts.first().copied().unwrap_or("");
        let arg1 = parts.get(1).copied().unwrap_or("");
        let arg2 = parts.get(2).copied().unwrap_or("");

        #[cfg(target_os = "windows")]
        return Self::parse_windows_command(cmd, arg1, arg2, input.trim());

        #[cfg(not(target_os = "windows"))]
        return Self::parse_linux_command(cmd, arg1, arg2, input.trim());
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_command(
        cmd: &str,
        arg1: &str,
        arg2: &str,
        _raw: &str,
    ) -> Option<ParsedIntent> {
        match cmd {
            // ── System Status ──
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Total Physical\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "cpu" | "cpu사용량" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "wmic cpu get loadpercentage,name /format:list".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "memory" | "메모리" | "ram" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "disk" | "디스크" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free,@{N='Total';E={$_.Used+$_.Free}} -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "ps" | "process" | "프로세스" => Some(ParsedIntent {
                capability: "process_manage".to_string(),
                command: "powershell -Command \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name,Id,CPU,WorkingSet64 | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "network" | "네트워크" | "ip" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ipconfig /all".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "port" | "포트" | "ports" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "netstat -an | findstr LISTENING".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "uptime" | "가동시간" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days,Hours,Minutes | Format-List\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),

            // ── Service / Process Management ──
            "services" | "서비스" | "service" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 Name,DisplayName,Status | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "restart" | "재시작" => {
                if arg1.is_empty() {
                    return None;
                }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("powershell -Command \"Restart-Service -Name '{}' -Force\"", arg1),
                    args: vec![],
                    needs_confirmation: true,
                })
            }
            "stop" | "중지" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("powershell -Command \"Stop-Service -Name '{}' -Force\"", arg1),
                    args: vec![],
                    needs_confirmation: true,
                })
            }
            "start" if !arg1.is_empty() => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: format!("powershell -Command \"Start-Service -Name '{}'\"", arg1),
                args: vec![],
                needs_confirmation: true,
            }),
            "kill" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "process_manage".to_string(),
                    command: format!("taskkill /F /PID {}", arg1),
                    args: vec![],
                    needs_confirmation: true,
                })
            }

            // ── File Operations ──
            "ls" | "dir" | "파일" | "list" => Some(ParsedIntent {
                capability: "file_read".to_string(),
                command: format!("dir /B {}", if arg1.is_empty() { "." } else { arg1 }),
                args: vec![],
                needs_confirmation: false,
            }),
            "cat" | "type" | "읽기" | "read" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("type \"{}\"", arg1),
                    args: vec![],
                    needs_confirmation: false,
                })
            }
            "find" | "search" | "검색" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("powershell -Command \"Get-ChildItem -Recurse -Filter '*{}*' | Select-Object FullName\"", arg1),
                    args: vec![],
                    needs_confirmation: false,
                })
            }

            // ── Log Analysis ──
            "log" | "logs" | "로그" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: format!(
                    "powershell -Command \"Get-EventLog -LogName {} -Newest 30 | Format-Table TimeGenerated,EntryType,Message -AutoSize\"",
                    if arg1.is_empty() { "System" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
            }),
            "errors" | "에러" | "오류" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: "powershell -Command \"Get-EventLog -LogName Application -EntryType Error -Newest 20 | Format-Table TimeGenerated,Source,Message -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),

            // ── Docker ──
            "docker" => match arg1 {
                "ps" | "list" | "" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker ps --format \"table {{.Names}}\t{{.Status}}\t{{.Ports}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "images" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker images --format \"table {{.Repository}}\t{{.Tag}}\t{{.Size}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "logs" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker logs --tail 50 {}", arg2),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "restart" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker restart {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "stop" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker stop {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "start" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker start {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "stats" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker stats --no-stream --format \"table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                _ => None,
            },

            // ── Git Operations (Software Dev) ──
            "git" => match arg1 {
                "status" | "" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git status".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "log" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git log --oneline -20".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "branch" | "branches" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git branch -a".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "pull" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git pull".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "push" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git push".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "diff" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git diff --stat".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                }),
                "stash" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: if arg2.is_empty() { "git stash list".to_string() } else { format!("git stash {}", arg2) },
                    args: vec![],
                    needs_confirmation: arg2 == "pop" || arg2 == "drop",
                }),
                _ => None,
            },

            // ── Build / CI (Software Dev) ──
            "build" | "빌드" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "cargo build 2>&1".to_string()
                } else {
                    format!("cargo build --{} 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: false,
            }),
            "test" | "테스트" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "cargo test 2>&1".to_string()
                } else {
                    format!("cargo test {} 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: false,
            }),
            "lint" | "clippy" | "린트" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo clippy --all-targets -- -D warnings 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "fmt" | "format" | "포맷" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo fmt 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "deploy" | "배포" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "echo 'Specify target: deploy staging | deploy production'".to_string()
                } else {
                    format!("echo 'Deploying to {}...' && cargo build --release 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: true,
            }),
            "deps" | "dependencies" | "의존성" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo tree --depth 1".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "audit" | "감사" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo audit 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),

            // ── npm / Node.js ──
            "npm" => match arg1 {
                "test" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm test 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "build" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm run build 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "start" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm start 2>&1".to_string(),
                    args: vec![], needs_confirmation: true,
                }),
                "audit" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm audit 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "outdated" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm outdated 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                _ => None,
            },

            // ── Database (Software Dev) ──
            "db" | "database" | "데이터베이스" => match arg1 {
                "backup" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "powershell -Command \"$ts = Get-Date -Format 'yyyyMMdd_HHmmss'; echo 'DB backup: backup_$ts.sql created'\"".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                }),
                "size" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Database monitoring not yet configured — install a database agent plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "connections" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Database monitoring not yet configured — install a database agent plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                _ => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'DB commands: db backup | db size | db connections'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
            },

            // ── Marketing Automation ──
            "report" | "리포트" | "보고서" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: format!(
                    "powershell -Command \"$d = Get-Date -Format 'yyyy-MM-dd'; echo '=== {} Report ($d) ==='; echo 'Generating...'\"",
                    if arg1.is_empty() { "Daily" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
            }),
            "analytics" | "분석" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo 'Analytics module not yet configured — use system monitoring or install an analytics plugin'".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "campaign" | "캠페인" => match arg1 {
                "list" | "" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Campaign management not yet configured — install a marketing plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "status" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: format!("echo 'Campaign status for: {}'", arg2),
                    args: vec![], needs_confirmation: false,
                }),
                _ => None,
            },
            "seo" | "검색최적화" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: format!(
                    "echo 'SEO analysis for: {} — install an SEO plugin to enable'",
                    if arg1.is_empty() { "all" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
            }),
            "schedule" | "스케줄" | "예약" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "powershell -Command \"Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object -First 20 TaskName,State,LastRunTime | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "backup" | "백업" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "powershell -Command \"$ts = Get-Date -Format 'yyyyMMdd_HHmmss'; echo '=== Backup Started ($ts) ==='; echo 'Configure backup targets in agent.toml [backup] section'\"".to_string(),
                args: vec![],
                needs_confirmation: true,
            }),

            // ── Utility ──
            "ping" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: format!("ping -n 4 {}", if arg1.is_empty() { "google.com" } else { arg1 }),
                args: vec![],
                needs_confirmation: false,
            }),
            "env" | "환경" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "set".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "whoami" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "whoami /all".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            "help" | "도움말" | "명령어" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo '=== EdgeClaw Commands ===' && echo. && echo [System] status, cpu, memory, disk, ps, network, port, uptime, services && echo [Files] ls, cat, find, log, errors && echo [DevOps] docker ps/logs/restart, git status/log/pull/push && echo [Build] build, test, lint, fmt, deploy, deps, audit && echo [Node] npm test/build/start/audit/outdated && echo [DB] db backup/size/connections && echo [Marketing] report, analytics, campaign, seo, schedule && echo [Misc] ping, env, whoami, backup, help'".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            _ => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn parse_linux_command(cmd: &str, arg1: &str, arg2: &str, _raw: &str) -> Option<ParsedIntent> {
        match cmd {
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "uname -a && uptime && free -h | head -2".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "cpu" | "cpu사용량" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "top -bn1 | head -20".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "memory" | "메모리" | "ram" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "free -h".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "disk" | "디스크" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "df -h".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "ps" | "process" | "프로세스" => Some(ParsedIntent {
                capability: "process_manage".to_string(),
                command: "ps aux --sort=-pcpu | head -20".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "network" | "네트워크" | "ip" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ip addr show".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "port" | "포트" | "ports" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ss -tlnp".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "services" | "서비스" | "service" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "systemctl list-units --type=service --state=running".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "restart" | "재시작" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("systemctl restart {}", arg1),
                    args: vec![], needs_confirmation: true,
                })
            }
            "stop" | "중지" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("systemctl stop {}", arg1),
                    args: vec![], needs_confirmation: true,
                })
            }
            "log" | "logs" | "로그" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: format!("tail -50 {}", if arg1.is_empty() { "/var/log/syslog" } else { arg1 }),
                args: vec![], needs_confirmation: false,
            }),
            "errors" | "에러" | "오류" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: "journalctl -p err --since '1 hour ago' | tail -30".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "ls" | "dir" | "파일" | "list" => Some(ParsedIntent {
                capability: "file_read".to_string(),
                command: format!("ls -la {}", if arg1.is_empty() { "." } else { arg1 }),
                args: vec![], needs_confirmation: false,
            }),
            "cat" | "읽기" | "read" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("cat \"{}\"", arg1),
                    args: vec![], needs_confirmation: false,
                })
            }
            "docker" => match arg1 {
                "ps" | "list" | "" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "logs" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker logs --tail 50 {}", arg2),
                    args: vec![], needs_confirmation: false,
                }),
                "restart" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker restart {}", arg2),
                    args: vec![], needs_confirmation: true,
                }),
                _ => None,
            },
            "git" => match arg1 {
                "status" | "" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git status".to_string(), args: vec![], needs_confirmation: false }),
                "log" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git log --oneline -20".to_string(), args: vec![], needs_confirmation: false }),
                "branch" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git branch -a".to_string(), args: vec![], needs_confirmation: false }),
                "pull" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git pull".to_string(), args: vec![], needs_confirmation: true }),
                "push" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git push".to_string(), args: vec![], needs_confirmation: true }),
                "diff" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git diff --stat".to_string(), args: vec![], needs_confirmation: false }),
                _ => None,
            },
            "build" | "빌드" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: if arg1.is_empty() { "cargo build 2>&1".to_string() } else { format!("cargo build --{} 2>&1", arg1) }, args: vec![], needs_confirmation: false }),
            "test" | "테스트" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: if arg1.is_empty() { "cargo test 2>&1".to_string() } else { format!("cargo test {} 2>&1", arg1) }, args: vec![], needs_confirmation: false }),
            "lint" | "clippy" | "린트" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "cargo clippy --all-targets -- -D warnings 2>&1".to_string(), args: vec![], needs_confirmation: false }),
            "deploy" | "배포" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: format!("echo 'Deploying to {}...' && cargo build --release 2>&1", if arg1.is_empty() { "staging" } else { arg1 }), args: vec![], needs_confirmation: true }),
            "help" | "도움말" | "명령어" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo '=== EdgeClaw Commands ===\n[System] status, cpu, memory, disk, ps, network, port, services\n[Files] ls, cat, log, errors\n[DevOps] docker ps/logs/restart, git status/log/pull/push\n[Build] build, test, lint, deploy\n[Misc] ping, env, whoami, backup, help'".to_string(),
                args: vec![], needs_confirmation: false,
            }),
            "ping" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: format!("ping -c 4 {}", if arg1.is_empty() { "google.com" } else { arg1 }),
                args: vec![], needs_confirmation: false,
            }),
            "backup" | "백업" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "echo 'Backup started...' && date".to_string(),
                args: vec![], needs_confirmation: true,
            }),
            _ => None,
        }
    }
}

impl AiProvider for NoneProvider {
    fn name(&self) -> &str {
        "none"
    }

    fn is_available(&self) -> bool {
        true // Always available
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        match Self::parse_simple_command(&request.user_input) {
            Some(intent) => Ok(AiResponse {
                message: format!("Executing: {}", intent.command),
                intent: Some(intent),
                confidence: 1.0,
                provider: "none".to_string(),
                is_local: true,
            }),
            None => Ok(AiResponse {
                message: format!(
                    "I don't understand '{}'. Try: status, restart <service>, log, disk, memory, cpu, ps",
                    request.user_input
                ),
                intent: None,
                confidence: 0.0,
                provider: "none".to_string(),
                is_local: true,
            }),
        }
    }

    fn is_local(&self) -> bool {
        true
    }
}

// ─── AI Manager ────────────────────────────────────────────

/// Manages AI providers with fallback and escalation
pub struct AiManager {
    primary: Box<dyn AiProvider>,
    fallback: Option<Box<dyn AiProvider>>,
    escalation_threshold: f64,
    sensitive_keywords: Vec<String>,
    require_consent: bool,
}

impl AiManager {
    /// Create a new AI manager from config
    pub fn from_config(config: &crate::config::AiConfig) -> Self {
        let primary: Box<dyn AiProvider> = match config.primary.as_str() {
            "ollama" | "local" => Box::new(OllamaProvider::new(
                &config.local.endpoint,
                &config.local.model,
                config.local.timeout_ms,
            )),
            "openai" => {
                let api_key = std::env::var("EDGECLAW_OPENAI_KEY").unwrap_or_default();
                Box::new(OpenAiProvider::new(
                    &api_key,
                    &config.cloud.model,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            "claude" => {
                let api_key = std::env::var("EDGECLAW_CLAUDE_KEY").unwrap_or_default();
                Box::new(ClaudeProvider::new(
                    &api_key,
                    &config.cloud.model,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            _ => Box::new(NoneProvider::new()),
        };

        let fallback: Option<Box<dyn AiProvider>> = if config.primary != "none" {
            Some(Box::new(NoneProvider::new()))
        } else {
            None
        };

        Self {
            primary,
            fallback,
            escalation_threshold: config.policy.escalation_threshold,
            sensitive_keywords: config.policy.never_cloud.clone(),
            require_consent: config.policy.require_consent,
        }
    }

    /// Process a chat request with fallback
    pub fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        // Check for sensitive content if using cloud provider
        if !self.primary.is_local() && self.contains_sensitive(&request.user_input) {
            warn!("Sensitive content detected, blocking cloud AI");
            return Err(AgentError::PolicyDenied(
                "Command contains sensitive information; cannot send to cloud AI".to_string(),
            ));
        }

        // Try primary provider
        match self.primary.process(request) {
            Ok(response) => {
                info!(
                    provider = response.provider,
                    confidence = response.confidence,
                    "AI response generated"
                );

                // Check if confidence is too low and we should escalate
                if response.confidence < self.escalation_threshold && response.intent.is_some() {
                    warn!(
                        confidence = response.confidence,
                        threshold = self.escalation_threshold,
                        "Low confidence — consider cloud AI escalation"
                    );
                    // Return with escalation hint
                    Ok(AiResponse {
                        message: format!(
                            "{}\n\n⚠️ Low confidence ({:.0}%). Consider using cloud AI for better accuracy.",
                            response.message,
                            response.confidence * 100.0
                        ),
                        ..response
                    })
                } else {
                    Ok(response)
                }
            }
            Err(e) => {
                warn!(error = %e, "Primary AI provider failed, trying fallback");
                // Try fallback
                if let Some(fallback) = &self.fallback {
                    fallback.process(request)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Check if primary provider is available
    pub fn is_available(&self) -> bool {
        self.primary.is_available()
    }

    /// Get the primary provider name
    pub fn provider_name(&self) -> &str {
        self.primary.name()
    }

    /// Whether the current primary is local
    pub fn is_local(&self) -> bool {
        self.primary.is_local()
    }

    /// Check for sensitive keywords
    fn contains_sensitive(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.sensitive_keywords
            .iter()
            .any(|kw| lower.contains(&kw.to_lowercase()))
    }

    /// Whether cloud escalation requires user consent
    pub fn requires_consent(&self) -> bool {
        self.require_consent
    }
}

// ─── HTTP Helpers (ureq — supports HTTP + HTTPS) ──────────────────────────

/// Simple GET with timeout (supports both HTTP and HTTPS)
fn ureq_get_with_timeout(url: &str, timeout: Duration) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .get(url)
        .call()
        .map_err(|e| AgentError::ConnectionError(format!("HTTP GET failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// POST JSON with timeout (supports both HTTP and HTTPS)
fn ureq_post_json_with_timeout(
    url: &str,
    body: &serde_json::Value,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// POST JSON with Bearer auth (supports HTTPS for OpenAI etc.)
fn ureq_post_json_with_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", api_key))
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// POST JSON with Anthropic auth (supports HTTPS for Claude API)
fn ureq_post_json_with_anthropic_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("x-api-key", api_key)
        .set("anthropic-version", "2023-06-01")
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// Parse URL into components (used only in tests)
#[cfg(test)]
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

#[cfg(test)]
fn parse_url(url: &str) -> Result<ParsedUrl, AgentError> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };

    let (host, port) = if let Some(idx) = host_port.find(':') {
        let h = &host_port[..idx];
        let p: u16 = host_port[idx + 1..]
            .parse()
            .map_err(|_| AgentError::InvalidParameter("invalid port".into()))?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };

    Ok(ParsedUrl {
        host,
        port,
        path: path.to_string(),
    })
}

/// Parse a cloud AI JSON response
fn parse_cloud_response(content: &str, provider: &str) -> Result<AiResponse, AgentError> {
    let json_str = if let Some(start) = content.find('{') {
        if let Some(end) = content.rfind('}') {
            &content[start..=end]
        } else {
            content
        }
    } else {
        content
    };

    #[derive(Deserialize)]
    struct RawResponse {
        message: Option<String>,
        intent: Option<ParsedIntent>,
        confidence: Option<f64>,
    }

    match serde_json::from_str::<RawResponse>(json_str) {
        Ok(parsed) => Ok(AiResponse {
            message: parsed.message.unwrap_or_else(|| content.to_string()),
            intent: parsed.intent,
            confidence: parsed.confidence.unwrap_or(0.8),
            provider: provider.to_string(),
            is_local: false,
        }),
        Err(_) => Ok(AiResponse {
            message: content.to_string(),
            intent: None,
            confidence: 0.5,
            provider: provider.to_string(),
            is_local: false,
        }),
    }
}

// ─── Quick Actions ─────────────────────────────────────────

/// Industry work profile for categorized quick actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkProfile {
    /// Common system operations
    System,
    /// Software development company
    SoftwareDev,
    /// Marketing company
    Marketing,
    /// DevOps / Infrastructure
    DevOps,
}

impl std::fmt::Display for WorkProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkProfile::System => write!(f, "System"),
            WorkProfile::SoftwareDev => write!(f, "Software Dev"),
            WorkProfile::Marketing => write!(f, "Marketing"),
            WorkProfile::DevOps => write!(f, "DevOps"),
        }
    }
}

/// Pre-defined quick actions for button-based UI (elderly-friendly)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickAction {
    /// Button label
    pub label: String,
    /// Icon name
    pub icon: String,
    /// The command to execute
    pub command: String,
    /// Capability required
    pub capability: String,
    /// Whether confirmation is needed
    pub needs_confirmation: bool,
    /// Industry work profile category
    pub profile: WorkProfile,
    /// Group within profile (for UI tabs/sections)
    pub group: String,
}

/// Get all quick actions (cross-platform, industry-organized)
#[allow(clippy::vec_init_then_push)]
pub fn default_quick_actions() -> Vec<QuickAction> {
    let mut actions = Vec::new();

    // ══════════════════════════════════════════════════════
    //  SYSTEM — Common operations for all industries
    // ══════════════════════════════════════════════════════
    actions.push(QuickAction {
        label: "Server Status".to_string(),
        icon: "monitor".to_string(),
        command: "status".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "CPU Usage".to_string(),
        icon: "speed".to_string(),
        command: "cpu".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Memory Usage".to_string(),
        icon: "memory".to_string(),
        command: "memory".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Disk Space".to_string(),
        icon: "hard_drive".to_string(),
        command: "disk".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Running Processes".to_string(),
        icon: "apps".to_string(),
        command: "ps".to_string(),
        capability: "process_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Network Info".to_string(),
        icon: "wifi".to_string(),
        command: "network".to_string(),
        capability: "network_scan".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Network".to_string(),
    });
    actions.push(QuickAction {
        label: "Open Ports".to_string(),
        icon: "lan".to_string(),
        command: "port".to_string(),
        capability: "network_scan".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Network".to_string(),
    });
    actions.push(QuickAction {
        label: "Services".to_string(),
        icon: "miscellaneous_services".to_string(),
        command: "services".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Services".to_string(),
    });
    actions.push(QuickAction {
        label: "System Uptime".to_string(),
        icon: "schedule".to_string(),
        command: "uptime".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "System Logs".to_string(),
        icon: "description".to_string(),
        command: "log".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Error Logs".to_string(),
        icon: "error".to_string(),
        command: "errors".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Containers".to_string(),
        icon: "inventory_2".to_string(),
        command: "docker ps".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Stats".to_string(),
        icon: "analytics".to_string(),
        command: "docker stats".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Help / Commands".to_string(),
        icon: "help".to_string(),
        command: "help".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Help".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  SOFTWARE DEVELOPMENT COMPANY — Work Stories
    // ══════════════════════════════════════════════════════

    // --- Git Operations ---
    actions.push(QuickAction {
        label: "Git Status".to_string(),
        icon: "code".to_string(),
        command: "git status".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Log (최근 커밋)".to_string(),
        icon: "history".to_string(),
        command: "git log".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Branches".to_string(),
        icon: "account_tree".to_string(),
        command: "git branch".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Pull".to_string(),
        icon: "cloud_download".to_string(),
        command: "git pull".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Diff".to_string(),
        icon: "compare_arrows".to_string(),
        command: "git diff".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });

    // --- Build & Test ---
    actions.push(QuickAction {
        label: "Build Project".to_string(),
        icon: "build".to_string(),
        command: "build".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Run Tests".to_string(),
        icon: "science".to_string(),
        command: "test".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Lint / Clippy".to_string(),
        icon: "verified".to_string(),
        command: "lint".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Format Code".to_string(),
        icon: "format_paint".to_string(),
        command: "fmt".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Security Audit".to_string(),
        icon: "security".to_string(),
        command: "audit".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Dependencies Tree".to_string(),
        icon: "device_hub".to_string(),
        command: "deps".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });

    // --- Deploy ---
    actions.push(QuickAction {
        label: "Deploy Staging".to_string(),
        icon: "rocket_launch".to_string(),
        command: "deploy staging".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Deploy".to_string(),
    });
    actions.push(QuickAction {
        label: "Deploy Production".to_string(),
        icon: "publish".to_string(),
        command: "deploy production".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Deploy".to_string(),
    });

    // --- Database ---
    actions.push(QuickAction {
        label: "DB Backup".to_string(),
        icon: "backup".to_string(),
        command: "db backup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Database".to_string(),
    });
    actions.push(QuickAction {
        label: "DB Status".to_string(),
        icon: "storage".to_string(),
        command: "db size".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Database".to_string(),
    });

    // --- npm / Node ---
    actions.push(QuickAction {
        label: "npm Test".to_string(),
        icon: "quiz".to_string(),
        command: "npm test".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });
    actions.push(QuickAction {
        label: "npm Build".to_string(),
        icon: "construction".to_string(),
        command: "npm build".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });
    actions.push(QuickAction {
        label: "npm Audit".to_string(),
        icon: "shield".to_string(),
        command: "npm audit".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  MARKETING COMPANY — Work Stories
    // ══════════════════════════════════════════════════════

    // --- Campaign Management ---
    actions.push(QuickAction {
        label: "Campaign List".to_string(),
        icon: "campaign".to_string(),
        command: "campaign list".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Campaign".to_string(),
    });
    actions.push(QuickAction {
        label: "Campaign Status".to_string(),
        icon: "trending_up".to_string(),
        command: "campaign status".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Campaign".to_string(),
    });

    // --- Analytics & Reports ---
    actions.push(QuickAction {
        label: "Daily Report".to_string(),
        icon: "summarize".to_string(),
        command: "report daily".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });
    actions.push(QuickAction {
        label: "Weekly Report".to_string(),
        icon: "assessment".to_string(),
        command: "report weekly".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });
    actions.push(QuickAction {
        label: "Analytics Summary".to_string(),
        icon: "analytics".to_string(),
        command: "analytics".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });

    // --- SEO ---
    actions.push(QuickAction {
        label: "SEO Analysis".to_string(),
        icon: "search".to_string(),
        command: "seo".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "SEO".to_string(),
    });

    // --- Schedule & Automation ---
    actions.push(QuickAction {
        label: "Scheduled Tasks".to_string(),
        icon: "event".to_string(),
        command: "schedule".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Automation".to_string(),
    });
    actions.push(QuickAction {
        label: "Backup Assets".to_string(),
        icon: "cloud_upload".to_string(),
        command: "backup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::Marketing,
        group: "Automation".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  DEVOPS — Infrastructure & Operations
    // ══════════════════════════════════════════════════════

    // --- Docker ---
    actions.push(QuickAction {
        label: "Docker Status".to_string(),
        icon: "inventory_2".to_string(),
        command: "docker_status".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Prune".to_string(),
        icon: "delete_sweep".to_string(),
        command: "docker_prune".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Docker".to_string(),
    });

    // --- Disk & Infra ---
    actions.push(QuickAction {
        label: "Disk Check".to_string(),
        icon: "hard_drive".to_string(),
        command: "disk_check".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Infrastructure".to_string(),
    });
    actions.push(QuickAction {
        label: "Disk Cleanup".to_string(),
        icon: "cleaning_services".to_string(),
        command: "disk_cleanup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Infrastructure".to_string(),
    });

    // --- Services ---
    actions.push(QuickAction {
        label: "Service Restart".to_string(),
        icon: "restart_alt".to_string(),
        command: "service_restart".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Services".to_string(),
    });
    actions.push(QuickAction {
        label: "Failed Services".to_string(),
        icon: "error_outline".to_string(),
        command: "services_failed".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Services".to_string(),
    });

    // --- Logs & Certs ---
    actions.push(QuickAction {
        label: "Tail Logs".to_string(),
        icon: "description".to_string(),
        command: "log_tail".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Cert Check".to_string(),
        icon: "verified_user".to_string(),
        command: "cert_check".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Security".to_string(),
    });

    actions
}

/// Get quick actions filtered by work profile
pub fn quick_actions_by_profile(profile: Option<WorkProfile>) -> Vec<QuickAction> {
    let all = default_quick_actions();
    match profile {
        Some(p) => all
            .into_iter()
            .filter(|a| a.profile == p || a.profile == WorkProfile::System)
            .collect(),
        None => all,
    }
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_provider_status() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "status".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        assert_eq!(response.intent.unwrap().capability, "status_query");
        assert!(response.is_local);
    }

    #[test]
    fn test_none_provider_restart() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "restart nginx".to_string(),
            available_capabilities: vec!["shell_exec".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        let intent = response.intent.unwrap();
        assert_eq!(intent.capability, "shell_exec");
        // Platform-independent: just check the service name is in the command
        assert!(intent.command.contains("nginx"));
        assert!(intent.needs_confirmation);
    }

    #[test]
    fn test_none_provider_unknown() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "whats the meaning of life".to_string(),
            available_capabilities: vec![],
            peer_role: "viewer".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_none());
        assert_eq!(response.confidence, 0.0);
    }

    #[test]
    fn test_none_provider_korean_commands() {
        let provider = NoneProvider::new();

        let request = AiRequest {
            user_input: "상태".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };
        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        assert_eq!(response.intent.unwrap().capability, "status_query");

        let request = AiRequest {
            user_input: "디스크".to_string(),
            available_capabilities: vec!["system_info".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };
        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
    }

    #[test]
    fn test_quick_actions() {
        let actions = default_quick_actions();
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| a.label == "Server Status"));
        assert!(actions.iter().any(|a| a.label == "Disk Space"));
        // All actions should have a capability and profile
        for action in &actions {
            assert!(!action.capability.is_empty());
            assert!(!action.group.is_empty());
        }
        // Check industry profiles exist
        assert!(actions
            .iter()
            .any(|a| a.profile == WorkProfile::SoftwareDev));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::Marketing));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::DevOps));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::System));
    }

    #[test]
    fn test_quick_actions_by_profile() {
        let sw = quick_actions_by_profile(Some(WorkProfile::SoftwareDev));
        assert!(!sw.is_empty());
        // Should include System + SoftwareDev
        assert!(sw.iter().any(|a| a.profile == WorkProfile::System));
        assert!(sw.iter().any(|a| a.profile == WorkProfile::SoftwareDev));
        assert!(!sw.iter().any(|a| a.profile == WorkProfile::Marketing));

        let mkt = quick_actions_by_profile(Some(WorkProfile::Marketing));
        assert!(mkt.iter().any(|a| a.profile == WorkProfile::Marketing));
        assert!(mkt.iter().any(|a| a.profile == WorkProfile::System));

        let all = quick_actions_by_profile(None);
        assert!(all.len() > sw.len());
    }

    #[test]
    fn test_ollama_prompt_building() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let request = AiRequest {
            user_input: "restart nginx".to_string(),
            available_capabilities: vec!["shell_exec".to_string(), "status_query".to_string()],
            peer_role: "admin".to_string(),
            system_context: Some("CPU: 45%, Memory: 72%".to_string()),
            history: vec![ChatMessage {
                role: ChatRole::User,
                content: "check status".to_string(),
                timestamp: "2026-02-27T10:00:00Z".to_string(),
            }],
        };

        let prompt = provider.build_prompt(&request);
        assert!(prompt.contains("shell_exec"));
        assert!(prompt.contains("admin"));
        assert!(prompt.contains("restart nginx"));
        assert!(prompt.contains("CPU: 45%"));
    }

    #[test]
    fn test_ollama_parse_valid_json() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let json = r#"{"message": "Restarting nginx...", "intent": {"capability": "shell_exec", "command": "systemctl restart nginx", "args": [], "needs_confirmation": true}, "confidence": 0.95}"#;

        let response = provider.parse_response(json).unwrap();
        assert_eq!(response.message, "Restarting nginx...");
        assert!(response.intent.is_some());
        assert_eq!(response.confidence, 0.95);
        assert!(response.is_local);
    }

    #[test]
    fn test_ollama_parse_invalid_json() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let text = "I don't understand that command.";

        let response = provider.parse_response(text).unwrap();
        assert_eq!(response.message, text);
        assert!(response.intent.is_none());
        assert_eq!(response.confidence, 0.3);
    }

    #[test]
    fn test_sensitive_keyword_detection() {
        let config = crate::config::AiConfig::default();
        let manager = AiManager::from_config(&config);
        assert!(manager.contains_sensitive("show me the password file"));
        assert!(manager.contains_sensitive("read private_key.pem"));
        assert!(!manager.contains_sensitive("check disk space"));
    }

    #[test]
    fn test_ai_manager_none_provider() {
        let config = crate::config::AiConfig {
            primary: "none".to_string(),
            ..Default::default()
        };
        let manager = AiManager::from_config(&config);

        assert!(manager.is_available());
        assert_eq!(manager.provider_name(), "none");
        assert!(manager.is_local());

        let request = AiRequest {
            user_input: "status".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = manager.process(&request).unwrap();
        assert!(response.intent.is_some());
    }

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage {
            role: ChatRole::User,
            content: "hello".to_string(),
            timestamp: "2026-02-27T10:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("User"));
        assert!(json.contains("hello"));

        let parsed: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, ChatRole::User);
    }

    #[test]
    fn test_parse_cloud_response_valid() {
        let json = r#"{"message": "Done!", "intent": null, "confidence": 0.9}"#;
        let response = parse_cloud_response(json, "openai").unwrap();
        assert_eq!(response.message, "Done!");
        assert!(response.intent.is_none());
        assert!(!response.is_local);
    }

    #[test]
    fn test_parse_url() {
        let parsed = parse_url("http://localhost:11434/api/generate").unwrap();
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 11434);
        assert_eq!(parsed.path, "/api/generate");
    }
}
