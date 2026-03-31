use super::{AiProvider, AiRequest, AiResponse, ParsedIntent};
use crate::error::AgentError;

/// No AI — just parses simple commands directly via a built-in rule engine.
/// Essential for low-latency system control and reliable deterministic tasks.
pub struct NoneProvider;

impl Default for NoneProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NoneProvider {
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
        _arg2: &str,
        _raw: &str,
    ) -> Option<ParsedIntent> {
        match cmd {
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".into(),
                command: "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"".into(),
                ..Default::default()
            }),
            "cpu" | "cpu사용량" => Some(ParsedIntent {
                capability: "system_info".into(),
                command: "wmic cpu get loadpercentage,name /format:list".into(),
                ..Default::default()
            }),
            "memory" | "메모리" | "ram" => Some(ParsedIntent {
                capability: "system_info".into(),
                command: "powershell -Command \"Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory\"".into(),
                ..Default::default()
            }),
            "disk" | "디스크" => Some(ParsedIntent {
                capability: "system_info".into(),
                command: "powershell -Command \"Get-PSDrive -PSProvider FileSystem\"".into(),
                ..Default::default()
            }),
            "ps" | "process" | "프로세스" => Some(ParsedIntent {
                capability: "process_manage".into(),
                command: "powershell -Command \"Get-Process | Select-Object Name,Id,CPU | Format-Table\"".into(),
                ..Default::default()
            }),
            "ls" | "dir" | "파일" => Some(ParsedIntent {
                capability: "file_read".into(),
                command: format!("dir /B {}", if arg1.is_empty() { "." } else { arg1 }),
                ..Default::default()
            }),
            "restart" | "재시작" if !arg1.is_empty() => Some(ParsedIntent {
                capability: "shell_exec".into(),
                command: format!("powershell -Command \"Restart-Service -Name '{}' -Force\"", arg1),
                needs_confirmation: true,
                ..Default::default()
            }),
            _ => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn parse_linux_command(cmd: &str, arg1: &str, _arg2: &str, _raw: &str) -> Option<ParsedIntent> {
        match cmd {
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".into(),
                command: "uname -a && uptime".into(),
                ..Default::default()
            }),
            "cpu" => Some(ParsedIntent {
                capability: "system_info".into(),
                command: "top -bn1 | grep Cpu".into(),
                ..Default::default()
            }),
            "ls" | "list" | "파일" => Some(ParsedIntent {
                capability: "file_read".into(),
                command: format!("ls -lh {}", if arg1.is_empty() { "." } else { arg1 }),
                ..Default::default()
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
        true
    }
    fn is_local(&self) -> bool {
        true
    }
    fn set_model(&mut self, _model: &str) -> Result<(), AgentError> {
        Ok(())
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        match Self::parse_simple_command(&request.user_input) {
            Some(intent) => Ok(AiResponse {
                message: format!("Executing local command: {}", intent.command),
                intent: Some(intent),
                confidence: 1.0,
                provider: "none".into(),
                is_local: true,
                sub_responses: Vec::new(),
            }),
            None => Ok(AiResponse {
                message: format!(
                    "Unknown command: '{}'. Enter 'help' for options.",
                    request.user_input
                ),
                intent: None,
                confidence: 0.0,
                provider: "none".into(),
                is_local: true,
                sub_responses: Vec::new(),
            }),
        }
    }
}
