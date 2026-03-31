use super::{AiRequest, ChatRole};

/// Build the unified prompt for CI (Collective Intelligence) orchestration.
/// Supports Bilingual (EN/KR) prompts and high-fidelity mission templates.
pub fn build_prompt(request: &AiRequest) -> String {
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

    let lang = request
        .preferred_language
        .as_deref()
        .unwrap_or("english")
        .to_lowercase();

    // Define language-specific rules and few-shot examples
    let (lang_rules, mission_example) = if lang == "korean" || lang == "ko" {
        (
            r#"- Use PROFESSIONAL MODERN KOREAN (표준어). NO dialects.
- ALL 'message', 'title', and 'description' MUST be in KOREAN HANGUL. 
- Use RAW UTF-8 Korean. NO Unicode escapes."#,
            r#"{
  "message": "사용자 요구사항을 분석한 마케팅 자동화 기획안입니다.",
  "intent": {
    "capability": "create_mission",
    "mission": {
      "id": "tel-campaign-001",
      "title": "텔레그램 바이럴 마케팅 오케스트레이션",
      "description": "사용자 유입 데이터를 실시간 분석하여 최적화된 마케팅 메시지를 자동 전송하는 시스템을 구축합니다.",
      "tasks": [
        { "id": "t1", "desc": "사용자 활동 데이터베이스 분석", "capability": "status_query", "command": "db_query" },
        { "id": "t2", "desc": "바이럴 메시지 자동 생성 및 발송", "capability": "shell_exec", "command": "viral_exec" }
      ]
    }
  }
}"#,
        )
    } else {
        (
            r#"- Use PROFESSIONAL MODERN ENGLISH.
- ALL 'message', 'title', and 'description' MUST be in English.
- Be concise and business-oriented."#,
            r#"{
  "message": "Here is the proposed business automation mission plan.",
  "intent": {
    "capability": "create_mission",
    "mission": {
      "id": "global-mission-001",
      "title": "Global Fleet Orchestration",
      "description": "Established high-precision monitoring and automation pulse across all connected edges.",
      "tasks": [
        { "id": "t1", "desc": "Check edge health status", "capability": "status_query", "command": "health_check" },
        { "id": "t2", "desc": "Synchronize global policy", "capability": "shell_exec", "command": "policy_sync" }
      ]
    }
  }
}"#,
        )
    };

    let persona = format!(
        r#"You are the EdgeClaw CI Orchestrator (EC-CIO), a high-precision business automation expert.
Your goal is to analyze user requests and propose a structured 'Mission' plan.

THOUGHT PROCESS:
1. Analyze the core business intent.
2. Formulate a mission title and description (strictly in the selected language).
3. Break down the goal into Atomic Task Units.

LANGUAGE RULES:
{lang_rules}

Respond ONLY in this JSON format:
{mission_example}"#
    );

    format!(
        r#"{persona}

Context: [{caps}]
User Role: {role}
{system_ctx}

{history}

User: {input}
"#,
        persona = persona,
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
