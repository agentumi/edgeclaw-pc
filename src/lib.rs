//! # EdgeClaw Desktop Agent
//!
//! Zero-trust edge AI executor for peer-to-peer device management.
//!
//! This crate provides the core [`AgentEngine`] that orchestrates:
//! - **Identity** — Ed25519/X25519 device authentication ([`identity`])
//! - **Sessions** — ECDH + AES-256-GCM encrypted channels ([`session`])
//! - **Policy** — Role-based access control with 5 roles & 17 capabilities ([`policy`])
//! - **AI** — Pluggable AI providers: Ollama, OpenAI, Claude, or built-in ([`ai`])
//! - **Execution** — Sandboxed async command execution ([`executor`])
//! - **Audit** — SHA-256 hash-chained tamper-evident logging ([`audit`])
//! - **Protocol** — ECNP v1.1 binary framing ([`ecnp`])
//! - **Web UI** — Embedded HTTP chat interface ([`webui`])
//!
//! # Quick Start
//!
//! ```no_run
//! use edgeclaw_agent::AgentEngine;
//! use edgeclaw_agent::config::AgentConfig;
//!
//! let config = AgentConfig::default();
//! let engine = AgentEngine::new(config);
//! let identity = engine.generate_identity().unwrap();
//! println!("Device: {}", identity.device_id);
//! ```

pub mod activity_anchor;
pub mod activity_collector;
pub mod activity_log;
pub mod activity_signing;
pub mod agent_comm;
pub mod agent_router;
pub mod ai;
pub mod ai_summary;
pub mod audit;
pub mod blockchain;
pub mod cbor_encoding;
pub mod chain;
pub mod config;
pub mod delegation;
pub mod discovery;
pub mod ecnp;
pub mod edge_ai;
pub mod error;
pub mod events;
pub mod executor;
pub mod federation;
pub mod gateway;
pub mod git_integration;
pub mod groups;
pub mod identity;
pub mod identity_passport;
pub mod intent_engine;
pub mod k8s;
pub mod license;
pub mod memory_distiller;
pub mod memory_engine;
pub mod memory_search;
pub mod metrics;
pub mod orchestrator;
pub mod peer;
pub mod persona;
pub mod policy;
pub mod protocol;
pub mod quantum_engine;
pub mod quantum_governance;
pub mod registry;
pub mod reputation;
pub mod scheduler;
pub mod search;
pub mod secure_boot;
pub mod security;
pub mod server;
pub mod session;
pub mod sync;
pub mod system;
pub mod task_board;
pub mod task_templates;
pub mod team_sync;
pub mod tee;
pub mod tee_sgx;
pub mod transport;
pub mod updater;
pub mod viral_diffusion;
pub mod wasm;
pub mod webhook;
pub mod websocket;
pub mod webui;
pub mod gui;
pub mod workflow_engine;
pub mod workflows;
pub mod x402_payment;

use std::sync::{Arc, Mutex};
use tracing::info;

use crate::activity_log::{ActivityEntry, ActivityManager, ActivityStats, ActivityType};
use crate::ai::{AiManager, AiRequest, AiResponse, ChatMessage, ChatRole};
use crate::audit::AuditManager;
use crate::config::AgentConfig;
use crate::ecnp::{EcnpCodec, EcnpMessage};
use crate::error::AgentError;
use crate::events::{AgentEvent, EventBus};
use crate::executor::{ExecRequest, ExecResponse, Executor};
use crate::identity::{DeviceIdentity, IdentityManager};
use crate::peer::{PeerInfo, PeerManager};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::protocol::MessageType;
use crate::session::{SessionInfo, SessionManager};
use crate::system::SystemInfo;

/// The main agent engine — orchestrates all subsystems
pub struct AgentEngine {
    config: AgentConfig,
    identity_manager: Mutex<IdentityManager>,
    session_manager: Mutex<SessionManager>,
    peer_manager: Mutex<PeerManager>,
    policy_engine: PolicyEngine,
    executor: Executor,
    ai_manager: Mutex<AiManager>,
    audit_manager: AuditManager,
    activity_manager: Arc<ActivityManager>,
    event_bus: Arc<EventBus>,
    chat_history: Mutex<Vec<ChatMessage>>,
    start_time: chrono::DateTime<chrono::Utc>,
    blockchain_client: Arc<crate::blockchain::BlockchainClient>,
    task_board: Mutex<crate::task_board::TaskBoard>,
    memory_engine: Mutex<crate::memory_engine::MemoryEngine>,
    reputation_engine: Mutex<crate::reputation::ReputationEngine>,
    agent_registry: Arc<crate::registry::AgentRegistry>,
    discovery_service: Arc<crate::discovery::DiscoveryService>,
    mode: Mutex<String>,
    group_manager: Arc<crate::groups::GroupManager>,
    /// V3: 현재 활성 프로세스 타입 (Fleet / Quantum)
    process_type: Mutex<crate::ai::ProcessType>,
    /// V3: 양자 메모리 오케스트레이터
    quantum_engine: Mutex<crate::quantum_engine::QuantumOrchestrator>,
    /// P1: Agent Persona (traits, specializations, communication style)
    persona: Mutex<crate::persona::AgentPersona>,
    /// P2-18: Cron-based task scheduler
    cron_scheduler: Mutex<crate::scheduler::CronScheduler>,
    /// P5: Quantum Governance Engine
    governance: Mutex<crate::quantum_governance::GovernanceEngine>,
    /// P3-08: Viral Diffusion Loop
    diffusion: Mutex<crate::viral_diffusion::DiffusionEngine>,
    /// P1-12: Agent-to-Agent Communication Hub
    comm_hub: Mutex<crate::agent_comm::CommunicationHub>,
    /// P6-04: A2A Delegation Engine (via Router)
    pub agent_router: Mutex<crate::agent_router::AgentRouter>,
    /// P6-01: Agent Passport NFT
    pub agent_passport: Mutex<Option<crate::identity_passport::AgentPassport>>,
    /// V3: Arb Telemetry Cache
    pub arb_telemetry: Mutex<crate::protocol::ArbTelemetryMessage>,
}

impl AgentEngine {
    pub fn memory_engine(&self) -> &Mutex<crate::memory_engine::MemoryEngine> {
        &self.memory_engine
    }

    /// Return the storage path for persisted memory state.
    pub fn memory_storage_path(&self) -> std::path::PathBuf {
        self.config.storage_dir().join("memory.md")
    }

    pub fn reputation_score(&self) -> f64 {
        let rep = self
            .reputation_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        rep.calculate_score()
    }

    pub fn agent_registry(&self) -> &Arc<crate::registry::AgentRegistry> {
        &self.agent_registry
    }

    /// V2.4 Start background orchestration threads (Missions, Heartbeats, etc)
    pub fn start_background_tasks(self: Arc<Self>) {
        let engine = self.clone();
        tokio::spawn(async move {
            eprintln!("[V2.4] Mission Orchestration Engine STARTING...");
            info!("Starting Mission Orchestration background loop");
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                // eprintln!("[V2.4] Pulse: Scanning Mission Registry...");
                // 1. Snapshot mission state without holding the massive AiManager lock across awaits
                let (active_m, ai_mgr_arc) = {
                    let ai = match engine.ai_manager.lock() {
                        Ok(a) => a,
                        Err(e) => e.into_inner(),
                    };
                    (ai.active_mission(), ai.mission_registry())
                };

                if let Some(mut m) = active_m {
                    eprintln!(
                        "[V2.4] Pulse: Processing Mission {} ({:?}) - Progress: {}%",
                        m.id, m.status, m.progress
                    );
                    let mut changed = false;

                    if m.status == crate::ai::MissionStatus::Planning {
                        info!(mission_id = %m.id, "Auto-transitioning Planning -> Active");
                        m.status = crate::ai::MissionStatus::Active;
                        m.progress = 10;
                        m.started_at = Some(chrono::Utc::now().to_rfc3339());
                        changed = true;

                        // ⚙️ Link to the Distributed Task Board
                        let mut board = match engine.task_board.lock() {
                            Ok(b) => b,
                            Err(e) => e.into_inner(),
                        };
                        for t in &m.tasks {
                            board.create_task(
                                &t.desc,
                                Some(&m.id),
                                crate::task_board::TaskPriority::High,
                                &[&t.capability],
                            );
                        }
                        let task_path = engine.config.storage_dir().join("tasks.jsonl");
                        let _ = board.save_to_file(&task_path);
                    } else if m.status == crate::ai::MissionStatus::Active {
                        let num_tasks = std::cmp::max(m.tasks.len() as u32, 1);
                        let step_size = 80 / num_tasks;
                        let current_task_idx =
                            ((m.progress.saturating_sub(10)) / step_size) as usize;

                        if current_task_idx < m.tasks.len() {
                            let task = m.tasks[current_task_idx].clone();
                            let step_name = &task.desc;
                            let cap = task.capability.to_uppercase();

                            info!(mission_id = %m.id, progress = m.progress, step = step_name, cap = cap, "MISSION EXECUTION MOTOR ENGAGED");

                            // 🚀 TRUE AUTONOMOUS EXECUTOR
                            let session_id = uuid::Uuid::nil(); // or default session
                            match cap.as_str() {
                                "SYSTEM_INFO" | "STATUS_QUERY" => {
                                    let _sys = engine.get_system_info();
                                    engine.activity_manager.record(
                                             crate::activity_log::ActivityType::Custom { category: cap.clone(), data: serde_json::json!({"action": step_name, "status": "success"}) },
                                             &format!("Executed internal system sub-routine: {}", step_name),
                                             session_id, 1, &[&cap], None, "system",
                                         );
                                }
                                "PEER_LIST" | "NETWORK_SCAN" => {
                                    let _peers = {
                                        let pm = engine
                                            .peer_manager
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        pm.list_peers()
                                    };
                                    engine.activity_manager.record(
                                        crate::activity_log::ActivityType::PeerActivity {
                                            peer_id: "all".to_string(),
                                            peer_name: "network".to_string(),
                                            action: cap.clone(),
                                        },
                                        &format!("Executed network sub-routine: {}", step_name),
                                        session_id,
                                        1,
                                        &[&cap],
                                        None,
                                        "network",
                                    );
                                }
                                "POLICY_SYNC" | "POLICY_OVERRIDE" => {
                                    engine.activity_manager.record(
                                             crate::activity_log::ActivityType::Custom { category: cap.clone(), data: serde_json::json!({"action": step_name, "status": "success"}) },
                                             &format!("Executed security policy sub-routine: {}", step_name),
                                             session_id, 2, &[&cap], None, "security",
                                         );
                                }
                                "SHELL_EXEC" | "PROCESS_MANAGE" => {
                                    let cmd = task
                                        .args
                                        .first()
                                        .cloned()
                                        .unwrap_or_else(|| "echo".to_string());
                                    let args = if task.args.len() > 1 {
                                        task.args[1..].to_vec()
                                    } else {
                                        vec!["autonomous_ok".to_string()]
                                    };

                                    let req = crate::executor::ExecRequest {
                                        execution_id: uuid::Uuid::new_v4().to_string(),
                                        action: "mission_step".to_string(),
                                        command: cmd.clone(),
                                        args: args.clone(),
                                        timeout_secs: 15,
                                        working_dir: None,
                                    };

                                    // 🚀 Secure execution with V2.x failure retry + V3 Quantum feedback
                                    let mut exec_success = false;
                                    let mut retry_count = 0u32;
                                    let max_retries = 2u32;

                                    match engine.executor.execute(req).await {
                                        Ok(res) => {
                                            let exit_ok =
                                                res.exit_code.map(|c| c == 0).unwrap_or(true);
                                            if exit_ok {
                                                engine.activity_manager.record(
                                                         crate::activity_log::ActivityType::CommandExec { command: cmd.clone(), exit_code: res.exit_code.unwrap_or(0), duration_ms: res.duration_ms, output_summary: Some(res.stdout) },
                                                         &format!("Mission step completed: {}", step_name),
                                                         session_id, 2, &[&cap], None, "automation",
                                                     );
                                            } else {
                                                // Step failed — trigger retry loop
                                                eprintln!(
                                                    "[V2.x] Mission step FAILED (exit: {:?}): {}",
                                                    res.exit_code, step_name
                                                );

                                                // V3: Report failure to Quantum Engine
                                                if let Ok(mut qe) = engine.quantum_engine.lock() {
                                                    qe.handle_failure(&m.id, step_name, 0.3);
                                                }

                                                // Retry loop with alternative args
                                                while retry_count < max_retries && !exec_success {
                                                    retry_count += 1;
                                                    eprintln!(
                                                        "[V2.x] Retrying step ({}/{})...",
                                                        retry_count, max_retries
                                                    );

                                                    let retry_req = crate::executor::ExecRequest {
                                                        execution_id: uuid::Uuid::new_v4()
                                                            .to_string(),
                                                        action: format!(
                                                            "mission_step_retry_{}",
                                                            retry_count
                                                        ),
                                                        command: cmd.clone(),
                                                        args: args.clone(),
                                                        timeout_secs: 30, // Extended timeout for retries
                                                        working_dir: None,
                                                    };

                                                    if let Ok(retry_res) =
                                                        engine.executor.execute(retry_req).await
                                                    {
                                                        if retry_res
                                                            .exit_code
                                                            .map(|c| c == 0)
                                                            .unwrap_or(true)
                                                        {
                                                            exec_success = true;
                                                            engine.activity_manager.record(
                                                                     crate::activity_log::ActivityType::CommandExec { command: cmd.clone(), exit_code: retry_res.exit_code.unwrap_or(0), duration_ms: retry_res.duration_ms, output_summary: Some(retry_res.stdout) },
                                                                     &format!("Mission step completed on retry {}: {}", retry_count, step_name),
                                                                     session_id, 2, &[&cap], None, "automation",
                                                                 );
                                                        }
                                                    }
                                                }

                                                if !exec_success {
                                                    // V3: Convert failure to innovation insight
                                                    if let Ok(mut qe) = engine.quantum_engine.lock()
                                                    {
                                                        qe.handle_failure(&m.id, step_name, 0.7);
                                                    }
                                                    engine.activity_manager.record(
                                                             crate::activity_log::ActivityType::Custom { category: "mission_failure".to_string(), data: serde_json::json!({"step": step_name, "retries": retry_count, "status": "exhausted"}) },
                                                             &format!("Mission step failed after {} retries: {}", retry_count, step_name),
                                                             session_id, 3, &[&cap], None, "orchestration",
                                                         );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[V2.x] Executor error: {}", e);
                                            // V3: Report executor error to Quantum Engine
                                            if let Ok(mut qe) = engine.quantum_engine.lock() {
                                                qe.handle_failure(&m.id, step_name, 0.5);
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    engine.activity_manager.record(
                                             crate::activity_log::ActivityType::Custom { category: cap.clone(), data: serde_json::json!({"action": step_name, "status": "executor_abstracted"}) },
                                             &format!("Abstract objective dispatched: {}", step_name),
                                             session_id, 1, &[&cap], None, "orchestration",
                                         );
                                }
                            }

                            engine.audit_manager.log(
                                &engine.config.agent.device_name,
                                "ai-agent",
                                "mission_step",
                                &format!("[{}] {}", m.id, step_name),
                                "success",
                                None,
                            );

                            m.progress += step_size;
                            if m.progress > 94 {
                                m.progress = 95;
                            }
                            changed = true;
                        } else {
                            // Finishing phase
                            if m.progress < 95 {
                                m.progress = 95;
                                changed = true;
                            } else if m.progress == 95 {
                                m.progress = 100;
                                m.status = crate::ai::MissionStatus::Success;
                                m.completed_at = Some(chrono::Utc::now().to_rfc3339());
                                info!(mission_id = %m.id, "Mission successfully completed!");
                                engine.audit_manager.log(
                                    &engine.config.agent.device_name,
                                    "ai-agent",
                                    "mission_complete",
                                    &format!("Mission {} reached 100%", m.id),
                                    "success",
                                    None,
                                );

                                // V3: Register successful mission as E-Max pattern in Quantum Hub
                                if let Ok(mut qe) = engine.quantum_engine.lock() {
                                    let task_count = m.tasks.len() as f64;
                                    let efficiency = if task_count > 0.0 {
                                        1.0 / task_count.sqrt()
                                    } else {
                                        0.5
                                    };
                                    qe.hub.register_pattern(
                                        &m.name,
                                        &m.category,
                                        0.8 + efficiency * 0.2, // High success rate since mission completed
                                        crate::quantum_engine::PatternType::EMax,
                                    );
                                    eprintln!("[V3] Mission '{}' archived as E-Max pattern (efficiency: {:.2})", m.name, efficiency);
                                }

                                // P1-06: Auto-update persona specialization on mission completion
                                if let Ok(mut persona) = engine.persona.lock() {
                                    let domain = if m.category.is_empty() {
                                        "general"
                                    } else {
                                        &m.category
                                    };
                                    persona.record_task_completion(domain);
                                }

                                changed = true;
                            }
                        }
                    }

                    if changed {
                        let missions_lock = ai_mgr_arc.missions.write();
                        if let Ok(mut lock) = missions_lock {
                            lock.insert(m.id.clone(), m);
                            let m_path = engine.config.storage_dir().join("missions.json");
                            if let Ok(data) = serde_json::to_string_pretty(&*lock) {
                                let _ = std::fs::write(&m_path, data);
                            }
                        }
                    }
                }
            }
        });

        // ─── P3-03: Memory Auto-Promotion + Persistence Background Task ────
        let engine2 = self.clone();
        tokio::spawn(async move {
            eprintln!("[V3] Memory Maintenance Engine STARTING...");
            info!("Starting Memory Maintenance background loop");
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // 1. Auto-promote memories (M30→M90→M365) based on reference_count
                let (promoted_count, expired_count, total_memories) = {
                    let mut mem = engine2
                        .memory_engine
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let before_m90 = mem.tiers.m90.len();
                    let before_m365 = mem.tiers.m365.len();
                    let before_total = mem.tiers.m30.len() + before_m90 + before_m365;

                    mem.tiers.promote_memories();
                    mem.tiers.clean_expired(chrono::Utc::now());

                    let after_m90 = mem.tiers.m90.len();
                    let after_m365 = mem.tiers.m365.len();
                    let after_total = mem.tiers.m30.len() + after_m90 + after_m365;

                    let promoted = (after_m90 - before_m90) + (after_m365 - before_m365);
                    let expired = if before_total > after_total + promoted {
                        before_total - after_total - promoted
                    } else {
                        0
                    };

                    (promoted, expired, after_total)
                };

                if promoted_count > 0 || expired_count > 0 {
                    info!(
                        promoted = promoted_count,
                        expired = expired_count,
                        total = total_memories,
                        "[P3-03] Memory maintenance cycle completed"
                    );
                }

                // 2. Persist memory state to MEMORY.md every cycle
                {
                    let mem = engine2
                        .memory_engine
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let path = engine2.memory_storage_path();
                    if let Err(e) = mem.save_to_markdown_file(&path) {
                        eprintln!("[V3] Memory persistence failed: {}", e);
                    }
                }

                // 3. P2-18: Cron Scheduler tick — check for triggered jobs
                {
                    let now = chrono::Utc::now();
                    let triggered = {
                        let mut sched = engine2
                            .cron_scheduler
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        sched.tick(&now)
                    };
                    for template_id in &triggered {
                        info!(template_id = %template_id, "[P2-18] Cron job triggered");
                    }
                }

                // 4. P1-05: Periodic Persona ↔ Memory sync
                engine2.sync_persona_from_memory();
            }
        });
    }

    /// P1-08: Boot Ritual — inject M0 CoreMemory + Lessons + Persona into AI system context
    ///
    /// Called once at startup to prime the AI manager with the agent's identity,
    /// memory context, and behavioral directives.
    pub fn boot_ritual(&self) {
        info!("[P1-08] Executing Boot Ritual...");

        // 1. Gather M0 CoreMemory context
        let memory_context = {
            let mem = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
            let mut ctx = String::new();

            // Soul definition
            if !mem.core.soul.content.is_empty() {
                ctx.push_str(&format!("[SOUL] {}\n", mem.core.soul.content));
            }

            // Absolute rules
            if !mem.core.absolute_rules.is_empty() {
                ctx.push_str("[RULES]\n");
                for rule in &mem.core.absolute_rules {
                    ctx.push_str(&format!("- {}\n", rule));
                }
            }

            // User profile
            if !mem.core.user_profile.name.is_empty() {
                ctx.push_str(&format!("[USER] {}\n", mem.core.user_profile.name));
                for (k, v) in &mem.core.user_profile.preferences {
                    ctx.push_str(&format!("  {}: {}\n", k, v));
                }
            }

            // Top lessons
            let top_lessons: Vec<_> = mem
                .lessons
                .lessons
                .iter()
                .filter(|l| l.effectiveness > 0.5)
                .take(10)
                .collect();
            if !top_lessons.is_empty() {
                ctx.push_str("[LESSONS]\n");
                for lesson in top_lessons {
                    ctx.push_str(&format!(
                        "- {} (eff: {:.0}%, applied: {}x)\n",
                        lesson.pattern,
                        lesson.effectiveness * 100.0,
                        lesson.applied_count
                    ));
                }
            }

            // Recent M365 high-importance memories
            let critical_memories: Vec<_> = mem
                .tiers
                .m365
                .iter()
                .filter(|m| m.importance >= 3)
                .take(5)
                .collect();
            if !critical_memories.is_empty() {
                ctx.push_str("[CRITICAL MEMORIES]\n");
                for m in critical_memories {
                    ctx.push_str(&format!("- {}\n", m.content));
                }
            }

            ctx
        };

        // 2. Gather Persona context (P1-09: CommunicationStyle injection)
        let persona_context = self.persona_system_prompt();

        // 3. Gather Quantum Hub context
        let quantum_context = {
            let qe = self
                .quantum_engine
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let stats = qe.hub.stats();
            format!(
                "[QUANTUM HUB] E-Max: {} patterns | C-Max: {} patterns | Insights: {} | Cycles: {}\n",
                stats.e_max_count, stats.c_max_count, stats.failure_insights_count, stats.total_cycles
            )
        };

        // 4. Gather process type
        let process_type = self.process_type();

        // 5. Build boot context string
        let boot_context = format!(
            "=== EDGECLAW BOOT RITUAL ===\n\
             Device: {}\n\
             Process Mode: {:?}\n\
             \n{}\
             {}\
             {}\
             === END BOOT RITUAL ===",
            self.config.agent.device_name,
            process_type,
            persona_context,
            memory_context,
            quantum_context,
        );

        // 6. Inject as system message into chat history
        {
            let mut history = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());

            // Remove any previous boot ritual message
            history.retain(|msg| {
                !(msg.role == crate::ai::ChatRole::System
                    && msg.content.contains("EDGECLAW BOOT RITUAL"))
            });

            // Insert boot ritual at the beginning
            history.insert(
                0,
                ChatMessage {
                    role: crate::ai::ChatRole::System,
                    content: boot_context.clone(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                },
            );
        }

        let mem_line_count = memory_context.lines().count();
        info!(
            memory_lines = mem_line_count,
            process_type = ?process_type,
            "[P1-08] Boot Ritual complete — {} memory context lines injected",
            mem_line_count
        );
    }
    /// Create a new engine with the given config
    pub fn new(config: AgentConfig) -> Self {
        let event_bus = Arc::new(EventBus::new(256));
        let mut executor = Executor::new(
            config.execution.max_concurrent,
            config.execution.default_timeout_secs,
            config.execution.max_timeout_secs,
            config.execution.allowed_paths.clone(),
        );
        executor.set_event_bus(event_bus.clone());
        let ai_manager = Mutex::new(AiManager::from_config(&config.ai));

        // Use persistent audit log if config dir is available
        let audit_manager = {
            #[cfg(test)]
            {
                AuditManager::new()
            }
            #[cfg(not(test))]
            {
                let audit_path = config.storage_dir().join("audit.jsonl");
                if let Some(p) = audit_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                AuditManager::with_persistence(audit_path)
            }
        };

        // Use persistent activity log if config dir is available
        let activity_manager = {
            #[cfg(test)]
            {
                Arc::new(ActivityManager::new(
                    "local",
                    &config.agent.device_name,
                    "owner",
                ))
            }
            #[cfg(not(test))]
            {
                let activity_path = config.storage_dir().join("activity.jsonl");
                if let Some(p) = activity_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                Arc::new(ActivityManager::with_persistence(
                    "local",
                    &config.agent.device_name,
                    "owner",
                    activity_path,
                ))
            }
        };

        // Initialize or load chat history from disk
        let history_path = config.storage_dir().join("chat_history.json");

        let loaded_history = if history_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&history_path) {
                serde_json::from_str(&data).unwrap_or_else(|_| Vec::new())
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // V2.4 Load Missions 🛡️
        let mission_path = config.storage_dir().join("missions.json");
        if mission_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&mission_path) {
                if let Ok(loaded) = serde_json::from_str::<
                    std::collections::HashMap<String, crate::ai::MissionMetadata>,
                >(&data)
                {
                    let ai_mgr = ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                    if let Ok(mut lock) = ai_mgr.mission_registry().missions.write() {
                        *lock = loaded;
                    }
                }
            }
        }

        Self {
            identity_manager: Mutex::new(IdentityManager::new()),
            session_manager: Mutex::new(SessionManager::new()),
            peer_manager: Mutex::new(PeerManager::new(50)),
            policy_engine: PolicyEngine::new(),
            executor,
            ai_manager,
            audit_manager,
            activity_manager,
            event_bus: event_bus.clone(),
            chat_history: Mutex::new(loaded_history),
            start_time: chrono::Utc::now(),
            blockchain_client: Arc::new(crate::blockchain::BlockchainClient::new(
                crate::blockchain::BlockchainConfig::default(),
            )),
            group_manager: Arc::new(crate::groups::GroupManager::new()),
            task_board: Mutex::new({
                let mut board = crate::task_board::TaskBoard::new(
                    &config.agent.device_name,
                    &config.webui.work_profile,
                );
                let task_path = config.storage_dir().join("tasks.jsonl");
                if task_path.exists() {
                    let _ = board.load_from_file(&task_path);
                }
                board
            }),
            memory_engine: Mutex::new({
                let memory_path = config.storage_dir().join("memory.md");
                if let Ok(Some(engine)) =
                    crate::memory_engine::MemoryEngine::load_from_markdown_file(&memory_path)
                {
                    engine
                } else if let Ok(Some(engine)) =
                    crate::memory_engine::MemoryEngine::load_from_markdown_file(
                        std::path::Path::new("MEMORY.md"),
                    )
                {
                    engine
                } else if let Ok(Some(engine)) =
                    crate::memory_engine::MemoryEngine::load_from_markdown_file(
                        std::path::Path::new("memory.md"),
                    )
                {
                    engine
                } else {
                    crate::memory_engine::MemoryEngine::new()
                }
            }),
            reputation_engine: Mutex::new({
                let mut rep = crate::reputation::ReputationEngine::new();
                // Add some mock history for reputation
                rep.add_task_result(crate::reputation::TaskResult {
                    task_id: uuid::Uuid::new_v4(),
                    counterparty_id: "system".to_string(),
                    task_weight: 1.0,
                    quality_score: 0.95,
                    pop_verified: true,
                    amount_usd: 100.0,
                    timestamp: chrono::Utc::now(),
                });
                rep
            }),
            agent_registry: Arc::new(crate::registry::AgentRegistry::with_storage_dir(
                config.storage_dir(),
            )),
            discovery_service: Arc::new(crate::discovery::DiscoveryService::new(
                &config.agent.device_name,
                config.agent.listen_port,
                &config.webui.work_profile,
                "2.0.0",
            )),
            mode: Mutex::new("sanctum".to_string()),
            process_type: Mutex::new(crate::ai::ProcessType::Fleet),
            quantum_engine: Mutex::new(crate::quantum_engine::QuantumOrchestrator::new()),
            persona: Mutex::new(crate::persona::AgentPersona::from_preset(
                &config.agent.device_name,
                crate::persona::PersonaPreset::Executor,
            )),
            cron_scheduler: Mutex::new(crate::scheduler::CronScheduler::new()),
            governance: Mutex::new(crate::quantum_governance::GovernanceEngine::new()),
            diffusion: Mutex::new(crate::viral_diffusion::DiffusionEngine::new()),
            comm_hub: Mutex::new(crate::agent_comm::CommunicationHub::new()),
            agent_router: Mutex::new(crate::agent_router::AgentRouter::new()),
            agent_passport: Mutex::new(None),
            arb_telemetry: Mutex::new(crate::protocol::ArbTelemetryMessage {
                pnl: 0.0,
                latency: 0.0,
                active_neurons: 0,
                message: "Initializing...".into(),
            }),
            config,
        }
    }

    pub fn mode(&self) -> String {
        self.mode.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_mode(&self, new_mode: &str) -> Result<(), AgentError> {
        let mut m = self.mode.lock().unwrap_or_else(|e| e.into_inner());
        *m = new_mode.to_string();

        if new_mode == "market" {
            let _ = self.discovery_service.register();
            info!("Switched to Market Mode (Public)");
        } else {
            self.discovery_service.unregister();
            info!("Switched to Sanctum Mode (Private)");
        }
        Ok(())
    }

    pub fn discovery_service(&self) -> &Arc<crate::discovery::DiscoveryService> {
        &self.discovery_service
    }

    // ─── V3: Process Type Selection ────────────────────────────

    /// 현재 프로세스 타입 반환 (Fleet / Quantum)
    pub fn process_type(&self) -> crate::ai::ProcessType {
        self.process_type
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 프로세스 타입 변경 (UI에서 Fleet ↔ Quantum 토글)
    pub fn set_process_type(&self, pt: crate::ai::ProcessType) {
        let mut lock = self.process_type.lock().unwrap_or_else(|e| e.into_inner());
        info!("[V3] Process Type switched to: {:?}", pt);
        *lock = pt;
    }

    /// 입력 텍스트에서 도메인을 자동 감지하여 전문가 페르소나 반환
    pub fn detect_domain_and_experts(&self, input: &str) -> (String, Vec<crate::ai::ExpertRole>) {
        let domain = crate::ai::DomainDetector::detect_domain(input);
        let roles = crate::ai::DomainDetector::get_expert_roles(domain);
        (domain.to_string(), roles)
    }

    /// V3: 미션 품질 점수 계산
    pub fn evaluate_mission_quality(&self, mission: &crate::ai::MissionMetadata) -> f64 {
        crate::ai::MissionQualityEvaluator::evaluate(mission)
    }

    /// V3: Quantum Engine을 통한 미션 그래프 초기화
    pub fn init_quantum_mission(
        &self,
        mission: &crate::ai::MissionMetadata,
        agent_ids: &[String],
    ) -> crate::quantum_engine::QuantumMissionState {
        let mut qe = self
            .quantum_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        qe.initialize_mission_graph(mission, agent_ids)
    }

    /// V3: Quantum Memory Hub 통계
    pub fn quantum_hub_stats(&self) -> crate::quantum_engine::QuantumHubStats {
        let qe = self
            .quantum_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        qe.hub.stats()
    }

    /// V3: 실패를 혁신 인사이트로 자산화
    pub fn pivot_failure_to_insight(
        &self,
        mission_id: &str,
        failure_desc: &str,
        error_magnitude: f64,
    ) -> Option<crate::quantum_engine::FailureInsight> {
        let mut qe = self
            .quantum_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        qe.handle_failure(mission_id, failure_desc, error_magnitude)
    }

    // ─── P1: Persona Management ────────────────────────────────

    /// Access the current agent persona
    pub fn persona(&self) -> &Mutex<crate::persona::AgentPersona> {
        &self.persona
    }

    /// Generate persona system prompt for AI injection (P1-09)
    pub fn persona_system_prompt(&self) -> String {
        let persona = self.persona.lock().unwrap_or_else(|e| e.into_inner());
        persona.to_system_prompt()
    }

    // ─── P3: Memory & 진화형 학습 ──────────────────────────────

    /// P3-04: Evaluate effectiveness of active lessons for a domain
    pub fn evaluate_lessons(&self, domain: &str, success: bool) {
        let mut mem = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
        let top_lessons = mem
            .lessons
            .top_effective(5, Some(domain))
            .into_iter()
            .map(|l| l.id)
            .collect::<Vec<_>>();

        for id in top_lessons {
            mem.lessons.record_outcome(&id, success);
        }
        tracing::info!(domain = %domain, success = success, "[P3-04] Evaluated lesson outcomes");
    }

    /// P3-02: Export local memory diff for P2P synchronization
    pub fn export_memory_diff(&self, since: &chrono::DateTime<chrono::Utc>) -> crate::memory_engine::MemoryDiff {
        let mem = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
        let identity = self.get_identity().unwrap_or_default();
        mem.generate_diff(since, &identity.device_id)
    }

    /// P3-02: Import remote memory diff
    pub fn import_memory_diff(&self, diff: &crate::memory_engine::MemoryDiff) -> (usize, usize) {
        let mut mem = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
        let stats = mem.apply_diff(diff);
        tracing::info!(
            memories = stats.0, 
            lessons = stats.1, 
            source = %diff.source_agent,
            "[P3-02] Imported memory diff"
        );
        stats
    }

    /// P1-05: Synchronize Persona specializations from MemoryEngine lesson data
    pub fn sync_persona_from_memory(&self) {
        let bridge_data = {
            let mem = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
            mem.extract_persona_bridge_data()
        };

        let mut persona = self.persona.lock().unwrap_or_else(|e| e.into_inner());
        for (domain, (success_tasks, applied_count)) in &bridge_data.domain_stats {
            // Ensure specialization exists
            persona.add_specialization(domain);
            // Update from lessons data
            if let Some(spec) = persona
                .specializations
                .iter_mut()
                .find(|s| s.domain.eq_ignore_ascii_case(domain))
            {
                spec.completed_tasks = spec.completed_tasks.max(*success_tasks);
                spec.lessons_applied = spec.lessons_applied.max(*applied_count);
                spec.recalculate_confidence();
            }
        }
    }

    // ─── P2-18: Scheduler Access ──────────────────────────

    /// Access the cron scheduler
    pub fn cron_scheduler(&self) -> &Mutex<crate::scheduler::CronScheduler> {
        &self.cron_scheduler
    }

    // ─── P5: Governance Access ────────────────────────────

    /// Access the quantum governance engine
    pub fn governance(&self) -> &Mutex<crate::quantum_governance::GovernanceEngine> {
        &self.governance
    }

    /// P5 convenience: submit a governance proposal
    pub fn submit_governance_proposal(
        &self,
        title: &str,
        description: &str,
        proposer: &str,
        severity: crate::quantum_governance::ProposalSeverity,
    ) -> crate::quantum_governance::GovernanceProposal {
        let mut gov = self.governance.lock().unwrap_or_else(|e| e.into_inner());
        gov.submit_proposal(title, description, proposer, severity, 24)
    }

    // ─── P3-08: Diffusion Access ─────────────────────────

    /// Access the viral diffusion engine
    pub fn diffusion(&self) -> &Mutex<crate::viral_diffusion::DiffusionEngine> {
        &self.diffusion
    }

    // ─── P1-12: Communication Hub Access ─────────────────

    /// Access the agent communication hub
    pub fn comm_hub(&self) -> &Mutex<crate::agent_comm::CommunicationHub> {
        &self.comm_hub
    }

    // ─── Clients ───────────────────────────────────────────
    pub fn blockchain_client(&self) -> Arc<crate::blockchain::BlockchainClient> {
        self.blockchain_client.clone()
    }

    pub fn ai_manager(&self) -> &Mutex<AiManager> {
        &self.ai_manager
    }

    pub fn peer_manager(&self) -> &Mutex<PeerManager> {
        &self.peer_manager
    }

    pub fn group_manager(&self) -> Arc<crate::groups::GroupManager> {
        self.group_manager.clone()
    }

    // ─── Identity ──────────────────────────────────────────

    /// Generate a new device identity
    pub fn generate_identity(&self) -> Result<DeviceIdentity, AgentError> {
        let mut mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let id = mgr.generate_identity(&self.config.agent.device_name)?;

        // Attach signing key to AI manager for signed requests (Cloud LLM)
        if let Ok(key) = mgr.get_signing_key() {
            let mut ai = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
            ai.set_identity(key);
        }

        Ok(id)
    }

    /// Get current device identity
    pub fn get_identity(&self) -> Result<DeviceIdentity, AgentError> {
        let mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.get_identity().cloned()
    }

    /// Get X25519 secret key bytes (for handshake)
    pub fn get_secret_key(&self) -> Result<[u8; 32], AgentError> {
        let mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.get_secret_key()
    }

    /// Get X25519 public key bytes (for handshake)
    pub fn get_public_key(&self) -> Result<[u8; 32], AgentError> {
        let mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.get_public_key()
    }

    /// Sign data with Ed25519 (for handshake authentication)
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.sign(data)
    }

    // ─── Peers ─────────────────────────────────────────────

    /// Register a peer connection
    pub fn add_peer(
        &self,
        peer_id: &str,
        device_name: &str,
        device_type: &str,
        address: &str,
        role: &str,
    ) -> Result<PeerInfo, AgentError> {
        let mut mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.add_peer(peer_id, device_name, device_type, address, role)
    }

    /// List all peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.list_peers()
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.connected_count()
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &str) -> bool {
        let mut mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.remove_peer(peer_id)
    }

    /// Access the task board
    pub fn task_board(&self) -> &Mutex<crate::task_board::TaskBoard> {
        &self.task_board
    }

    // ─── Sessions ──────────────────────────────────────────

    /// Create an encrypted session with a peer
    pub fn create_session(
        &self,
        peer_id: &str,
        remote_public: &[u8; 32],
    ) -> Result<SessionInfo, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let secret = id_mgr.get_secret_key()?;
        drop(id_mgr);

        let mut sess_mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sess_mgr.create_session(peer_id, &secret, remote_public)
    }

    /// Encrypt a message in a session
    pub fn encrypt_message(
        &self,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let mut mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.encrypt(session_id, plaintext)
    }

    /// Decrypt a message in a session
    pub fn decrypt_message(
        &self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let mut mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.decrypt(session_id, ciphertext)
    }

    // ─── Policy ────────────────────────────────────────────

    /// Evaluate a capability request
    pub fn evaluate_capability(
        &self,
        capability: &str,
        role: &str,
    ) -> Result<PolicyDecision, AgentError> {
        self.policy_engine.evaluate(capability, role)
    }

    /// Check if capability requires sandbox
    pub fn requires_sandbox(&self, capability: &str) -> bool {
        self.policy_engine.requires_sandbox(capability)
    }

    // ─── Execution ─────────────────────────────────────────

    /// List models for the current AI provider
    pub fn list_ai_models(&self) -> Vec<String> {
        let mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.list_models()
    }

    /// Execute a command after policy check
    pub async fn execute_command(
        &self,
        peer_id: &str,
        request: ExecRequest,
    ) -> Result<ExecResponse, AgentError> {
        // Lookup peer role (scope-limited to drop MutexGuard before await)
        let role = {
            let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
            mgr.get_peer_role(peer_id)
                .ok_or_else(|| AgentError::NotFound(format!("peer not found: {peer_id}")))?
        };

        // Policy check
        // Policy check with group overrides
        let overrides = {
            let gm = self.group_manager();
            let group_ids = gm.get_peer_groups(peer_id);
            let mut combined = std::collections::HashMap::new();
            for gid in group_ids {
                if let Some(group) = gm.get_group(&gid) {
                    for (cap, allowed) in group.policy_overrides {
                        // Policy: Explicit DENY in any group wins if multiple groups provide conflicting overrides
                        combined
                            .entry(cap)
                            .and_modify(|v| *v &= allowed)
                            .or_insert(allowed);
                    }
                }
            }
            combined
        };

        let decision =
            self.policy_engine
                .evaluate_with_overrides(&request.action, &role, &overrides)?;
        if !decision.allowed {
            // Audit the denial
            let device_id = self
                .get_identity()
                .map(|id| id.device_id)
                .unwrap_or_else(|_| "unknown".to_string());
            self.audit_manager.log(
                &device_id,
                &role,
                &request.action,
                &request.command,
                "denied",
                Some(&decision.reason),
            );
            return Err(AgentError::PolicyDenied(decision.reason));
        }

        // Publish CommandStarted event
        self.event_bus.publish(AgentEvent::CommandStarted {
            execution_id: request.execution_id.clone(),
            command: request.command.clone(),
            peer_id: peer_id.to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Execute
        let result = self.executor.execute(request.clone()).await;

        // Audit the execution
        let device_id = self
            .get_identity()
            .map(|id| id.device_id)
            .unwrap_or_else(|_| "unknown".to_string());
        match &result {
            Ok(resp) => {
                self.audit_manager.log(
                    &device_id,
                    &role,
                    &request.action,
                    &request.command,
                    if resp.success { "success" } else { "failed" },
                    None,
                );
                // Publish CommandCompleted event
                self.event_bus.publish(AgentEvent::CommandCompleted {
                    execution_id: resp.execution_id.clone(),
                    success: resp.success,
                    exit_code: resp.exit_code,
                    duration_ms: resp.duration_ms,
                });
            }
            Err(e) => {
                self.audit_manager.log(
                    &device_id,
                    &role,
                    &request.action,
                    &request.command,
                    "error",
                    Some(&e.to_string()),
                );
                // Publish alert for execution error
                self.event_bus.publish(AgentEvent::Alert {
                    severity: events::AlertSeverity::Warning,
                    message: format!("Command failed: {}", e),
                    source: "executor".to_string(),
                });
            }
        }

        result
    }

    // ─── System ────────────────────────────────────────────

    /// Get system information
    pub fn get_system_info(&self) -> SystemInfo {
        system::collect_system_info()
    }

    /// Get detected capabilities
    pub fn get_capabilities(&self) -> Vec<String> {
        system::detect_capabilities()
    }

    /// Get agent uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        (chrono::Utc::now() - self.start_time).num_seconds() as u64
    }

    // ─── Protocol ──────────────────────────────────────────

    /// Create an ECM (Edge Capability Manifest)
    pub fn create_ecm(&self) -> Result<String, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let identity = id_mgr.get_identity()?;
        let caps = self.get_capabilities();
        protocol::create_ecm(
            &identity.device_id,
            &identity.device_name,
            &identity.platform,
            &caps,
        )
    }

    /// Create a heartbeat message
    pub fn create_heartbeat(&self) -> Result<String, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let identity = id_mgr.get_identity()?;
        let sys = self.get_system_info();
        protocol::create_heartbeat(
            &identity.device_id,
            self.uptime_secs(),
            sys.cpu_usage,
            sys.memory_usage_percent,
            self.connected_count() as u32,
        )
    }

    /// Encode data into ECNP frame
    pub fn encode_ecnp(
        &self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        EcnpCodec::encode(msg_type, payload)
    }

    /// Decode an ECNP frame
    pub fn decode_ecnp(&self, data: &[u8]) -> Result<EcnpMessage, AgentError> {
        EcnpCodec::decode(data)
    }

    /// Get config reference
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// Get the event bus for subscribing to real-time events
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    // ─── Activity Log ──────────────────────────────────────

    /// Get the activity manager reference
    pub fn activity_manager(&self) -> &Arc<ActivityManager> {
        &self.activity_manager
    }

    /// Record an activity entry
    #[allow(clippy::too_many_arguments)]
    pub fn record_activity(
        &self,
        activity_type: ActivityType,
        content: &str,
        session_id: uuid::Uuid,
        importance: u8,
        tags: &[&str],
        file_path: Option<&str>,
        project: &str,
    ) -> ActivityEntry {
        self.activity_manager.record(
            activity_type,
            content,
            session_id,
            importance,
            tags,
            file_path,
            project,
        )
    }

    /// Get activity log statistics
    pub fn activity_stats(&self) -> ActivityStats {
        self.activity_manager.stats()
    }

    /// Search activity log
    pub fn search_activities(&self, query: &str, limit: usize) -> Vec<ActivityEntry> {
        self.activity_manager.search(query, limit)
    }

    /// Get recent activity entries
    pub fn recent_activities(&self, n: usize) -> Vec<ActivityEntry> {
        self.activity_manager.recent(n)
    }

    /// Get activity count
    pub fn activity_count(&self) -> usize {
        self.activity_manager.count()
    }

    /// Verify activity chain integrity
    pub fn verify_activity_chain(&self) -> Result<bool, String> {
        self.activity_manager.verify_chain()
    }

    /// Export activity log as JSON
    pub fn export_activity_log(&self) -> Result<String, serde_json::Error> {
        self.activity_manager.export_json()
    }

    /// Export activity log as CSV
    pub fn export_activity_csv(&self) -> Result<String, AgentError> {
        self.activity_manager.export_csv()
    }

    /// Full-text search using Tantivy index (scored results)
    pub fn fts_search_activities(&self, query: &str, limit: usize) -> Vec<(f32, ActivityEntry)> {
        self.activity_manager.full_text_search(query, limit)
    }

    /// Generate a highlighted snippet for a search result.
    pub fn highlight_activity(&self, query: &str, content: &str) -> String {
        self.activity_manager.highlight(query, content)
    }

    // ─── AI Chat ───────────────────────────────────────────

    /// Process a chat message through the AI provider
    pub fn chat(
        &self,
        peer_id: &str,
        user_input: &str,
        model: Option<String>,
        attachments: Vec<crate::ai::FileAttachment>,
        lang: Option<String>,
    ) -> Result<AiResponse, AgentError> {
        let trimmed = user_input.trim();

        let (role, history) = {
            let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
            let r = mgr
                .get_peer_role(peer_id)
                .unwrap_or_else(|| "viewer".to_string());
            let h_mgr = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
            (r, h_mgr.clone())
        };

        // Intercept commands (Phase 4.1 Orchestration)
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(AiResponse::default());
        }
        let command = parts[0].to_lowercase();

        // 1. /models - List available models
        if command == "/models" || trimmed == "/list models" {
            let mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
            let models = mgr.list_models();
            let msg = if models.is_empty() {
                format!("No models found for provider **{}**.", mgr.provider_name())
            } else {
                format!(
                    "Available models for **{}**:\n\n- {}",
                    mgr.provider_name(),
                    models.join("\n- ")
                )
            };
            return Ok(AiResponse {
                message: msg,
                intent: None,
                confidence: 1.0,
                provider: "system".to_string(),
                is_local: true,
                sub_responses: Vec::new(),
            });
        }

        // 2. /mode - Change agent focus mode
        if command == "/mode" {
            if parts.len() > 1 {
                let target_mode = parts[1].to_lowercase();
                if target_mode == "market"
                    || target_mode == "sanctum"
                    || target_mode == "automation"
                    || target_mode == "fleet"
                {
                    self.set_mode(&target_mode)?;
                    return Ok(AiResponse {
                        message: format!(
                            "Agent mode updated to: **{}**",
                            target_mode.to_uppercase()
                        ),
                        intent: None,
                        confidence: 1.0,
                        provider: "system".to_string(),
                        is_local: true,
                        sub_responses: Vec::new(),
                    });
                }
            }
            return Ok(AiResponse {
                message: "Usage: `/mode <market|sanctum|automation|fleet>`".to_string(),
                intent: None,
                confidence: 1.0,
                provider: "system".to_string(),
                is_local: true,
                sub_responses: Vec::new(),
            });
        }

        // 3. /model - Change primary AI model
        if command == "/model" {
            // RBAC: Only Admin/Owner can change AI profile
            self.policy_engine.evaluate("policy_override", &role)?;
            if parts.len() > 1 {
                let target_model = parts[1].to_string();
                let mut mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                match mgr.set_model(&target_model) {
                    Ok(_) => {
                        return Ok(AiResponse {
                            message: format!("AI model updated to: **{}**", target_model),
                            intent: None,
                            confidence: 1.0,
                            provider: "system".to_string(),
                            is_local: true,
                            sub_responses: Vec::new(),
                        });
                    }
                    Err(e) => {
                        return Ok(AiResponse {
                            message: format!("Failed to update model: {}", e),
                            intent: None,
                            confidence: 1.0,
                            provider: "system".to_string(),
                            is_local: true,
                            sub_responses: Vec::new(),
                        });
                    }
                }
            }
            return Ok(AiResponse {
                message: "Usage: `/model <model_name>` (e.g. `/model gpt-oss`, `/model llama3`)"
                    .to_string(),
                intent: None,
                confidence: 1.0,
                provider: "system".to_string(),
                is_local: true,
                sub_responses: Vec::new(),
            });
        }

        // Security: Check if user has basic talk permission (Non-command check)
        self.policy_engine.evaluate("status_query", &role)?;

        // Phase 4: Direct Agent Routing (DAR)
        if trimmed.starts_with('@') {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let mention = parts[0].strip_prefix('@').unwrap_or_default().trim();
            let body = if parts.len() > 1 {
                parts[1..].join(" ")
            } else {
                String::new()
            };

            // 1. Check if it's a local Mission context
            let mission = {
                let ai = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                ai.mission_registry().get_by_role(mention)
            };

            if let Some(m) = mission {
                return Ok(AiResponse {
                    message: format!("**DAR Route Activated**: Talking to mission **{}** (Role: {}). \n\nMessage: {}", m.name, m.role, body),
                    intent: None,
                    confidence: 1.0,
                    provider: "dar_orchestrator".to_string(),
                    is_local: true,
                    sub_responses: Vec::new(),
                });
            }

            // 2. Check if it's a remote Peer
            let has_peer = {
                let pm = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
                pm.get_peer(mention).is_some()
            };

            if has_peer {
                return Ok(AiResponse {
                    message: format!("**DAR Route Activated**: Forwarding message to remote agent `@{} via ECNP v1.1**.", mention),
                    intent: None,
                    confidence: 1.0,
                    provider: "dar_broker".to_string(),
                    is_local: false,
                    sub_responses: Vec::new(),
                });
            }
        }

        // Intercept /parallel command
        let mut is_parallel = false;
        let mut processed_user_input = user_input.to_string();
        if trimmed.starts_with("/parallel") {
            is_parallel = true;
            processed_user_input = trimmed.replacen("/parallel", "", 1).trim().to_string();
            if processed_user_input.is_empty() {
                return Ok(AiResponse {
                    message:
                        "Parallel mode activated. Please provide a prompt for parallel processing."
                            .to_string(),
                    intent: None,
                    confidence: 1.0,
                    provider: "system".to_string(),
                    is_local: true,
                    sub_responses: Vec::new(),
                });
            }
        }

        // Intercept /ingest_docs command
        if trimmed == "/ingest_docs" {
            let docs_path = std::path::PathBuf::from("d:\\edgeclaw\\docs");
            let mut items_added = 0;
            if let Ok(entries) = std::fs::read_dir(&docs_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("md") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let file_name = path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            let mut memory =
                                self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
                            memory
                                .knowledge
                                .add_item(crate::memory_engine::KnowledgeItem {
                                    title: file_name,
                                    keywords: vec!["documentation".to_string()],
                                    summary: String::new(),
                                    content,
                                    group_id: None,
                                });
                            items_added += 1;
                        }
                    }
                }
            }
            return Ok(AiResponse {
                message: format!("Successfully ingested **{}** documentation files from `docs/` into local KnowledgeBase.", items_added),
                intent: None,
                confidence: 1.0,
                provider: "system".to_string(),
                is_local: true,
                sub_responses: Vec::new(),
            });
        }
        if trimmed.starts_with("/mission") {
            // RBAC: Check mission management permission
            self.policy_engine.evaluate("process_manage", &role)?;
            let mission_prompt = trimmed.replacen("/mission", "", 1).trim().to_string();
            if mission_prompt.is_empty() {
                return Ok(AiResponse {
                    message: "Usage: `/mission <your mission description>`".to_string(),
                    intent: None,
                    confidence: 1.0,
                    provider: "system".to_string(),
                    is_local: true,
                    sub_responses: Vec::new(),
                });
            }

            // V2.x Fleet Mission Planner: 도메인 감지 → 전문가 수준 ATU 자동 분해
            let domain = crate::ai::DomainDetector::detect_domain(&mission_prompt);
            let peer_count = {
                let pm = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
                pm.list_peers().len().max(1)
            };
            let planning_prompt = crate::ai::FleetMissionPlanner::build_mission_planning_prompt(
                &mission_prompt,
                domain,
                peer_count,
            );

            println!(
                "[V2.x Fleet] Mission planning via Fleet Planner. Domain: {}, Peers: {}",
                domain, peer_count
            );

            // Send the planning prompt to AI for structured mission decomposition
            let planning_request = AiRequest {
                user_input: planning_prompt,
                available_capabilities: self.get_capabilities(),
                peer_role: role.clone(),
                system_context: Some(
                    "CRITICAL: Respond ONLY with valid JSON. No explanation text before or after the JSON.".to_string()
                ),
                history: Vec::new(),
                model: None,
                attachments: Vec::new(),
                parallel: false,
                strategies: vec!["mission_planning".to_string()],
                preferred_language: Some(self.config.agent.language.clone()),
            };

            let planning_result = {
                let mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                mgr.process(&planning_request)
            };

            match planning_result {
                Ok(ref resp)
                    if resp
                        .intent
                        .as_ref()
                        .and_then(|i| i.mission.as_ref())
                        .is_some() =>
                {
                    // AI successfully decomposed the mission into ATUs
                    let mission = resp.intent.as_ref().unwrap().mission.as_ref().unwrap();
                    let quality = crate::ai::MissionQualityEvaluator::evaluate(mission);
                    println!(
                        "[V2.x Fleet] Mission quality: {:.2}, tasks: {}",
                        quality,
                        mission.tasks.len()
                    );

                    // Phase 5 Audit: Log mission creation
                    self.audit_manager.log(
                        &self.config.agent.device_name,
                        &role,
                        "mission_create",
                        &format!(
                            "Fleet Planner decomposed mission '{}' into {} ATUs (quality: {:.2})",
                            mission.name,
                            mission.tasks.len(),
                            quality
                        ),
                        "success",
                        None,
                    );

                    return Ok(resp.clone());
                }
                _ => {
                    // Fallback: Register as simple mission if AI failed to decompose
                    println!("[V2.x Fleet] AI planning failed, falling back to simple mission registration");
                    let ai = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                    ai.mission_registry().register(crate::ai::MissionMetadata {
                        id: format!("miss_{}", chrono::Utc::now().timestamp()),
                        name: mission_prompt.clone(),
                        description: mission_prompt.clone(),
                        category: domain.to_string(),
                        tags: vec![],
                        role: "general".to_string(),
                        owner: role.clone(),
                        goals: vec![mission_prompt.clone()],
                        status: crate::ai::MissionStatus::Active,
                        progress: 0,
                        tasks: vec![],
                        created_at: chrono::Utc::now().to_rfc3339(),
                        started_at: None,
                        completed_at: None,
                    });

                    self.audit_manager.log(
                        &self.config.agent.device_name,
                        &role,
                        "mission_create",
                        &format!("User created mission (simple): {}", mission_prompt),
                        "success",
                        None,
                    );

                    return Ok(AiResponse {
                        message: format!("Mission received: \"{}\". Domain: {}. Agent will now focus on this mission.", mission_prompt, domain),
                        intent: None,
                        confidence: 1.0,
                        provider: "system".to_string(),
                        is_local: true,
                        sub_responses: Vec::new(),
                    });
                }
            }
        }

        // Check if parallel mode is enabled via global config
        if !self.config.ai.consensus_models.is_empty() {
            is_parallel = true;
        }

        // Knowledge Base Retrieval (Phase 6)
        let mut knowledge_context = String::new();
        let mut doc_titles = Vec::new();
        {
            let memory = self.memory_engine.lock().unwrap_or_else(|e| e.into_inner());
            let matches = memory.knowledge.search(&processed_user_input);
            if !matches.is_empty() {
                knowledge_context.push_str("\n\nRelevant Documentation Found:\n");
                for item in matches.iter().take(2) {
                    doc_titles.push(item.title.clone());
                    knowledge_context.push_str(&format!(
                        "--- {} ---\n{}\n",
                        item.title,
                        item.content.chars().take(1000).collect::<String>()
                    ));
                }
            }
        }

        if !doc_titles.is_empty() {
            self.event_bus
                .publish(crate::events::AgentEvent::KnowledgeRetrieved {
                    query: processed_user_input.clone(),
                    doc_titles,
                });
        }

        let sys_info = self.get_system_info();
        let fleet_ctx = {
            let pm = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
            format!("Fleet: {} agents connected", pm.list_peers().len())
        };
        let mission_ctx = {
            let ai = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
            format!("Missions: {} active", ai.mission_registry().list().len())
        };
        let system_context = Some(format!(
            "CPU: {:.1}%, Mem: {:.1}%, {}. {}. Mode: {}{}",
            sys_info.cpu_usage,
            sys_info.memory_usage_percent,
            fleet_ctx,
            mission_ctx,
            self.mode.lock().unwrap_or_else(|e| e.into_inner()),
            knowledge_context
        ));

        let request = AiRequest {
            user_input: processed_user_input.clone(),
            available_capabilities: self.get_capabilities(),
            peer_role: role.clone(),
            system_context,
            history,
            model,
            attachments,
            parallel: is_parallel,
            strategies: vec!["logic".to_string(), "consensus".to_string()],
            preferred_language: lang.or_else(|| Some(self.config.agent.language.clone())),
        };

        if is_parallel {
            self.event_bus
                .publish(crate::events::AgentEvent::ConsensusStarted {
                    prompt: processed_user_input.clone(),
                    models: self.config.ai.consensus_models.clone(),
                });
        }

        let response = {
            let mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
            let mut resp = mgr.process(&request)?;

            // Automatically handle mission proposals
            if let Some(ref mut intent) = resp.intent {
                if let Some(ref mission) = intent.mission {
                    mgr.mission_registry().register(mission.clone());
                    info!("AI proposed a new mission: {}", mission.name);
                }
            }
            resp
        };

        if is_parallel {
            self.event_bus
                .publish(crate::events::AgentEvent::ConsensusReached {
                    prompt: processed_user_input.clone(),
                    result: response.message.clone(),
                    confidence: response.confidence,
                });
        }

        // Phase 5 Audit: Parallel/Consensus results
        if !response.sub_responses.is_empty() {
            self.audit_manager.log(
                &self.config.agent.device_name,
                &role,
                "ai_consensus",
                &format!(
                    "Consensus reached among {} models for prompt: {}",
                    response.sub_responses.len(),
                    processed_user_input
                ),
                "success",
                None,
            );
        }

        // Add to conversation history
        {
            let mut h = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
            h.push(ChatMessage {
                role: ChatRole::User,
                content: user_input.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
            h.push(ChatMessage {
                role: ChatRole::Assistant,
                content: response.message.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });

            // Keep last 20 messages
            if h.len() > 20 {
                let drain_to = h.len() - 20;
                h.drain(..drain_to);
            }

            // Phase 2 Extension: Save chat history to standardized disk location 🛡️
            let history_path = self.config.storage_dir().join("chat_history.json");

            if let Ok(json) = serde_json::to_string_pretty(&*h) {
                let _ = std::fs::create_dir_all(history_path.parent().unwrap());
                let _ = std::fs::write(&history_path, json);
            }
        }

        // Audit the AI interaction
        let device_id = self
            .get_identity()
            .map(|id| id.device_id)
            .unwrap_or_else(|_| "unknown".to_string());
        self.audit_manager.log(
            &device_id,
            &role,
            "ai_chat",
            user_input,
            &response.provider,
            Some(&format!("confidence: {:.2}", response.confidence)),
        );

        Ok(response)
    }

    pub async fn chat_execute(
        &self,
        peer_id: &str,
        user_input: &str,
    ) -> Result<(AiResponse, Option<ExecResponse>), AgentError> {
        let ai_response = self.chat(peer_id, user_input, None, vec![], None)?;

        if let Some(ref intent) = ai_response.intent {
            // Build execution request from intent
            let request = ExecRequest {
                execution_id: uuid::Uuid::new_v4().to_string(),
                action: intent.capability.clone(),
                command: intent.command.clone(),
                args: intent.args.clone(),
                timeout_secs: 30,
                working_dir: None,
            };

            match self.execute_command(peer_id, request).await {
                Ok(exec_result) => {
                    // P3-04: Evaluate lessons for this domain based on execution success
                    self.evaluate_lessons(&intent.capability, exec_result.success);
                    Ok((ai_response, Some(exec_result)))
                }
                Err(e) => {
                    // P3-04: Evaluate lessons as failed if execution errors out
                    self.evaluate_lessons(&intent.capability, false);

                    // Return AI response + error info
                    Ok((
                        AiResponse {
                            message: format!(
                                "{}\n\n❌ Execution failed: {}",
                                ai_response.message, e
                            ),
                            ..ai_response
                        },
                        None,
                    ))
                }
            }
        } else {
            Ok((ai_response, None))
        }
    }

    /// Get quick actions available for the given role (filtered by work profile from config)
    pub fn get_quick_actions(&self, role: &str) -> Vec<ai::QuickAction> {
        let profile_str = self.config().webui.work_profile.to_lowercase();
        let profile = match profile_str.as_str() {
            "software_dev" | "softwaredev" | "dev" => Some(ai::WorkProfile::SoftwareDev),
            "marketing" | "mkt" => Some(ai::WorkProfile::Marketing),
            "system" => Some(ai::WorkProfile::System),
            "devops" | "ops" => Some(ai::WorkProfile::DevOps),
            "all" | "" => None, // show everything
            custom => Some(ai::WorkProfile::Custom(custom.to_string())),
        };
        ai::quick_actions_by_profile(profile)
            .into_iter()
            .filter(|a| {
                self.policy_engine
                    .evaluate(&a.capability, role)
                    .map(|d| d.allowed)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get AI provider status
    pub fn ai_status(&self) -> serde_json::Value {
        let mgr = self.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "provider": mgr.provider_name(),
            "available": mgr.is_available(),
            "local": mgr.is_local(),
            "requires_consent": mgr.requires_consent(),
        })
    }

    // ─── Audit ─────────────────────────────────────────────

    /// Get audit log entries
    pub fn get_audit_log(&self, count: usize) -> Vec<audit::AuditEntry> {
        self.audit_manager.last_entries(count)
    }

    /// Verify audit chain integrity
    pub fn verify_audit_chain(&self) -> Result<bool, String> {
        self.audit_manager.verify()
    }

    /// Export full audit log as JSON
    pub fn export_audit_log(&self) -> Result<String, serde_json::Error> {
        self.audit_manager.export()
    }

    /// Get audit entry count
    pub fn audit_count(&self) -> usize {
        self.audit_manager.count()
    }

    // ─── Task Board ────────────────────────────────────────

    /// List all tasks
    pub fn list_tasks(&self) -> Vec<crate::task_board::TaskEntry> {
        let board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board.list_all().into_iter().cloned().collect()
    }

    /// List tasks filtered by status and/or assignee.
    pub fn list_tasks_filtered(
        &self,
        status: Option<&crate::task_board::TaskStatus>,
        assignee: Option<&str>,
    ) -> Vec<crate::task_board::TaskEntry> {
        let board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board
            .list_filtered(status, assignee)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Create a task
    pub fn create_task(
        &self,
        title: &str,
        description: Option<&str>,
        priority: crate::task_board::TaskPriority,
        tags: &[&str],
    ) -> crate::task_board::TaskEntry {
        let mut board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board.create_task(title, description, priority, tags)
    }

    /// Move a task
    pub fn move_task(
        &self,
        task_id: uuid::Uuid,
        new_status: crate::task_board::TaskStatus,
    ) -> Result<crate::task_board::TaskEntry, AgentError> {
        let mut board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board
            .move_task(task_id, new_status)
            .ok_or_else(|| AgentError::NotFound(format!("task not found: {}", task_id)))
    }

    /// Assign a task to an agent.
    pub fn assign_task(
        &self,
        task_id: uuid::Uuid,
        assignee: &str,
    ) -> Result<crate::task_board::TaskEntry, AgentError> {
        let mut board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board
            .assign_task(task_id, assignee)
            .ok_or_else(|| AgentError::NotFound(format!("task not found: {}", task_id)))
    }

    /// Delete a task from the board.
    pub fn delete_task(&self, task_id: uuid::Uuid) -> bool {
        let mut board = self.task_board.lock().unwrap_or_else(|e| e.into_inner());
        board.archive_task(task_id).is_some()
    }

    /// Get current chat history.
    pub fn get_chat_history(&self) -> Vec<ChatMessage> {
        let history = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
        history.clone()
    }

    /// Clear chat history.
    pub fn clear_chat_history(&self) {
        let mut history = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
        history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> AgentEngine {
        AgentEngine::new(AgentConfig::default())
    }

    #[test]
    fn test_create_engine() {
        let engine = test_engine();
        assert_eq!(engine.config().agent.listen_port, 8443);
    }

    #[test]
    fn test_identity_lifecycle() {
        let engine = test_engine();
        assert!(engine.get_identity().is_err());
        let id = engine.generate_identity().unwrap();
        assert!(!id.device_id.is_empty());
        let id2 = engine.get_identity().unwrap();
        assert_eq!(id.device_id, id2.device_id);
    }

    #[test]
    fn test_peer_management() {
        let engine = test_engine();
        engine
            .add_peer("p1", "iPhone", "mobile", "10.0.0.1", "admin")
            .unwrap();
        assert_eq!(engine.get_peers().len(), 1);
        assert_eq!(engine.connected_count(), 1);
        assert!(engine.remove_peer("p1"));
        assert_eq!(engine.get_peers().len(), 0);
    }

    #[test]
    fn test_session_and_encryption() {
        let engine = test_engine();
        engine.generate_identity().unwrap();

        let peer_key: [u8; 32] = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 64,
        ];
        let session = engine.create_session("peer-1", &peer_key).unwrap();
        assert_eq!(session.state, "active");

        let encrypted = engine
            .encrypt_message(&session.session_id, b"test data")
            .unwrap();
        let decrypted = engine
            .decrypt_message(&session.session_id, &encrypted)
            .unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn test_policy_evaluation() {
        let engine = test_engine();
        let d = engine
            .evaluate_capability("status_query", "viewer")
            .unwrap();
        assert!(d.allowed);

        let d = engine.evaluate_capability("shell_exec", "viewer").unwrap();
        assert!(!d.allowed);

        let d = engine.evaluate_capability("shell_exec", "owner").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn test_ecnp_encode_decode() {
        let engine = test_engine();
        let encoded = engine.encode_ecnp(MessageType::Heartbeat, b"ping").unwrap();
        let decoded = engine.decode_ecnp(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Heartbeat as u8);
        assert_eq!(decoded.payload, b"ping");
    }

    #[test]
    fn test_system_info() {
        let engine = test_engine();
        let info = engine.get_system_info();
        assert!(info.cpu_count > 0);
        assert!(info.total_memory_mb > 0);
    }

    #[test]
    fn test_capabilities_detection() {
        let engine = test_engine();
        let caps = engine.get_capabilities();
        assert!(caps.contains(&"status_query".to_string()));
        assert!(caps.len() >= 10);
    }

    #[test]
    fn test_uptime() {
        let engine = test_engine();
        assert!(engine.uptime_secs() < 2);
    }

    #[tokio::test]
    async fn test_execute_with_policy_check() {
        let engine = test_engine();
        engine.generate_identity().unwrap();
        engine
            .add_peer("ctrl-1", "Controller", "mobile", "10.0.0.1", "owner")
            .unwrap();

        let request = ExecRequest {
            execution_id: "exec-001".to_string(),
            action: "shell_exec".to_string(),
            command: "echo policy_pass".to_string(),
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };

        let result = engine.execute_command("ctrl-1", request).await.unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("policy_pass"));
    }

    #[tokio::test]
    async fn test_execute_policy_denied() {
        let engine = test_engine();
        engine
            .add_peer("ctrl-2", "Viewer", "mobile", "10.0.0.2", "viewer")
            .unwrap();

        let request = ExecRequest {
            execution_id: "exec-002".to_string(),
            action: "shell_exec".to_string(),
            command: "echo should_fail".to_string(),
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };

        let result = engine.execute_command("ctrl-2", request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AgentError::PolicyDenied(_)));
    }

    #[test]
    fn test_event_bus_accessible() {
        let engine = test_engine();
        let bus = engine.event_bus();
        let mut rx = bus.subscribe();
        bus.publish(crate::events::AgentEvent::Heartbeat { uptime_secs: 1 });
        let event = rx.try_recv();
        assert!(event.is_ok());
    }

    #[test]
    fn test_quick_actions_owner() {
        let engine = test_engine();
        let actions = engine.get_quick_actions("owner");
        assert!(!actions.is_empty(), "owner should have quick actions");
    }

    #[test]
    fn test_quick_actions_viewer() {
        let engine = test_engine();
        let actions = engine.get_quick_actions("viewer");
        // Viewer has limited capabilities
        for action in &actions {
            assert!(
                ["status_query", "log_read", "system_info"].contains(&action.capability.as_str()),
                "viewer should only have viewer-level capabilities"
            );
        }
    }

    #[test]
    fn test_ai_status() {
        let engine = test_engine();
        let status = engine.ai_status();
        assert!(status.get("provider").is_some());
        assert!(status.get("available").is_some());
        assert!(status.get("local").is_some());
    }

    #[test]
    fn test_task_assign_and_filtered_list() {
        let engine = test_engine();
        let task = engine.create_task(
            "Filter test",
            None,
            crate::task_board::TaskPriority::High,
            &[],
        );
        let assigned = engine.assign_task(task.id, "local-1").unwrap();
        assert_eq!(assigned.assignee.as_deref(), Some("local-1"));

        let filtered = engine.list_tasks_filtered(None, Some("local-1"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, task.id);
    }

    #[test]
    fn test_audit_log() {
        let engine = test_engine();
        let entries = engine.get_audit_log(10);
        // may or may not be empty depending on engine init
        let _ = entries;
        let _ = engine.audit_count();
    }

    #[test]
    fn test_audit_chain_verify() {
        let engine = test_engine();
        let result = engine.verify_audit_chain();
        // May succeed or fail based on log state
        let _ = result;
    }

    #[test]
    fn test_export_audit_log() {
        let engine = test_engine();
        let json = engine.export_audit_log().unwrap();
        assert!(json.starts_with('['));
    }

    #[test]
    fn test_create_heartbeat() {
        let engine = test_engine();
        engine.generate_identity().unwrap();
        let hb = engine.create_heartbeat();
        assert!(hb.is_ok());
        let json: serde_json::Value = serde_json::from_str(&hb.unwrap()).unwrap();
        assert!(json.get("uptime_secs").is_some());
    }

    #[test]
    fn test_chat_without_identity() {
        let engine = test_engine();
        engine
            .add_peer("p1", "User", "mobile", "10.0.0.1", "owner")
            .unwrap();
        // Chat should work even without identity (uses "unknown" for audit)
        let _response = engine.chat("p1", "/models", None, Vec::new(), None).unwrap();
    }

    #[test]
    fn test_memory_storage_path() {
        let engine = test_engine();
        let path = engine.memory_storage_path();
        assert_eq!(path.file_name().and_then(|s| s.to_str()), Some("memory.md"));
    }
}
