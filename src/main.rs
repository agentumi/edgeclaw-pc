//! EdgeClaw Desktop Agent — CLI entry point.
//!
//! Provides `init`, `start`, `status`, `identity`, `capabilities`,
//! `info`, and `chat` subcommands via clap.

use clap::{Parser, Subcommand};
use edgeclaw_agent::config::AgentConfig;
use edgeclaw_agent::protocol::MessageType;
use edgeclaw_agent::websocket::{WebSocketConfig, WebSocketServer};
use edgeclaw_agent::webui::{WebUiConfig, WebUiServer};
use edgeclaw_agent::AgentEngine;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "edgeclaw-agent")]
#[command(version = "1.0.0")]
#[command(about = "EdgeClaw PC Agent — Zero-Trust Edge AI Executor")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value_t = default_config_path())]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the agent daemon
    Start,
    /// Show agent status
    Status,
    /// Show device identity
    Identity,
    /// List detected capabilities
    Capabilities,
    /// Show system information
    Info,
    /// Initialize default configuration
    Init,
    /// Interactive chat with AI
    Chat,
    /// Show AI provider status
    AiStatus,
    /// Show audit log
    AuditLog {
        /// Number of recent entries to show
        #[arg(short, long, default_value_t = 20)]
        count: usize,
    },
    /// Verify audit chain integrity
    AuditVerify,
    /// Check agent health (for monitoring/Docker)
    Health,
    /// Launch web chat UI (opens browser)
    WebUi {
        /// Port for the web UI server
        #[arg(short, long)]
        port: Option<u16>,
        /// Don't auto-open browser
        #[arg(long)]
        no_open: bool,
    },
}

fn default_config_path() -> String {
    AgentConfig::default_path().to_string_lossy().to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let config_path = PathBuf::from(&cli.config);
    let config = AgentConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("Warning: failed to load config: {e}, using defaults");
        AgentConfig::default()
    });

    match cli.command.unwrap_or(Commands::Start) {
        Commands::Init => {
            info!("Initializing default configuration");
            config.save(&config_path)?;
            println!("Config saved to: {}", config_path.display());
            Ok(())
        }
        Commands::Identity => {
            let engine = AgentEngine::new(config);
            let identity = engine.generate_identity()?;
            println!("Device Identity:");
            println!("  ID:          {}", identity.device_id);
            println!("  Name:        {}", identity.device_name);
            println!("  Public Key:  {}", identity.public_key_hex);
            println!("  Fingerprint: {}", identity.fingerprint);
            println!("  Platform:    {}", identity.platform);
            println!("  Created:     {}", identity.created_at);
            Ok(())
        }
        Commands::Capabilities => {
            let engine = AgentEngine::new(config);
            let caps = engine.get_capabilities();
            println!("Detected Capabilities ({}):", caps.len());
            for cap in &caps {
                let sandbox = if engine.requires_sandbox(cap) {
                    " [sandbox]"
                } else {
                    ""
                };
                println!("  - {cap}{sandbox}");
            }
            Ok(())
        }
        Commands::Info => {
            let info = edgeclaw_agent::system::collect_system_info();
            println!("System Information:");
            println!("  Hostname:  {}", info.hostname);
            println!("  OS:        {} {}", info.os_name, info.os_version);
            println!("  Arch:      {}", info.arch);
            println!("  CPU:       {} ({} cores)", info.cpu_brand, info.cpu_count);
            println!("  CPU Usage: {:.1}%", info.cpu_usage);
            println!(
                "  Memory:    {}/{} MB ({:.1}%)",
                info.used_memory_mb, info.total_memory_mb, info.memory_usage_percent
            );
            println!(
                "  Disk:      {:.1}/{:.1} GB",
                info.used_disk_gb, info.total_disk_gb
            );
            println!("  Uptime:    {}s", info.uptime_secs);
            Ok(())
        }
        Commands::Status => {
            // Try to reach running agent health endpoint
            let health_url = format!(
                "http://{}:{}/api/health",
                config.webui.bind, config.webui.port
            );
            let mut live = false;
            if let Ok(resp) = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .get(&health_url)
                .call()
            {
                if let Ok(body) = resp.into_string() {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        println!("EdgeClaw Agent v1.0.0 — RUNNING");
                        println!("  Uptime: {}s", json["uptime_secs"]);
                        println!("  AI:     {}", json["components"]["ai"]);
                        println!("  Port:   {}", config.agent.listen_port);
                        println!(
                            "  WebUI:  http://{}:{}",
                            config.webui.bind, config.webui.port
                        );
                        live = true;
                    }
                }
            }
            if !live {
                println!("EdgeClaw Agent v1.0.0 — NOT RUNNING");
                println!("  Config: {}", config_path.display());
                println!("  Port:   {}", config.agent.listen_port);
                println!("  Mode:   {}", config.security.policy_mode);
                println!("  AI:     {}", config.ai.primary);
                println!("  Tip:    Run `edgeclaw-agent start` to start");
            }
            Ok(())
        }
        Commands::Chat => {
            let engine = AgentEngine::new(config);
            engine.generate_identity()?;
            // Register self as owner peer for chat
            engine.add_peer("console", "Console", "cli", "localhost", "owner")?;

            println!("EdgeClaw AI Chat (type 'exit' to quit)");
            println!("AI Provider: {}", engine.ai_status()["provider"]);
            println!("---");

            let stdin = std::io::stdin();
            loop {
                print!("You: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut input = String::new();
                stdin.read_line(&mut input)?;
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }
                if input == "exit" || input == "quit" {
                    break;
                }

                match engine.chat_execute("console", input).await {
                    Ok((resp, exec_result)) => {
                        println!("Agent: {}", resp.message);
                        if let Some(intent) = &resp.intent {
                            println!("  → [{}] {}", intent.capability, intent.command);
                        }
                        if let Some(exec) = exec_result {
                            if exec.success {
                                if !exec.stdout.is_empty() {
                                    println!("{}", exec.stdout.trim_end());
                                }
                            } else {
                                println!("  ⚠ Exit code: {:?}", exec.exit_code);
                                if !exec.stderr.is_empty() {
                                    println!("  {}", exec.stderr.trim_end());
                                }
                            }
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            Ok(())
        }
        Commands::AiStatus => {
            let engine = AgentEngine::new(config);
            let status = engine.ai_status();
            println!("AI Provider Status:");
            println!("  Provider:  {}", status["provider"]);
            println!("  Available: {}", status["available"]);
            println!("  Local:     {}", status["local"]);
            println!("  Consent:   {}", status["requires_consent"]);
            Ok(())
        }
        Commands::AuditLog { count } => {
            let engine = AgentEngine::new(config);
            println!("Audit Log (last {} entries):", count);
            let entries = engine.get_audit_log(count);
            if entries.is_empty() {
                println!("  (no entries)");
            }
            for entry in entries {
                println!(
                    "  #{} [{}] {} {} -> {} ({})",
                    entry.sequence,
                    entry.timestamp,
                    entry.actor_role,
                    entry.capability,
                    entry.result,
                    entry.hash.chars().take(16).collect::<String>()
                );
            }
            Ok(())
        }
        Commands::AuditVerify => {
            let engine = AgentEngine::new(config);
            match engine.verify_audit_chain() {
                Ok(true) => println!(
                    "✅ Audit chain integrity verified ({} entries)",
                    engine.audit_count()
                ),
                Ok(false) => println!("❌ Audit chain verification failed"),
                Err(e) => println!("❌ Chain broken: {}", e),
            }
            Ok(())
        }
        Commands::Health => {
            let engine = AgentEngine::new(config);
            let ai = engine.ai_status();
            let sys = edgeclaw_agent::system::collect_system_info();
            let healthy = sys.cpu_usage < 95.0 && sys.memory_usage_percent < 95.0;
            if healthy {
                println!("{{\"status\":\"ok\",\"version\":\"1.0.0\",\"ai\":\"{}\",\"cpu\":{:.1},\"mem\":{:.1}}}",
                    ai["provider"], sys.cpu_usage, sys.memory_usage_percent);
                Ok(())
            } else {
                eprintln!(
                    "UNHEALTHY: cpu={:.1}% mem={:.1}%",
                    sys.cpu_usage, sys.memory_usage_percent
                );
                std::process::exit(1);
            }
        }
        Commands::Start => {
            info!(
                version = "1.0.0",
                port = config.agent.listen_port,
                "EdgeClaw Agent starting"
            );

            let engine = Arc::new(AgentEngine::new(config.clone()));

            // Generate identity on first run
            let identity = engine.generate_identity()?;
            info!(
                device_id = %identity.device_id,
                fingerprint = %identity.fingerprint,
                platform = %identity.platform,
                "Device identity generated"
            );

            // Register web-client as owner peer for chat
            engine.add_peer("web-client", "WebUI", "browser", "127.0.0.1", "owner")?;

            let num_agents = config.webui.effective_max_agents();

            // Print agent startup banner
            println!("╔══════════════════════════════════════════╗");
            println!("║     EdgeClaw PC Agent v1.0.0             ║");
            println!("║     Zero-Trust Edge AI Executor          ║");
            println!("╠══════════════════════════════════════════╣");
            println!("║  ID:   {}  ║", &identity.device_id[..36]);
            println!("║  FP:   {}                       ║", identity.fingerprint);
            println!(
                "║  Port: {}                             ║",
                engine.config().agent.listen_port
            );
            if config.webui.enabled {
                println!(
                    "║  Chat: http://{}:{}            ║",
                    config.webui.bind, config.webui.port
                );
                println!(
                    "║  Tier: {} ({} agent{})               ║",
                    config.webui.license_tier,
                    num_agents,
                    if num_agents > 1 { "s" } else { "" }
                );
                println!(
                    "║  Profile: {:16}              ║",
                    config.webui.work_profile
                );
            }
            println!("╚══════════════════════════════════════════╝");

            // Start Web UI server(s) — multi-agent: one per port
            if config.webui.enabled {
                for i in 0..num_agents {
                    let port = config.webui.agent_port(i);
                    let webui_bind = format!("{}:{}", config.webui.bind, port);
                    let webui_engine = engine.clone();
                    let auto_open = config.webui.auto_open && i == 0; // only open first
                    let webui_url = format!("http://{}", webui_bind);
                    let agent_idx = i;
                    let auth_pw = config.webui.auth_password.clone();
                    let cors_orig = config.webui.cors_origin.clone();

                    // Register each agent's peer
                    if i > 0 {
                        let peer_id = format!("web-client-{}", i);
                        let _ = engine.add_peer(
                            &peer_id,
                            &format!("WebUI-{}", i),
                            "browser",
                            "127.0.0.1",
                            "owner",
                        );
                    }

                    info!(port = port, agent = agent_idx, "Starting Web UI agent");

                    tokio::spawn(async move {
                        let mut webui = WebUiServer::new(
                            WebUiConfig {
                                bind_addr: webui_bind,
                                auth_password: auth_pw,
                                cors_origin: cors_orig,
                            },
                            webui_engine,
                        );
                        if auto_open {
                            let _ = open_browser(&webui_url);
                        }
                        if let Err(e) = webui.start().await {
                            error!(error = %e, agent = agent_idx, "Web UI server error");
                        }
                    });
                }
                if num_agents > 1 {
                    println!(
                        "  Agents: {} instances on ports {}-{}",
                        num_agents,
                        config.webui.port,
                        config.webui.agent_port(num_agents - 1)
                    );
                }
            }

            // Start WebSocket server for real-time events
            if config.websocket.enabled {
                let ws_bind = format!("{}:{}", config.websocket.bind, config.websocket.port);
                let ws_event_bus = engine.event_bus().clone();
                let ws_max_clients = config.websocket.max_clients;

                println!(
                    "║  WS:   ws://{}:{}                ║",
                    config.websocket.bind, config.websocket.port
                );

                tokio::spawn(async move {
                    let mut ws_server = WebSocketServer::new(
                        WebSocketConfig {
                            bind_addr: ws_bind,
                            auth_token: String::new(),
                            max_clients: ws_max_clients,
                        },
                        ws_event_bus,
                    );
                    if let Err(e) = ws_server.start().await {
                        error!(error = %e, "WebSocket server error");
                    }
                });
            }

            // Start TCP server
            let bind_addr = format!("0.0.0.0:{}", engine.config().agent.listen_port);
            let (msg_tx, mut msg_rx) =
                tokio::sync::mpsc::channel::<edgeclaw_agent::server::IncomingMessage>(256);

            // Start periodic metrics publisher → EventBus
            {
                let metrics_engine = engine.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        let sys = metrics_engine.get_system_info();
                        metrics_engine.event_bus().publish(
                            edgeclaw_agent::events::AgentEvent::MetricUpdate {
                                cpu_percent: sys.cpu_usage as f64,
                                memory_percent: sys.memory_usage_percent as f64,
                                active_connections: metrics_engine.connected_count() as u32,
                                active_executions: 0,
                            },
                        );
                    }
                });
            }

            let mut tcp_server =
                edgeclaw_agent::server::TcpServer::new(edgeclaw_agent::server::TcpServerConfig {
                    bind_addr,
                    max_connections: engine.config().agent.max_connections,
                    handshake_timeout_secs: 5,
                });

            // Message handler task — dispatch by message type
            let _handler_engine = engine.clone();
            tokio::spawn(async move {
                while let Some(msg) = msg_rx.recv().await {
                    let msg_type = MessageType::try_from(msg.message.msg_type);
                    match msg_type {
                        Ok(MessageType::Heartbeat) => {
                            info!(
                                peer = %msg.peer_addr,
                                payload_len = msg.message.payload.len(),
                                "heartbeat received"
                            );
                        }
                        Ok(MessageType::Handshake) => {
                            info!(peer = %msg.peer_addr, "handshake received");
                            if let Ok(text) = String::from_utf8(msg.message.payload.clone()) {
                                if let Ok(ecm) = edgeclaw_agent::protocol::parse_ecm(&text) {
                                    info!(
                                        device_id = %ecm.device_id,
                                        device_name = %ecm.device_name,
                                        caps = ecm.capabilities.len(),
                                        "peer registered from handshake"
                                    );
                                }
                            }
                        }
                        Ok(MessageType::Data) => {
                            info!(
                                peer = %msg.peer_addr,
                                payload_len = msg.message.payload.len(),
                                "data message received"
                            );
                        }
                        Ok(MessageType::Telemetry) => {
                            info!(peer = %msg.peer_addr, "telemetry received");
                        }
                        Ok(mt) => {
                            info!(
                                peer = %msg.peer_addr,
                                msg_type = ?mt,
                                "unhandled message type"
                            );
                        }
                        Err(e) => {
                            warn!(peer = %msg.peer_addr, error = %e, "unknown message type");
                        }
                    }
                }
            });

            // Graceful shutdown on Ctrl+C
            let tcp_handle = tokio::spawn(async move {
                if let Err(e) = tcp_server.start(msg_tx).await {
                    error!(error = %e, "TCP server error");
                }
            });

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received — shutting down gracefully");
                    println!("\nShutting down...");
                }
                _ = tcp_handle => {
                    info!("TCP server stopped");
                }
            }

            info!("EdgeClaw Agent stopped");
            Ok(())
        }
        Commands::WebUi { port, no_open } => {
            let engine = Arc::new(AgentEngine::new(config.clone()));
            engine.generate_identity()?;
            engine.add_peer("web-client", "WebUI", "browser", "127.0.0.1", "owner")?;

            let webui_port = port.unwrap_or(config.webui.port);
            let webui_bind = format!("{}:{}", config.webui.bind, webui_port);
            let webui_url = format!("http://{}", webui_bind);

            println!("EdgeClaw Web Chat UI");
            println!("  URL: {}", webui_url);
            println!("  AI:  {}", engine.ai_status()["provider"]);
            println!("Press Ctrl+C to stop.\n");

            if !no_open {
                let _ = open_browser(&webui_url);
            }

            let mut webui = WebUiServer::new(
                WebUiConfig {
                    bind_addr: webui_bind,
                    auth_password: config.webui.auth_password.clone(),
                    cors_origin: config.webui.cors_origin.clone(),
                },
                engine,
            );
            if let Err(e) = webui.start().await {
                error!(error = %e, "Web UI server error");
            }
            Ok(())
        }
    }
}

/// Open a URL in the default system browser
fn open_browser(url: &str) -> Result<(), std::io::Error> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}
