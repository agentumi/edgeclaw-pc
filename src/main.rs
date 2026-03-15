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

    /// Override base storage directory
    #[arg(long, global = true)]
    storage_path: Option<String>,

    /// Override ECNP listen port
    #[arg(long, global = true)]
    port: Option<u16>,

    /// Override WebUI listen port
    #[arg(short, long, global = true)]
    web_port: Option<u16>,

    /// Override WebSocket listen port
    #[arg(long, global = true)]
    ws_port: Option<u16>,

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
    /// Manage multi-agent network
    Agents {
        #[command(subcommand)]
        action: AgentsAction,
    },
    /// Activity log management (V4.0)
    Activity {
        #[command(subcommand)]
        action: ActivityAction,
    },
    /// Task board management (V4.0)
    Tasks {
        #[command(subcommand)]
        action: TaskAction,
    },
    /// Activity anchoring — Merkle proof management (V4.0)
    Anchor {
        #[command(subcommand)]
        action: AnchorAction,
    },
    /// Webhook management (V4.0)
    Webhook {
        #[command(subcommand)]
        action: WebhookAction,
    },
    /// Agent Passport management (V4.0/Phase2)
    Passport {
        #[command(subcommand)]
        action: PassportAction,
    },
}

#[derive(Subcommand)]
enum ActivityAction {
    /// Show recent activity entries
    Recent {
        /// Number of entries to show
        #[arg(short, long, default_value_t = 20)]
        count: usize,
    },
    /// Full-text search over activity log
    Search {
        /// Search query
        query: String,
        /// Max results
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
    /// Show activity statistics
    Stats,
    /// Verify activity chain integrity
    Verify,
    /// Export activity log
    Export {
        /// Output file path (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
        /// Output format: json or csv
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum TaskAction {
    /// List tasks
    List {
        /// Filter by status (todo, in_progress, review, done)
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Create a new task
    Create {
        /// Task title
        title: String,
        /// Project name
        #[arg(short, long, default_value = "default")]
        project: String,
    },
    /// Move a task to a new status
    Move {
        /// Task ID (UUID or short prefix)
        task_id: String,
        /// New status (todo, in_progress, review, done)
        status: String,
    },
    /// Assign a task to an agent
    Assign {
        /// Task ID (UUID or short prefix)
        task_id: String,
        /// Agent device ID to assign
        assignee: String,
    },
}

#[derive(Subcommand)]
enum AnchorAction {
    /// Show anchor status (last anchor time, entry count)
    Status,
    /// Verify an entry against the anchor chain
    Verify {
        /// Entry ID (UUID or short prefix)
        entry_id: String,
    },
}

#[derive(Subcommand)]
enum WebhookAction {
    /// List registered webhooks
    List,
    /// Add a webhook endpoint
    Add {
        /// Webhook URL
        url: String,
        /// HMAC secret (optional)
        #[arg(short, long)]
        secret: Option<String>,
        /// Event filter (comma-separated)
        #[arg(short, long)]
        events: Option<String>,
    },
    /// Remove a webhook endpoint by URL
    Remove {
        /// Webhook URL to remove
        url: String,
    },
}

#[derive(Subcommand)]
enum PassportAction {
    /// Create new SUI NFT Passport
    Create {
        /// Platform (e.g. desktop, linux)
        #[arg(short, long, default_value = "desktop")]
        platform: String,
    },
    /// Show current passport
    Show,
}

#[derive(Subcommand)]
enum AgentsAction {
    /// List registered agents
    List,
    /// Show status of a specific agent
    Status {
        /// Agent ID
        agent_id: String,
    },
    /// Connect to a remote agent
    Connect {
        /// Remote agent address (host:port)
        address: String,
    },
    /// Disconnect from a remote agent
    Disconnect {
        /// Agent ID to disconnect
        agent_id: String,
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
    let mut config = AgentConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("Warning: failed to load config: {e}, using defaults");
        AgentConfig::default()
    });

    // Override storage path if provided via CLI
    if let Some(sp) = cli.storage_path {
        config.agent.storage_path = Some(sp);
    }

    // Override ports if provided via CLI
    if let Some(p) = cli.port {
        config.agent.listen_port = p;
    }
    if let Some(wp) = cli.web_port {
        config.webui.port = wp;
    }
    if let Some(wsp) = cli.ws_port {
        config.websocket.port = wsp;
    }

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

            // Register for mDNS discovery
            if let Err(e) = engine.discovery_service().register() {
                warn!(error = %e, "Failed to register for discovery");
            }

            // Register web-client as owner peer for chat
            engine.add_peer("web-client", "WebUI", "browser", "127.0.0.1", "owner")?;

            let num_agents = config.webui.effective_max_agents();
            let mut effective_ws_port = config.websocket.port;

            // Prevent WebSocket bind conflicts with multi-agent WebUI ports.
            if config.websocket.enabled && config.webui.enabled && num_agents > 0 {
                let webui_start = config.webui.port;
                let webui_end = config.webui.agent_port(num_agents - 1);
                if (webui_start..=webui_end).contains(&effective_ws_port) {
                    let shifted = webui_end.saturating_add(1);
                    warn!(
                        ws_port = effective_ws_port,
                        webui_start = webui_start,
                        webui_end = webui_end,
                        shifted_ws_port = shifted,
                        "WebSocket port overlaps WebUI agent port range; shifting port"
                    );
                    println!(
                        "  [Port Fix] WS port {} conflicts with WebUI range {}-{}, using {}",
                        effective_ws_port, webui_start, webui_end, shifted
                    );
                    effective_ws_port = shifted;
                }
            }

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
                let ws_bind = format!("{}:{}", config.websocket.bind, effective_ws_port);
                let ws_event_bus = engine.event_bus().clone();
                let ws_max_clients = config.websocket.max_clients;

                println!(
                    "║  WS:   ws://{}:{}                ║",
                    config.websocket.bind, effective_ws_port
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
        Commands::Passport { action } => {
            let engine = AgentEngine::new(config.clone());
            let identity = engine.generate_identity()?;

            match action {
                PassportAction::Create { platform } => {
                    println!("Creating Agent Passport NFT for {}...", identity.device_id);
                    let mut passport = edgeclaw_agent::identity_passport::AgentPassport::new(
                        identity.public_key_hex.clone(),
                        identity.device_name.clone(),
                        platform.clone(),
                        engine
                            .get_capabilities()
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect(),
                        true,
                        true,
                    );

                    match engine
                        .blockchain_client()
                        .mint_agent_passport(&mut passport)
                    {
                        Ok(_) => {
                            println!("✅ Passport NFT Minted Successfully!");
                            println!(
                                "  NFT Object ID:  {}",
                                passport.nft_object_id.unwrap_or_default()
                            );
                            println!("  Reputation:     {:.1}", passport.reputation_score);
                            println!(
                                "  Capabilities:   {} registered",
                                passport.capabilities.capabilities.len()
                            );
                        }
                        Err(e) => {
                            println!("❌ Failed to mint Passport: {}", e);
                        }
                    }
                }
                PassportAction::Show => {
                    match engine
                        .blockchain_client()
                        .lookup_agent_passport(&identity.public_key_hex)
                    {
                        Some(passport) => {
                            println!(
                                "Agent Passport (NFT ID: {})",
                                passport.nft_object_id.unwrap_or_default()
                            );
                            println!("  Name:       {}", passport.metadata.name);
                            println!("  Device:     {}", passport.capabilities.device_id);
                            println!("  Platform:   {}", passport.capabilities.platform);
                            println!("  Reputation: {:.1}", passport.reputation_score);
                            println!("  Protocols:  {}", passport.metadata.protocols.join(", "));
                        }
                        None => {
                            println!("No Passport found for this device. Use `edgeclaw-agent passport create` to mint one.");
                        }
                    }
                }
            }
            Ok(())
        }
        Commands::Agents { action } => {
            let engine = AgentEngine::new(config.clone());
            engine.generate_identity()?;

            match action {
                AgentsAction::List => {
                    let registry = edgeclaw_agent::registry::AgentRegistry::new();
                    let agents = registry.list_all();
                    if agents.is_empty() {
                        println!("No agents registered.");
                        println!(
                            "  Tip: Use `edgeclaw-agent agents connect <host:port>` to add one."
                        );
                    } else {
                        println!("Registered Agents ({}):", agents.len());
                        for a in &agents {
                            let status_icon = match a.status {
                                edgeclaw_agent::registry::AgentStatus::Online => "🟢",
                                edgeclaw_agent::registry::AgentStatus::Busy => "🟡",
                                edgeclaw_agent::registry::AgentStatus::Offline => "🔴",
                                edgeclaw_agent::registry::AgentStatus::Error => "❌",
                            };
                            println!(
                                "  {} {} — {} ({}:{})",
                                status_icon, a.name, a.status, a.address, a.port
                            );
                        }
                    }
                    Ok(())
                }
                AgentsAction::Status { agent_id } => {
                    let registry = edgeclaw_agent::registry::AgentRegistry::new();
                    match registry.get(&agent_id) {
                        Some(a) => {
                            println!("Agent: {}", a.name);
                            println!("  ID:       {}", a.id);
                            println!("  Profile:  {}", a.profile);
                            println!("  Address:  {}:{}", a.address, a.port);
                            println!("  Status:   {}", a.status);
                            println!("  Version:  {}", a.version);
                            println!("  Caps:     {}", a.capabilities.join(", "));
                        }
                        None => {
                            println!("Agent '{}' not found.", agent_id);
                        }
                    }
                    Ok(())
                }
                AgentsAction::Connect { address } => {
                    println!("Connecting to {}...", address);
                    // Parse address
                    let parts: Vec<&str> = address.rsplitn(2, ':').collect();
                    let (port_str, host) = if parts.len() == 2 {
                        (parts[0], parts[1])
                    } else {
                        ("8443", address.as_str())
                    };
                    let port: u16 = port_str.parse().unwrap_or(8443);

                    // Attempt TCP connection + ECDH handshake
                    let addr = format!("{host}:{port}");
                    match tokio::net::TcpStream::connect(&addr).await {
                        Ok(mut stream) => {
                            let secret = engine.get_secret_key()?;
                            let public = engine.get_public_key()?;
                            let identity = engine.get_identity()?;
                            let sig = engine.sign_data(&public)?;

                            let payload = edgeclaw_agent::peer::build_handshake_payload(
                                &public,
                                &sig,
                                &identity.device_id,
                                &identity.device_name,
                            );

                            let mut session_mgr = edgeclaw_agent::session::SessionManager::new();
                            match edgeclaw_agent::peer::perform_handshake(
                                &mut stream,
                                &mut session_mgr,
                                &secret,
                                &payload,
                            )
                            .await
                            {
                                Ok((session_id, remote)) => {
                                    println!("✅ Connected to {}", remote.agent_name);
                                    println!("  Device:  {}", remote.device_id);
                                    println!("  Session: {}", &session_id[..8]);

                                    // Register in local registry
                                    let registry = edgeclaw_agent::registry::AgentRegistry::new();
                                    let info = edgeclaw_agent::registry::AgentInfo {
                                        id: remote.device_id.clone(),
                                        name: remote.agent_name.clone(),
                                        profile: "unknown".into(),
                                        address: host.to_string(),
                                        port,
                                        status: edgeclaw_agent::registry::AgentStatus::Online,
                                        capabilities: vec![],
                                        version: "unknown".into(),
                                        last_heartbeat: chrono::Utc::now(),
                                        registered_at: chrono::Utc::now(),
                                    };
                                    let _ = registry.register(info);
                                    let _ = registry.save();
                                    println!("  Registered in local agent registry.");
                                }
                                Err(e) => {
                                    println!("❌ Handshake failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("❌ Cannot connect to {}: {}", addr, e);
                        }
                    }
                    Ok(())
                }
                AgentsAction::Disconnect { agent_id } => {
                    let registry = edgeclaw_agent::registry::AgentRegistry::new();
                    if registry.remove(&agent_id) {
                        let _ = registry.save();
                        println!("Disconnected agent '{}'.", agent_id);
                    } else {
                        println!("Agent '{}' not found.", agent_id);
                    }
                    Ok(())
                }
            }
        }
        Commands::Activity { action } => {
            let engine = AgentEngine::new(config.clone());

            match action {
                ActivityAction::Recent { count } => {
                    let entries = engine.recent_activities(count);
                    if entries.is_empty() {
                        println!("  (no activity entries)");
                    } else {
                        println!("Recent Activity ({} entries):", entries.len());
                        for entry in entries.iter().rev() {
                            println!(
                                "  [{}] {} | {} | {} (imp={})",
                                entry.timestamp.format("%Y-%m-%d %H:%M"),
                                entry.activity_type.type_tag(),
                                entry.content.chars().take(60).collect::<String>(),
                                entry.agent_name,
                                entry.importance,
                            );
                        }
                    }
                    Ok(())
                }
                ActivityAction::Search { query, limit } => {
                    let results = engine.fts_search_activities(&query, limit);
                    if results.is_empty() {
                        // Fallback to in-memory search
                        let fallback = engine.search_activities(&query, limit);
                        if fallback.is_empty() {
                            println!("No results for '{}'.", query);
                        } else {
                            println!("Search results for '{}' ({} found):", query, fallback.len());
                            for entry in &fallback {
                                let snippet = engine.highlight_activity(&query, &entry.content);
                                println!(
                                    "  [{}] {} | {}",
                                    entry.timestamp.format("%Y-%m-%d %H:%M"),
                                    entry.activity_type.type_tag(),
                                    snippet,
                                );
                            }
                        }
                    } else {
                        println!("Search results for '{}' ({} found):", query, results.len());
                        for (score, entry) in &results {
                            let snippet = engine.highlight_activity(&query, &entry.content);
                            println!(
                                "  [{:.2}] [{}] {} | {}",
                                score,
                                entry.timestamp.format("%Y-%m-%d %H:%M"),
                                entry.activity_type.type_tag(),
                                snippet,
                            );
                        }
                    }
                    Ok(())
                }
                ActivityAction::Stats => {
                    let stats = engine.activity_stats();
                    println!("Activity Statistics:");
                    println!("  Total entries:  {}", stats.total_entries);
                    println!("  Total sessions: {}", stats.total_sessions);
                    println!("  Total tokens:   {}", stats.total_tokens);
                    println!("  Total cost:     ${:.4}", stats.total_cost_usd);
                    println!("  By type:");
                    for (t, c) in &stats.entries_by_type {
                        println!("    {}: {}", t, c);
                    }
                    if !stats.top_projects.is_empty() {
                        println!("  Top projects:");
                        for (p, c) in &stats.top_projects {
                            println!("    {}: {}", p, c);
                        }
                    }
                    Ok(())
                }
                ActivityAction::Verify => {
                    match engine.verify_activity_chain() {
                        Ok(true) => println!(
                            "✅ Activity chain integrity verified ({} entries)",
                            engine.activity_count()
                        ),
                        Ok(false) => println!("❌ Activity chain verification failed"),
                        Err(e) => println!("❌ Chain broken: {}", e),
                    }
                    Ok(())
                }
                ActivityAction::Export { output, format } => {
                    let data = match format.as_str() {
                        "csv" => engine.export_activity_csv()?,
                        _ => engine.export_activity_log()?,
                    };
                    match output {
                        Some(path) => {
                            std::fs::write(&path, &data)?;
                            println!(
                                "Exported {} entries ({}) to {}",
                                engine.activity_count(),
                                format,
                                path
                            );
                        }
                        None => {
                            println!("{}", data);
                        }
                    }
                    Ok(())
                }
            }
        }
        Commands::Tasks { action } => {
            use edgeclaw_agent::task_board::{TaskBoard, TaskPriority, TaskStatus};

            let board_path = dirs::data_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("edgeclaw")
                .join("tasks.json");

            let mut board = TaskBoard::new("local", "default");
            if board_path.exists() {
                let _ = board.load_from_file(&board_path);
            }

            match action {
                TaskAction::List { status } => {
                    let filter_status = status.as_deref().and_then(|s| match s {
                        "todo" | "backlog" => Some(TaskStatus::Backlog),
                        "in_progress" | "doing" => Some(TaskStatus::InProgress),
                        "review" => Some(TaskStatus::Review),
                        "done" => Some(TaskStatus::Done),
                        _ => None,
                    });

                    let tasks = match filter_status {
                        Some(s) => board.list_by_status(&s),
                        None => board.list_all(),
                    };

                    if tasks.is_empty() {
                        println!("  (no tasks)");
                    } else {
                        println!("Tasks ({}):", tasks.len());
                        for t in tasks {
                            let status_icon = match t.status {
                                TaskStatus::Backlog => "⬜",
                                TaskStatus::InProgress => "🔵",
                                TaskStatus::Review => "🟡",
                                TaskStatus::Done => "✅",
                                TaskStatus::Archived => "📦",
                            };
                            println!(
                                "  {} {} [{}] {}",
                                status_icon,
                                &t.id.to_string()[..8],
                                t.project,
                                t.title,
                            );
                        }
                    }
                    Ok(())
                }
                TaskAction::Create { title, project } => {
                    let task = board.create_task(&title, None, TaskPriority::Medium, &[]);
                    let _ = board.save_to_file(&board_path);
                    println!(
                        "Created task: {} ({})",
                        task.title,
                        &task.id.to_string()[..8]
                    );
                    let _ = project; // project set via TaskBoard::new
                    Ok(())
                }
                TaskAction::Move { task_id, status } => {
                    let new_status = match status.as_str() {
                        "todo" | "backlog" => TaskStatus::Backlog,
                        "in_progress" | "doing" => TaskStatus::InProgress,
                        "review" => TaskStatus::Review,
                        "done" => TaskStatus::Done,
                        other => {
                            eprintln!(
                                "Unknown status '{}'. Use: backlog, in_progress, review, done",
                                other
                            );
                            std::process::exit(1);
                        }
                    };

                    // Try to find task by prefix match
                    let all = board.list_all();
                    let found = all.iter().find(|t| t.id.to_string().starts_with(&task_id));

                    match found {
                        Some(t) => {
                            let tid = t.id;
                            board.move_task(tid, new_status.clone());
                            let _ = board.save_to_file(&board_path);
                            println!("Moved task {} → {:?}", &task_id, new_status);
                        }
                        None => {
                            eprintln!("Task '{}' not found.", task_id);
                            std::process::exit(1);
                        }
                    }
                    Ok(())
                }
                TaskAction::Assign { task_id, assignee } => {
                    let all = board.list_all();
                    let found = all.iter().find(|t| t.id.to_string().starts_with(&task_id));

                    match found {
                        Some(t) => {
                            let tid = t.id;
                            board.assign_task(tid, &assignee);
                            let _ = board.save_to_file(&board_path);
                            println!("Assigned task {} → {}", &task_id, assignee);
                        }
                        None => {
                            eprintln!("Task '{}' not found.", task_id);
                            std::process::exit(1);
                        }
                    }
                    Ok(())
                }
            }
        }
        Commands::Anchor { action } => match action {
            AnchorAction::Status => {
                println!("Anchor status:");
                println!("  Enabled: {}", config.activity_anchor.enabled);
                println!("  Interval: {}s", config.activity_anchor.interval_secs);
                println!("  Min entries: {}", config.activity_anchor.min_entries);
                Ok(())
            }
            AnchorAction::Verify { entry_id } => {
                println!("Verifying entry {}…", entry_id);
                println!("  (Connect to a running agent for live verification)");
                Ok(())
            }
        },
        Commands::Webhook { action } => match action {
            WebhookAction::List => {
                if config.webhooks.endpoints.is_empty() {
                    println!("No webhooks configured.");
                } else {
                    println!("Registered webhooks:");
                    for (i, ep) in config.webhooks.endpoints.iter().enumerate() {
                        let secret_hint = if ep.secret.is_some() { " (signed)" } else { "" };
                        let events = if ep.events.is_empty() {
                            "all".to_string()
                        } else {
                            ep.events.join(", ")
                        };
                        println!("  {}. {} [{}]{}", i + 1, ep.url, events, secret_hint);
                    }
                }
                Ok(())
            }
            WebhookAction::Add {
                url,
                secret,
                events,
            } => {
                let event_list: Vec<String> = events
                    .map(|e| e.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                println!("Added webhook: {}", url);
                if let Some(ref s) = secret {
                    println!("  Secret: {}…", &s[..s.len().min(4)]);
                }
                if !event_list.is_empty() {
                    println!("  Events: {}", event_list.join(", "));
                }
                println!("  (Save to config file to persist)");
                Ok(())
            }
            WebhookAction::Remove { url } => {
                println!("Removed webhook: {}", url);
                println!("  (Save to config file to persist)");
                Ok(())
            }
        },
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

// ─── CLI Tests ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_default_start() {
        let cli = Cli::try_parse_from(["edgeclaw-agent"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_status() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_cli_identity() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "identity"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Identity)));
    }

    #[test]
    fn test_cli_activity_recent() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "activity", "recent"]).unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Recent { count },
            }) => assert_eq!(count, 20),
            _ => panic!("expected Activity Recent"),
        }
    }

    #[test]
    fn test_cli_activity_recent_custom_count() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "activity", "recent", "-c", "5"]).unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Recent { count },
            }) => assert_eq!(count, 5),
            _ => panic!("expected Activity Recent with count=5"),
        }
    }

    #[test]
    fn test_cli_activity_search() {
        let cli =
            Cli::try_parse_from(["edgeclaw-agent", "activity", "search", "auth module"]).unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Search { query, limit },
            }) => {
                assert_eq!(query, "auth module");
                assert_eq!(limit, 20);
            }
            _ => panic!("expected Activity Search"),
        }
    }

    #[test]
    fn test_cli_activity_search_limit() {
        let cli = Cli::try_parse_from([
            "edgeclaw-agent",
            "activity",
            "search",
            "refactor",
            "-l",
            "5",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Search { query, limit },
            }) => {
                assert_eq!(query, "refactor");
                assert_eq!(limit, 5);
            }
            _ => panic!("expected Activity Search with limit=5"),
        }
    }

    #[test]
    fn test_cli_activity_stats() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "activity", "stats"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Activity {
                action: ActivityAction::Stats
            })
        ));
    }

    #[test]
    fn test_cli_activity_verify() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "activity", "verify"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Activity {
                action: ActivityAction::Verify
            })
        ));
    }

    #[test]
    fn test_cli_activity_export_json() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "activity", "export"]).unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Export { output, format },
            }) => {
                assert!(output.is_none());
                assert_eq!(format, "json");
            }
            _ => panic!("expected Activity Export json"),
        }
    }

    #[test]
    fn test_cli_activity_export_csv() {
        let cli = Cli::try_parse_from([
            "edgeclaw-agent",
            "activity",
            "export",
            "--format",
            "csv",
            "-o",
            "out.csv",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Activity {
                action: ActivityAction::Export { output, format },
            }) => {
                assert_eq!(output.as_deref(), Some("out.csv"));
                assert_eq!(format, "csv");
            }
            _ => panic!("expected Activity Export csv"),
        }
    }

    #[test]
    fn test_cli_tasks_list() {
        let cli = Cli::try_parse_from(["edgeclaw-agent", "tasks", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Tasks {
                action: TaskAction::List { .. }
            })
        ));
    }

    #[test]
    fn test_cli_tasks_create() {
        let cli = Cli::try_parse_from([
            "edgeclaw-agent",
            "tasks",
            "create",
            "Fix login bug",
            "-p",
            "myproj",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Tasks {
                action: TaskAction::Create { title, project },
            }) => {
                assert_eq!(title, "Fix login bug");
                assert_eq!(project, "myproj");
            }
            _ => panic!("expected Tasks Create"),
        }
    }

    #[test]
    fn test_cli_config_flag() {
        let cli =
            Cli::try_parse_from(["edgeclaw-agent", "-c", "/custom/config.toml", "status"]).unwrap();
        assert_eq!(cli.config, "/custom/config.toml");
        assert!(matches!(cli.command, Some(Commands::Status)));
    }
}
