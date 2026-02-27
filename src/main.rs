use clap::{Parser, Subcommand};
use edgeclaw_agent::config::AgentConfig;
use edgeclaw_agent::AgentEngine;
use std::path::PathBuf;
use tracing::{error, info};

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
            println!("EdgeClaw Agent v1.0.0");
            println!("Status: running");
            println!("Config: {}", config_path.display());
            println!("Port:   {}", config.agent.listen_port);
            println!("Mode:   {}", config.security.policy_mode);
            println!("AI:     {}", config.ai.primary);
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

                match engine.chat("console", input) {
                    Ok(resp) => {
                        println!("Agent: {}", resp.message);
                        if let Some(intent) = &resp.intent {
                            println!("  → [{}] {}", intent.capability, intent.command);
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
        Commands::Start => {
            info!(
                version = "1.0.0",
                port = config.agent.listen_port,
                "EdgeClaw Agent starting"
            );

            let engine = AgentEngine::new(config);

            // Generate identity on first run
            let identity = engine.generate_identity()?;
            info!(
                device_id = %identity.device_id,
                fingerprint = %identity.fingerprint,
                platform = %identity.platform,
                "Device identity generated"
            );

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
            println!("╚══════════════════════════════════════════╝");

            // Start TCP server
            let bind_addr = format!("0.0.0.0:{}", engine.config().agent.listen_port);
            let (msg_tx, mut msg_rx) =
                tokio::sync::mpsc::channel::<edgeclaw_agent::server::IncomingMessage>(256);

            let mut tcp_server =
                edgeclaw_agent::server::TcpServer::new(edgeclaw_agent::server::TcpServerConfig {
                    bind_addr,
                    max_connections: engine.config().agent.max_connections,
                });

            // Message handler task
            tokio::spawn(async move {
                while let Some(msg) = msg_rx.recv().await {
                    info!(
                        peer = %msg.peer_addr,
                        msg_type = msg.message.msg_type,
                        payload_len = msg.message.payload.len(),
                        "received ECNP message"
                    );
                }
            });

            // Run server until shutdown
            if let Err(e) = tcp_server.start(msg_tx).await {
                error!(error = %e, "TCP server error");
            }

            info!("EdgeClaw Agent stopped");
            Ok(())
        }
    }
}
