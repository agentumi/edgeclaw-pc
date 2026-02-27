//! Agent discovery — mDNS service registration and LAN scanning.
//!
//! Provides [`DiscoveryService`] for automatic agent discovery using
//! mDNS-SD (`_edgeclaw._tcp.local.`) and fallback TCP port scanning
//! for environments where mDNS is unavailable.

use crate::error::AgentError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tracing::info;

/// Service type for mDNS registration
const SERVICE_TYPE: &str = "_edgeclaw._tcp.local.";

/// Federated service type for cross-org mDNS discovery
const FEDERATION_SERVICE_TYPE: &str = "_edgeclaw-fed._tcp.local.";

/// Default port range for TCP fallback scan
const DEFAULT_PORT_START: u16 = 9443;
const DEFAULT_PORT_END: u16 = 9453;

/// Information about a discovered agent
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredAgent {
    /// Agent name (hostname or custom)
    pub name: String,
    /// IP address
    pub address: String,
    /// ECNP listen port
    pub port: u16,
    /// Agent profile (e.g., "System", "SoftwareDev")
    pub profile: String,
    /// Agent version
    pub version: String,
    /// When this agent was last seen
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Agent discovery service using mDNS and TCP scanning
pub struct DiscoveryService {
    /// Currently discovered agents
    agents: Arc<Mutex<HashMap<String, DiscoveredAgent>>>,
    /// Our agent's name for registration
    agent_name: String,
    /// Our ECNP listen port
    listen_port: u16,
    /// Our profile
    profile: String,
    /// Our version
    version: String,
    /// Whether the service is active
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl DiscoveryService {
    /// Create a new discovery service
    pub fn new(agent_name: &str, listen_port: u16, profile: &str, version: &str) -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            agent_name: agent_name.to_string(),
            listen_port,
            profile: profile.to_string(),
            version: version.to_string(),
            active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Register this agent via mDNS-SD
    pub fn register(&self) -> Result<(), AgentError> {
        info!(
            name = %self.agent_name,
            port = self.listen_port,
            "registering agent via mDNS"
        );

        let mdns = mdns_sd::ServiceDaemon::new()
            .map_err(|e| AgentError::ConnectionError(format!("mDNS daemon error: {e}")))?;

        let mut properties = HashMap::new();
        properties.insert("profile".to_string(), self.profile.clone());
        properties.insert("version".to_string(), self.version.clone());

        let service_info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE,
            &self.agent_name,
            &format!("{}.local.", self.agent_name),
            "",
            self.listen_port,
            properties,
        )
        .map_err(|e| AgentError::ConnectionError(format!("mDNS service info error: {e}")))?;

        mdns.register(service_info)
            .map_err(|e| AgentError::ConnectionError(format!("mDNS register error: {e}")))?;

        self.active.store(true, std::sync::atomic::Ordering::SeqCst);
        info!("mDNS registration complete");
        Ok(())
    }

    /// Discover agents via mDNS browse (non-blocking, returns current snapshot)
    pub fn discover_mdns(&self) -> Result<Vec<DiscoveredAgent>, AgentError> {
        let mdns = mdns_sd::ServiceDaemon::new()
            .map_err(|e| AgentError::ConnectionError(format!("mDNS daemon error: {e}")))?;

        let receiver = mdns
            .browse(SERVICE_TYPE)
            .map_err(|e| AgentError::ConnectionError(format!("mDNS browse error: {e}")))?;

        let mut found = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

        while std::time::Instant::now() < deadline {
            match receiver.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    let name = info.get_fullname().to_string();
                    let port = info.get_port();
                    let addresses = info.get_addresses();
                    let address = addresses
                        .iter()
                        .next()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    let properties = info.get_properties();
                    let profile = properties
                        .get_property_val_str("profile")
                        .unwrap_or("unknown")
                        .to_string();
                    let version = properties
                        .get_property_val_str("version")
                        .unwrap_or("0.0.0")
                        .to_string();

                    let agent = DiscoveredAgent {
                        name,
                        address,
                        port,
                        profile,
                        version,
                        last_seen: chrono::Utc::now(),
                    };

                    found.push(agent);
                }
                Ok(_) => {} // Other events (searching, removed, etc.)
                Err(e) => {
                    // Check if this is a timeout (continue) or real error (break)
                    let msg = format!("{e}");
                    if msg.contains("timed out") || msg.contains("Timeout") {
                        continue;
                    }
                    break;
                }
            }
        }

        let _ = mdns.stop_browse(SERVICE_TYPE);

        // Cache discovered agents
        if let Ok(mut agents) = self.agents.lock() {
            for agent in &found {
                agents.insert(agent.name.clone(), agent.clone());
            }
        }

        Ok(found)
    }

    /// Fallback: scan TCP ports on local network for EdgeClaw agents
    pub async fn scan_lan(&self, subnet: &str) -> Vec<DiscoveredAgent> {
        let mut found = Vec::new();

        // Parse subnet like "192.168.1" and scan .1-.254
        for host in 1..=254u8 {
            let ip = format!("{subnet}.{host}");
            for port in DEFAULT_PORT_START..=DEFAULT_PORT_END {
                let addr: SocketAddr = match format!("{ip}:{port}").parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                // Quick TCP connect probe with 200ms timeout
                if let Ok(Ok(_stream)) = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    info!(addr = %addr, "found agent via TCP scan");
                    found.push(DiscoveredAgent {
                        name: format!("agent-{ip}"),
                        address: ip.clone(),
                        port,
                        profile: "unknown".to_string(),
                        version: "unknown".to_string(),
                        last_seen: chrono::Utc::now(),
                    });
                }
            }
        }

        // Cache results
        if let Ok(mut agents) = self.agents.lock() {
            for agent in &found {
                agents.insert(agent.name.clone(), agent.clone());
            }
        }

        found
    }

    /// Register this agent in the federation mDNS namespace for cross-org discovery.
    pub fn register_federation(&self, org_id: &str) -> Result<(), AgentError> {
        info!(
            name = %self.agent_name,
            org_id = %org_id,
            "registering agent in federation namespace"
        );

        let mdns = mdns_sd::ServiceDaemon::new()
            .map_err(|e| AgentError::ConnectionError(format!("mDNS daemon error: {e}")))?;

        let mut properties = HashMap::new();
        properties.insert("profile".to_string(), self.profile.clone());
        properties.insert("version".to_string(), self.version.clone());
        properties.insert("org_id".to_string(), org_id.to_string());

        let service_info = mdns_sd::ServiceInfo::new(
            FEDERATION_SERVICE_TYPE,
            &self.agent_name,
            &format!("{}.local.", self.agent_name),
            "",
            self.listen_port,
            properties,
        )
        .map_err(|e| AgentError::ConnectionError(format!("mDNS service info error: {e}")))?;

        mdns.register(service_info)
            .map_err(|e| AgentError::ConnectionError(format!("mDNS register error: {e}")))?;

        info!("federation mDNS registration complete");
        Ok(())
    }

    /// Discover federated agents from other organizations via mDNS.
    pub fn discover_federations(&self) -> Result<Vec<DiscoveredAgent>, AgentError> {
        let mdns = mdns_sd::ServiceDaemon::new()
            .map_err(|e| AgentError::ConnectionError(format!("mDNS daemon error: {e}")))?;

        let receiver = mdns.browse(FEDERATION_SERVICE_TYPE).map_err(|e| {
            AgentError::ConnectionError(format!("mDNS browse federation error: {e}"))
        })?;

        let mut found = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

        while std::time::Instant::now() < deadline {
            match receiver.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    let name = info.get_fullname().to_string();
                    let port = info.get_port();
                    let addresses = info.get_addresses();
                    let address = addresses
                        .iter()
                        .next()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    let properties = info.get_properties();
                    let profile = properties
                        .get_property_val_str("profile")
                        .unwrap_or("unknown")
                        .to_string();
                    let version = properties
                        .get_property_val_str("version")
                        .unwrap_or("0.0.0")
                        .to_string();

                    let agent = DiscoveredAgent {
                        name,
                        address,
                        port,
                        profile,
                        version,
                        last_seen: chrono::Utc::now(),
                    };
                    found.push(agent);
                }
                Ok(_) => {}
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("timed out") || msg.contains("Timeout") {
                        continue;
                    }
                    break;
                }
            }
        }

        let _ = mdns.stop_browse(FEDERATION_SERVICE_TYPE);

        // Cache with a "fed:" prefix
        if let Ok(mut agents) = self.agents.lock() {
            for agent in &found {
                agents.insert(format!("fed:{}", agent.name), agent.clone());
            }
        }

        Ok(found)
    }

    /// Get cached discovered agents
    pub fn cached_agents(&self) -> Vec<DiscoveredAgent> {
        self.agents
            .lock()
            .map(|a| a.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove a cached agent
    pub fn remove_cached(&self, name: &str) -> bool {
        self.agents
            .lock()
            .map(|mut a| a.remove(name).is_some())
            .unwrap_or(false)
    }

    /// Whether the discovery service is actively registered
    pub fn is_active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Unregister — just marks inactive (mDNS daemon handles cleanup on drop)
    pub fn unregister(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        info!("mDNS registration removed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_service_creation() {
        let svc = DiscoveryService::new("test-agent", 9443, "System", "1.0.0");
        assert_eq!(svc.agent_name, "test-agent");
        assert_eq!(svc.listen_port, 9443);
        assert!(!svc.is_active());
    }

    #[test]
    fn test_cached_agents_empty() {
        let svc = DiscoveryService::new("test", 9443, "System", "1.0.0");
        assert!(svc.cached_agents().is_empty());
    }

    #[test]
    fn test_discovered_agent_serialize() {
        let agent = DiscoveredAgent {
            name: "agent-1".to_string(),
            address: "192.168.1.10".to_string(),
            port: 9443,
            profile: "System".to_string(),
            version: "1.0.0".to_string(),
            last_seen: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&agent).unwrap();
        assert!(json.contains("agent-1"));
        assert!(json.contains("192.168.1.10"));
    }

    #[test]
    fn test_cache_and_remove() {
        let svc = DiscoveryService::new("test", 9443, "System", "1.0.0");
        {
            let mut agents = svc.agents.lock().unwrap();
            agents.insert(
                "agent-1".to_string(),
                DiscoveredAgent {
                    name: "agent-1".to_string(),
                    address: "10.0.0.1".to_string(),
                    port: 9443,
                    profile: "System".to_string(),
                    version: "1.0.0".to_string(),
                    last_seen: chrono::Utc::now(),
                },
            );
        }
        assert_eq!(svc.cached_agents().len(), 1);
        assert!(svc.remove_cached("agent-1"));
        assert!(svc.cached_agents().is_empty());
    }

    #[test]
    fn test_unregister() {
        let svc = DiscoveryService::new("test", 9443, "System", "1.0.0");
        svc.active.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(svc.is_active());
        svc.unregister();
        assert!(!svc.is_active());
    }

    #[test]
    fn test_service_type_constant() {
        assert_eq!(SERVICE_TYPE, "_edgeclaw._tcp.local.");
    }

    #[test]
    fn test_federation_service_type() {
        assert_eq!(FEDERATION_SERVICE_TYPE, "_edgeclaw-fed._tcp.local.");
        assert_ne!(SERVICE_TYPE, FEDERATION_SERVICE_TYPE);
    }

    #[test]
    fn test_port_range() {
        assert_eq!(DEFAULT_PORT_START, 9443);
        assert_eq!(DEFAULT_PORT_END, 9453);
        const { assert!(DEFAULT_PORT_END > DEFAULT_PORT_START) };
    }
}
