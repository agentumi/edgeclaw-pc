//! Agent registry — persistent agent tracking and status management.
//!
//! Maintains a registry of known agents with status tracking,
//! heartbeat timeout detection, and file-based persistence to
//! `$APPDATA/edgeclaw/agents.json`.

use crate::error::AgentError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Agent status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Online,
    Busy,
    Offline,
    Error,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Busy => write!(f, "busy"),
            Self::Offline => write!(f, "offline"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Complete information about a registered agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub profile: String,
    pub address: String,
    pub port: u16,
    pub status: AgentStatus,
    pub capabilities: Vec<String>,
    pub version: String,
    pub last_heartbeat: DateTime<Utc>,
    pub registered_at: DateTime<Utc>,
}

/// Timeout before marking an agent as Offline (seconds)
const HEARTBEAT_TIMEOUT_SECS: i64 = 60;

/// Agent registry with file persistence
pub struct AgentRegistry {
    agents: Arc<Mutex<HashMap<String, AgentInfo>>>,
    persist_path: PathBuf,
}

impl AgentRegistry {
    /// Create a new registry, loading from disk if available
    pub fn new() -> Self {
        let persist_path = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("edgeclaw")
            .join("agents.json");

        let mut registry = Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            persist_path,
        };

        if let Err(e) = registry.load() {
            warn!(error = %e, "failed to load agent registry, starting fresh");
        }

        registry
    }

    /// Create with a custom persistence path (for testing)
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            persist_path: path,
        }
    }

    /// Register a new agent or update an existing one
    pub fn register(&self, info: AgentInfo) -> Result<(), AgentError> {
        let id = info.id.clone();
        if let Ok(mut agents) = self.agents.lock() {
            agents.insert(id.clone(), info);
            info!(agent_id = %id, "agent registered");
            drop(agents);
            let _ = self.save();
            Ok(())
        } else {
            Err(AgentError::InternalError("registry lock poisoned".into()))
        }
    }

    /// Update agent status
    pub fn update_status(&self, agent_id: &str, status: AgentStatus) -> Result<(), AgentError> {
        if let Ok(mut agents) = self.agents.lock() {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.status = status;
                agent.last_heartbeat = Utc::now();
                drop(agents);
                let _ = self.save();
                Ok(())
            } else {
                Err(AgentError::NotFound(format!("agent {agent_id}")))
            }
        } else {
            Err(AgentError::InternalError("registry lock poisoned".into()))
        }
    }

    /// Record a heartbeat for an agent
    pub fn heartbeat(&self, agent_id: &str) -> Result<(), AgentError> {
        if let Ok(mut agents) = self.agents.lock() {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.last_heartbeat = Utc::now();
                if agent.status == AgentStatus::Offline {
                    agent.status = AgentStatus::Online;
                }
                Ok(())
            } else {
                Err(AgentError::NotFound(format!("agent {agent_id}")))
            }
        } else {
            Err(AgentError::InternalError("registry lock poisoned".into()))
        }
    }

    /// Remove an agent from the registry
    pub fn remove(&self, agent_id: &str) -> bool {
        let removed = self
            .agents
            .lock()
            .map(|mut a| a.remove(agent_id).is_some())
            .unwrap_or(false);
        if removed {
            let _ = self.save();
            info!(agent_id = %agent_id, "agent removed");
        }
        removed
    }

    /// Get agent info
    pub fn get(&self, agent_id: &str) -> Option<AgentInfo> {
        self.agents
            .lock()
            .ok()
            .and_then(|a| a.get(agent_id).cloned())
    }

    /// List all agents
    pub fn list_all(&self) -> Vec<AgentInfo> {
        self.agents
            .lock()
            .map(|a| a.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List only online agents
    pub fn list_online(&self) -> Vec<AgentInfo> {
        self.agents
            .lock()
            .map(|a| {
                a.values()
                    .filter(|info| info.status == AgentStatus::Online)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Count online agents
    pub fn count_online(&self) -> usize {
        self.list_online().len()
    }

    /// Check heartbeat timeouts and mark timed-out agents as Offline
    pub fn check_timeouts(&self) -> Vec<String> {
        let now = Utc::now();
        let mut timed_out = Vec::new();

        if let Ok(mut agents) = self.agents.lock() {
            for (id, agent) in agents.iter_mut() {
                if agent.status == AgentStatus::Online || agent.status == AgentStatus::Busy {
                    let elapsed = now - agent.last_heartbeat;
                    if elapsed.num_seconds() > HEARTBEAT_TIMEOUT_SECS {
                        agent.status = AgentStatus::Offline;
                        timed_out.push(id.clone());
                        warn!(agent_id = %id, "agent timed out");
                    }
                }
            }
        }

        if !timed_out.is_empty() {
            let _ = self.save();
        }

        timed_out
    }

    /// Persist registry to disk
    pub fn save(&self) -> Result<(), AgentError> {
        if let Some(parent) = self.persist_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let agents = self
            .agents
            .lock()
            .map_err(|_| AgentError::InternalError("lock poisoned".into()))?;
        let json = serde_json::to_string_pretty(&*agents)?;
        std::fs::write(&self.persist_path, json)?;
        Ok(())
    }

    /// Load registry from disk
    pub fn load(&mut self) -> Result<(), AgentError> {
        if !self.persist_path.exists() {
            return Ok(());
        }
        let data = std::fs::read_to_string(&self.persist_path)?;
        let agents: HashMap<String, AgentInfo> = serde_json::from_str(&data)?;
        if let Ok(mut a) = self.agents.lock() {
            *a = agents;
        }
        info!(path = %self.persist_path.display(), "loaded agent registry");
        Ok(())
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent(id: &str) -> AgentInfo {
        AgentInfo {
            id: id.to_string(),
            name: format!("Agent {id}"),
            profile: "System".to_string(),
            address: "127.0.0.1".to_string(),
            port: 9443,
            status: AgentStatus::Online,
            capabilities: vec!["status_query".to_string()],
            version: "1.0.0".to_string(),
            last_heartbeat: Utc::now(),
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn test_register_and_get() {
        let tmp = std::env::temp_dir().join("ectest_registry1.json");
        let registry = AgentRegistry::with_path(tmp.clone());
        registry.register(test_agent("a1")).unwrap();

        let info = registry.get("a1").unwrap();
        assert_eq!(info.name, "Agent a1");
        assert_eq!(info.status, AgentStatus::Online);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_list_all_and_online() {
        let tmp = std::env::temp_dir().join("ectest_registry2.json");
        let registry = AgentRegistry::with_path(tmp.clone());
        registry.register(test_agent("a1")).unwrap();

        let mut offline = test_agent("a2");
        offline.status = AgentStatus::Offline;
        registry.register(offline).unwrap();

        assert_eq!(registry.list_all().len(), 2);
        assert_eq!(registry.list_online().len(), 1);
        assert_eq!(registry.count_online(), 1);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_update_status() {
        let tmp = std::env::temp_dir().join("ectest_registry3.json");
        let registry = AgentRegistry::with_path(tmp.clone());
        registry.register(test_agent("a1")).unwrap();

        registry.update_status("a1", AgentStatus::Busy).unwrap();
        let info = registry.get("a1").unwrap();
        assert_eq!(info.status, AgentStatus::Busy);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_remove() {
        let tmp = std::env::temp_dir().join("ectest_registry4.json");
        let registry = AgentRegistry::with_path(tmp.clone());
        registry.register(test_agent("a1")).unwrap();
        assert!(registry.remove("a1"));
        assert!(registry.get("a1").is_none());
        assert!(!registry.remove("a1"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_heartbeat() {
        let tmp = std::env::temp_dir().join("ectest_registry5.json");
        let registry = AgentRegistry::with_path(tmp.clone());

        let mut agent = test_agent("a1");
        agent.status = AgentStatus::Offline;
        registry.register(agent).unwrap();

        // Heartbeat should bring agent back online
        registry.heartbeat("a1").unwrap();
        let info = registry.get("a1").unwrap();
        assert_eq!(info.status, AgentStatus::Online);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_heartbeat_timeout() {
        let tmp = std::env::temp_dir().join("ectest_registry6.json");
        let registry = AgentRegistry::with_path(tmp.clone());

        let mut agent = test_agent("a1");
        // Set last heartbeat to 120 seconds ago
        agent.last_heartbeat = Utc::now() - chrono::Duration::seconds(120);
        registry.register(agent).unwrap();

        let timed_out = registry.check_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], "a1");

        let info = registry.get("a1").unwrap();
        assert_eq!(info.status, AgentStatus::Offline);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_persistence() {
        let tmp = std::env::temp_dir().join("ectest_registry7.json");
        let _ = std::fs::remove_file(&tmp);

        // Save
        {
            let registry = AgentRegistry::with_path(tmp.clone());
            registry.register(test_agent("a1")).unwrap();
        }

        // Load
        {
            let _registry = AgentRegistry::with_path(tmp.clone());
            // Load happens in constructor-like manual load
            let data = std::fs::read_to_string(&tmp).unwrap();
            let agents: HashMap<String, AgentInfo> = serde_json::from_str(&data).unwrap();
            assert!(agents.contains_key("a1"));
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_agent_status_display() {
        assert_eq!(AgentStatus::Online.to_string(), "online");
        assert_eq!(AgentStatus::Busy.to_string(), "busy");
        assert_eq!(AgentStatus::Offline.to_string(), "offline");
        assert_eq!(AgentStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_agent_info_serialize() {
        let agent = test_agent("a1");
        let json = serde_json::to_string(&agent).unwrap();
        assert!(json.contains("\"id\":\"a1\""));
        assert!(json.contains("\"online\""));

        let deserialized: AgentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "a1");
    }

    #[test]
    fn test_update_status_not_found() {
        let tmp = std::env::temp_dir().join(format!(
            "ectest_reg_notfound1_{}.json",
            uuid::Uuid::new_v4()
        ));
        let registry = AgentRegistry::with_path(tmp.clone());
        let result = registry.update_status("nonexistent", AgentStatus::Busy);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("nonexistent"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_heartbeat_not_found() {
        let tmp = std::env::temp_dir().join(format!(
            "ectest_reg_notfound2_{}.json",
            uuid::Uuid::new_v4()
        ));
        let registry = AgentRegistry::with_path(tmp.clone());
        let result = registry.heartbeat("nonexistent");
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("nonexistent"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_registry_save_and_load_explicit() {
        let tmp =
            std::env::temp_dir().join(format!("ectest_reg_saveload_{}.json", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_file(&tmp);
        let registry = AgentRegistry::with_path(tmp.clone());
        registry.register(test_agent("save1")).unwrap();
        registry.register(test_agent("save2")).unwrap();
        registry.save().unwrap();

        // Create new registry and load from same path
        let mut registry2 = AgentRegistry::with_path(tmp.clone());
        registry2.load().unwrap();
        assert_eq!(registry2.list_all().len(), 2);
        assert!(registry2.get("save1").is_some());
        assert!(registry2.get("save2").is_some());
        let _ = std::fs::remove_file(&tmp);
    }
}
