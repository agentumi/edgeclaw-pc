pub mod activities;
pub mod agents;
pub mod auth;
pub mod chat;
pub mod config;
pub mod extensions;
pub mod fleet;
pub mod groups;
pub mod memory;
pub mod metrics;
pub mod registry;
pub mod status;
pub mod tasks;
pub mod templates;

use crate::AgentEngine;
use std::path::PathBuf;

/// Common helper to get avatar storage directory
pub fn avatar_storage_dir(engine: &AgentEngine) -> PathBuf {
    engine.config().storage_dir().join("avatars")
}
