//! Encrypted session management — ECDH key exchange + AES-256-GCM.
//!
//! Manages peer sessions derived from X25519 ECDH key agreement with
//! HKDF-SHA256 key derivation. Supports IP binding, key rotation,
//! and automatic expiry cleanup.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::AgentError;

/// Session information exposed to external callers
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub peer_id: String,
    pub state: String,
    pub created_at: String,
    pub expires_at: String,
    pub messages_sent: u64,
    pub messages_received: u64,
}

/// Internal session state
struct Session {
    session_key: [u8; 32],
    nonce_counter: u64,
    peer_id: String,
    bound_ip: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    messages_sent: u64,
    messages_received: u64,
}

/// Manages encrypted sessions with connected peers
pub struct SessionManager {
    sessions: std::collections::HashMap<String, Session>,
    session_duration_secs: i64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            session_duration_secs: 3600,
        }
    }

    /// Create a session via X25519 ECDH key exchange
    pub fn create_session(
        &mut self,
        peer_id: &str,
        local_secret: &[u8; 32],
        remote_public: &[u8; 32],
    ) -> Result<SessionInfo, AgentError> {
        self.create_session_with_ip(peer_id, local_secret, remote_public, None)
    }

    /// Create a session via X25519 ECDH key exchange, binding to an IP address
    pub fn create_session_with_ip(
        &mut self,
        peer_id: &str,
        local_secret: &[u8; 32],
        remote_public: &[u8; 32],
        bind_ip: Option<&str>,
    ) -> Result<SessionInfo, AgentError> {
        let secret = StaticSecret::from(*local_secret);
        let public = PublicKey::from(*remote_public);
        let shared_secret = secret.diffie_hellman(&public);

        // Derive session key via HKDF-SHA256
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ecnp-session-v2", &mut session_key)
            .map_err(|_| AgentError::CryptoError("HKDF expansion failed".into()))?;

        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::seconds(self.session_duration_secs);

        let info = SessionInfo {
            session_id: session_id.clone(),
            peer_id: peer_id.to_string(),
            state: "active".to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            messages_sent: 0,
            messages_received: 0,
        };

        self.sessions.insert(
            session_id,
            Session {
                session_key,
                nonce_counter: 0,
                peer_id: peer_id.to_string(),
                bound_ip: bind_ip.map(|ip| ip.to_string()),
                created_at: now,
                expires_at: expires,
                messages_sent: 0,
                messages_received: 0,
            },
        );

        Ok(info)
    }

    /// Encrypt a message in the given session
    pub fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, AgentError> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(AgentError::NotFound("session not found".into()))?;

        if chrono::Utc::now() > session.expires_at {
            return Err(AgentError::SessionExpired);
        }

        session.nonce_counter += 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&session.nonce_counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&session.session_key)
            .map_err(|_| AgentError::CryptoError("invalid key length".into()))?;

        let ciphertext = cipher.encrypt(nonce, plaintext)?;
        session.messages_sent += 1;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a message in the given session
    pub fn decrypt(&mut self, session_id: &str, data: &[u8]) -> Result<Vec<u8>, AgentError> {
        if data.len() < 12 {
            return Err(AgentError::CryptoError("data too short for nonce".into()));
        }

        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(AgentError::NotFound("session not found".into()))?;

        if chrono::Utc::now() > session.expires_at {
            return Err(AgentError::SessionExpired);
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let cipher = Aes256Gcm::new_from_slice(&session.session_key)
            .map_err(|_| AgentError::CryptoError("invalid key length".into()))?;

        let plaintext = cipher.decrypt(nonce, ciphertext)?;
        session.messages_received += 1;

        Ok(plaintext)
    }

    /// Get session info
    pub fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        self.sessions.get(session_id).map(|s| SessionInfo {
            session_id: session_id.to_string(),
            peer_id: s.peer_id.clone(),
            state: if chrono::Utc::now() > s.expires_at {
                "expired"
            } else {
                "active"
            }
            .to_string(),
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            messages_sent: s.messages_sent,
            messages_received: s.messages_received,
        })
    }

    /// List active session IDs
    pub fn active_sessions(&self) -> Vec<String> {
        let now = chrono::Utc::now();
        self.sessions
            .iter()
            .filter(|(_, s)| now < s.expires_at)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Close and remove a session
    pub fn close_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Remove all expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let now = chrono::Utc::now();
        let before = self.sessions.len();
        self.sessions.retain(|_, s| now < s.expires_at);
        before - self.sessions.len()
    }

    /// Verify that a session's bound IP matches the given IP.
    ///
    /// Returns `Ok(true)` if the IP matches or no IP is bound.
    /// Returns `Err` if the IP does not match.
    pub fn verify_session_ip(&self, session_id: &str, client_ip: &str) -> Result<bool, AgentError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or(AgentError::NotFound("session not found".into()))?;

        if let Some(ref bound) = session.bound_ip {
            if bound != client_ip {
                return Err(AgentError::AuthenticationError(format!(
                    "session bound to {}, request from {}",
                    bound, client_ip
                )));
            }
        }
        Ok(true)
    }

    /// Check if a session needs key rotation (within 10% of expiry)
    pub fn needs_rotation(&self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            let now = chrono::Utc::now();
            if now >= session.expires_at {
                return true;
            }
            let total_duration = session.expires_at - session.created_at;
            let remaining = session.expires_at - now;
            // Rotate when less than 10% of session time remains
            remaining < total_duration / 10
        } else {
            false
        }
    }

    /// Rotate a session key by performing a new ECDH exchange.
    ///
    /// Creates a new session with the same peer and IP binding,
    /// then closes the old session. Returns the new session info.
    pub fn rotate_session(
        &mut self,
        old_session_id: &str,
        local_secret: &[u8; 32],
        remote_public: &[u8; 32],
    ) -> Result<SessionInfo, AgentError> {
        let (peer_id, bound_ip) = {
            let old = self
                .sessions
                .get(old_session_id)
                .ok_or(AgentError::NotFound("session not found".into()))?;
            (old.peer_id.clone(), old.bound_ip.clone())
        };

        let new_info = self.create_session_with_ip(
            &peer_id,
            local_secret,
            remote_public,
            bound_ip.as_deref(),
        )?;

        // Close old session after new one is established
        self.close_session(old_session_id);

        Ok(new_info)
    }

    /// Get all sessions that need rotation
    pub fn sessions_needing_rotation(&self) -> Vec<String> {
        self.sessions
            .keys()
            .filter(|id| self.needs_rotation(id))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session() -> (SessionManager, String) {
        let mut mgr = SessionManager::new();
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let _public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let info = mgr
            .create_session("peer-1", &secret_a.to_bytes(), public_b.as_bytes())
            .unwrap();
        (mgr, info.session_id)
    }

    #[test]
    fn test_session_creation() {
        let (mgr, session_id) = create_test_session();
        let info = mgr.get_session(&session_id).unwrap();
        assert_eq!(info.state, "active");
        assert_eq!(info.peer_id, "peer-1");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let mut mgr_a = SessionManager::new();
        let mut mgr_b = SessionManager::new();

        let info_a = mgr_a
            .create_session("peer-b", &secret_a.to_bytes(), public_b.as_bytes())
            .unwrap();
        let info_b = mgr_b
            .create_session("peer-a", &secret_b.to_bytes(), public_a.as_bytes())
            .unwrap();

        let plaintext = b"hello from agent";
        let encrypted = mgr_a.encrypt(&info_a.session_id, plaintext).unwrap();
        let decrypted = mgr_b.decrypt(&info_b.session_id, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_close_session() {
        let (mut mgr, session_id) = create_test_session();
        assert!(mgr.close_session(&session_id));
        assert!(mgr.get_session(&session_id).is_none());
    }

    #[test]
    fn test_active_sessions() {
        let (mgr, session_id) = create_test_session();
        let active = mgr.active_sessions();
        assert!(active.contains(&session_id));
    }

    #[test]
    fn test_session_ip_binding() {
        let mut mgr = SessionManager::new();
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let info = mgr
            .create_session_with_ip(
                "peer-1",
                &secret_a.to_bytes(),
                public_b.as_bytes(),
                Some("192.168.1.10"),
            )
            .unwrap();

        // Same IP → ok
        assert!(mgr
            .verify_session_ip(&info.session_id, "192.168.1.10")
            .is_ok());

        // Different IP → error
        assert!(mgr.verify_session_ip(&info.session_id, "10.0.0.1").is_err());
    }

    #[test]
    fn test_session_no_ip_binding() {
        let (mgr, session_id) = create_test_session();
        // No IP bound → any IP is ok
        assert!(mgr.verify_session_ip(&session_id, "1.2.3.4").is_ok());
    }

    #[test]
    fn test_needs_rotation_fresh_session() {
        let (mgr, session_id) = create_test_session();
        // Fresh session should not need rotation
        assert!(!mgr.needs_rotation(&session_id));
    }

    #[test]
    fn test_rotate_session() {
        let mut mgr = SessionManager::new();
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_b = x25519_dalek::PublicKey::from(&secret_b);

        let old_info = mgr
            .create_session("peer-1", &secret_a.to_bytes(), public_b.as_bytes())
            .unwrap();

        // Generate new keys for rotation
        let secret_c = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let secret_d = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_d = x25519_dalek::PublicKey::from(&secret_d);

        let new_info = mgr
            .rotate_session(
                &old_info.session_id,
                &secret_c.to_bytes(),
                public_d.as_bytes(),
            )
            .unwrap();

        // Old session is gone
        assert!(mgr.get_session(&old_info.session_id).is_none());
        // New session exists
        assert!(mgr.get_session(&new_info.session_id).is_some());
        assert_eq!(new_info.peer_id, "peer-1");
    }

    #[test]
    fn test_sessions_needing_rotation_empty() {
        let (mgr, _) = create_test_session();
        let needing = mgr.sessions_needing_rotation();
        assert!(needing.is_empty());
    }
}
