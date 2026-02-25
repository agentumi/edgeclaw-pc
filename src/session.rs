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
}
