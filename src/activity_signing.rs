//! Ed25519 digital signatures for activity entries.
//!
//! Adds per-entry Ed25519 signatures to the activity log, providing
//! cryptographic proof of authorship in addition to hash-chain integrity.
//! Compatible with the existing [`crate::identity::IdentityManager`].

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::activity_log::ActivityEntry;

/// Sign an activity entry using a device Ed25519 signing key.
///
/// Produces a hex-encoded Ed25519 signature over the entry's canonical hash.
pub fn sign_entry(entry: &ActivityEntry, signing_key: &SigningKey) -> String {
    let hash_bytes = compute_signable_hash(entry);
    let signature = signing_key.sign(&hash_bytes);
    hex::encode(signature.to_bytes())
}

/// Verify an entry's Ed25519 signature using the corresponding verifying key.
///
/// Returns `true` if the signature is valid, `false` if invalid or missing.
pub fn verify_entry_signature(
    entry: &ActivityEntry,
    signature_hex: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    if signature_hex.is_empty() {
        return false;
    }

    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let hash_bytes = compute_signable_hash(entry);
    verifying_key.verify(&hash_bytes, &signature).is_ok()
}

/// Batch-verify all entry signatures in a log.
///
/// Returns a list of entry IDs with invalid signatures.
/// Entries with no signature (empty string) are skipped.
pub fn verify_signatures(
    entries: &[(ActivityEntry, String)],
    verifying_key: &VerifyingKey,
) -> Vec<Uuid> {
    let mut invalid = Vec::new();
    for (entry, signature) in entries {
        // Skip unsigned entries (migration compatibility)
        if signature.is_empty() {
            continue;
        }
        if !verify_entry_signature(entry, signature, verifying_key) {
            invalid.push(entry.id);
        }
    }
    if invalid.is_empty() {
        info!(count = entries.len(), "All entry signatures verified");
    } else {
        warn!(
            invalid_count = invalid.len(),
            total = entries.len(),
            "Some entry signatures failed verification"
        );
    }
    invalid
}

/// Compute the canonical hash of an entry for signing purposes.
///
/// This deterministically combines the entry fields into a SHA-256 hash
/// that serves as the message for Ed25519 signing.
fn compute_signable_hash(entry: &ActivityEntry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(entry.id.as_bytes());
    hasher.update(entry.session_id.as_bytes());
    hasher.update(entry.agent_id.as_bytes());
    hasher.update(entry.content.as_bytes());
    hasher.update(entry.importance.to_le_bytes());
    hasher.update(entry.timestamp.to_rfc3339().as_bytes());
    hasher.update(entry.lamport_clock.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.activity_type.type_tag().as_bytes());
    hasher.update(entry.hash.as_bytes());
    hasher.finalize().to_vec()
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::ActivityType;
    use chrono::Utc;
    use rand::rngs::OsRng;

    fn sample_entry() -> ActivityEntry {
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "agent-1".into(),
            activity_type: ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: Some("new code".into()),
                lines_changed: 3,
            },
            project: "edgeclaw".into(),
            file_path: Some("src/lib.rs".into()),
            content: "Refactored session module".into(),
            tags: vec!["rust".into(), "refactor".into()],
            importance: 2,
            timestamp: Utc::now(),
            lamport_clock: 10,
            prev_hash: "0".repeat(64),
            hash: "abc123".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn test_sign_and_verify_success() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let entry = sample_entry();

        let signature = sign_entry(&entry, &signing_key);
        assert!(!signature.is_empty());
        assert!(verify_entry_signature(&entry, &signature, &verifying_key));
    }

    #[test]
    fn test_tampered_entry_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let entry = sample_entry();

        let signature = sign_entry(&entry, &signing_key);

        // Tamper with the entry
        let mut tampered = entry.clone();
        tampered.content = "TAMPERED content".into();

        assert!(!verify_entry_signature(
            &tampered,
            &signature,
            &verifying_key
        ));
    }

    #[test]
    fn test_unsigned_entry_returns_false() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let entry = sample_entry();

        assert!(!verify_entry_signature(&entry, "", &verifying_key));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let other_verifying = other_key.verifying_key();
        let entry = sample_entry();

        let signature = sign_entry(&entry, &signing_key);
        assert!(!verify_entry_signature(
            &entry,
            &signature,
            &other_verifying
        ));
    }

    #[test]
    fn test_record_without_key_produces_no_signature() {
        // When no signing key is available, entries have no signature
        let entry = sample_entry();
        // Verify that an empty signature is handled gracefully
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        assert!(!verify_entry_signature(&entry, "", &verifying_key));
    }

    #[test]
    fn test_batch_verify_mixed_signed_unsigned() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let e1 = sample_entry();
        let sig1 = sign_entry(&e1, &signing_key);

        let e2 = sample_entry();
        let sig2 = String::new(); // unsigned

        let e3 = sample_entry();
        let sig3 = sign_entry(&e3, &signing_key);

        let entries = vec![(e1, sig1), (e2, sig2), (e3, sig3)];

        let invalid = verify_signatures(&entries, &verifying_key);
        assert!(invalid.is_empty()); // unsigned are skipped, signed are valid
    }

    #[test]
    fn test_batch_verify_detects_invalid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let e1 = sample_entry();
        let sig1 = sign_entry(&e1, &signing_key);

        let e2 = sample_entry();
        let sig2 = "deadbeef".repeat(8); // invalid signature

        let entries = vec![(e1, sig1), (e2.clone(), sig2)];

        let invalid = verify_signatures(&entries, &verifying_key);
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0], e2.id);
    }

    #[test]
    fn test_invalid_hex_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let entry = sample_entry();

        assert!(!verify_entry_signature(&entry, "not_hex!!", &verifying_key));
    }
}
