#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard: need at least 32 (key) + 12 (nonce) + 1 (data) bytes
    if data.len() < 45 {
        return;
    }
    let key_bytes: [u8; 32] = data[..32].try_into().unwrap();
    let nonce_bytes: [u8; 12] = data[32..44].try_into().unwrap();
    let plaintext = &data[44..];

    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt must not panic
    if let Ok(ciphertext) = cipher.encrypt(nonce, plaintext) {
        // Decrypt must not panic
        let _ = cipher.decrypt(nonce, ciphertext.as_ref());
    }
});
