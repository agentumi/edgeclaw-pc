//! ECNP v1.1 protocol codec for WebAssembly.
//!
//! Provides JavaScript-callable functions for encoding and decoding
//! EdgeClaw Network Protocol binary frames in the browser or Node.js.

use wasm_bindgen::prelude::*;

const ECNP_VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 6;
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// ECNP message types.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 0x01,
    Data = 0x02,
    Control = 0x03,
    Heartbeat = 0x04,
    Error = 0x05,
    Auth = 0x06,
    Telemetry = 0x07,
    PolicyUpdate = 0x08,
}

/// Decoded ECNP frame.
#[wasm_bindgen]
pub struct EcnpFrame {
    msg_type: u8,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl EcnpFrame {
    /// Get the message type byte.
    #[wasm_bindgen(getter)]
    pub fn msg_type(&self) -> u8 {
        self.msg_type
    }

    /// Get the payload as a byte array.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// Get the payload as a UTF-8 string (returns empty if invalid UTF-8).
    #[wasm_bindgen(js_name = "payloadString")]
    pub fn payload_string(&self) -> String {
        String::from_utf8(self.payload.clone()).unwrap_or_default()
    }
}

/// Encode a payload into an ECNP v1.1 binary frame.
///
/// @param msg_type - Message type (0x01-0x08)
/// @param payload  - Raw payload bytes
/// @returns Encoded ECNP frame bytes
#[wasm_bindgen(js_name = "ecnpEncode")]
pub fn ecnp_encode(msg_type: u8, payload: &[u8]) -> Result<Vec<u8>, JsError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(JsError::new(&format!(
            "payload size {} exceeds max {}",
            payload.len(),
            MAX_PAYLOAD_SIZE
        )));
    }

    // Validate message type
    let mt = match msg_type {
        0x01..=0x08 => msg_type,
        _ => return Err(JsError::new(&format!("invalid message type: 0x{msg_type:02x}"))),
    };

    let length = payload.len() as u32;
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame.push(ECNP_VERSION);
    frame.push(mt);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode an ECNP v1.1 binary frame.
///
/// @param data - Raw frame bytes
/// @returns Decoded EcnpFrame with msg_type and payload
#[wasm_bindgen(js_name = "ecnpDecode")]
pub fn ecnp_decode(data: &[u8]) -> Result<EcnpFrame, JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new("frame too short for ECNP header"));
    }

    let version = data[0];
    if version != ECNP_VERSION {
        return Err(JsError::new(&format!(
            "unsupported ECNP version: 0x{version:02x}"
        )));
    }

    let msg_type = data[1];
    if !(0x01..=0x08).contains(&msg_type) {
        return Err(JsError::new(&format!(
            "invalid message type: 0x{msg_type:02x}"
        )));
    }

    let length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;

    if length > MAX_PAYLOAD_SIZE {
        return Err(JsError::new("payload exceeds max size"));
    }

    if data.len() < HEADER_SIZE + length {
        return Err(JsError::new(&format!(
            "frame truncated: expected {} bytes, got {}",
            HEADER_SIZE + length,
            data.len()
        )));
    }

    Ok(EcnpFrame {
        msg_type,
        payload: data[HEADER_SIZE..HEADER_SIZE + length].to_vec(),
    })
}

/// Validate an ECNP frame without extracting the payload.
///
/// @param data - Raw frame bytes
/// @returns true if the frame is valid
#[wasm_bindgen(js_name = "ecnpValidate")]
pub fn ecnp_validate(data: &[u8]) -> bool {
    ecnp_decode(data).is_ok()
}

/// Get the ECNP protocol version string.
#[wasm_bindgen(js_name = "ecnpVersion")]
pub fn ecnp_version() -> String {
    "ECNP/1.1".to_string()
}

/// Get bridge metadata as a JSON string.
#[wasm_bindgen(js_name = "ecnpBridgeInfo")]
pub fn ecnp_bridge_info() -> String {
    serde_json::json!({
        "protocol": "ECNP/1.1",
        "bridge_version": "1.0.0",
        "target": "wasm32-unknown-unknown",
        "message_types": [
            "Handshake", "Data", "Control", "Heartbeat",
            "Error", "Auth", "Telemetry", "PolicyUpdate"
        ]
    })
    .to_string()
}

/// Encode a string payload into an ECNP frame.
///
/// Convenience wrapper that encodes a UTF-8 string.
#[wasm_bindgen(js_name = "ecnpEncodeString")]
pub fn ecnp_encode_string(msg_type: u8, text: &str) -> Result<Vec<u8>, JsError> {
    ecnp_encode(msg_type, text.as_bytes())
}

/// Encode→Decode roundtrip test (self-test callable from JS).
///
/// @returns true if roundtrip succeeds
#[wasm_bindgen(js_name = "ecnpSelfTest")]
pub fn ecnp_self_test() -> bool {
    let payload = b"edgeclaw-wasm-test";
    let frame = match ecnp_encode(0x04, payload) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let decoded = match ecnp_decode(&frame) {
        Ok(d) => d,
        Err(_) => return false,
    };
    decoded.msg_type == 0x04 && decoded.payload == payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = b"test payload";
        let frame = ecnp_encode(0x02, payload).unwrap();
        let decoded = ecnp_decode(&frame).unwrap();
        assert_eq!(decoded.msg_type(), 0x02);
        assert_eq!(decoded.payload(), payload);
    }

    #[test]
    fn test_all_message_types() {
        for t in 0x01..=0x08u8 {
            let frame = ecnp_encode(t, b"ok").unwrap();
            let decoded = ecnp_decode(&frame).unwrap();
            assert_eq!(decoded.msg_type(), t);
        }
    }

    #[test]
    fn test_invalid_type() {
        // JsError panics on non-wasm; use std::panic::catch_unwind or check encode logic
        let result = std::panic::catch_unwind(|| ecnp_encode(0x00, b"bad"));
        assert!(result.is_err() || result.unwrap().is_err());
        let result = std::panic::catch_unwind(|| ecnp_encode(0x09, b"bad"));
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[test]
    fn test_validate() {
        let frame = ecnp_encode(0x04, b"heartbeat").unwrap();
        assert!(ecnp_validate(&frame));
        // On native, JsError panics — so ecnp_validate will panic too.
        // Use catch_unwind to handle this: panic = invalid = "not valid"
        let r1 = std::panic::catch_unwind(|| ecnp_validate(&[0xFF, 0x00]));
        assert!(r1.is_err() || r1.unwrap() == false);
        let r2 = std::panic::catch_unwind(|| ecnp_validate(&[]));
        assert!(r2.is_err() || r2.unwrap() == false);
    }

    #[test]
    fn test_decode_short() {
        let result = std::panic::catch_unwind(|| ecnp_decode(&[]));
        assert!(result.is_err() || result.unwrap().is_err());
        let result = std::panic::catch_unwind(|| ecnp_decode(&[0x01]));
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[test]
    fn test_decode_wrong_version() {
        let frame = vec![0xFF, 0x01, 0, 0, 0, 0];
        let result = std::panic::catch_unwind(|| ecnp_decode(&frame));
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[test]
    fn test_payload_string() {
        let frame = ecnp_encode(0x02, b"hello world").unwrap();
        let decoded = ecnp_decode(&frame).unwrap();
        assert_eq!(decoded.payload_string(), "hello world");
    }

    #[test]
    fn test_empty_payload() {
        let frame = ecnp_encode(0x04, &[]).unwrap();
        let decoded = ecnp_decode(&frame).unwrap();
        assert!(decoded.payload().is_empty());
    }

    #[test]
    fn test_version_string() {
        assert_eq!(ecnp_version(), "ECNP/1.1");
    }

    #[test]
    fn test_bridge_info() {
        let info = ecnp_bridge_info();
        assert!(info.contains("ECNP/1.1"));
        assert!(info.contains("wasm32"));
        assert!(info.contains("Heartbeat"));
    }

    #[test]
    fn test_self_test() {
        assert!(ecnp_self_test());
    }

    #[test]
    fn test_encode_string() {
        let frame = ecnp_encode_string(0x04, "heartbeat-ping").unwrap();
        let decoded = ecnp_decode(&frame).unwrap();
        assert_eq!(decoded.payload_string(), "heartbeat-ping");
    }

    #[test]
    fn test_truncated_frame() {
        // Valid header but payload too short
        let frame = vec![0x01, 0x02, 0, 0, 0, 10, 1, 2]; // says 10 bytes, only 2
        let result = std::panic::catch_unwind(|| ecnp_decode(&frame));
        assert!(result.is_err() || result.unwrap().is_err());
    }
}
