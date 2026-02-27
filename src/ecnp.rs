//! ECNP v1.1 binary framing codec.
//!
//! Implements the EdgeClaw Network Protocol binary wire format with
//! version byte, message type, 4-byte big-endian length, and payload.
//! Maximum frame size is 1 MB.

use crate::error::AgentError;
use crate::protocol::MessageType;

const ECNP_VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 6; // Version(1) + Type(1) + Length(4)
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB

/// Decoded ECNP message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EcnpMessage {
    pub version: u8,
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

/// ECNP v1.1 binary framing codec
pub struct EcnpCodec;

impl EcnpCodec {
    /// Encode a message into ECNP binary frame
    pub fn encode(msg_type: MessageType, payload: &[u8]) -> Result<Vec<u8>, AgentError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(AgentError::InvalidParameter(format!(
                "payload size {} exceeds max {}",
                payload.len(),
                MAX_PAYLOAD_SIZE
            )));
        }

        let length = payload.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
        frame.push(ECNP_VERSION);
        frame.push(msg_type as u8);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    /// Decode an ECNP binary frame
    pub fn decode(data: &[u8]) -> Result<EcnpMessage, AgentError> {
        if data.len() < HEADER_SIZE {
            return Err(AgentError::InvalidParameter(
                "frame too short for header".into(),
            ));
        }

        let version = data[0];
        if version != ECNP_VERSION {
            return Err(AgentError::InvalidParameter(format!(
                "unsupported ECNP version: 0x{version:02x}"
            )));
        }

        let msg_type = data[1];
        let _ = MessageType::try_from(msg_type)?;

        let length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;

        if length > MAX_PAYLOAD_SIZE {
            return Err(AgentError::InvalidParameter(
                "payload exceeds max size".into(),
            ));
        }

        if data.len() < HEADER_SIZE + length {
            return Err(AgentError::InvalidParameter(format!(
                "frame truncated: expected {} bytes, got {}",
                HEADER_SIZE + length,
                data.len()
            )));
        }

        Ok(EcnpMessage {
            version,
            msg_type,
            payload: data[HEADER_SIZE..HEADER_SIZE + length].to_vec(),
        })
    }

    /// Encode a string payload
    pub fn encode_string(msg_type: MessageType, text: &str) -> Result<Vec<u8>, AgentError> {
        Self::encode(msg_type, text.as_bytes())
    }

    /// Decode and return payload as UTF-8 string
    pub fn decode_string(data: &[u8]) -> Result<(u8, String), AgentError> {
        let msg = Self::decode(data)?;
        let text = String::from_utf8(msg.payload)
            .map_err(|_| AgentError::SerializationError("invalid UTF-8 payload".into()))?;
        Ok((msg.msg_type, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = b"test payload data";
        let encoded = EcnpCodec::encode(MessageType::Data, payload).unwrap();
        let decoded = EcnpCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.version, ECNP_VERSION);
        assert_eq!(decoded.msg_type, MessageType::Data as u8);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_string_roundtrip() {
        let text = "heartbeat ping";
        let encoded = EcnpCodec::encode_string(MessageType::Heartbeat, text).unwrap();
        let (msg_type, decoded) = EcnpCodec::decode_string(&encoded).unwrap();
        assert_eq!(msg_type, MessageType::Heartbeat as u8);
        assert_eq!(decoded, text);
    }

    #[test]
    fn test_all_message_types() {
        let types = [
            MessageType::Handshake,
            MessageType::Data,
            MessageType::Control,
            MessageType::Heartbeat,
            MessageType::Error,
            MessageType::Auth,
            MessageType::Telemetry,
            MessageType::PolicyUpdate,
        ];
        for mt in types {
            let encoded = EcnpCodec::encode(mt, b"ok").unwrap();
            let decoded = EcnpCodec::decode(&encoded).unwrap();
            assert_eq!(decoded.msg_type, mt as u8);
        }
    }

    #[test]
    fn test_decode_too_short() {
        assert!(EcnpCodec::decode(&[0x01]).is_err());
    }

    #[test]
    fn test_decode_wrong_version() {
        let frame = vec![0xFF, 0x01, 0, 0, 0, 0];
        assert!(EcnpCodec::decode(&frame).is_err());
    }

    #[test]
    fn test_empty_payload() {
        let encoded = EcnpCodec::encode(MessageType::Heartbeat, &[]).unwrap();
        let decoded = EcnpCodec::decode(&encoded).unwrap();
        assert!(decoded.payload.is_empty());
    }
}
