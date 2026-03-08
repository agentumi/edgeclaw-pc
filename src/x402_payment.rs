//! x402 Payment Gateway — HTTP 402 automatic SUI micro-payment.
//!
//! Handles the x402 protocol flow:
//! 1. Detect HTTP 402 Payment Required response
//! 2. Parse payment requirements from the WWW-Payment header
//! 3. Create SUI escrow and construct payment proof
//! 4. Retry the request with X-Payment header

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AgentError;

// ─── Payment Requirement ───────────────────────────────────────────────────────

/// Payment requirement parsed from a WWW-Payment header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirement {
    pub recipient: String,
    pub amount_sui: f64,
    pub description: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub nonce: String,
}

impl PaymentRequirement {
    pub fn new(recipient: &str, amount_sui: f64, description: &str) -> Self {
        Self {
            recipient: recipient.to_string(),
            amount_sui,
            description: description.to_string(),
            expires_at: None,
            nonce: Uuid::new_v4().to_string(),
        }
    }

    /// Encode to a compact header string
    pub fn to_header_value(&self) -> String {
        format!(
            "SUI recipient={},amount={},desc={},nonce={}",
            self.recipient, self.amount_sui, self.description, self.nonce
        )
    }

    /// Parse from a header string
    pub fn from_header_value(header: &str) -> Result<Self, AgentError> {
        if !header.starts_with("SUI ") {
            return Err(AgentError::InvalidParameter(
                "Not a SUI payment header".into(),
            ));
        }
        let parts = &header[4..]; // strip "SUI "
        let mut recipient = String::new();
        let mut amount_sui = 0.0_f64;
        let mut description = String::new();
        let mut nonce = Uuid::new_v4().to_string();

        for kv in parts.split(',') {
            let pair: Vec<&str> = kv.splitn(2, '=').collect();
            if pair.len() != 2 {
                continue;
            }
            match pair[0].trim() {
                "recipient" => recipient = pair[1].to_string(),
                "amount" => {
                    amount_sui = pair[1].parse::<f64>().map_err(|_| {
                        AgentError::InvalidParameter("Invalid amount in payment header".into())
                    })?
                }
                "desc" => description = pair[1].to_string(),
                "nonce" => nonce = pair[1].to_string(),
                _ => {}
            }
        }

        if recipient.is_empty() {
            return Err(AgentError::InvalidParameter(
                "Missing recipient in payment header".into(),
            ));
        }

        Ok(Self {
            recipient,
            amount_sui,
            description,
            nonce,
            expires_at: None,
        })
    }
}

// ─── Payment Proof ─────────────────────────────────────────────────────────────

/// Payment proof to include in retried request via X-Payment header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    pub tx_digest: String,
    pub payer: String,
    pub recipient: String,
    pub amount_sui: f64,
    pub nonce: String,
    pub timestamp: DateTime<Utc>,
}

impl PaymentProof {
    pub fn to_header_value(&self) -> String {
        format!(
            "SUI tx={},payer={},recipient={},amount={},nonce={},ts={}",
            self.tx_digest,
            self.payer,
            self.recipient,
            self.amount_sui,
            self.nonce,
            self.timestamp.timestamp()
        )
    }
}

// ─── Payment Record ─────────────────────────────────────────────────────────────

/// Full record of an x402 payment transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub id: Uuid,
    pub requirement: PaymentRequirement,
    pub proof: PaymentProof,
    pub paid_at: DateTime<Utc>,
    pub endpoint: String,
}

// ─── x402 Gateway ──────────────────────────────────────────────────────────────

/// x402 payment gateway for handling HTTP 402 payment flows
pub struct X402Gateway {
    payer_id: String,
    balance_sui: f64,
    records: Vec<PaymentRecord>,
    max_auto_payment: f64,
}

impl X402Gateway {
    pub fn new(payer_id: &str, initial_balance: f64, max_auto_payment: f64) -> Self {
        Self {
            payer_id: payer_id.to_string(),
            balance_sui: initial_balance,
            records: Vec::new(),
            max_auto_payment,
        }
    }

    /// Check if the gateway can auto-pay the required amount
    pub fn can_auto_pay(&self, amount: f64) -> bool {
        amount <= self.max_auto_payment && self.balance_sui >= amount
    }

    /// Execute a micro-payment for the given requirement.
    /// Returns a PaymentProof to include in the retried request.
    pub fn pay(&mut self, requirement: &PaymentRequirement, endpoint: &str) -> Result<PaymentProof, AgentError> {
        if requirement.amount_sui <= 0.0 {
            return Err(AgentError::InvalidParameter(
                "Payment amount must be positive".into(),
            ));
        }
        if !self.can_auto_pay(requirement.amount_sui) {
            return Err(AgentError::InvalidParameter(format!(
                "Cannot auto-pay {:.4} SUI (balance: {:.4}, limit: {:.4})",
                requirement.amount_sui, self.balance_sui, self.max_auto_payment
            )));
        }

        // Deduct balance
        self.balance_sui -= requirement.amount_sui;

        // Create mock SUI transaction
        let tx_digest = format!(
            "0xtx_{}_{}",
            &requirement.nonce[..8.min(requirement.nonce.len())],
            (requirement.amount_sui * 1_000_000.0) as u64
        );

        let proof = PaymentProof {
            tx_digest: tx_digest.clone(),
            payer: self.payer_id.clone(),
            recipient: requirement.recipient.clone(),
            amount_sui: requirement.amount_sui,
            nonce: requirement.nonce.clone(),
            timestamp: Utc::now(),
        };

        let record = PaymentRecord {
            id: Uuid::new_v4(),
            requirement: requirement.clone(),
            proof: proof.clone(),
            paid_at: Utc::now(),
            endpoint: endpoint.to_string(),
        };

        self.records.push(record);
        Ok(proof)
    }

    pub fn balance(&self) -> f64 {
        self.balance_sui
    }

    pub fn records(&self) -> &[PaymentRecord] {
        &self.records
    }

    pub fn total_spent(&self) -> f64 {
        self.records.iter().map(|r| r.requirement.amount_sui).sum()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_requirement_header_roundtrip() {
        let req = PaymentRequirement::new("0xrecipient", 0.5, "API call");
        let header = req.to_header_value();
        let parsed = PaymentRequirement::from_header_value(&header).unwrap();
        assert_eq!(parsed.recipient, "0xrecipient");
        assert!((parsed.amount_sui - 0.5).abs() < 0.001);
        assert_eq!(parsed.description, "API call");
    }

    #[test]
    fn test_payment_requirement_invalid_protocol() {
        let result = PaymentRequirement::from_header_value("ETH recipient=0x...");
        assert!(result.is_err());
    }

    #[test]
    fn test_payment_requirement_missing_recipient() {
        let result = PaymentRequirement::from_header_value("SUI amount=1.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_gateway_can_auto_pay() {
        let gateway = X402Gateway::new("payer_1", 10.0, 1.0);
        assert!(gateway.can_auto_pay(0.5));
        assert!(!gateway.can_auto_pay(2.0)); // exceeds limit
        assert!(!gateway.can_auto_pay(11.0)); // exceeds balance
    }

    #[test]
    fn test_gateway_pay_success() {
        let mut gateway = X402Gateway::new("payer_1", 10.0, 5.0);
        let req = PaymentRequirement::new("0xrecipient", 1.5, "Test payment");
        let proof = gateway.pay(&req, "/api/data").unwrap();

        assert_eq!(proof.recipient, "0xrecipient");
        assert!((proof.amount_sui - 1.5).abs() < 0.001);
        assert!((gateway.balance() - 8.5).abs() < 0.001);
        assert_eq!(gateway.records().len(), 1);
    }

    #[test]
    fn test_gateway_pay_exceeds_limit() {
        let mut gateway = X402Gateway::new("payer_1", 100.0, 1.0);
        let req = PaymentRequirement::new("0xrecipient", 5.0, "Big payment");
        let result = gateway.pay(&req, "/api/data");
        assert!(result.is_err());
    }

    #[test]
    fn test_gateway_pay_insufficient_balance() {
        let mut gateway = X402Gateway::new("payer_1", 0.1, 100.0);
        let req = PaymentRequirement::new("0xrecipient", 1.0, "Too expensive");
        let result = gateway.pay(&req, "/api/data");
        assert!(result.is_err());
    }

    #[test]
    fn test_gateway_total_spent() {
        let mut gateway = X402Gateway::new("payer_1", 100.0, 50.0);
        let r1 = PaymentRequirement::new("0xr", 1.0, "Call 1");
        let r2 = PaymentRequirement::new("0xr", 2.5, "Call 2");
        gateway.pay(&r1, "/api/a").unwrap();
        gateway.pay(&r2, "/api/b").unwrap();
        assert!((gateway.total_spent() - 3.5).abs() < 0.001);
    }

    #[test]
    fn test_payment_proof_header_value() {
        let proof = PaymentProof {
            tx_digest: "0xtx_abc".to_string(),
            payer: "payer_1".to_string(),
            recipient: "0xrecipient".to_string(),
            amount_sui: 1.0,
            nonce: "abc123".to_string(),
            timestamp: Utc::now(),
        };
        let header = proof.to_header_value();
        assert!(header.contains("0xtx_abc"));
        assert!(header.contains("payer_1"));
        assert!(header.contains("0xrecipient"));
    }

    #[test]
    fn test_gateway_zero_amount_payment() {
        let mut gateway = X402Gateway::new("payer_1", 10.0, 10.0);
        let req = PaymentRequirement::new("0xr", 0.0, "Free?");
        let result = gateway.pay(&req, "/api");
        assert!(result.is_err());
    }
}
