//! EdgeClaw CosmWasm Smart Contract
//!
//! Combined contract for Cosmos IBC-enabled chains:
//! - Device Registry
//! - Policy NFT (CW-721 compatible)
//! - Task Token (ECLAW, CW-20 compatible)
//! - Audit Anchor

pub mod msg;
pub mod state;
pub mod error;
pub mod contract;

pub use crate::error::ContractError;
