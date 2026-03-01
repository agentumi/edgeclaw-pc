use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Device already registered: {public_key}")]
    DeviceAlreadyRegistered { public_key: String },

    #[error("Device not found: {public_key}")]
    DeviceNotFound { public_key: String },

    #[error("Invalid role: {role}")]
    InvalidRole { role: String },

    #[error("Policy not found: {policy_id}")]
    PolicyNotFound { policy_id: u64 },

    #[error("Policy already revoked")]
    PolicyAlreadyRevoked {},

    #[error("Invalid batch range")]
    InvalidBatchRange {},

    #[error("Batch overlaps with previous anchor")]
    BatchOverlap {},
}
