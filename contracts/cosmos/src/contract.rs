//! EdgeClaw CosmWasm Contract — Entry Points & Handlers

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

use crate::error::ContractError;
use crate::msg::{
    AnchorResponse, BalanceResponse, BoolResponse, CountResponse, DeviceResponse, ExecuteMsg,
    InstantiateMsg, PolicyResponse, QueryMsg, SupplyResponse,
};
use crate::state::{
    AuditAnchorRecord, Config, DeviceRecord, PolicyRecord, AUDIT_ANCHORS, BALANCES, CONFIG,
    DEVICES, POLICIES,
};

// ─── Instantiate ───────────────────────────────────────

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let config = Config {
        admin: info.sender.clone(),
        device_count: 0,
        next_policy_id: 0,
        anchor_count: 0,
        last_batch_end: 0,
        total_supply: 0,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", info.sender))
}

// ─── Execute ───────────────────────────────────────────

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // Device Registry
        ExecuteMsg::RegisterDevice {
            public_key,
            device_name,
            device_type,
        } => execute_register_device(deps, env, info, public_key, device_name, device_type),
        ExecuteMsg::DeactivateDevice { public_key } => {
            execute_deactivate_device(deps, info, public_key)
        }
        ExecuteMsg::ReactivateDevice { public_key } => {
            execute_reactivate_device(deps, info, public_key)
        }

        // Policy NFT
        ExecuteMsg::MintPolicy {
            owner,
            role,
            capabilities,
            expires_at,
        } => execute_mint_policy(deps, env, info, owner, role, capabilities, expires_at),
        ExecuteMsg::RevokePolicy { policy_id } => execute_revoke_policy(deps, info, policy_id),

        // Task Token
        ExecuteMsg::MintTokens { recipient, amount } => {
            execute_mint_tokens(deps, info, recipient, amount)
        }
        ExecuteMsg::RewardTask {
            task_id,
            executor,
            amount,
        } => execute_reward_task(deps, info, task_id, executor, amount),

        // Audit Anchor
        ExecuteMsg::AnchorAudit {
            batch_start,
            batch_end,
            batch_hash,
        } => execute_anchor_audit(deps, env, info, batch_start, batch_end, batch_hash),
    }
}

// ─── Device Registry Handlers ──────────────────────────

fn execute_register_device(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    public_key: String,
    device_name: String,
    device_type: String,
) -> Result<Response, ContractError> {
    if DEVICES.has(deps.storage, &public_key) {
        return Err(ContractError::DeviceAlreadyRegistered { public_key });
    }

    let record = DeviceRecord {
        public_key: public_key.clone(),
        device_name: device_name.clone(),
        device_type: device_type.clone(),
        owner: info.sender.clone(),
        registered_at: env.block.time.seconds(),
        active: true,
    };

    DEVICES.save(deps.storage, &public_key, &record)?;

    let mut config = CONFIG.load(deps.storage)?;
    config.device_count += 1;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "register_device")
        .add_attribute("public_key", public_key)
        .add_attribute("device_name", device_name)
        .add_attribute("device_type", device_type)
        .add_attribute("owner", info.sender))
}

fn execute_deactivate_device(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> Result<Response, ContractError> {
    let mut record = DEVICES
        .load(deps.storage, &public_key)
        .map_err(|_| ContractError::DeviceNotFound {
            public_key: public_key.clone(),
        })?;

    let config = CONFIG.load(deps.storage)?;
    if info.sender != record.owner && info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    record.active = false;
    DEVICES.save(deps.storage, &public_key, &record)?;

    Ok(Response::new()
        .add_attribute("action", "deactivate_device")
        .add_attribute("public_key", public_key))
}

fn execute_reactivate_device(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> Result<Response, ContractError> {
    let mut record = DEVICES
        .load(deps.storage, &public_key)
        .map_err(|_| ContractError::DeviceNotFound {
            public_key: public_key.clone(),
        })?;

    let config = CONFIG.load(deps.storage)?;
    if info.sender != record.owner && info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    record.active = true;
    DEVICES.save(deps.storage, &public_key, &record)?;

    Ok(Response::new()
        .add_attribute("action", "reactivate_device")
        .add_attribute("public_key", public_key))
}

// ─── Policy NFT Handlers ──────────────────────────────

fn execute_mint_policy(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    owner: String,
    role: String,
    capabilities: Vec<String>,
    expires_at: u64,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    let valid_roles = ["owner", "admin", "operator", "viewer", "guest"];
    if !valid_roles.contains(&role.as_str()) {
        return Err(ContractError::InvalidRole { role });
    }

    let owner_addr = deps.api.addr_validate(&owner)?;
    let policy_id = config.next_policy_id;

    let record = PolicyRecord {
        policy_id,
        owner: owner_addr,
        role: role.clone(),
        capabilities: capabilities.clone(),
        expires_at,
        issuer: info.sender.clone(),
        created_at: env.block.time.seconds(),
        revoked: false,
    };

    POLICIES.save(deps.storage, policy_id, &record)?;
    config.next_policy_id += 1;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "mint_policy")
        .add_attribute("policy_id", policy_id.to_string())
        .add_attribute("owner", owner)
        .add_attribute("role", role))
}

fn execute_revoke_policy(
    deps: DepsMut,
    info: MessageInfo,
    policy_id: u64,
) -> Result<Response, ContractError> {
    let mut record = POLICIES
        .load(deps.storage, policy_id)
        .map_err(|_| ContractError::PolicyNotFound { policy_id })?;

    let config = CONFIG.load(deps.storage)?;
    if info.sender != record.issuer && info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }
    if record.revoked {
        return Err(ContractError::PolicyAlreadyRevoked {});
    }

    record.revoked = true;
    POLICIES.save(deps.storage, policy_id, &record)?;

    Ok(Response::new()
        .add_attribute("action", "revoke_policy")
        .add_attribute("policy_id", policy_id.to_string()))
}

// ─── Task Token Handlers ──────────────────────────────

fn execute_mint_tokens(
    deps: DepsMut,
    info: MessageInfo,
    recipient: String,
    amount: u64,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    let balance = BALANCES
        .may_load(deps.storage, &recipient)?
        .unwrap_or(0);
    BALANCES.save(deps.storage, &recipient, &(balance + amount as u128))?;
    config.total_supply += amount as u128;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "mint_tokens")
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount.to_string()))
}

fn execute_reward_task(
    deps: DepsMut,
    info: MessageInfo,
    task_id: String,
    executor: String,
    amount: u64,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }

    let balance = BALANCES
        .may_load(deps.storage, &executor)?
        .unwrap_or(0);
    BALANCES.save(deps.storage, &executor, &(balance + amount as u128))?;
    config.total_supply += amount as u128;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "reward_task")
        .add_attribute("task_id", task_id)
        .add_attribute("executor", executor)
        .add_attribute("amount", amount.to_string()))
}

// ─── Audit Anchor Handlers ────────────────────────────

fn execute_anchor_audit(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    batch_start: u64,
    batch_end: u64,
    batch_hash: String,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(ContractError::Unauthorized {});
    }
    if batch_start > batch_end {
        return Err(ContractError::InvalidBatchRange {});
    }
    if config.anchor_count > 0 && batch_start <= config.last_batch_end {
        return Err(ContractError::BatchOverlap {});
    }

    let record = AuditAnchorRecord {
        index: config.anchor_count,
        batch_start,
        batch_end,
        batch_hash: batch_hash.clone(),
        anchored_at: env.block.time.seconds(),
        submitter: info.sender,
    };

    AUDIT_ANCHORS.save(deps.storage, config.anchor_count, &record)?;
    config.anchor_count += 1;
    config.last_batch_end = batch_end;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "anchor_audit")
        .add_attribute("batch_start", batch_start.to_string())
        .add_attribute("batch_end", batch_end.to_string())
        .add_attribute("batch_hash", batch_hash))
}

// ─── Query ─────────────────────────────────────────────

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetDevice { public_key } => {
            let record = DEVICES.load(deps.storage, &public_key)?;
            to_json_binary(&DeviceResponse {
                public_key: record.public_key,
                device_name: record.device_name,
                device_type: record.device_type,
                owner: record.owner.to_string(),
                registered_at: record.registered_at,
                active: record.active,
            })
        }
        QueryMsg::GetDeviceCount {} => {
            let config = CONFIG.load(deps.storage)?;
            to_json_binary(&CountResponse {
                count: config.device_count,
            })
        }
        QueryMsg::GetPolicy { policy_id } => {
            let record = POLICIES.load(deps.storage, policy_id)?;
            to_json_binary(&PolicyResponse {
                policy_id: record.policy_id,
                owner: record.owner.to_string(),
                role: record.role,
                capabilities: record.capabilities,
                expires_at: record.expires_at,
                issuer: record.issuer.to_string(),
                created_at: record.created_at,
                revoked: record.revoked,
            })
        }
        QueryMsg::VerifyPolicy { policy_id } => {
            let result = match POLICIES.may_load(deps.storage, policy_id)? {
                Some(record) => {
                    if record.revoked {
                        false
                    } else if record.expires_at > 0
                        && env.block.time.seconds() > record.expires_at
                    {
                        false
                    } else {
                        true
                    }
                }
                None => false,
            };
            to_json_binary(&BoolResponse { result })
        }
        QueryMsg::GetBalance { account } => {
            let balance = BALANCES
                .may_load(deps.storage, &account)?
                .unwrap_or(0);
            to_json_binary(&BalanceResponse {
                balance: balance as u64,
            })
        }
        QueryMsg::GetTotalSupply {} => {
            let config = CONFIG.load(deps.storage)?;
            to_json_binary(&SupplyResponse {
                total_supply: config.total_supply as u64,
            })
        }
        QueryMsg::GetAnchorCount {} => {
            let config = CONFIG.load(deps.storage)?;
            to_json_binary(&CountResponse {
                count: config.anchor_count,
            })
        }
        QueryMsg::GetAnchor { index } => {
            let record = AUDIT_ANCHORS.load(deps.storage, index)?;
            to_json_binary(&AnchorResponse {
                index: record.index,
                batch_start: record.batch_start,
                batch_end: record.batch_end,
                batch_hash: record.batch_hash,
                anchored_at: record.anchored_at,
                submitter: record.submitter.to_string(),
            })
        }
        QueryMsg::VerifyAuditChain {} => {
            let config = CONFIG.load(deps.storage)?;
            let mut valid = true;
            if config.anchor_count > 1 {
                for i in 1..config.anchor_count {
                    let prev = AUDIT_ANCHORS.load(deps.storage, i - 1)?;
                    let curr = AUDIT_ANCHORS.load(deps.storage, i)?;
                    if curr.batch_start <= prev.batch_end {
                        valid = false;
                        break;
                    }
                }
            }
            to_json_binary(&BoolResponse { result: valid })
        }
    }
}
