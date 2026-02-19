//! Well-known logical trie keys for ConsensusState fields.
//!
//! All keys are hashed with `keccak256` before insertion into the MPT.
//! Each field of each struct gets its own trie entry for fine-grained proofs.

use alloy_primitives::hex;

// --- Scalar fields ---
pub const EPOCH: &[u8] = b"epoch";
pub const VIEW: &[u8] = b"view";
pub const LATEST_HEIGHT: &[u8] = b"latest_height";
pub const HEAD_DIGEST: &[u8] = b"head_digest";
pub const EPOCH_GENESIS_HASH: &[u8] = b"epoch_genesis_hash";
pub const VALIDATOR_MINIMUM_STAKE: &[u8] = b"validator_minimum_stake";
pub const VALIDATOR_MAXIMUM_STAKE: &[u8] = b"validator_maximum_stake";
pub const NEXT_WITHDRAWAL_INDEX: &[u8] = b"next_withdrawal_index";

// --- Forkchoice sub-fields ---
pub const FORKCHOICE_HEAD_BLOCK_HASH: &[u8] = b"forkchoice_head_block_hash";
pub const FORKCHOICE_SAFE_BLOCK_HASH: &[u8] = b"forkchoice_safe_block_hash";
pub const FORKCHOICE_FINALIZED_BLOCK_HASH: &[u8] = b"forkchoice_finalized_block_hash";

// --- Deposit queue per-field keys ---

pub fn deposit_queue_request_consensus_pubkey(node_pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"deposit_queue_request_consensus_pubkey_", node_pubkey)
}

pub fn deposit_queue_request_withdrawal_credentials(node_pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(
        b"deposit_queue_request_withdrawal_credentials_",
        node_pubkey,
    )
}

pub fn deposit_queue_request_amount(node_pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"deposit_queue_request_amount_", node_pubkey)
}

pub fn deposit_queue_request_node_signature(node_pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"deposit_queue_request_node_signature_", node_pubkey)
}

pub fn deposit_queue_request_consensus_signature(node_pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"deposit_queue_request_consensus_signature_", node_pubkey)
}

// --- Withdrawal queue per-field keys ---

pub fn withdrawal_queue_request_balance_deduction(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"withdrawal_queue_request_balance_deduction_", pubkey)
}

pub fn withdrawal_queue_request_address(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"withdrawal_queue_request_address_", pubkey)
}

pub fn withdrawal_queue_request_amount(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"withdrawal_queue_request_amount_", pubkey)
}

pub fn withdrawal_queue_request_epoch(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"withdrawal_queue_request_epoch_", pubkey)
}

// --- Validator account per-field keys ---

pub fn validator_account_consensus_public_key(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"validator_accounts_account_consensus_public_key_", pubkey)
}

pub fn validator_account_withdrawal_credentials(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(
        b"validator_accounts_account_withdrawal_credentials_",
        pubkey,
    )
}

pub fn validator_account_balance(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"validator_accounts_account_balance_", pubkey)
}

pub fn validator_account_status(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"validator_accounts_account_status_", pubkey)
}

pub fn validator_account_has_pending_deposit(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"validator_accounts_account_has_pending_deposit_", pubkey)
}

pub fn validator_account_has_pending_withdrawal(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(
        b"validator_accounts_account_has_pending_withdrawal_",
        pubkey,
    )
}

pub fn validator_account_joining_epoch(pubkey: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"validator_accounts_account_joining_epoch_", pubkey)
}

// --- Protocol param changes keys ---

pub fn protocol_param_changes_param(variant_name: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + variant_name.len());
    key.extend_from_slice(b"protocol_param_changes_param_");
    key.extend_from_slice(variant_name);
    key
}

// --- Added validators keys ---

pub fn added_validators_consensus_key(node_key: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"added_validators_consensus_key_", node_key)
}

// --- Removed validators keys ---

pub fn removed_validators(node_key: &[u8; 32]) -> Vec<u8> {
    prefixed_key(b"removed_validators_", node_key)
}

// --- Parsing ---

/// Parse a human-readable key descriptor into a logical trie key.
///
/// Scalar keys: `"epoch"`, `"view"`, `"latest_height"`, etc.
/// Parameterized keys: `"validator_account_balance:0xABCD..."` (hex-encoded 32-byte pubkey after colon).
pub fn parse_key(descriptor: &str) -> Result<Vec<u8>, String> {
    // Try scalar keys first
    match descriptor {
        "epoch" => return Ok(EPOCH.to_vec()),
        "view" => return Ok(VIEW.to_vec()),
        "latest_height" => return Ok(LATEST_HEIGHT.to_vec()),
        "head_digest" => return Ok(HEAD_DIGEST.to_vec()),
        "epoch_genesis_hash" => return Ok(EPOCH_GENESIS_HASH.to_vec()),
        "validator_minimum_stake" => return Ok(VALIDATOR_MINIMUM_STAKE.to_vec()),
        "validator_maximum_stake" => return Ok(VALIDATOR_MAXIMUM_STAKE.to_vec()),
        "next_withdrawal_index" => return Ok(NEXT_WITHDRAWAL_INDEX.to_vec()),
        "forkchoice_head_block_hash" => return Ok(FORKCHOICE_HEAD_BLOCK_HASH.to_vec()),
        "forkchoice_safe_block_hash" => return Ok(FORKCHOICE_SAFE_BLOCK_HASH.to_vec()),
        "forkchoice_finalized_block_hash" => return Ok(FORKCHOICE_FINALIZED_BLOCK_HASH.to_vec()),
        _ => {}
    }

    // Try parameterized keys (field_name:hex_pubkey)
    let (field, hex_str) = descriptor
        .split_once(':')
        .ok_or_else(|| format!("unknown key: {descriptor}"))?;

    let pubkey = parse_hex_pubkey(hex_str)?;

    match field {
        // Validator account fields
        "validator_account_balance" => Ok(validator_account_balance(&pubkey)),
        "validator_account_status" => Ok(validator_account_status(&pubkey)),
        "validator_account_consensus_public_key" => {
            Ok(validator_account_consensus_public_key(&pubkey))
        }
        "validator_account_withdrawal_credentials" => {
            Ok(validator_account_withdrawal_credentials(&pubkey))
        }
        "validator_account_has_pending_deposit" => {
            Ok(validator_account_has_pending_deposit(&pubkey))
        }
        "validator_account_has_pending_withdrawal" => {
            Ok(validator_account_has_pending_withdrawal(&pubkey))
        }
        "validator_account_joining_epoch" => Ok(validator_account_joining_epoch(&pubkey)),
        // Deposit queue fields
        "deposit_queue_request_amount" => Ok(deposit_queue_request_amount(&pubkey)),
        "deposit_queue_request_consensus_pubkey" => {
            Ok(deposit_queue_request_consensus_pubkey(&pubkey))
        }
        "deposit_queue_request_withdrawal_credentials" => {
            Ok(deposit_queue_request_withdrawal_credentials(&pubkey))
        }
        "deposit_queue_request_node_signature" => Ok(deposit_queue_request_node_signature(&pubkey)),
        "deposit_queue_request_consensus_signature" => {
            Ok(deposit_queue_request_consensus_signature(&pubkey))
        }
        // Withdrawal queue fields
        "withdrawal_queue_request_amount" => Ok(withdrawal_queue_request_amount(&pubkey)),
        "withdrawal_queue_request_balance_deduction" => {
            Ok(withdrawal_queue_request_balance_deduction(&pubkey))
        }
        "withdrawal_queue_request_address" => Ok(withdrawal_queue_request_address(&pubkey)),
        "withdrawal_queue_request_epoch" => Ok(withdrawal_queue_request_epoch(&pubkey)),
        // Added/removed validators
        "added_validators_consensus_key" => Ok(added_validators_consensus_key(&pubkey)),
        "removed_validators" => Ok(removed_validators(&pubkey)),
        _ => Err(format!("unknown parameterized key: {field}")),
    }
}

fn parse_hex_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "pubkey must be exactly 32 bytes".to_string())
}

// --- Helper ---

fn prefixed_key(prefix: &[u8], suffix: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}
