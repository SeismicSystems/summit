//! Well-known logical trie keys for ConsensusState fields.
//!
//! All keys are hashed with `keccak256` before insertion into the MPT.
//! Each field of each struct gets its own trie entry for fine-grained proofs.

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

// --- Helper ---

fn prefixed_key(prefix: &[u8], suffix: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}
