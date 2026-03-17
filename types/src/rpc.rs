use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorAccountResponse {
    pub consensus_public_key: Vec<u8>,
    pub withdrawal_credentials: [u8; 20],
    pub balance: u64,
    pub status: String,
    pub has_pending_deposit: bool,
    pub has_pending_withdrawal: bool,
    pub joining_epoch: u64,
    pub last_deposit_index: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepositResponse {
    pub node_pubkey: [u8; 32],
    pub consensus_pubkey: Vec<u8>,
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub node_signature: Vec<u8>,
    pub consensus_signature: Vec<u8>,
    pub index: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PendingWithdrawalResponse {
    pub withdrawal_index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
    pub pubkey: [u8; 32],
    pub balance_deduction: u64,
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckpointRes {
    pub digest: [u8; 32],
    pub epoch: u64,
    pub checkpoint: Vec<u8>,
    pub last_block: Vec<u8>,
    pub finalized_header: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckpointInfoRes {
    pub epoch: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FinalizedHeaderRes {
    pub epoch: u64,
    pub finalized_header: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StateRootResponse {
    pub root: [u8; 32],
    /// The EL block number at capture time. The root appears on-chain in EL block
    /// `el_block_number + 1` — query that block's timestamp via the beacon roots contract.
    pub el_block_number: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StateProofResponse {
    pub root: [u8; 32],
    /// The EL block number at capture time. The root appears on-chain in EL block
    /// `el_block_number + 1` — query that block's timestamp via the beacon roots contract.
    pub el_block_number: u64,
    pub proofs: Vec<crate::ssz_state_tree::SszProof>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EpochBoundsResponse {
    pub first_height: u64,
    pub last_height: u64,
}
