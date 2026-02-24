use serde::{Deserialize, Serialize};

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
    pub proofs: Vec<crate::ssz_state_tree::SszStateProof>,
}
