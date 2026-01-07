use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeysResponse {
    pub node: String,
    pub consensus: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DepositTransactionResponse {
    pub node_pubkey: [u8; 32],
    pub consensus_pubkey: Vec<u8>,
    pub withdrawal_credentials: [u8; 32],
    pub node_signature: Vec<u8>,
    pub consensus_signature: Vec<u8>,
    pub deposit_data_root: [u8; 32],
}

pub use summit_types::rpc::{CheckpointInfoRes, CheckpointRes};
