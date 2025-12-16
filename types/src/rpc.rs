use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckpointRes {
    pub checkpoint: Vec<u8>,
    pub digest: [u8; 32],
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckpointInfoRes {
    pub epoch: u64,
    pub digest: [u8; 32],
}
