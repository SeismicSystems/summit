use serde::{Deserialize, Serialize};
use std::num::ParseIntError;

#[derive(Debug)]
pub enum ClientError {
    Request(reqwest::Error),
    Parse(ParseIntError),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Request(e)
    }
}

impl From<ParseIntError> for ClientError {
    fn from(e: ParseIntError) -> Self {
        ClientError::Parse(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Request(e) => write!(f, "request error: {}", e),
            ClientError::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    Genesis,
    Node,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerModeResponse {
    pub mode: ServerMode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeysResponse {
    pub node: String,
    pub consensus: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointRes {
    pub checkpoint: Vec<u8>,
    pub digest: [u8; 32],
    pub epoch: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointInfoRes {
    pub epoch: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositTransactionResponse {
    pub node_pubkey: [u8; 32],
    pub consensus_pubkey: Vec<u8>, // 48 bytes
    pub withdrawal_credentials: [u8; 32],
    pub node_signature: Vec<u8>, // 48 bytes
    pub consensus_signature: Vec<u8>, // 96 bytes
    pub deposit_data_root: [u8; 32],
}
