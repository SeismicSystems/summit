//! Summit RPC client
//!
//! # Example
//!
//! ```no_run
//! use summit_rpc::client::{Client, SummitClient, NodeClient, GenesisClient};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = Client::new("http://localhost:8080");
//!
//!     // Check server mode
//!     let mode = client.server_mode().await.unwrap();
//!
//!     // Use node-specific methods
//!     let height = client.get_latest_height().await.unwrap();
//!
//!     // Use genesis-specific methods
//!     let genesis = std::fs::read_to_string("genesis.json").unwrap();
//!     client.send_genesis(genesis).await.unwrap();
//! }
//! ```

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
    pub consensus_pubkey: Vec<u8>,
    pub withdrawal_credentials: [u8; 32],
    pub node_signature: Vec<u8>,
    pub consensus_signature: Vec<u8>,
    pub deposit_data_root: [u8; 32],
}

/// Shared client methods available in both genesis and node modes
#[async_trait::async_trait]
pub trait SummitClient {
    /// Health check
    async fn health(&self) -> Result<String, reqwest::Error>;

    /// Get server mode (genesis or node)
    async fn server_mode(&self) -> Result<ServerModeResponse, reqwest::Error>;

    /// Get node and consensus public keys
    async fn get_public_keys(&self) -> Result<PublicKeysResponse, reqwest::Error>;
}

/// Genesis-specific client methods
#[async_trait::async_trait]
pub trait GenesisClient: SummitClient {
    /// Send genesis file
    async fn send_genesis(&self, body: String) -> Result<String, reqwest::Error>;
}

/// Node-specific client methods
#[async_trait::async_trait]
pub trait NodeClient: SummitClient {
    /// Get checkpoint by epoch
    async fn get_checkpoint(&self, epoch: u64) -> Result<CheckpointRes, reqwest::Error>;

    /// Get latest checkpoint
    async fn get_latest_checkpoint(&self) -> Result<CheckpointRes, reqwest::Error>;

    /// Get latest checkpoint info
    async fn get_latest_checkpoint_info(&self) -> Result<CheckpointInfoRes, reqwest::Error>;

    /// Get latest height
    async fn get_latest_height(&self) -> Result<u64, ClientError>;

    /// Get validator balance by public key
    async fn get_validator_balance(&self, public_key: &str) -> Result<u64, ClientError>;

    /// Get deposit signature
    async fn get_deposit_signature(
        &self,
        amount: u64,
        address: &str,
    ) -> Result<DepositTransactionResponse, reqwest::Error>;
}

/// HTTP client for Summit RPC
pub struct Client {
    base_url: String,
    client: reqwest::Client,
}

impl Client {
    /// Create a new client with the given base URL
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            base_url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

#[async_trait::async_trait]
impl SummitClient for Client {
    async fn health(&self) -> Result<String, reqwest::Error> {
        self.client.get(self.url("health")).send().await?.text().await
    }

    async fn server_mode(&self) -> Result<ServerModeResponse, reqwest::Error> {
        self.client.get(self.url("server_mode")).send().await?.json().await
    }

    async fn get_public_keys(&self) -> Result<PublicKeysResponse, reqwest::Error> {
        self.client.get(self.url("get_public_keys")).send().await?.json().await
    }
}

#[async_trait::async_trait]
impl GenesisClient for Client {
    async fn send_genesis(&self, body: String) -> Result<String, reqwest::Error> {
        self.client
            .post(self.url("send_genesis"))
            .body(body)
            .send()
            .await?
            .text()
            .await
    }
}

#[async_trait::async_trait]
impl NodeClient for Client {
    async fn get_checkpoint(&self, epoch: u64) -> Result<CheckpointRes, reqwest::Error> {
        self.client
            .get(self.url(&format!("get_checkpoint/{}", epoch)))
            .send()
            .await?
            .json()
            .await
    }

    async fn get_latest_checkpoint(&self) -> Result<CheckpointRes, reqwest::Error> {
        self.client.get(self.url("get_latest_checkpoint")).send().await?.json().await
    }

    async fn get_latest_checkpoint_info(&self) -> Result<CheckpointInfoRes, reqwest::Error> {
        self.client.get(self.url("get_latest_checkpoint_info")).send().await?.json().await
    }

    async fn get_latest_height(&self) -> Result<u64, ClientError> {
        let text = self.client.get(self.url("get_latest_height")).send().await?.text().await?;
        Ok(text.parse()?)
    }

    async fn get_validator_balance(&self, public_key: &str) -> Result<u64, ClientError> {
        let text = self
            .client
            .get(self.url(&format!("get_validator_balance?public_key={}", public_key)))
            .send()
            .await?
            .text()
            .await?;
        Ok(text.parse()?)
    }

    async fn get_deposit_signature(
        &self,
        amount: u64,
        address: &str,
    ) -> Result<DepositTransactionResponse, reqwest::Error> {
        self.client
            .get(self.url(&format!("get_deposit_signature/{}/{}", amount, address)))
            .send()
            .await?
            .json()
            .await
    }
}
