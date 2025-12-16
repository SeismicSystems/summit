use summit_types::rpc::{
    CheckpointInfoRes, CheckpointRes, DepositTransactionResponse, PublicKeysResponse,
    ServerModeResponse,
};

use crate::client::types::ClientError;

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
