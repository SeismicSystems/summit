use crate::client::{traits::*, types::*};

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
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[async_trait::async_trait]
impl SummitClient for Client {
    async fn health(&self) -> Result<String, reqwest::Error> {
        self.client
            .get(self.url("health"))
            .send()
            .await?
            .text()
            .await
    }

    async fn server_mode(&self) -> Result<ServerModeResponse, reqwest::Error> {
        self.client
            .get(self.url("server_mode"))
            .send()
            .await?
            .json()
            .await
    }

    async fn get_public_keys(&self) -> Result<PublicKeysResponse, reqwest::Error> {
        self.client
            .get(self.url("get_public_keys"))
            .send()
            .await?
            .json()
            .await
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
        self.client
            .get(self.url("get_latest_checkpoint"))
            .send()
            .await?
            .json()
            .await
    }

    async fn get_latest_checkpoint_info(&self) -> Result<CheckpointInfoRes, reqwest::Error> {
        self.client
            .get(self.url("get_latest_checkpoint_info"))
            .send()
            .await?
            .json()
            .await
    }

    async fn get_latest_height(&self) -> Result<u64, ClientError> {
        let text = self
            .client
            .get(self.url("get_latest_height"))
            .send()
            .await?
            .text()
            .await?;
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
