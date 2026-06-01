/*
This is the Client to speak with the engine API on Reth

The engine api is what consensus uses to drive the execution client forward. There is only 3 main endpoints that we hit
but they do different things depending on the args

engine_forkchoiceUpdatedV3 : This updates the forkchoice head to a specific head. If the optionally arg payload_attributes is provided it will also trigger the
    building of a new block on the execution client. This will mainly be called in 2 scenerios: 1) When a validator has been selected to propose a block he will
    call with payload_attributes to trigger the building process. 2) After a block a validator has previously validated a block(therefore saved on execution client) and
    it has received enough attestations to be committed by consensus


engine_getPayloadV3 : This is called to retrieve a block from execution client. This is called after a node has previously called engine_forkchoiceUpdatedV3 with payload
    attributes to begin the build process

engine_newPayloadV3 : This is called to store(not commit) and validate blocks received from other validators. This is called after receiving a block and it is how we decide if
    we should attest if the block is valid. If it is valid and we reach quorom when we call engine_forkchoiceUpdatedV3 it will set this block to head

*/
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, FixedBytes};
use alloy_provider::{ProviderBuilder, RootProvider, ext::EngineApi};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV4, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId,
    PayloadStatus,
};
use tracing::{error, warn};

use crate::Block;
use alloy_transport::TransportError;
use alloy_transport_ipc::IpcConnect;
use std::future::Future;

/// Typed error returned by `EngineClient` methods so callers can decide
/// whether to retry, drop a round, or shut down — instead of the wrapper
/// panicking on every non-transport JSON-RPC failure.
///
/// Transport-level retry already happens inside each engine-client method
/// via `wait_until_reconnect_available`, so by the time an
/// `EngineClientError` reaches a caller the call has already been retried
/// once after reconnect (or the error is JSON-RPC level, which is not
/// retryable). Callers typically treat any `Err` as a graceful shutdown
/// signal.
#[derive(Debug)]
pub struct EngineClientError(pub TransportError);

impl std::fmt::Display for EngineClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "execution client error: {}", self.0)
    }
}

impl std::error::Error for EngineClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<TransportError> for EngineClientError {
    fn from(e: TransportError) -> Self {
        EngineClientError(e)
    }
}

pub trait EngineClient: Clone + Send + Sync + 'static {
    fn start_building_block(
        &mut self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        suggested_fee_recipient: Address,
        parent_beacon_block_root: Option<FixedBytes<32>>,
        #[cfg(feature = "bench")] height: u64,
    ) -> impl Future<Output = Result<Option<PayloadId>, EngineClientError>> + Send;

    fn get_payload(
        &mut self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Result<ExecutionPayloadEnvelopeV4, EngineClientError>> + Send;

    fn check_payload(
        &mut self,
        block: &Block,
    ) -> impl Future<Output = Result<PayloadStatus, EngineClientError>> + Send;

    fn commit_hash(
        &mut self,
        fork_choice_state: ForkchoiceState,
    ) -> impl Future<Output = Result<ForkchoiceUpdated, EngineClientError>> + Send;
}

#[derive(Clone)]
pub struct RethEngineClient {
    engine_ipc_path: String,
    provider: RootProvider,
}

impl RethEngineClient {
    pub async fn new(engine_ipc_path: String) -> Self {
        let ipc = IpcConnect::new(engine_ipc_path.clone());
        let provider = ProviderBuilder::default().connect_ipc(ipc).await.unwrap();
        Self {
            provider,
            engine_ipc_path,
        }
    }

    pub async fn wait_until_reconnect_available(&mut self) {
        loop {
            let ipc = IpcConnect::new(self.engine_ipc_path.clone());

            match ProviderBuilder::default().connect_ipc(ipc).await {
                Ok(provider) => {
                    self.provider = provider;
                    break;
                }
                Err(e) => {
                    error!("Failed to connect to IPC, retrying: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

impl EngineClient for RethEngineClient {
    async fn start_building_block(
        &mut self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        suggested_fee_recipient: Address,
        parent_beacon_block_root: Option<FixedBytes<32>>,
        #[cfg(feature = "bench")] _height: u64,
    ) -> Result<Option<PayloadId>, EngineClientError> {
        let payload_attributes = PayloadAttributes {
            timestamp,
            prev_randao: [0; 32].into(),
            suggested_fee_recipient,
            withdrawals: Some(withdrawals),
            parent_beacon_block_root,
        };

        let res = match self
            .provider
            .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes.clone()))
            .await
        {
            Ok(res) => res,
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
                    .await
                    .map_err(EngineClientError::from)?
            }
            Err(e) => return Err(EngineClientError::from(e)),
        };

        if res.is_invalid() {
            error!("invalid returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }
        if res.is_syncing() {
            warn!("syncing returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }

        Ok(res.payload_id)
    }

    async fn get_payload(
        &mut self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayloadEnvelopeV4, EngineClientError> {
        match self.provider.get_payload_v4(payload_id).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .get_payload_v4(payload_id)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }

    async fn check_payload(&mut self, block: &Block) -> Result<PayloadStatus, EngineClientError> {
        match self
            .provider
            .new_payload_v4(
                block.payload.clone(),
                Vec::new(),
                block.header.parent_beacon_block_root.into(),
                block.execution_requests.clone(),
            )
            .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .new_payload_v4(
                        block.payload.clone(),
                        Vec::new(),
                        block.header.parent_beacon_block_root.into(),
                        block.execution_requests.clone(),
                    )
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }

    async fn commit_hash(
        &mut self,
        fork_choice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, EngineClientError> {
        match self
            .provider
            .fork_choice_updated_v3(fork_choice_state, None)
            .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .fork_choice_updated_v3(fork_choice_state, None)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }
}

#[cfg(feature = "bad-blocks")]
#[derive(Clone)]
pub struct BadBlockEngineClient {
    engine_ipc_path: String,
    provider: RootProvider,
    /// How often a bad block should happen
    bad_block_timing: u64,
}

#[cfg(feature = "bad-blocks")]
impl BadBlockEngineClient {
    pub async fn new(engine_ipc_path: String, bad_block_timing: u64) -> Self {
        let ipc = IpcConnect::new(engine_ipc_path.clone());
        let provider = ProviderBuilder::default().connect_ipc(ipc).await.unwrap();
        Self {
            provider,
            engine_ipc_path,
            bad_block_timing,
        }
    }

    pub async fn wait_until_reconnect_available(&mut self) {
        loop {
            let ipc = IpcConnect::new(self.engine_ipc_path.clone());

            match ProviderBuilder::default().connect_ipc(ipc).await {
                Ok(provider) => {
                    self.provider = provider;
                    break;
                }
                Err(e) => {
                    error!("Failed to connect to IPC, retrying: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

#[cfg(feature = "bad-blocks")]
impl EngineClient for BadBlockEngineClient {
    async fn start_building_block(
        &mut self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        suggested_fee_recipient: Address,
        parent_beacon_block_root: Option<FixedBytes<32>>,
        #[cfg(feature = "bench")] _height: u64,
    ) -> Result<Option<PayloadId>, EngineClientError> {
        let payload_attributes = PayloadAttributes {
            timestamp,
            prev_randao: [0; 32].into(),
            suggested_fee_recipient,
            withdrawals: Some(withdrawals),
            parent_beacon_block_root,
        };

        let res = match self
            .provider
            .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes.clone()))
            .await
        {
            Ok(res) => res,
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
                    .await
                    .map_err(EngineClientError::from)?
            }
            Err(e) => return Err(EngineClientError::from(e)),
        };

        if res.is_invalid() {
            error!("invalid returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }
        if res.is_syncing() {
            warn!("syncing returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }

        Ok(res.payload_id)
    }

    async fn get_payload(
        &mut self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayloadEnvelopeV4, EngineClientError> {
        match self.provider.get_payload_v4(payload_id).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .get_payload_v4(payload_id)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }

    async fn check_payload(&mut self, block: &Block) -> Result<PayloadStatus, EngineClientError> {
        let parent_beacon_block_root = if block.view().is_multiple_of(self.bad_block_timing) {
            [1; 32].into()
        } else {
            block.header.parent_beacon_block_root.into()
        };

        match self
            .provider
            .new_payload_v4(
                block.payload.clone(),
                Vec::new(),
                parent_beacon_block_root,
                block.execution_requests.clone(),
            )
            .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .new_payload_v4(
                        block.payload.clone(),
                        Vec::new(),
                        block.header.parent_beacon_block_root.into(),
                        block.execution_requests.clone(),
                    )
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }

    async fn commit_hash(
        &mut self,
        fork_choice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, EngineClientError> {
        match self
            .provider
            .fork_choice_updated_v3(fork_choice_state, None)
            .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await;
                self.provider
                    .fork_choice_updated_v3(fork_choice_state, None)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }
}

#[cfg(feature = "bench")]
pub mod benchmarking {
    use crate::engine_client::{EngineClient, EngineClientError};
    use crate::{Block, Digest};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::{Address, B256, FixedBytes, U256};
    use alloy_provider::{ProviderBuilder, RootProvider, ext::EngineApi};
    use alloy_rpc_types_engine::{
        ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV3,
        ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus,
    };
    use alloy_transport_ipc::IpcConnect;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::path::PathBuf;

    #[derive(Clone)]
    pub struct EthereumHistoricalEngineClient {
        provider: RootProvider,
        block_dir: PathBuf,
    }

    impl EthereumHistoricalEngineClient {
        pub async fn new(engine_ipc_path: String, block_dir: PathBuf) -> Self {
            let ipc = IpcConnect::new(engine_ipc_path);
            let provider = ProviderBuilder::default().connect_ipc(ipc).await.unwrap();

            Self {
                provider,
                block_dir,
            }
        }
    }

    impl EngineClient for EthereumHistoricalEngineClient {
        async fn start_building_block(
            &mut self,
            _fork_choice_state: ForkchoiceState,
            _timestamp: u64,
            _withdrawals: Vec<Withdrawal>,
            _suggested_fee_recipient: Address,
            _parent_beacon_block_hash: Option<FixedBytes<32>>,
            #[cfg(feature = "bench")] height: u64,
        ) -> Result<Option<PayloadId>, EngineClientError> {
            let next_block_num = height + 1;
            Ok(Some(PayloadId::new(next_block_num.to_le_bytes())))
        }

        async fn get_payload(
            &mut self,
            payload_id: PayloadId,
        ) -> Result<ExecutionPayloadEnvelopeV4, EngineClientError> {
            let block_num = u64::from_le_bytes(payload_id.0.into());
            let filename = format!("block-{block_num}");
            let file_path = self.block_dir.join(filename);

            let data = fs::read(&file_path)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to read block file {}: {}", file_path.display(), e)
                })
                .expect("failed to read block file");

            let block_data: ExecutionPayloadV3 =
                ssz::Decode::from_ssz_bytes(&data).expect("failed to read block file");

            // Convert to ExecutionPayloadEnvelopeV4 with correct structure
            Ok(ExecutionPayloadEnvelopeV4 {
                envelope_inner: ExecutionPayloadEnvelopeV3 {
                    execution_payload: block_data,
                    block_value: U256::ZERO,
                    blobs_bundle: Default::default(),
                    should_override_builder: false,
                },
                execution_requests: Requests::default(),
            })
        }

        async fn check_payload(
            &mut self,
            block: &Block,
        ) -> Result<PayloadStatus, EngineClientError> {
            // For Ethereum, use standard engine_newPayloadV4 without Optimism-specific logic
            self.provider
                .new_payload_v4(
                    block.payload.clone(),
                    Vec::new(),     // versioned_hashes - empty for historical blocks
                    [1; 32].into(), // parent_beacon_block_root
                    block.execution_requests.clone(), // execution_requests
                )
                .await
                .map_err(EngineClientError::from)
        }

        async fn commit_hash(
            &mut self,
            fork_choice_state: ForkchoiceState,
        ) -> Result<ForkchoiceUpdated, EngineClientError> {
            self.provider
                .fork_choice_updated_v3(fork_choice_state, None)
                .await
                .map_err(EngineClientError::from)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EthereumBlockData {
        pub block_number: u64,
        pub payload: ExecutionPayloadV3,
        pub requests: FixedBytes<32>,
        pub parent_beacon_block_root: B256,
        pub versioned_hashes: Vec<B256>,
    }

    impl EthereumBlockData {
        pub fn from_file(file_path: &PathBuf) -> anyhow::Result<Self> {
            let json_data = fs::read_to_string(file_path)?;
            let block_data: EthereumBlockData = serde_json::from_str(&json_data)?;
            Ok(block_data)
        }

        pub fn to_block(self, parent: Digest, height: u64, timestamp: u64, view: u64) -> Block {
            // Create execution requests from the stored requests hash
            let execution_requests = Vec::new(); // Convert from self.requests if needed

            // Compute and return the entire block
            Block::compute_digest(
                parent,
                height,
                timestamp,
                self.payload,
                execution_requests,
                0, // epoch
                view,
                None,                    // checkpoint_hash
                Digest::from([0u8; 32]), // prev_epoch_header_hash
                Vec::new(),              // added_validators
                Vec::new(),              // removed_validators
                [0u8; 32],               // parent_beacon_block_root
            )
        }
    }
}
