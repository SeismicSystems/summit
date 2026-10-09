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
use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadId, PayloadStatus,
};
use reth_seismic_engine_types::{
    SeismicExecutionPayloadEnvelopeV4, SeismicExecutionPayloadV3, SeismicPayloadAttributes,
};
use tracing::{error, warn};

use crate::Block;
use alloy_transport::{TransportError, TransportErrorKind, TransportResult};
use alloy_transport_ipc::IpcConnect;
use std::future::Future;

/// Seismic's Engine API carries the sub-second block timestamp in extended payload attribute
/// and execution payload types (see `reth_seismic_engine_types`). `alloy_provider`'s `EngineApi`
/// extension is fixed to the stock types, so the three Seismic-typed methods are issued as raw
/// JSON-RPC requests. Everything else about the Engine API is unchanged.
async fn fork_choice_updated_v3(
    provider: &RootProvider,
    fork_choice_state: ForkchoiceState,
    payload_attributes: Option<SeismicPayloadAttributes>,
) -> TransportResult<ForkchoiceUpdated> {
    provider
        .client()
        .request(
            "engine_forkchoiceUpdatedV3",
            (fork_choice_state, payload_attributes),
        )
        .await
}

async fn get_payload_v4(
    provider: &RootProvider,
    payload_id: PayloadId,
) -> TransportResult<SeismicExecutionPayloadEnvelopeV4> {
    provider
        .client()
        .request("engine_getPayloadV4", (payload_id,))
        .await
}

async fn new_payload_v4(
    provider: &RootProvider,
    payload: &SeismicExecutionPayloadV3,
    versioned_hashes: Vec<FixedBytes<32>>,
    parent_beacon_block_root: FixedBytes<32>,
    execution_requests: &[Bytes],
) -> TransportResult<PayloadStatus> {
    provider
        .client()
        .request(
            "engine_newPayloadV4",
            (
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests,
            ),
        )
        .await
}

/// Builds Seismic payload attributes from a Unix **millisecond** block time: the stock
/// `timestamp` gets the seconds, `timestampMillisPart` the remainder.
fn payload_attributes(
    timestamp_millis: u64,
    withdrawals: Vec<Withdrawal>,
    suggested_fee_recipient: Address,
    parent_beacon_block_root: Option<FixedBytes<32>>,
) -> SeismicPayloadAttributes {
    SeismicPayloadAttributes::from_timestamp_millis(
        PayloadAttributes {
            timestamp: 0,
            prev_randao: [0; 32].into(),
            suggested_fee_recipient,
            withdrawals: Some(withdrawals),
            parent_beacon_block_root,
        },
        timestamp_millis,
    )
}

/// The number of times the engine client will try to reconnect
/// after failing to connect to the IPC socket.
const IPC_CONNECT_MAX_RETRIES: u32 = 200;

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

impl EngineClientError {
    /// Construct a custom, non-retryable engine-client error from a message.
    /// Primarily for tests that simulate an execution-client failure (e.g. a
    /// failed forkchoice commit at an epoch boundary).
    pub fn custom(msg: &str) -> Self {
        EngineClientError(TransportErrorKind::custom_str(msg))
    }
}

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
    /// Starts building a block at the given Unix **millisecond** timestamp.
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
    ) -> impl Future<Output = Result<SeismicExecutionPayloadEnvelopeV4, EngineClientError>> + Send;

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

    /// Try to reconnect the IPC provider, retrying up to
    /// [`IPC_CONNECT_MAX_RETRIES`] times. Returns `Ok(())` once reconnected, or
    /// `Err` carrying the last transport error if the attempts are exhausted, so
    /// callers surface "reconnect attempts exhausted" instead of retrying against
    /// a stale provider that is still disconnected.
    pub async fn wait_until_reconnect_available(&mut self) -> Result<(), EngineClientError> {
        let mut last_err = None;
        for attempt in 1..=IPC_CONNECT_MAX_RETRIES {
            let ipc = IpcConnect::new(self.engine_ipc_path.clone());

            match ProviderBuilder::default().connect_ipc(ipc).await {
                Ok(provider) => {
                    self.provider = provider;
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to connect to IPC (attempt {attempt}/{IPC_CONNECT_MAX_RETRIES}), retrying: {e}"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
        error!("exhausted {IPC_CONNECT_MAX_RETRIES} IPC reconnect attempts; giving up");
        Err(EngineClientError::from(last_err.expect(
            "IPC_CONNECT_MAX_RETRIES is non-zero, so at least one attempt ran",
        )))
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
        let payload_attributes = payload_attributes(
            timestamp,
            withdrawals,
            suggested_fee_recipient,
            parent_beacon_block_root,
        );

        let res = match fork_choice_updated_v3(
            &self.provider,
            fork_choice_state,
            Some(payload_attributes.clone()),
        )
        .await
        {
            Ok(res) => res,
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                fork_choice_updated_v3(&self.provider, fork_choice_state, Some(payload_attributes))
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
    ) -> Result<SeismicExecutionPayloadEnvelopeV4, EngineClientError> {
        match get_payload_v4(&self.provider, payload_id).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                get_payload_v4(&self.provider, payload_id)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }

    async fn check_payload(&mut self, block: &Block) -> Result<PayloadStatus, EngineClientError> {
        // versioned_hashes is `Vec::new()` because Summit does not currently
        // support blob transactions: any payload with `blob_gas_used > 0` is
        // rejected at handle_verify time, so check_payload only ever sees
        // non-blob payloads.
        match new_payload_v4(
            &self.provider,
            &block.payload,
            Vec::new(),
            block.header.parent_beacon_block_root().into(),
            &block.execution_requests,
        )
        .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                new_payload_v4(
                    &self.provider,
                    &block.payload,
                    Vec::new(),
                    block.header.parent_beacon_block_root().into(),
                    &block.execution_requests,
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
        match fork_choice_updated_v3(&self.provider, fork_choice_state, None).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                fork_choice_updated_v3(&self.provider, fork_choice_state, None)
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

    /// Try to reconnect the IPC provider, retrying up to
    /// [`IPC_CONNECT_MAX_RETRIES`] times. Returns `Ok(())` once reconnected, or
    /// `Err` carrying the last transport error if the attempts are exhausted, so
    /// callers surface "reconnect attempts exhausted" instead of retrying against
    /// a stale provider that is still disconnected.
    pub async fn wait_until_reconnect_available(&mut self) -> Result<(), EngineClientError> {
        let mut last_err = None;
        for attempt in 1..=IPC_CONNECT_MAX_RETRIES {
            let ipc = IpcConnect::new(self.engine_ipc_path.clone());

            match ProviderBuilder::default().connect_ipc(ipc).await {
                Ok(provider) => {
                    self.provider = provider;
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Failed to connect to IPC (attempt {attempt}/{IPC_CONNECT_MAX_RETRIES}), retrying: {e}"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
        error!("exhausted {IPC_CONNECT_MAX_RETRIES} IPC reconnect attempts; giving up");
        Err(EngineClientError::from(last_err.expect(
            "IPC_CONNECT_MAX_RETRIES is non-zero, so at least one attempt ran",
        )))
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
        let payload_attributes = payload_attributes(
            timestamp,
            withdrawals,
            suggested_fee_recipient,
            parent_beacon_block_root,
        );

        let res = match fork_choice_updated_v3(
            &self.provider,
            fork_choice_state,
            Some(payload_attributes.clone()),
        )
        .await
        {
            Ok(res) => res,
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                fork_choice_updated_v3(&self.provider, fork_choice_state, Some(payload_attributes))
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
    ) -> Result<SeismicExecutionPayloadEnvelopeV4, EngineClientError> {
        match get_payload_v4(&self.provider, payload_id).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                get_payload_v4(&self.provider, payload_id)
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
            block.header.parent_beacon_block_root().into()
        };

        match new_payload_v4(
            &self.provider,
            &block.payload,
            Vec::new(),
            parent_beacon_block_root,
            &block.execution_requests,
        )
        .await
        {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                new_payload_v4(
                    &self.provider,
                    &block.payload,
                    Vec::new(),
                    block.header.parent_beacon_block_root().into(),
                    &block.execution_requests,
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
        match fork_choice_updated_v3(&self.provider, fork_choice_state, None).await {
            Ok(res) => Ok(res),
            Err(e) if e.is_transport_error() => {
                self.wait_until_reconnect_available().await?;
                fork_choice_updated_v3(&self.provider, fork_choice_state, None)
                    .await
                    .map_err(EngineClientError::from)
            }
            Err(e) => Err(EngineClientError::from(e)),
        }
    }
}

#[cfg(feature = "bench")]
pub mod benchmarking {
    use crate::Block;
    use crate::engine_client::{EngineClient, EngineClientError};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::{Address, FixedBytes, U256};
    use alloy_provider::{ProviderBuilder, RootProvider};
    use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus};
    use alloy_transport_ipc::IpcConnect;
    use reth_seismic_engine_types::{
        SeismicExecutionPayloadEnvelopeV3, SeismicExecutionPayloadEnvelopeV4,
        SeismicExecutionPayloadV3,
    };
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
        ) -> Result<SeismicExecutionPayloadEnvelopeV4, EngineClientError> {
            let block_num = u64::from_le_bytes(payload_id.0.into());
            let filename = format!("block-{block_num}");
            let file_path = self.block_dir.join(filename);

            let data = fs::read(&file_path)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to read block file {}: {}", file_path.display(), e)
                })
                .expect("failed to read block file");

            let block_data: SeismicExecutionPayloadV3 =
                ssz::Decode::from_ssz_bytes(&data).expect("failed to read block file");

            // Convert to the V4 envelope with correct structure
            Ok(SeismicExecutionPayloadEnvelopeV4 {
                envelope_inner: SeismicExecutionPayloadEnvelopeV3 {
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
            super::new_payload_v4(
                &self.provider,
                &block.payload,
                Vec::new(),     // versioned_hashes - empty for historical blocks
                [1; 32].into(), // parent_beacon_block_root
                &block.execution_requests,
            )
            .await
            .map_err(EngineClientError::from)
        }

        async fn commit_hash(
            &mut self,
            fork_choice_state: ForkchoiceState,
        ) -> Result<ForkchoiceUpdated, EngineClientError> {
            super::fork_choice_updated_v3(&self.provider, fork_choice_state, None)
                .await
                .map_err(EngineClientError::from)
        }
    }
}
