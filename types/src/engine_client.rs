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
use alloy_provider::{ProviderBuilder, RootProvider, ext::EngineApi};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV4, ForkchoiceState, PayloadAttributes, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::Block;
use alloy_primitives::B256;
use alloy_transport_ipc::IpcConnect;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use std::future::Future;

#[derive(Debug, Error)]
pub enum EngineClientError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid forkchoice state")]
    InvalidForkchoice(String),

    #[error("Payload status is invalid: {0:?}")]
    InvalidPayload(String),

    #[error("Engine is syncing")]
    Syncing,

    #[error("Payload not found or not ready")]
    PayloadNotReady,
}

pub trait EngineClient: Clone + Send + Sync + 'static {
    /// Start building a new block on top of a specific parent block
    ///
    /// This is Phase 1 of block building: tell reth to start constructing a block
    /// on top of the specified parent. The parent must already be executed via
    /// `execute_block_optimistically` or this will return SYNCING.
    ///
    /// # Arguments
    /// * `parent_block_hash` - The block to build on top of (current head)
    /// * `safe_block_hash` - The safe/justified block
    /// * `finalized_block_hash` - The finalized block
    /// * `timestamp` - Timestamp for the new block
    /// * `withdrawals` - Validator withdrawals for this block
    ///
    /// # Returns
    /// * `PayloadId` - Use this to retrieve the built block with `get_payload`
    ///
    /// # Engine API
    /// Calls: `engine_forkchoiceUpdatedV3` with payload attributes
    fn start_building_block(
        &self,
        parent_block_hash: B256,
        safe_block_hash: B256,
        finalized_block_hash: B256,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        #[cfg(feature = "bench")] height: u64,
    ) -> impl Future<Output = Result<PayloadId, EngineClientError>> + Send;

    /// Retrieve a built payload by its ID
    ///
    /// This is Phase 2 of block building: retrieve the payload that reth built.
    /// Call this after `start_building_block` returns a payload ID.
    ///
    /// # Arguments
    /// * `payload_id` - The payload ID returned from `start_building_block`
    ///
    /// # Returns
    /// * `ExecutionPayloadEnvelopeV4` - The built block payload with execution requests
    ///
    /// # Engine API
    /// Calls: `engine_getPayloadV4`
    fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Result<ExecutionPayloadEnvelopeV4, EngineClientError>> + Send;

    /// Execute and validate a block optimistically
    ///
    /// This adds the block to reth's fork tree but does NOT make it canonical.
    /// The block is fully executed (transactions run, state root computed) and
    /// stored in memory as part of a potential fork.
    ///
    /// # Arguments
    /// * `payload` - The execution payload to validate
    /// * `execution_requests` - Execution requests (deposits, withdrawals, etc.)
    ///
    /// # Returns
    /// * `PayloadStatus` - VALID, INVALID, ACCEPTED, or SYNCING
    ///
    /// # Notes
    /// - If you submit blocks in order (parent before child), this should never return SYNCING
    /// - After this returns VALID, the block is executed but not yet canonical
    /// - Call `set_canonical_head` to make it canonical
    /// - Multiple competing blocks can be executed at the same height (multiple forks)
    /// - Execution is expensive (runs all transactions), but only happens once
    ///
    /// # Engine API
    /// Calls: `engine_newPayloadV4`
    fn execute_block_optimistically<C: Signer, V: Variant>(
        &self,
        block: &Block<C, V>,
    ) -> impl Future<Output = Result<PayloadStatus, EngineClientError>> + Send;

    /// Set the canonical chain head
    ///
    /// This tells reth which fork is the canonical chain. The specified blocks
    /// must already be executed via `execute_block_optimistically`, or this will
    /// return SYNCING.
    ///
    /// This operation is FAST because blocks are already executed - reth just:
    /// 1. Marks them as canonical (in-memory update)
    /// 2. Updates internal state trackers
    /// 3. Triggers async persistence to database
    ///
    /// NO re-execution happens here!
    ///
    /// # Arguments
    /// * `head_block_hash` - The new canonical head
    /// * `safe_block_hash` - The new safe block
    /// * `finalized_block_hash` - The new finalized block
    ///
    /// # Invariant
    /// These blocks must form a chain: finalized → safe → head
    ///
    /// # Notes
    /// - Blocks must be executed first via `execute_block_optimistically`
    /// - This operation is instant (~10-50ms, just in-memory updates)
    /// - Finalized blocks allow reth to prune competing forks
    /// - Persistence to database happens asynchronously in the background
    ///
    /// # Engine API
    /// Calls: `engine_forkchoiceUpdatedV3` without payload attributes
    fn set_canonical_head(
        &self,
        head_block_hash: B256,
        safe_block_hash: B256,
        finalized_block_hash: B256,
    ) -> impl Future<Output = Result<(), EngineClientError>> + Send;
}

#[derive(Clone)]
pub struct RethEngineClient {
    provider: RootProvider,
}

impl RethEngineClient {
    pub async fn new(engine_ipc_path: String) -> Self {
        let ipc = IpcConnect::new(engine_ipc_path);
        let provider = ProviderBuilder::default().connect_ipc(ipc).await.unwrap();
        Self { provider }
    }
}

impl EngineClient for RethEngineClient {
    async fn start_building_block(
        &self,
        parent_block_hash: B256,
        safe_block_hash: B256,
        finalized_block_hash: B256,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        #[cfg(feature = "bench")] _height: u64,
    ) -> Result<PayloadId, EngineClientError> {
        let fork_choice_state = ForkchoiceState {
            head_block_hash: parent_block_hash,
            safe_block_hash,
            finalized_block_hash,
        };

        let payload_attributes = PayloadAttributes {
            timestamp,
            // TODO: Replace with actual randao from consensus layer
            prev_randao: B256::from([0u8; 32]),
            suggested_fee_recipient: [1; 20].into(),
            withdrawals: Some(withdrawals),
            // TODO: Replace with actual beacon block root from consensus layer
            parent_beacon_block_root: Some(B256::from([1u8; 32])),
        };

        debug!(
            target: "engine::client",
            parent = %parent_block_hash,
            timestamp = timestamp,
            "Starting block build"
        );

        let response = self
            .provider
            .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
            .await
            .map_err(|e| EngineClientError::RpcError(e.to_string()))?;

        match response.payload_status.status {
            PayloadStatusEnum::Valid | PayloadStatusEnum::Accepted => {
                let payload_id = response
                    .payload_id
                    .ok_or(EngineClientError::PayloadNotReady)?;

                debug!(
                    target: "engine::client",
                    ?payload_id,
                    "Block build started"
                );
                Ok(payload_id)
            }
            PayloadStatusEnum::Syncing => {
                warn!(
                    target: "engine::client",
                    parent = %parent_block_hash,
                    "Engine syncing - parent block not found"
                );
                Err(EngineClientError::Syncing)
            }
            PayloadStatusEnum::Invalid {
                ref validation_error,
            } => {
                error!(
                    target: "engine::client",
                    parent = %parent_block_hash,
                    ?response,
                    "Invalid forkchoice state: {validation_error}",
                );
                Err(EngineClientError::InvalidForkchoice(
                    validation_error.clone(),
                ))
            }
        }
    }

    async fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> Result<ExecutionPayloadEnvelopeV4, EngineClientError> {
        debug!(
            target: "engine::client",
            ?payload_id,
            "Retrieving payload"
        );

        let payload_envelope = self
            .provider
            .get_payload_v4(payload_id)
            .await
            .map_err(|e| EngineClientError::RpcError(e.to_string()))?;

        debug!(
            target: "engine::client",
            block_hash = %payload_envelope.execution_payload.payload_inner.payload_inner.block_hash,
            block_number = payload_envelope.execution_payload.payload_inner.payload_inner.block_number,
            tx_count = payload_envelope.execution_payload.payload_inner.payload_inner.transactions.len(),
            "Payload retrieved"
        );

        Ok(payload_envelope)
    }

    async fn execute_block_optimistically<C: Signer, V: Variant>(
        &self,
        block: &Block<C, V>,
    ) -> Result<PayloadStatus, EngineClientError> {
        execute_block_optimistically(&self.provider, block).await
    }

    async fn set_canonical_head(
        &self,
        head_block_hash: B256,
        safe_block_hash: B256,
        finalized_block_hash: B256,
    ) -> Result<(), EngineClientError> {
        set_canonical_head(
            &self.provider,
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        )
        .await
    }
}

async fn execute_block_optimistically<C: Signer, V: Variant>(
    provider: &RootProvider,
    block: &Block<C, V>,
) -> Result<PayloadStatus, EngineClientError> {
    debug!(
        target: "engine::client",
        block_hash = %block.payload.payload_inner.payload_inner.block_hash,
        block_number = block.payload.payload_inner.payload_inner.block_number,
        parent = %block.payload.payload_inner.payload_inner.parent_hash,
        "Executing block optimistically"
    );

    // TODO: Extract versioned hashes from blob transactions
    // For now, assume no blob transactions
    let versioned_hashes = Vec::new();

    // TODO: Replace with actual beacon block root
    let parent_beacon_block_root = B256::from([1u8; 32]);

    let status = provider
        .new_payload_v4(
            block.payload.clone(),
            versioned_hashes,
            parent_beacon_block_root,
            block.execution_requests.clone(),
        )
        .await
        .map_err(|e| EngineClientError::RpcError(e.to_string()))?;

    match status.status {
        PayloadStatusEnum::Valid => {
            debug!(
                target: "engine::client",
                block_hash = %block.payload.payload_inner.payload_inner.block_hash,
                "Block is VALID"
            );
            Ok(status)
        }
        PayloadStatusEnum::Accepted => {
            debug!(
                target: "engine::client",
                block_hash = %block.payload.payload_inner.payload_inner.block_hash,
                "Block is ACCEPTED (optimistic)"
            );
            Ok(status)
        }
        PayloadStatusEnum::Invalid {
            ref validation_error,
        } => {
            error!(
                target: "engine::client",
                block_hash = %block.payload.payload_inner.payload_inner.block_hash,
                ?status,
                "Block is INVALID: {validation_error}"
            );
            Err(EngineClientError::InvalidPayload(validation_error.clone()))
        }
        PayloadStatusEnum::Syncing => {
            warn!(
                target: "engine::client",
                block_hash = %block.payload.payload_inner.payload_inner.block_hash,
                parent = %block.payload.payload_inner.payload_inner.parent_hash,
                "Block is SYNCING (parent missing)"
            );
            Ok(status)
        }
    }
}

async fn set_canonical_head(
    provider: &RootProvider,
    head_block_hash: B256,
    safe_block_hash: B256,
    finalized_block_hash: B256,
) -> Result<(), EngineClientError> {
    debug!(
        target: "engine::client",
        head = %head_block_hash,
        safe = %safe_block_hash,
        finalized = %finalized_block_hash,
        "Setting canonical head"
    );

    let fork_choice_state = ForkchoiceState {
        head_block_hash,
        safe_block_hash,
        finalized_block_hash,
    };

    let response = provider
        .fork_choice_updated_v3(fork_choice_state, None)
        .await
        .map_err(|e| EngineClientError::RpcError(e.to_string()))?;

    match response.payload_status.status {
        PayloadStatusEnum::Valid | PayloadStatusEnum::Accepted => {
            debug!(
                target: "engine::client",
                head = %head_block_hash,
                "Canonical head set"
            );
            Ok(())
        }
        PayloadStatusEnum::Syncing => {
            warn!(
                target: "engine::client",
                head = %head_block_hash,
                "⏳ Engine syncing - head block not executed yet"
            );
            Err(EngineClientError::Syncing)
        }
        PayloadStatusEnum::Invalid {
            ref validation_error,
        } => {
            error!(
                target: "engine::client",
                head = %head_block_hash,
                ?response,
                "Invalid forkchoice"
            );
            Err(EngineClientError::InvalidForkchoice(
                validation_error.clone(),
            ))
        }
    }
}

#[cfg(feature = "bench")]
pub mod benchmarking {
    use crate::engine_client::{EngineClient, execute_block_optimistically, set_canonical_head};
    use crate::{Block, EngineClientError};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::{B256, U256};
    use alloy_provider::{ProviderBuilder, RootProvider};
    use alloy_rpc_types_engine::{
        ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV3, PayloadId,
        PayloadStatus,
    };
    use alloy_transport_ipc::IpcConnect;
    use commonware_cryptography::Signer;
    use commonware_cryptography::bls12381::primitives::variant::Variant;
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
            &self,
            _parent_block_hash: B256,
            _safe_block_hash: B256,
            _finalized_block_hash: B256,
            _timestamp: u64,
            _withdrawals: Vec<Withdrawal>,
            #[cfg(feature = "bench")] height: u64,
        ) -> Result<PayloadId, EngineClientError> {
            let next_block_num = height + 1;
            Ok(PayloadId::new(next_block_num.to_le_bytes()))
        }

        async fn get_payload(
            &self,
            payload_id: PayloadId,
        ) -> Result<ExecutionPayloadEnvelopeV4, EngineClientError> {
            let block_num = u64::from_le_bytes(payload_id.0.into());
            let filename = format!("block-{block_num}");
            let file_path = self.block_dir.join(filename);

            let data = fs::read(&file_path).map_err(|e| {
                EngineClientError::RpcError(format!(
                    "failed to read block file {}: {}",
                    file_path.display(),
                    e
                ))
            })?;

            let block_data: ExecutionPayloadV3 =
                ssz::Decode::from_ssz_bytes(&data).map_err(|e| {
                    EngineClientError::RpcError(format!(
                        "failed to parse payload for file {}: {:?}",
                        file_path.display(),
                        e
                    ))
                })?;

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

        async fn execute_block_optimistically<C: Signer, V: Variant>(
            &self,
            block: &Block<C, V>,
        ) -> Result<PayloadStatus, EngineClientError> {
            execute_block_optimistically(&self.provider, block).await
        }

        async fn set_canonical_head(
            &self,
            head_block_hash: B256,
            safe_block_hash: B256,
            finalized_block_hash: B256,
        ) -> Result<(), EngineClientError> {
            set_canonical_head(
                &self.provider,
                head_block_hash,
                safe_block_hash,
                finalized_block_hash,
            )
            .await
        }
    }
}
