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
};
use tracing::{error, warn};

use crate::Block;
use alloy_transport_ipc::IpcConnect;
use std::future::Future;

pub trait EngineClient: Clone + Send + Sync + 'static {
    fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        #[cfg(any(feature = "bench", feature = "base-bench"))] height: u64,
    ) -> impl Future<Output = Option<PayloadId>> + Send;

    fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = ExecutionPayloadEnvelopeV4> + Send;

    fn check_payload(&self, block: &Block) -> impl Future<Output = PayloadStatus> + Send;

    fn commit_hash(&self, fork_choice_state: ForkchoiceState) -> impl Future<Output = ()> + Send;
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
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
        #[cfg(any(feature = "bench", feature = "base-bench"))] _height: u64,
    ) -> Option<PayloadId> {
        let payload_attributes = PayloadAttributes {
            timestamp,
            prev_randao: [0; 32].into(),
            // todo(dalton): this should be the validators public key
            suggested_fee_recipient: [1; 20].into(),
            withdrawals: Some(withdrawals),
            // todo(dalton): we should make this something that we can associate with the simplex height
            parent_beacon_block_root: Some([1; 32].into()),
        };
        let res = self
            .provider
            .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
            .await
            .unwrap();

        if res.is_invalid() {
            error!("invalid returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }
        if res.is_syncing() {
            warn!("syncing returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }

        res.payload_id
    }

    async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
        self.provider.get_payload_v4(payload_id).await.unwrap()
    }

    async fn check_payload(&self, block: &Block) -> PayloadStatus {
        self.provider
            .new_payload_v4(
                block.payload.clone(),
                Vec::new(),
                [1; 32].into(),
                block.execution_requests.clone(),
            )
            .await
            .unwrap()
    }

    async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
        self.provider
            .fork_choice_updated_v3(fork_choice_state, None)
            .await
            .unwrap();
    }
}

#[cfg(feature = "base-bench")]
pub mod base_benchmarking {
    use crate::engine_client::EngineClient;
    use crate::utils::benchmarking::BlockIndex;
    use crate::{Block, Digest};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::{B256, FixedBytes, U256};
    use alloy_provider::{Provider, ProviderBuilder, RootProvider, ext::EngineApi};
    use alloy_rpc_types_engine::{
        ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV3,
        ForkchoiceState, PayloadId, PayloadStatus,
    };
    use alloy_transport_ipc::IpcConnect;
    use op_alloy_network::Optimism;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::path::PathBuf;

    #[derive(Clone)]
    pub struct HistoricalEngineClient {
        provider: RootProvider<Optimism>,
        block_dir: PathBuf,
        block_index: BlockIndex,
    }

    impl HistoricalEngineClient {
        pub async fn new(engine_ipc_path: String, block_dir: PathBuf) -> Self {
            let ipc = IpcConnect::new(engine_ipc_path);
            let provider: RootProvider<Optimism> =
                ProviderBuilder::default().connect_ipc(ipc).await.unwrap();

            let index_path = block_dir.join("index.json");
            let block_index =
                BlockIndex::load_from_file(&index_path).expect("failed to load block index");

            Self {
                provider,
                block_dir,
                block_index,
            }
        }
    }

    impl EngineClient for HistoricalEngineClient {
        async fn start_building_block(
            &self,
            fork_choice_state: ForkchoiceState,
            _timestamp: u64,
            _withdrawals: Vec<Withdrawal>,
            #[cfg(any(feature = "bench", feature = "base-bench"))] _height: u64,
        ) -> Option<PayloadId> {
            let block_num = self
                .block_index
                .get_block_number(&fork_choice_state.head_block_hash)?;
            let next_block_num = block_num + 1;
            if self.block_index.get_block_file(next_block_num).is_some() {
                let bytes: [u8; 8] = next_block_num.to_le_bytes();
                Some(PayloadId::new(bytes))
            } else {
                None
            }
        }

        async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
            let block_num = u64::from_le_bytes(payload_id.0.into());
            let filename = self
                .block_index
                .get_block_file(block_num)
                .expect("block not found in index");

            let file_path = self.block_dir.join(filename);

            let json_data = fs::read_to_string(&file_path)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to read block file {}: {}", file_path.display(), e)
                })
                .expect("failed to read block file");

            let block_data: BlockData = serde_json::from_str(&json_data)
                .map_err(|e| anyhow::anyhow!("Failed to parse block data: {}", e))
                .expect("failed to parse block data");

            // TODO(matthias): we throw away the execution requests and some other data here

            // Convert to ExecutionPayloadEnvelopeV4 with correct structure
            ExecutionPayloadEnvelopeV4 {
                envelope_inner: ExecutionPayloadEnvelopeV3 {
                    execution_payload: block_data.payload,
                    block_value: U256::ZERO, // Historical blocks don't have block value
                    blobs_bundle: Default::default(), // No blobs in historical blocks
                    should_override_builder: false,
                },
                execution_requests: Requests::default(),
            }
        }

        async fn check_payload(&self, block: &Block) -> PayloadStatus {
            let timestamp = block.payload.payload_inner.payload_inner.timestamp;
            let canyon_activation = 1704992401u64; // January 11, 2024 - Canyon activation on Base

            if timestamp < canyon_activation {
                // Pre-Canyon: construct payload without withdrawals field at all
                //let payload_v1_only = ExecutionPayloadV3 {
                //    payload_inner: alloy_rpc_types_engine::ExecutionPayloadV2 {
                //        payload_inner: block.payload.payload_inner.payload_inner.clone(),
                //        withdrawals: Vec::new(), // This should be removed entirely, but can't with current types
                //    },
                //    blob_gas_used: 0,
                //    excess_blob_gas: 0,
                //};

                // For pre-Canyon blocks, use engine_newPayloadV1 with only V1 fields
                let payload_v1_json = serde_json::json!({
                    "parentHash": block.payload.payload_inner.payload_inner.parent_hash,
                    "feeRecipient": block.payload.payload_inner.payload_inner.fee_recipient,
                    "stateRoot": block.payload.payload_inner.payload_inner.state_root,
                    "receiptsRoot": block.payload.payload_inner.payload_inner.receipts_root,
                    "logsBloom": block.payload.payload_inner.payload_inner.logs_bloom,
                    "prevRandao": block.payload.payload_inner.payload_inner.prev_randao,
                    "blockNumber": format!("0x{:x}", block.payload.payload_inner.payload_inner.block_number),
                    "gasLimit": format!("0x{:x}", block.payload.payload_inner.payload_inner.gas_limit),
                    "gasUsed": format!("0x{:x}", block.payload.payload_inner.payload_inner.gas_used),
                    "timestamp": format!("0x{:x}", block.payload.payload_inner.payload_inner.timestamp),
                    "extraData": block.payload.payload_inner.payload_inner.extra_data,
                    "baseFeePerGas": format!("0x{:x}", block.payload.payload_inner.payload_inner.base_fee_per_gas),
                    "blockHash": block.payload.payload_inner.payload_inner.block_hash,
                    "transactions": block.payload.payload_inner.payload_inner.transactions
                    // No withdrawals, withdrawalsRoot, blobGasUsed, or excessBlobGas for V1
                });

                self.provider
                    .client()
                    .request("engine_newPayloadV2", (payload_v1_json,))
                    .await
                    .unwrap()
            } else {
                // Post-Canyon: use OpExecutionPayloadV4 (with withdrawals)
                let op_payload = op_alloy_rpc_types_engine::OpExecutionPayloadV4 {
                    payload_inner: block.payload.clone(),
                    withdrawals_root: B256::ZERO, // Calculate from withdrawals if needed
                };

                let params = (
                    op_payload,
                    Vec::<B256>::new(),    // versioned_hashes - empty for Optimism
                    B256::from([1u8; 32]), // parent_beacon_block_root
                    Vec::<alloy_primitives::Bytes>::new(), // execution_requests - empty for Optimism
                );

                self.provider
                    .client()
                    .request("engine_newPayloadV4", params)
                    .await
                    .unwrap()
            }
        }

        async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
            self.provider
                .fork_choice_updated_v3(fork_choice_state, None)
                .await
                .unwrap();
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct BlockData {
        pub block_number: u64,
        pub payload: ExecutionPayloadV3,
        pub requests: FixedBytes<32>,
        pub parent_beacon_block_root: B256,
        pub versioned_hashes: Vec<B256>,
    }

    impl BlockData {
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
                U256::ZERO, // block_value
                view,
                None,
                [0u8; 32].into(),
                Vec::new(), // added_validators
                Vec::new(), // removed_validators
            )
        }
    }
}

#[cfg(feature = "bench")]
pub mod benchmarking {
    use crate::engine_client::EngineClient;
    use crate::{Block, Digest};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::{B256, FixedBytes, U256};
    use alloy_provider::{ProviderBuilder, RootProvider, ext::EngineApi};
    use alloy_rpc_types_engine::{
        ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV3,
        ForkchoiceState, PayloadId, PayloadStatus,
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
            &self,
            _fork_choice_state: ForkchoiceState,
            _timestamp: u64,
            _withdrawals: Vec<Withdrawal>,
            #[cfg(any(feature = "bench", feature = "base-bench"))] height: u64,
        ) -> Option<PayloadId> {
            let next_block_num = height + 1;
            Some(PayloadId::new(next_block_num.to_le_bytes()))
        }

        async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
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
            ExecutionPayloadEnvelopeV4 {
                envelope_inner: ExecutionPayloadEnvelopeV3 {
                    execution_payload: block_data,
                    block_value: U256::ZERO,
                    blobs_bundle: Default::default(),
                    should_override_builder: false,
                },
                execution_requests: Requests::default(),
            }
        }

        async fn check_payload(&self, block: &Block) -> PayloadStatus {
            // For Ethereum, use standard engine_newPayloadV4 without Optimism-specific logic
            self.provider
                .new_payload_v4(
                    block.payload.clone(),
                    Vec::new(),     // versioned_hashes - empty for historical blocks
                    [1; 32].into(), // parent_beacon_block_root
                    block.execution_requests.clone(), // execution_requests
                )
                .await
                .unwrap()
        }

        async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
            self.provider
                .fork_choice_updated_v3(fork_choice_state, None)
                .await
                .unwrap();
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
                U256::ZERO, // block_value
                view,
                None,             // checkpoint_hash
                [0u8; 32].into(), // prev_epoch_header_hash
                Vec::new(),       // added_validators
                Vec::new(),       // removed_validators
            )
        }
    }
}
