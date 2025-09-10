use anyhow::Result;

use std::{fs, path::PathBuf, str::FromStr as _, sync::Mutex};

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{B256, FixedBytes, U256};
use alloy_provider::{RootProvider, Provider, ext::EngineApi};
use op_alloy_network::Optimism;
use alloy_rpc_types_engine::{
    ExecutionPayloadV3, ForkchoiceState, JwtSecret, PayloadId, PayloadStatus,
};
use op_alloy_rpc_types_engine::OpExecutionPayloadEnvelopeV4;
use alloy_transport_http::{
    AuthLayer, AuthService, Http, HyperClient,
    hyper::body::Bytes as HyperBytes,
    hyper_util::{client::legacy::Client, rt::TokioExecutor},
};
use http_body_util::Full;
use serde::{Deserialize, Serialize};
use summit_types::{Block, Digest};
use tower::ServiceBuilder;

const STARTING_HISTORICAL_BLOCK: u64 = 0;
const BLOCK_DIR: &str = "/tmp/blocks";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let engine_url = "http://localhost:8551";
    let jwt_secret = "a0e59655e8a3017d0d7db047f1d138fbde22afd2a7e5345bd41fda618850539a";

    let client = HistoricalEngineClient::new(engine_url.to_string(), jwt_secret);

    // Load and commit blocks to Reth
    for _ in 0..50000 {
        match client.load_next_block() {
            Ok(block_data) => {
                let block_number = block_data.block_number;
                let block_hash = block_data.payload.payload_inner.payload_inner.block_hash;
                let parent_hash = block_data.payload.payload_inner.payload_inner.parent_hash;
                let timestamp = block_data.payload.payload_inner.payload_inner.timestamp;
                
                println!("Processing block {}: hash={:?}", block_number, block_hash);

                // Convert block data to Summit Block for check_payload
                let genesis_hash = [0xf7, 0x12, 0xaa, 0x92, 0x41, 0xcc, 0x24, 0x36, 0x9b, 0x14, 0x3c, 0xf6, 0xdc, 0xe8, 0x5f, 0x09, 0x02, 0xa9, 0x73, 0x1e, 0x70, 0xd6, 0x68, 0x18, 0xa3, 0xa5, 0x84, 0x5b, 0x29, 0x6c, 0x73, 0xdd];
                let parent_digest: Digest = if block_number == 0 { 
                    genesis_hash.into() 
                } else { 
                    (*parent_hash).into() 
                };
                let summit_block = block_data.to_block(
                    parent_digest,
                    block_number,
                    timestamp,
                    block_number, // use block number as view
                );

                // Check payload with Reth
                let payload_status = client.check_payload(&summit_block).await;
                println!("  Payload status: {:?}", payload_status);

                // Commit the block hash to Reth
                let fork_choice_state = ForkchoiceState {
                    head_block_hash: block_hash,
                    safe_block_hash: parent_hash,
                    finalized_block_hash: parent_hash,
                };

                client.commit_hash(fork_choice_state).await;
                println!("  Committed block {} to Reth", block_number);
            }
            Err(e) => {
                eprintln!("Failed to load block: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct HistoricalEngineClient {
    provider: RootProvider<Optimism>,
    block_dir: PathBuf,
    current_block: std::sync::Arc<Mutex<u64>>,
}

impl HistoricalEngineClient {
    pub fn new(engine_url: String, jwt_secret: &str) -> Self {
        let secret = JwtSecret::from_hex(jwt_secret).unwrap();
        let url = engine_url.parse().unwrap();

        // todo(dalton): bringing in Full here as a conveniance at the moment. If i dont end up using any of the benefits here we can switch to just Bytes and drop dep
        let hyper_client = Client::builder(TokioExecutor::new()).build_http::<Full<HyperBytes>>();
        let service = ServiceBuilder::new()
            .layer(AuthLayer::new(secret))
            .service(hyper_client);

        let layer_transport: HyperClient<
            Full<HyperBytes>,
            AuthService<
                Client<
                    alloy_transport_http::hyper_util::client::legacy::connect::HttpConnector,
                    Full<HyperBytes>,
                >,
            >,
        > = HyperClient::with_service(service);

        let http_hyper = Http::with_client(layer_transport, url);

        let rpc_client = alloy_rpc_client::RpcClient::new(http_hyper, true);

        let provider = RootProvider::<Optimism>::new(rpc_client);

        let block_dir = PathBuf::from_str(BLOCK_DIR).unwrap();
        Self {
            provider,
            block_dir,
            current_block: std::sync::Arc::new(Mutex::new(STARTING_HISTORICAL_BLOCK)),
        }
    }

    fn load_next_block(&self) -> Result<BlockData> {
        let mut current = self.current_block.lock().unwrap();
        let block_number = *current;
        *current += 1;

        let filename = format!("block_{}.json", block_number);
        let file_path = self.block_dir.join(&filename);
        
        let json_data = fs::read_to_string(&file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read block file {}: {}", file_path.display(), e))?;
        
        let block_data: BlockData = serde_json::from_str(&json_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse block data: {}", e))?;
        
        Ok(block_data)
    }
}

impl HistoricalEngineClient {
    // Custom implementation without the EngineClient trait
    async fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        _timestamp: u64,
        _withdrawals: Vec<Withdrawal>,
    ) -> Option<PayloadId> {
        
        Some(PayloadId::new([1u8; 8]))
    }

    async fn get_payload(&self, _payload_id: PayloadId) -> OpExecutionPayloadEnvelopeV4 {
        // Load the next historical block
        let block_data = self.load_next_block().expect("Failed to load next block");
        
        // Convert ExecutionPayloadV3 to OpExecutionPayloadV4 
        // OpExecutionPayloadV4 extends the regular ExecutionPayloadV3 with withdrawals_root
        let op_payload_v4 = op_alloy_rpc_types_engine::OpExecutionPayloadV4 {
            payload_inner: block_data.payload, // Use the ExecutionPayloadV3 directly
            withdrawals_root: B256::ZERO, // Calculate from withdrawals if needed
        };

        // Convert to OpExecutionPayloadEnvelopeV4 with correct structure
        OpExecutionPayloadEnvelopeV4 {
            execution_payload: op_payload_v4,
            block_value: U256::ZERO, // Historical blocks don't have block value
            blobs_bundle: Default::default(), // No blobs in historical blocks
            should_override_builder: false,
            parent_beacon_block_root: block_data.parent_beacon_block_root,
            execution_requests: Vec::new(), // No execution requests for historical blocks
        }
    }

    async fn check_payload(&self, block: &Block) -> PayloadStatus {
        let timestamp = block.payload.payload_inner.payload_inner.timestamp;
        let canyon_activation = 1704992401u64; // January 11, 2024 - Canyon activation on Base
        
        if timestamp < canyon_activation {
            // Pre-Canyon: construct payload without withdrawals field at all
            let payload_v1_only = ExecutionPayloadV3 {
                payload_inner: alloy_rpc_types_engine::ExecutionPayloadV2 {
                    payload_inner: block.payload.payload_inner.payload_inner.clone(),
                    withdrawals: Vec::new(), // This should be removed entirely, but can't with current types
                },
                blob_gas_used: 0,
                excess_blob_gas: 0,
            };
            
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
                Vec::<B256>::new(), // versioned_hashes - empty for Optimism
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
        )
    }
}
