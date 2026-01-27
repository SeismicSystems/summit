//! Mock implementations for finalizer tests.

use alloy_primitives::U256;
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3, ForkchoiceState, PayloadId, PayloadStatus, PayloadStatusEnum,
};
use summit_types::network_oracle::NetworkOracle;
use summit_types::{Block, EngineClient, PublicKey};

/// Minimal mock EngineClient that accepts all blocks
#[derive(Clone)]
pub struct MockEngineClient;

impl EngineClient for MockEngineClient {
    #[allow(unused_variables)]
    async fn start_building_block(
        &mut self,
        _fork_choice_state: ForkchoiceState,
        _timestamp: u64,
        _withdrawals: Vec<alloy_eips::eip4895::Withdrawal>,
        #[cfg(feature = "bench")] height: u64,
    ) -> Option<PayloadId> {
        Some(PayloadId::new([0u8; 8]))
    }

    async fn get_payload(&mut self, _payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
        ExecutionPayloadEnvelopeV4 {
            envelope_inner: ExecutionPayloadEnvelopeV3 {
                execution_payload: ExecutionPayloadV3 {
                    payload_inner: ExecutionPayloadV2 {
                        payload_inner: ExecutionPayloadV1 {
                            base_fee_per_gas: U256::from(1000000000u64),
                            block_number: 0,
                            block_hash: [0u8; 32].into(),
                            logs_bloom: Default::default(),
                            extra_data: Default::default(),
                            gas_limit: 30000000,
                            gas_used: 0,
                            timestamp: 0,
                            fee_recipient: Default::default(),
                            parent_hash: [0u8; 32].into(),
                            prev_randao: Default::default(),
                            receipts_root: Default::default(),
                            state_root: Default::default(),
                            transactions: Vec::new(),
                        },
                        withdrawals: Vec::new().into(),
                    },
                    blob_gas_used: 0,
                    excess_blob_gas: 0,
                },
                block_value: U256::ZERO,
                blobs_bundle: Default::default(),
                should_override_builder: false,
            },
            execution_requests: Default::default(),
        }
    }

    async fn check_payload(&mut self, _block: &Block) -> PayloadStatus {
        PayloadStatus {
            status: PayloadStatusEnum::Valid,
            latest_valid_hash: Some([0u8; 32].into()),
        }
    }

    async fn commit_hash(&mut self, _fork_choice_state: ForkchoiceState) {}
}

/// Minimal mock NetworkOracle
#[derive(Clone)]
pub struct MockNetworkOracle;

impl NetworkOracle<PublicKey> for MockNetworkOracle {
    async fn register(&mut self, _index: u64, _peers: Vec<PublicKey>) {}
}

impl commonware_p2p::Blocker for MockNetworkOracle {
    type PublicKey = PublicKey;
    async fn block(&mut self, _public_key: Self::PublicKey) {}
}
