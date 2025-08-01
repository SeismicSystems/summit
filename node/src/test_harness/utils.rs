use std::time::{SystemTime, UNIX_EPOCH};
use alloy_rpc_types_engine::{BlobsBundleV1, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3};
use alloy_consensus::{TxEnvelope, Block as AlloyBlock};
use alloy_consensus::private::alloy_eips::eip4895::Withdrawal;
use alloy_consensus::private::alloy_eips::eip7685::Requests;
use alloy_primitives::{Address, Bloom, Bytes, FixedBytes, B256, U256};
use rand::Rng;

pub fn payload(parent_hash: B256, block_number: u64) -> ExecutionPayloadEnvelopeV4 {
    ExecutionPayloadEnvelopeV4 {
        envelope_inner: ExecutionPayloadEnvelopeV3 {
            execution_payload: payload_v3(parent_hash, block_number),
            block_value: U256::from(1_000_000_000u64),
            blobs_bundle: BlobsBundleV1::default(),
            should_override_builder: false,
        },
        execution_requests: Requests::default(),
    }
}

fn payload_v3(parent_hash: B256, block_number: u64) -> ExecutionPayloadV3 {
    ExecutionPayloadV3 {
        payload_inner: payload_v2(parent_hash, block_number),
        blob_gas_used: 29_500_000,
        excess_blob_gas: 500_000,
    }
}

fn payload_v2(parent_hash: B256, block_number: u64) -> ExecutionPayloadV2 {
    ExecutionPayloadV2 {
        payload_inner: payload_v1(parent_hash, block_number),
        withdrawals: vec![],
    }
}

fn payload_v1(parent_hash: B256, block_number: u64) -> ExecutionPayloadV1 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill(&mut random_bytes);
    let block_hash = FixedBytes::<32>::from_slice(&random_bytes);
    ExecutionPayloadV1 {
        parent_hash,
        fee_recipient: Address::ZERO,
        state_root: FixedBytes::<32>::from_slice(&[0; 32]),
        receipts_root: FixedBytes::<32>::from_slice(&[0; 32]),
        logs_bloom: Bloom::ZERO,
        prev_randao: B256::ZERO,
        block_number,
        gas_limit: 21_000,
        gas_used: 21_000,
        timestamp,
        extra_data: Bytes::new(),
        base_fee_per_gas: U256::from(1_000_000_000u64),
        block_hash,
        transactions: vec![],
    }
}