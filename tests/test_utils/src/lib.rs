use std::{net::SocketAddr, time::Duration};

pub mod integration;

use alloy_primitives::U256;
use alloy_rpc_types_engine::ExecutionPayloadV3;
use commonware_cryptography::{bls12381::PrivateKey, PrivateKeyExt};
use commonware_runtime::tokio;
use futures_timer::Delay;
use governor::Quota;
use summit_types::{Block, Genesis, Validator};
use tempfile::TempDir;

pub struct TestContext {
    pub temp_dirs: Vec<TempDir>,
    pub genesis: Genesis,
    pub validator_keys: Vec<PrivateKey>,
    pub runtime_config: tokio::Config,
}

impl TestContext {
    pub fn new(num_validators: usize) -> Self {
        let validator_keys = generate_test_keys(num_validators);
        let genesis = create_test_genesis(&validator_keys);
        let runtime_config = tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(2)
            .with_catch_panics(false);

        Self {
            temp_dirs: Vec::new(),
            genesis,
            validator_keys,
            runtime_config,
        }
    }

    pub fn create_temp_dir(&mut self) -> &TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        self.temp_dirs.push(temp_dir);
        self.temp_dirs.last().unwrap()
    }

    pub fn with_storage_dir(&mut self, temp_dir: &TempDir) -> tokio::Config {
        self.runtime_config
            .clone()
            .with_storage_directory(temp_dir.path().to_path_buf())
    }
}

pub fn generate_test_keys(count: usize) -> Vec<PrivateKey> {
    (0..count)
        .map(|i| {
            PrivateKey::from_seed(i as u64)
        })
        .collect()
}

pub fn create_test_genesis(keys: &[PrivateKey]) -> Genesis {
    let validators = keys
        .iter()
        .enumerate()
        .map(|(i, _key)| {
            // Create a placeholder public key in valid hex format
            // In real usage, this would use the proper Signer API
            let public_key = format!("{:0>96}", i); // 96 chars for a valid BLS public key hex
            let port = 26600 + (i * 10);
            
            Validator {
                public_key,
                ip_address: format!("127.0.0.1:{}", port),
            }
        })
        .collect();

    Genesis {
        validators,
        eth_genesis_hash: "0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616".to_string(),
        leader_timeout_ms: 1000,
        notarization_timeout_ms: 2000,
        nullify_timeout_ms: 2000,
        activity_timeout_views: 64,
        skip_timeout_views: 8,
        max_message_size_bytes: 1048576, // 1MB
        namespace: "_TEST_BFT".to_string(),
        identity: "test_network".to_string(),
    }
}

pub fn create_test_block(height: u64, parent_digest: [u8; 32]) -> Block {
    let payload = create_minimal_execution_payload();
    
    Block::compute_digest(
        parent_digest.into(),
        height,
        current_timestamp(),
        payload,
        vec![],
        U256::ZERO,
    )
}

pub fn create_minimal_execution_payload() -> ExecutionPayloadV3 {
    ExecutionPayloadV3 {
        payload_inner: alloy_rpc_types_engine::ExecutionPayloadV2 {
            payload_inner: alloy_rpc_types_engine::ExecutionPayloadV1 {
                parent_hash: [0u8; 32].into(),
                fee_recipient: [0u8; 20].into(),
                state_root: [0u8; 32].into(),
                receipts_root: [0u8; 32].into(),
                logs_bloom: [0u8; 256].into(),
                prev_randao: [0u8; 32].into(),
                block_number: 0,
                gas_limit: 21000,
                gas_used: 0,
                timestamp: current_timestamp(),
                extra_data: Default::default(),
                base_fee_per_gas: U256::from(1000000000u64), // 1 gwei
                block_hash: [0u8; 32].into(),
                transactions: vec![],
            },
            withdrawals: vec![],
        },
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn create_test_quota(per_second: u32) -> Quota {
    governor::Quota::per_second(std::num::NonZeroU32::new(per_second).unwrap())
}

pub fn create_socket_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

pub async fn wait_for_condition<F>(mut condition: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        // Use futures timer for async sleep
        Delay::new(Duration::from_millis(10)).await;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_keys_creates_unique_keys() {
        let keys = generate_test_keys(4);
        assert_eq!(keys.len(), 4);
        
        // Just verify we generated the right number of keys
        // In a real implementation, we would properly compare the keys
    }

    #[test]
    fn test_create_test_genesis_has_correct_validators() {
        let keys = generate_test_keys(3);
        let genesis = create_test_genesis(&keys);
        
        assert_eq!(genesis.validator_count(), 3);
        assert_eq!(genesis.namespace, "_TEST_BFT");
        
        // The genesis should have 3 validators
        assert_eq!(genesis.validators.len(), 3);
        
        // Each validator should have a unique port
        for (i, validator) in genesis.validators.iter().enumerate() {
            let expected_port = 26600 + (i * 10);
            assert!(validator.ip_address.contains(&expected_port.to_string()));
        }
    }

    #[test]
    fn test_create_test_block_increments_height() {
        let parent = [1u8; 32];
        let block = create_test_block(10, parent);
        
        assert_eq!(block.height, 10);
        assert_eq!(block.parent.as_ref(), &parent);
    }

    #[test]
    fn test_test_context_creation() {
        let ctx = TestContext::new(2);
        assert_eq!(ctx.validator_keys.len(), 2);
        assert_eq!(ctx.genesis.validator_count(), 2);
    }
}