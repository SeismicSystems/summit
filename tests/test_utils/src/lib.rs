use std::time::Duration;

pub mod integration;

use commonware_cryptography::{bls12381::PrivateKey, PrivateKeyExt};
use commonware_runtime::tokio;
use futures_timer::Delay;
use summit_types::{Genesis, Validator};
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
    use crate::{create_test_genesis, generate_test_keys, TestContext};


    /// Just verify we generated the right number of keys
    #[test]
    fn test_generate_test_keys_creates_unique_keys() {
        let keys = generate_test_keys(4);
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn test_create_test_genesis_has_correct_validators() {
        let keys = generate_test_keys(3);
        let genesis = create_test_genesis(&keys);
        
        assert_eq!(genesis.validator_count(), 3);
        assert_eq!(genesis.namespace, "_TEST_BFT");
        
        assert_eq!(genesis.validators.len(), 3);
        
        // Each validator should have a unique port
        for (i, validator) in genesis.validators.iter().enumerate() {
            let expected_port = 26600 + (i * 10);
            assert!(validator.ip_address.contains(&expected_port.to_string()));
        }
    }


    #[test]
    fn test_test_context_creation() {
        let ctx = TestContext::new(2);
        assert_eq!(ctx.validator_keys.len(), 2);
        assert_eq!(ctx.genesis.validator_count(), 2);
    }
}