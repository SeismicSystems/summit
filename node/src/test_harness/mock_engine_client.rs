use alloy_eips::eip4895::Withdrawal;
use alloy_eips::eip7685::Requests;
use alloy_primitives::hex;
use alloy_primitives::{Address, B256, Bloom, Bytes, FixedBytes, U256};
use alloy_rpc_types_engine::{
    BlobsBundleV1, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV1,
    ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use summit_application::engine_client::EngineClient;
use summit_types::Block;

#[derive(Clone)]
pub struct MockEngineClient {
    client_id: String,
    state: Arc<Mutex<MockEngineState>>,
    // Execution requests that will be included in the blocks
    execution_requests: Arc<Mutex<HashMap<u64, Requests>>>,
}

#[derive(Debug)]
struct MockEngineState {
    // Payload building - tracks blocks being built
    building_payloads: HashMap<PayloadId, ExecutionPayloadEnvelopeV4>,

    // Simple blockchain state
    canonical_blocks: HashMap<FixedBytes<32>, ExecutionPayloadV3>,
    canonical_by_number: HashMap<u64, FixedBytes<32>>,
    current_head: FixedBytes<32>,
    next_block_number: u64,

    // Block validation
    known_blocks: HashMap<FixedBytes<32>, PayloadStatus>,
    // Store full block data for blocks we already validated (from check_payload)
    validated_blocks: HashMap<FixedBytes<32>, ExecutionPayloadV3>,

    // For testing
    force_invalid: bool,
    should_fail: bool,
}

impl MockEngineClient {
    /// Create a new mock engine client
    pub fn new(
        client_id: String,
        genesis_hash: [u8; 32],
        execution_requests: Arc<Mutex<HashMap<u64, Requests>>>,
    ) -> Self {
        let state = MockEngineState::new(genesis_hash);

        Self {
            client_id,
            state: Arc::new(Mutex::new(state)),
            execution_requests,
        }
    }

    /// Get the client ID
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Get current chain height
    pub fn get_chain_height(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.next_block_number.saturating_sub(1)
    }

    /// Get canonical chain as list of (block_number, block_hash)
    pub fn get_canonical_chain(&self) -> Vec<(u64, FixedBytes<32>)> {
        let state = self.state.lock().unwrap();
        let mut chain: Vec<_> = state
            .canonical_by_number
            .iter()
            .map(|(&number, &hash)| (number, hash))
            .collect();
        chain.sort_by_key(|&(number, _)| number);
        chain
    }

    /// Get all withdrawals from the canonical chain
    pub fn get_withdrawals(&self) -> HashMap<u64, Vec<Withdrawal>> {
        let canonical_chain = self.get_canonical_chain();
        let state = self.state.lock().unwrap();
        let mut withdrawals = HashMap::new();
        for (height, block_hash) in canonical_chain {
            // First try canonical_blocks (committed blocks)
            let block = if let Some(block) = state.canonical_blocks.get(&block_hash) {
                Some(block.clone())
            } else {
                // Fallback to building_payloads (uncommitted blocks)
                state
                    .building_payloads
                    .values()
                    .find(|envelope| {
                        envelope
                            .envelope_inner
                            .execution_payload
                            .payload_inner
                            .payload_inner
                            .block_hash
                            == block_hash
                    })
                    .map(|envelope| envelope.envelope_inner.execution_payload.clone())
            };

            if let Some(block) = block {
                if !block.payload_inner.withdrawals.is_empty() {
                    withdrawals.insert(height, block.payload_inner.withdrawals);
                }
            }
        }
        withdrawals
    }

    #[allow(unused)]
    /// Check if a block exists in canonical chain
    pub fn has_block(&self, block_hash: FixedBytes<32>) -> bool {
        let state = self.state.lock().unwrap();
        state.canonical_blocks.contains_key(&block_hash)
    }

    #[allow(unused)]
    /// Add a block to canonical chain (for testing consensus)
    pub fn add_canonical_block(&self, block: ExecutionPayloadV3) -> bool {
        let mut state = self.state.lock().unwrap();

        let block_number = block.payload_inner.payload_inner.block_number;
        let block_hash = block.payload_inner.payload_inner.block_hash;

        // Verify sequential block number
        if block_number != state.next_block_number {
            return false;
        }

        // Verify parent exists (except for block 1 after genesis)
        if block_number > 1 {
            if !state.canonical_by_number.contains_key(&(block_number - 1)) {
                return false;
            }
        }

        // Add to canonical chain
        state.canonical_blocks.insert(block_hash, block);
        state.canonical_by_number.insert(block_number, block_hash);
        state.current_head = block_hash;
        state.next_block_number += 1;

        true
    }

    #[allow(unused)]
    // Test configuration methods
    pub fn set_force_invalid(&self, force: bool) {
        let mut state = self.state.lock().unwrap();
        state.force_invalid = force;
    }

    #[allow(unused)]
    pub fn set_should_fail(&self, should_fail: bool) {
        let mut state = self.state.lock().unwrap();
        state.should_fail = should_fail;
    }
}

impl MockEngineState {
    fn new(genesis_hash: [u8; 32]) -> Self {
        let mut canonical_blocks = HashMap::new();
        let mut canonical_by_number = HashMap::new();

        // Create deterministic genesis block
        let genesis_hash = FixedBytes::from(genesis_hash);
        let genesis_block = Self::create_genesis_block();

        canonical_blocks.insert(genesis_hash, genesis_block);
        canonical_by_number.insert(0, genesis_hash);

        Self {
            building_payloads: HashMap::new(),
            canonical_blocks,
            canonical_by_number,
            current_head: genesis_hash,
            next_block_number: 1,
            known_blocks: HashMap::new(),
            validated_blocks: HashMap::new(),
            force_invalid: false,
            should_fail: false,
        }
    }

    fn create_genesis_block() -> ExecutionPayloadV3 {
        let genesis_payload_v1 = ExecutionPayloadV1 {
            parent_hash: FixedBytes::from([0u8; 32]),
            fee_recipient: Address::ZERO,
            state_root: FixedBytes::from([0u8; 32]),
            receipts_root: FixedBytes::from([0u8; 32]),
            logs_bloom: Bloom::ZERO,
            prev_randao: B256::ZERO,
            block_number: 0,
            gas_limit: 21_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::from("genesis"),
            base_fee_per_gas: U256::ZERO,
            block_hash: FixedBytes::from([0u8; 32]),
            transactions: vec![],
        };

        let genesis_payload_v2 = ExecutionPayloadV2 {
            payload_inner: genesis_payload_v1,
            withdrawals: vec![],
        };

        ExecutionPayloadV3 {
            payload_inner: genesis_payload_v2,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    fn create_block_payload(
        &self,
        parent_hash: FixedBytes<32>,
        timestamp: u64,
        client_id: &str,
        withdrawals: Vec<Withdrawal>,
    ) -> ExecutionPayloadV3 {
        // Create deterministic but unique block hash
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(parent_hash.as_slice());
        hasher.update(&self.next_block_number.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(client_id.as_bytes());
        let block_hash = FixedBytes::<32>::from_slice(&hasher.finalize()[..32]);

        let payload_v1 = ExecutionPayloadV1 {
            parent_hash,
            fee_recipient: Address::from([1u8; 20]),
            state_root: FixedBytes::from([1u8; 32]),
            receipts_root: FixedBytes::from([1u8; 32]),
            logs_bloom: Bloom::ZERO,
            prev_randao: B256::ZERO,
            block_number: self.next_block_number,
            gas_limit: 21_000,
            gas_used: 21_000,
            timestamp,
            extra_data: Bytes::from(
                format!("block-{}-{}", self.next_block_number, client_id).into_bytes(),
            ),
            base_fee_per_gas: U256::from(1_000_000_000u64),
            block_hash,
            transactions: vec![],
        };

        let payload_v2 = ExecutionPayloadV2 {
            payload_inner: payload_v1,
            withdrawals,
        };

        ExecutionPayloadV3 {
            payload_inner: payload_v2,
            blob_gas_used: 100_000,
            excess_blob_gas: 50_000,
        }
    }
}

impl EngineClient for MockEngineClient {
    async fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
    ) -> Option<PayloadId> {
        let mut state = self.state.lock().unwrap();

        if state.should_fail {
            return None;
        }

        // Verify we know about the head block
        if !state
            .canonical_blocks
            .contains_key(&fork_choice_state.head_block_hash)
        {
            return None;
        }

        // Generate unique payload ID
        let payload_id = {
            let mut rng = rand::thread_rng();
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            PayloadId::new(bytes)
        };

        // Create the new block
        let new_block = state.create_block_payload(
            fork_choice_state.head_block_hash,
            timestamp,
            &self.client_id,
            withdrawals,
        );

        // Wrap in envelope
        let block_num = state.next_block_number;
        let execution_requests = self.execution_requests.lock().unwrap().remove(&block_num);
        let envelope = ExecutionPayloadEnvelopeV4 {
            envelope_inner: ExecutionPayloadEnvelopeV3 {
                execution_payload: new_block,
                block_value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
                blobs_bundle: BlobsBundleV1::default(),
                should_override_builder: false,
            },
            execution_requests: execution_requests.unwrap_or_default(),
        };

        // Store for later retrieval
        state.building_payloads.insert(payload_id, envelope);

        Some(payload_id)
    }

    async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
        let state = self.state.lock().unwrap();

        state
            .building_payloads
            .get(&payload_id)
            .cloned()
            .expect("Payload ID not found")
    }

    async fn check_payload(&self, block: &Block) -> PayloadStatus {
        let mut state = self.state.lock().unwrap();

        if state.force_invalid {
            return PayloadStatus::new(
                PayloadStatusEnum::Invalid {
                    validation_error: "Mock: Forced invalid".to_string(),
                },
                None,
            );
        }

        let block_hash = block.payload.payload_inner.payload_inner.block_hash;
        let parent_hash = block.payload.payload_inner.payload_inner.parent_hash;

        // Check if parent exists in our canonical chain
        if !state.canonical_blocks.contains_key(&parent_hash) {
            let status = PayloadStatus::new(
                PayloadStatusEnum::Invalid {
                    validation_error: "Parent block not found".to_string(),
                },
                None,
            );
            state.known_blocks.insert(block_hash, status.clone());
            return status;
        }

        // Block is valid - store both status and block data
        let status = PayloadStatus::new(PayloadStatusEnum::Valid, Some(block_hash));
        state.known_blocks.insert(block_hash, status.clone());
        state
            .validated_blocks
            .insert(block_hash, block.payload.clone());
        status
    }

    async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
        let mut state = self.state.lock().unwrap();

        // Update current head
        state.current_head = fork_choice_state.head_block_hash;

        // First, try to find the block in our building payloads (blocks we built)
        let matching_block = state
            .building_payloads
            .values()
            .find(|envelope| {
                envelope
                    .envelope_inner
                    .execution_payload
                    .payload_inner
                    .payload_inner
                    .block_hash
                    == fork_choice_state.head_block_hash
            })
            .map(|envelope| envelope.envelope_inner.execution_payload.clone());

        if let Some(block) = matching_block {
            let block_number = block.payload_inner.payload_inner.block_number;
            let block_hash = block.payload_inner.payload_inner.block_hash;

            // Add to canonical chain if it's the next expected block
            if block_number == state.next_block_number {
                state.canonical_blocks.insert(block_hash, block);
                state.canonical_by_number.insert(block_number, block_hash);
                state.next_block_number += 1;
            }
        } else {
            // Block not in building_payloads - check if we validated it via check_payload
            let validated_block = state
                .validated_blocks
                .get(&fork_choice_state.head_block_hash)
                .cloned();

            if let Some(block) = validated_block {
                let block_number = block.payload_inner.payload_inner.block_number;
                let block_hash = block.payload_inner.payload_inner.block_hash;

                // Add to canonical chain if it's the next expected block
                if block_number == state.next_block_number {
                    state.canonical_blocks.insert(block_hash, block);
                    state.canonical_by_number.insert(block_number, block_hash);
                    state.next_block_number += 1;
                }
            }
        }
    }
}

pub struct MockEngineNetworkBuilder {
    genesis_hash: [u8; 32],
    execution_requests: Option<HashMap<u64, Requests>>,
}

impl MockEngineNetworkBuilder {
    pub fn new(genesis_hash: [u8; 32]) -> Self {
        Self {
            genesis_hash,
            execution_requests: None,
        }
    }

    pub fn with_execution_requests(mut self, requests: HashMap<u64, Requests>) -> Self {
        self.execution_requests = Some(requests);
        self
    }

    pub fn build(self) -> MockEngineNetwork {
        MockEngineNetwork {
            genesis_hash: self.genesis_hash,
            clients: Arc::new(Mutex::new(Vec::new())),
            execution_requests: Arc::new(Mutex::new(self.execution_requests.unwrap_or_default())),
        }
    }
}

/// Network for managing multiple mock engine clients
#[derive(Clone)]
pub struct MockEngineNetwork {
    genesis_hash: [u8; 32],
    clients: Arc<Mutex<Vec<MockEngineClient>>>,
    execution_requests: Arc<Mutex<HashMap<u64, Requests>>>,
}

impl MockEngineNetwork {
    pub fn new(genesis_hash: [u8; 32]) -> Self {
        Self {
            genesis_hash,
            clients: Arc::new(Mutex::new(Vec::new())),
            execution_requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new mock engine client
    pub fn create_client(&self, client_id: String) -> MockEngineClient {
        let client = MockEngineClient::new(
            client_id,
            self.genesis_hash,
            self.execution_requests.clone(),
        );

        let mut clients = self.clients.lock().unwrap();
        clients.push(client.clone());

        client
    }

    /// Get all clients
    pub fn get_clients(&self) -> Vec<MockEngineClient> {
        let clients = self.clients.lock().unwrap();
        clients.clone()
    }

    /// Print all canonical chains for debugging consensus issues
    fn print_all_canonical_chains(&self, until_block: Option<u64>, error_type: &str) {
        let clients = self.get_clients();
        println!("=== CONSENSUS ERROR: {} ===", error_type);
        for client in &clients {
            let chain = client.get_canonical_chain();
            let height = until_block.unwrap_or(client.get_chain_height());
            println!("Client {}: height={}", client.client_id(), height);
            for (block_number, block_hash) in &chain {
                if until_block.is_none() || *block_number <= height {
                    println!(
                        "  Block {}: {}",
                        block_number,
                        hex::encode(block_hash.as_slice())
                    );
                }
            }
        }
    }

    /// Check if all clients have the same canonical chain (consensus)
    pub fn verify_consensus(&self, until_block: Option<u64>) -> Result<(), String> {
        let clients = self.get_clients();

        if clients.len() < 2 {
            return Ok(());
        }

        let reference_height = until_block.unwrap_or(clients[0].get_chain_height());
        let reference_chain: Vec<(u64, _)> = clients[0]
            .get_canonical_chain()
            .into_iter()
            .filter(|(height, _)| *height <= reference_height)
            .collect();

        for client in clients.iter().skip(1) {
            let client_height = until_block.unwrap_or(client.get_chain_height());
            let client_chain: Vec<(u64, _)> = client
                .get_canonical_chain()
                .into_iter()
                .filter(|(height, _)| *height <= client_height)
                .collect();

            if client_height != reference_height {
                self.print_all_canonical_chains(until_block, "HEIGHT MISMATCH");
                return Err(format!(
                    "Height mismatch: {} has {}, {} has {}",
                    clients[0].client_id(),
                    reference_height,
                    client.client_id(),
                    client_height
                ));
            }

            if client_chain != reference_chain {
                self.print_all_canonical_chains(until_block, "CHAIN MISMATCH");
                return Err(format!(
                    "Chain mismatch: {} differs from {}",
                    client.client_id(),
                    clients[0].client_id()
                ));
            }
        }

        Ok(())
    }

    /// Get consensus height (all clients must agree)
    pub fn get_consensus_height(&self) -> Result<u64, String> {
        self.verify_consensus(None)?;

        let clients = self.get_clients();
        if clients.is_empty() {
            Ok(0)
        } else {
            Ok(clients[0].get_chain_height())
        }
    }

    /// Get all withdrawals from the canonical chain
    pub fn get_withdrawals(&self) -> HashMap<u64, Vec<Withdrawal>> {
        let clients = self.get_clients();
        let withdrawals = clients[0].get_withdrawals();
        withdrawals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_engine_client() {
        let genesis_hash = [0; 32];
        let client = MockEngineClient::new(
            "test".to_string(),
            genesis_hash,
            Arc::new(Mutex::new(HashMap::new())),
        );

        // Should start at genesis
        assert_eq!(client.get_chain_height(), 0);

        // Build a block
        let genesis_state = ForkchoiceState {
            head_block_hash: FixedBytes::from(genesis_hash),
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };

        let payload_id = client
            .start_building_block(genesis_state, 1000, vec![])
            .await
            .unwrap();
        let envelope = client.get_payload(payload_id).await;
        let block = envelope.envelope_inner.execution_payload;

        // Commit the block
        let new_fork_choice = ForkchoiceState {
            head_block_hash: block.payload_inner.payload_inner.block_hash,
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };

        client.commit_hash(new_fork_choice).await;

        // Should now be at height 1
        assert_eq!(client.get_chain_height(), 1);
    }

    #[tokio::test]
    async fn test_multiple_clients_consensus() {
        let genesis_hash = [0; 32];
        let network = MockEngineNetwork::new(genesis_hash);

        // Create 3 clients
        let client1 = network.create_client("client1".to_string());
        let client2 = network.create_client("client2".to_string());
        let client3 = network.create_client("client3".to_string());

        // All should start in consensus at height 0
        assert!(network.verify_consensus(None).is_ok());
        assert_eq!(network.get_consensus_height().unwrap(), 0);

        // All clients should have identical genesis chains
        let chain1 = client1.get_canonical_chain();
        let chain2 = client2.get_canonical_chain();
        let chain3 = client3.get_canonical_chain();

        assert_eq!(chain1, chain2);
        assert_eq!(chain2, chain3);
        assert_eq!(chain1.len(), 1); // Just genesis
    }

    #[tokio::test]
    async fn test_client_divergence_and_convergence() {
        let genesis_hash = [0; 32];
        let network = MockEngineNetwork::new(genesis_hash);

        let client1 = network.create_client("client1".to_string());
        let client2 = network.create_client("client2".to_string());

        // Start in consensus
        assert!(network.verify_consensus(None).is_ok());

        // Client1 builds and commits a block
        let genesis_state = ForkchoiceState {
            head_block_hash: FixedBytes::from([0u8; 32]),
            safe_block_hash: FixedBytes::from([0u8; 32]),
            finalized_block_hash: FixedBytes::from([0u8; 32]),
        };

        let payload_id = client1
            .start_building_block(genesis_state, 1000, vec![])
            .await
            .unwrap();
        let envelope = client1.get_payload(payload_id).await;
        let block1 = envelope.envelope_inner.execution_payload.clone();

        let fork_choice1 = ForkchoiceState {
            head_block_hash: block1.payload_inner.payload_inner.block_hash,
            safe_block_hash: FixedBytes::from([0u8; 32]),
            finalized_block_hash: FixedBytes::from([0u8; 32]),
        };

        client1.commit_hash(fork_choice1).await;

        // Now clients are diverged
        assert_eq!(client1.get_chain_height(), 1);
        assert_eq!(client2.get_chain_height(), 0);
        assert!(network.verify_consensus(None).is_err());

        // Simulate consensus: client2 receives the block through Engine API
        // First, client2 validates the block (like receiving it from network)
        let block_for_validation = Block::compute_digest(
            summit_types::Digest::from([0u8; 32]), // Genesis digest
            1,
            1000,
            block1.clone(),
            Vec::new(),
            alloy_primitives::U256::from(1_000_000_000_000_000_000u64),
            1,
            None,
            [0u8; 32].into(),
        );

        // Client2 checks the payload (validates it)
        let validation_result = client2.check_payload(&block_for_validation).await;
        assert!(matches!(validation_result.status, PayloadStatusEnum::Valid));

        // Client2 commits to this fork choice (accepting the block)
        client2.commit_hash(fork_choice1).await;

        // Now they should be in consensus again
        assert_eq!(client2.get_chain_height(), 1);
        assert!(network.verify_consensus(None).is_ok());
        assert_eq!(network.get_consensus_height().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_multiple_block_production() {
        let genesis_hash = [0; 32];
        let network = MockEngineNetwork::new(genesis_hash);

        let client1 = network.create_client("node1".to_string());
        let client2 = network.create_client("node2".to_string());
        let client3 = network.create_client("node3".to_string());

        let mut current_head = FixedBytes::from(genesis_hash);

        // Simulate 3 rounds of block production
        for round in 1..=3 {
            let producer = match round % 3 {
                1 => &client1,
                2 => &client2,
                _ => &client3,
            };

            // Producer builds a block
            let fork_choice = ForkchoiceState {
                head_block_hash: current_head,
                safe_block_hash: current_head,
                finalized_block_hash: current_head,
            };

            let payload_id = producer
                .start_building_block(fork_choice, (round * 1000) as u64, vec![])
                .await
                .unwrap();
            let envelope = producer.get_payload(payload_id).await;
            let new_block = envelope.envelope_inner.execution_payload.clone();

            let new_fork_choice = ForkchoiceState {
                head_block_hash: new_block.payload_inner.payload_inner.block_hash,
                safe_block_hash: current_head,
                finalized_block_hash: current_head,
            };

            // Producer commits the block
            producer.commit_hash(new_fork_choice).await;

            // Simulate network propagation - all other clients get the block via Engine API
            for client in [&client1, &client2, &client3] {
                if client.client_id() != producer.client_id() {
                    // Each client validates the block (like receiving it from network)
                    let block_for_validation = summit_types::Block::compute_digest(
                        summit_types::Digest::from([(round - 1) as u8; 32]), // Parent digest
                        round as u64,
                        (round * 1000) as u64,
                        new_block.clone(),
                        Vec::new(),
                        U256::from(1_000_000_000_000_000_000u64),
                        1,
                        None,
                        [0u8; 32].into(),
                    );

                    // Client validates the block
                    let validation_result = client.check_payload(&block_for_validation).await;
                    assert!(matches!(validation_result.status, PayloadStatusEnum::Valid));

                    // Client commits to this fork choice (accepting the block)
                    client.commit_hash(new_fork_choice).await;
                }
            }

            // All should be in consensus at height `round`
            assert!(network.verify_consensus(None).is_ok());
            assert_eq!(network.get_consensus_height().unwrap(), round as u64);

            current_head = new_block.payload_inner.payload_inner.block_hash;
        }

        // Final verification - all clients have same 4-block chain (genesis + 3 blocks)
        for client in [&client1, &client2, &client3] {
            let chain = client.get_canonical_chain();
            assert_eq!(chain.len(), 4); // genesis + 3 blocks
            println!("{} chain: {:?}", client.client_id(), chain);
        }
    }

    #[tokio::test]
    async fn test_network_get_withdrawals() {
        let genesis_hash = [0; 32];
        let network = MockEngineNetwork::new(genesis_hash);

        let client1 = network.create_client("client1".to_string());
        let client2 = network.create_client("client2".to_string());

        // Create a withdrawal for testing
        let withdrawal = Withdrawal {
            index: 0,
            validator_index: 1,
            address: Address::from([1u8; 20]),
            amount: 32_000_000_000, // 32 ETH in wei
        };

        // Start building block with withdrawal
        let genesis_state = ForkchoiceState {
            head_block_hash: FixedBytes::from(genesis_hash),
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };

        let payload_id = client1
            .start_building_block(genesis_state, 1000, vec![withdrawal.clone()])
            .await
            .unwrap();

        // Get the payload and modify it to include the withdrawal
        let mut envelope = client1.get_payload(payload_id).await;
        envelope
            .envelope_inner
            .execution_payload
            .payload_inner
            .withdrawals = vec![withdrawal.clone()];

        // Update the building payload with the withdrawal
        {
            let mut state = client1.state.lock().unwrap();
            state.building_payloads.insert(payload_id, envelope.clone());
        }

        let block = envelope.envelope_inner.execution_payload.clone();

        // Commit the block to both clients
        let new_fork_choice = ForkchoiceState {
            head_block_hash: block.payload_inner.payload_inner.block_hash,
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };

        client1.commit_hash(new_fork_choice).await;

        // Simulate network propagation to client2
        let block_for_validation = Block::compute_digest(
            summit_types::Digest::from([0u8; 32]),
            1,
            1000,
            block.clone(),
            Vec::new(),
            alloy_primitives::U256::from(1_000_000_000_000_000_000u64),
            1,
            None,
            [0u8; 32].into(),
        );

        client2.check_payload(&block_for_validation).await;
        client2.commit_hash(new_fork_choice).await;

        // Test that network.get_withdrawals() returns the withdrawal
        let withdrawals = network.get_withdrawals();

        assert_eq!(withdrawals.len(), 1);
        assert!(withdrawals.contains_key(&1));
        let block_1_withdrawals = withdrawals.get(&1).unwrap();
        assert_eq!(block_1_withdrawals.len(), 1);
        assert_eq!(block_1_withdrawals[0], withdrawal);
    }

    #[tokio::test]
    async fn test_consensus_failure_scenarios() {
        let genesis_hash = [0; 32];
        let network = MockEngineNetwork::new(genesis_hash);

        let client1 = network.create_client("client1".to_string());
        let client2 = network.create_client("client2".to_string());
        let client3 = network.create_client("client3".to_string());

        // Start in consensus
        assert!(network.verify_consensus(None).is_ok());

        // Create conflicting blocks on different clients
        let genesis_state = ForkchoiceState {
            head_block_hash: FixedBytes::from(genesis_hash),
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };

        // Client1 builds block A
        let payload_id_a = client1
            .start_building_block(genesis_state, 1000, vec![])
            .await
            .unwrap();
        let envelope_a = client1.get_payload(payload_id_a).await;
        let block_a = envelope_a.envelope_inner.execution_payload.clone();

        // Client2 builds block B (different from A due to client_id in hash)
        let payload_id_b = client2
            .start_building_block(genesis_state, 1000, vec![])
            .await
            .unwrap();
        let envelope_b = client2.get_payload(payload_id_b).await;
        let block_b = envelope_b.envelope_inner.execution_payload.clone();

        // Blocks should be different
        assert_ne!(
            block_a.payload_inner.payload_inner.block_hash,
            block_b.payload_inner.payload_inner.block_hash
        );

        // Client1 commits block A
        let fork_choice_a = ForkchoiceState {
            head_block_hash: block_a.payload_inner.payload_inner.block_hash,
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };
        client1.commit_hash(fork_choice_a).await;

        // Client2 commits block B
        let fork_choice_b = ForkchoiceState {
            head_block_hash: block_b.payload_inner.payload_inner.block_hash,
            safe_block_hash: FixedBytes::from(genesis_hash),
            finalized_block_hash: FixedBytes::from(genesis_hash),
        };
        client2.commit_hash(fork_choice_b).await;

        // Now consensus should fail - clients have different blocks at height 1
        assert!(network.verify_consensus(None).is_err());

        // Heights are same but chains differ
        assert_eq!(client1.get_chain_height(), 1);
        assert_eq!(client2.get_chain_height(), 1);
        assert_eq!(client3.get_chain_height(), 0); // client3 has no blocks
    }
}
