use std::{collections::HashMap, time::Duration};
use anyhow::Result;
use tempfile::TempDir;
use summit_types::Block;
use commonware_cryptography::bls12381::PrivateKey;

use crate::TestContext;

/// High-level integration test harness for multi-node consensus scenarios
pub struct ConsensusHarness {
    pub context: TestContext,
    pub nodes: Vec<TestNode>,
    pub network: TestNetwork,
}

/// Represents a single consensus node in the test network
pub struct TestNode {
    pub id: usize,
    pub temp_dir: TempDir,
    pub private_key: PrivateKey,
    pub is_online: bool,
    pub is_byzantine: bool,
}

/// Manages network conditions and partitions for testing
pub struct TestNetwork {
    pub partitions: HashMap<usize, Vec<usize>>, // node_id -> can_communicate_with
    pub delays: HashMap<(usize, usize), Duration>, // (from, to) -> delay
    pub drop_rate: f64, // 0.0 = no drops, 1.0 = drop all
}

impl ConsensusHarness {
    /// Create a new consensus test harness with n nodes
    pub fn new(node_count: usize) -> Self {
        let context = TestContext::new(node_count);
        let nodes = (0..node_count)
            .map(|id| TestNode {
                id,
                temp_dir: TempDir::new().expect("Failed to create temp dir"),
                private_key: context.validator_keys[id].clone(),
                is_online: true,
                is_byzantine: false,
            })
            .collect();

        let network = TestNetwork::new(node_count);

        Self {
            context,
            nodes,
            network,
        }
    }

    /// Take nodes offline (simulates crash failures)
    pub fn take_nodes_offline(&mut self, node_ids: Vec<usize>) -> &mut Self {
        for &id in &node_ids {
            if let Some(node) = self.nodes.get_mut(id) {
                node.is_online = false;
            }
        }
        self
    }

    /// Make nodes Byzantine (simulates malicious behavior)  
    pub fn make_nodes_byzantine(&mut self, node_ids: Vec<usize>) -> &mut Self {
        for &id in &node_ids {
            if let Some(node) = self.nodes.get_mut(id) {
                node.is_byzantine = true;
            }
        }
        self
    }

    /// Create network partition isolating specified nodes
    pub fn partition_nodes(&mut self, isolated_nodes: Vec<usize>) -> &mut Self {
        self.network.create_partition(isolated_nodes);
        self
    }

    /// Get count of healthy (online + non-Byzantine) nodes
    pub fn healthy_node_count(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| n.is_online && !n.is_byzantine)
            .count()
    }

    /// Check if we have enough nodes for BFT consensus (> 2f)
    pub fn can_reach_consensus(&self) -> bool {
        let healthy = self.healthy_node_count();
        let total = self.nodes.len();
        healthy > (2 * total) / 3
    }

    /// Simulate running consensus and return whether it succeeded
    pub async fn run_consensus(&self, rounds: usize) -> Result<ConsensusResult> {
        if !self.can_reach_consensus() {
            return Ok(ConsensusResult::InsufficientNodes);
        }

        // Simulate consensus rounds
        let mut finalized_blocks: Vec<Block> = Vec::new();
        
        for round in 0..rounds {
            if self.simulate_consensus_round(round).await? {
                let block = Block::compute_digest(
                    if round == 0 { [0u8; 32].into() } else { finalized_blocks[round - 1].digest },
                    round as u64,
                    self.current_timestamp(),
                    crate::create_minimal_execution_payload(),
                    vec![],
                    alloy_primitives::U256::ZERO,
                );
                finalized_blocks.push(block);
            } else {
                return Ok(ConsensusResult::Timeout);
            }
        }

        Ok(ConsensusResult::Success { finalized_blocks })
    }

    /// Simulate a single consensus round
    async fn simulate_consensus_round(&self, round: usize) -> Result<bool> {
        let healthy_nodes: Vec<_> = self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is_online && !node.is_byzantine)
            .collect();

        // Need majority to succeed
        let required_votes = (healthy_nodes.len() / 2) + 1;
        
        // Simulate proposal phase
        let leader_id = round % healthy_nodes.len();
        let healthy_node_ids: Vec<usize> = healthy_nodes.iter().map(|(i, _)| *i).collect();
        if !self.network.can_communicate(leader_id, &healthy_node_ids) {
            return Ok(false); // Leader partitioned
        }

        // Simulate voting phase with network conditions
        let mut votes = 0;
        for (node_id, _) in &healthy_nodes {
            if self.network.can_communicate(leader_id, &vec![*node_id]) {
                votes += 1;
            }
        }

        Ok(votes >= required_votes)
    }

    fn current_timestamp(&self) -> u64 {
        crate::current_timestamp()
    }
}

impl TestNetwork {
    fn new(_node_count: usize) -> Self {
        Self {
            partitions: HashMap::new(),
            delays: HashMap::new(),
            drop_rate: 0.0,
        }
    }

    fn create_partition(&mut self, isolated_nodes: Vec<usize>) {
        for &node_id in &isolated_nodes {
            self.partitions.insert(node_id, vec![]); // Isolated nodes can't communicate
        }
    }

    fn can_communicate(&self, from: usize, to_nodes: &[usize]) -> bool {
        if let Some(allowed) = self.partitions.get(&from) {
            to_nodes.iter().any(|&to| allowed.contains(&to))
        } else {
            true // No partition restrictions
        }
    }
}

#[derive(Debug)]
pub enum ConsensusResult {
    Success { finalized_blocks: Vec<Block> },
    Timeout,
    InsufficientNodes,
}

/// Builder for common test scenarios
pub struct ScenarioBuilder;

impl ScenarioBuilder {
    /// Create a basic happy path scenario (3f+1 nodes, all healthy)  
    pub fn happy_path(f: usize) -> ConsensusHarness {
        ConsensusHarness::new(3 * f + 1)
    }

    /// Create scenario with f Byzantine nodes (should still reach consensus)
    pub fn with_byzantine_minority(f: usize) -> ConsensusHarness {
        let mut harness = ConsensusHarness::new(3 * f + 1);
        let byzantine_nodes: Vec<_> = (0..f).collect();
        harness.make_nodes_byzantine(byzantine_nodes);
        harness
    }

    /// Create scenario with f nodes offline (should still reach consensus)
    pub fn with_offline_minority(f: usize) -> ConsensusHarness {
        let mut harness = ConsensusHarness::new(3 * f + 1);
        let offline_nodes: Vec<_> = (0..f).collect();
        harness.take_nodes_offline(offline_nodes);
        harness
    }

    /// Create scenario where consensus should fail (too many failures)
    pub fn consensus_impossible(total_nodes: usize, failed_nodes: usize) -> ConsensusHarness {
        let mut harness = ConsensusHarness::new(total_nodes);
        let failure_nodes: Vec<_> = (0..failed_nodes).collect();
        harness.take_nodes_offline(failure_nodes);
        harness
    }

    /// Create network partition scenario
    pub fn network_partition(total_nodes: usize, partition_size: usize) -> ConsensusHarness {
        let mut harness = ConsensusHarness::new(total_nodes);
        let isolated_nodes: Vec<_> = (0..partition_size).collect();
        harness.partition_nodes(isolated_nodes);
        harness
    }
}

#[cfg(test)]
mod tests {
    use crate::integration::{ConsensusHarness, ConsensusResult, ScenarioBuilder};

    #[test]
    fn test_consensus_harness_creation() {
        let harness = ConsensusHarness::new(4);
        assert_eq!(harness.nodes.len(), 4);
        assert_eq!(harness.healthy_node_count(), 4);
        assert!(harness.can_reach_consensus());
    }

    #[test]
    fn test_scenario_builder_happy_path() {
        let harness = ScenarioBuilder::happy_path(1); // f=1, n=4
        assert_eq!(harness.nodes.len(), 4);
        assert!(harness.can_reach_consensus());
    }

    #[test]
    fn test_byzantine_minority_scenario() {
        let harness = ScenarioBuilder::with_byzantine_minority(1); // f=1, n=4, 1 Byzantine
        assert_eq!(harness.nodes.len(), 4);
        assert_eq!(harness.healthy_node_count(), 3);
        assert!(harness.can_reach_consensus());
    }

    #[test]
    fn test_consensus_impossible_scenario() {
        let harness = ScenarioBuilder::consensus_impossible(4, 3); // 3 out of 4 failed
        assert_eq!(harness.nodes.len(), 4);
        assert_eq!(harness.healthy_node_count(), 1);
        assert!(!harness.can_reach_consensus());
    }
}