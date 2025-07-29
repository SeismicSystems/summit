#[cfg(test)]
use test_utils::integration::{ConsensusHarness, ScenarioBuilder};

/// Test that minority Byzantine nodes don't prevent consensus
#[test]
fn test_byzantine_minority_tolerance() {
    // f=1, n=4: 1 Byzantine node should not prevent consensus
    let harness = ScenarioBuilder::with_byzantine_minority(1);
    
    assert_eq!(harness.nodes.len(), 4);
    assert_eq!(harness.healthy_node_count(), 3); // 3 honest nodes
    assert!(harness.can_reach_consensus()); // Should still reach consensus
}

/// Test that consensus fails when Byzantine nodes exceed fault tolerance
#[test]
fn test_byzantine_majority_prevents_consensus() {
    // 3 out of 4 nodes Byzantine - should prevent consensus
    let harness = ScenarioBuilder::consensus_impossible(4, 3);
    
    assert_eq!(harness.nodes.len(), 4);
    assert_eq!(harness.healthy_node_count(), 1); // Only 1 honest node
    assert!(!harness.can_reach_consensus()); // Should NOT reach consensus
}

/// Test Byzantine fault tolerance boundary conditions
#[test]
fn test_byzantine_fault_tolerance_boundary() {
    // Test exactly at the BFT boundary
    
    // For n=7, f=2: Should work with 2 Byzantine nodes (5 honest > 2*7/3 = 4.67)
    let mut harness_7_2 = ConsensusHarness::new(7);
    harness_7_2.make_nodes_byzantine(vec![0, 1]);
    assert_eq!(harness_7_2.healthy_node_count(), 5);
    assert!(harness_7_2.can_reach_consensus());
    
    // For n=7, f=3: Should fail with 3 Byzantine nodes (4 honest <= 2*7/3)
    let mut harness_7_3 = ConsensusHarness::new(7);
    harness_7_3.make_nodes_byzantine(vec![0, 1, 2]);
    assert_eq!(harness_7_3.healthy_node_count(), 4);
    assert!(!harness_7_3.can_reach_consensus());
}

/// Test mixed failure scenarios (offline + Byzantine)
#[test] 
fn test_mixed_failure_scenarios() {
    // Start with 7 nodes, make 1 Byzantine and 1 offline
    let mut harness = ConsensusHarness::new(7);
    harness.make_nodes_byzantine(vec![0]);
    harness.take_nodes_offline(vec![1]);
    
    assert_eq!(harness.nodes.len(), 7);
    assert_eq!(harness.healthy_node_count(), 5); // 5 honest and online
    assert!(harness.can_reach_consensus()); // Should still work
    
    // Add one more failure to push over the edge
    harness.take_nodes_offline(vec![2]);
    assert_eq!(harness.healthy_node_count(), 4);
    assert!(!harness.can_reach_consensus()); // Should fail now
}

/// Test that happy path works as baseline
#[test]
fn test_happy_path_baseline() {
    let harness = ScenarioBuilder::happy_path(2); // f=2, n=7
    
    assert_eq!(harness.nodes.len(), 7);
    assert_eq!(harness.healthy_node_count(), 7); // All nodes healthy
    assert!(harness.can_reach_consensus());
}

/// Test edge case with minimal BFT network
#[test]
fn test_minimal_bft_network() {
    // n=4 is minimal for f=1 Byzantine fault tolerance
    let harness = ConsensusHarness::new(4);
    
    assert_eq!(harness.nodes.len(), 4);
    assert_eq!(harness.healthy_node_count(), 4);
    assert!(harness.can_reach_consensus()); // 4 > 2*4/3 = 2.67
}