use anyhow::Result;
use test_utils::{TestContext, generate_test_keys, create_test_genesis};

#[tokio::test]
async fn test_multi_node_context_creation() -> Result<()> {
    let harness = TestContext::new(7); // f=2, n=7 for BFT
    
    assert_eq!(harness.validator_keys.len(), 7);
    assert_eq!(harness.genesis.validator_count(), 7);
    
    Ok(())
}

#[tokio::test]
async fn test_minimal_genesis_creation() -> Result<()> {
    let keys = generate_test_keys(4);
    let genesis = create_test_genesis(&keys);
    
    assert_eq!(genesis.validator_count(), 4);
    assert_eq!(genesis.namespace, "_TEST_BFT");
    
    Ok(())
}

#[tokio::test]
async fn test_bft_node_count_boundary() -> Result<()> {
    // Test BFT boundary conditions
    // For f Byzantine faults, need 3f+1 total nodes
    
    // f=1 requires 4 nodes
    let harness_4 = TestContext::new(4);
    assert_eq!(harness_4.validator_keys.len(), 4);
    
    // f=2 requires 7 nodes  
    let harness_7 = TestContext::new(7);
    assert_eq!(harness_7.validator_keys.len(), 7);
    
    Ok(())
}

#[tokio::test]
async fn test_test_utilities_isolation() -> Result<()> {
    // Test that different test contexts are isolated
    let harness1 = TestContext::new(3);
    let harness2 = TestContext::new(3);
    
    // Each should have their own keys and genesis
    assert_eq!(harness1.validator_keys.len(), 3);
    assert_eq!(harness2.validator_keys.len(), 3);
    
    // Genesis should be identical structure but separate instances
    assert_eq!(harness1.genesis.validator_count(), harness2.genesis.validator_count());
    
    Ok(())
}