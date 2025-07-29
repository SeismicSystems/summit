use anyhow::Result;
use test_utils::TestContext;

#[tokio::test]
async fn test_single_node_basic_setup() -> Result<()> {
    let harness = TestContext::new(1);
    
    // Basic test to verify we can create a test context
    assert_eq!(harness.validator_keys.len(), 1);
    assert_eq!(harness.genesis.validator_count(), 1);
    
    Ok(())
}

#[tokio::test] 
async fn test_three_node_basic_setup() -> Result<()> {
    let harness = TestContext::new(3);
    
    // Basic test to verify we can create a multi-node test context
    assert_eq!(harness.validator_keys.len(), 3);
    assert_eq!(harness.genesis.validator_count(), 3);
    
    Ok(())
}

#[tokio::test]
async fn test_genesis_block_creation() -> Result<()> {
    let _harness = TestContext::new(4);
    
    // Test that we can create genesis blocks for testing
    let genesis_hash = [42u8; 32];
    let genesis_block = summit_types::Block::genesis(genesis_hash);
    
    assert_eq!(genesis_block.height, 0);
    assert_eq!(genesis_block.parent.as_ref(), &genesis_hash);
    
    Ok(())
}

#[tokio::test]
async fn test_test_context_temp_directories() -> Result<()> {
    let mut harness = TestContext::new(2);
    
    // Test temp directory creation - need to make calls separately due to borrowing
    let temp_dir1_path = {
        let temp_dir = harness.create_temp_dir();
        temp_dir.path().to_path_buf()
    };
    
    let temp_dir2_path = {
        let temp_dir = harness.create_temp_dir();
        temp_dir.path().to_path_buf()
    };
    
    assert!(temp_dir1_path.exists());
    assert!(temp_dir2_path.exists());
    assert_ne!(temp_dir1_path, temp_dir2_path);
    
    Ok(())
}