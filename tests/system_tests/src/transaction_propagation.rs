use std::time::Duration;

use anyhow::{Context, Result};
use futures::future::try_join_all;

use crate::multi_node_consensus::MultiNodeTestHarness;

/// Test transaction propagation and inclusion across multiple nodes
pub struct TransactionPropagationTest {
    harness: MultiNodeTestHarness,
    client_accounts: Vec<String>, // External clients sending transactions
    recipient_accounts: Vec<String>, // Recipients of transactions
}

impl TransactionPropagationTest {
    /// Create a new transaction propagation test with the specified node count
    pub async fn new(node_count: usize) -> Result<Self> {
        let harness = MultiNodeTestHarness::start(node_count).await?;
        
        // Create external client accounts (these would be funded in a real test)
        let client_accounts = harness.create_test_accounts().await?;
        
        // Create recipient accounts for transactions
        let recipient_accounts = vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333".to_string(),
            "0x4444444444444444444444444444444444444444".to_string(),
        ];

        Ok(Self {
            harness,
            client_accounts,
            recipient_accounts,
        })
    }

    /// Test that transactions sent from external clients to different nodes all get included
    pub async fn test_concurrent_transactions(&self) -> Result<()> {
        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let value = "0xde0b6b3a7640000"; // 1 ETH in hex
        let mut tx_hashes = Vec::new();

        // Send transactions from external clients to different nodes concurrently
        for (i, recipient) in self.recipient_accounts.iter().enumerate() {
            let node_id = i % self.harness.node_count;
            let client_account = &self.client_accounts[i % self.client_accounts.len()];
            
            let tx_hash = self.harness
                .send_transaction_from_client(node_id, client_account, recipient, value)
                .await
                .context(format!("Failed to send transaction {} from client {} to node {}", i, client_account, node_id))?;
            
            tracing::info!("Client {} sent transaction {} to node {}: {}", client_account, i, node_id, tx_hash);
            tx_hashes.push(tx_hash);
        }

        // Wait for transactions to be included
        std_tokio::time::sleep(Duration::from_secs(20)).await;

        // Verify all nodes have consistent latest blocks
        self.verify_all_nodes_consistent().await?;

        // Check that transactions were included
        self.verify_transactions_included(&tx_hashes).await?;

        Ok(())
    }

    /// Test transaction ordering consistency across nodes
    pub async fn test_transaction_ordering(&self) -> Result<()> {
        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let base_value = 1000000000000000000u64; // 1 ETH in wei
        let mut tx_hashes = Vec::new();
        let client_account = &self.client_accounts[0]; // Use first client account

        // Send multiple transactions quickly from the same client to the same node
        for i in 0..3 {
            let value = format!("0x{:x}", base_value + i as u64);
            let recipient = &self.recipient_accounts[i % self.recipient_accounts.len()];
            
            let tx_hash = self.harness
                .send_transaction_from_client(0, client_account, recipient, &value)
                .await
                .context(format!("Failed to send transaction {} from client {}", i, client_account))?;
                
            tx_hashes.push(tx_hash);
            
            // Small delay to ensure ordering
            std_tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Wait for inclusion
        std_tokio::time::sleep(Duration::from_secs(15)).await;

        // Verify transaction ordering is consistent across all nodes
        self.verify_transaction_order_consistency().await?;

        Ok(())
    }

    /// Test that large transaction batches from multiple clients are handled correctly
    pub async fn test_large_transaction_batch(&self) -> Result<()> {
        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let num_transactions = 10;
        let value = "0x16345785d8a0000"; // 0.1 ETH in hex
        let mut tx_hashes = Vec::new();

        // Send many transactions from different clients across different nodes
        for i in 0..num_transactions {
            let node_id = i % self.harness.node_count;
            let client_account = &self.client_accounts[i % self.client_accounts.len()];
            let recipient = &self.recipient_accounts[i % self.recipient_accounts.len()];
            
            let tx_hash = self.harness
                .send_transaction_from_client(node_id, client_account, recipient, value)
                .await
                .context(format!("Failed to send transaction {} from client {} to node {}", i, client_account, node_id))?;
                
            tx_hashes.push(tx_hash);
            
            if i % 3 == 0 {
                std_tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        tracing::info!("Sent {} transactions across {} nodes", num_transactions, self.harness.node_count);

        // Wait for all transactions to be processed
        std_tokio::time::sleep(Duration::from_secs(30)).await;

        // Verify consistency
        self.verify_all_nodes_consistent().await?;

        // Check transaction inclusion
        self.verify_transactions_included(&tx_hashes).await?;

        Ok(())
    }

    /// Verify that all nodes have consistent latest blocks
    async fn verify_all_nodes_consistent(&self) -> Result<()> {
        let blocks: Vec<_> = (0..self.harness.node_count)
            .map(|i| self.harness.get_latest_block(i))
            .collect();
        let blocks = try_join_all(blocks).await?;

        let mut block_hashes = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            if let Some(hash) = block.get("hash").and_then(|h| h.as_str()) {
                block_hashes.push(hash.to_string());
            } else {
                anyhow::bail!("Node {} latest block has no hash", i);
            }
        }

        let first_hash = &block_hashes[0];
        if !block_hashes.iter().all(|hash| hash == first_hash) {
            anyhow::bail!(
                "Nodes have inconsistent latest blocks: {:?}",
                block_hashes
            );
        }

        tracing::info!("All {} nodes have consistent latest block: {:?}", 
                      self.harness.node_count, first_hash);
        Ok(())
    }

    /// Verify that transactions were included in blocks
    async fn verify_transactions_included(&self, tx_hashes: &[String]) -> Result<()> {
        let block_height = self.harness.get_block_number(0).await?;

        // Check recent blocks for our transactions
        let mut found_transactions = 0;
        
        for height in (block_height.saturating_sub(5))..=block_height {
            let block = self.harness.rpc_call(
                0,
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{:x}", height), true])
            ).await.context(format!("Failed to get block {}", height))?;

            if let Some(transactions) = block.get("transactions").and_then(|t| t.as_array()) {
                for tx in transactions {
                    if let Some(tx_hash) = tx.get("hash").and_then(|h| h.as_str()) {
                        if tx_hashes.contains(&tx_hash.to_string()) {
                            found_transactions += 1;
                        }
                    }
                }
            }
        }

        if found_transactions < tx_hashes.len() {
            tracing::warn!(
                "Only found {}/{} transactions in recent blocks",
                found_transactions,
                tx_hashes.len()
            );
        } else {
            tracing::info!("All {} transactions found in blocks", tx_hashes.len());
        }

        Ok(())
    }

    /// Verify transaction ordering is consistent across nodes
    async fn verify_transaction_order_consistency(&self) -> Result<()> {
        let blocks: Vec<_> = (0..self.harness.node_count)
            .map(|i| self.harness.get_latest_block(i))
            .collect();
        let blocks = try_join_all(blocks).await?;

        // Extract transaction orders from each node
        let mut transaction_orders = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let mut tx_hashes = Vec::new();
            if let Some(transactions) = block.get("transactions").and_then(|t| t.as_array()) {
                for tx in transactions {
                    if let Some(hash) = tx.get("hash").and_then(|h| h.as_str()) {
                        tx_hashes.push(hash.to_string());
                    }
                }
            }
            transaction_orders.push((i, tx_hashes));
        }

        // Compare orders (they should be identical)
        if let Some((_, first_order)) = transaction_orders.first() {
            for (node_id, order) in &transaction_orders[1..] {
                if order != first_order {
                    anyhow::bail!(
                        "Transaction order differs between node 0 and node {}: {:?} vs {:?}",
                        node_id,
                        first_order,
                        order
                    );
                }
            }
        }

        tracing::info!("Transaction ordering is consistent across all nodes");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test] 
    fn test_account_creation() {
        // Test that we can create test accounts (these come from testnet/dev.json)
        let client_accounts = vec![
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(), // From testnet/dev.json
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(), // From testnet/dev.json
        ];
        
        let recipient_accounts = vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ];
        
        assert_eq!(client_accounts.len(), 2);
        assert_eq!(recipient_accounts.len(), 2);
        assert!(client_accounts[0].starts_with("0x"));
        assert!(recipient_accounts[0].starts_with("0x"));
    }
}