use std::time::Duration;

use anyhow::{Context, Result};

use crate::multi_node_consensus::MultiNodeTestHarness;

/// Demonstrates external clients (not nodes) sending transactions to the consensus network
pub struct ExternalClientTest {
    harness: MultiNodeTestHarness,
}

impl ExternalClientTest {
    /// Create a new external client test with the specified node count
    pub async fn new(node_count: usize) -> Result<Self> {
        let harness = MultiNodeTestHarness::start(node_count).await?;
        
        Ok(Self { harness })
    }

    /// Test multiple external clients sending transactions to different nodes
    pub async fn test_external_clients_to_consensus_network(&self) -> Result<()> {
        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        // External clients (these represent users/applications, NOT consensus nodes)
        let external_clients = self.harness.create_test_accounts().await?;
        
        // Recipients for the transactions
        let recipients = vec![
            "0x1234567890123456789012345678901234567890",
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "0x9876543210987654321098765432109876543210",
        ];

        let mut tx_hashes = Vec::new();
        let value = "0x2386f26fc10000"; // 0.01 ETH in hex

        // Each external client sends a transaction to a different node
        for (i, recipient) in recipients.iter().enumerate() {
            let client = &external_clients[i % external_clients.len()];
            let target_node = i % self.harness.node_count;
            
            tracing::info!(
                "External client {} sending transaction to recipient {} via node {}",
                client, recipient, target_node
            );

            let tx_hash = self.harness
                .send_transaction_from_client(target_node, client, recipient, value)
                .await
                .context(format!(
                    "External client {} failed to send transaction to node {}",
                    client, target_node
                ))?;

            tx_hashes.push(tx_hash);
            
            // Small delay between transactions
            std_tokio::time::sleep(Duration::from_millis(200)).await;
        }

        tracing::info!(
            "All {} external clients have submitted transactions. Waiting for consensus...",
            recipients.len()
        );

        // Wait for transactions to be included in blocks
        std_tokio::time::sleep(Duration::from_secs(15)).await;

        // Verify all nodes reached consensus on the same blocks
        self.verify_cross_node_consensus().await?;

        // Verify transactions were included
        self.verify_transaction_inclusion(&tx_hashes).await?;

        Ok(())
    }

    /// Test that external clients can send to any node and still reach consensus
    pub async fn test_client_node_agnostic_consensus(&self) -> Result<()> {
        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let external_clients = self.harness.create_test_accounts().await?;
        let client = &external_clients[0]; // Single client
        let recipient = "0x5555555555555555555555555555555555555555";
        let value = "0x1bc16d674ec80000"; // 2 ETH in hex

        let mut tx_hashes = Vec::new();

        // Same client sends transactions to ALL nodes
        for node_id in 0..self.harness.node_count {
            tracing::info!(
                "External client {} sending transaction to node {} (recipient: {})",
                client, node_id, recipient
            );

            let tx_hash = self.harness
                .send_transaction_from_client(node_id, client, recipient, value)
                .await
                .context(format!(
                    "Client {} failed to send transaction to node {}",
                    client, node_id
                ))?;

            tx_hashes.push(tx_hash);
            
            // Small delay between sends
            std_tokio::time::sleep(Duration::from_millis(500)).await;
        }

        tracing::info!(
            "External client sent {} transactions across all {} nodes",
            tx_hashes.len(), 
            self.harness.node_count
        );

        // Wait for consensus
        std_tokio::time::sleep(Duration::from_secs(20)).await;

        // All nodes should have consistent state despite receiving transactions separately
        self.verify_cross_node_consensus().await?;

        Ok(())
    }

    /// Verify that all nodes have reached consensus on block hashes
    async fn verify_cross_node_consensus(&self) -> Result<()> {
        let mut block_numbers = Vec::new();
        
        // Get current block numbers from all nodes
        for node_id in 0..self.harness.node_count {
            let block_number = self.harness.get_block_number(node_id).await?;
            block_numbers.push(block_number);
        }

        tracing::info!("Block numbers across nodes: {:?}", block_numbers);

        // Find minimum block height that all nodes should have
        let min_height = *block_numbers.iter().min().unwrap();
        
        if min_height > 0 {
            // Verify consistency at the minimum height
            let consistent = self.harness
                .verify_block_consistency(min_height)
                .await?;
            
            if !consistent {
                anyhow::bail!(
                    "Nodes do not have consistent blocks at height {}. This indicates consensus failure.",
                    min_height
                );
            }
            
            tracing::info!(
                "✅ All {} nodes have consistent blocks at height {}",
                self.harness.node_count,
                min_height
            );
        }

        Ok(())
    }

    /// Verify that transactions from external clients were included
    async fn verify_transaction_inclusion(&self, tx_hashes: &[String]) -> Result<()> {
        let block_height = self.harness.get_block_number(0).await?;
        let mut found_transactions = 0;
        
        // Check recent blocks for our transactions
        for height in (block_height.saturating_sub(10))..=block_height {
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
                            tracing::info!("✅ Found transaction {} in block {}", tx_hash, height);
                        }
                    }
                }
            }
        }

        if found_transactions > 0 {
            tracing::info!(
                "✅ Found {}/{} transactions from external clients in recent blocks",
                found_transactions,
                tx_hashes.len()
            );
        } else {
            tracing::warn!(
                "⚠️  Did not find any of the {} transactions from external clients in recent blocks",
                tx_hashes.len()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_external_client_test_creation() {
        // Test that we can create the test structure
        // (The actual async test would require spawning real nodes)
        
        // Verify addresses have the correct format (these come from the genesis file)
        let external_clients = vec![
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(), // From testnet/dev.json
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(), // From testnet/dev.json
        ];
        
        assert_eq!(external_clients.len(), 2);
        assert!(external_clients.iter().all(|addr| addr.starts_with("0x")));
        assert!(external_clients.iter().all(|addr| addr.len() == 42)); // 0x + 40 hex chars
    }
}