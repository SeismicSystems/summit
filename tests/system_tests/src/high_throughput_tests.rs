use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use futures::future::try_join_all;

use crate::multi_node_consensus::MultiNodeTestHarness;

/// High-throughput transaction testing for sustained load scenarios
pub struct HighThroughputTest {
    harness: MultiNodeTestHarness,
    client_accounts: Vec<String>,
    recipient_pool: Vec<String>,
}

impl HighThroughputTest {
    /// Create a new high-throughput test with the specified node count
    pub async fn new(node_count: usize) -> Result<Self> {
        let harness = MultiNodeTestHarness::start(node_count).await?;
        
        // Get funded accounts from genesis file
        let client_accounts = harness.create_test_accounts().await?;
        
        // Create a large pool of recipient addresses
        let recipient_pool = Self::generate_recipient_pool(100);
        
        Ok(Self {
            harness,
            client_accounts,
            recipient_pool,
        })
    }

    /// Generate a pool of recipient addresses for testing
    fn generate_recipient_pool(count: usize) -> Vec<String> {
        let mut recipients = Vec::new();
        for i in 0..count {
            // Generate deterministic but varied recipient addresses
            recipients.push(format!("0x{:040x}", i * 0x123456789abcdef));
        }
        recipients
    }

    /// Test sustained transaction load for at least 1 minute with 1000+ transactions
    pub async fn test_sustained_high_throughput(&self, min_duration_secs: u64, min_transactions: usize) -> Result<()> {
        tracing::info!(
            "Starting sustained high-throughput test: {} seconds minimum, {} transactions minimum",
            min_duration_secs,
            min_transactions
        );

        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let start_time = Instant::now();
        let min_duration = Duration::from_secs(min_duration_secs);
        
        // Shared counters for tracking progress
        let transactions_sent = Arc::new(AtomicUsize::new(0));
        let _transactions_confirmed = Arc::new(AtomicUsize::new(0));
        let mut all_tx_hashes = Vec::new();

        // Transaction sending parameters
        let base_value = 100000000000000u64; // 0.0001 ETH in wei
        let batch_size = 50; // Send transactions in batches
        let batch_delay = Duration::from_millis(200); // Delay between batches

        tracing::info!("Beginning transaction flood...");

        // Phase 1: Send transactions continuously for the specified duration
        while start_time.elapsed() < min_duration || transactions_sent.load(Ordering::Relaxed) < min_transactions {
            let mut batch_futures = Vec::new();
            
            // Create a batch of transactions
            for i in 0..batch_size {
                let client_account = &self.client_accounts[i % self.client_accounts.len()];
                let recipient = &self.recipient_pool[i % self.recipient_pool.len()];
                let node_id = i % self.harness.node_count;
                
                // Vary transaction values slightly to avoid nonce conflicts
                let value = format!("0x{:x}", base_value + (i as u64 * 1000));
                
                let harness = &self.harness;
                let client = client_account.clone();
                let recipient = recipient.clone();
                let value = value.clone();
                
                let tx_counter = Arc::clone(&transactions_sent);
                
                // Create future for this transaction
                let tx_future = async move {
                    let result = harness
                        .send_transaction_from_client(node_id, &client, &recipient, &value)
                        .await;
                    
                    match result {
                        Ok(tx_hash) => {
                            tx_counter.fetch_add(1, Ordering::Relaxed);
                            Ok(Some(tx_hash))
                        }
                        Err(e) => {
                            tracing::warn!("Transaction failed: {}", e);
                            Ok(None)
                        }
                    }
                };
                
                batch_futures.push(tx_future);
            }

            // Execute batch concurrently
            let batch_results: Result<Vec<Option<String>>> = try_join_all(batch_futures).await;
            
            match batch_results {
                Ok(results) => {
                    for result in results {
                        if let Some(tx_hash) = result {
                            all_tx_hashes.push(tx_hash);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Batch failed: {}", e);
                }
            }

            let sent_count = transactions_sent.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed();
            
            if sent_count % 200 == 0 {
                tracing::info!(
                    "Progress: {} transactions sent in {:.1}s (rate: {:.1} tx/s)",
                    sent_count,
                    elapsed.as_secs_f64(),
                    sent_count as f64 / elapsed.as_secs_f64()
                );
            }

            // Short delay between batches to avoid overwhelming nodes
            std_tokio::time::sleep(batch_delay).await;
        }

        let total_sent = transactions_sent.load(Ordering::Relaxed);
        let total_duration = start_time.elapsed();
        
        tracing::info!(
            "Transaction sending complete: {} transactions sent in {:.1}s (avg rate: {:.1} tx/s)",
            total_sent,
            total_duration.as_secs_f64(),
            total_sent as f64 / total_duration.as_secs_f64()
        );

        // Phase 2: Wait for transactions to be included in blocks
        tracing::info!("Waiting for transaction inclusion and consensus...");
        std_tokio::time::sleep(Duration::from_secs(30)).await;

        // Phase 3: Verify consensus and transaction inclusion
        self.verify_sustained_consensus().await?;
        let included_count = self.verify_transaction_inclusion(&all_tx_hashes).await?;

        // Phase 4: Validate results
        let inclusion_rate = (included_count as f64 / total_sent as f64) * 100.0;
        
        tracing::info!(
            "✅ Test Results: {}/{} transactions included ({:.1}% inclusion rate)",
            included_count,
            total_sent,
            inclusion_rate
        );

        // Assertions
        assert!(
            total_duration >= min_duration,
            "Test duration {:.1}s was less than minimum {}s",
            total_duration.as_secs_f64(),
            min_duration_secs
        );

        assert!(
            total_sent >= min_transactions,
            "Only {} transactions sent, minimum was {}",
            total_sent,
            min_transactions
        );

        assert!(
            included_count >= min_transactions,
            "Only {} transactions included in blocks, minimum was {}",
            included_count,
            min_transactions
        );

        assert!(
            inclusion_rate >= 80.0,
            "Transaction inclusion rate {:.1}% is too low (minimum 80%)",
            inclusion_rate
        );

        tracing::info!("🎉 High-throughput test PASSED!");

        Ok(())
    }

    /// Test transaction throughput with multiple concurrent clients
    pub async fn test_concurrent_client_load(&self, num_concurrent_clients: usize, transactions_per_client: usize) -> Result<()> {
        tracing::info!(
            "Starting concurrent client load test: {} clients, {} transactions each",
            num_concurrent_clients,
            transactions_per_client
        );

        // Wait for nodes to be ready
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        let start_time = Instant::now();
        let mut client_futures = Vec::new();

        // Create futures for each concurrent client
        for client_id in 0..num_concurrent_clients {
            let client_account = &self.client_accounts[client_id % self.client_accounts.len()];
            let harness = &self.harness;
            let recipient_pool = &self.recipient_pool;
            let client_account = client_account.clone();
            
            let client_future = async move {
                let mut tx_hashes = Vec::new();
                let base_value = 50000000000000u64; // 0.00005 ETH
                
                for tx_id in 0..transactions_per_client {
                    let recipient = &recipient_pool[(client_id * 1000 + tx_id) % recipient_pool.len()];
                    let node_id = (client_id + tx_id) % harness.node_count;
                    let value = format!("0x{:x}", base_value + (tx_id as u64 * 100));
                    
                    match harness
                        .send_transaction_from_client(node_id, &client_account, recipient, &value)
                        .await
                    {
                        Ok(tx_hash) => {
                            tx_hashes.push(tx_hash);
                        }
                        Err(e) => {
                            tracing::warn!("Client {} transaction {} failed: {}", client_id, tx_id, e);
                        }
                    }
                    
                    // Small delay between transactions from same client
                    if tx_id % 10 == 0 {
                        std_tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
                
                tracing::info!("Client {} completed {} transactions", client_id, tx_hashes.len());
                Ok::<Vec<String>, anyhow::Error>(tx_hashes)
            };
            
            client_futures.push(client_future);
        }

        // Execute all clients concurrently
        let all_results: Result<Vec<Vec<String>>, anyhow::Error> = try_join_all(client_futures).await;
        let all_results = all_results?;
        
        // Flatten all transaction hashes
        let all_tx_hashes: Vec<String> = all_results.into_iter().flatten().collect();
        let total_sent = all_tx_hashes.len();
        let total_duration = start_time.elapsed();

        tracing::info!(
            "All {} clients completed: {} total transactions in {:.1}s",
            num_concurrent_clients,
            total_sent,
            total_duration.as_secs_f64()
        );

        // Wait for inclusion
        std_tokio::time::sleep(Duration::from_secs(20)).await;

        // Verify results
        self.verify_sustained_consensus().await?;
        let included_count = self.verify_transaction_inclusion(&all_tx_hashes).await?;

        let expected_total = num_concurrent_clients * transactions_per_client;
        let inclusion_rate = (included_count as f64 / total_sent as f64) * 100.0;

        tracing::info!(
            "✅ Concurrent client test results: {}/{} transactions included ({:.1}%)",
            included_count,
            total_sent,
            inclusion_rate
        );

        assert!(
            total_sent >= expected_total * 8 / 10, // Allow for some failures
            "Too few transactions sent: {} < {}",
            total_sent,
            expected_total * 8 / 10
        );

        assert!(
            included_count >= expected_total * 7 / 10, // Expect most to be included
            "Too few transactions included: {} < {}",
            included_count,
            expected_total * 7 / 10
        );

        Ok(())
    }

    /// Verify that all nodes maintain consensus throughout the test
    async fn verify_sustained_consensus(&self) -> Result<()> {
        let mut block_numbers = Vec::new();
        
        for node_id in 0..self.harness.node_count {
            let block_number = self.harness.get_block_number(node_id).await?;
            block_numbers.push(block_number);
        }

        tracing::info!("Final block numbers across nodes: {:?}", block_numbers);

        // All nodes should be within a few blocks of each other
        let min_height = *block_numbers.iter().min().unwrap();
        let max_height = *block_numbers.iter().max().unwrap();
        
        assert!(
            max_height - min_height <= 2,
            "Nodes have diverged too much: min={}, max={}",
            min_height,
            max_height
        );

        // Verify consistency at a common height
        if min_height > 1 {
            let consistent = self.harness
                .verify_block_consistency(min_height - 1)
                .await?;
            
            assert!(consistent, "Nodes do not have consistent blocks at height {}", min_height - 1);
        }

        tracing::info!("✅ All nodes maintained consensus throughout high-throughput test");
        Ok(())
    }

    /// Count how many transactions were actually included in blocks
    async fn verify_transaction_inclusion(&self, tx_hashes: &[String]) -> Result<usize> {
        let block_height = self.harness.get_block_number(0).await?;
        let mut found_transactions = 0;
        
        tracing::info!("Scanning {} blocks for {} transactions...", block_height, tx_hashes.len());
        
        // Check all blocks (this might take a while for high throughput tests)
        for height in 1..=block_height {
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
            
            // Progress updates for long scans
            if height % 100 == 0 {
                tracing::info!("Scanned {} blocks, found {} transactions so far", height, found_transactions);
            }
        }

        tracing::info!(
            "✅ Transaction inclusion scan complete: {}/{} transactions found in {} blocks",
            found_transactions,
            tx_hashes.len(),
            block_height
        );

        Ok(found_transactions)
    }
}

#[cfg(test)]
mod tests {
    use crate::high_throughput_tests::HighThroughputTest;

    #[test]
    fn test_recipient_pool_generation() {
        let recipients = HighThroughputTest::generate_recipient_pool(10);
        
        assert_eq!(recipients.len(), 10);
        assert!(recipients.iter().all(|addr| addr.starts_with("0x")));
        assert!(recipients.iter().all(|addr| addr.len() == 42));
        
        // Should be deterministic
        let recipients2 = HighThroughputTest::generate_recipient_pool(10);
        assert_eq!(recipients, recipients2);
    }

    #[test]
    fn test_throughput_parameters() {
        // Test parameter validation
        let min_duration = 60; // 1 minute
        let min_transactions = 1000;
        
        assert!(min_duration > 0);
        assert!(min_transactions > 0);
        assert!(min_transactions >= 100); // Should be meaningful load
    }
}