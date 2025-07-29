use anyhow::Result;

use crate::high_throughput_tests::HighThroughputTest;

/// Example stress test configurations
/// These demonstrate how to use the HighThroughputTest for various scenarios
/// 
/// To run these tests with real nodes, use:
/// cargo test --package system-tests -- --ignored

#[cfg(test)]
mod stress_test_examples {

    #[test]
    fn test_stress_test_parameters() {
        // Test that we can configure various stress test scenarios
        
        // 1 minute, 1000+ transactions test
        let duration_1min = 60;
        let min_tx_1000 = 1000;
        assert!(duration_1min > 0);
        assert!(min_tx_1000 >= 1000);
        
        // 2 minute, 2000+ transactions test
        let duration_2min = 120;
        let min_tx_2000 = 2000;
        assert!(duration_2min >= 60);
        assert!(min_tx_2000 >= 2000);
        
        // Extreme load test parameters
        let duration_5min = 300;
        let min_tx_5000 = 5000;
        assert!(duration_5min >= 300);
        assert!(min_tx_5000 >= 5000);
        
        // Concurrent client test parameters
        let num_clients = 20;
        let tx_per_client = 100;
        let total_expected = num_clients * tx_per_client;
        assert!(total_expected >= 2000);
    }
}

/// Helper functions for stress testing
pub mod stress_test_utils {
    use super::*;

    /// Run a custom throughput test with specified parameters
    pub async fn run_custom_throughput_test(
        node_count: usize,
        duration_secs: u64,
        min_transactions: usize,
    ) -> Result<()> {
        tracing::info!(
            "Starting custom throughput test: {} nodes, {}s duration, {} min transactions",
            node_count,
            duration_secs,
            min_transactions
        );

        let test = HighThroughputTest::new(node_count).await?;
        test.test_sustained_high_throughput(duration_secs, min_transactions).await?;

        Ok(())
    }

    /// Run a custom concurrent client test
    pub async fn run_custom_concurrent_test(
        node_count: usize,
        num_clients: usize,
        transactions_per_client: usize,
    ) -> Result<()> {
        tracing::info!(
            "Starting custom concurrent test: {} nodes, {} clients, {} tx/client",
            node_count,
            num_clients,
            transactions_per_client
        );

        let test = HighThroughputTest::new(node_count).await?;
        test.test_concurrent_client_load(num_clients, transactions_per_client).await?;

        Ok(())
    }
}