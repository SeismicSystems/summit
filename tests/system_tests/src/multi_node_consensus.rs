use std::time::Duration;

use alloy_node_bindings::{Reth, RethInstance};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;

/// Test harness that spawns real node processes for integration testing
pub struct MultiNodeTestHarness {
    temp_dir: TempDir,
    reth_processes: Vec<RethInstance>,
    pub node_count: usize,
    http_client: Client,
    rpc_urls: Vec<String>,
}

impl MultiNodeTestHarness {
    /// Start a multi-node testnet with the specified number of nodes
    pub async fn start(node_count: usize) -> Result<Self> {
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        
        let mut harness = Self {
            temp_dir,
            reth_processes: Vec::new(),
            node_count,
            http_client: Client::new(),
            rpc_urls: Vec::new(),
        };

        // Start each Reth node
        for node_id in 0..node_count {
            harness.start_single_reth_node(node_id).await?;
        }

        // Wait for nodes to start up
        std_tokio::time::sleep(Duration::from_secs(10)).await;

        Ok(harness)
    }

    async fn start_single_reth_node(&mut self, node_id: usize) -> Result<()> {
        let node_temp_dir = self.temp_dir.path().join(format!("node{}", node_id));
        std::fs::create_dir_all(&node_temp_dir)?;

        // Create JWT secret file
        let jwt_path = node_temp_dir.join("jwt.hex");
        std::fs::write(&jwt_path, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?;

        // Start Reth instance
        let reth_builder = Reth::new()
            .instance((node_id + 1) as u16)
            .data_dir(node_temp_dir.join("reth_db"))
            .arg("--authrpc.jwtsecret")
            .arg(&jwt_path);

        let reth = reth_builder.spawn();
        let _auth_port = reth.auth_port().context("Failed to get auth port")?;
        let http_port = reth.http_port();

        // Store RPC URL for this node
        let rpc_url = format!("http://localhost:{}", http_port);
        self.rpc_urls.push(rpc_url);

        tracing::info!("Started Reth node {} on HTTP port {}", node_id, http_port);

        self.reth_processes.push(reth);

        Ok(())
    }

    /// Make a JSON-RPC call to a specific node
    pub async fn rpc_call(&self, node_id: usize, method: &str, params: Value) -> Result<Value> {
        if node_id >= self.rpc_urls.len() {
            anyhow::bail!("Node {} not available", node_id);
        }

        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self.http_client
            .post(&self.rpc_urls[node_id])
            .json(&request)
            .send()
            .await
            .context("Failed to send RPC request")?;

        let response_json: Value = response.json().await.context("Failed to parse RPC response")?;
        
        if let Some(error) = response_json.get("error") {
            anyhow::bail!("RPC error: {}", error);
        }

        response_json.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No result in RPC response"))
    }

    /// Send a transaction from an external client to a specific node and return the transaction hash
    pub async fn send_transaction_from_client(&self, node_id: usize, from: &str, to: &str, value: &str) -> Result<String> {
        let tx_request = json!({
            "to": to,
            "value": value,
            "from": from,
            "gas": "0x5208", // 21000 gas for simple transfer
            "gasPrice": "0x3b9aca00" // 1 gwei
        });

        let result = self.rpc_call(node_id, "eth_sendTransaction", json!([tx_request])).await?;
        
        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Invalid transaction hash format"))
    }

    /// Create funded test accounts from the genesis file (simulates external users)
    pub async fn create_test_accounts(&self) -> Result<Vec<String>> {
        // Read the genesis file from the testnet directory
        let genesis_path = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("testnet/dev.json");
            
        let genesis_content = std::fs::read_to_string(&genesis_path)
            .context(format!("Failed to read genesis file at {:?}", genesis_path))?;
            
        let genesis: Value = serde_json::from_str(&genesis_content)
            .context("Failed to parse genesis file")?;
        
        // Extract funded accounts from the genesis file
        let mut accounts = Vec::new();
        if let Some(alloc) = genesis.get("alloc").and_then(|a| a.as_object()) {
            for address in alloc.keys() {
                accounts.push(address.clone());
            }
        }
        
        accounts.sort(); // For deterministic ordering
        
        tracing::info!("Loaded {} funded accounts from genesis file", accounts.len());
        
        Ok(accounts)
    }

    /// Get the latest block from a specific node
    pub async fn get_latest_block(&self, node_id: usize) -> Result<Value> {
        self.rpc_call(node_id, "eth_getBlockByNumber", json!(["latest", true])).await
    }

    /// Get block number from a specific node
    pub async fn get_block_number(&self, node_id: usize) -> Result<u64> {
        let result = self.rpc_call(node_id, "eth_blockNumber", json!([])).await?;
        
        let hex_str = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Block number not a string"))?;
        
        let without_prefix = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        u64::from_str_radix(without_prefix, 16)
            .context("Failed to parse block number")
    }

    /// Wait for all nodes to reach the same block height
    pub async fn wait_for_consensus(&self, target_height: u64, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Timeout waiting for consensus");
            }

            let mut all_at_height = true;
            let mut heights = Vec::new();

            for node_id in 0..self.node_count {
                let height = self.get_block_number(node_id).await?;
                heights.push(height);

                if height < target_height {
                    all_at_height = false;
                }
            }

            if all_at_height {
                tracing::info!("All nodes reached height {}: {:?}", target_height, heights);
                return Ok(());
            }

            std_tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Verify that all nodes have the same block at a given height
    pub async fn verify_block_consistency(&self, height: u64) -> Result<bool> {
        let mut block_hashes = Vec::new();

        for node_id in 0..self.node_count {
            let block = self.rpc_call(
                node_id, 
                "eth_getBlockByNumber", 
                json!([format!("0x{:x}", height), false])
            ).await?;

            if let Some(hash) = block.get("hash").and_then(|h| h.as_str()) {
                block_hashes.push(hash.to_string());
            } else {
                anyhow::bail!("Block {} from node {} has no hash", height, node_id);
            }
        }

        // Check if all hashes are the same
        let first_hash = &block_hashes[0];
        let all_same = block_hashes.iter().all(|hash| hash == first_hash);

        if all_same {
            tracing::info!("All nodes have consistent block at height {}: {}", height, first_hash);
        } else {
            tracing::error!("Block inconsistency at height {}: {:?}", height, block_hashes);
        }

        Ok(all_same)
    }
}

impl Drop for MultiNodeTestHarness {
    fn drop(&mut self) {
        // Cleanup is handled by TempDir and process drops
        tracing::info!("Shutting down multi-node test harness");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        // Test that we can create the harness struct without errors
        let temp_dir = TempDir::new().unwrap();
        let harness = MultiNodeTestHarness {
            temp_dir,
            reth_processes: Vec::new(),
            node_count: 3,
            http_client: Client::new(),
            rpc_urls: Vec::new(),
        };
        
        assert_eq!(harness.node_count, 3);
        assert_eq!(harness.rpc_urls.len(), 0);
    }
}