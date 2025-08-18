use alloy_primitives::{B256, BlockNumber, FixedBytes};
use alloy_provider::network::AnyRpcBlock;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_engine::{ExecutionPayload, ExecutionPayloadV3};
use clap::{Arg, Command};
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::time::{Duration, sleep};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
struct BlockData {
    pub block_number: u64,
    pub payload: ExecutionPayloadV3,
    pub requests: FixedBytes<32>,
    pub parent_beacon_block_root: B256,
    pub versioned_hashes: Vec<B256>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockIndex {
    blocks: HashMap<u64, String>, // block_number -> filename
}

impl BlockIndex {
    fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }

    fn add_block(&mut self, block_number: u64, filename: String) {
        self.blocks.insert(block_number, filename);
    }

    fn get_block_file(&self, block_number: u64) -> Option<&String> {
        self.blocks.get(&block_number)
    }

    fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            let json = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&json)?)
        } else {
            Ok(Self::new())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let matches = Command::new("Block Fetcher")
        .version("1.0")
        .about("Fetches historical Ethereum blocks from RPC and saves them to disk")
        .arg(
            Arg::new("rpc-url")
                .long("rpc-url")
                .value_name("URL")
                .help("RPC endpoint URL")
                .required(true),
        )
        .arg(
            Arg::new("start-block")
                .long("start-block")
                .value_name("NUMBER")
                .help("Starting block number")
                .required(true),
        )
        .arg(
            Arg::new("end-block")
                .long("end-block")
                .value_name("NUMBER")
                .help("Ending block number")
                .required(true),
        )
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .value_name("PATH")
                .help("Output directory for block files")
                .default_value("./blocks"),
        )
        .arg(
            Arg::new("batch-size")
                .long("batch-size")
                .value_name("SIZE")
                .help("Number of blocks to process in parallel")
                .default_value("10"),
        )
        .arg(
            Arg::new("delay-ms")
                .long("delay-ms")
                .value_name("MS")
                .help("Delay between batches in milliseconds")
                .default_value("100"),
        )
        .get_matches();

    let rpc_url = matches.get_one::<String>("rpc-url").unwrap();
    let start_block: u64 = matches.get_one::<String>("start-block").unwrap().parse()?;
    let end_block: u64 = matches.get_one::<String>("end-block").unwrap().parse()?;
    let output_dir = PathBuf::from(matches.get_one::<String>("output-dir").unwrap());
    let batch_size: usize = matches.get_one::<String>("batch-size").unwrap().parse()?;
    let delay_ms: u64 = matches.get_one::<String>("delay-ms").unwrap().parse()?;

    if start_block > end_block {
        return Err(eyre::eyre!(
            "Start block must be less than or equal to end block"
        ));
    }

    // Create output directory
    fs::create_dir_all(&output_dir)?;

    // Initialize block index
    let index_path = output_dir.join("index.json");
    let mut block_index = BlockIndex::load_from_file(&index_path)?;

    info!("Connecting to RPC at {}", rpc_url);
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);

    info!("Fetching blocks from {} to {}", start_block, end_block);
    info!("Output directory: {}", output_dir.display());
    info!("Batch size: {}, delay: {}ms", batch_size, delay_ms);

    let total_blocks = end_block - start_block + 1;
    let mut processed = 0;

    for chunk_start in (start_block..=end_block).step_by(batch_size) {
        let chunk_end = (chunk_start + batch_size as u64 - 1).min(end_block);

        info!("Processing batch: {} to {}", chunk_start, chunk_end);

        let mut tasks = Vec::new();

        for block_num in chunk_start..=chunk_end {
            // Skip if block already exists
            if block_index.get_block_file(block_num).is_some() {
                info!("Block {} already exists, skipping", block_num);
                processed += 1;
                continue;
            }

            let provider_clone = provider.clone();
            let task =
                tokio::spawn(
                    async move { fetch_and_serialize_block(provider_clone, block_num).await },
                );
            tasks.push((block_num, task));
        }

        // Wait for all tasks in this batch to complete
        for (block_num, task) in tasks {
            match task.await? {
                Ok(block_data) => {
                    let filename = format!("block_{}.json", block_num);
                    let file_path = output_dir.join(&filename);

                    // Save block data to file
                    let json = serde_json::to_string_pretty(&block_data)?;
                    fs::write(&file_path, json)?;

                    // Update index
                    block_index.add_block(block_num, filename);

                    processed += 1;
                    info!("Saved block {} ({}/{})", block_num, processed, total_blocks);
                }
                Err(e) => {
                    error!("Failed to fetch block {}: {}", block_num, e);
                }
            }
        }

        // Save index periodically
        block_index.save_to_file(&index_path)?;

        // Add delay between batches to be nice to the RPC endpoint
        if chunk_end < end_block {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    // Final save of index
    block_index.save_to_file(&index_path)?;
    info!("Completed! Processed {} blocks", processed);
    info!("Block index saved to: {}", index_path.display());

    Ok(())
}

async fn fetch_and_serialize_block(
    provider: impl Provider,
    block_number: u64,
) -> Result<BlockData> {
    let block_id = BlockNumber::from(block_number).into();

    // Fetch full block with transactions
    let block: AnyRpcBlock = provider
        .get_block(block_id)
        .full()
        .await?
        .ok_or_else(|| eyre::eyre!("Block {} not found", block_number))
        .unwrap()
        .into();

    let block = block
        .into_inner()
        .map_header(|header| header.map(|h| h.into_header_with_defaults()))
        .try_map_transactions(|tx| {
            // try to convert unknowns into op type so that we can also support optimism
            tx.try_into_either::<op_alloy_consensus::OpTxEnvelope>()
        })
        .unwrap()
        .into_consensus();

    let versioned_hashes = block
        .body
        .blob_versioned_hashes_iter()
        .copied()
        .collect::<Vec<_>>();

    let (payload, sidecar) = ExecutionPayload::from_block_slow(&block);

    Ok(BlockData {
        block_number,
        payload: payload.as_v3().unwrap().clone(),
        requests: sidecar.requests_hash().unwrap(),
        parent_beacon_block_root: block.header.parent_beacon_block_root.unwrap(),
        versioned_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_index() {
        let mut index = BlockIndex::new();
        index.add_block(12345, "block_12345.json".to_string());

        assert_eq!(
            index.get_block_file(12345),
            Some(&"block_12345.json".to_string())
        );
        assert_eq!(index.get_block_file(54321), None);
    }

    #[tokio::test]
    async fn test_block_index_persistence() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_index.json");

        // Clean up any existing test file
        let _ = fs::remove_file(&test_file);

        {
            let mut index = BlockIndex::new();
            index.add_block(100, "block_100.json".to_string());
            index.add_block(101, "block_101.json".to_string());
            index.save_to_file(&test_file)?;
        }

        // Load and verify
        let loaded_index = BlockIndex::load_from_file(&test_file)?;
        assert_eq!(
            loaded_index.get_block_file(100),
            Some(&"block_100.json".to_string())
        );
        assert_eq!(
            loaded_index.get_block_file(101),
            Some(&"block_101.json".to_string())
        );

        // Clean up
        fs::remove_file(&test_file)?;

        Ok(())
    }
}
