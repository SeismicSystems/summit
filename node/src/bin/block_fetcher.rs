use alloy_network::AnyRpcBlock;
use alloy_primitives::{B256, BlockNumber, FixedBytes};
use alloy_provider::{Provider, RootProvider, network::AnyNetwork};
use alloy_rpc_client::ClientBuilder;
use alloy_rpc_types_engine::{ExecutionPayload, ExecutionPayloadV3};
use anyhow::{Result, anyhow};
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use summit_types::utils::benchmarking::BlockIndex;
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
        return Err(anyhow!(
            "Start block must be less than or equal to end block"
        ));
    }

    // Create output directory
    fs::create_dir_all(&output_dir)?;

    // Initialize block index
    let index_path = output_dir.join("index.json");
    let mut block_index = BlockIndex::load_from_file(&index_path)?;

    info!("Connecting to RPC at {}", rpc_url);
    let client = ClientBuilder::default().http(rpc_url.parse()?);
    let provider = RootProvider::<AnyNetwork>::new(client);

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

                    let block_hash = block_data.payload.payload_inner.payload_inner.block_hash;

                    // Save block data to file
                    let json = serde_json::to_string_pretty(&block_data)?;

                    let temp_file = output_dir.join("block.temp");
                    fs::write(&temp_file, json)?;
                    fs::rename(&temp_file, file_path)?;

                    // Update index
                    block_index.add_block(block_num, block_hash, filename);

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
    provider: impl Provider<AnyNetwork>,
    block_number: u64,
) -> Result<BlockData> {
    let block_id = BlockNumber::from(block_number).into();

    // Fetch full block with transactions
    let block: AnyRpcBlock = provider
        .get_block(block_id)
        .full()
        .await?
        .ok_or_else(|| anyhow!("Block {} not found", block_number))?;

    let block = block
        .into_inner()
        .map_header(|header| header.map(|h| h.into_header_with_defaults()))
        .try_map_transactions(|tx| {
            // try to convert unknowns into op type so that we can also support optimism
            tx.try_into_either::<op_alloy_consensus::OpTxEnvelope>()
        })?
        .into_consensus();

    // Extract parent beacon block root
    //let parent_beacon_block_root = block.header.parent_beacon_block_root;

    // Extract blob versioned hashes
    let versioned_hashes = block
        .body
        .blob_versioned_hashes_iter()
        .copied()
        .collect::<Vec<_>>();

    // Convert to execution payload
    let (payload, sidecar) = ExecutionPayload::from_block_slow(&block);

    // Convert payload to V3 format, handling V1/V2 payloads
    let payload_v3 = match payload {
        ExecutionPayload::V1(v1) => ExecutionPayloadV3 {
            payload_inner: alloy_rpc_types_engine::ExecutionPayloadV2 {
                payload_inner: v1,
                withdrawals: Vec::new(), // V1 doesn't have withdrawals
            },
            blob_gas_used: 0, // V1 doesn't have blob gas
            excess_blob_gas: 0,
        },
        ExecutionPayload::V2(v2) => ExecutionPayloadV3 {
            payload_inner: v2,
            blob_gas_used: 0, // V2 doesn't have blob gas
            excess_blob_gas: 0,
        },
        ExecutionPayload::V3(v3) => v3,
    };

    Ok(BlockData {
        block_number,
        payload: payload_v3,
        requests: sidecar.requests_hash().unwrap_or_default(),
        parent_beacon_block_root: block.header.parent_beacon_block_root.unwrap_or_default(),
        versioned_hashes,
    })
}
