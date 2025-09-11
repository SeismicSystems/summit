use alloy_rpc_types_engine::{ExecutionPayloadEnvelopeV4, ForkchoiceState};
use anyhow::Result;
use clap::{Arg, Command};
use commonware_utils::from_hex_formatted;
use std::path::PathBuf;
use summit_application::engine_client::EngineClient;
use summit_application::engine_client::benchmarking::HistoricalEngineClient;
use summit_types::{Block, Digest};

const GENESIS_HASH: &str = "0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let matches = Command::new("Execute Blocks")
        .version("1.0")
        .about("Executes historical blocks through op-reth engine API")
        .arg(
            Arg::new("block-dir")
                .long("block-dir")
                .value_name("PATH")
                .help("Directory containing block files")
                .required(true),
        )
        .arg(
            Arg::new("genesis-hash")
                .long("genesis-hash")
                .value_name("HASH")
                .help("Genesis block hash")
                .default_value(GENESIS_HASH),
        )
        .arg(
            Arg::new("engine-ipc-path")
                .long("engine-ipc-path")
                .value_name("PATH")
                .help("Engine API IPC socket path")
                .required(true),
        )
        .arg(
            Arg::new("num-blocks")
                .long("num-blocks")
                .value_name("COUNT")
                .help("Number of blocks to process")
                .default_value("50000"),
        )
        .get_matches();

    let block_dir = PathBuf::from(matches.get_one::<String>("block-dir").unwrap());
    let genesis_hash_str = matches.get_one::<String>("genesis-hash").unwrap();
    let engine_ipc_path = matches
        .get_one::<String>("engine-ipc-path")
        .unwrap()
        .to_string();
    let num_blocks: u64 = matches.get_one::<String>("num-blocks").unwrap().parse()?;

    let client = HistoricalEngineClient::new(engine_ipc_path, block_dir).await;

    // Load and commit blocks to Reth
    let genesis_hash: [u8; 32] = from_hex_formatted(genesis_hash_str)
        .unwrap()
        .try_into()
        .unwrap();

    let mut forkchoice = ForkchoiceState {
        head_block_hash: genesis_hash.into(),
        safe_block_hash: genesis_hash.into(),
        finalized_block_hash: genesis_hash.into(),
    };
    for _ in 0..num_blocks {
        match client.start_building_block(forkchoice, 0, vec![]).await {
            Some(payload_id) => {
                let payload = client.get_payload(payload_id).await;

                let block_number = payload
                    .execution_payload
                    .payload_inner
                    .payload_inner
                    .block_number;
                let block_hash = payload
                    .execution_payload
                    .payload_inner
                    .payload_inner
                    .block_hash;
                let parent_hash = payload
                    .execution_payload
                    .payload_inner
                    .payload_inner
                    .parent_hash;

                println!("Processing block {}: hash={:?}", block_number, block_hash);

                // Convert block data to Summit Block for check_payload
                //let genesis_hash = [0xf7, 0x12, 0xaa, 0x92, 0x41, 0xcc, 0x24, 0x36, 0x9b, 0x14, 0x3c, 0xf6, 0xdc, 0xe8, 0x5f, 0x09, 0x02, 0xa9, 0x73, 0x1e, 0x70, 0xd6, 0x68, 0x18, 0xa3, 0xa5, 0x84, 0x5b, 0x29, 0x6c, 0x73, 0xdd];
                let parent_digest: Digest = if block_number == 0 {
                    genesis_hash.into()
                } else {
                    (*parent_hash).into()
                };

                // use block number as view
                let summit_block =
                    execution_payload_envelope_to_block(payload, parent_digest, block_number);

                // Check payload with Reth
                let payload_status = client.check_payload(&summit_block).await;
                println!("  Payload status: {:?}", payload_status);

                forkchoice = ForkchoiceState {
                    head_block_hash: block_hash,
                    safe_block_hash: block_hash,
                    finalized_block_hash: block_hash,
                };

                client.commit_hash(forkchoice).await;
                println!("  Committed block {} to Reth", block_number);
            }
            None => {
                // this also happens when there are no more blocks
                eprintln!("failed to load block");
                break;
            }
        }
    }

    Ok(())
}

fn execution_payload_envelope_to_block(
    payload: ExecutionPayloadEnvelopeV4,
    parent: Digest,
    view: u64,
) -> Block {
    let execution_payload = payload.envelope_inner.execution_payload;
    let height = execution_payload.payload_inner.payload_inner.block_number;
    let timestamp = execution_payload.payload_inner.payload_inner.timestamp;

    // Convert execution requests from the envelope
    let execution_requests = payload.execution_requests.into_iter().collect::<Vec<_>>();

    Block::compute_digest(
        parent,
        height,
        timestamp,
        execution_payload,
        execution_requests,
        payload.envelope_inner.block_value,
        view,
    )
}
