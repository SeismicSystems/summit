use alloy_rpc_types_engine::{ExecutionPayloadEnvelopeV4, ForkchoiceState};
use anyhow::Result;
use clap::{Arg, Command};
use commonware_utils::from_hex_formatted;
use std::path::PathBuf;
use summit_types::engine_client::EngineClient;
#[cfg(feature = "base-bench")]
use summit_types::engine_client::base_benchmarking::HistoricalEngineClient;
#[cfg(feature = "bench")]
use summit_types::engine_client::benchmarking::EthereumHistoricalEngineClient;
use summit_types::{Block, Digest};

#[cfg(all(feature = "base-bench", not(feature = "bench")))]
const GENESIS_HASH: &str = "0xf712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd";
#[cfg(feature = "bench")]
const GENESIS_HASH: &str = "0x655cc1ecc77fe1eab4b1e62a1f461b7fddc9b06109b5ab3e9dc68c144b30c773";

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
            Arg::new("start-block")
                .long("start-block")
                .value_name("COUNT")
                .help("Block number of the first block")
                .default_value("0"),
        )
        .arg(
            Arg::new("num-blocks")
                .long("num-blocks")
                .value_name("COUNT")
                .help("Number of blocks to process")
                .default_value("1000"),
        )
        .get_matches();

    let block_dir = PathBuf::from(matches.get_one::<String>("block-dir").unwrap());
    let genesis_hash_str = matches.get_one::<String>("genesis-hash").unwrap();
    let engine_ipc_path = matches
        .get_one::<String>("engine-ipc-path")
        .unwrap()
        .to_string();
    let start_block: u64 = matches.get_one::<String>("start-block").unwrap().parse()?;
    let num_blocks: u64 = matches.get_one::<String>("num-blocks").unwrap().parse()?;

    #[allow(unused)]
    #[cfg(feature = "base-bench")]
    let client = HistoricalEngineClient::new(engine_ipc_path.clone(), block_dir.clone()).await;
    #[allow(unused)]
    #[cfg(feature = "bench")]
    let mut client = EthereumHistoricalEngineClient::new(engine_ipc_path, block_dir).await;

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
    let mut block_number = start_block;
    for _ in 0..num_blocks {
        println!("Block number: {}", block_number);
        #[cfg(any(feature = "bench", feature = "base-bench"))]
        let result = client
            .start_building_block(forkchoice, 0, vec![], block_number)
            .await;
        #[cfg(not(any(feature = "bench", feature = "base-bench")))]
        let result = client.start_building_block(forkchoice, 0, vec![]).await;
        match result {
            Some(payload_id) => {
                let payload = client.get_payload(payload_id).await;
                block_number = u64::from_le_bytes(payload_id.0.into());

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

                println!("forkchoice: {:?}", block_hash);
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
        0, // epoch
        view,
        None,                    // checkpoint_hash
        Digest::from([0u8; 32]), // prev_epoch_header_hash
        Vec::new(),              // added_validators
        Vec::new(),              // removed_validators
    )
}

/* Use this bash script to start Reth with the correct configuration

#!/bin/bash

# Base Mainnet Reth Startup Script
# This script starts op-reth configured for Base mainnet with Engine API enabled
# Usage: ./start-base-mainnet.sh [--debug] [--clear] [additional args...]

set -e

# Parse flags
DEBUG_MODE=false
CLEAR_DATA=false
ARGS=()

for arg in "$@"; do
    case $arg in
    --debug)
        DEBUG_MODE=true
        shift
        ;;
    --clear)
        CLEAR_DATA=true
        shift
        ;;
    *)
        ARGS+=("$arg")
        ;;
    esac
done

# Configuration
DATA_DIR="$HOME/.reth/base-mainnet"
JWT_SECRET_PATH="$DATA_DIR/jwt.hex"
IPC_PATH="/tmp/reth-engine.ipc"
ENGINE_PORT=8551
HTTP_PORT=8545
WS_PORT=8546
P2P_PORT=30303

# Debug configuration
if [ "$DEBUG_MODE" = true ]; then
    LOG_LEVEL="debug"
    LOG_TARGETS="reth::cli,op_reth::cli,reth_node_core,reth_engine_tree,reth_evm,reth_provider,reth_blockchain_tree"
else
    LOG_LEVEL="info"
    LOG_TARGETS=""
fi

# Clear data directory if requested
if [ "$CLEAR_DATA" = true ]; then
    if [ -d "$DATA_DIR" ]; then
        echo "Clearing data directory: $DATA_DIR"
        rm -rf "$DATA_DIR"
    fi
fi

# Create data directory if it doesn't exist
mkdir -p "$DATA_DIR"

echo "Starting Base mainnet node..."
echo "Data directory: $DATA_DIR"
echo "Engine API: http://localhost:$ENGINE_PORT"
echo "Engine IPC: $IPC_PATH"
echo "HTTP RPC: http://localhost:$HTTP_PORT"
echo "WebSocket RPC: ws://localhost:$WS_PORT"
echo "Metrics: http://localhost:9001/metrics"
echo "Log level: $LOG_LEVEL"

# Build logging arguments
LOG_ARGS=()
if [ "$DEBUG_MODE" = true ]; then
    LOG_ARGS+=(--log.stdout.filter "$LOG_TARGETS=$LOG_LEVEL")
    LOG_ARGS+=(--log.file.filter "$LOG_TARGETS=$LOG_LEVEL")
    LOG_ARGS+=(-vvvv) # Very verbose
else
    LOG_ARGS+=(--log.stdout.filter "$LOG_LEVEL")
    LOG_ARGS+=(-vvv) # Info level
fi

# Start op-reth with Base mainnet configuration
exec cargo run --bin op-reth --package op-reth --release -- node \
    --chain base \
    --datadir "$DATA_DIR" \
    --port "$P2P_PORT" \
    --http \
    --http.port "$HTTP_PORT" \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --ws \
    --ws.port "$WS_PORT" \
    --ws.addr 0.0.0.0 \
    --auth-ipc \
    --auth-ipc.path "$IPC_PATH" \
    --full \
    --discovery.port "$P2P_PORT" \
    --metrics 0.0.0.0:9001 \
    "${LOG_ARGS[@]}" \
    "${ARGS[@]}"
 */
