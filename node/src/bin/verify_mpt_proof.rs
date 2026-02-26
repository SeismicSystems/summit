use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy_primitives::{Address, Bytes, U256, address, keccak256};
use clap::Parser;
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio as cw_tokio};
use futures::{FutureExt, pin_mut};
use jsonrpsee::http_client::HttpClientBuilder;
use std::collections::VecDeque;
use std::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr as _,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit_rpc::{SummitApiClient, SummitProofApiClient};
use summit_types::reth::Reth;
use summit_types::state_trie_key;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;

/// MPT verify precompile address in seismic-reth.
const MPT_VERIFY_ADDRESS: Address = address!("000000000000000000000000000000000000006A");

/// EIP-4788 beacon roots contract address.
const BEACON_ROOTS_ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

// Solidity contract that reads the state root from the beacon root contract
// and verifies an MPT proof via the precompile at 0x6A.
// Source: node/src/bin/MptProofVerifier.sol
sol! {
    #[sol(rpc, bytecode = "6080604052348015600e575f5ffd5b5061038f8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c806385852ce41461002d575b5f5ffd5b61004061003b366004610261565b610052565b60405190815260200160405180910390f35b5f5f5f720f3df6d732807ef1319fb7b8bb8522d0beac026001600160a01b03168660405160200161008591815260200190565b60408051601f198184030181529082905261009f916102d8565b5f60405180830381855afa9150503d805f81146100d7576040519150601f19603f3d011682016040523d82523d5f602084013e6100dc565b606091505b50915091508180156100ef575080516020145b6101405760405162461bcd60e51b815260206004820152601960248201527f626561636f6e20726f6f74206c6f6f6b7570206661696c65640000000000000060448201526064015b60405180910390fd5b8080602001905181019061015491906102ee565b92505f5f606a6001600160a01b031685888860405160200161017893929190610305565b60408051601f1981840301815290829052610192916102d8565b5f60405180830381855afa9150503d805f81146101ca576040519150601f19603f3d011682016040523d82523d5f602084013e6101cf565b606091505b50915091508180156101e357506020815110155b801561020a575080601f815181106101fd576101fd61031e565b60209101015160f81c6001145b6102565760405162461bcd60e51b815260206004820152601760248201527f4d505420766572696669636174696f6e206661696c65640000000000000000006044820152606401610137565b505050509392505050565b5f5f5f60408486031215610273575f5ffd5b83359250602084013567ffffffffffffffff811115610290575f5ffd5b8401601f810186136102a0575f5ffd5b803567ffffffffffffffff8111156102b6575f5ffd5b8660208284010111156102c7575f5ffd5b939660209190910195509293505050565b5f82518060208501845e5f920191825250919050565b5f602082840312156102fe575f5ffd5b5051919050565b838152818360208301375f910160200190815292915050565b634e487b7160e01b5f52603260045260245ffdfea2646970667358221220b71fedd15ce7dbd01f93188902209c75df5b1e0d90e6808a034743245447262d64736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3464313362633133005a")]
    contract MptProofVerifier {
        function verify(uint256 timestamp, bytes calldata proofData) external view returns (bytes32 root);
    }
}

/// Encode precompile input for the MPT verify precompile at 0x6A.
///
/// Format (per-key proofs matching the precompile's expected layout):
///   root (32 bytes)
///   item_count (u32 BE)
///   per item:
///     keccak256(logical_key) (32)
///     has_value (1)
///     [value_len (u32 BE) | value_bytes]   — only if has_value == 0x01
///     proof_node_count (u32 BE)            — number of proof nodes for this key
///     per node: node_len (u32 BE) | node_bytes
fn encode_mpt_verify_input(
    root: &[u8; 32],
    logical_keys: &[&[u8]],
    values: &[Option<Vec<u8>>],
    per_key_proofs: &[Vec<Vec<u8>>],
) -> Vec<u8> {
    assert_eq!(logical_keys.len(), values.len());
    assert_eq!(logical_keys.len(), per_key_proofs.len());
    let mut buf = Vec::new();

    buf.extend_from_slice(root);
    buf.extend_from_slice(&(logical_keys.len() as u32).to_be_bytes());

    for ((key, value), proof_nodes) in logical_keys
        .iter()
        .zip(values.iter())
        .zip(per_key_proofs.iter())
    {
        let hashed = keccak256(key);
        buf.extend_from_slice(hashed.as_slice());
        match value {
            Some(v) => {
                buf.push(0x01);
                buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
                buf.extend_from_slice(v);
            }
            None => {
                buf.push(0x00);
            }
        }
        // Per-key proof nodes
        buf.extend_from_slice(&(proof_nodes.len() as u32).to_be_bytes());
        for node in proof_nodes {
            buf.extend_from_slice(&(node.len() as u32).to_be_bytes());
            buf.extend_from_slice(node);
        }
    }
    buf
}

struct NodeRuntime {
    thread: JoinHandle<()>,
    stop_tx: mpsc::UnboundedSender<()>,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    pub log_dir: Option<String>,
    #[arg(long, default_value = "/tmp/summit_mpt_proof_test")]
    pub data_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Clean slate
    let data_dir_path = PathBuf::from(&args.data_dir);
    if data_dir_path.exists() {
        fs::remove_dir_all(&data_dir_path)?;
    }
    if let Some(ref log_dir) = args.log_dir {
        let _ = fs::remove_dir_all(log_dir);
        fs::create_dir_all(log_dir)?;
    }

    let storage_dir = data_dir_path.join("stores");
    let cfg = cw_tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(storage_dir)
        .with_catch_panics(false);
    let executor = cw_tokio::Runner::new(cfg);

    let node_runtimes = executor.start(|context| {
        async move {
            let log_level = Level::from_str("info").expect("Invalid log level");
            cw_tokio::telemetry::init(
                context.with_label("metrics"),
                cw_tokio::telemetry::Logging {
                    level: log_level,
                    json: false,
                },
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6969)),
                None,
            );

            let mut handles = VecDeque::new();
            let mut node_runtimes: Vec<NodeRuntime> = Vec::new();

            // ---------------------------------------------------------------
            // Start 4 Reth + 4 Summit nodes
            // ---------------------------------------------------------------
            println!("Starting testnet...");
            for x in 0..NUM_NODES {
                println!("******* STARTING RETH FOR NODE {x}");
                let data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
                fs::create_dir_all(&data_dir).expect("Failed to create data directory");

                let reth_builder = Reth::new()
                    .instance(x + 1)
                    .keep_stdout()
                    .data_dir(data_dir)
                    .arg("--enclave.mock-server")
                    .arg("--enclave.endpoint-port")
                    .arg(format!("1744{x}"))
                    .arg("--auth-ipc")
                    .arg("--auth-ipc.path")
                    .arg(format!("/tmp/reth_engine_api{x}.ipc"))
                    .arg("--metrics")
                    .arg(format!("0.0.0.0:{}", 9001 + x));

                let mut reth = reth_builder.spawn();
                let stdout = reth.stdout().expect("Failed to get stdout");

                let log_dir = args.log_dir.clone();
                context.clone().spawn(async move |_| {
                    let reader = BufReader::new(stdout);
                    let mut log_file = log_dir.as_ref().map(|dir| {
                        fs::File::create(format!("{}/node{}.log", dir, x))
                            .expect("Failed to create log file")
                    });
                    for line in reader.lines().map_while(Result::ok) {
                        if let Some(ref mut file) = log_file {
                            writeln!(file, "[Node {}] {}", x, line)
                                .expect("Failed to write to log file");
                        }
                    }
                });

                println!("Node {} rpc address: {}", x, reth.http_port());
                handles.push_back(reth);

                let flags = get_node_flags(x.into());
                let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
                let data_dir_clone = args.data_dir.clone();
                let thread = std::thread::spawn(move || {
                    let storage_dir =
                        PathBuf::from(&data_dir_clone).join("stores").join(format!("node{}", x));
                    let cfg = cw_tokio::Config::default()
                        .with_tcp_nodelay(Some(true))
                        .with_worker_threads(4)
                        .with_storage_directory(storage_dir)
                        .with_catch_panics(true);
                    let executor = cw_tokio::Runner::new(cfg);
                    executor.start(|node_context| async move {
                        let node_handle = node_context.clone().spawn(|ctx| async move {
                            run_node_local(ctx, flags, None, None).await.unwrap();
                        });
                        let stop_fut = stop_rx.recv().fuse();
                        pin_mut!(stop_fut);
                        futures::select! {
                            _ = stop_fut => {
                                println!("Node {} received stop signal, shutting down runtime...", x);
                                node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
                            }
                            _ = node_handle.fuse() => {
                                println!("Node {} handle completed", x);
                            }
                        }
                    });
                });
                node_runtimes.push(NodeRuntime { thread, stop_tx });
            }

            context.sleep(Duration::from_secs(5)).await;

            // ---------------------------------------------------------------
            // Wait for state
            // ---------------------------------------------------------------
            println!("Waiting for state...");
            let summit_rpc_port = get_node_flags(0).rpc_port;
            loop {
                match get_latest_height(summit_rpc_port).await {
                    Ok(h) if h > 0 => {
                        println!("Summit node 0 at height {h}");
                        break;
                    }
                    Ok(h) => println!("Summit height: {h}, waiting..."),
                    Err(e) => println!("Waiting for Summit RPC... ({e})"),
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // Give the network a few more blocks so the proof trie has been captured
            context.sleep(Duration::from_secs(5)).await;

            // ---------------------------------------------------------------
            // Query getStateProof(["epoch", "latest_height"])
            // ---------------------------------------------------------------
            println!("Querying getStateProof([\"epoch\", \"latest_height\"])...");
            let summit_url = format!("http://localhost:{}", summit_rpc_port);
            let summit_client = HttpClientBuilder::default().build(&summit_url).unwrap();
            let proof_resp = summit_client
                .get_state_proof(vec!["epoch".into(), "latest_height".into()])
                .await
                .expect("getStateProof failed");

            println!("  root: 0x{}", alloy::hex::encode(proof_resp.root));
            println!("  el_block_number: {}", proof_resp.el_block_number);
            println!(
                "  values: {:?}",
                proof_resp
                    .values
                    .iter()
                    .map(|v| v.as_ref().map(|b| format!("0x{}", alloy::hex::encode(b))))
                    .collect::<Vec<_>>()
            );
            println!("  proof nodes: {}", proof_resp.proof.len());

            // Build alloy provider (with wallet for TEST C)
            let node0_http_port = handles[0].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);
            let private_key =
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer =
                PrivateKeySigner::from_str(private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            // Logical keys that match the RPC query
            let logical_keys: Vec<&[u8]> =
                vec![state_trie_key::EPOCH, state_trie_key::LATEST_HEIGHT];

            // ---------------------------------------------------------------
            // TEST A: Beacon root contract
            // ---------------------------------------------------------------
            println!("\nTEST A: Beacon root contract query");
            let target_block = proof_resp.el_block_number + 1;
            // Wait for the target block to exist
            loop {
                match provider.get_block_number().await {
                    Ok(n) if n >= target_block => break,
                    Ok(n) => println!("  Reth at block {n}, waiting for {target_block}..."),
                    Err(e) => println!("  Reth not ready: {e}"),
                }
                context.sleep(Duration::from_secs(1)).await;
            }

            let block = provider
                .get_block_by_number(target_block.into())
                .await
                .expect("Failed to get block")
                .expect("Block not found");
            let timestamp = block.header.timestamp;
            println!("  Block {target_block} timestamp: {timestamp}");
            // The beacon root contract uses TIMESTAMPMS (0x4B), so it stores
            // millisecond timestamps. Query with the block's ms timestamp directly.
            let beacon_input = U256::from(timestamp).to_be_bytes::<32>();
            let beacon_tx = TransactionRequest::default()
                .with_to(BEACON_ROOTS_ADDRESS)
                .with_input(Bytes::copy_from_slice(&beacon_input));
            let beacon_result = provider
                .call(beacon_tx)
                .await
                .expect("Beacon root call failed");

            let returned_root: [u8; 32] = beacon_result[..32]
                .try_into()
                .expect("Beacon root response not 32 bytes");
            println!(
                "  Beacon root contract returned: 0x{}",
                alloy::hex::encode(returned_root)
            );
            assert_eq!(
                returned_root, proof_resp.root,
                "Beacon root does not match state proof root"
            );
            println!("  Root matches: YES");

            // ---------------------------------------------------------------
            // TEST B: Direct eth_call to precompile 0x6A
            // ---------------------------------------------------------------
            println!("\nTEST B: Direct eth_call to precompile 0x6A");
            let precompile_input = encode_mpt_verify_input(
                &proof_resp.root,
                &logical_keys,
                &proof_resp.values,
                &proof_resp.proof,
            );

            let precompile_tx = TransactionRequest::default()
                .with_to(MPT_VERIFY_ADDRESS)
                .with_input(Bytes::copy_from_slice(&precompile_input));
            let precompile_result = provider
                .call(precompile_tx)
                .await
                .expect("Precompile eth_call failed");

            assert!(
                precompile_result.len() >= 32,
                "Precompile output too short: {} bytes",
                precompile_result.len()
            );
            assert_eq!(
                precompile_result[31], 0x01,
                "Precompile did not return success (0x01)"
            );
            println!("  Result: SUCCESS (output[31] = 0x01)");

            // ---------------------------------------------------------------
            // TEST C: Deploy verifier contract + real transaction
            // ---------------------------------------------------------------
            println!("\nTEST C: Deploy MptProofVerifier + real transaction");

            // Deploy the Solidity contract
            let contract = MptProofVerifier::deploy(&provider)
                .await
                .expect("MptProofVerifier deploy failed");
            println!("  Contract deployed at: {}", contract.address());

            // proofData = precompile input WITHOUT the leading 32-byte root.
            // The contract reads the root from the beacon root contract itself.
            let proof_data = Bytes::copy_from_slice(&precompile_input[32..]);

            // First, verify via eth_call that the returned root matches
            let call_result = contract
                .verify(U256::from(timestamp), proof_data.clone())
                .call()
                .await
                .expect("MptProofVerifier.verify() eth_call failed");
            let contract_root: [u8; 32] = call_result.into();
            assert_eq!(
                contract_root, proof_resp.root,
                "Contract-returned root does not match expected root"
            );
            println!(
                "  eth_call returned root: 0x{}",
                alloy::hex::encode(contract_root)
            );

            // Now send a real transaction to exercise the full EVM path
            let pending_tx = contract
                .verify(U256::from(timestamp), proof_data)
                .gas(30_000_000)
                .gas_price(1_000_000_000)
                .send()
                .await
                .expect("MptProofVerifier.verify() send failed");
            let receipt = pending_tx
                .get_receipt()
                .await
                .expect("MptProofVerifier.verify() receipt failed");
            assert!(receipt.status(), "MptProofVerifier transaction reverted");
            println!("  Transaction status: SUCCESS");

            // ---------------------------------------------------------------
            // TEST D: Exclusion proof for nonexistent key
            // ---------------------------------------------------------------
            println!("\nTEST D: Exclusion proof for nonexistent key");
            let nonexistent_key = "validator_account_balance:0x0000000000000000000000000000000000000000000000000000000000000000";
            let exclusion_resp = summit_client
                .get_state_proof(vec![nonexistent_key.into()])
                .await
                .expect("getStateProof (exclusion) failed");

            assert!(
                exclusion_resp.values[0].is_none(),
                "Expected None for nonexistent key, got Some"
            );

            // Parse the logical key for encoding
            let parsed_key = summit_types::state_trie_key::validator_account_balance(&[0u8; 32]);
            let exclusion_logical_keys: Vec<&[u8]> = vec![&parsed_key];
            let exclusion_input = encode_mpt_verify_input(
                &exclusion_resp.root,
                &exclusion_logical_keys,
                &exclusion_resp.values,
                &exclusion_resp.proof,
            );

            let exclusion_tx = TransactionRequest::default()
                .with_to(MPT_VERIFY_ADDRESS)
                .with_input(Bytes::copy_from_slice(&exclusion_input));
            let exclusion_result = provider
                .call(exclusion_tx)
                .await
                .expect("Exclusion proof eth_call failed");

            assert!(
                exclusion_result.len() >= 32,
                "Exclusion proof output too short"
            );
            assert_eq!(
                exclusion_result[31], 0x01,
                "Exclusion proof did not return success"
            );
            println!("  Result: SUCCESS");

            // ---------------------------------------------------------------
            // Done
            // ---------------------------------------------------------------
            println!("\nAll tests passed!");

            // Shutdown
            println!("Sending stop signals to all {} nodes...", node_runtimes.len());
            for (idx, node_runtime) in node_runtimes.iter().enumerate() {
                println!("Sending stop signal to node {idx}...");
                let _ = node_runtime.stop_tx.send(());
            }

            Ok::<_, Box<dyn std::error::Error>>(node_runtimes)
        }
    })?;

    // Join all node threads outside async context
    println!("Waiting for all nodes to shut down...");
    for (idx, node_runtime) in node_runtimes.into_iter().enumerate() {
        println!("Waiting for node {idx} to join...");
        match node_runtime.thread.join() {
            Ok(_) => println!("Node {idx} thread joined successfully"),
            Err(e) => println!("Node {idx} thread join failed: {e:?}"),
        }
    }

    println!("All nodes shut down cleanly");
    std::process::exit(0);
}

async fn get_latest_height(rpc_port: u16) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", rpc_port);
    let client = HttpClientBuilder::default().build(&url)?;
    let height = client.get_latest_height().await?;
    Ok(height)
}

fn get_node_flags(node: usize) -> RunFlags {
    let path = format!("testnet/node{node}/");
    RunFlags {
        archive_mode: false,
        key_store_path: path.clone(),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        prom_ip: "0.0.0.0".into(),
        rpc_port: (3030 + (node * 10)) as u16,
        worker_threads: 2,
        log_level: "debug".into(),
        db_prefix: format!("{node}-quarts"),
        genesis_path: "./example_genesis.toml".into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(feature = "bench")]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: false,
        ip: None,
        bootstrappers: None,
    }
}
