/*
This bin will start 4 reth nodes with an instance of consensus for each and keep running so you can run other tests or submit transactions

Their rpc endpoints are localhost:8545-node_number
node0_port = 8545
node1_port = 8544
...
node3_port = 8542


*/
use alloy::hex::FromHex;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, U256, keccak256};
use clap::Parser;
use commonware_cryptography::Sha256;
use commonware_cryptography::{Hasher, PrivateKeyExt, Signer, bls12381, ed25519::PrivateKey};
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio as cw_tokio};
use futures::{FutureExt, pin_mut};
use ssz::Decode;
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
use summit::engine::VALIDATOR_MINIMUM_STAKE;
use summit_types::PROTOCOL_VERSION;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::execution_request::DepositRequest;
use summit_types::execution_request::compute_deposit_data_root;
use summit_types::reth::Reth;
use summit_types::rpc::CheckpointRes;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;

struct NodeRuntime {
    thread: JoinHandle<()>,
    stop_tx: mpsc::UnboundedSender<()>,
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to the directory containing historical blocks for benchmarking
    #[cfg(any(feature = "base-bench", feature = "bench"))]
    #[arg(long)]
    pub bench_block_dir: Option<String>,
    /// Path to the log directory
    #[arg(long)]
    pub log_dir: Option<String>,
    /// Path to the data directory for test
    #[arg(long, default_value = "/tmp/summit_checkpointing_test")]
    pub data_dir: String,
    /// Height at which the joining node will download the checkpoint
    #[arg(long, default_value_t = 1000)]
    pub checkpoint_height: u64,
    /// Height that all nodes must reach for the test to succeed
    #[arg(long, default_value_t = 2000)]
    pub stop_height: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Remove data_dir if it exists to start fresh
    let data_dir_path = PathBuf::from(&args.data_dir);
    if data_dir_path.exists() {
        fs::remove_dir_all(&data_dir_path)?;
    }

    // Create log directory if specified
    if let Some(ref log_dir) = args.log_dir {
        fs::remove_dir_all(log_dir)?;
        fs::create_dir_all(log_dir)?;
    }

    let storage_dir = data_dir_path.join("stores");

    let cfg = cw_tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(storage_dir)
        .with_catch_panics(false);
    let executor = cw_tokio::Runner::new(cfg);

    executor.start(|context| {
        async move {
            // Configure telemetry
            let log_level = Level::from_str("info").expect("Invalid log level");
            cw_tokio::telemetry::init(
                context.with_label("metrics"),
                cw_tokio::telemetry::Logging {
                    level: log_level,
                    // todo: dont know what this does
                    json: false,
                },
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6969)),
                None,
            );

            // Vec to hold all the join handles
            let mut handles = VecDeque::new();
            let mut node_runtimes: Vec<NodeRuntime> = Vec::new();
            // let mut read_threads = Vec::new();

            // Start all nodes at the beginning
            for x in 0..NUM_NODES {
                // Start Reth
                println!("******* STARTING RETH FOR NODE {x}");

                // Create data directory if it doesn't exist
                let data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
                fs::create_dir_all(&data_dir).expect("Failed to create data directory");

                // Build and spawn reth instance
                let reth_builder = Reth::new()
                    .instance(x + 1)
                    .keep_stdout()
                    //    .genesis(serde_json::from_str(&genesis_str).expect("invalid genesis"))
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

                // Get stdout handle
                let stdout = reth.stdout().expect("Failed to get stdout");

                let log_dir = args.log_dir.clone();
                context.clone().spawn(async move |_| {
                    let reader = BufReader::new(stdout);
                    let mut log_file = log_dir.as_ref().map(|dir| {
                        fs::File::create(format!("{}/node{}.log", dir, x))
                            .expect("Failed to create log file")
                    });

                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                if let Some(ref mut file) = log_file {
                                    writeln!(file, "[Node {}] {}", x, line)
                                        .expect("Failed to write to log file");
                                }
                            }
                            Err(_e) => {
                                //   eprintln!("[Node {}] Error reading line: {}", x, e);
                            }
                        }
                    }
                });

                let _auth_port = reth.auth_port().unwrap();

                println!("Node {} rpc address: {}", x, reth.http_port());

                handles.push_back(reth);

                #[allow(unused_mut)]
                let mut flags = get_node_flags(x.into());

                #[cfg(any(feature = "base-bench", feature = "bench"))]
                {
                    flags.bench_block_dir = args.bench_block_dir.clone();
                }

                // Start our consensus engine in its own runtime/thread
                let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
                let data_dir_clone = args.data_dir.clone();
                let thread = std::thread::spawn(move || {
                    let storage_dir = PathBuf::from(&data_dir_clone).join("stores").join(format!("node{}", x));
                    let cfg = cw_tokio::Config::default()
                        .with_tcp_nodelay(Some(true))
                        .with_worker_threads(4)
                        .with_storage_directory(storage_dir)
                        .with_catch_panics(true);
                    let executor = cw_tokio::Runner::new(cfg);

                    executor.start(|node_context| async move {
                        let node_handle = node_context.clone().spawn(|ctx| async move {
                            run_node_local(ctx, flags, None).await.unwrap();
                        });

                        // Wait for stop signal or node completion
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

            // Wait a bit for nodes to be ready
            context.sleep(Duration::from_secs(5)).await;

            // Send a deposit transaction to node0
            println!("Sending deposit transaction to node 0");
            let node0_http_port = handles[0].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);

            // Create a test private key and signer
            let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer = PrivateKeySigner::from_str(private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);

            // Create provider with wallet
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            // Deposit contract address (you'll need to set this to the actual address)
            let deposit_contract =
                Address::from_hex("0x00000000219ab540356cBB839Cbe05303d7705Fa").unwrap();

            // Create test deposit parameters
            // Generate a deterministic ed25519 key pair and get the public key
            // Generate node (ed25519) keys
            let ed25519_private_key = PrivateKey::from_seed(100);
            let ed25519_public_key = ed25519_private_key.public_key();
            let ed25519_pubkey_bytes: [u8; 32] = ed25519_public_key.to_vec().try_into().unwrap();

            // Generate consensus (BLS) keys
            let bls_private_key = bls12381::PrivateKey::from_seed(100);
            let bls_public_key = bls_private_key.public_key();

            // Withdrawal credentials (32 bytes) - 0x01 prefix for execution address withdrawal
            // Format: 0x01 || 0x00...00 (11 bytes) || execution_address (20 bytes)
            let mut withdrawal_credentials = [0u8; 32];
            withdrawal_credentials[0] = 0x01; // ETH1 withdrawal prefix
            // Bytes 1-11 remain zero
            // Set the last 20 bytes to the withdrawal address (using the same address as the sender)
            let withdrawal_address =
                Address::from_hex("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_slice());

            let amount = VALIDATOR_MINIMUM_STAKE;

            let deposit_request = DepositRequest {
                node_pubkey: ed25519_public_key,
                consensus_pubkey: bls_public_key.clone(),
                withdrawal_credentials,
                amount,
                node_signature: [0; 64],
                consensus_signature: [0; 96],
                index: 0, // not included in the signature
            };

            let protocol_version_digest = Sha256::hash(&PROTOCOL_VERSION.to_le_bytes());
            let message = deposit_request.as_message(protocol_version_digest);

            // Sign with node (ed25519) key
            let node_signature = ed25519_private_key.sign(&[], &message);
            let node_signature_bytes: [u8; 64] = node_signature.as_ref().try_into().unwrap();

            // Sign with consensus (BLS) key
            let consensus_signature = bls_private_key.sign(&[], &message);
            let consensus_signature_slice: &[u8] = consensus_signature.as_ref();
            let consensus_signature_bytes: [u8; 96] = consensus_signature_slice.try_into().unwrap();

            // Convert VALIDATOR_MINIMUM_STAKE (in gwei) to wei
            let deposit_amount = U256::from(amount) * U256::from(1_000_000_000u64); // gwei to wei

            // Get BLS public key bytes
            use commonware_codec::Encode;
            let bls_pubkey_bytes: [u8; 48] = bls_public_key.encode().as_ref()[..48].try_into().unwrap();

            send_deposit_transaction(
                &provider,
                deposit_contract,
                deposit_amount,
                &ed25519_pubkey_bytes,
                &bls_pubkey_bytes,
                &withdrawal_credentials,
                &node_signature_bytes,
                &consensus_signature_bytes,
                0, // nonce
            )
            .await
            .expect("failed to send deposit transaction");

            // Wait for nodes to reach checkpoint height
            println!(
                "Waiting for nodes to reach checkpoint height {}",
                args.checkpoint_height
            );
            let node0_rpc_port = get_node_flags(0).rpc_port;
            loop {
                match get_latest_height(node0_rpc_port).await {
                    Ok(height) if height >= args.checkpoint_height => {
                        println!("Nodes reached checkpoint height {}", height);
                        break;
                    }
                    Ok(height) => {
                        println!("Node 0 at height {}", height);
                    }
                    Err(e) => {
                        println!("Error querying height: {}", e);
                    }
                }
                context.sleep(Duration::from_secs(1)).await;
            }

            // Retrieve checkpoint from first node
            println!("Retrieving checkpoint from node 0");
            let checkpoint_state = loop {
                match get_latest_checkpoint(node0_rpc_port).await {
                    Ok(Some(checkpoint)) => {
                        let state = ConsensusState::try_from(&checkpoint)
                            .expect("Failed to parse checkpoint");
                        println!("Retrieved checkpoint at height {}", state.latest_height);
                        break state;
                    }
                    Ok(None) => {
                        println!("Checkpoint not yet available");
                    }
                    Err(e) => {
                        println!("Error retrieving checkpoint: {}", e);
                    }
                }
                context.sleep(Duration::from_secs(1)).await;
            };

            // Start the joining Reth node
            let x = NUM_NODES;
            let num_nodes = NUM_NODES + 1;
            println!("******* STARTING RETH FOR NODE {} (joining node)", x);
            let data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
            fs::create_dir_all(&data_dir).expect("Failed to create data directory");

            // Copy db and static_files from node0 to initialize the joining node

            // Stop node0's consensus engine first (to avoid IPC errors)
            let source_node = 0;
            println!("Stopping node{} consensus engine...", source_node);
            let node0_runtime = node_runtimes.remove(source_node);

            // Send stop signal and wait for runtime to shut down gracefully
            node0_runtime.stop_tx.send(()).expect("Failed to send stop signal");
            println!("Waiting for node{} runtime to shut down...", source_node);
            let _ = tokio::task::spawn_blocking(move || {
                node0_runtime.thread.join().expect("Failed to join node0 thread");
            }).await;

            // Give OS time to release ports (P2P sockets can take time to close)
            println!("Waiting for ports to be released...");
            context.sleep(Duration::from_secs(3)).await;

            // Stop source reth instance and wait for graceful shutdown
            let mut snapshot_reth = handles.pop_front().expect("No reth instance to snapshot");
            println!("Sending SIGTERM to node{} Reth and waiting for shutdown...", source_node);
            snapshot_reth.terminate_and_wait().expect("Failed to terminate reth");
            println!("Node{} shut down successfully", source_node);

            let source_data_dir = format!("{}/node{}/data/reth_db", args.data_dir, source_node);

            println!("Copying db from node{} to node{}", source_node, x);
            let source_db = format!("{}/db", source_data_dir);
            let dest_db = format!("{}/db", data_dir);
            copy_dir_all(&source_db, &dest_db).expect("Failed to copy db directory");

            println!("Copying static_files from node{} to node{}", source_node, x);
            let source_static = format!("{}/static_files", source_data_dir);
            let dest_static = format!("{}/static_files", data_dir);
            copy_dir_all(&source_static, &dest_static)
                .expect("Failed to copy static_files directory");

            // Restart nodeß's reth instance
            //let reth_builder = Reth::new()
            //    .instance((source_node + 1) as u16)
            //    .keep_stdout()
            //    //    .genesis(serde_json::from_str(&genesis_str).expect("invalid genesis"))
            //    .data_dir(source_data_dir.clone())
            //    .arg("--enclave.mock-server")
            //    .arg("--enclave.endpoint-port")
            //    .arg(format!("1744{source_node}"))
            //    .arg("--auth-ipc")
            //    .arg("--auth-ipc.path")
            //    .arg(format!("/tmp/reth_engine_api{source_node}.ipc"))
            //    .arg("--metrics")
            //    .arg(format!("0.0.0.0:{}", 9001 + source_node));
            //let reth = reth_builder.spawn();
            //handles.push_front(reth);

            // Restart node0's consensus engine in a new runtime/thread
            //println!("Restarting node{} consensus engine...", source_node);
            //let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
            //let data_dir_clone = args.data_dir.clone();
            //let thread = std::thread::spawn(move || {
            //    let storage_dir = PathBuf::from(&data_dir_clone).join("stores").join(format!("node{}", source_node));
            //    let cfg = cw_tokio::Config::default()
            //        .with_tcp_nodelay(Some(true))
            //        .with_worker_threads(4)
            //        .with_storage_directory(storage_dir)
            //        .with_catch_panics(true);
            //    let executor = cw_tokio::Runner::new(cfg);

            //    executor.start(|node_context| async move {
            //        let flags = get_node_flags(source_node);
            //        let node_handle = node_context.clone().spawn(|ctx| async move {
            //            run_node_with_runtime(ctx, flags, None).await.unwrap();
            //        });

            //        // Wait for stop signal or node completion
            //        let stop_fut = stop_rx.recv().fuse();
            //        pin_mut!(stop_fut);
            //        futures::select! {
            //            _ = stop_fut => {
            //                println!("Node {} received stop signal, shutting down runtime...", source_node);
            //                node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
            //            }
            //            _ = node_handle.fuse() => {
            //                println!("Node {} handle completed", source_node);
            //            }
            //        }
            //    });
            //});
            //node_runtimes.insert(source_node, NodeRuntime { thread, stop_tx });

            // Start node4's reth instance
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

                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            if let Some(ref mut file) = log_file {
                                writeln!(file, "[Node {}] {}", x, line)
                                    .expect("Failed to write to log file");
                            }
                        }
                        Err(_e) => {}
                    }
                }
            });

            println!("Node {} rpc address: {}", x, reth.http_port());
            handles.push_back(reth);

            // Start the 4th consensus node with checkpoint
            #[allow(unused_mut)]
            let mut flags = get_node_flags(x.into());

            #[cfg(any(feature = "base-bench", feature = "bench"))]
            {
                flags.bench_block_dir = args.bench_block_dir.clone();
            }

            let node_key_path = format!("{}/node{}/data/node_key.pem", args.data_dir, x);
            let consensus_key_path = format!("{}/node{}/data/consensus_key.pem", args.data_dir, x);

            // Write node key
            let encoded_node_key = ed25519_private_key.to_string();
            fs::write(&node_key_path, encoded_node_key).expect("Unable to write node key to disk");

            // Write consensus key
            let encoded_consensus_key = bls_private_key.to_string();
            fs::write(&consensus_key_path, encoded_consensus_key).expect("Unable to write consensus key to disk");

            flags.key_store_path = format!("{}/node{}/data", args.data_dir, x);
            flags.ip = Some("127.0.0.1:26640".to_string());

            println!(
                "Starting consensus engine for node {} with checkpoint",
                ed25519_private_key.public_key()
            );

            // Start the joining node in its own runtime/thread
            let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
            let data_dir_clone = args.data_dir.clone();
            let thread = std::thread::spawn(move || {
                let storage_dir = PathBuf::from(&data_dir_clone).join("stores").join(format!("node{}", x));
                let cfg = cw_tokio::Config::default()
                    .with_tcp_nodelay(Some(true))
                    .with_worker_threads(4)
                    .with_storage_directory(storage_dir)
                    .with_catch_panics(true);
                let executor = cw_tokio::Runner::new(cfg);

                executor.start(|node_context| async move {
                    let node_handle = node_context.clone().spawn(|ctx| async move {
                        run_node_local(ctx, flags, Some(checkpoint_state)).await.unwrap();
                    });

                    // Wait for stop signal or node completion
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

            // Wait for all nodes to continue making progress
            println!(
                "Waiting for all {} nodes to reach height {}",
                num_nodes, args.stop_height
            );
            loop {
                let mut all_ready = true;
                //for idx in 0..num_nodes {
                // Skip node0
                for idx in 1..num_nodes {
                    let rpc_port = get_node_flags(idx as usize).rpc_port;
                    match get_latest_height(rpc_port).await {
                        Ok(height) => {
                            if height < args.stop_height {
                                all_ready = false;
                                println!("Node {} at height {}", idx, height);
                            }
                        }
                        Err(e) => {
                            all_ready = false;
                            println!("Node {} error: {}", idx, e);
                        }
                    }
                }
                if all_ready {
                    println!("All nodes have reached target height!");
                    break;
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            println!("Test completed successfully!");

            // Send stop signals to all nodes first
            println!("Sending stop signals to all {} nodes...", node_runtimes.len());
            for (idx, node_runtime) in node_runtimes.iter().enumerate() {
                println!("Sending stop signal to node index {}...", idx);
                let _ = node_runtime.stop_tx.send(());
            }

            // Now wait for all threads to finish
            println!("Waiting for all nodes to shut down...");
            for (idx, node_runtime) in node_runtimes.into_iter().enumerate() {
                println!("Waiting for node index {} to join...", idx);
                let _ = tokio::task::spawn_blocking(move || {
                    match node_runtime.thread.join() {
                        Ok(_) => println!("Node index {} thread joined successfully", idx),
                        Err(e) => println!("Node index {} thread join failed: {:?}", idx, e),
                    }
                }).await;
            }

            println!("All nodes shut down cleanly");
            Ok(())
        }
    })
}

fn copy_dir_all(src: &str, dst: &str) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = PathBuf::from(dst).join(entry.file_name());

        if ty.is_dir() {
            copy_dir_all(
                src_path.to_str().expect("Invalid path"),
                dst_path.to_str().expect("Invalid path"),
            )?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

async fn get_latest_height(rpc_port: u16) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}/get_latest_height", rpc_port);
    let response = reqwest::get(&url).await?.text().await?;
    Ok(response.parse()?)
}

async fn get_latest_checkpoint(
    rpc_port: u16,
) -> Result<Option<Checkpoint>, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}/get_latest_checkpoint", rpc_port);
    let response = reqwest::get(&url).await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let checkpoint_resp: CheckpointRes = resp.json().await?;
            //  let bytes = from_hex_formatted(&hex_str).ok_or("Failed to decode hex")?;
            let checkpoint = Checkpoint::from_ssz_bytes(&checkpoint_resp.checkpoint)
                .map_err(|e| format!("Failed to decode checkpoint: {:?}", e))?;
            Ok(Some(checkpoint))
        }
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_deposit_transaction<P>(
    provider: &P,
    deposit_contract_address: Address,
    deposit_amount: U256,
    node_pubkey: &[u8; 32],
    consensus_pubkey: &[u8; 48],
    withdrawal_credentials: &[u8; 32],
    node_signature: &[u8; 64],
    consensus_signature: &[u8; 96],
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Provider + WalletProvider,
{
    // Compute the correct deposit data root for this transaction
    let deposit_data_root = compute_deposit_data_root(
        node_pubkey,
        consensus_pubkey,
        withdrawal_credentials,
        deposit_amount,
        node_signature,
        consensus_signature,
    );

    // Create deposit function call data: deposit(bytes,bytes,bytes,bytes,bytes,bytes32)
    let function_selector = &keccak256("deposit(bytes,bytes,bytes,bytes,bytes,bytes32)")[0..4];
    let mut call_data = function_selector.to_vec();

    // ABI encode parameters - calculate offsets for 6 parameters (5 dynamic + 1 fixed)
    // Offsets start after the 6 parameter slots (6 * 32 bytes)
    let offset_to_node_pubkey = 6 * 32;
    let offset_to_consensus_pubkey =
        offset_to_node_pubkey + 32 + node_pubkey.len().div_ceil(32) * 32;
    let offset_to_withdrawal_creds =
        offset_to_consensus_pubkey + 32 + consensus_pubkey.len().div_ceil(32) * 32;
    let offset_to_node_signature =
        offset_to_withdrawal_creds + 32 + withdrawal_credentials.len().div_ceil(32) * 32;
    let offset_to_consensus_signature =
        offset_to_node_signature + 32 + node_signature.len().div_ceil(32) * 32;

    // Add parameter offsets
    let mut offset_bytes = vec![0u8; 32];
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_withdrawal_creds as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_node_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_consensus_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add the fixed bytes32 parameter (deposit_data_root)
    call_data.extend_from_slice(&deposit_data_root);

    // Add dynamic data
    let mut length_bytes = [0u8; 32];

    // Node pubkey (32 bytes ed25519)
    length_bytes[28..32].copy_from_slice(&(node_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_pubkey);

    // Consensus pubkey (48 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_pubkey);
    call_data.extend_from_slice(&[0u8; 16]); // Pad 48 to 64 bytes (next 32-byte boundary)

    // Withdrawal credentials (32 bytes)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(withdrawal_credentials.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(withdrawal_credentials);

    // Node signature (64 bytes ed25519)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(node_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(node_signature);

    // Consensus signature (96 bytes BLS)
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(consensus_signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    call_data.extend_from_slice(consensus_signature);

    let tx_request = TransactionRequest::default()
        .with_to(deposit_contract_address)
        .with_value(deposit_amount)
        .with_input(call_data)
        .with_gas_limit(500_000)
        .with_gas_price(1_000_000_000) // 1 gwei
        .with_nonce(nonce);

    match provider.send_transaction(tx_request).await {
        Ok(pending) => {
            println!("Transaction sent: {}", pending.tx_hash());
            match pending.get_receipt().await {
                Ok(receipt) => {
                    println!("Receipt: {:?}", receipt);
                    Ok(())
                }
                Err(e) => panic!("Transaction failed: {e}"),
            }
        }
        Err(e) => panic!("Error sending transaction: {}", e),
    }
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
        #[cfg(any(feature = "base-bench", feature = "bench"))]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: None,
        ip: None,
    }
}

/*
This test only works if the deposit contract is deployed. The contract can be added as a pre-deploy to the Reth genesis like this:

"0x00000000219ab540356cBB839Cbe05303d7705Fa": {
    "code": "0x60806040526004361061003f5760003560e01c806301ffc9a71461004457806322895118146100b6578063621fd130146101e3578063c5f2892f14610273575b600080fd5b34801561005057600080fd5b5061009c6004803603602081101561006757600080fd5b8101908080357bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916906020019092919050505061029e565b604051808215151515815260200191505060405180910390f35b6101e1600480360360808110156100cc57600080fd5b81019080803590602001906401000000008111156100e957600080fd5b8201836020820111156100fb57600080fd5b8035906020019184600183028401116401000000008311171561011d57600080fd5b90919293919293908035906020019064010000000081111561013e57600080fd5b82018360208201111561015057600080fd5b8035906020019184600183028401116401000000008311171561017257600080fd5b90919293919293908035906020019064010000000081111561019357600080fd5b8201836020820111156101a557600080fd5b803590602001918460018302840111640100000000831117156101c757600080fd5b909192939192939080359060200190929190505050610370565b005b3480156101ef57600080fd5b506101f8610fd0565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561023857808201518184015260208101905061021d565b50505050905090810190601f1680156102655780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561027f57600080fd5b50610288610fe2565b6040518082815260200191505060405180910390f35b60007f01ffc9a7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916148061036957507f85640907000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916145b9050919050565b603087879050146103cc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806116ec6026913960400191505060405180910390fd5b60208585905014610428576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260368152602001806116836036913960400191505060405180910390fd5b60608383905014610484576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602981526020018061175f6029913960400191505060405180910390fd5b670de0b6b3a76400003410156104e5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806117396026913960400191505060405180910390fd5b6000633b9aca0034816104f457fe5b061461054b576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260338152602001806116b96033913960400191505060405180910390fd5b6000633b9aca00348161055a57fe5b04905067ffffffffffffffff80168111156105c0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260278152602001806117126027913960400191505060405180910390fd5b60606105cb82611314565b90507f649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c589898989858a8a610600602054611314565b60405180806020018060200180602001806020018060200186810386528e8e82818152602001925080828437600081840152601f19601f82011690508083019250505086810385528c8c82818152602001925080828437600081840152601f19601f82011690508083019250505086810384528a818151815260200191508051906020019080838360005b838110156106a657808201518184015260208101905061068b565b50505050905090810190601f1680156106d35780820380516001836020036101000a031916815260200191505b508681038352898982818152602001925080828437600081840152601f19601f820116905080830192505050868103825287818151815260200191508051906020019080838360005b8381101561073757808201518184015260208101905061071c565b50505050905090810190601f1680156107645780820380516001836020036101000a031916815260200191505b509d505050505050505050505050505060405180910390a1600060028a8a600060801b6040516020018084848082843780830192505050826fffffffffffffffffffffffffffffffff19166fffffffffffffffffffffffffffffffff1916815260100193505050506040516020818303038152906040526040518082805190602001908083835b6020831061080e57805182526020820191506020810190506020830392506107eb565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610850573d6000803e3d6000fd5b5050506040513d602081101561086557600080fd5b8101908080519060200190929190505050905060006002808888600090604092610891939291906115da565b6040516020018083838082843780830192505050925050506040516020818303038152906040526040518082805190602001908083835b602083106108eb57805182526020820191506020810190506020830392506108c8565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa15801561092d573d6000803e3d6000fd5b5050506040513d602081101561094257600080fd5b8101908080519060200190929190505050600289896040908092610968939291906115da565b6000801b604051602001808484808284378083019250505082815260200193505050506040516020818303038152906040526040518082805190602001908083835b602083106109cd57805182526020820191506020810190506020830392506109aa565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610a0f573d6000803e3d6000fd5b5050506040513d6020811015610a2457600080fd5b810190808051906020019092919050505060405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b60208310610a8e5780518252602082019150602081019050602083039250610a6b565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610ad0573d6000803e3d6000fd5b5050506040513d6020811015610ae557600080fd5b810190808051906020019092919050505090506000600280848c8c604051602001808481526020018383808284378083019250505093505050506040516020818303038152906040526040518082805190602001908083835b60208310610b615780518252602082019150602081019050602083039250610b3e565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610ba3573d6000803e3d6000fd5b5050506040513d6020811015610bb857600080fd5b8101908080519060200190929190505050600286600060401b866040516020018084805190602001908083835b60208310610c085780518252602082019150602081019050602083039250610be5565b6001836020036101000a0380198251168184511680821785525050505050509050018367ffffffffffffffff191667ffffffffffffffff1916815260180182815260200193505050506040516020818303038152906040526040518082805190602001908083835b60208310610c935780518252602082019150602081019050602083039250610c70565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610cd5573d6000803e3d6000fd5b5050506040513d6020811015610cea57600080fd5b810190808051906020019092919050505060405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b60208310610d545780518252602082019150602081019050602083039250610d31565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610d96573d6000803e3d6000fd5b5050506040513d6020811015610dab57600080fd5b81019080805190602001909291905050509050858114610e16576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252605481526020018061162f6054913960600191505060405180910390fd5b6001602060020a0360205410610e77576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602181526020018061160e6021913960400191505060405180910390fd5b60016020600082825401925050819055506000602054905060008090505b6020811015610fb75760018083161415610ec8578260008260208110610eb757fe5b018190555050505050505050610fc7565b600260008260208110610ed757fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b60208310610f335780518252602082019150602081019050602083039250610f10565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610f75573d6000803e3d6000fd5b5050506040513d6020811015610f8a57600080fd5b8101908080519060200190929190505050925060028281610fa757fe5b0491508080600101915050610e95565b506000610fc057fe5b5050505050505b50505050505050565b6060610fdd602054611314565b905090565b6000806000602054905060008090505b60208110156111d057600180831614156110e05760026000826020811061101557fe5b01548460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b60208310611071578051825260208201915060208101905060208303925061104e565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa1580156110b3573d6000803e3d6000fd5b5050506040513d60208110156110c857600080fd5b810190808051906020019092919050505092506111b6565b600283602183602081106110f057fe5b015460405160200180838152602001828152602001925050506040516020818303038152906040526040518082805190602001908083835b6020831061114b5780518252602082019150602081019050602083039250611128565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa15801561118d573d6000803e3d6000fd5b5050506040513d60208110156111a257600080fd5b810190808051906020019092919050505092505b600282816111c057fe5b0491508080600101915050610ff2565b506002826111df602054611314565b600060401b6040516020018084815260200183805190602001908083835b6020831061122057805182526020820191506020810190506020830392506111fd565b6001836020036101000a0380198251168184511680821785525050505050509050018267ffffffffffffffff191667ffffffffffffffff1916815260180193505050506040516020818303038152906040526040518082805190602001908083835b602083106112a55780518252602082019150602081019050602083039250611282565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa1580156112e7573d6000803e3d6000fd5b5050506040513d60208110156112fc57600080fd5b81019080805190602001909291905050509250505090565b6060600867ffffffffffffffff8111801561132e57600080fd5b506040519080825280601f01601f1916602001820160405280156113615781602001600182028036833780820191505090505b50905060008260c01b90508060076008811061137957fe5b1a60f81b8260008151811061138a57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350806006600881106113c657fe5b1a60f81b826001815181106113d757fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060056008811061141357fe5b1a60f81b8260028151811061142457fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060046008811061146057fe5b1a60f81b8260038151811061147157fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350806003600881106114ad57fe5b1a60f81b826004815181106114be57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350806002600881106114fa57fe5b1a60f81b8260058151811061150b57fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060016008811061154757fe5b1a60f81b8260068151811061155857fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053508060006008811061159457fe5b1a60f81b826007815181106115a557fe5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535050919050565b600080858511156115ea57600080fd5b838611156115f757600080fd5b600185028301915084860390509450949250505056fe4465706f736974436f6e74726163743a206d65726b6c6520747265652066756c6c4465706f736974436f6e74726163743a207265636f6e7374727563746564204465706f7369744461746120646f6573206e6f74206d6174636820737570706c696564206465706f7369745f646174615f726f6f744465706f736974436f6e74726163743a20696e76616c6964207769746864726177616c5f63726564656e7469616c73206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c7565206e6f74206d756c7469706c65206f6620677765694465706f736974436f6e74726163743a20696e76616c6964207075626b6579206c656e6774684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f20686967684465706f736974436f6e74726163743a206465706f7369742076616c756520746f6f206c6f774465706f736974436f6e74726163743a20696e76616c6964207369676e6174757265206c656e677468a2646970667358221220061922152bf33e33341dc256ce0c64bb49c53fc5bbc7d9cc77b02b9623906e9364736f6c634300060b0033",
    "balance": "0x0"
}

Also this Address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 should have enough funds to send a transaction.

 */
