/*
This bin will start 4 reth nodes with an instance of consensus for each and keep running so you can run other tests or submit transactions

Their rpc endpoints are localhost:8545-node_number
node0_port = 8545
node1_port = 8544
...
node3_port = 8542


*/
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr as _,
};

use alloy_node_bindings::Reth;
use clap::Parser;
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio};
use summit::args::{RunFlags, run_node_with_runtime};
use summit::engine::VALIDATOR_MINIMUM_STAKE;
use tracing::Level;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use commonware_utils::from_hex_formatted;
use ssz::Decode;
use alloy_primitives::{Address, U256, keccak256, FixedBytes};
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::rpc::types::TransactionRequest;
use sha2::{Sha256, Digest};

#[derive(Parser, Debug)]
struct Args {
    /// Number of nodes you want to run for this test
    #[arg(long, default_value_t = 4)]
    nodes: u16,
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
        fs::create_dir_all(log_dir)?;
    }

    let storage_dir = data_dir_path.join("stores");

    let cfg = tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(storage_dir)
        .with_catch_panics(false);
    let executor = tokio::Runner::new(cfg);

    executor.start(|context| {
        async move {
            // Configure telemetry
            let log_level = Level::from_str("info").expect("Invalid log level");
            tokio::telemetry::init(
                context.with_label("metrics"),
                tokio::telemetry::Logging {
                    level: log_level,
                    // todo: dont know what this does
                    json: false,
                },
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6969)),
                None,
            );

            // Vector to hold all the join handles
            let mut handles = Vec::new();
            let mut consensus_handles = Vec::new();
            // let mut read_threads = Vec::new();

            // Start only 3 nodes initially (the 4th will join later after checkpoint)
            let initial_nodes = 3;

            for x in 0..initial_nodes {
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

                handles.push(reth);

                #[allow(unused_mut)]
                let mut flags = get_node_flags(x.into());

                #[cfg(any(feature = "base-bench", feature = "bench"))]
                {
                    flags.bench_block_dir = args.bench_block_dir.clone();
                }

                // Start our consensus engine
                let handle = run_node_with_runtime(context.with_label(&format!("node{x}")), flags, None);
                consensus_handles.push(handle);
            }

            // Wait a bit for nodes to be ready
            context.sleep(std::time::Duration::from_secs(5)).await;

            // Send a deposit transaction to node0
            println!("Sending deposit transaction to node 0");
            let node0_http_port = handles[0].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);

            // Create a test private key and signer
            let private_key = FixedBytes::<32>::from([1u8; 32]);
            let signer = PrivateKeySigner::from_bytes(&private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);

            // Create provider with wallet
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            // Deposit contract address (you'll need to set this to the actual address)
            let deposit_contract = Address::from([0u8; 20]); // TODO: Set actual deposit contract address

            // Create test deposit parameters
            let ed25519_pubkey = [2u8; 32]; // Test pubkey
            let withdrawal_credentials = [0u8; 32]; // Test withdrawal credentials
            let signature = [0u8; 96]; // Test signature

            // Convert VALIDATOR_MINIMUM_STAKE (in gwei) to wei
            let deposit_amount = U256::from(VALIDATOR_MINIMUM_STAKE) * U256::from(1_000_000_000u64); // gwei to wei

            match send_deposit_transaction(
                &provider,
                deposit_contract,
                deposit_amount,
                &ed25519_pubkey,
                &withdrawal_credentials,
                &signature,
                0, // nonce
            ).await {
                Ok(_) => println!("Deposit transaction sent successfully"),
                Err(e) => println!("Failed to send deposit transaction: {}", e),
            }

            // Wait for nodes to reach checkpoint height
            println!("Waiting for nodes to reach checkpoint height {}", args.checkpoint_height);
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
                context.sleep(std::time::Duration::from_secs(1)).await;
            }

            // Retrieve checkpoint from first node
            println!("Retrieving checkpoint from node 0");
            let checkpoint = loop {
                match get_checkpoint(node0_rpc_port).await {
                    Ok(Some(checkpoint)) => {
                        let state = ConsensusState::try_from(&checkpoint)
                            .expect("Failed to parse checkpoint");
                        println!("Retrieved checkpoint at height {}", state.latest_height);
                        break checkpoint;
                    }
                    Ok(None) => {
                        println!("Checkpoint not yet available");
                    }
                    Err(e) => {
                        println!("Error retrieving checkpoint: {}", e);
                    }
                }
                context.sleep(std::time::Duration::from_secs(1)).await;
            };

            // Start the joining Reth node
            //let x = initial_nodes;
            //println!("******* STARTING RETH FOR NODE {} (joining node)", x);
            //let data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
            //fs::create_dir_all(&data_dir).expect("Failed to create data directory");

            //// Copy db and static_files from node0 to initialize the joining node
            //let source_node = 0;
            //let source_data_dir = format!("{}/node{}/data/reth_db", args.data_dir, source_node);

            //println!("Copying db from node{} to node{}", source_node, x);
            //let source_db = format!("{}/db", source_data_dir);
            //let dest_db = format!("{}/db", data_dir);
            //copy_dir_all(&source_db, &dest_db).expect("Failed to copy db directory");

            //println!("Copying static_files from node{} to node{}", source_node, x);
            //let source_static = format!("{}/static_files", source_data_dir);
            //let dest_static = format!("{}/static_files", data_dir);
            //copy_dir_all(&source_static, &dest_static).expect("Failed to copy static_files directory");

            //let reth_builder = Reth::new()
            //    .instance(x + 1)
            //    .keep_stdout()
            //    .data_dir(data_dir)
            //    .arg("--enclave.mock-server")
            //    .arg("--enclave.endpoint-port")
            //    .arg(format!("1744{x}"))
            //    .arg("--auth-ipc")
            //    .arg("--auth-ipc.path")
            //    .arg(format!("/tmp/reth_engine_api{x}.ipc"))
            //    .arg("--metrics")
            //    .arg(format!("0.0.0.0:{}", 9001 + x));

            //let mut reth = reth_builder.spawn();

            //let stdout = reth.stdout().expect("Failed to get stdout");

            //let log_dir = args.log_dir.clone();
            //context.clone().spawn(async move |_| {
            //    let reader = BufReader::new(stdout);
            //    let mut log_file = log_dir.as_ref().map(|dir| {
            //        fs::File::create(format!("{}/node{}.log", dir, x))
            //            .expect("Failed to create log file")
            //    });

            //    for line in reader.lines() {
            //        match line {
            //            Ok(line) => {
            //                if let Some(ref mut file) = log_file {
            //                    writeln!(file, "[Node {}] {}", x, line)
            //                        .expect("Failed to write to log file");
            //                }
            //            }
            //            Err(_e) => {}
            //        }
            //    }
            //});

            //println!("Node {} rpc address: {}", x, reth.http_port());
            //handles.push(reth);

            //// Start the 4th consensus node with checkpoint
            //#[allow(unused_mut)]
            //let mut flags = get_node_flags(x.into());

            //#[cfg(any(feature = "base-bench", feature = "bench"))]
            //{
            //    flags.bench_block_dir = args.bench_block_dir.clone();
            //}

            //println!("Starting consensus engine for node 3 with checkpoint");
            //let handle = run_node_with_runtime(context.with_label(&format!("node{x}")), flags, Some(checkpoint));
            //consensus_handles.push(handle);

            //// Wait for all nodes to continue making progress
            //println!("Waiting for all {} nodes to reach height {}", args.nodes, args.stop_height);
            //loop {
            //    let mut all_ready = true;
            //    for idx in 0..args.nodes {
            //        let rpc_port = get_node_flags(idx as usize).rpc_port;
            //        match get_latest_height(rpc_port).await {
            //            Ok(height) => {
            //                if height < args.stop_height {
            //                    all_ready = false;
            //                    println!("Node {} at height {}", idx, height);
            //                }
            //            }
            //            Err(e) => {
            //                all_ready = false;
            //                println!("Node {} error: {}", idx, e);
            //            }
            //        }
            //    }
            //    if all_ready {
            //        println!("All nodes have reached target height!");
            //        break;
            //    }
            //    context.sleep(std::time::Duration::from_secs(2)).await;
            //}

            //println!("Test completed successfully!");

            //// Keep running
            //if let Err(e) = futures::future::try_join_all(consensus_handles).await {
            //    tracing::error!("Failed: {:?}", e);
            //}

            //// Due to how alloy node_bindings work we have to do this to prevent the reth_instances from being dropped and shutdown by the compiler
            //for reth in handles {
            //    println!("{:?}", reth.auth_port());
            //}

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

async fn get_checkpoint(rpc_port: u16) -> Result<Option<Checkpoint>, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}/get_checkpoint", rpc_port);
    let response = reqwest::get(&url).await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let hex_str = resp.text().await?;
            let bytes = from_hex_formatted(&hex_str)
                .ok_or("Failed to decode hex")?;
            let checkpoint = Checkpoint::from_ssz_bytes(&bytes)
                .map_err(|e| format!("Failed to decode checkpoint: {:?}", e))?;
            Ok(Some(checkpoint))
        }
        _ => Ok(None),
    }
}

fn compute_deposit_data_root(
    ed25519_pubkey: &[u8],
    withdrawal_credentials: &[u8],
    amount: U256,
    signature: &[u8],
) -> [u8; 32] {
    /*
    bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
    bytes32 signature_root = sha256(abi.encodePacked(
        sha256(abi.encodePacked(signature[:64])),
        sha256(abi.encodePacked(signature[64:], bytes32(0)))
    ));
    bytes32 node = sha256(abi.encodePacked(
        sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
        sha256(abi.encodePacked(amount, bytes24(0), signature_root))
    ));
     */

    // Left-pad ed25519 key to 48 bytes (prepend zeros)
    let mut padded_pubkey = vec![0u8; 48 - ed25519_pubkey.len()];
    padded_pubkey.extend_from_slice(ed25519_pubkey);

    // 1. pubkey_root = sha256(padded_pubkey || bytes16(0))
    let mut hasher = Sha256::new();
    hasher.update(&padded_pubkey);
    hasher.update(&[0u8; 16]); // bytes16(0)
    let pubkey_root = hasher.finalize();

    // 2. signature_root = sha256(sha256(signature[0:64]) || sha256(signature[64:96] || bytes32(0)))
    let mut hasher = Sha256::new();
    hasher.update(&signature[0..64]);
    let sig_part1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&signature[64..96]);
    hasher.update(&[0u8; 32]); // bytes32(0)
    let sig_part2 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&sig_part1);
    hasher.update(&sig_part2);
    let signature_root = hasher.finalize();

    // 3. Convert amount to 8-byte little-endian (gwei)
    let amount_gwei = amount / U256::from(10).pow(U256::from(9)); // Convert wei to gwei
    let amount_u64 = amount_gwei.to::<u64>(); // Convert to u64 (should fit for reasonable amounts)
    let amount_bytes = amount_u64.to_le_bytes(); // 8 bytes little-endian

    // 4. node = sha256(sha256(pubkey_root || withdrawal_credentials) || sha256(amount || bytes24(0) || signature_root))
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_root);
    hasher.update(withdrawal_credentials);
    let left_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&amount_bytes);
    hasher.update(&[0u8; 24]); // bytes24(0)
    hasher.update(&signature_root);
    let right_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&left_node);
    hasher.update(&right_node);
    let deposit_data_root = hasher.finalize();

    let digest_bytes: &[u8] = deposit_data_root.as_ref();
    let result: [u8; 32] = digest_bytes.try_into().expect("SHA-256 digest is always 32 bytes");
    result
}

async fn send_deposit_transaction<P>(
    provider: &P,
    deposit_contract_address: Address,
    deposit_amount: U256,
    ed25519_pubkey: &[u8],
    withdrawal_credentials: &[u8],
    signature: &[u8],
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Provider + WalletProvider,
{
    // Left-pad ed25519 key to 48 bytes for the contract (prepend zeros)
    let mut padded_pubkey = vec![0u8; 48 - ed25519_pubkey.len()];
    padded_pubkey.extend_from_slice(ed25519_pubkey);

    // Compute the correct deposit data root for this transaction
    let deposit_data_root = compute_deposit_data_root(ed25519_pubkey, withdrawal_credentials, deposit_amount, signature);

    // Create deposit function call data: deposit(bytes,bytes,bytes,bytes32)
    let function_selector = &keccak256("deposit(bytes,bytes,bytes,bytes32)")[0..4];
    let mut call_data = function_selector.to_vec();

    // ABI encode parameters - calculate offsets for 4 parameters (3 dynamic + 1 fixed)
    let offset_to_pubkey = 4 * 32;
    let offset_to_withdrawal_creds = offset_to_pubkey + 32 + ((padded_pubkey.len() + 31) / 32) * 32;
    let offset_to_signature = offset_to_withdrawal_creds + 32 + ((withdrawal_credentials.len() + 31) / 32) * 32;

    // Add parameter offsets
    let mut offset_bytes = vec![0u8; 32];
    offset_bytes[28..32].copy_from_slice(&(offset_to_pubkey as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_withdrawal_creds as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    offset_bytes.fill(0);
    offset_bytes[28..32].copy_from_slice(&(offset_to_signature as u32).to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add the fixed bytes32 parameter (deposit_data_root)
    call_data.extend_from_slice(&deposit_data_root);

    // Add dynamic data
    let mut length_bytes = vec![0u8; 32];

    // Padded pubkey (48 bytes)
    length_bytes[28..32].copy_from_slice(&(padded_pubkey.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    let mut pubkey_padded = padded_pubkey.clone();
    while pubkey_padded.len() % 32 != 0 { pubkey_padded.push(0); }
    call_data.extend_from_slice(&pubkey_padded);

    // Withdrawal credentials
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(withdrawal_credentials.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    let mut withdrawal_creds_padded = withdrawal_credentials.to_vec();
    while withdrawal_creds_padded.len() % 32 != 0 { withdrawal_creds_padded.push(0); }
    call_data.extend_from_slice(&withdrawal_creds_padded);

    // Signature
    length_bytes.fill(0);
    length_bytes[28..32].copy_from_slice(&(signature.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);
    let mut signature_padded = signature.to_vec();
    while signature_padded.len() % 32 != 0 { signature_padded.push(0); }
    call_data.extend_from_slice(&signature_padded);

    let tx_request = TransactionRequest::default()
        .with_to(deposit_contract_address)
        .with_value(deposit_amount)
        .with_input(call_data)
        .with_gas_limit(500_000)
        .with_gas_price(1_000_000_000) // 1 gwei
        .with_nonce(nonce);

    match provider.send_transaction(tx_request).await {
        Ok(pending) => {
            println!("   Transaction sent: {}", pending.tx_hash());
            Ok(())
        }
        Err(e) => {
            println!("   Error sending transaction: {}", e);
            Err(e.into())
        }
    }
}

fn get_node_flags(node: usize) -> RunFlags {
    let path = format!("testnet/node{node}/");

    RunFlags {
        key_path: format!("{path}key.pem"),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        rpc_port: (3030 + (node * 10)) as u16,
        worker_threads: 2,
        log_level: "debug".into(),
        db_prefix: format!("{node}-quarts"),
        genesis_path: "./example_genesis.toml".into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(any(feature = "base-bench", feature = "bench"))]
        bench_block_dir: None,
    }
}
