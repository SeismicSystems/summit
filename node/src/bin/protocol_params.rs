/*
This binary tests protocol parameter updates via the protocol params contract.

It starts 4 reth nodes with consensus instances, sends a transaction to update a protocol parameter,
and verifies that all nodes process the change and continue making progress.

RPC endpoints:
node0_port = 3030
node1_port = 3040
node2_port = 3050
node3_port = 3060
*/
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
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
use summit::engine::BLOCKS_PER_EPOCH;
use summit_rpc::SummitApiClient;
use summit_types::reth::Reth;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;

#[allow(unused)]
struct NodeRuntime {
    thread: JoinHandle<()>,
    stop_tx: mpsc::UnboundedSender<()>,
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to the directory containing historical blocks for benchmarking
    #[cfg(feature = "bench")]
    #[arg(long)]
    pub bench_block_dir: Option<String>,
    /// Path to the log directory
    #[arg(long)]
    pub log_dir: Option<String>,
    /// Path to the data directory for test
    #[arg(long, default_value = "/tmp/summit_withdraw_test")]
    pub data_dir: String,
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
                            run_node_local(ctx, flags, None, None).await.unwrap();
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
            context.sleep(Duration::from_secs(2)).await;

            // Send a transaction to update the maximum stake protocol parameter
            println!("Sending protocol parameter update transaction to raise maximum stake to 64 ETH");
            let node0_http_port = handles[1].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);

            // Create a test private key and signer.
            // This private key has to be the owner of the protocol params contract.
            let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer = PrivateKeySigner::from_str(private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);

            // Create provider with wallet
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            let protocol_params_contract_address = Address::from_str("0x0000000000000000000000000000506172616D73").unwrap();

            // Set parameter ID 0x01 (MaximumStake) to 64 ETH (64_000_000_000 gwei)
            let param_id: u8 = 0x01; // MaximumStake
            let new_max_stake: u64 = 64_000_000_000; // 64 ETH in gwei

            // Encode the u64 value as little-endian bytes
            let param_data = new_max_stake.to_le_bytes();

            // Encode param with length prefix: [length, ...data]
            let mut param_value = Vec::with_capacity(param_data.len() + 1);
            param_value.push(param_data.len() as u8);
            param_value.extend_from_slice(&param_data);

            send_protocol_params_transaction(&provider, protocol_params_contract_address, param_id, param_value, 0)
                .await
                .expect("failed to send protocol params transaction");

            // Wait for nodes to process the transaction and make some progress
            let target_height = BLOCKS_PER_EPOCH + 1;
            println!(
                "Waiting for all {} nodes to reach height {} (to ensure protocol param change is processed)",
                NUM_NODES, target_height
            );
            loop {
                let mut all_ready = true;
                for idx in 0..NUM_NODES {
                    let rpc_port = get_node_flags(idx as usize).rpc_port;
                    match get_latest_height(rpc_port).await {
                        Ok(height) => {
                            if height < target_height {
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
                    println!("All nodes have reached height {}", target_height);
                    break;
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // Verify that the maximum stake was correctly updated
            println!("Verifying maximum stake was updated to {} gwei...", new_max_stake);
            let rpc_port = get_node_flags(0).rpc_port;
            let url = format!("http://localhost:{}", rpc_port);
            let client = HttpClientBuilder::default().build(&url).expect("Failed to create RPC client");

            let max_stake = client.get_maximum_stake().await.expect("Failed to get maximum stake");
            println!("Current maximum stake: {} gwei", max_stake);

            assert_eq!(max_stake, new_max_stake, "Maximum stake should be {} gwei", new_max_stake);
            println!("✓ Maximum stake successfully updated to {} gwei!", new_max_stake);

            println!("Protocol parameter change test completed successfully!");

            Ok::<(), Box<dyn std::error::Error>>(())
        }
    })?;
    std::process::exit(0);
}

async fn send_protocol_params_transaction<P>(
    provider: &P,
    protocol_params_contract_address: Address,
    param_id: u8,
    param_value: Vec<u8>,
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Provider + WalletProvider,
{
    use alloy_primitives::keccak256;

    // ABI encode the function call: set_param(uint8 param_id, bytes calldata param)
    // Function selector is first 4 bytes of keccak256("set_param(uint8,bytes)")
    let function_selector = &keccak256("set_param(uint8,bytes)")[0..4];

    // ABI encoding:
    // - 4 bytes: function selector
    // - 32 bytes: param_id (uint8 left-padded to 32 bytes)
    // - 32 bytes: offset to bytes data (always 0x40 = 64 bytes from start of params)
    // - 32 bytes: length of bytes data
    // - N bytes: actual bytes data (padded to 32-byte boundary)

    let mut call_data = Vec::new();

    // Add function selector
    call_data.extend_from_slice(function_selector);

    // Add param_id (uint8 left-padded to 32 bytes)
    let mut param_id_bytes = [0u8; 32];
    param_id_bytes[31] = param_id;
    call_data.extend_from_slice(&param_id_bytes);

    // Add offset to bytes data (0x40 = 64 bytes from start of parameter encoding)
    let mut offset_bytes = [0u8; 32];
    offset_bytes[28..32].copy_from_slice(&64u32.to_be_bytes());
    call_data.extend_from_slice(&offset_bytes);

    // Add length of bytes data
    let mut length_bytes = [0u8; 32];
    length_bytes[28..32].copy_from_slice(&(param_value.len() as u32).to_be_bytes());
    call_data.extend_from_slice(&length_bytes);

    // Add the actual bytes data
    call_data.extend_from_slice(&param_value);

    // Pad to 32-byte boundary if needed
    let padding_needed = (32 - (param_value.len() % 32)) % 32;
    if padding_needed > 0 {
        call_data.extend_from_slice(&vec![0u8; padding_needed]);
    }

    let tx_request = TransactionRequest::default()
        .to(protocol_params_contract_address)
        .input(call_data.into())
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
