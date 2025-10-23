/*
This bin will start 4 reth nodes with an instance of consensus for each and keep running so you can run other tests or submit transactions

Their rpc endpoints are localhost:8545-node_number
node0_port = 8545
node1_port = 8544
...
node3_port = 8542


*/
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, U256};
use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio as cw_tokio};
use commonware_utils::from_hex_formatted;
use futures::{FutureExt, pin_mut};
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
use summit::args::{RunFlags, run_node_with_runtime};
use summit::engine::{EPOCH_NUM_BLOCKS, VALIDATOR_MINIMUM_STAKE};
use summit_types::PublicKey;
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
    #[cfg(any(feature = "base-bench", feature = "bench"))]
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
                            run_node_with_runtime(ctx, flags, None).await.unwrap();
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

            // Send a withdrawal transaction to one of the Reth instances
            println!("Sending deposit transaction to node 1");
            let node0_http_port = handles[1].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);

            // Create a test private key and signer
            let private_key = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
            let signer = PrivateKeySigner::from_str(private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);

            // Create provider with wallet
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            let withdrawal_contract_address = Address::from_str("0x00000961Ef480Eb55e80D19ad83579A64c007002").unwrap();
            let pub_key_bytes = from_hex_formatted("f205c8c88d5d1753843dd0fc9810390efd00d6f752dd555c0ad4000bfcac2226").ok_or("PublicKey bad format").unwrap();
            let pub_key_bytes_ar: [u8; 32] = pub_key_bytes.try_into().unwrap();
            let _public_key = PublicKey::decode(&pub_key_bytes_ar[..]).map_err(|_| "Unable to decode Public Key").unwrap();
            let withdrawal_amount = VALIDATOR_MINIMUM_STAKE;
            let withdrawal_fee = U256::from(1000000000000000u64); // 0.001 ETH fee

            // Check balance before withdrawal
            let withdrawal_credentials = Address::from_str("0x90F79bf6EB2c4f870365E785982E1f101E93b906").unwrap();
            let balance_before = provider.get_balance(withdrawal_credentials).await.expect("Failed to get balance before withdrawal");
            println!("Withdrawal credentials balance before: {} wei", balance_before);

            send_withdrawal_transaction(&provider, withdrawal_contract_address, &pub_key_bytes_ar, withdrawal_amount, withdrawal_fee, 0)
                .await
                .expect("failed to send deposit transaction");

            // Wait for all nodes to continue making progress
            let epoch_end = EPOCH_NUM_BLOCKS;
            println!(
                "Waiting for all {} nodes to reach height {}",
                NUM_NODES, epoch_end
            );
            loop {
                let mut all_ready = true;
                for idx in 0..(NUM_NODES - 1) {
                    let rpc_port = get_node_flags(idx as usize).rpc_port;
                    match get_latest_height(rpc_port).await {
                        Ok(height) => {
                            if height < epoch_end {
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
                    println!("All nodes have reached height {}", epoch_end);
                    break;
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            context.sleep(Duration::from_secs(3)).await;

            // Check that the balance was incremented on the execution layer (Reth)
            let node0_http_port = handles[0].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);
            let node0_provider = ProviderBuilder::new().connect_http(node0_url.parse().expect("Invalid URL"));

            // Check

            let balance_after = node0_provider.get_balance(withdrawal_credentials).await.expect("Failed to get balance after withdrawal");
            println!("Withdrawal credentials balance after: {} wei", balance_after);

            // The withdrawal amount was VALIDATOR_MINIMUM_STAKE (32 ETH in gwei)
            // Converting to wei: 32_000_000_000 gwei * 10^9 = 32 * 10^18 wei
            let expected_difference = U256::from(VALIDATOR_MINIMUM_STAKE) * U256::from(1_000_000_000u64);
            let actual_difference = balance_after - balance_before;

            // Allow tolerance for gas fees (0.01 ETH = 10^16 wei)
            let tolerance = U256::from(10_000_000_000_000_000u64);
            let lower_bound = expected_difference - tolerance;
            let upper_bound = expected_difference + tolerance;
            assert!(actual_difference >= lower_bound && actual_difference <= upper_bound,
                "Balance difference {} is outside expected range [{}, {}]",
                actual_difference, lower_bound, upper_bound);
            println!("Withdrawal successful: balance increased by {} wei (expected ~{})",
                actual_difference, expected_difference);

            // Check that the validator was removed from the consensus state
            let rpc_port = get_node_flags(0).rpc_port;
            let validator_balance = get_validator_balance(rpc_port, "f205c8c88d5d1753843dd0fc9810390efd00d6f752dd555c0ad4000bfcac2226".to_string()).await;
            if let Err(msg) = validator_balance {
                assert_eq!(msg.to_string(), "Validator not found");
                println!("Validator that withdrew is not on the consensus state anymore");
            } else {
                panic!("Validator should not be on the consensus state anymore");
            }

            Ok(())
        }
    })
}

async fn send_withdrawal_transaction<P>(
    provider: &P,
    withdrawal_contract_address: Address,
    //validator_pubkey: &[u8; 48],
    ed25519_pubkey: &[u8; 32],
    withdrawal_amount: u64, // Amount in gwei
    withdrawal_fee: U256,   // Current fee required by the contract
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Provider + WalletProvider,
{
    // Left-pad ed25519 key to 48 bytes for the contract (prepend zeros)
    let mut padded_pubkey = [0u8; 48];
    padded_pubkey[16..48].copy_from_slice(ed25519_pubkey);

    // EIP-7002: Input is exactly 56 bytes: validator_pubkey (48 bytes) + amount (8 bytes, big-endian uint64)
    let mut call_data = Vec::with_capacity(56);

    // Add validator pubkey (48 bytes)
    call_data.extend_from_slice(&padded_pubkey);

    // Add withdrawal amount (8 bytes, big-endian uint64)
    call_data.extend_from_slice(&withdrawal_amount.to_be_bytes());

    let tx_request = TransactionRequest::default()
        .to(withdrawal_contract_address)
        .value(withdrawal_fee) // Must send enough ETH to cover withdrawal request fee
        .input(call_data.into())
        .with_gas_limit(500_000) // Lower gas limit for simpler operation
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
    let url = format!("http://localhost:{}/get_latest_height", rpc_port);
    let response = reqwest::get(&url).await?.text().await?;
    Ok(response.parse()?)
}

async fn get_validator_balance(
    rpc_port: u16,
    public_key: String,
) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!(
        "http://localhost:{}/get_validator_balance?public_key={}",
        rpc_port, public_key
    );
    let response = reqwest::get(&url).await?.text().await?;
    let Ok(balance) = response.parse() else {
        return Err(response.into());
    };
    Ok(balance)
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
        checkpoint_path: None,
        ip: None,
    }
}
