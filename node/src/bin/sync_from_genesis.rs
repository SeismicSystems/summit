/*
This test verifies that a new validator can join the network by syncing from genesis
using a bootstrapper node for peer discovery.

## Test Flow

### Phase 1: Validator Withdrawal (Changes the Peer Set)
1. Start 4 genesis validators (nodes 0-3) with their corresponding Reth instances
2. Send a withdrawal transaction for one of the validators
3. Wait for all nodes to reach the withdrawal epoch (validator exits the committee)
4. Verify the withdrawal was processed

This phase changes the active validator set from the genesis configuration. This is
important because it means a new node syncing from genesis cannot simply use the
genesis validator list as its peer set - the validator set has changed since genesis.

### Phase 2: New Validator Joins via Genesis Sync
1. Generate new ed25519 and BLS keys for the joining validator
2. Send a deposit transaction to register the new validator
3. Create a bootstrappers.toml file pointing to one of the active validators
4. Start a new Reth + consensus node with the bootstrappers config (no checkpoint)
5. The new node syncs from genesis using the bootstrapper for peer discovery
6. Wait for the new node to catch up with the other nodes
7. Verify the new validator is in the consensus state with the correct balance

## RPC Endpoints
- Reth HTTP: localhost:8545 - node_number (node0=8545, node1=8544, ...)
- Consensus RPC: ports 3030, 3040, 3050, 3060 for nodes 0-3, 3070 for joining node
- P2P: ports 26600, 26610, 26620, 26630 for nodes 0-3, 26640 for joining node

*/
use alloy::hex::FromHex;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, U256};
use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_cryptography::Sha256;
use commonware_cryptography::{Hasher, Signer, bls12381, ed25519::PrivateKey};
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio as cw_tokio};
use commonware_utils::from_hex_formatted;
use futures::{FutureExt, pin_mut};
use jsonrpsee::core::ClientError;
use jsonrpsee::http_client::HttpClientBuilder;
use std::collections::VecDeque;
use std::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr as _,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit::engine::VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
use summit::test_harness::transactions::send_deposit_transaction;
use summit_rpc::SummitApiClient;
use summit_types::PROTOCOL_VERSION;
use summit_types::PublicKey;
use summit_types::execution_request::DepositRequest;
use summit_types::reth::Reth;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;
const VALIDATOR_MINIMUM_STAKE: u64 = 32_000_000_000;

struct NodeRuntime {
    _thread: JoinHandle<()>,
    _stop_tx: mpsc::UnboundedSender<()>,
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

                #[cfg(feature = "bench")]
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

                node_runtimes.push(NodeRuntime { _thread: thread, _stop_tx: stop_tx });
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
            let end_epoch = VALIDATOR_WITHDRAWAL_NUM_EPOCHS + 1;
            println!(
                "Waiting for all {} nodes to reach epoch {}",
                NUM_NODES, end_epoch
            );
            loop {
                let mut all_ready = true;
                for idx in 0..(NUM_NODES - 1) {
                    let rpc_port = get_node_flags(idx as usize).rpc_port;
                    match get_latest_epoch(rpc_port).await {
                        Ok(epoch) => {
                            if epoch < end_epoch {
                                all_ready = false;
                                println!("Node {} at epoch {}", idx, epoch);
                            }
                        }
                        Err(e) => {
                            all_ready = false;
                            println!("Node {} error: {}", idx, e);
                        }
                    }
                }
                if all_ready {
                    println!("All nodes have reached epoch {}", end_epoch);
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
            if let Err(e) = validator_balance {
                // Parse the JSON-RPC error
                if let Some(ClientError::Call(err)) = e.downcast_ref::<ClientError>() {
                    assert_eq!(err.message(), "Validator not found");
                    println!("Success: validator that withdrew is not on the consensus state anymore");
                } else {
                    panic!("Expected JSON-RPC Call error with 'Validator not found', got: {}", e);
                }
            } else {
                panic!("Validator should not be on the consensus state anymore");
            }

            println!("\n========== Phase 1 completed successfully! ==========");


            // ========== PHASE 2: Add a new validator that syncs from genesis ==========
            println!("\n========== Starting Phase 2: Adding new validator syncing from genesis ==========\n");
            use std::io::Write as _;
            std::io::stdout().flush().unwrap();

            // Generate keys for new validator
            let ed25519_private_key = PrivateKey::from_seed(100);
            let ed25519_public_key = ed25519_private_key.public_key();
            let ed25519_pubkey_bytes: [u8; 32] = ed25519_public_key.to_vec().try_into().unwrap();

            let bls_private_key = bls12381::PrivateKey::from_seed(100);
            let bls_public_key = bls_private_key.public_key();

            // Withdrawal credentials (32 bytes) - 0x01 prefix for execution address withdrawal
            let mut new_withdrawal_credentials = [0u8; 32];
            new_withdrawal_credentials[0] = 0x01;
            let new_withdrawal_address =
                Address::from_hex("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            new_withdrawal_credentials[12..32].copy_from_slice(new_withdrawal_address.as_slice());

            let deposit_amount = VALIDATOR_MINIMUM_STAKE;

            let deposit_request = DepositRequest {
                node_pubkey: ed25519_public_key,
                consensus_pubkey: bls_public_key.clone(),
                withdrawal_credentials: new_withdrawal_credentials,
                amount: deposit_amount,
                node_signature: [0; 64],
                consensus_signature: [0; 96],
                index: 0,
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

            // Convert to wei for the deposit transaction
            let deposit_amount_wei = U256::from(deposit_amount) * U256::from(1_000_000_000u64);

            // Get BLS public key bytes
            use commonware_codec::Encode;
            let bls_pubkey_bytes: [u8; 48] = bls_public_key.encode().as_ref()[..48].try_into().unwrap();

            // Deposit contract address
            let deposit_contract =
                Address::from_hex("0x00000000219ab540356cBB839Cbe05303d7705Fa").unwrap();

            // Use different wallet for deposit (one with funds)
            let deposit_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let deposit_signer = PrivateKeySigner::from_str(deposit_private_key).expect("Failed to create signer");
            let deposit_wallet = EthereumWallet::from(deposit_signer);

            let deposit_provider = ProviderBuilder::new()
                .wallet(deposit_wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            println!("Sending deposit transaction for new validator");
            std::io::stdout().flush().unwrap();
            send_deposit_transaction(
                &deposit_provider,
                deposit_contract,
                deposit_amount_wei,
                &ed25519_pubkey_bytes,
                &bls_pubkey_bytes,
                &new_withdrawal_credentials,
                &node_signature_bytes,
                &consensus_signature_bytes,
                0,
            )
            .await
            .expect("failed to send deposit transaction");

            println!("Deposit transaction completed successfully");
            std::io::stdout().flush().unwrap();

            // Start a new Reth node for the joining validator
            let x = NUM_NODES;
            println!("******* STARTING RETH FOR NODE {} (joining node)", x);
            std::io::stdout().flush().unwrap();
            let new_node_data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
            fs::create_dir_all(&new_node_data_dir).expect("Failed to create data directory");

            let reth_builder = Reth::new()
                .instance(x + 1)
                .keep_stdout()
                .data_dir(new_node_data_dir)
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

            // Write keys for the new node
            let node_key_path = format!("{}/node{}/data/node_key.pem", args.data_dir, x);
            let consensus_key_path = format!("{}/node{}/data/consensus_key.pem", args.data_dir, x);

            let encoded_node_key = commonware_utils::hex(&ed25519_private_key.encode());
            fs::write(&node_key_path, encoded_node_key).expect("Unable to write node key to disk");

            let encoded_consensus_key = commonware_utils::hex(&bls_private_key.encode());
            fs::write(&consensus_key_path, encoded_consensus_key).expect("Unable to write consensus key to disk");

            // Start the joining node - syncing from genesis (no checkpoint)
            #[allow(unused_mut)]
            let mut flags = get_node_flags(x.into());

            #[cfg(feature = "bench")]
            {
                flags.bench_block_dir = args.bench_block_dir.clone();
            }

            flags.key_store_path = format!("{}/node{}/data", args.data_dir, x);
            flags.ip = Some("127.0.0.1:26640".to_string());

            // Create a bootstrappers.toml file with one of the genesis validators
            // Read the genesis to get a validator's public key
            let genesis = summit_types::Genesis::load_from_file("./example_genesis.toml")
                .expect("Failed to load genesis");
            let validators = genesis.get_validators().expect("Failed to get validators");
            let bootstrap_validator = &validators[0];
            let bootstrap_pk_hex = commonware_utils::hex(bootstrap_validator.node_public_key.as_ref());
            let bootstrap_addr = bootstrap_validator.ip_address;

            let bootstrappers_path = format!("{}/bootstrappers.toml", args.data_dir);
            let bootstrappers_content = format!(
                r#"[[bootstrappers]]
node_public_key = "0x{}"
address = "{}"
"#,
                bootstrap_pk_hex, bootstrap_addr
            );
            fs::write(&bootstrappers_path, bootstrappers_content)
                .expect("Failed to write bootstrappers.toml");
            println!("Created bootstrappers.toml with validator {} at {}", bootstrap_pk_hex, bootstrap_addr);

            flags.bootstrappers = Some(bootstrappers_path);

            println!(
                "Starting consensus engine for node {} (syncing from genesis)",
                ed25519_private_key.public_key()
            );

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
                        // No checkpoint - sync from genesis
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

            node_runtimes.push(NodeRuntime { _thread: thread, _stop_tx: stop_tx });

            // Wait for the new node to sync and catch up with the other nodes
            let new_node_rpc_port = get_node_flags(x as usize).rpc_port;
            let reference_node_rpc_port = get_node_flags(0).rpc_port;
            println!("Waiting for new node to sync from genesis and catch up with other nodes");

            loop {
                let reference_epoch = get_latest_epoch(reference_node_rpc_port).await.unwrap_or(0);
                match get_latest_epoch(new_node_rpc_port).await {
                    Ok(new_node_epoch) => {
                        println!("New node at epoch {} (reference node at epoch {})", new_node_epoch, reference_epoch);
                        if new_node_epoch >= reference_epoch {
                            println!("New node synced from genesis and caught up at epoch {}!", new_node_epoch);
                            break;
                        }
                    }
                    Err(e) => {
                        println!("New node starting up... ({})", e);
                    }
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // Verify the new validator is in the consensus state
            let new_validator_pubkey = commonware_utils::hex(&ed25519_pubkey_bytes);
            let new_validator_balance = get_validator_balance(new_node_rpc_port, new_validator_pubkey.clone()).await;
            match new_validator_balance {
                Ok(balance) => {
                    println!("Success: new validator {} has balance {} in consensus state", new_validator_pubkey, balance);
                }
                Err(e) => {
                    panic!("New validator should be in the consensus state: {}", e);
                }
            }


            Ok::<(), Box<dyn std::error::Error>>(())
        }
    })?;
    std::process::exit(0);
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

async fn get_latest_epoch(rpc_port: u16) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", rpc_port);
    let client = HttpClientBuilder::default().build(&url)?;
    let epoch = client.get_latest_epoch().await?;
    Ok(epoch)
}

async fn get_validator_balance(
    rpc_port: u16,
    public_key: String,
) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", rpc_port);
    let client = HttpClientBuilder::default().build(&url)?;
    let balance = client.get_validator_balance(public_key).await?;
    Ok(balance)
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
