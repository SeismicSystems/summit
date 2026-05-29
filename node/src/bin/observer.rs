/*
End-to-end observer test.

Starts NUM_NODES genesis validators + 1 observer node, then waits for every node
(including the observer) to reach `--stop-height`.

The observer:
  - Derives its p2p identity from validator 1's master node key via `--observer 0`.
  - Has its own fresh BLS consensus key that is NOT in the validator set, so
    Simplex treats it as a non-participant while its signatures do not collide
    with the real validator 1.
  - Is tracked as a secondary peer by every validator via the genesis
    `observers_per_validator` field.
  - Runs its own Reth instance to execute finalized blocks via Engine API IPC.

Flow:
  1. Start 4 validators with their Reth instances.
  2. Prepare the observer's key store (copy of validator 1's `node_key.pem`
     alongside a fresh `consensus_key.pem`).
  3. Start the observer's Reth instance and consensus node with `--observer 0`.
  4. Poll every node's consensus RPC until all have `latest_height >= stop_height`.
*/

use clap::Parser;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Signer, bls12381, ed25519::PrivateKey};
use commonware_runtime::{Clock, Runner as _, Spawner as _, tokio as cw_tokio};
use commonware_utils::from_hex_formatted;
use futures::{FutureExt, pin_mut};
use jsonrpsee::http_client::HttpClientBuilder;
use ssz::Decode;
use std::collections::VecDeque;
use std::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    path::PathBuf,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit_rpc::SummitApiClient;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::ext_private_key::derive_child_public;
use summit_types::genesis::Genesis;
use summit_types::header::FinalizedHeader;
use summit_types::reth::Reth;
use summit_types::rpc::CheckpointRes;
use summit_types::scheme::MultisigScheme;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;
const GENESIS_PATH: &str = "./example_genesis.toml";
const E2E_BLOCKS_PER_EPOCH: u64 = 50;

// The observer derives from this validator's master key. Pick a validator that
// is expected to stay up throughout the test.
const MASTER_VALIDATOR_IDX: usize = 1;
const OBSERVER_DERIVE_IDX: u32 = 0;
// Logical slot for the observer's ports / IPC path / data directory.
const OBSERVER_SLOT: usize = (NUM_NODES + 1) as usize;

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
    /// Path to the data directory for the test
    #[arg(long, default_value = "/tmp/summit_observer_test")]
    pub data_dir: String,
    /// Height that all nodes (including the observer) must reach for the test to succeed
    #[arg(long, default_value_t = 100)]
    pub stop_height: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let data_dir_path = PathBuf::from(&args.data_dir);
    if data_dir_path.exists() {
        fs::remove_dir_all(&data_dir_path)?;
    }

    if let Some(ref log_dir) = args.log_dir {
        if PathBuf::from(log_dir).exists() {
            fs::remove_dir_all(log_dir)?;
        }
        fs::create_dir_all(log_dir)?;
    }

    let storage_dir = data_dir_path.join("stores");
    let cfg = cw_tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(storage_dir)
        .with_catch_panics(false);
    let executor = cw_tokio::Runner::new(cfg);

    let mut genesis = Genesis::load_from_file(GENESIS_PATH).expect("Failed to load genesis file");
    genesis.blocks_per_epoch = E2E_BLOCKS_PER_EPOCH;
    assert!(
        genesis.observers_per_validator > OBSERVER_DERIVE_IDX,
        "genesis.observers_per_validator ({}) must be > OBSERVER_DERIVE_IDX ({}) for this test",
        genesis.observers_per_validator,
        OBSERVER_DERIVE_IDX
    );

    fs::create_dir_all(&data_dir_path).expect("Failed to create data directory");
    let e2e_genesis_path = data_dir_path.join("genesis.toml");
    let genesis_str = toml::to_string_pretty(&genesis).expect("Failed to serialize genesis");
    fs::write(&e2e_genesis_path, genesis_str).expect("Failed to write e2e genesis");
    let e2e_genesis_path_str = e2e_genesis_path.to_str().unwrap().to_string();

    let node_runtimes = executor.start(|context| {
        async move {
            let _critical_log_guard = summit::telemetry::init(Level::INFO, None);

            let mut handles = VecDeque::new();
            let mut node_runtimes: Vec<NodeRuntime> = Vec::new();

            // --- Validators ---
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
                                .expect("Failed to write log file");
                        }
                    }
                });

                println!("Node {} rpc address: {}", x, reth.http_port());
                handles.push_back(reth);

                #[allow(unused_mut)]
                let mut flags = get_node_flags(x.into(), &e2e_genesis_path_str);

                #[cfg(feature = "bench")]
                {
                    flags.bench_block_dir = args.bench_block_dir.clone();
                }

                let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
                let data_dir_clone = args.data_dir.clone();
                let thread = std::thread::spawn(move || {
                    let storage_dir = PathBuf::from(&data_dir_clone)
                        .join("stores")
                        .join(format!("node{}", x));
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

            // --- Observer ---
            let observer_reth_data_dir = format!("{}/observer/data/reth_db", args.data_dir);
            let observer_key_dir = format!("{}/observer/keys", args.data_dir);
            fs::create_dir_all(&observer_reth_data_dir)
                .expect("Failed to create observer reth data directory");
            fs::create_dir_all(&observer_key_dir)
                .expect("Failed to create observer key directory");

            // Copy the master validator's node key — the observer derives its p2p
            // identity from this master via `--observer 0`.
            fs::copy(
                format!("testnet/node{}/node_key.pem", MASTER_VALIDATOR_IDX),
                format!("{}/node_key.pem", observer_key_dir),
            )
            .expect("Failed to copy master validator's node_key.pem");

            // Fresh BLS key for the observer — not in the validator set, so its
            // Simplex signatures are not accepted and don't collide with validator 1.
            let observer_bls_key = bls12381::PrivateKey::from_seed(0xDEAD_BEEF);
            let observer_bls_encoded = commonware_utils::hex(&observer_bls_key.encode());
            fs::write(
                format!("{}/consensus_key.pem", observer_key_dir),
                observer_bls_encoded,
            )
            .expect("Failed to write observer BLS key");

            println!("******* STARTING RETH FOR OBSERVER");
            let observer_reth_builder = Reth::new()
                .instance(OBSERVER_SLOT as u16 + 1)
                .keep_stdout()
                .data_dir(observer_reth_data_dir)
                .arg("--enclave.mock-server")
                .arg("--enclave.endpoint-port")
                .arg(format!("1744{}", OBSERVER_SLOT))
                .arg("--auth-ipc")
                .arg("--auth-ipc.path")
                .arg(format!("/tmp/reth_engine_api{}.ipc", OBSERVER_SLOT))
                .arg("--metrics")
                .arg(format!("0.0.0.0:{}", 9001 + OBSERVER_SLOT));

            let mut observer_reth = observer_reth_builder.spawn();
            let observer_stdout = observer_reth.stdout().expect("Failed to get observer stdout");
            let log_dir = args.log_dir.clone();
            context.clone().spawn(async move |_| {
                let reader = BufReader::new(observer_stdout);
                let mut log_file = log_dir.as_ref().map(|dir| {
                    fs::File::create(format!("{}/observer.log", dir))
                        .expect("Failed to create observer log file")
                });
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(ref mut file) = log_file {
                        writeln!(file, "[Observer] {}", line)
                            .expect("Failed to write observer log");
                    }
                }
            });

            println!("Observer rpc address: {}", observer_reth.http_port());
            handles.push_back(observer_reth);

            let mut observer_flags = get_node_flags(OBSERVER_SLOT, &e2e_genesis_path_str);
            observer_flags.key_store_path = observer_key_dir.clone();
            observer_flags.observer = Some(OBSERVER_DERIVE_IDX);
            // Pin the observer's advertised IP so it does NOT inherit the master
            // validator's genesis IP (which is already bound by validator 1).
            observer_flags.ip = Some(format!("127.0.0.1:{}", 26600 + OBSERVER_SLOT * 10));

            println!(
                "Starting observer consensus engine (master = node{}, derive index = {})",
                MASTER_VALIDATOR_IDX, OBSERVER_DERIVE_IDX
            );

            let (observer_stop_tx, mut observer_stop_rx) = mpsc::unbounded_channel();
            let data_dir_clone = args.data_dir.clone();
            let observer_thread = std::thread::spawn(move || {
                let storage_dir = PathBuf::from(&data_dir_clone)
                    .join("stores")
                    .join("observer");
                let cfg = cw_tokio::Config::default()
                    .with_tcp_nodelay(Some(true))
                    .with_worker_threads(4)
                    .with_storage_directory(storage_dir)
                    .with_catch_panics(true);
                let executor = cw_tokio::Runner::new(cfg);

                executor.start(|node_context| async move {
                    let node_handle = node_context.clone().spawn(|ctx| async move {
                        run_node_local(ctx, observer_flags, None, None)
                            .await
                            .unwrap();
                    });

                    let stop_fut = observer_stop_rx.recv().fuse();
                    pin_mut!(stop_fut);
                    futures::select! {
                        _ = stop_fut => {
                            println!("Observer received stop signal, shutting down runtime...");
                            node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
                        }
                        _ = node_handle.fuse() => {
                            println!("Observer handle completed");
                        }
                    }
                });
            });

            node_runtimes.push(NodeRuntime {
                thread: observer_thread,
                stop_tx: observer_stop_tx,
            });

            // Let reth + consensus settle before polling.
            context.sleep(Duration::from_secs(5)).await;

            // --- Wait for every node to reach stop_height ---
            println!(
                "Waiting for all {} validators and the observer to reach height {}",
                NUM_NODES, args.stop_height
            );

            let observer_rpc_port = get_node_flags(OBSERVER_SLOT, &e2e_genesis_path_str).rpc_port;

            loop {
                let mut all_ready = true;
                for idx in 0..(NUM_NODES as usize) {
                    let rpc_port = get_node_flags(idx, &e2e_genesis_path_str).rpc_port;
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
                match get_latest_height(observer_rpc_port).await {
                    Ok(height) => {
                        if height < args.stop_height {
                            all_ready = false;
                            println!("Observer at height {}", height);
                        } else {
                            println!("Observer reached height {}", height);
                        }
                    }
                    Err(e) => {
                        all_ready = false;
                        println!("Observer error: {}", e);
                    }
                }

                if all_ready {
                    println!("All nodes (including the observer) reached target height!");
                    break;
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // --- Verify the observer did not participate in consensus ---
            println!("Verifying observer did not sign any finalized block...");

            let master_key_hex = fs::read_to_string(format!(
                "testnet/node{}/node_key.pem",
                MASTER_VALIDATOR_IDX
            ))
            .expect("failed to read master node key");
            let master_key_bytes =
                from_hex_formatted(&master_key_hex).expect("invalid hex in master node key");
            let master_priv_key = PrivateKey::decode(&master_key_bytes[..])
                .expect("failed to decode master private key");
            let observer_pubkey =
                derive_child_public(master_priv_key.public_key(), OBSERVER_DERIVE_IDX);

            let val_rpc_port = get_node_flags(0, &e2e_genesis_path_str).rpc_port;
            let checkpoint_res = fetch_latest_checkpoint(val_rpc_port)
                .await
                .expect("failed to fetch latest checkpoint from validator 0");

            let checkpoint = Checkpoint::from_ssz_bytes(&checkpoint_res.checkpoint)
                .expect("failed to decode checkpoint");
            let consensus_state = ConsensusState::try_from(&checkpoint)
                .expect("failed to reconstruct consensus state from checkpoint");

            // Simplex's participant order is the ed25519-ascending order of the
            // active validator set; sort here to match.
            let mut active_validators = consensus_state.get_active_validators();
            active_validators.sort_by(|a, b| a.0.cmp(&b.0));

            for (idx, (v_pk, _)) in active_validators.iter().enumerate() {
                assert_ne!(
                    v_pk, &observer_pubkey,
                    "observer pubkey ({}) must not appear in the validator set (found at index {})",
                    observer_pubkey, idx
                );
            }
            println!(
                "    observer pubkey {} is NOT in the active validator set ({} validators)",
                observer_pubkey,
                active_validators.len()
            );

            let finalized_header = FinalizedHeader::<MultisigScheme>::from_ssz_bytes(
                &checkpoint_res.finalized_header,
            )
            .expect("failed to decode finalized header");

            let signers = &finalized_header.finalization.certificate.signers;
            let signer_count = signers.count();
            let expected_quorum = 2 * active_validators.len() / 3 + 1;
            assert!(
                signer_count >= expected_quorum,
                "expected at least {} signers (quorum of {} validators), got {}",
                expected_quorum,
                active_validators.len(),
                signer_count
            );

            for participant in signers.iter() {
                let signer_idx = usize::from(participant);
                assert!(
                    signer_idx < active_validators.len(),
                    "signer index {} is out of range for {} participants",
                    signer_idx,
                    active_validators.len()
                );
                let (signer_pk, _) = &active_validators[signer_idx];
                assert_ne!(
                    signer_pk, &observer_pubkey,
                    "observer pubkey {} must not appear as a finalization signer",
                    observer_pubkey
                );
            }
            println!(
                "    latest finalized block (epoch {}, view {}) has {} signers, none of which is the observer",
                finalized_header.header.epoch, finalized_header.header.view, signer_count
            );

            println!("Test completed successfully!");

            println!("Sending stop signals to all {} nodes...", node_runtimes.len());
            for (idx, node_runtime) in node_runtimes.iter().enumerate() {
                println!("Sending stop signal to node index {}...", idx);
                let _ = node_runtime.stop_tx.send(());
            }

            Ok::<_, Box<dyn std::error::Error>>(node_runtimes)
        }
    })?;

    println!("Waiting for all nodes to shut down...");
    for (idx, node_runtime) in node_runtimes.into_iter().enumerate() {
        println!("Waiting for node index {} to join...", idx);
        match node_runtime.thread.join() {
            Ok(_) => println!("Node index {} thread joined successfully", idx),
            Err(e) => println!("Node index {} thread join failed: {:?}", idx, e),
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

async fn fetch_latest_checkpoint(
    rpc_port: u16,
) -> Result<CheckpointRes, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", rpc_port);
    let client = HttpClientBuilder::default().build(&url)?;
    let res = client.get_latest_checkpoint().await?;
    Ok(res)
}

fn get_node_flags(node: usize, genesis_path: &str) -> RunFlags {
    let path = format!("testnet/node{node}/");

    RunFlags {
        key_store_path: path.clone(),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        prom_ip: "0.0.0.0".into(),
        rpc_port: (3030 + (node * 10)) as u16,
        admin_rpc_port: (3031 + (node * 10)) as u16,
        rpc_max_request_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        rpc_max_response_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        worker_threads: Some(2),
        log_level: "debug".into(),
        db_prefix: format!("{node}"),
        genesis_path: genesis_path.into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(feature = "bench")]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: false,
        ip: None,
        bootstrappers: None,
        critical_log_dir: None,
        observer: None,
    }
}
