/*
End-to-end follower test.

Starts NUM_NODES genesis validators, waits for them to reach `--join-height`,
then starts a follower (`summit run --follow <url>...`) that reaches
`--stop-height` from the validators' RPC alone, and reports how long it took to
catch up.

The follower:
  - Has no keystore: its `--key-store-path` is an empty directory, and its
    `getPublicKeys` must report that follow mode has no identity.
  - Registers with no P2P network and runs no Simplex; it fetches finalized
    blocks through each validator's follower listener (`--follower-rpc-port`).
  - Runs its own Reth instance and executes every finalized block.
*/

use clap::Parser;
use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, tokio as cw_tokio};
use futures::{FutureExt, pin_mut};
use jsonrpsee::http_client::HttpClientBuilder;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    path::PathBuf,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit_rpc::SummitApiClient;
use summit_types::genesis::Genesis;
use summit_types::reth::Reth;
use tokio::sync::mpsc;
use tracing::Level;

const NUM_NODES: u16 = 4;
const GENESIS_PATH: &str = "./example_genesis.toml";
const E2E_BLOCKS_PER_EPOCH: u64 = 50;
// Logical slot for the follower's ports / IPC path / data directory.
const FOLLOWER_SLOT: usize = (NUM_NODES + 1) as usize;

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
    #[arg(long, default_value = "/tmp/summit_follower_test")]
    pub data_dir: String,
    /// Height the validators reach before the follower starts
    #[arg(long, default_value_t = 60)]
    pub join_height: u64,
    /// Height that all nodes (including the follower) must reach for the test to succeed
    #[arg(long, default_value_t = 120)]
    pub stop_height: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    assert!(
        args.join_height < args.stop_height,
        "--join-height must be below --stop-height"
    );

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
                    .arg("--seismic.purpose-keys-source")
                    .arg("built-in")
                    .arg("--auth-ipc")
                    .arg("--auth-ipc.path")
                    .arg(format!("/tmp/reth_engine_api{x}.ipc"))
                    .arg("--metrics")
                    .arg(format!("0.0.0.0:{}", 9001 + x));

                let mut reth = reth_builder.spawn();
                let stdout = reth.stdout().expect("Failed to get stdout");
                let log_dir = args.log_dir.clone();
                context.child("reth").spawn(async move |_| {
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
                        let node_handle = node_context.child("node").spawn(move |ctx| async move {
                            // a coordinated shutdown (graceful stop or committee exit) returns
                            // ok; a genuine core task failure returns err and must fail the
                            // scenario instead of being masked as a clean node exit.
                            if let Err(e) = run_node_local(ctx, flags, None, None).await.unwrap() {
                                eprintln!("node {x} core task failed: {e:?}; failing scenario");
                                std::process::exit(1);
                            }
                        });

                        let stop_fut = stop_rx.recv().fuse();
                        pin_mut!(stop_fut);
                        futures::select! {
                            _ = stop_fut => {
                                println!("Node {} received stop signal, shutting down runtime...", x);
                                node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
                            }
                            _ = node_handle.fuse() => {
                                // Every validator here is a required participant; its handle
                                // completing without a stop signal means it went down
                                // unexpectedly, so fail the scenario.
                                eprintln!("Node {} handle completed unexpectedly; failing scenario", x);
                                std::process::exit(1);
                            }
                        }
                    });
                });

                node_runtimes.push(NodeRuntime { thread, stop_tx });
            }

            // --- Wait for the cohort to reach join_height ---
            let validator_rpc_port = get_node_flags(0, &e2e_genesis_path_str).rpc_port;
            loop {
                match get_latest_height(validator_rpc_port).await {
                    Ok(height) if height >= args.join_height => break,
                    Ok(height) => println!("Node 0 at height {height}, waiting for {}", args.join_height),
                    Err(e) => println!("Node 0 error: {e}"),
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // --- Follower ---
            let follower_reth_data_dir = format!("{}/follower/data/reth_db", args.data_dir);
            let follower_key_dir = format!("{}/follower/keys", args.data_dir);
            fs::create_dir_all(&follower_reth_data_dir)
                .expect("Failed to create follower reth data directory");
            // Empty: follow mode must not read a keystore.
            fs::create_dir_all(&follower_key_dir)
                .expect("Failed to create follower key directory");

            println!("******* STARTING RETH FOR FOLLOWER");
            let follower_reth_builder = Reth::new()
                .instance(FOLLOWER_SLOT as u16 + 1)
                .keep_stdout()
                .data_dir(follower_reth_data_dir)
                .arg("--seismic.purpose-keys-source")
                .arg("built-in")
                .arg("--auth-ipc")
                .arg("--auth-ipc.path")
                .arg(format!("/tmp/reth_engine_api{}.ipc", FOLLOWER_SLOT))
                .arg("--metrics")
                .arg(format!("0.0.0.0:{}", 9001 + FOLLOWER_SLOT));

            let mut follower_reth = follower_reth_builder.spawn();
            let follower_stdout = follower_reth.stdout().expect("Failed to get follower stdout");
            let log_dir = args.log_dir.clone();
            context.child("reth").spawn(async move |_| {
                let reader = BufReader::new(follower_stdout);
                let mut log_file = log_dir.as_ref().map(|dir| {
                    fs::File::create(format!("{}/follower.log", dir))
                        .expect("Failed to create follower log file")
                });
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(ref mut file) = log_file {
                        writeln!(file, "[Follower] {}", line)
                            .expect("Failed to write follower log");
                    }
                }
            });

            println!("Follower rpc address: {}", follower_reth.http_port());
            handles.push_back(follower_reth);

            let mut follower_flags = get_node_flags(FOLLOWER_SLOT, &e2e_genesis_path_str);
            follower_flags.key_store_path = follower_key_dir;
            follower_flags.follow = (0..NUM_NODES as usize)
                .map(|idx| format!("http://localhost:{}", follower_rpc_port(idx)))
                .collect();
            let follower_rpc_port = follower_flags.rpc_port;

            let cohort_tip = get_latest_height(validator_rpc_port)
                .await
                .expect("failed to read the cohort's tip");
            println!(
                "Starting follower at cohort height {cohort_tip}, following {:?}",
                follower_flags.follow
            );
            let follower_started = Instant::now();

            let (follower_stop_tx, mut follower_stop_rx) = mpsc::unbounded_channel();
            let data_dir_clone = args.data_dir.clone();
            let follower_thread = std::thread::spawn(move || {
                let storage_dir = PathBuf::from(&data_dir_clone)
                    .join("stores")
                    .join("follower");
                let cfg = cw_tokio::Config::default()
                    .with_tcp_nodelay(Some(true))
                    .with_worker_threads(4)
                    .with_storage_directory(storage_dir)
                    .with_catch_panics(true);
                let executor = cw_tokio::Runner::new(cfg);

                executor.start(|node_context| async move {
                    let node_handle = node_context.child("node").spawn(move |ctx| async move {
                        // the follower is a required participant: a genuine core task failure
                        // (err) must fail the scenario rather than be masked as a clean exit.
                        if let Err(e) = run_node_local(ctx, follower_flags, None, None)
                            .await
                            .unwrap()
                        {
                            eprintln!("follower core task failed: {e:?}; failing scenario");
                            std::process::exit(1);
                        }
                    });

                    let stop_fut = follower_stop_rx.recv().fuse();
                    pin_mut!(stop_fut);
                    futures::select! {
                        _ = stop_fut => {
                            println!("Follower received stop signal, shutting down runtime...");
                            node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
                        }
                        _ = node_handle.fuse() => {
                            eprintln!("Follower handle completed unexpectedly; failing scenario");
                            std::process::exit(1);
                        }
                    }
                });
            });

            node_runtimes.push(NodeRuntime {
                thread: follower_thread,
                stop_tx: follower_stop_tx,
            });

            // --- Wait for the follower to catch up, then for every node to reach stop_height ---
            let mut caught_up = None;
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
                match get_latest_height(follower_rpc_port).await {
                    Ok(height) => {
                        if caught_up.is_none() && height >= cohort_tip {
                            let elapsed = follower_started.elapsed();
                            println!(
                                "Follower caught up to cohort height {cohort_tip} in {:.1}s ({:.1} blocks/s)",
                                elapsed.as_secs_f64(),
                                cohort_tip as f64 / elapsed.as_secs_f64()
                            );
                            caught_up = Some(elapsed);
                        }
                        if height < args.stop_height {
                            all_ready = false;
                            println!("Follower at height {}", height);
                        } else {
                            println!("Follower reached height {}", height);
                        }
                    }
                    Err(e) => {
                        all_ready = false;
                        println!("Follower error: {}", e);
                    }
                }

                if all_ready {
                    println!("All nodes (including the follower) reached target height!");
                    break;
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // --- Verify the follower holds no identity ---
            let follower_client =
                HttpClientBuilder::default().build(format!("http://localhost:{follower_rpc_port}"))?;
            match follower_client.get_public_keys().await {
                Err(jsonrpsee::core::client::Error::Call(e)) if e.code() == 4005 => {
                    println!("    follower reports no identity (getPublicKeys: {})", e.message());
                }
                other => panic!("follower getPublicKeys must be disabled in follow mode, got {other:?}"),
            }

            println!(
                "Follower reached height {} in {:.1}s from start",
                args.stop_height,
                follower_started.elapsed().as_secs_f64()
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
            Err(e) => {
                eprintln!("Node index {} thread join failed: {:?}", idx, e);
                std::process::exit(1);
            }
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

fn follower_rpc_port(node: usize) -> u16 {
    (3032 + (node * 10)) as u16
}

fn get_node_flags(node: usize, genesis_path: &str) -> RunFlags {
    let path = format!("testnet/node{node}/");

    RunFlags {
        key_store_path: path.clone(),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        prom_ip: "0.0.0.0".into(),
        rpc_ip: "0.0.0.0".into(),
        rpc_port: (3030 + (node * 10)) as u16,
        admin_rpc_port: (3031 + (node * 10)) as u16,
        rpc_max_request_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        rpc_max_response_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        rpc_request_timeout_secs: summit_rpc::DEFAULT_RPC_REQUEST_TIMEOUT_SECS,
        rpc_max_batch_size: summit_rpc::DEFAULT_RPC_MAX_BATCH_SIZE,
        worker_threads: Some(2),
        log_level: "debug".into(),
        db_prefix: format!("{node}"),
        genesis_path: genesis_path.into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(feature = "bench")]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: false,
        weak_subjectivity_path: None,
        unsafe_skip_checkpoint_verification: false,
        ip: None,
        bootstrappers: None,
        critical_log_dir: None,
        observer: None,
        follow: Vec::new(),
        // Every node serves its resolver on loopback, so the follower can
        // follow any of them (and could itself be followed).
        follower_rpc_ip: "127.0.0.1".into(),
        follower_rpc_port: Some(follower_rpc_port(node)),
        finalizer_pending_notarized_max: 1000,
    }
}
