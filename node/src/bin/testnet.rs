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
    path::PathBuf,
};

use alloy_node_bindings::Reth;
use clap::Parser;
use commonware_runtime::{Metrics as _, Runner as _, Spawner as _, tokio};
use summit::args::{RunFlags, run_node_with_runtime};

#[derive(Parser, Debug)]
struct Args {
    /// Number of nodes you want to run for this test
    #[arg(long, default_value_t = 4)]
    nodes: u16,
    #[arg[long]]
    only_reth: bool,
    /// Path to the directory containing historical blocks for benchmarking
    #[cfg(any(feature = "base-bench", feature = "bench"))]
    #[arg(long)]
    pub bench_block_dir: Option<String>,
    /// Path to the log directory
    #[arg(long)]
    pub log_dir: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tokio-console subscriber if feature is enabled
    #[cfg(feature = "tokio-console")]
    {
        console_subscriber::ConsoleLayer::builder()
            .retention(std::time::Duration::from_secs(60))
            .init();
    }

    let args = Args::parse();

    // Create log directory if specified
    if let Some(ref log_dir) = args.log_dir {
        fs::create_dir_all(log_dir)?;
    }

    let cfg = tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(PathBuf::from("testnet/stores"))
        .with_catch_panics(false);
    let executor = tokio::Runner::new(cfg);

    executor.start(|context| {
        async move {
            // Configure telemetry (skip if tokio-console is enabled)
            #[cfg(not(feature = "tokio-console"))]
            {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                use std::str::FromStr as _;
                use tracing::Level;

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
            }

            // Vector to hold all the join handles
            let mut handles = Vec::new();
            let mut consensus_handles = Vec::new();
            // let mut read_threads = Vec::new();

            for x in 0..args.nodes {
                // Start Reth
                println!("******* STARTING RETH FOR NODE {x}");
                // Build and spawn reth instance
                let reth_builder = Reth::new()
                    .instance(x + 1)
                    .keep_stdout()
                    //    .genesis(serde_json::from_str(&genesis_str).expect("invalid genesis"))
                    .data_dir(format!("testnet/node{x}/data/reth_db"))
                    .arg("--authrpc.jwtsecret")
                    .arg("testnet/jwt.hex")
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
                // Spawn a thread to read stdout since it's blocking I/O
                // let reader_thread = std::thread::spawn(move || {
                //     let reader = BufReader::new(stdout);
                //     for line in reader.lines() {
                //         match line {
                //             Ok(line) => {
                //                 println!("[Node {}] {}", x, line);
                //             }
                //             Err(e) => {
                //                 eprintln!("[Node {}] Error reading line: {}", x, e);
                //             }
                //         }
                //     }
                // });

                let _auth_port = reth.auth_port().unwrap();

                println!("Node {} rpc address: {}", x, reth.http_port());

                // read_threads.push(reader_thread);
                handles.push(reth);

                if args.only_reth {
                    continue;
                }
                #[allow(unused_mut)]
                let mut flags = get_node_flags(x.into());

                #[cfg(any(feature = "base-bench", feature = "bench"))]
                {
                    flags.bench_block_dir = args.bench_block_dir.clone();
                }

                // Start our consensus engine
                let handle = run_node_with_runtime(context.with_label(&format!("node{x}")), flags);
                consensus_handles.push(handle);
            }

            // for reader in read_threads {
            //     reader.join().unwrap();
            // }
            if let Err(e) = futures::future::try_join_all(consensus_handles).await {
                tracing::error!("Failed: {:?}", e);
            }

            // Due to how alloy node_bindings work we have to do this to prevent the reth_instances from being dropped and shutdown by the compiler
            for reth in handles {
                println!("{:?}", reth.auth_port());
            }

            Ok(())
        }
    })
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
