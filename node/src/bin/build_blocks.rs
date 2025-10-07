/*
This bin will start 4 reth nodes with an instance of consensus for each and keep running so you can run other tests or submit transactions

Their rpc endpoints are localhost:8545-node_number
node0_port = 8545
node1_port = 8544
...
node3_port = 8542


*/
use std::{
    io::{BufRead as _, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr as _,
};

use alloy_node_bindings::Reth;
use clap::Parser;
use commonware_runtime::{Metrics as _, Runner as _, Spawner as _, tokio};
use summit::args::{RunFlags, run_node_with_runtime};
use tracing::Level;

#[derive(Parser, Debug)]
struct Args {
    /// Number of nodes you want to run for this test
    #[arg(long, default_value_t = 4)]
    nodes: u16,
    #[arg[long]]
    only_reth: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    todo!()
    // let args = Args::parse();

    // let cfg = tokio::Config::default()
    //     .with_tcp_nodelay(Some(true))
    //     .with_worker_threads(16)
    //     .with_storage_directory(PathBuf::from("testnet/stores"))
    //     .with_catch_panics(false);
    // let executor = tokio::Runner::new(cfg);

    // executor.start(|context| {
    //     async move {
    //         // Configure telemetry
    //         let log_level = Level::from_str("info").expect("Invalid log level");
    //         tokio::telemetry::init(
    //             context.with_label("metrics"),
    //             tokio::telemetry::Logging {
    //                 level: log_level,
    //                 // todo: dont know what this does
    //                 json: false,
    //             },
    //             Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6969)),
    //             None,
    //         );

    //         // Vector to hold all the join handles
    //         let mut handles = Vec::new();
    //         let mut consensus_handles = Vec::new();
    //         // let mut read_threads = Vec::new();

    //         // Start Reth
    //         println!("******* STARTING RETH FOR NODE {x}");
    //         // Build and spawn reth instance
    //         let reth_builder = Reth::new()
    //             .instance(x + 1)
    //             .keep_stdout()
    //             //    .genesis(serde_json::from_str(&genesis_str).expect("invalid genesis"))
    //             .data_dir(format!("testnet/node{x}/data/reth_db"))
    //             .arg("--authrpc.jwtsecret")
    //             .arg("testnet/jwt.hex")
    //             .arg("--enclave.mock-server")
    //             .arg("--enclave.endpoint-port")
    //             .arg(format!("1744{x}"))
    //             .arg("--auth-ipc")
    //             .arg("--auth-ipc.path")
    //             .arg(format!("/tmp/reth_engine_api{x}.ipc"));

    //         let mut reth = reth_builder.spawn();

    //         // Get stdout handle
    //         let stdout = reth.stdout().expect("Failed to get stdout");

    //         context.clone().spawn(async move |_| {
    //             let reader = BufReader::new(stdout);
    //             for line in reader.lines() {
    //                 match line {
    //                     Ok(line) => {
    //                         println!("[Node] {}", line);
    //                     }
    //                     Err(_e) => {
    //                         eprintln!("[Node ] Error reading line: {}", x);
    //                     }
    //                 }
    //             }
    //         });
    //         // Spawn a thread to read stdout since it's blocking I/O
    //         // let reader_thread = std::thread::spawn(move || {
    //         //     let reader = BufReader::new(stdout);
    //         //     for line in reader.lines() {
    //         //         match line {
    //         //             Ok(line) => {
    //         //                 println!("[Node {}] {}", x, line);
    //         //             }
    //         //             Err(e) => {
    //         //                 eprintln!("[Node {}] Error reading line: {}", x, e);
    //         //             }
    //         //         }
    //         //     }
    //         // });

    //         let _auth_port = reth.auth_port().unwrap();

    //         println!("Node {} rpc address: {}", x, reth.http_port());

    //         // read_threads.push(reader_thread);
    //         handles.push(reth);

    //         // for reader in read_threads {
    //         //     reader.join().unwrap();
    //         // }
    //         if let Err(e) = futures::future::try_join_all(consensus_handles).await {
    //             tracing::error!("Failed: {:?}", e);
    //         }

    //         // Due to how alloy node_bindings work we have to do this to prevent the reth_instances from being dropped and shutdown by the compiler
    //         for reth in handles {
    //             println!("{:?}", reth.auth_port());
    //         }

    //         Ok(())
    //     }
    // })
}
