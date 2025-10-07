use crate::{
    config::{
        BACKFILLER_CHANNEL, BROADCASTER_CHANNEL, EngineConfig, MESSAGE_BACKLOG, PENDING_CHANNEL,
        RESOLVER_CHANNEL, expect_signer,
    },
    engine::Engine,
    keys::KeySubCmd,
};
use clap::{Args, Parser, Subcommand};
use commonware_cryptography::Signer;
use commonware_p2p::authenticated;
use commonware_runtime::{Handle, Metrics as _, Runner, Spawner as _, tokio};
use summit_rpc::{PathSender, start_rpc_server, start_rpc_server_for_genesis};
use tokio_util::sync::CancellationToken;

use futures::{channel::oneshot, future::try_join_all};
use governor::Quota;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr as _,
};
#[cfg(feature = "base-bench")]
use summit_types::engine_client::base_benchmarking::HistoricalEngineClient;

#[cfg(feature = "bench")]
use summit_types::engine_client::benchmarking::EthereumHistoricalEngineClient;

use summit_types::{Genesis, PublicKey, RethEngineClient, utils::get_expanded_path};
use tracing::{Level, error};

pub const DEFAULT_KEY_PATH: &str = "~/.seismic/consensus/key.pem";
pub const DEFAULT_DB_FOLDER: &str = "~/.seismic/consensus/store";

pub const DEFAULT_ENGINE_IPC_PATH: &str = "/tmp/reth_engine_api.ipc";

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: Command,
}

impl CliArgs {
    pub fn exec(&self) {
        self.cmd.exec()
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Start the validator
    Run {
        #[command(flatten)]
        flags: RunFlags,
    },
    /// Key management utilities
    #[command(subcommand)]
    Keys(KeySubCmd),
}

#[derive(Args, Debug, Clone)]
pub struct RunFlags {
    /// Path to your private key or where you want it generated
    #[arg(long, default_value_t = DEFAULT_KEY_PATH.into())]
    pub key_path: String,
    /// Path to the folder we will keep the consensus DB
    #[arg(long, default_value_t = DEFAULT_DB_FOLDER.into())]
    pub store_path: String,
    /// Path to the engine IPC socket
    #[arg(long, default_value_t = DEFAULT_ENGINE_IPC_PATH.into())]
    pub engine_ipc_path: String,
    /// Path to the directory containing historical blocks for benchmarking
    #[cfg(any(feature = "base-bench", feature = "bench"))]
    #[arg(long)]
    pub bench_block_dir: Option<String>,
    /// Port Consensus runs on
    #[arg(long, default_value_t = 18551)]
    pub port: u16,

    /// Port Consensus runs on
    #[arg(long, default_value_t = 9090)]
    pub prom_port: u16,

    /// Port RPC server runs on
    #[arg(long, default_value_t = 3030)]
    pub rpc_port: u16,

    #[arg(long, default_value_t = 4)]
    pub worker_threads: usize,

    /// level for logs (error,warn,info,debug,trace)
    #[arg(
        long,
        default_value_t = String::from("debug")
    )]
    pub log_level: String,
    #[arg(
        long,
        default_value_t = String::from("quartz")
    )]
    pub db_prefix: String,
    /// Path to the genesis file
    #[arg(
        long,
        default_value_t = String::from("./example_genesis.toml")
    )]
    pub genesis_path: String,
}

impl Command {
    pub fn exec(&self) {
        match self {
            Command::Run { flags } => self.run_node(flags),

            Command::Keys(cmd) => cmd.exec(),
        }
    }

    fn has_file(path: &str) -> bool {
        let path_buf = get_expanded_path(path).expect("Invalid filepath");
        path_buf.exists()
            || !std::fs::read_to_string(&path_buf)
                .unwrap_or_default()
                .trim()
                .is_empty()
    }

    fn check_sender(path: String, tx: oneshot::Sender<()>) -> PathSender {
        let sender = match Self::has_file(&path) {
            true => {
                let _ = tx.send(());
                None
            }
            false => Some(tx),
        };
        PathSender::new(path, sender)
    }

    pub fn run_node(&self, flags: &RunFlags) {
        let store_path = get_expanded_path(&flags.store_path).expect("Invalid store path");
        let signer = expect_signer(&flags.key_path);

        // Initialize runtime
        let cfg = tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(flags.worker_threads)
            .with_storage_directory(store_path)
            .with_catch_panics(false);
        let executor = tokio::Runner::new(cfg);

        executor.start(|context| async move {
            let (genesis_tx, genesis_rx) = oneshot::channel();

            let cancel_token = CancellationToken::new();
            let cloned_token = cancel_token.clone();

            // use the context async move to spawn a new runtime
            let genesis_path = flags.genesis_path.clone();
            let rpc_port = flags.rpc_port;
            let _rpc_handle = context
                .with_label("rpc_genesis")
                .spawn(move |_context| async move {
                    let genesis_sender = Command::check_sender(genesis_path, genesis_tx);
                    if let Err(e) =
                        start_rpc_server_for_genesis(genesis_sender, rpc_port, cloned_token).await
                    {
                        error!("RPC server failed: {}", e);
                    }
                });

            // Wait for genesis if needed
            let _ = genesis_rx.await;
            // Shut down the genesis rpc server after receiving the genesis file
            cancel_token.cancel();

            let genesis =
                Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

            let mut committee: Vec<(PublicKey, SocketAddr)> = genesis
                .validators
                .iter()
                .map(|v| v.try_into().expect("Invalid validator in genesis"))
                .collect();
            committee.sort();
            let peers: Vec<PublicKey> = committee.iter().map(|v| v.0.clone()).collect();

            let engine_ipc_path = get_expanded_path(&flags.engine_ipc_path)
                .expect("failed to expand engine ipc path");

            #[allow(unused)]
            #[cfg(feature = "base-bench")]
            let engine_client = {
                let block_dir = flags
                    .bench_block_dir
                    .as_ref()
                    .map(|p| get_expanded_path(p).expect("Invalid block directory path"))
                    .expect("bench_block_dir is required when using bench feature");
                HistoricalEngineClient::new(
                    engine_ipc_path.to_string_lossy().to_string(),
                    block_dir,
                )
                .await
            };

            #[allow(unused)]
            #[cfg(feature = "bench")]
            let engine_client = {
                let block_dir = flags
                    .bench_block_dir
                    .as_ref()
                    .map(|p| get_expanded_path(p).expect("Invalid block directory path"))
                    .expect("bench_block_dir is required when using bench feature");
                EthereumHistoricalEngineClient::new(
                    engine_ipc_path.to_string_lossy().to_string(),
                    block_dir,
                )
                .await
            };

            #[cfg(not(any(feature = "bench", feature = "base-bench")))]
            let engine_client =
                RethEngineClient::new(engine_ipc_path.to_string_lossy().to_string()).await;

            let config = EngineConfig::get_engine_config(
                engine_client,
                signer,
                peers.clone(),
                flags.db_prefix.clone(),
                &genesis,
                None,
            )
            .unwrap();

            let our_ip = committee
                .iter()
                .find_map(|v| {
                    if v.0 == config.signer.public_key() {
                        Some(v.1)
                    } else {
                        None
                    }
                })
                .expect("This node is not on the committee");

            // Configure telemetry
            let log_level = Level::from_str(&flags.log_level).expect("Invalid log level");
            tokio::telemetry::init(
                context.with_label("telemetry"),
                tokio::telemetry::Logging {
                    level: log_level,
                    // todo: dont know what this does
                    json: false,
                },
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    flags.prom_port + 1,
                )),
                None,
            );

            // Start prometheus endpoint
            #[cfg(feature = "prom")]
            {
                use crate::prom::hooks::Hooks;
                use crate::prom::server::{MetricServer, MetricServerConfig};
                use std::net::SocketAddr;

                let hooks = Hooks::builder().build();

                let listen_addr = format!("0.0.0.0:{}", flags.prom_port)
                    .parse::<SocketAddr>()
                    .unwrap();
                let config = MetricServerConfig::new(listen_addr, hooks);
                MetricServer::new(config).serve().await.unwrap();
            }

            // configure network

            let mut p2p_cfg = authenticated::discovery::Config::aggressive(
                config.signer.clone(),
                genesis.namespace.as_bytes(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port),
                our_ip,
                committee.clone(),
                genesis.max_message_size_bytes as usize,
            );
            p2p_cfg.mailbox_size = config.mailbox_size;

            // Start p2p
            let (mut network, mut oracle) =
                authenticated::discovery::Network::new(context.with_label("network"), p2p_cfg);

            // Provide authorized peers
            oracle
                .register(0, committee.into_iter().map(|(key, _)| key).collect())
                .await;

            // Register pending channel
            let pending_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
            let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

            // Register resolver channel
            let resolver_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
            let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

            // Register broadcast channel
            let broadcaster_limit = Quota::per_second(NonZeroU32::new(8).unwrap());
            let broadcaster =
                network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

            let backfiller =
                network.register(BACKFILLER_CHANNEL, config.backfill_quota, MESSAGE_BACKLOG);

            // Create network
            let p2p = network.start();
            // create engine
            let engine = Engine::new(context.with_label("engine"), config).await;

            let finalizer_mailbox = engine.finalizer_mailbox.clone();

            // Start engine
            let engine = engine.start(pending, resolver, broadcaster, backfiller);

            // Start RPC server
            let key_path = flags.key_path.clone();
            let rpc_port = flags.rpc_port;
            let rpc_handle = context.with_label("rpc").spawn(move |_context| async move {
                if let Err(e) = start_rpc_server(finalizer_mailbox, key_path, rpc_port).await {
                    error!("RPC server failed: {}", e);
                }
            });

            // Wait for any task to error
            if let Err(e) = try_join_all(vec![p2p, engine, rpc_handle]).await {
                error!(?e, "task failed");
            }
        })
    }
}

pub fn run_node_with_runtime(context: tokio::Context, flags: RunFlags) -> Handle<()> {
    context.spawn(async move |context| {
        let signer = expect_signer(&flags.key_path);

        let (genesis_tx, genesis_rx) = oneshot::channel();

        let cancel_token = CancellationToken::new();
        let cloned_token = cancel_token.clone();
        // use the context async move to spawn a new runtime
        let rpc_port = flags.rpc_port;
        let genesis_path = flags.genesis_path.clone();
        let _rpc_handle = context
            .with_label("rpc_genesis")
            .spawn(move |_context| async move {
                let genesis_sender = Command::check_sender(genesis_path, genesis_tx);
                if let Err(e) =
                    start_rpc_server_for_genesis(genesis_sender, rpc_port, cloned_token).await
                {
                    error!("RPC server failed: {}", e);
                }
            });

        // Wait for genesis if needed
        let _ = genesis_rx.await;
        // Shut down the genesis rpc server after receiving the genesis file
        cancel_token.cancel();

        let genesis =
            Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

        let mut committee: Vec<(PublicKey, SocketAddr)> = genesis
            .validators
            .iter()
            .map(|v| v.try_into().expect("Invalid validator in genesis"))
            .collect();
        committee.sort();

        let peers: Vec<PublicKey> = committee.iter().map(|v| v.0.clone()).collect();

        let engine_ipc_path =
            get_expanded_path(&flags.engine_ipc_path).expect("failed to expand engine ipc path");
        let engine_client =
            RethEngineClient::new(engine_ipc_path.to_string_lossy().to_string()).await;

        let config = EngineConfig::get_engine_config(
            engine_client,
            signer,
            peers.clone(),
            flags.db_prefix.clone(),
            &genesis,
            None,
        )
        .unwrap();

        let our_ip = committee
            .iter()
            .find_map(|v| {
                if v.0 == config.signer.public_key() {
                    Some(v.1)
                } else {
                    None
                }
            })
            .expect("This node is not on the committee");

        // configure network

        let mut p2p_cfg = authenticated::lookup::Config::aggressive(
            config.signer.clone(),
            genesis.namespace.as_bytes(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port),
            our_ip,
            genesis.max_message_size_bytes as usize,
        );
        p2p_cfg.mailbox_size = config.mailbox_size;

        // Start p2p
        let (mut network, mut oracle) =
            authenticated::lookup::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle.register(0, committee).await;

        // Register pending channel
        let pending_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

        // Register resolver channel
        let resolver_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

        // Register broadcast channel
        let broadcaster_limit = Quota::per_second(NonZeroU32::new(8).unwrap());
        let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

        let backfiller =
            network.register(BACKFILLER_CHANNEL, config.backfill_quota, MESSAGE_BACKLOG);

        // Create network
        let p2p = network.start();
        // create engine
        let engine = Engine::new(context.with_label("engine"), config).await;

        let finalizer_mailbox = engine.finalizer_mailbox.clone();
        // Start engine
        let engine = engine.start(pending, resolver, broadcaster, backfiller);

        // Start RPC server
        let key_path = flags.key_path.clone();
        let rpc_port = flags.rpc_port;
        let rpc_handle = context
            .with_label("rpc_genesis")
            .spawn(move |_context| async move {
                if let Err(e) = start_rpc_server(finalizer_mailbox, key_path, rpc_port).await {
                    error!("RPC server failed: {}", e);
                }
            });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, engine, rpc_handle]).await {
            error!(?e, "task failed");
        }
    })
}
