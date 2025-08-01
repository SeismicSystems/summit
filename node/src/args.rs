use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr as _,
};
use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use commonware_cryptography::Signer;
use commonware_p2p::authenticated;
use commonware_runtime::{Handle, Metrics as _, Runner, Spawner as _, tokio};
use futures::future::try_join_all;
use governor::Quota;
use summit_types::{Genesis, PublicKey};
use tracing::{Level, error};
use summit_application::engine_client::RethEngineClient;
use crate::{
    config::{
        BACKFILLER_CHANNEL, BROADCASTER_CHANNEL, EngineConfig, MESSAGE_BACKLOG, PENDING_CHANNEL,
        RECOVERED_CHANNEL, RESOLVER_CHANNEL,
    },
    engine::Engine,
    keys::KeySubCmd,
    utils::get_expanded_path,
};

//use crate::keys::KeySubCmd;

pub const DEFAULT_KEY_PATH: &str = "~/.seismic/consensus/key.pem";
pub const DEFAULT_SHARE_PATH: &str = "~/.seismic/consensus/share.pem";
pub const DEFAULT_DB_FOLDER: &str = "~/.seismic/consensus/store";

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: Command,

    #[command(flatten)]
    pub flags: Flags,
}

impl CliArgs {
    pub fn exec(&self) {
        self.cmd.exec(&self.flags)
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Start the validator
    Run,
    /// Key management utilities
    #[command(subcommand)]
    Keys(KeySubCmd),
}

#[derive(Args, Debug, Clone)]
pub struct Flags {
    /// Path to your private key or where you want it generated
    #[arg(long, default_value_t = DEFAULT_KEY_PATH.into())]
    pub key_path: String,
    /// path to this nodes polynomial share
    #[arg(long, default_value_t = DEFAULT_SHARE_PATH.into())]
    pub share_path: String,
    /// Path to the folder we will keep the consensus DB
    #[arg(long, default_value_t = DEFAULT_DB_FOLDER.into())]
    pub store_path: String,
    /// Url to the engine API of the execution client
    #[arg(long, default_value_t = 8551)]
    pub engine_port: u16, // todo(dalton): should we make this URL instead of just port to support off server execution clients
    /// JWT token for communicating with engine api
    #[arg(
        long,
        default_value_t = String::from("~/.seismic/jwt.hex")
    )]
    pub engine_jwt_path: String, // todo(dalton): Lets point this at a file instead of expecting a string to keep inline with how reth handles this
    /// Port Consensus runs on
    #[arg(long, default_value_t = 8551)]
    pub port: u16,

    /// Port Consensus runs on
    #[arg(long, default_value_t = 9090)]
    pub prom_port: u16,

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
    pub fn exec(&self, flags: &Flags) {
        match self {
            Command::Run => self.run_node(flags),
            Command::Keys(cmd) => cmd.exec(flags),
        }
    }

    pub fn run_node(&self, flags: &Flags) {
        let genesis =
            Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

        let mut committee: Vec<(PublicKey, SocketAddr)> = genesis
            .validators
            .iter()
            .map(|v| v.try_into().expect("Invalid validator in genesis"))
            .collect();
        committee.sort();
        let engine_url = format!("http://0.0.0.0:{}", flags.engine_port);
        let peers: Vec<PublicKey> = committee.iter().map(|v| v.0.clone()).collect();

        // read JWT from file
        let jwt_path = get_expanded_path(&flags.engine_jwt_path).expect("failed to expand jwt path");
        let engine_jwt = std::fs::read_to_string(jwt_path).expect("failed to load jwt");
        let engine_client = RethEngineClient::new(engine_url.clone(), &engine_jwt);
        let config = EngineConfig::get_engine_config(
            engine_client,
            flags.key_path.clone(),
            flags.share_path.clone(),
            peers.clone(),
            flags.db_prefix.clone(),
            &genesis,
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

        let store_path = get_expanded_path(&flags.store_path).expect("Invalid store path");

        // Initialize runtime
        let cfg = tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(flags.worker_threads)
            .with_storage_directory(store_path)
            .with_catch_panics(false);
        let executor = tokio::Runner::new(cfg);

        executor.start(|context| async move {
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

            // Register recovered channel
            let recovered_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
            let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

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
            let engine = Engine::new(context.with_label("engine"), config, oracle).await;

            // Start engine
            let engine = engine.start(pending, recovered, resolver, broadcaster, backfiller);

            // Wait for any task to error
            if let Err(e) = try_join_all(vec![p2p, engine]).await {
                error!(?e, "task failed");
            }
        })
    }
}

pub fn run_node_with_runtime(
    context: commonware_runtime::tokio::Context,
    flags: Flags,
) -> Handle<()> {
    let genesis = Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

    let mut committee: Vec<(PublicKey, SocketAddr)> = genesis
        .validators
        .iter()
        .map(|v| v.try_into().expect("Invalid validator in genesis"))
        .collect();
    committee.sort();

    let engine_url = format!("http://0.0.0.0:{}", flags.engine_port);
    let peers: Vec<PublicKey> = committee.iter().map(|v| v.0.clone()).collect();

    let jwt_path = get_expanded_path(&flags.engine_jwt_path).expect("failed to expand jwt path");
    let engine_jwt = std::fs::read_to_string(jwt_path).expect("failed to load jwt");
    let engine_client = RethEngineClient::new(engine_url.clone(), &engine_jwt);
    let config = EngineConfig::get_engine_config(
        engine_client,
        flags.key_path.clone(),
        flags.share_path.clone(),
        peers.clone(),
        flags.db_prefix.clone(),
        &genesis,
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

    context.spawn(async move |context| {
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

        // Register recovered channel
        let recovered_limit = Quota::per_second(NonZeroU32::new(128).unwrap());
        let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

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
        let engine = Engine::new(context.with_label("engine"), config, oracle).await;

        // Start engine
        let engine = engine.start(pending, recovered, resolver, broadcaster, backfiller);

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, engine]).await {
            error!(?e, "task failed");
        }
    })
}
