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

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::ReadExt;
use commonware_utils::from_hex_formatted;
use futures::{channel::oneshot, future::try_join_all};
use governor::Quota;
use ssz::Decode;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    str::FromStr as _,
};
#[cfg(feature = "base-bench")]
use summit_types::engine_client::base_benchmarking::HistoricalEngineClient;

#[cfg(feature = "bench")]
use summit_types::engine_client::benchmarking::EthereumHistoricalEngineClient;

use crate::config::MAILBOX_SIZE;
use crate::engine::VALIDATOR_MINIMUM_STAKE;
#[cfg(not(any(feature = "bench", feature = "base-bench")))]
use summit_types::RethEngineClient;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::network_oracle::DiscoveryOracle;
use summit_types::{Genesis, PublicKey, utils::get_expanded_path};
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
    /// Path to a checkpoint file
    #[arg(long)]
    pub checkpoint_path: Option<String>,
    /// IP address for this node (optional, will use genesis if not provided)
    #[arg(long)]
    pub ip: Option<String>,
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
        // Initialize tokio-console subscriber if feature is enabled
        #[cfg(feature = "tokio-console")]
        {
            console_subscriber::init();
        }

        let maybe_checkpoint = flags.checkpoint_path.as_ref().map(|path| {
            // TODO(matthias): verify the checkpoint
            let checkpoint_bytes: Vec<u8> =
                std::fs::read(path).expect("failed to read checkpoint from disk");
            let checkpoint =
                Checkpoint::from_ssz_bytes(&checkpoint_bytes).expect("failed to parse checkpoint");
            ConsensusState::try_from(checkpoint)
                .expect("failed to create consensus state from checkpoint")
        });

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

            let mut committee: Vec<(PublicKey, SocketAddr, Address)> = genesis
                .validators
                .iter()
                .map(|v| v.try_into().expect("Invalid validator in genesis"))
                .collect();
            committee.sort();

            let genesis_hash: [u8; 32] = from_hex_formatted(&genesis.eth_genesis_hash)
                .map(|hash_bytes| hash_bytes.try_into())
                .expect("bad eth_genesis_hash")
                .expect("bad eth_genesis_hash");
            let initial_state = get_initial_state(genesis_hash, &committee, maybe_checkpoint);
            let mut peers: Vec<PublicKey> = initial_state
                .validator_accounts
                .iter()
                .filter(|(_, acc)| !(acc.status == ValidatorStatus::Inactive))
                .map(|(v, _)| {
                    let mut key_bytes = &v[..];
                    PublicKey::read(&mut key_bytes).expect("failed to parse public key")
                })
                .collect();
            peers.sort();

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

            let our_ip = if let Some(ref ip_str) = flags.ip {
                ip_str
                    .parse::<SocketAddr>()
                    .expect("Invalid IP address format")
            } else {
                committee
                    .iter()
                    .find_map(|v| {
                        if v.0 == signer.public_key() {
                            Some(v.1)
                        } else {
                            None
                        }
                    })
                    .expect("This node is not on the committee")
            };

            let mut network_committee: Vec<(PublicKey, SocketAddr)> = committee
                .into_iter()
                .map(|(key, ip, _)| (key, ip))
                .collect();
            let our_public_key = signer.public_key();
            if !network_committee
                .iter()
                .any(|(key, _)| key == &our_public_key)
            {
                network_committee.push((our_public_key, our_ip));
                network_committee.sort();
            }

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
                let stop_signal = context.stopped();
                MetricServer::new(config).serve(stop_signal).await.unwrap();
            }

            // configure network
            let mut p2p_cfg = authenticated::discovery::Config::recommended(
                signer.clone(),
                genesis.namespace.as_bytes(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port),
                our_ip,
                network_committee.clone(),
                genesis.max_message_size_bytes as usize,
            );
            p2p_cfg.mailbox_size = MAILBOX_SIZE;

            // Start p2p
            let (mut network, mut oracle) =
                authenticated::discovery::Network::new(context.with_label("network"), p2p_cfg);

            // Provide authorized peers
            oracle
                .register(initial_state.latest_height, peers.clone())
                .await;

            let oracle = DiscoveryOracle::new(oracle);
            let config = EngineConfig::get_engine_config(
                engine_client,
                oracle,
                signer,
                peers,
                flags.db_prefix.clone(),
                &genesis,
                initial_state,
            )
            .unwrap();

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
            let stop_signal = context.stopped();
            let rpc_handle = context.with_label("rpc").spawn(move |_context| async move {
                if let Err(e) =
                    start_rpc_server(finalizer_mailbox, key_path, rpc_port, stop_signal).await
                {
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

pub fn run_node_with_runtime(
    context: tokio::Context,
    flags: RunFlags,
    checkpoint: Option<ConsensusState>,
) -> Handle<()> {
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

        let mut committee: Vec<(PublicKey, SocketAddr, Address)> = genesis
            .validators
            .iter()
            .map(|v| v.try_into().expect("Invalid validator in genesis"))
            .collect();
        committee.sort();

        let genesis_hash: [u8; 32] = from_hex_formatted(&genesis.eth_genesis_hash)
            .map(|hash_bytes| hash_bytes.try_into())
            .expect("bad eth_genesis_hash")
            .expect("bad eth_genesis_hash");
        let initial_state = get_initial_state(genesis_hash, &committee, checkpoint);
        let mut peers: Vec<PublicKey> = initial_state
            .validator_accounts
            .iter()
            .filter(|(_, acc)| !(acc.status == ValidatorStatus::Inactive))
            .map(|(v, _)| {
                let mut key_bytes = &v[..];
                PublicKey::read(&mut key_bytes).expect("failed to parse public key")
            })
            .collect();
        peers.sort();

        let engine_ipc_path =
            get_expanded_path(&flags.engine_ipc_path).expect("failed to expand engine ipc path");

        #[allow(unused)]
        #[cfg(feature = "base-bench")]
        let engine_client = {
            let block_dir = flags
                .bench_block_dir
                .as_ref()
                .map(|p| get_expanded_path(p).expect("Invalid block directory path"))
                .expect("bench_block_dir is required when using bench feature");
            HistoricalEngineClient::new(engine_ipc_path.to_string_lossy().to_string(), block_dir)
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

        let our_ip = if let Some(ref ip_str) = flags.ip {
            ip_str
                .parse::<SocketAddr>()
                .expect("Invalid IP address format")
        } else {
            committee
                .iter()
                .find_map(|v| {
                    if v.0 == signer.public_key() {
                        Some(v.1)
                    } else {
                        None
                    }
                })
                .expect("This node is not on the committee")
        };

        let mut network_committee: Vec<(PublicKey, SocketAddr)> = committee
            .into_iter()
            .map(|(key, ip, _)| (key, ip))
            .collect();
        let our_public_key = signer.public_key();
        if !network_committee
            .iter()
            .any(|(key, _)| key == &our_public_key)
        {
            network_committee.push((our_public_key, our_ip));
            network_committee.sort();
        }

        // configure network
        #[cfg(feature = "e2e")]
        let mut p2p_cfg = authenticated::discovery::Config::aggressive(
            signer.clone(),
            genesis.namespace.as_bytes(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port),
            our_ip,
            network_committee,
            genesis.max_message_size_bytes as usize,
        );
        #[cfg(not(feature = "e2e"))]
        let mut p2p_cfg = authenticated::discovery::Config::recommended(
            signer.clone(),
            genesis.namespace.as_bytes(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port),
            our_ip,
            network_committee,
            genesis.max_message_size_bytes as usize,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;

        // Start p2p
        let (mut network, mut oracle) =
            authenticated::discovery::Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        oracle
            .register(initial_state.latest_height, peers.clone())
            .await;

        let oracle = DiscoveryOracle::new(oracle);

        let config = EngineConfig::get_engine_config(
            engine_client,
            oracle,
            signer,
            peers,
            flags.db_prefix.clone(),
            &genesis,
            initial_state,
        )
        .unwrap();

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
            let stop_signal = context.stopped();
            let config = MetricServerConfig::new(listen_addr, hooks);
            MetricServer::new(config).serve(stop_signal).await.unwrap();
        }

        // Start RPC server
        let key_path = flags.key_path.clone();
        let rpc_port = flags.rpc_port;
        let stop_signal = context.stopped();
        let rpc_handle = context
            .with_label("rpc_genesis")
            .spawn(move |_context| async move {
                if let Err(e) =
                    start_rpc_server(finalizer_mailbox, key_path, rpc_port, stop_signal).await
                {
                    error!("RPC server failed: {}", e);
                }
            });

        // Wait for any task to error
        if let Err(e) = try_join_all(vec![p2p, engine, rpc_handle]).await {
            error!(?e, "task failed");
        }
    })
}

fn get_initial_state(
    genesis_hash: [u8; 32],
    genesis_committee: &Vec<(PublicKey, SocketAddr, Address)>,
    checkpoint: Option<ConsensusState>,
) -> ConsensusState {
    let genesis_hash: B256 = genesis_hash.into();
    checkpoint.unwrap_or_else(|| {
        let forkchoice = ForkchoiceState {
            head_block_hash: genesis_hash,
            safe_block_hash: genesis_hash,
            finalized_block_hash: genesis_hash,
        };
        let mut state = ConsensusState::new(forkchoice);
        // Add the genesis nodes to the consensus state with the minimum stake balance.
        for (pubkey, _, address) in genesis_committee {
            let pubkey_bytes: [u8; 32] = pubkey
                .as_ref()
                .try_into()
                .expect("Public key must be 32 bytes");
            let account = ValidatorAccount {
                // TODO(matthias): we have to add a withdrawal address to the genesis
                withdrawal_credentials: *address,
                balance: VALIDATOR_MINIMUM_STAKE,
                pending_withdrawal_amount: 0,
                status: ValidatorStatus::Active,
                // TODO(matthias): this index is comes from the deposit contract.
                // Since there is no deposit transaction for the genesis nodes, the index will still be
                // 0 for the deposit contract. Right now we only use this index to avoid counting the same deposit request twice.
                // Since we set the index to 0 here, we cannot rely on the uniqueness. The first actual deposit request will have
                // index 0 as well.
                last_deposit_index: 0,
            };
            state.validator_accounts.insert(pubkey_bytes, account);
        }
        state
    })
}
