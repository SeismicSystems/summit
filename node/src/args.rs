use crate::{
    config::{
        BACKFILLER_CHANNEL, BROADCASTER_CHANNEL, EngineConfig, FINALIZER_PENDING_NOTARIZED_MAX,
        MESSAGE_BACKLOG, PENDING_CHANNEL, RECOVERED_CHANNEL, RESOLVER_CHANNEL, expect_key_store,
    },
    engine::Engine,
    keys::KeySubCmd,
};
use clap::{Args, Parser, Subcommand};
use commonware_codec::Read;
use commonware_cryptography::{Signer, certificate::Scheme};
use commonware_p2p::{Ingress, authenticated};
use commonware_runtime::{Handle, Metrics as _, Runner, Spawner as _, tokio};
use summit_rpc::{PathSender, start_rpc_server, start_rpc_server_for_genesis};
use tokio_util::sync::CancellationToken;

use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_utils::from_hex_formatted;
use futures::{channel::oneshot, future::try_join_all};
use governor::Quota;
use ssz::Decode;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    str::FromStr as _,
};

#[cfg(feature = "bench")]
use summit_types::engine_client::benchmarking::EthereumHistoricalEngineClient;

#[cfg(feature = "bad-blocks")]
use summit_types::engine_client::BadBlockEngineClient;

use crate::config::MAILBOX_SIZE;
use summit_types::FinalizedHeader;
#[cfg(not(feature = "bench"))]
use summit_types::RethEngineClient;
use summit_types::bootstrap::Bootstrappers;
use summit_types::checkpoint::{self, Checkpoint};
use summit_types::ext_private_key::ExtPrivateKey;
use summit_types::keystore::KeyStore;
use summit_types::network_oracle::DiscoveryOracle;
use summit_types::{
    Block, EngineClient,
    account::{ValidatorAccount, ValidatorStatus},
    bls12381,
};
use summit_types::{Genesis, PrivateKey, PublicKey, Validator, utils::get_expanded_path};
use summit_types::{consensus_state::ConsensusState, scheme::MultisigScheme};
use tracing::{Level, error, info, warn};

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
        flags: Box<RunFlags>,
    },
    /// Key management utilities
    #[command(subcommand)]
    Keys(KeySubCmd),
}

#[derive(Args, Debug, Clone)]
pub struct RunFlags {
    /// Path to your keystore directory containing node_key.pem and consensus_key.pem
    #[arg(long, default_value_t = String::from("~/.seismic/consensus/keys"))]
    pub key_store_path: String,
    /// Path to the folder we will keep the consensus DB
    #[arg(long, default_value_t = DEFAULT_DB_FOLDER.into())]
    pub store_path: String,
    /// Path to the engine IPC socket
    #[arg(long, default_value_t = DEFAULT_ENGINE_IPC_PATH.into())]
    pub engine_ipc_path: String,
    /// Path to the directory containing historical blocks for benchmarking
    #[cfg(feature = "bench")]
    #[arg(long)]
    pub bench_block_dir: Option<String>,
    /// Port Consensus runs on
    #[arg(long, default_value_t = 18551)]
    pub port: u16,

    /// Prometheus address
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    pub prom_ip: String,
    /// Port Consensus runs on
    #[arg(long, default_value_t = 9090)]
    pub prom_port: u16,

    /// Port RPC server runs on
    #[arg(long, default_value_t = 3030)]
    pub rpc_port: u16,

    /// Port for the localhost-only admin RPC server (handles validator-key
    /// signing methods like `getDepositSignature`).
    #[arg(long, default_value_t = 3031)]
    pub admin_rpc_port: u16,

    /// Number of tokio worker threads (defaults to number of logical CPUs)
    #[arg(long)]
    pub worker_threads: Option<usize>,

    /// level for logs (error,warn,info,debug,trace)
    #[arg(
        long,
        default_value_t = String::from("debug")
    )]
    pub log_level: String,
    #[arg(
        long,
        default_value_t = String::from("summit")
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

    /// If set, fall back to genesis when the checkpoint path doesn't exist instead of panicking
    #[arg(long)]
    pub checkpoint_or_default: bool,

    /// IP address for this node (optional, will use genesis if not provided)
    #[arg(long)]
    pub ip: Option<String>,

    /// Path to a TOML file containing bootstrapper nodes (pubkey and address) for syncing
    #[arg(long)]
    pub bootstrappers: Option<String>,

    /// Directory for critical event log files (daily rotation).
    /// When set, events emitted with target "critical" are written to files in this directory.
    #[arg(long)]
    pub critical_log_dir: Option<String>,

    /// Observer mode: RPC-only node that follows the chain without proposing or voting on blocks.
    /// The value is a derivation index that produces a distinct identity from the base node key.
    #[arg(long)]
    pub observer: Option<u32>,

    /// Hard cap on unique deferred notarized blocks while the execution layer is SYNCING.
    #[arg(long, default_value_t = FINALIZER_PENDING_NOTARIZED_MAX)]
    pub finalizer_pending_notarized_max: usize,
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

        let loaded = if let Some(checkpoint_path) = &flags.checkpoint_path {
            read_checkpoint::<MultisigScheme>(checkpoint_path, flags.checkpoint_or_default)
        } else {
            LoadedCheckpoint {
                consensus_state: None,
                last_block: None,
                finalized_header: None,
                raw_checkpoint: None,
                finalized_headers_chain: None,
            }
        };
        let store_path = get_expanded_path(&flags.store_path).expect("Invalid store path");

        // Initialize runtime
        let worker_threads = flags
            .worker_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));
        let cfg = tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(worker_threads)
            .with_storage_directory(store_path)
            .with_catch_panics(false);
        let executor = tokio::Runner::new(cfg);

        let flags = flags.clone();

        executor.start(|context| async move {
            let key_store = expect_key_store(&flags.key_store_path);
            run_node_inner(context, flags, key_store, loaded).await;
        })
    }
}

async fn run_node_inner(
    context: tokio::Context,
    flags: RunFlags,
    key_store: KeyStore<PrivateKey>,
    loaded: LoadedCheckpoint<MultisigScheme>,
) {
    let context = context.with_label("summit_cw");
    let (genesis_tx, genesis_rx) = oneshot::channel();

    let cancel_token = CancellationToken::new();
    let cloned_token = cancel_token.clone();

    let genesis_path = flags.genesis_path.clone();
    let genesis_key_store_path = flags.key_store_path.clone();
    let genesis_rpc_port = flags.rpc_port;
    let _rpc_handle = context
        .with_label("rpc_genesis")
        .spawn(move |_context| async move {
            let genesis_sender = Command::check_sender(genesis_path, genesis_tx);
            if let Err(e) = start_rpc_server_for_genesis(
                genesis_sender,
                genesis_key_store_path,
                genesis_rpc_port,
                cloned_token,
            )
            .await
            {
                error!("RPC server failed: {}", e);
            }
        });

    // Wait for genesis if needed
    let _ = genesis_rx.await;
    // Shut down the genesis rpc server after receiving the genesis file
    cancel_token.cancel();

    let genesis = Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

    let mut committee: Vec<Validator> = genesis.get_validators().expect("Failed to get validators");
    committee.sort_by(|lhs, rhs| lhs.node_public_key.cmp(&rhs.node_public_key));

    info!(
        namespace = genesis.namespace,
        genesis_validators = committee.len(),
        min_stake = genesis.validator_minimum_stake,
        max_stake = genesis.validator_maximum_stake,
        "loaded genesis configuration"
    );

    // Verify checkpoint if finalized headers chain was provided
    if let (Some(raw_checkpoint), Some(headers_chain)) =
        (&loaded.raw_checkpoint, &loaded.finalized_headers_chain)
    {
        checkpoint::verify_checkpoint_chain(&genesis, headers_chain, raw_checkpoint)
            .expect("checkpoint verification failed");
        info!(
            epochs_verified = headers_chain.len(),
            "checkpoint verified successfully"
        );
    } else if loaded.raw_checkpoint.is_some() {
        warn!("checkpoint loaded without finalized headers chain - skipping verification");
    }

    let initial_state = get_initial_state(&genesis, &committee, loaded.consensus_state);
    let peers = initial_state.get_validator_keys();

    let engine_ipc_path =
        get_expanded_path(&flags.engine_ipc_path).expect("failed to expand engine ipc path");

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

    #[cfg(not(feature = "bench"))]
    let engine_client = RethEngineClient::new(engine_ipc_path.to_string_lossy().to_string()).await;

    let our_ip = get_node_ip(&flags, &key_store, &committee).await;

    let mut network_committee: Vec<(PublicKey, SocketAddr)> = committee
        .into_iter()
        .map(|v| (v.node_public_key, v.ip_address))
        .collect();

    let our_public_key = key_store.node_key.public_key();
    if !network_committee
        .iter()
        .any(|(key, _)| key == &our_public_key)
    {
        network_committee.push((our_public_key, our_ip));
        network_committee.sort();
    }

    // Configure telemetry with optional critical file logger
    let log_level = Level::from_str(&flags.log_level).expect("Invalid log level");
    let critical_log_dir = flags
        .critical_log_dir
        .as_ref()
        .map(|p| get_expanded_path(p).expect("Invalid critical log directory path"));
    let _critical_log_guard = crate::telemetry::init(log_level, critical_log_dir.as_deref());

    // Start prometheus endpoint (merges Summit + commonware runtime metrics)
    #[cfg(feature = "prom")]
    {
        use crate::prom::hooks::Hooks;
        use crate::prom::server::{MetricServer, MetricServerConfig};
        use std::net::SocketAddr;

        let hooks = Hooks::builder().build();

        let listen_addr = format!("{}:{}", flags.prom_ip, flags.prom_port)
            .parse::<SocketAddr>()
            .unwrap();
        let config = MetricServerConfig::new(listen_addr, hooks, Some(context.clone()));
        let stop_signal = context.stopped();
        MetricServer::new(config).serve(stop_signal).await.unwrap();
    }

    // configure network
    let network_committee_ingress: Vec<_> =
        if let Some(ref bootstrappers_path) = flags.bootstrappers {
            Bootstrappers::load_from_file(bootstrappers_path)
                .expect("Failed to load bootstrappers file")
                .to_ingress_list()
                .expect("Failed to parse bootstrappers")
        } else {
            network_committee
                .iter()
                .map(|(pk, addr)| (pk.clone(), Ingress::from(*addr)))
                .collect()
        };

    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port);
    let namespace = genesis.namespace.as_bytes();
    let max_message_size = genesis.max_message_size_bytes as u32;

    let (engine, p2p, rpc_handle) = if let Some(index) = flags.observer {
        let signer = ExtPrivateKey::derive_child_signer(&key_store.node_key, index);
        let mut p2p_cfg = authenticated::discovery::Config::recommended(
            signer,
            namespace,
            listen,
            our_ip,
            network_committee_ingress,
            max_message_size,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;
        start_network_and_engine(
            context.clone(),
            p2p_cfg,
            engine_client,
            key_store,
            peers,
            flags,
            &genesis,
            initial_state,
            loaded.last_block,
            loaded.finalized_header,
        )
        .await
    } else {
        let signer = key_store.node_key.clone();
        let mut p2p_cfg = authenticated::discovery::Config::recommended(
            signer,
            namespace,
            listen,
            our_ip,
            network_committee_ingress,
            max_message_size,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;
        start_network_and_engine(
            context.clone(),
            p2p_cfg,
            engine_client,
            key_store,
            peers,
            flags,
            &genesis,
            initial_state,
            loaded.last_block,
            loaded.finalized_header,
        )
        .await
    };

    // Wait for any task to error
    if let Err(e) = try_join_all(vec![p2p, engine, rpc_handle]).await {
        error!(?e, "task failed");
    }
}

pub fn run_node_local(
    context: tokio::Context,
    flags: RunFlags,
    checkpoint: Option<ConsensusState>,
    checkpoint_parent_block: Option<Block>,
) -> Handle<()> {
    context.spawn(async move |context| {
        let key_store = expect_key_store(&flags.key_store_path);
        run_node_local_inner(
            context,
            flags,
            key_store,
            checkpoint,
            checkpoint_parent_block,
        )
        .await;
    })
}

async fn run_node_local_inner(
    context: tokio::Context,
    flags: RunFlags,
    key_store: KeyStore<PrivateKey>,
    checkpoint: Option<ConsensusState>,
    checkpoint_parent_block: Option<Block>,
) {
    let context = context.with_label("summit_cw");

    let (genesis_tx, genesis_rx) = oneshot::channel();

    let cancel_token = CancellationToken::new();
    let cloned_token = cancel_token.clone();
    let genesis_rpc_port = flags.rpc_port;
    let genesis_path = flags.genesis_path.clone();
    let genesis_key_store_path = flags.key_store_path.clone();
    let _rpc_handle = context
        .with_label("rpc_genesis")
        .spawn(move |_context| async move {
            let genesis_sender = Command::check_sender(genesis_path, genesis_tx);
            if let Err(e) = start_rpc_server_for_genesis(
                genesis_sender,
                genesis_key_store_path,
                genesis_rpc_port,
                cloned_token,
            )
            .await
            {
                error!("RPC server failed: {}", e);
            }
        });

    // Wait for genesis if needed
    let _ = genesis_rx.await;
    // Shut down the genesis rpc server after receiving the genesis file
    cancel_token.cancel();

    let genesis = Genesis::load_from_file(&flags.genesis_path).expect("Can not find genesis file");

    let mut committee: Vec<Validator> = genesis.get_validators().expect("Failed to get validators");
    committee.sort_by(|lhs, rhs| lhs.node_public_key.cmp(&rhs.node_public_key));

    let initial_state = get_initial_state(&genesis, &committee, checkpoint);
    let peers = initial_state.get_validator_keys();

    let engine_ipc_path =
        get_expanded_path(&flags.engine_ipc_path).expect("failed to expand engine ipc path");

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

    #[cfg(feature = "bad-blocks")]
    let engine_client =
        BadBlockEngineClient::new(engine_ipc_path.to_string_lossy().to_string(), 4).await;

    #[cfg(all(not(feature = "bench"), not(feature = "bad-blocks")))]
    let engine_client = RethEngineClient::new(engine_ipc_path.to_string_lossy().to_string()).await;

    let our_ip = get_node_ip(&flags, &key_store, &committee).await;

    let mut network_committee: Vec<(PublicKey, SocketAddr)> = committee
        .into_iter()
        .map(|v| (v.node_public_key, v.ip_address))
        .collect();
    let our_public_key = key_store.node_key.public_key();
    if !network_committee
        .iter()
        .any(|(key, _)| key == &our_public_key)
    {
        network_committee.push((our_public_key, our_ip));
        network_committee.sort();
    }

    // configure network
    let network_committee_ingress: Vec<_> =
        if let Some(ref bootstrappers_path) = flags.bootstrappers {
            Bootstrappers::load_from_file(bootstrappers_path)
                .expect("Failed to load bootstrappers file")
                .to_ingress_list()
                .expect("Failed to parse bootstrappers")
        } else {
            network_committee
                .iter()
                .map(|(pk, addr)| (pk.clone(), Ingress::from(*addr)))
                .collect()
        };

    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flags.port);
    let namespace = genesis.namespace.as_bytes();
    let max_message_size = genesis.max_message_size_bytes as u32;

    let (engine, p2p, rpc_handle) = if let Some(index) = flags.observer {
        let signer = ExtPrivateKey::derive_child_signer(&key_store.node_key, index);
        let mut p2p_cfg = authenticated::discovery::Config::local(
            signer,
            namespace,
            listen,
            our_ip,
            network_committee_ingress,
            max_message_size,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;
        start_network_and_engine(
            context.clone(),
            p2p_cfg,
            engine_client,
            key_store,
            peers,
            flags.clone(),
            &genesis,
            initial_state,
            checkpoint_parent_block,
            None,
        )
        .await
    } else {
        let signer = key_store.node_key.clone();
        let mut p2p_cfg = authenticated::discovery::Config::local(
            signer,
            namespace,
            listen,
            our_ip,
            network_committee_ingress,
            max_message_size,
        );
        p2p_cfg.mailbox_size = MAILBOX_SIZE;
        start_network_and_engine(
            context.clone(),
            p2p_cfg,
            engine_client,
            key_store,
            peers,
            flags.clone(),
            &genesis,
            initial_state,
            checkpoint_parent_block,
            None,
        )
        .await
    };

    // Start prometheus endpoint
    #[cfg(feature = "prom")]
    {
        use crate::prom::hooks::Hooks;
        use crate::prom::server::{MetricServer, MetricServerConfig};
        use std::net::SocketAddr;

        let hooks = Hooks::builder().build();

        let listen_addr = format!("{}:{}", flags.prom_ip, flags.prom_port)
            .parse::<SocketAddr>()
            .unwrap();
        let stop_signal = context.stopped();
        let config = MetricServerConfig::new(listen_addr, hooks, Some(context.clone()));
        MetricServer::new(config).serve(stop_signal).await.unwrap();
    }

    // Wait for any task to error
    if let Err(e) = try_join_all(vec![p2p, engine, rpc_handle]).await {
        error!(?e, "task failed");
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_network_and_engine<S, EC>(
    context: tokio::Context,
    p2p_cfg: authenticated::discovery::Config<S>,
    engine_client: EC,
    key_store: KeyStore<PrivateKey>,
    peers: Vec<(PublicKey, bls12381::PublicKey)>,
    flags: RunFlags,
    genesis: &Genesis,
    initial_state: ConsensusState,
    checkpoint_last_block: Option<Block>,
    checkpoint_finalized_header: Option<FinalizedHeader<MultisigScheme>>,
) -> (Handle<()>, Handle<()>, Handle<()>)
where
    S: Signer<PublicKey = PublicKey>,
    EC: EngineClient,
{
    let (mut network, oracle) =
        authenticated::discovery::Network::new(context.with_label("network"), p2p_cfg);

    let oracle = DiscoveryOracle::new(oracle);
    let config = EngineConfig::get_engine_config(
        engine_client,
        oracle,
        key_store,
        peers,
        flags.db_prefix,
        genesis,
        initial_state,
        checkpoint_last_block,
        checkpoint_finalized_header,
        flags.finalizer_pending_notarized_max,
    )
    .unwrap();

    let pending_limit = Quota::per_second(NonZeroU32::new(512).unwrap());
    let pending = network.register(PENDING_CHANNEL, pending_limit, MESSAGE_BACKLOG);

    let recovered_limit = Quota::per_second(NonZeroU32::new(512).unwrap());
    let recovered = network.register(RECOVERED_CHANNEL, recovered_limit, MESSAGE_BACKLOG);

    let resolver_limit = Quota::per_second(NonZeroU32::new(512).unwrap());
    let resolver = network.register(RESOLVER_CHANNEL, resolver_limit, MESSAGE_BACKLOG);

    let broadcaster_limit = Quota::per_second(NonZeroU32::new(512).unwrap());
    let broadcaster = network.register(BROADCASTER_CHANNEL, broadcaster_limit, MESSAGE_BACKLOG);

    let backfiller = network.register(BACKFILLER_CHANNEL, config.backfill_quota, MESSAGE_BACKLOG);

    let engine: Engine<_, _, _, _> = Engine::new(context.with_label("engine"), config).await;
    #[cfg(feature = "permissioned")]
    let paused = engine.paused.clone();

    let finalizer_mailbox = engine.finalizer_mailbox.clone();
    let engine = engine.start(pending, recovered, resolver, broadcaster, backfiller);

    let p2p = network.start();

    // Start RPC server
    let key_store_path = flags.key_store_path;
    let rpc_port = flags.rpc_port;
    let admin_rpc_port = flags.admin_rpc_port;
    let stop_signal = context.stopped();
    let rpc_handle = context.with_label("rpc").spawn(move |_context| async move {
        if let Err(e) = start_rpc_server(
            finalizer_mailbox,
            key_store_path,
            rpc_port,
            admin_rpc_port,
            stop_signal,
            #[cfg(feature = "permissioned")]
            paused,
        )
        .await
        {
            error!("RPC server failed: {}", e);
        }
    });
    (engine, p2p, rpc_handle)
}

fn get_initial_state(
    genesis: &Genesis,
    genesis_committee: &Vec<Validator>,
    checkpoint: Option<ConsensusState>,
) -> ConsensusState {
    let epoch_length =
        NonZeroU64::new(genesis.blocks_per_epoch).expect("blocks_per_epoch must be nonzero");
    let genesis_hash: [u8; 32] = from_hex_formatted(&genesis.eth_genesis_hash)
        .map(|hash_bytes| hash_bytes.try_into())
        .expect("bad eth_genesis_hash")
        .expect("bad eth_genesis_hash");
    let treasury_address = genesis
        .treasury_address
        .parse::<Address>()
        .expect("invalid treasury_address");
    let genesis_hash: B256 = genesis_hash.into();
    checkpoint.unwrap_or_else(|| {
        let forkchoice = ForkchoiceState {
            head_block_hash: genesis_hash,
            safe_block_hash: genesis_hash,
            finalized_block_hash: genesis_hash,
        };
        let mut state = ConsensusState::new(
            forkchoice,
            genesis.validator_minimum_stake,
            genesis.validator_maximum_stake,
            epoch_length,
            genesis.allowed_timestamp_future_ms,
            treasury_address,
            genesis.max_deposits_per_epoch,
            genesis.max_withdrawals_per_epoch,
            genesis.observers_per_validator,
        );
        // Add the genesis nodes to the consensus state with the minimum stake balance.
        for validator in genesis_committee {
            let pubkey_bytes: [u8; 32] = validator
                .node_public_key
                .as_ref()
                .try_into()
                .expect("Public key must be 32 bytes");
            let account = ValidatorAccount {
                consensus_public_key: validator.consensus_public_key.clone(),
                withdrawal_credentials: validator.withdrawal_credentials,
                balance: genesis.validator_minimum_stake,
                status: ValidatorStatus::Active,
                has_pending_deposit: false,
                has_pending_withdrawal: false,
                joining_epoch: 0,
                // This index comes from the deposit contract.
                // Since there is no deposit transaction for the genesis nodes, the index will still be
                // 0 for the deposit contract. Right now we only use this index to avoid counting the same deposit request twice.
                // Since we set the index to 0 here, we cannot rely on the uniqueness. The first actual deposit request will have
                // index 0 as well.
                last_deposit_index: 0,
            };
            state.set_account(pubkey_bytes, account);
        }
        state
    })
}

async fn get_node_ip(
    flags: &RunFlags,
    key_store: &KeyStore<PrivateKey>,
    committee: &[Validator],
) -> SocketAddr {
    if let Some(ref ip_str) = flags.ip {
        ip_str
            .parse::<SocketAddr>()
            .expect("Invalid IP address format")
    } else if let Some(addr) = committee.iter().find_map(|v| {
        if v.node_public_key == key_store.node_key.public_key() {
            Some(v.ip_address)
        } else {
            None
        }
    }) {
        addr
    } else {
        info!("node not on committee, resolving external IP");
        let ip = crate::nat::resolve_external_ip()
            .await
            .expect("failed to resolve external IP: not on committee and all IP services failed");
        SocketAddr::new(ip, flags.port)
    }
}

struct LoadedCheckpoint<S: Scheme> {
    consensus_state: Option<ConsensusState>,
    last_block: Option<Block>,
    finalized_header: Option<FinalizedHeader<S>>,
    raw_checkpoint: Option<Checkpoint>,
    finalized_headers_chain: Option<Vec<FinalizedHeader<S>>>,
}

fn read_checkpoint<S: Scheme>(
    checkpoint_path: &String,
    checkpoint_or_default: bool,
) -> LoadedCheckpoint<S>
where
    <S::Certificate as Read>::Cfg: From<usize>,
{
    let path = Path::new(&checkpoint_path);

    if path.is_file() {
        // Only a checkpoint file
        let checkpoint_bytes = std::fs::read(path).expect("failed to read checkpoint from disk");
        let checkpoint =
            Checkpoint::from_ssz_bytes(&checkpoint_bytes).expect("failed to parse checkpoint");

        let consensus_state = ConsensusState::try_from(&checkpoint)
            .expect("failed to create consensus state from checkpoint");

        info!(
            epoch = consensus_state.get_epoch(),
            height = consensus_state.get_latest_height(),
            num_validators = consensus_state.num_validators(),
            checkpoint_path = %path.display(),
            "loaded checkpoint from file"
        );

        LoadedCheckpoint {
            consensus_state: Some(consensus_state),
            last_block: None,
            finalized_header: None,
            raw_checkpoint: Some(checkpoint),
            finalized_headers_chain: None,
        }
    } else if path.is_dir() {
        let checkpoint_file_path = path.join("checkpoint");
        let last_block_path = path.join("last_block");
        let header_path = path.join("finalized_header");

        let (consensus_state, raw_checkpoint) = {
            let checkpoint_bytes =
                std::fs::read(checkpoint_file_path).expect("failed to read checkpoint from disk");

            let checkpoint =
                Checkpoint::from_ssz_bytes(&checkpoint_bytes).expect("failed to parse checkpoint");

            let consensus_state = ConsensusState::try_from(&checkpoint)
                .expect("failed to create consensus state from checkpoint");

            (Some(consensus_state), Some(checkpoint))
        };

        let last_block = std::fs::read(last_block_path)
            .map(|bytes| Block::from_ssz_bytes(&bytes).ok())
            .ok()
            .flatten();

        let header = std::fs::read(header_path)
            .map(|bytes| FinalizedHeader::<S>::from_ssz_bytes(&bytes).ok())
            .ok()
            .flatten();

        // Load finalized headers chain for verification if present
        let finalized_headers_dir = path.join("finalized_headers");
        let finalized_headers_chain = if finalized_headers_dir.is_dir() {
            let mut headers = Vec::new();
            let mut epoch = 0u64;
            loop {
                let header_file = finalized_headers_dir.join(epoch.to_string());
                if !header_file.exists() {
                    break;
                }
                let header_bytes = std::fs::read(&header_file).unwrap_or_else(|e| {
                    panic!("failed to read finalized header for epoch {epoch}: {e}")
                });
                let h = FinalizedHeader::<S>::from_ssz_bytes(&header_bytes).unwrap_or_else(|e| {
                    panic!("failed to parse finalized header for epoch {epoch}: {e:?}")
                });
                headers.push(h);
                epoch += 1;
            }
            if headers.is_empty() {
                None
            } else {
                info!(
                    num_headers = headers.len(),
                    "loaded finalized headers chain for checkpoint verification"
                );
                Some(headers)
            }
        } else {
            None
        };

        if let Some(ref state) = consensus_state {
            info!(
                epoch = state.get_epoch(),
                height = state.get_latest_height(),
                num_validators = state.num_validators(),
                has_last_block = last_block.is_some(),
                has_finalized_header = header.is_some(),
                has_verification_headers = finalized_headers_chain.is_some(),
                checkpoint_dir = %path.display(),
                "loaded checkpoint from directory"
            );
        }

        LoadedCheckpoint {
            consensus_state,
            last_block,
            finalized_header: header,
            raw_checkpoint,
            finalized_headers_chain,
        }
    } else if checkpoint_or_default {
        LoadedCheckpoint {
            consensus_state: None,
            last_block: None,
            finalized_header: None,
            raw_checkpoint: None,
            finalized_headers_chain: None,
        }
    } else {
        panic!("Could not find checkpoint");
    }
}
