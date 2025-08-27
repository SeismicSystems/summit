use crate::config::EngineConfig;
use commonware_broadcast::buffered;
use commonware_consensus::marshal;
use commonware_consensus::threshold_simplex::{self, Engine as Simplex};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{poly::public, variant::MinPk},
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_utils::{NZU64, NZUsize};
use futures::future::try_join_all;
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use std::num::NonZero;
use summit_application::ApplicationConfig;
use summit_application::engine_client::EngineClient;
use summit_application::finalizer::FinalizerMailbox;
use summit_application::registry::Registry;
use summit_types::{Block, Digest, PrivateKey, PublicKey};
use tracing::{error, warn};

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024);
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

// Marshal config
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_INITIAL_SIZE: u32 = 65_536; // todo(dalton): Check this default
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const MAX_REPAIR: u64 = 20;

const BUFFER_POOL_PAGE_SIZE: NonZero<usize> = NZUsize!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
//

// Onboarding config (set arbitrarily for now)

#[cfg(debug_assertions)]
const VALIDATOR_ONBOARDING_INTERVAL: u64 = 1;
#[cfg(not(debug_assertions))]
const VALIDATOR_ONBOARDING_INTERVAL: u64 = 10;
const VALIDATOR_ONBOARDING_LIMIT_PER_BLOCK: usize = 3;
pub const VALIDATOR_MINIMUM_STAKE: u64 = 32_000_000_000; // in gwei

#[cfg(debug_assertions)]
pub const VALIDATOR_WITHDRAWAL_PERIOD: u64 = 5;
#[cfg(not(debug_assertions))]
const VALIDATOR_WITHDRAWAL_PERIOD: u64 = 100;
const VALIDATOR_MAX_WITHDRAWALS_PER_BLOCK: usize = 16;
//

pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    C: EngineClient,
> {
    context: E,
    application: summit_application::Actor<E, C>,
    buffer: buffered::Engine<E, PublicKey, Block>,
    buffer_mailbox: buffered::Mailbox<PublicKey, Block>,
    marshal: marshal::Actor<Block, E, MinPk, PublicKey, Registry>,
    marshal_mailbox: marshal::Mailbox<MinPk, Block>,
    finalizer_mailbox: FinalizerMailbox,

    simplex: Simplex<
        E,
        PrivateKey,
        B,
        MinPk,
        Digest,
        summit_application::Mailbox,
        summit_application::Mailbox,
        marshal::Mailbox<MinPk, Block>,
        Registry,
    >,
}

impl<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    C: EngineClient,
> Engine<E, B, C>
{
    pub async fn new(context: E, cfg: EngineConfig<C>, blocker: B) -> Self {
        let identity = *public::<MinPk>(&cfg.polynomial);
        let registry = Registry::new(cfg.participants, cfg.polynomial, cfg.share);
        // create application
        let (application, application_mailbox, finalizer_mailbox) = summit_application::Actor::new(
            context.with_label("application"),
            ApplicationConfig {
                engine_client: cfg.engine_client,
                registry: registry.clone(),
                mailbox_size: cfg.mailbox_size,
                partition_prefix: cfg.partition_prefix.clone(),
                genesis_hash: cfg.genesis_hash,
                validator_onboarding_interval: VALIDATOR_ONBOARDING_INTERVAL,
                validator_onboarding_limit_per_block: VALIDATOR_ONBOARDING_LIMIT_PER_BLOCK,
                validator_minimum_stake: VALIDATOR_MINIMUM_STAKE,
                validator_withdrawal_period: VALIDATOR_WITHDRAWAL_PERIOD,
                validator_max_withdrawals_per_block: VALIDATOR_MAX_WITHDRAWALS_PER_BLOCK,
            },
        )
        .await;

        // create the buffer
        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config {
                public_key: cfg.signer.public_key(),
                mailbox_size: cfg.mailbox_size,
                deque_size: cfg.deque_size,
                priority: true,
                codec_config: (),
            },
        );

        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        let (marshal, marshal_mailbox): (_, marshal::Mailbox<MinPk, Block>) = marshal::Actor::init(
            context.with_label("marshal"),
            marshal::Config {
                public_key: cfg.signer.public_key(),
                identity,
                coordinator: registry.clone(),
                partition_prefix: cfg.partition_prefix.clone(),
                mailbox_size: cfg.mailbox_size,
                backfill_quota: cfg.backfill_quota,
                view_retention_timeout: cfg
                    .activity_timeout
                    .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                namespace: cfg.namespace.as_bytes().to_vec(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                immutable_items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                freezer_table_initial_size: FREEZER_INITIAL_SIZE,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                codec_config: (),
                max_repair: MAX_REPAIR,
            },
        )
        .await;

        // create simplex
        let simplex = Simplex::new(
            context.with_label("simplex"),
            threshold_simplex::Config {
                blocker,
                crypto: cfg.signer,
                automaton: application_mailbox.clone(),
                relay: application_mailbox.clone(),
                reporter: marshal_mailbox.clone(),
                supervisor: registry,
                partition: format!("{}-summit", cfg.partition_prefix),
                compression: None,
                mailbox_size: cfg.mailbox_size,
                namespace: cfg.namespace.clone().as_bytes().to_vec(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,
                fetch_concurrent: cfg.fetch_concurrent,
                buffer_pool,
            },
        );

        Self {
            context,
            application,
            buffer,
            buffer_mailbox,
            simplex,
            marshal,
            marshal_mailbox,
            finalizer_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        self,
        pending_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        backfill_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        self.context.clone().spawn(|_| {
            self.run(
                pending_network,
                recovered_network,
                resolver_network,
                broadcast_network,
                backfill_network,
            )
        })
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    async fn run(
        self,
        pending_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        backfill_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        // start the application
        let app_handle = self.application.start(self.marshal_mailbox);
        // start the buffer
        let buffer_handle = self.buffer.start(broadcast_network);
        // start marshal
        let marshal_handle = self.marshal.start(
            self.finalizer_mailbox,
            self.buffer_mailbox,
            backfill_network,
        );
        // start simplex
        let simplex_handle =
            self.simplex
                .start(pending_network, recovered_network, resolver_network);

        // Wait for any actor to finish
        if let Err(e) = try_join_all(vec![
            app_handle,
            buffer_handle,
            marshal_handle,
            simplex_handle,
        ])
        .await
        {
            error!(?e, "engine failed");
        } else {
            warn!("engine stopped");
        }
    }
}
