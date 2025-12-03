use crate::config::EngineConfig;
use commonware_broadcast::buffered;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_consensus::types::ViewDelta;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::primitives::group;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_p2p::{Blocker, Manager, Receiver, Sender, utils::requester};
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Clock, Handle, Metrics, Network, Spawner, Storage};
use commonware_storage::archive::immutable;
use commonware_utils::acknowledgement::Exact;
use commonware_utils::{NZU64, NZUsize};
use futures::FutureExt;
use futures::future::try_join_all;
use governor::{Quota, clock::Clock as GClock};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use std::num::{NonZero, NonZeroU32};
use std::time::Duration;
use summit_application::ApplicationConfig;
use summit_finalizer::actor::Finalizer;
use summit_finalizer::{FinalizerConfig, FinalizerMailbox};
use summit_types::network_oracle::NetworkOracle;
use summit_types::scheme::{MultisigScheme, SummitSchemeProvider};
use summit_types::{Block, EngineClient, PublicKey};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::ZeroizeOnDrop;

pub const PROTOCOL_VERSION: u32 = 1;

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024);
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

const BUFFER_POOL_PAGE_SIZE: NonZero<usize> = NZUsize!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const FREEZER_TABLE_INITIAL_SIZE: u32 = 1024 * 1024; // 100mb
const MAX_REPAIR: NonZero<usize> = NZUsize!(10);

//
// Onboarding config (set arbitrarily for now)

const VALIDATOR_ONBOARDING_LIMIT_PER_BLOCK: usize = 3;
pub const VALIDATOR_MINIMUM_STAKE: u64 = 32_000_000_000; // in gwei

#[cfg(feature = "e2e")]
pub const VALIDATOR_WITHDRAWAL_PERIOD: u64 = 10;
#[cfg(all(debug_assertions, not(feature = "e2e")))]
pub const VALIDATOR_WITHDRAWAL_PERIOD: u64 = 5;
#[cfg(all(not(debug_assertions), not(feature = "e2e")))]
const VALIDATOR_WITHDRAWAL_PERIOD: u64 = 100;
#[cfg(all(feature = "e2e", not(debug_assertions)))]
pub const BLOCKS_PER_EPOCH: u64 = 50;
#[cfg(debug_assertions)]
pub const BLOCKS_PER_EPOCH: u64 = 10;
#[cfg(all(not(debug_assertions), not(feature = "e2e")))]
const BLOCKS_PER_EPOCH: u64 = 10000;
const VALIDATOR_MAX_WITHDRAWALS_PER_BLOCK: usize = 16;
//

pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics + Network,
    C: EngineClient,
    O: NetworkOracle<PublicKey> + Blocker<PublicKey = S::PublicKey> + Manager<PublicKey = PublicKey>,
    S: Signer<PublicKey = PublicKey>,
> {
    context: E,
    application: summit_application::Actor<E, C, MultisigScheme<S, MinPk>, S::PublicKey, S, MinPk>,
    buffer: buffered::Engine<E, S::PublicKey, Block<S, MinPk>>,
    buffer_mailbox: buffered::Mailbox<S::PublicKey, Block<S, MinPk>>,
    #[allow(clippy::type_complexity)]
    syncer: summit_syncer::Actor<
        E,
        Block<S, MinPk>,
        SummitSchemeProvider<S, MinPk>,
        MultisigScheme<S, MinPk>,
        immutable::Archive<
            E,
            summit_types::Digest,
            commonware_consensus::simplex::types::Finalization<
                MultisigScheme<S, MinPk>,
                summit_types::Digest,
            >,
        >,
        immutable::Archive<E, summit_types::Digest, Block<S, MinPk>>,
        Exact,
    >,
    syncer_mailbox: summit_syncer::Mailbox<MultisigScheme<S, MinPk>, Block<S, MinPk>>,
    finalizer: Finalizer<E, C, O, S, MinPk>,
    pub finalizer_mailbox: FinalizerMailbox<MultisigScheme<S, MinPk>, Block<S, MinPk>>,
    orchestrator:
        summit_orchestrator::Actor<E, O, MinPk, S, summit_application::Mailbox<S::PublicKey>>,
    oracle: O,
    node_public_key: PublicKey,
    mailbox_size: usize,
    sync_height: u64,
    sync_epoch: u64,
    sync_view: u64,
    cancellation_token: CancellationToken,
}

impl<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics + Network,
    C: EngineClient,
    O: NetworkOracle<PublicKey> + Blocker<PublicKey = S::PublicKey> + Manager<PublicKey = PublicKey>,
    S: Signer<PublicKey = PublicKey> + ZeroizeOnDrop,
> Engine<E, C, O, S>
where
    MultisigScheme<S, MinPk>: Scheme<PublicKey = S::PublicKey>,
{
    pub async fn new(context: E, cfg: EngineConfig<C, S, O>) -> Self {
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        let encoded = cfg.key_store.consensus_key.encode();
        let private_scalar = group::Private::decode(&mut encoded.as_ref())
            .expect("failed to extract scalar from private key");
        let scheme_provider: SummitSchemeProvider<S, MinPk> =
            SummitSchemeProvider::new(private_scalar);

        let cancellation_token = CancellationToken::new();

        // create application
        let (application, application_mailbox) = summit_application::Actor::new(
            context.with_label("application"),
            ApplicationConfig {
                engine_client: cfg.engine_client.clone(),
                mailbox_size: cfg.mailbox_size,
                partition_prefix: cfg.partition_prefix.clone(),
                genesis_hash: cfg.genesis_hash,
                cancellation_token: cancellation_token.clone(),
            },
        )
        .await;

        // create the buffer
        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config {
                public_key: cfg.key_store.node_key.public_key(),
                mailbox_size: cfg.mailbox_size,
                deque_size: cfg.deque_size,
                priority: true,
                codec_config: (),
            },
        );

        // create the syncer
        // Initialize finalizations by height archive
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    cfg.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    cfg.partition_prefix
                ),
                freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalizations-by-height-freezer-journal",
                    cfg.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    cfg.partition_prefix
                ),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: MultisigScheme::<S, MinPk>::certificate_codec_config_unbounded(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        // Initialize finalized blocks archive
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", cfg.partition_prefix),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    cfg.partition_prefix
                ),
                freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalized_blocks-freezer-journal",
                    cfg.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", cfg.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: (),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let syncer_config = summit_syncer::Config {
            scheme_provider: scheme_provider.clone(),
            epoch_length: BLOCKS_PER_EPOCH,
            partition_prefix: cfg.partition_prefix.clone(),
            mailbox_size: cfg.mailbox_size,
            view_retention_timeout: ViewDelta::new(cfg.activity_timeout),
            namespace: cfg.namespace.as_bytes().to_vec(),
            prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
            buffer_pool: buffer_pool.clone(),
            replay_buffer: REPLAY_BUFFER,
            write_buffer: WRITE_BUFFER,
            block_codec_config: (),
            max_repair: MAX_REPAIR,
            _marker: PhantomData,
        };

        let (syncer, syncer_mailbox) = summit_syncer::Actor::init(
            context.with_label("syncer"),
            finalizations_by_height,
            finalized_blocks,
            syncer_config,
        )
        .await;

        // create orchestrator
        let (orchestrator, orchestrator_mailbox) = summit_orchestrator::Actor::new(
            context.with_label("orchestrator"),
            summit_orchestrator::Config {
                oracle: cfg.oracle.clone(),
                application: application_mailbox.clone(),
                scheme_provider: scheme_provider.clone(),
                syncer_mailbox: syncer_mailbox.clone(),
                namespace: cfg.namespace.as_bytes().to_vec(),
                muxer_size: cfg.mailbox_size,
                mailbox_size: cfg.mailbox_size,
                rate_limit: cfg.fetch_rate_per_peer,
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                partition_prefix: cfg.partition_prefix.clone(),
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                fetch_timeout: cfg.fetch_timeout,
                activity_timeout: ViewDelta::new(cfg.activity_timeout),
                skip_timeout: ViewDelta::new(cfg.skip_timeout),
            },
        );

        // create finalizer
        let (finalizer, initial_state, finalizer_mailbox) = Finalizer::new(
            context.with_label("finalizer"),
            FinalizerConfig {
                mailbox_size: cfg.mailbox_size,
                db_prefix: cfg.partition_prefix.clone(),
                engine_client: cfg.engine_client,
                oracle: cfg.oracle.clone(),
                orchestrator_mailbox,
                epoch_num_of_blocks: BLOCKS_PER_EPOCH,
                validator_max_withdrawals_per_block: VALIDATOR_MAX_WITHDRAWALS_PER_BLOCK,
                validator_minimum_stake: VALIDATOR_MINIMUM_STAKE,
                validator_withdrawal_period: VALIDATOR_WITHDRAWAL_PERIOD,
                validator_onboarding_limit_per_block: VALIDATOR_ONBOARDING_LIMIT_PER_BLOCK,
                buffer_pool: buffer_pool.clone(),
                genesis_hash: cfg.genesis_hash,
                initial_state: cfg.initial_state,
                protocol_version: PROTOCOL_VERSION,
                node_public_key: cfg.key_store.node_key.public_key().clone(),
                cancellation_token: cancellation_token.clone(),
                _variant_marker: PhantomData,
            },
        )
        .await;
        // Initialize the sync variables from the consensus state returned by the finalizer.
        // This covers the case where the finalizer reads the consensus state from disk.
        let sync_height = initial_state.latest_height;
        let sync_epoch = initial_state.epoch;
        let sync_view = initial_state.view;

        Self {
            context,
            application,
            buffer,
            buffer_mailbox,
            syncer,
            syncer_mailbox,
            finalizer,
            finalizer_mailbox,
            orchestrator,
            oracle: cfg.oracle,
            node_public_key: cfg.key_store.node_key.public_key(),
            mailbox_size: cfg.mailbox_size,
            sync_height,
            sync_epoch,
            sync_view,
            cancellation_token,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        self,
        pending_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        orchestrator_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        broadcast_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
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
                orchestrator_network,
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
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        orchestrator_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        broadcast_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        backfill_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        // start the application
        let app_handle = self
            .application
            .start(self.syncer_mailbox, self.finalizer_mailbox.clone());
        // start the buffer
        let buffer_handle = self.buffer.start(broadcast_network);

        // Initialize resolver for backfill
        let resolver_config = summit_syncer::resolver::p2p::Config {
            public_key: self.node_public_key.clone(),
            manager: self.oracle.clone(),
            blocker: self.oracle.clone(),
            mailbox_size: self.mailbox_size,
            requester_config: requester::Config {
                me: Some(self.node_public_key.clone()),
                rate_limit: Quota::per_second(NonZeroU32::new(5).unwrap()),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let (resolver_rx, resolver) =
            summit_syncer::resolver::p2p::init(&self.context, resolver_config, backfill_network);

        let finalizer_handle = self.finalizer.start();
        // start the syncer
        let syncer_handle = self.syncer.start(
            self.finalizer_mailbox.clone(),
            self.buffer_mailbox.clone(),
            (resolver_rx, resolver),
            self.sync_height,
            self.sync_epoch,
            self.sync_view,
        );
        // start the orchestrator
        let orchestrator_handle = self.orchestrator.start(
            pending_network,
            recovered_network,
            resolver_network,
            orchestrator_network,
        );

        // Wait for either all actors to finish or cancellation signal
        let actors_fut = try_join_all(vec![
            app_handle,
            buffer_handle,
            finalizer_handle,
            syncer_handle,
            orchestrator_handle,
        ])
        .fuse();
        let cancellation_fut = self.cancellation_token.cancelled().fuse();
        futures::pin_mut!(actors_fut, cancellation_fut);

        futures::select! {
            result = actors_fut => {
                if let Err(e) = result {
                    error!(?e, "engine failed");
                } else {
                    warn!("engine stopped");
                }
            }
            _ = cancellation_fut => {
                info!("cancellation triggered, waiting for actors to finish");
                if let Err(e) = actors_fut.await {
                    error!(?e, "engine failed during graceful shutdown");
                }
            }
        }
    }
}
