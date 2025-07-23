use commonware_broadcast::buffered;
use commonware_consensus::simplex::{self, Engine as Simplex};
use commonware_cryptography::Signer as _;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use futures::{channel::mpsc, future::try_join_all};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use seismicbft_application::ApplicationConfig;
use seismicbft_syncer::Orchestrator;
use seismicbft_types::{Block, Digest, NAMESPACE, PrivateKey, PublicKey};
use tracing::{error, warn};

use crate::config::EngineConfig;

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const REPLAY_BUFFER: usize = 8 * 1024 * 1024;
const WRITE_BUFFER: usize = 1024 * 1024;
// todo: explore implications of this with simplex
const MAX_PARTICIPANTS: usize = 10_000;

pub struct Engine<E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics> {
    context: E,
    application: seismicbft_application::Actor<E>,
    buffer: buffered::Engine<E, PublicKey, Block>,
    buffer_mailbox: buffered::Mailbox<PublicKey, Block>,
    syncer: seismicbft_syncer::Actor<E>,
    orchestrator: Orchestrator,
    syncer_mailbox: seismicbft_syncer::Mailbox,
    simplex: Simplex<
        E,
        PrivateKey,
        Digest,
        seismicbft_application::Mailbox,
        seismicbft_application::Mailbox,
        seismicbft_syncer::Mailbox,
        seismicbft_application::Supervisor,
    >,
}

impl<E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics> Engine<E> {
    pub async fn new(context: E, cfg: EngineConfig) -> Self {
        // create application
        let (application, application_mailbox, supervisor) = seismicbft_application::Actor::new(
            context.with_label("application"),
            ApplicationConfig {
                participants: cfg.participants.clone(),
                mailbox_size: cfg.mailbox_size,
                engine_url: cfg.engine_url,
                engine_jwt: cfg.engine_jwt,
                partition_prefix: cfg.partition_prefix.clone(),
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

        // create the syncer
        let syncer_config = seismicbft_syncer::Config {
            partition_prefix: cfg.partition_prefix.clone(),
            public_key: cfg.signer.public_key(),
            participants: cfg.participants,
            mailbox_size: cfg.mailbox_size,
            backfill_quota: cfg.backfill_quota,
            activity_timeout: cfg.activity_timeout,
            indexer: cfg.indexer_url,
        };
        let (syncer, syncer_mailbox, orchestrator) =
            seismicbft_syncer::Actor::new(context.with_label("syncer"), syncer_config).await;

        // create simplex
        let simplex = Simplex::new(
            context.with_label("simplex"),
            simplex::Config {
                crypto: cfg.signer,
                automaton: application_mailbox.clone(),
                relay: application_mailbox.clone(),
                reporter: syncer_mailbox.clone(),
                supervisor,
                partition: format!("{}-seismicbft", cfg.partition_prefix),
                compression: None,
                mailbox_size: cfg.mailbox_size,
                namespace: NAMESPACE.to_vec(),
                replay_concurrency: 1,
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                activity_timeout: cfg.activity_timeout,
                max_participants: MAX_PARTICIPANTS,
                skip_timeout: cfg.skip_timeout,
                fetch_timeout: cfg.fetch_timeout,
                max_fetch_count: cfg.max_fetch_count,
                fetch_rate_per_peer: cfg.fetch_rate_per_peer,
                fetch_concurrent: cfg.fetch_concurrent,
            },
        );

        Self {
            context,
            application,
            buffer,
            buffer_mailbox,
            syncer,
            syncer_mailbox,
            orchestrator,
            simplex,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    pub fn start(
        self,
        voter_network: (
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
                voter_network,
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
        voter_network: (
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
        let finalizer_network = mpsc::channel::<()>(1);
        let tx_finalizer = finalizer_network.0.clone();
        // start the application
        let app_handle =
            self.application
                .start(self.syncer_mailbox, self.orchestrator, finalizer_network);
        // start the buffer
        let buffer_handle = self.buffer.start(broadcast_network);
        // start the syncer
        let syncer_handle = self
            .syncer
            .start(self.buffer_mailbox, backfill_network, tx_finalizer);
        // start simplex
        let simplex_handle = self.simplex.start(voter_network, resolver_network);

        // Wait for any actor to finish
        if let Err(e) = try_join_all(vec![
            app_handle,
            buffer_handle,
            syncer_handle,
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
