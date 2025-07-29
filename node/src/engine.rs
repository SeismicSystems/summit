use commonware_broadcast::buffered;
use commonware_consensus::threshold_simplex::{self, Engine as Simplex};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{poly::public, variant::MinPk},
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use futures::{channel::mpsc, future::try_join_all};
use governor::clock::Clock as GClock;
use rand::{CryptoRng, Rng};
use summit_application::ApplicationConfig;
use summit_syncer::{Orchestrator, registry::Registry};
use summit_types::{Block, Digest, PrivateKey, PublicKey};
use tracing::{error, warn};

use crate::config::EngineConfig;

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const REPLAY_BUFFER: usize = 8 * 1024 * 1024;
const WRITE_BUFFER: usize = 1024 * 1024;

pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
> {
    context: E,
    application: summit_application::Actor<E>,
    buffer: buffered::Engine<E, PublicKey, Block>,
    buffer_mailbox: buffered::Mailbox<PublicKey, Block>,
    syncer: summit_syncer::Actor<E>,
    orchestrator: Orchestrator,
    syncer_mailbox: summit_syncer::Mailbox,
    simplex: Simplex<
        E,
        PrivateKey,
        B,
        MinPk,
        Digest,
        summit_application::Mailbox,
        summit_application::Mailbox,
        summit_syncer::Mailbox,
        Registry,
    >,
}

impl<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
> Engine<E, B>
{
    pub async fn new(context: E, cfg: EngineConfig, blocker: B) -> Self {
        let identity = *public::<MinPk>(&cfg.polynomial);
        // create application
        let (application, application_mailbox) = summit_application::Actor::new(
            context.with_label("application"),
            ApplicationConfig {
                mailbox_size: cfg.mailbox_size,
                engine_url: cfg.engine_url,
                engine_jwt: cfg.engine_jwt,
                partition_prefix: cfg.partition_prefix.clone(),
                genesis_hash: cfg.genesis_hash,
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

        let registry = Registry::new(cfg.participants, cfg.polynomial, cfg.share);

        // create the syncer
        let syncer_config = summit_syncer::Config {
            partition_prefix: cfg.partition_prefix.clone(),
            public_key: cfg.signer.public_key(),
            registry: registry.clone(),
            mailbox_size: cfg.mailbox_size,
            backfill_quota: cfg.backfill_quota,
            activity_timeout: cfg.activity_timeout,
            namespace: cfg.namespace.clone(),
            identity,
        };
        let (syncer, syncer_mailbox, orchestrator) =
            summit_syncer::Actor::new(context.with_label("syncer"), syncer_config).await;

        // create simplex
        let simplex = Simplex::new(
            context.with_label("simplex"),
            threshold_simplex::Config {
                blocker,
                crypto: cfg.signer,
                automaton: application_mailbox.clone(),
                relay: application_mailbox.clone(),
                reporter: syncer_mailbox.clone(),
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
        let simplex_handle =
            self.simplex
                .start(pending_network, recovered_network, resolver_network);

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
