//! Consensus engine orchestrator for epoch transitions.
use crate::{Mailbox, Message};
use summit_types::{Block, Digest, scheme::SummitSchemeProvider, utils::last_block_in_epoch};

use commonware_consensus::{
    CertifiableAutomaton, Relay,
    simplex::{self, types::Context},
    types::{Epoch, Height, ViewDelta},
};
use commonware_cryptography::{Sha256, Signer, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{Builder, MuxHandle, Muxer},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage, buffer::PoolRef, spawn_cell,
};
use commonware_utils::{NZUsize, vec::NonEmptyVec};
use futures::{StreamExt, channel::mpsc};
use governor::clock::Clock as GClock;
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, time::Duration};
use summit_types::scheme::{EpochSchemeProvider, MultisigScheme};
use tracing::info;

/// Configuration for the orchestrator.
pub struct Config<B, V, C, A, St>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    A: CertifiableAutomaton<Context = Context<Digest, C::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest>,
    St: Strategy,
{
    pub oracle: B,
    pub application: A,
    pub scheme_provider: SummitSchemeProvider<C, V>,
    pub syncer_mailbox: summit_syncer::Mailbox<MultisigScheme<C, V>, Block<C, V>>,

    pub namespace: Vec<u8>,
    pub muxer_size: usize,
    pub mailbox_size: usize,

    pub blocks_per_epoch: u64,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,

    // Consensus timeouts
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,

    pub _strategy: std::marker::PhantomData<St>,
}

pub struct Actor<E, B, V, C, A, St>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer<PublicKey = summit_types::PublicKey>,
    A: CertifiableAutomaton<Context = Context<Digest, C::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest>,
    St: Strategy,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message>,
    application: A,

    oracle: B,
    syncer_mailbox: summit_syncer::Mailbox<MultisigScheme<C, V>, Block<C, V>>,
    scheme_provider: SummitSchemeProvider<C, V>,

    muxer_size: usize,
    partition_prefix: String,
    pool_ref: PoolRef,
    blocks_per_epoch: u64,

    // Consensus timeouts
    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    fetch_timeout: Duration,
    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,

    _strategy: std::marker::PhantomData<St>,
}

impl<E, B, V, C, A, St> Actor<E, B, V, C, A, St>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer<PublicKey = summit_types::PublicKey>,
    A: CertifiableAutomaton<Context = Context<Digest, C::PublicKey>, Digest = Digest>
        + Relay<Digest = Digest>,
    St: Strategy,
{
    pub fn new(context: E, config: Config<B, V, C, A, St>) -> (Self, Mailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        let pool_ref = PoolRef::new(NZUsize!(16_384), NZUsize!(10_000));

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                oracle: config.oracle,
                syncer_mailbox: config.syncer_mailbox,
                scheme_provider: config.scheme_provider,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                pool_ref,
                blocks_per_epoch: config.blocks_per_epoch,
                leader_timeout: config.leader_timeout,
                notarization_timeout: config.notarization_timeout,
                nullify_retry: config.nullify_retry,
                fetch_timeout: config.fetch_timeout,
                activity_timeout: config.activity_timeout,
                skip_timeout: config.skip_timeout,
                _strategy: std::marker::PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(pending, recovered, resolver).await)
    }

    async fn run(
        mut self,
        (pending_sender, pending_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (recovered_sender, recovered_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
        (resolver_sender, resolver_receiver): (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) {
        // Start muxers for each physical channel used by consensus
        let (mux, mut pending_mux, mut pending_backup) = Muxer::builder(
            self.context.with_label("pending_mux"),
            pending_sender,
            pending_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();
        let (mux, mut recovered_mux) = Muxer::new(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
            self.muxer_size,
        );
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        // Wait for instructions to transition epochs.
        let mut engines: BTreeMap<Epoch, Handle<()>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_stopped => {
                info!("context shutdown, stopping orchestrator");
            },
            message = pending_backup.next() => {
                // If a message is received in an unregistered sub-channel in the pending network,
                // ensure we have the boundary finalization.
                let Some((their_epoch, (from, _))) = message else {
                    info!("pending mux backup channel closed, shutting down orchestrator");
                    break;
                };
                let their_epoch = Epoch::new(their_epoch);
                let Some(our_epoch) = engines.keys().last().copied() else {
                    continue;
                };
                if their_epoch <= our_epoch {
                    continue;
                }

                // If we're not in the committee of the latest epoch we know about and we observe
                // another participant that is ahead of us, ensure we have the boundary finalization.
                // We target only the peer who claims to be ahead. If we receive messages from
                // multiple peers claiming to be ahead, each call adds them to the target set,
                // giving us more peers to try fetching from.
                let boundary_height = Height::new(last_block_in_epoch(self.blocks_per_epoch, our_epoch.get()));
                self.syncer_mailbox.hint_finalized(boundary_height, NonEmptyVec::new(from)).await;
            },
            transition = self.mailbox.next() => {
                let Some(transition) = transition else {
                    info!("mailbox closed, shutting down orchestrator");
                    break;
                };

                match transition {
                    Message::Enter(transition) => {
                        // If the epoch is already in the map, ignore.
                        if engines.contains_key(&transition.epoch) {
                            info!(epoch = transition.epoch.get(), "entered existing epoch");
                            continue;
                        }

                        // Register the new signing scheme with the scheme provider.
                        let scheme = <SummitSchemeProvider<C, V> as EpochSchemeProvider<Digest>>::scheme_for_epoch(&self.scheme_provider, &transition);
                        assert!(self.scheme_provider.register(transition.epoch, scheme.clone()));

                        // Enter the new epoch.
                        let engine = self
                            .enter_epoch(
                                transition.epoch,
                                scheme,
                                &mut pending_mux,
                                &mut recovered_mux,
                                &mut resolver_mux,
                            )
                            .await;
                        engines.insert(transition.epoch, engine);

                        info!(epoch = transition.epoch.get(), "entered epoch");
                    }
                    Message::Exit(epoch) => {
                        // Remove the engine and abort it.
                        let Some(engine) = engines.remove(&epoch) else {
                            info!(epoch = epoch.get(), "exited non-existent epoch");
                            continue;
                        };
                        engine.abort();

                        // Unregister the signing scheme for the epoch.
                        assert!(self.scheme_provider.unregister(&epoch));

                        info!(epoch = epoch.get(), "exited epoch");
                    }
                }
            },
        }
    }

    async fn enter_epoch(
        &mut self,
        epoch: Epoch,
        scheme: MultisigScheme<C, V>,
        pending_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        recovered_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
        resolver_mux: &mut MuxHandle<
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        >,
    ) -> Handle<()> {
        // Start the new engine
        let elector = simplex::elector::RoundRobin::<Sha256>::default();
        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
                elector,
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.syncer_mailbox.clone(),
                partition: format!("{}_consensus_{}", self.partition_prefix, epoch),
                mailbox_size: 1024,
                epoch,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: self.leader_timeout,
                notarization_timeout: self.notarization_timeout,
                nullify_retry: self.nullify_retry,
                fetch_timeout: self.fetch_timeout,
                activity_timeout: self.activity_timeout,
                skip_timeout: self.skip_timeout,
                fetch_concurrent: 2,
                buffer_pool: self.pool_ref.clone(),
            },
        );

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(epoch.get()).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch.get()).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch.get()).await.unwrap();

        info!("orchestrator: starting Simplex engine for epoch {}", epoch);
        engine.start(pending_sc, recovered_sc, resolver_sc)
    }
}
