//! Consensus engine orchestrator for epoch transitions.
use crate::{Mailbox, Message};
use summit_types::{Block, Digest, scheme::SummitSchemeProvider};

use commonware_codec::{DecodeExt, Encode, varint::UInt};
use commonware_consensus::{
    Automaton, Relay,
    simplex::{
        self,
        types::{Context, Voter},
    },
    types::Epoch,
    utils::last_block_in_epoch,
};
use commonware_cryptography::{Signer, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::mux::{Builder, MuxHandle, Muxer},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage, buffer::PoolRef, spawn_cell,
};
use commonware_utils::{NZU32, NZUsize};
use futures::{StreamExt, channel::mpsc};
use governor::{Quota, RateLimiter, clock::Clock as GClock};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeMap, time::Duration};
use summit_types::scheme::{EpochSchemeProvider, MultisigScheme};
use tracing::{debug, info, warn};

/// Configuration for the orchestrator.
pub struct Config<B, V, C, A>
where
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer,
    A: Automaton<Context = Context<Digest, C::PublicKey>, Digest = Digest> + Relay<Digest = Digest>,
{
    pub oracle: B,
    pub application: A,
    pub scheme_provider: SummitSchemeProvider<C, V>,
    pub syncer_mailbox: summit_syncer::Mailbox<MultisigScheme<C, V>, Block<C, V>>,

    pub namespace: Vec<u8>,
    pub muxer_size: usize,
    pub mailbox_size: usize,
    pub rate_limit: Quota,

    pub blocks_per_epoch: u64,

    // Partition prefix used for orchestrator metadata persistence
    pub partition_prefix: String,

    // Consensus timeouts
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
}

pub struct Actor<E, B, V, C, A>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer<PublicKey = summit_types::PublicKey>,
    A: Automaton<Context = Context<Digest, C::PublicKey>, Digest = Digest> + Relay<Digest = Digest>,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message>,
    application: A,

    oracle: B,
    syncer_mailbox: summit_syncer::Mailbox<MultisigScheme<C, V>, Block<C, V>>,
    scheme_provider: SummitSchemeProvider<C, V>,

    namespace: Vec<u8>,
    muxer_size: usize,
    partition_prefix: String,
    rate_limit: governor::Quota,
    pool_ref: PoolRef,
    blocks_per_epoch: u64,

    // Consensus timeouts
    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    fetch_timeout: Duration,
    activity_timeout: u64,
    skip_timeout: u64,
}

impl<E, B, V, C, A> Actor<E, B, V, C, A>
where
    E: Spawner + Metrics + Rng + CryptoRng + Clock + GClock + Storage + Network,
    B: Blocker<PublicKey = C::PublicKey>,
    V: Variant,
    C: Signer<PublicKey = summit_types::PublicKey>,
    A: Automaton<Context = Context<Digest, C::PublicKey>, Digest = Digest> + Relay<Digest = Digest>,
{
    pub fn new(context: E, config: Config<B, V, C, A>) -> (Self, Mailbox) {
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
                namespace: config.namespace,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                rate_limit: config.rate_limit,
                pool_ref,
                blocks_per_epoch: config.blocks_per_epoch,
                leader_timeout: config.leader_timeout,
                notarization_timeout: config.notarization_timeout,
                nullify_retry: config.nullify_retry,
                fetch_timeout: config.fetch_timeout,
                activity_timeout: config.activity_timeout,
                skip_timeout: config.skip_timeout,
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
        orchestrator: (
            impl Sender<PublicKey = C::PublicKey>,
            impl Receiver<PublicKey = C::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(pending, recovered, resolver, orchestrator).await
        )
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
        (mut orchestrator_sender, mut orchestrator_receiver): (
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
        let (mux, mut recovered_mux, mut recovered_global_sender) = Muxer::builder(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
            self.muxer_size,
        )
        .with_global_sender()
        .build();
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        // Create rate limiter for orchestrators
        let rate_limiter = RateLimiter::hashmap_with_clock(self.rate_limit, &self.context);

        // Wait for instructions to transition epochs.
        let mut engines = BTreeMap::new();
        loop {
            select! {
                message = pending_backup.next() => {
                    // If a message is received in an unregistered sub-channel in the pending network,
                    // attempt to forward the orchestrator for the epoch.
                    let Some((their_epoch, (from, _))) = message else {
                        warn!("pending mux backup channel closed, shutting down orchestrator");
                        break;
                    };
                    let Some(our_epoch) = engines.keys().last().copied() else {
                        debug!(their_epoch, ?from, "received message from unregistered epoch with no known epochs");
                        continue;
                    };
                    if their_epoch <= our_epoch {
                        debug!(their_epoch, our_epoch, ?from, "received message from past epoch");
                        continue;
                    }

                    // If we're not in the committee of the latest epoch we know about and we observe another
                    // participant that is ahead of us, send a message on the orchestrator channel to prompt
                    // them to send us the finalization of the epoch boundary block for our latest known epoch.
                    if rate_limiter.check_key(&from).is_err() {
                        continue;
                    }
                    let boundary_height = last_block_in_epoch(self.blocks_per_epoch, our_epoch);
                    if self.syncer_mailbox.get_finalization(boundary_height).await.is_some() {
                        // Only request the orchestrator if we don't already have it.
                        continue;
                    };
                    debug!(
                        their_epoch,
                        ?from,
                        "received backup message from future epoch, requesting orchestrator"
                    );

                    // Send the request to the orchestrator. This operation is best-effort.
                    if orchestrator_sender.send(
                        Recipients::One(from),
                        UInt(our_epoch).encode().freeze(),
                        true
                    ).await.is_err() {
                        warn!("failed to send orchestrator request, shutting down orchestrator");
                        break;
                    }
                },
                message = orchestrator_receiver.recv() => {
                    let Ok((from, bytes)) = message else {
                        warn!("orchestrator channel closed, shutting down orchestrator");
                        break;
                    };
                    let epoch = match UInt::<Epoch>::decode(bytes.as_ref()) {
                        Ok(epoch) => epoch.0,
                        Err(err) => {
                            debug!(?err, ?from, "failed to decode epoch from orchestrator request");
                            self.oracle.block(from).await;
                            continue;
                        }
                    };

                    // Fetch the finalization certificate for the last block within the subchannel's epoch.
                    // If the node is state synced, marshal may not have the finalization locally, and the
                    // peer will need to fetch it from another node on the network.
                    let boundary_height = last_block_in_epoch(self.blocks_per_epoch, epoch);
                    let Some(finalization) = self.syncer_mailbox.get_finalization(boundary_height).await else {
                        debug!(epoch, ?from, "missing finalization for old epoch");
                        continue;
                    };
                    debug!(
                        epoch,
                        boundary_height,
                        ?from,
                        "received message on pending network from old epoch. forwarding orchestrator"
                    );

                    // Forward the finalization to the sender. This operation is best-effort.
                    //
                    // TODO (#2032): Send back to orchestrator for direct insertion into marshal.
                    let message = Voter::<MultisigScheme<C, V>, Digest>::Finalization(finalization);
                    if recovered_global_sender
                        .send(
                            epoch,
                            Recipients::One(from),
                            message.encode().freeze(),
                            false,
                        )
                        .await.is_err() {
                            warn!("failed to forward finalization, shutting down orchestrator");
                            break;
                        }
                },
                transition = self.mailbox.next() => {
                    let Some(transition) = transition else {
                        warn!("mailbox closed, shutting down orchestrator");
                        break;
                    };

                    match transition {
                        Message::Enter(transition) => {
                            // If the epoch is already in the map, ignore.
                            if engines.contains_key(&transition.epoch) {
                                warn!(epoch = transition.epoch, "entered existing epoch");
                                continue;
                            }

                            // Register the new signing scheme with the scheme provider.
                            let scheme = self.scheme_provider.scheme_for_epoch(&transition);
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

                            info!(epoch = transition.epoch, "entered epoch");
                        }
                        Message::Exit(epoch) => {
                            // Remove the engine and abort it.
                            let Some(engine) = engines.remove(&epoch) else {
                                warn!(epoch, "exited non-existent epoch");
                                continue;
                            };
                            engine.abort();

                            // Unregister the signing scheme for the epoch.
                            assert!(self.scheme_provider.unregister(&epoch));

                            info!(epoch, "exited epoch");
                        }
                    }
                },
            }
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
        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.syncer_mailbox.clone(),
                partition: format!("{}_consensus_{}", self.partition_prefix, epoch),
                mailbox_size: 1024,
                epoch,
                namespace: self.namespace.clone(),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                leader_timeout: self.leader_timeout,
                notarization_timeout: self.notarization_timeout,
                nullify_retry: self.nullify_retry,
                fetch_timeout: self.fetch_timeout,
                activity_timeout: self.activity_timeout,
                skip_timeout: self.skip_timeout,
                max_fetch_count: 32,
                fetch_concurrent: 2,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                buffer_pool: self.pool_ref.clone(),
            },
        );

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(epoch).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch).await.unwrap();

        info!("orchestrator: starting Simplex engine for epoch {}", epoch);
        engine.start(pending_sc, recovered_sc, resolver_sc)
    }
}
