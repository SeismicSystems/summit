use super::{
    acks::{PendingAck, PendingAcks},
    cache,
    config::{Config, SyncCheckpoint, SyncStart},
    delivery::PendingVerification,
    durability::{DispatchGate, Durable as _},
    floor::Floor,
    ingress::{
        handler::{self, Annotation, Key, Request},
        mailbox::{Identifier as BlockID, Mailbox, Message},
    },
    stream::Stream,
};
use crate::{Update, variant::Buffer as _};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_broadcast::buffered;
use commonware_codec::{Decode, Encode};
use commonware_consensus::marshal::store::{Blocks, Certificates};
use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::simplex::types::{
    Finalization, Notarization, Subject, verify_certificates,
};
use commonware_consensus::types::{Epoch, Epocher, Height, Round, View, ViewDelta};
use commonware_consensus::{Block, Epochable, Reporter, Viewable};
use commonware_cryptography::PublicKey;
use commonware_cryptography::certificate::{Provider, Verifier as CertificateVerifier};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Resolver, TargetedResolver};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    Acknowledgement, BoxedError,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter, Pool},
};
use futures::{
    future::{join, join_all},
    try_join,
};
use governor::clock::Clock as GClock;
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::num::NonZeroUsize;
use std::sync::Arc;
#[cfg(feature = "prom")]
use std::time::Instant;
use summit_types::Digest;
use summit_types::utils::is_last_block_of_epoch;
use tracing::{debug, error, info, warn};

/// A resolver delivery plus the peer-validity response channel. Local
/// annotations on the delivery decide how accepted data is used.
struct ResolverDelivery<D: commonware_cryptography::Digest> {
    delivery: Delivery<Key<D>, Annotation>,
    value: Bytes,
    response: oneshot::Sender<bool>,
}

/// Completion produced by the actor's independent durability pool.
enum PooledSync<B> {
    Observed,
    Finalized(u64),
    Notarized(B),
}

/// Pool of subscription waiter futures. Each resolves to the requested
/// (digest, block) pair on delivery, or to the digest when the wait fails.
type BlockWaiters<B> = AbortablePool<
    Result<
        (<B as commonware_cryptography::Digestible>::Digest, B),
        <B as commonware_cryptography::Digestible>::Digest,
    >,
>;

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<B: Block> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<B>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Aborter,
}

/// Whether a block's header view may legitimately differ from the view of the
/// certificate that certified it.
///
/// Header view must equal the certified view for every block, with one exception:
/// a same-digest reproposal of the final block of an epoch. Summit re-proposes the
/// epoch-terminal block in a later view until it finalizes, so the reused block
/// bytes carry the original (earlier) view while the network re-certifies the same
/// digest in the later view. The digest commits to the header view, so the
/// certificate is for that exact block; honest validators only produced it because
/// the live verification path (`handle_verify`) accepts such reproposals without a
/// view check. Sync/import must mirror that, or catch-up rejects valid boundary
/// reproposal certificates. The epoch is bound separately by the caller; this only
/// relaxes the view comparison.
fn header_view_binds_to_round<ES: Epocher>(
    epocher: &ES,
    height: u64,
    header_view: u64,
    certified_view: u64,
) -> bool {
    header_view == certified_view
        || (is_last_block_of_epoch(epocher, height) && header_view < certified_view)
}

/// The [Actor] is responsible for receiving uncertified blocks from the broadcast mechanism,
/// receiving notarizations and finalizations from consensus, and reconstructing a total order
/// of blocks.
///
/// The actor is designed to be used in a view-based model. Each view corresponds to a
/// potential block in the chain. The actor will only finalize a block if it has a
/// corresponding finalization.
///
/// The actor also provides a backfill mechanism for missing blocks. If the actor receives a
/// finalization for a block that is ahead of its current view, it will request the missing blocks
/// from its peers. This ensures that the actor can catch up to the rest of the network if it falls
/// behind.
pub struct Actor<E, B, P, FC, FB, ES, T, A = Exact>
where
    E: BufferPooler + CryptoRng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block<Digest = Digest> + Epochable + Viewable,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Digest>>,
    FC: Certificates<BlockDigest = B::Digest, Commitment = B::Digest, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    // ---------- Context ----------
    context: ContextCell<E>,

    // ---------- Message Passing ----------
    // Mailbox
    mailbox: mailbox::Receiver<Message<P::Scheme, B>>,

    // ---------- Configuration ----------
    // Provider for epoch-specific signing schemes
    provider: P,
    // Epocher for determining epoch boundaries
    epocher: ES,
    // Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: ViewDelta,
    // Maximum number of blocks to repair at once
    max_repair: NonZeroUsize,
    // Codec configuration for block type
    block_codec_config: B::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // ---------- State ----------
    // Last proposed block
    last_proposed_block: Option<(Round, B::Digest, B)>,
    // Current processed floor and any pending floor update
    floor: Floor<P::Scheme, B::Digest>,
    // Application delivery cursor
    stream: Stream<E>,
    // Pending application acknowledgements
    pending_acks: PendingAcks<B, A>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Digest, BlockSubscription<B>>,
    // Finalized archive writes awaiting a covering sync
    dispatch_gate: DispatchGate,
    // Blocks whose durable notarized update must precede finalized delivery
    pending_notarized_reports: BTreeSet<B::Digest>,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, B, P::Scheme>,
    // Finalizations stored by height
    finalizations_by_height: FC,
    // Finalized blocks stored by height
    finalized_blocks: FB,

    // ---------- Metrics ----------
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,
}

impl<E, B, P, FC, FB, ES, T, A> Actor<E, B, P, FC, FB, ES, T, A>
where
    E: BufferPooler + CryptoRng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block<Digest = Digest> + Epochable + Viewable,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Digest>>,
    FC: Certificates<BlockDigest = B::Digest, Commitment = B::Digest, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    /// Create a new application actor.
    pub async fn init(
        context: E,
        finalizations_by_height: FC,
        finalized_blocks: FB,
        config: Config<B, P, ES, T>,
    ) -> (Self, Mailbox<P::Scheme, B>) {
        // Initialize cache
        let prunable_config = cache::Config {
            partition_prefix: config.partition_prefix.clone(),
            prunable_items_per_section: config.prunable_items_per_section,
            replay_buffer: config.replay_buffer,
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            key_page_cache: config.page_cache.clone(),
        };
        let cache = cache::Manager::init(
            context.child("cache"),
            prunable_config,
            config.block_codec_config.clone(),
        )
        .await;

        // Initialize metadata tracking application progress
        let application_metadata_partition =
            format!("{}-application-metadata", config.partition_prefix);
        let stream = Stream::new(
            context.child("application_metadata"),
            &application_metadata_partition,
        )
        .await;

        // Create metrics
        let finalized_height = context.gauge("finalized_height", "Finalized height of application");
        let processed_height = context.gauge("processed_height", "Processed height of application");

        // Initialize mailbox
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                provider: config.scheme_provider,
                epocher: config.epocher,
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                block_codec_config: config.block_codec_config,
                strategy: config.strategy,
                last_proposed_block: None,
                floor: Floor::resolved(None, Round::zero()),
                stream,
                pending_acks: PendingAcks::new(config.max_pending_acks.get()),
                tip: Height::zero(),
                block_subscriptions: BTreeMap::new(),
                dispatch_gate: DispatchGate::default(),
                pending_notarized_reports: BTreeSet::new(),
                cache,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the actor.
    pub fn start<R, K>(
        mut self,
        application: impl Reporter<Activity = Update<B, P::Scheme, A>>,
        buffer: buffered::Mailbox<K, B>,
        resolver: (handler::Receiver<B::Digest>, R),
        sync_start: SyncStart,
        checkpoint: Option<SyncCheckpoint<B, P::Scheme>>,
    ) -> Handle<()>
    where
        R: TargetedResolver<
                Key = Key<B::Digest>,
                Subscriber = Annotation,
                PublicKey = <P::Scheme as CertificateVerifier>::PublicKey,
            >,
        K: PublicKey + From<<P::Scheme as CertificateVerifier>::PublicKey>,
    {
        spawn_cell!(
            self.context,
            self.run(application, buffer, resolver, sync_start, checkpoint)
        )
    }

    /// Run the application actor.
    async fn run<R, K>(
        mut self,
        mut application: impl Reporter<Activity = Update<B, P::Scheme, A>>,
        mut buffer: buffered::Mailbox<K, B>,
        (mut resolver_rx, mut resolver): (handler::Receiver<B::Digest>, R),
        sync_start: SyncStart,
        checkpoint: Option<SyncCheckpoint<B, P::Scheme>>,
    ) where
        R: TargetedResolver<
                Key = Key<B::Digest>,
                Subscriber = Annotation,
                PublicKey = <P::Scheme as CertificateVerifier>::PublicKey,
            >,
        K: PublicKey + From<<P::Scheme as CertificateVerifier>::PublicKey>,
    {
        let SyncStart {
            height: sync_height,
            epoch: sync_epoch,
            view: sync_view,
        } = sync_start;
        self.stream.acknowledge(Height::new(sync_height));
        self.floor.set_processed_height(Height::new(sync_height));
        self.floor
            .set_processed_round(Round::new(Epoch::new(sync_epoch), View::new(sync_view)));
        self.tip = Height::new(sync_height);
        info!(sync_height, sync_epoch, sync_view, "syncer initialized");

        // If we have a checkpoint, finalize the last block to complete the checkpoint
        if let Some(checkpoint) = checkpoint {
            let height = checkpoint.last_block.height();
            let last_block_digest = checkpoint.last_block.digest();
            let finalization = checkpoint.finalized_header.map(|h| h.into_finalization());
            // Defense in depth: last_block and finalized_header arrive as
            // independent artifacts. The finalization certifies a specific block
            // digest, so refuse to complete the checkpoint with a finalization
            // that certifies a different block than the supplied last_block. The
            // node startup path already binds these against the verified header
            // chain; asserting it here keeps the boundary safe for any caller.
            if let Some(finalization) = finalization.as_ref() {
                assert!(
                    finalization.proposal.payload == last_block_digest,
                    "checkpoint finalization certifies a different block than last_block"
                );
            }
            self.store_finalization(
                height,
                last_block_digest,
                checkpoint.last_block,
                finalization,
                &mut application,
            )
            .await;
            self.sync_finalized().await;
        }

        let _ = self
            .processed_height
            .try_set(self.floor.processed_height().get());

        // Create a local pool for waiter futures.
        let mut waiters = BlockWaiters::<B>::default();

        // Observe non-blocking storage syncs without stalling mailbox processing.
        let mut syncs = Pool::<PooledSync<B>>::default();

        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, commitment)) = tip {
            application.report(Update::Tip(height.get(), commitment));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Load persisted cache epochs so find_block can discover blocks
        // written before the last shutdown.
        self.cache.load_persisted_epochs().await;

        // Attempt to repair any gaps in the finalized blocks archive, if there are any.
        if self
            .try_repair_gaps(&mut buffer, &mut resolver, &mut application)
            .await
        {
            self.sync_finalized().await;
        }

        // Attempt to dispatch the next finalized block to the application, if it is ready.
        self.try_dispatch_blocks(&mut application, &mut resolver)
            .await;

        select_loop! {
            self.context,
            on_start => {
                // Remove any dropped subscribers. If all subscribers dropped, abort the waiter.
                self.block_subscriptions.retain(|_, bs| {
                    bs.subscribers.retain(|tx| !tx.is_closed());
                    !bs.subscribers.is_empty()
                });
            },
            on_stopped => {
                debug!("context shutdown, stopping syncer");
            },
            sync = syncs.next_completed() => {
                match sync {
                    PooledSync::Observed => {}
                    PooledSync::Finalized(seq) => {
                        self.dispatch_gate.release(seq);
                        self.try_dispatch_blocks(&mut application, &mut resolver).await;
                    }
                    PooledSync::Notarized(block) => {
                        self.pending_notarized_reports.remove(&block.digest());
                        application.report(Update::NotarizedBlock(block));
                        self.try_dispatch_blocks(&mut application, &mut resolver).await;
                    }
                }
            },
            // Handle waiter completions first
            result = waiters.next_completed() => {
                let Ok(completion) = result else {
                    continue; // Aborted future
                };
                match completion {
                    Ok((commitment, block)) => {
                        self.notify_subscribers(commitment, &block);
                        self.apply_floor_anchor(&block, &mut buffer, &mut application, &mut resolver)
                            .await;
                    }
                    Err(commitment) => {
                        debug!(
                            ?commitment,
                            "buffer subscription closed, canceling local subscribers"
                        );
                        self.block_subscriptions.remove(&commitment);
                    }
                }
            },
            // Handle application acknowledgements (drain all ready acks, sync once)
            result = self.pending_acks.current() => {
                if !self.handle_ack(result, &mut application, &mut resolver).await {
                    return;
                }
            },
            // Handle consensus inputs before backfill or resolver traffic
            Some(message) = self.mailbox.recv() else {
                info!("mailbox closed, shutting down");
                break;
            } => {
                self.handle_mailbox_message(
                    message,
                    &mut resolver,
                    &mut waiters,
                    &mut syncs,
                    &mut buffer,
                    &mut application,
                )
                .await;
            },
            // Handle resolver messages last (batched up to max_repair, sync once)
            Some(message) = resolver_rx.recv() else {
                info!("handler closed, shutting down");
                return;
            } => {
                self.handle_resolver_message(
                    message,
                    &mut resolver_rx,
                    &mut resolver,
                    &mut syncs,
                    &mut buffer,
                    &mut application,
                )
                .await;
            },
        }
    }

    /// Handles one ready application acknowledgement and drains any queued acks
    /// that are already complete.
    ///
    /// Returns `false` if the actor should shut down.
    async fn handle_ack<R>(
        &mut self,
        result: <A::Waiter as std::future::Future>::Output,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
        resolver: &mut R,
    ) -> bool
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
    {
        // Start with the ack that woke this `select_loop!` arm.
        let mut pending = Some(self.pending_acks.complete_current(result));
        loop {
            let (height, commitment, result) = pending.take().expect("pending ack must exist");
            let _ = commitment;
            match result {
                Ok(()) => {
                    // Apply in-memory progress updates for this acknowledged block.
                    self.update_processed_height(height, resolver);
                    self.update_processed_round(height, resolver).await;
                }
                Err(e) => {
                    error!(?e, %height, "application did not acknowledge block");
                    return false;
                }
            }

            // Opportunistically drain any additional already-ready acks so we
            // can persist one metadata sync for the whole batch.
            let Some(next) = self.pending_acks.pop_ready() else {
                break;
            };
            pending = Some(next);
        }

        // Persist buffered processed-height updates once after draining all ready acks.
        if let Err(e) = self.stream.sync().await {
            error!(?e, "failed to sync application progress");
            return false;
        }

        // Fill the pipeline
        self.try_dispatch_blocks(application, resolver).await;
        true
    }

    /// Handles a single mailbox message from local consensus/application callers.
    async fn handle_mailbox_message<R, K>(
        &mut self,
        message: Message<P::Scheme, B>,
        resolver: &mut R,
        waiters: &mut BlockWaiters<B>,
        syncs: &mut Pool<PooledSync<B>>,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
    ) where
        R: TargetedResolver<
                Key = Key<B::Digest>,
                Subscriber = Annotation,
                PublicKey = <P::Scheme as CertificateVerifier>::PublicKey,
            >,
        K: PublicKey + From<<P::Scheme as CertificateVerifier>::PublicKey>,
    {
        if message.response_closed() {
            return;
        }

        match message {
            Message::GetInfo {
                identifier,
                response,
            } => {
                let info = match identifier {
                    BlockID::Digest(commitment) => self
                        .finalized_blocks
                        .get(ArchiveID::Key(&commitment))
                        .await
                        .ok()
                        .flatten()
                        .map(|b| (b.height(), commitment)),
                    BlockID::Height(height) => self.get_info_by_height(height).await,
                    BlockID::Latest => self.get_latest().await,
                };
                response.send_lossy(info);
            }
            Message::GetVerified { round, response } => {
                let block = self.cache.get_verified(round).await;
                response.send_lossy(block);
            }
            Message::Proposed { round, block, ack } => {
                // Match marshal's latency-sensitive ordering: hand the proposal
                // to the network before any storage work can delay propagation.
                buffer.send(round, Arc::new(block.clone()), Recipients::All);

                // If the round has already been pruned by tip advancement,
                // `cache_verified` is a no-op because the round is below
                // the retention floor (and no longer is required by consensus
                // to make progress).
                let handle = self
                    .cache_verified(round, block.digest(), block.clone())
                    .await;
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;

                // Retain the block in memory so a subsequent `Forward` can
                // re-send it without reloading from storage. An older retained
                // proposal (if any) is overwritten.
                let commitment = block.digest();
                self.last_proposed_block = Some((round, commitment, block));
                ack.send_lossy(handle);
            }
            Message::Forward {
                round,
                commitment,
                recipients,
            } => {
                if matches!(&recipients, Recipients::Some(peers) if peers.is_empty()) {
                    return;
                }
                let block = match self.take_proposed(round, commitment) {
                    Some(block) => block,
                    None => {
                        let Some(block) = self.find_block(buffer, commitment).await else {
                            debug!(?commitment, "block not found for forwarding");
                            return;
                        };
                        block
                    }
                };
                let recipients = match recipients {
                    Recipients::All => Recipients::All,
                    Recipients::Some(peers) => {
                        Recipients::Some(peers.into_iter().map(K::from).collect())
                    }
                    Recipients::One(peer) => Recipients::One(K::from(peer)),
                };
                buffer.send(round, Arc::new(block), recipients);
            }
            Message::Verified { round, block, ack } => {
                // If the round has already been pruned by tip advancement,
                // `cache_verified` is a no-op because the round is below
                // the retention floor (and no longer is required by consensus
                // to make progress).
                let handle = self
                    .cache_verified(round, block.digest(), block.clone())
                    .await;
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;
                ack.send_lossy(handle);
            }
            Message::Certified { round, block, ack } => {
                // If the round has already been pruned by tip advancement,
                // `cache_block` is a no-op because the round is below
                // the retention floor (and no longer is required by consensus
                // to make progress).
                let commitment = block.digest();
                let block_sync = if self.cache.has_verified(round, &commitment).await {
                    self.notify_subscribers(commitment, &block);
                    self.cache.start_sync_verified(round).await
                } else {
                    self.cache_block(round, commitment, block.clone()).await
                };
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;
                let certificate_sync = self.cache.start_sync_notarizations(round).await;
                let handle = Handle::from_future(async move {
                    let (certificate, block) = join(certificate_sync, block_sync).await;
                    certificate.and(block)
                });
                ack.send_lossy(handle);
            }
            Message::Notarization { notarization } => {
                let round = notarization.round();
                let commitment = notarization.proposal.payload;

                // Store notarization by view
                let notarization_sync = self
                    .cache
                    .put_notarization(round, commitment, notarization.clone())
                    .await;

                // A notarization alone is not enough to fetch missing proposal
                // data. If the block is not locally available, remember the
                // certificate and wait for a later finalization/repair path
                // (or a round-bound subscription) to fetch it.
                if let Some(block) = self.find_block(buffer, commitment).await {
                    let block_sync = if self.cache.has_verified(round, &commitment).await {
                        self.notify_subscribers(commitment, &block);
                        debug!(?round, "notarized block covered by verified write");
                        self.cache.start_sync_verified(round).await
                    } else {
                        self.cache_block(round, commitment, block.clone()).await
                    };
                    let installed_floor = self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await;
                    if !installed_floor {
                        self.pending_notarized_reports.insert(commitment);
                    }
                    syncs.push(async move {
                        let (certificate, block_durable) = join(
                            notarization_sync.durable(round, "notarization"),
                            block_sync.durable(round, "notarized"),
                        )
                        .await;
                        if certificate && block_durable && !installed_floor {
                            PooledSync::Notarized(block)
                        } else {
                            PooledSync::Observed
                        }
                    });
                } else {
                    debug!(?round, "notarized block unavailable locally");
                    syncs.push(async move {
                        notarization_sync.durable(round, "notarization").await;
                        PooledSync::Observed
                    });
                }
            }
            Message::Finalization { finalization } => {
                let round = finalization.round();
                let commitment = finalization.proposal.payload;

                // Cache finalization by round
                self.cache
                    .put_finalization(round, commitment, finalization.clone())
                    .await;

                // Search for the finalized block locally, otherwise fetch it remotely.
                if let Some(block) = self.find_block(buffer, commitment).await {
                    // The anchor path stores the floor block and finalization,
                    // advances floors, prunes below them, and resumes dispatch.
                    if self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await
                    {
                        return;
                    }

                    let height = block.height();
                    self.update_processed_round_floor(height, round, resolver)
                        .await;
                    if self
                        .store_finalization(
                            height,
                            commitment,
                            block,
                            Some(finalization),
                            application,
                        )
                        .await
                    {
                        // If a floor anchor is pending, repair and dispatch are
                        // no-ops until the anchor block is stored.
                        self.try_repair_gaps(buffer, resolver, application).await;
                        self.start_finalized_sync(round, syncs).await;
                        debug!(?round, %height, "finalized block stored");
                    }
                } else {
                    // The finalization carries a round and commitment, but not a
                    // height. Keep the request round-bound until the block is decoded.
                    debug!(?round, ?commitment, "finalized block missing");
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_round(commitment, round),
                        )
                        .ignore();
                }
            }
            Message::Fault { evidence } => {
                // A committee member signed conflicting votes (Byzantine fault).
                // Forward to the application (finalizer), which owns critical
                // logging, metrics, and identity resolution against consensus state.
                debug!(
                    epoch = evidence.epoch.get(),
                    view = evidence.view.get(),
                    signer_index = evidence.signer.get(),
                    kind = ?evidence.kind(),
                    "forwarding Byzantine fault evidence to application"
                );
                application.report(Update::Fault(evidence));
            }
            Message::GetBlock {
                identifier,
                response,
            } => match identifier {
                BlockID::Digest(commitment) => {
                    let result = self.find_block(buffer, commitment).await;
                    response.send_lossy(result);
                }
                BlockID::Height(height) => {
                    let result = self.get_finalized_block(height).await;
                    response.send_lossy(result);
                }
                BlockID::Latest => {
                    let block = match self.get_latest().await {
                        Some((_, commitment)) => self.find_block(buffer, commitment).await,
                        None => None,
                    };
                    response.send_lossy(block);
                }
            },
            Message::GetFinalization { height, response } => {
                let finalization = self.get_finalization_by_height(height).await;
                response.send_lossy(finalization);
            }
            Message::GetProcessedHeight { response } => {
                response.send_lossy(self.stream.processed_height());
            }
            Message::HintFinalized { height, targets } => {
                // Skip if finalization is already available locally.
                if self.has_finalization_by_height(height).await {
                    return;
                }

                // Trigger a targeted fetch via the resolver (denied below the floor).
                self.floor
                    .fetch_targeted_if_permitted(resolver, Request::finalized(height), targets)
                    .ignore();
            }
            Message::HintNotarized { round, commitment } => {
                if self.find_block(buffer, commitment).await.is_none() {
                    self.floor
                        .fetch_if_permitted(resolver, Request::notarized(round))
                        .ignore();
                }
            }
            Message::Subscribe {
                round,
                commitment,
                response,
            } => {
                // Check for block locally
                if let Some(block) = self.find_block(buffer, commitment).await {
                    response.send_lossy(block);
                    return;
                }

                // We don't have the block locally, so fetch the block from the network
                // if we have an associated round. If we only have the digest, don't make
                // the request as we wouldn't know when to drop it, and the request may
                // never complete if the block is not finalized.
                if let Some(round) = round {
                    if self
                        .floor
                        .fetch_if_permitted(resolver, Request::notarized(round))
                        .denied()
                    {
                        warn!(
                            ?round,
                            ?commitment,
                            last_processed_round = ?self.floor.processed_round(),
                            last_processed_height = %self.floor.processed_height(),
                            tip = %self.tip,
                            "subscription for block in past round that wasn't finalized - possible notarize-nullify race"
                        );

                        #[cfg(feature = "prom")]
                        counter!("syncer_stuck_subscription_total").increment(1);

                        return;
                    }
                    // The fetch (with notarization) was issued. If this is a valid
                    // view, this request should be fine to keep open until
                    // resolution or pruning (even if the oneshot is canceled).
                    debug!(?round, ?commitment, "requested block missing");
                }

                // Register subscriber
                debug!(?round, ?commitment, "registering subscriber");
                match self.block_subscriptions.entry(commitment) {
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().subscribers.push(response);
                    }
                    Entry::Vacant(entry) => {
                        let rx = buffer.subscribe(commitment);
                        let aborter = waiters.push(async move {
                            rx.await
                                .map(|block| (commitment, (*block).clone()))
                                .map_err(|_| commitment)
                        });
                        entry.insert(BlockSubscription {
                            subscribers: vec![response],
                            _aborter: aborter,
                        });
                    }
                }
            }
            Message::SetFloor { finalization } => {
                self.install_floor(finalization, true, resolver, buffer, application)
                    .await;
            }
            Message::Prune { height } => {
                // Only allow pruning at or below the current floor
                if height > self.floor.processed_height() {
                    warn!(%height, floor = %self.floor.processed_height(), "prune height above floor, ignoring");
                    return;
                }

                // Prune the finalized block and finalization certificate archives in parallel.
                self.prune_finalized_archives(height)
                    .await
                    .expect("failed to prune finalized archives");

                // Intentionally keep existing block subscriptions alive. Canceling
                // waiters can have catastrophic consequences because actors do not
                // retry subscriptions on failed channels.
            }
        }
    }

    /// Handles a batch of resolver messages and starts one finalized-archive
    /// sync covering writes accepted by the batch.
    async fn handle_resolver_message<R, K>(
        &mut self,
        message: handler::Message<B::Digest>,
        resolver_rx: &mut handler::Receiver<B::Digest>,
        resolver: &mut R,
        syncs: &mut Pool<PooledSync<B>>,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
    ) where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        let mut handled = false;
        let mut produces = Vec::new();
        let mut delivers = Vec::new();

        // Drain up to max_repair resolver messages. Block deliveries are handled
        // immediately, certificate-bearing deliveries are batched for verification,
        // and produce responses wait until repair has had a chance to fill gaps.
        for msg in std::iter::once(message)
            .chain(std::iter::from_fn(|| resolver_rx.try_recv().ok()))
            .take(self.max_repair.get())
        {
            if msg.response_closed() {
                continue;
            }
            handled = true;

            match msg {
                handler::Message::Produce { key, response } => {
                    produces.push((key, response));
                }
                handler::Message::Deliver {
                    delivery,
                    value,
                    response,
                } => {
                    self.handle_deliver(
                        ResolverDelivery {
                            delivery,
                            value,
                            response,
                        },
                        &mut delivers,
                        buffer,
                        application,
                        resolver,
                    )
                    .await;
                }
            }
        }
        if !handled {
            return;
        }

        // Batch verify and process all certificate-bearing deliveries.
        self.verify_delivered(delivers, buffer, application, resolver)
            .await;

        // Attempt to fill gaps before handling produce requests so we can serve
        // data received earlier in the same batch.
        self.try_repair_gaps(buffer, resolver, application).await;
        self.start_finalized_sync(self.floor.processed_round(), syncs)
            .await;

        // Handle produce requests in parallel.
        join_all(
            produces
                .into_iter()
                .filter(|(_, response)| !response.is_closed())
                .map(|(key, response)| self.handle_produce(key, response, buffer)),
        )
        .await;
    }

    /// Handle a produce request from a remote peer.
    async fn handle_produce<K: PublicKey>(
        &self,
        key: Key<B::Digest>,
        response: oneshot::Sender<Bytes>,
        buffer: &buffered::Mailbox<K, B>,
    ) {
        match key {
            Key::Block(commitment) => {
                let Some(block) = self.find_block(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy(block.encode());
            }
            Key::Finalized { height } => {
                let height = Height::new(height);
                let Some(finalization) = self.get_finalization_by_height(height).await else {
                    debug!(%height, "finalization missing on request");
                    return;
                };
                let Some(block) = self.get_finalized_block(height).await else {
                    debug!(%height, "finalized block missing on request");
                    return;
                };
                response.send_lossy((finalization, block).encode());
            }
            Key::Notarized { round } => {
                let Some(notarization) = self.cache.get_notarization(round).await else {
                    debug!(?round, "notarization missing on request");
                    return;
                };
                let commitment = notarization.proposal.payload;
                let Some(block) = self.find_block(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy((notarization, block).encode());
            }
        }
    }

    /// Verifies and installs a floor, fetching the anchor block if needed.
    async fn install_floor<R, K>(
        &mut self,
        finalization: Finalization<P::Scheme, B::Digest>,
        skip_if_superseded: bool,
        resolver: &mut R,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
    ) where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        let round = finalization.round();
        if round <= self.floor.processed_round() {
            warn!(
                ?round,
                floor = ?self.floor.processed_round(),
                "floor not updated, below existing round floor"
            );
            return;
        }

        let Some(scheme) = self.get_scheme_certificate_verifier(finalization.epoch()) else {
            panic!("floor finalization epoch unavailable");
        };
        assert!(
            finalization.verify(self.context.as_mut(), &scheme, &self.strategy),
            "floor finalization must verify"
        );

        let commitment = finalization.proposal.payload;
        self.cache
            .put_finalization(round, commitment, finalization.clone())
            .await;

        // A pending anchor at the same or a newer floor already blocks
        // progress. Keep waiting for it instead of replacing it.
        if skip_if_superseded && self.floor.has_pending_anchor_at_or_after(round) {
            return;
        }

        if let Some(block) = self.find_block(buffer, commitment).await {
            self.floor.await_anchor(finalization);
            assert!(
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await
            );
            return;
        }

        // The pending floor owns the next application sync point. Drop any
        // in-flight acks before they can advance the processed height past it.
        self.pending_acks.clear();

        debug!(?round, ?commitment, "starting fetch for floor block");
        self.floor.await_anchor(finalization);
        self.floor
            .fetch_if_permitted(
                resolver,
                Request::finalized_block_by_round(commitment, round),
            )
            .ignore();
    }

    /// Applies a block if it satisfies the current floor transition.
    async fn apply_floor_anchor<R, K>(
        &mut self,
        block: &B,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
        resolver: &mut R,
    ) -> bool
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        let commitment = block.digest();
        if !self.floor.matches_pending_anchor(commitment) {
            return false;
        }
        let block = block.clone();

        // This anchor cannot move the application sync point, but its
        // finalization round can still prune round-bound resolver work.
        // Keep pending acks intact because processed_height is unchanged.
        let height = block.height();
        if height <= self.floor.processed_height() {
            warn!(
                %height,
                existing = %self.floor.processed_height(),
                "floor not updated, at or below existing"
            );
            let finalization = self
                .floor
                .take_pending_anchor()
                .expect("pending floor anchor missing");
            self.update_processed_round_floor(height, finalization.round(), resolver)
                .await;
            if self.try_repair_gaps(buffer, resolver, application).await {
                self.sync_finalized().await;
            }
            self.try_dispatch_blocks(application, resolver).await;
            return true;
        }

        let finalization = self
            .floor
            .take_pending_anchor()
            .expect("pending floor anchor missing");
        let round = finalization.round();
        try_join!(
            async {
                self.finalized_blocks
                    .put(block.clone())
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .put(height, commitment, finalization)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )
        .expect("failed to store floor anchor");
        self.sync_finalized().await;
        self.notify_subscribers(commitment, &block);

        if height > self.tip {
            application.report(Update::Tip(height.get(), commitment));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // The anchor is durable, but the application still needs to process it.
        // Record the previous height so dispatch resumes at the anchor itself.
        let dispatch_floor = height
            .previous()
            .expect("floor anchor above processed height must have predecessor");
        self.update_processed_height(dispatch_floor, resolver);
        self.update_processed_round_floor(dispatch_floor, round, resolver)
            .await;
        self.stream
            .sync()
            .await
            .expect("failed to sync floor metadata");

        // Drop all pending acknowledgement waiters so any in-flight application
        // acks for blocks below the new floor cannot rewrite the processed floor.
        self.pending_acks.clear();

        // The floor is durable, so cache/finalized data below it can be pruned.
        self.prune_after_floor(height)
            .await
            .expect("failed to prune data below floor");

        // Intentionally keep existing block subscriptions alive. Canceling
        // waiters can have catastrophic consequences (nodes can get stuck in
        // different views) as actors do not retry subscriptions on failed channels.
        if self.try_repair_gaps(buffer, resolver, application).await {
            self.sync_finalized().await;
        }
        self.try_dispatch_blocks(application, resolver).await;
        true
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    /// Returns true if finalization archives were written and need syncing.
    async fn handle_deliver<R, K>(
        &mut self,
        message: ResolverDelivery<B::Digest>,
        delivers: &mut Vec<PendingVerification<P::Scheme, B>>,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
        resolver: &mut R,
    ) -> bool
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        let ResolverDelivery {
            delivery,
            value,
            response,
        } = message;
        let Delivery { key, subscribers } = delivery;
        match key {
            Key::Block(commitment) => {
                let Ok(block) = B::decode_cfg(value.as_ref(), &self.block_codec_config) else {
                    response.send_lossy(false);
                    return false;
                };
                if block.digest() != commitment {
                    response.send_lossy(false);
                    return false;
                }

                // This block may match the pending floor request. Whether it
                // installs or is rejected as the floor anchor, do not also
                // process it as an ordinary block delivery.
                if self
                    .apply_floor_anchor(&block, buffer, application, resolver)
                    .await
                {
                    response.send_lossy(true);
                    return false;
                }

                // The commitment validates the peer response. Annotations are
                // local context attached to the request and do not affect peer
                // validity.
                self.notify_subscribers(commitment, &block);

                // The peer-visible request only says "give me this block".
                // Local annotations explain why the block was requested and
                // therefore where, if anywhere, it should be stored.
                let height = block.height();
                let annotations: Vec<_> = subscribers
                    .into_vec()
                    .into_iter()
                    .map(|(annotation, _span)| annotation)
                    .collect();

                // Round-bound proposal-parent fetches are `Key::Notarized`
                // deliveries and are handled below. In this block-keyed path,
                // `Finalized` means the block belongs in the finalized chain.
                let finalization = self.cache.get_finalization_for(commitment).await;
                if let Some(finalization) = &finalization {
                    self.update_processed_round_floor(height, finalization.round(), resolver)
                        .await;
                }
                let wrote = if finalization.is_some()
                    || annotations
                        .iter()
                        .any(|annotation| matches!(annotation, Annotation::Finalized(_)))
                {
                    self.store_finalization(height, commitment, block, finalization, application)
                        .await
                } else {
                    if annotations
                        .iter()
                        .any(|annotation| matches!(annotation, Annotation::Certified { .. }))
                        && height > self.floor.processed_height()
                        && let Some(bounds) = self.epocher.containing(height)
                    {
                        self.cache
                            .put_certified(bounds.epoch(), height, commitment, block)
                            .await;
                    }
                    false
                };
                debug!(?commitment, %height, "received block");
                response.send_lossy(true);
                wrote
            }
            Key::Finalized { height } => {
                let height = Height::new(height);
                let Some(bounds) = self.epocher.containing(height) else {
                    debug!(
                        %height,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };
                let epoch = bounds.epoch();
                let Some(scheme) = self.get_scheme_certificate_verifier(epoch) else {
                    debug!(
                        %height,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };

                let Ok((finalization, block)) =
                    <(Finalization<P::Scheme, B::Digest>, B)>::decode_cfg(
                        value,
                        &(
                            scheme.certificate_codec_config(),
                            self.block_codec_config.clone(),
                        ),
                    )
                else {
                    response.send_lossy(false);
                    return false;
                };

                let certified_round = finalization.round();
                if block.height() != height
                    || finalization.proposal.payload != block.digest()
                    || finalization.epoch() != epoch
                    || block.epoch() != certified_round.epoch()
                    || !header_view_binds_to_round(
                        &self.epocher,
                        block.height().get(),
                        block.view().get(),
                        certified_round.view().get(),
                    )
                {
                    warn!(
                        ?certified_round,
                        block_height = %block.height(),
                        block_epoch = %block.epoch(),
                        block_view = %block.view(),
                        expected_height = %height,
                        expected_epoch = %epoch,
                        "rejecting finalized delivery with header/certificate round mismatch"
                    );
                    response.send_lossy(false);
                    return false;
                }
                delivers.push(PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                });
                false
            }
            Key::Notarized { round } => {
                let Some(scheme) = self.get_scheme_certificate_verifier(round.epoch()) else {
                    debug!(
                        ?round,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };

                let Ok((notarization, block)) =
                    <(Notarization<P::Scheme, B::Digest>, B)>::decode_cfg(
                        value,
                        &(
                            scheme.certificate_codec_config(),
                            self.block_codec_config.clone(),
                        ),
                    )
                else {
                    response.send_lossy(false);
                    return false;
                };

                let certified_round = notarization.round();
                if certified_round != round
                    || notarization.proposal.payload != block.digest()
                    || block.epoch() != certified_round.epoch()
                    || !header_view_binds_to_round(
                        &self.epocher,
                        block.height().get(),
                        block.view().get(),
                        certified_round.view().get(),
                    )
                {
                    warn!(
                        ?certified_round,
                        block_epoch = %block.epoch(),
                        block_view = %block.view(),
                        "rejecting notarized delivery with header/certificate round mismatch"
                    );
                    response.send_lossy(false);
                    return false;
                }
                delivers.push(PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                });
                false
            }
        }
    }

    /// Batch verify pending certificates and process valid items.
    async fn verify_delivered<R, K>(
        &mut self,
        mut delivers: Vec<PendingVerification<P::Scheme, B>>,
        buffer: &mut buffered::Mailbox<K, B>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
        resolver: &mut R,
    ) where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        delivers.retain(|item| !item.response_closed());
        if delivers.is_empty() {
            return;
        }

        // Extract (subject, certificate) pairs for batch verification.
        let certs: Vec<_> = delivers
            .iter()
            .map(|item| match item {
                PendingVerification::Finalized { finalization, .. } => (
                    Subject::Finalize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                ),
                PendingVerification::Notarized { notarization, .. } => (
                    Subject::Notarize {
                        proposal: &notarization.proposal,
                    },
                    &notarization.certificate,
                ),
            })
            .collect();

        // Batch verify per epoch using scoped verifiers.
        let verified = {
            let mut verified = vec![false; delivers.len()];

            // Group indices by epoch.
            let mut by_epoch: BTreeMap<Epoch, Vec<usize>> = BTreeMap::new();
            for (i, item) in delivers.iter().enumerate() {
                let epoch = match item {
                    PendingVerification::Notarized { notarization, .. } => notarization.epoch(),
                    PendingVerification::Finalized { finalization, .. } => finalization.epoch(),
                };
                by_epoch.entry(epoch).or_default().push(i);
            }

            // Batch verify each epoch group.
            for (epoch, indices) in &by_epoch {
                let Some(scheme) = self.provider.scoped(*epoch) else {
                    continue;
                };
                let group: Vec<_> = indices.iter().map(|&i| certs[i]).collect();
                let results =
                    verify_certificates(self.context.as_mut(), &scheme, &group, &self.strategy);
                for (j, &idx) in indices.iter().enumerate() {
                    verified[idx] = results[j];
                }
            }
            verified
        };

        // Process each verified item, rejecting unverified ones.
        for (index, item) in delivers.drain(..).enumerate() {
            if !verified[index] {
                match item {
                    PendingVerification::Finalized { response, .. }
                    | PendingVerification::Notarized { response, .. } => {
                        response.send_lossy(false);
                    }
                }
                continue;
            }
            match item {
                PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                } => {
                    // Valid finalization received.
                    response.send_lossy(true);
                    let round = finalization.round();
                    let height = block.height();
                    let commitment = block.digest();
                    debug!(?round, %height, "received finalization");

                    // The floor-anchor path fully handles this finalization
                    // and moves the lower bound past it.
                    if self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await
                    {
                        continue;
                    }

                    self.update_processed_round_floor(height, round, resolver)
                        .await;

                    self.store_finalization(
                        height,
                        commitment,
                        block,
                        Some(finalization),
                        application,
                    )
                    .await;
                }
                PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                } => {
                    // Valid notarization received.
                    response.send_lossy(true);
                    let round = notarization.round();
                    let commitment = block.digest();
                    debug!(?round, ?commitment, "received notarization");

                    // Match marshal's imported-data ordering: make the block and
                    // certificate durable before repair bookkeeping can advance.
                    let height = block.height();
                    let block_sync = self.cache_block(round, commitment, block.clone()).await;
                    let notarization_sync = self
                        .cache
                        .put_notarization(round, commitment, notarization)
                        .await;
                    join(
                        block_sync.durable(round, "notarized"),
                        notarization_sync.durable(round, "notarization"),
                    )
                    .await;

                    // A notarized delivery can carry the pending floor block
                    // after the finalization is cached.
                    let installed_floor = self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await;
                    if installed_floor {
                        continue;
                    }

                    // If there exists a finalization certificate for this block, we
                    // should finalize it. This could finalize the block faster when
                    // a notarization then a finalization are received via consensus
                    // and we resolve the notarization request before the block request.
                    if let Some(finalization) = self.cache.get_finalization_for(commitment).await {
                        self.update_processed_round_floor(height, finalization.round(), resolver)
                            .await;

                        self.store_finalization(
                            height,
                            commitment,
                            block.clone(),
                            Some(finalization),
                            application,
                        )
                        .await;
                    }
                    application.report(Update::NotarizedBlock(block));
                }
            }
        }
    }

    /// Returns a scoped certificate verifier for the given epoch.
    fn get_scheme_certificate_verifier(
        &self,
        epoch: Epoch,
    ) -> Option<commonware_cryptography::certificate::Scoped<P::Scheme>> {
        self.provider.scoped(epoch)
    }

    // -------------------- Waiters --------------------

    /// Notify any subscribers for the given commitment with the provided block.
    fn notify_subscribers(&mut self, commitment: B::Digest, block: &B) {
        if let Some(mut bs) = self.block_subscriptions.remove(&commitment) {
            for subscriber in bs.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
    }

    // -------------------- Application Dispatch --------------------

    /// Attempt to dispatch finalized blocks to the application until the pipeline is full
    /// or no more blocks are available.
    ///
    /// This does NOT advance the processed floor height or sync metadata. It only
    /// sends blocks to the application and enqueues pending acks. Metadata is
    /// updated later when acks arrive and [`Self::handle_ack`] runs.
    ///
    /// Acks are processed in FIFO order so the processed floor height always
    /// advances sequentially.
    async fn try_dispatch_blocks<R>(
        &mut self,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
        resolver: &mut R,
    ) where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
    {
        // Dispatch resumes after the floor anchor is durably stored.
        if self.floor.blocks_progress() {
            return;
        }

        let barrier = self.dispatch_gate.barrier();
        while self.pending_acks.has_capacity() {
            let next_height = self
                .pending_acks
                .next_dispatch_height(self.stream.next_height());
            if barrier.is_some_and(|lowest| next_height >= lowest) {
                return;
            }
            let Some(block) = self.get_finalized_block(next_height).await else {
                return;
            };
            assert_eq!(
                block.height(),
                next_height,
                "finalized block height mismatch"
            );

            let (height, commitment) = (block.height(), block.digest());
            if self.pending_notarized_reports.contains(&commitment) {
                return;
            }
            let (ack, ack_waiter) = A::handle();

            if is_last_block_of_epoch(&self.epocher, next_height.get()) {
                let Some(finalization) = self.get_finalization_by_height(next_height).await else {
                    // The last block of an epoch will always have an explicit finalization certificate.
                    // The finalizer requires it for storing the finalized header.
                    self.floor
                        .fetch_if_permitted(resolver, Request::finalized(next_height))
                        .ignore();
                    return;
                };

                // The block and finalization are loaded independently by height
                // from two immutable archives. Re-verify the stored block is the
                // one this certificate finalizes before binding them into a
                // finalized-header report: a mismatch means the local archives are
                // inconsistent and must not be exported as a finalized header.
                if finalization.proposal.payload != commitment {
                    error!(
                        target: "critical",
                        %height,
                        stored_block = ?commitment,
                        certified = ?finalization.proposal.payload,
                        "finalized block does not match the stored finalization for its \
                         height; local archive inconsistency, halting dispatch"
                    );
                    return;
                }

                application.report(Update::FinalizedBlock((block, Some(finalization)), ack));
            } else {
                application.report(Update::FinalizedBlock((block, None), ack));
            }

            self.pending_acks.enqueue(PendingAck {
                height,
                commitment,
                receiver: ack_waiter,
            });
        }
    }

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(
        &mut self,
        round: Round,
        commitment: B::Digest,
        block: B,
    ) -> Handle<()> {
        self.notify_subscribers(commitment, &block);
        self.cache.put_verified(round, commitment, block).await
    }

    /// If a block previously accepted via [`Message::Proposed`] matches the
    /// supplied `(round, commitment)`, remove and return it.
    fn take_proposed(&mut self, round: Round, commitment: B::Digest) -> Option<B> {
        let (cached_round, cached_commitment, _) = self.last_proposed_block.as_ref()?;
        if *cached_round != round || *cached_commitment != commitment {
            return None;
        }
        self.last_proposed_block.take().map(|(_, _, block)| block)
    }

    /// Add a notarized block to the prunable archive.
    async fn cache_block(&mut self, round: Round, commitment: B::Digest, block: B) -> Handle<()> {
        self.notify_subscribers(commitment, &block);
        self.cache.put_block(round, commitment, block).await
    }

    // -------------------- Immutable Storage --------------------

    /// Sync both finalization archives to durable storage, blocking the actor.
    ///
    /// Must be called within the same `select_loop!` arm as any preceding
    /// [`Self::store_finalization`] / [`Self::try_repair_gaps`] writes, before yielding back
    /// to the loop.
    async fn sync_finalized(&mut self) {
        if let Err(e) = try_join!(
            async {
                self.finalized_blocks.sync().await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .sync()
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
        ) {
            panic!("failed to sync finalization archives: {e}");
        }
        self.dispatch_gate.clear();
    }

    /// Start a pooled sync covering all finalized writes buffered so far.
    ///
    /// Stores with a native non-blocking `start_sync` keep the actor responsive
    /// while durability is pending. Stores without one may complete the sync
    /// before returning the handle, as permitted by the storage trait.
    async fn start_finalized_sync(&mut self, round: Round, syncs: &mut Pool<PooledSync<B>>) {
        let Some(seq) = self.dispatch_gate.adopt() else {
            return;
        };
        let (blocks, finalizations) = try_join!(
            async {
                let handle = self.finalized_blocks.start_sync().await.map_err(Box::new)?;
                Ok::<_, BoxedError>(handle)
            },
            async {
                let handle = self
                    .finalizations_by_height
                    .start_sync()
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(handle)
            },
        )
        .unwrap_or_else(|e| panic!("failed to start finalization archive sync: {e}"));
        syncs.push(async move {
            let (blocks, finalizations) = join(
                blocks.durable(round, "finalized blocks"),
                finalizations.durable(round, "finalizations"),
            )
            .await;
            if blocks && finalizations {
                PooledSync::Finalized(seq)
            } else {
                PooledSync::Observed
            }
        });
    }

    /// Get a finalized block from the immutable archive.
    async fn get_finalized_block(&self, height: Height) -> Option<B> {
        match self
            .finalized_blocks
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: Height,
    ) -> Option<Finalization<P::Scheme, B::Digest>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Check whether a finalization exists at `height` without fetching it.
    async fn has_finalization_by_height(&self, height: Height) -> bool {
        match self.finalizations_by_height.has(height).await {
            Ok(has) => has,
            Err(e) => panic!("failed to check finalization: {e}"),
        }
    }

    /// Get finalized block information from either the finalization archive or
    /// the finalized-block archive.
    async fn get_info_by_height(&self, height: Height) -> Option<(Height, B::Digest)> {
        if let Some(finalization) = self.get_finalization_by_height(height).await {
            return Some((height, finalization.proposal.payload));
        }

        self.get_finalized_block(height)
            .await
            .map(|block| (block.height(), block.digest()))
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// Writes are buffered and not synced. Before yielding to the
    /// `select_loop!`, the caller must invoke either
    /// [`sync_finalized`](Self::sync_finalized) or
    /// [`start_finalized_sync`](Self::start_finalized_sync).
    ///
    /// Returns `true` if data was written and the archives need syncing.
    async fn store_finalization(
        &mut self,
        height: Height,
        commitment: B::Digest,
        block: B,
        finalization: Option<Finalization<P::Scheme, B::Digest>>,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
    ) -> bool {
        // Blocks below the last processed height are stale
        if height <= self.floor.processed_height() {
            debug!(
                %height,
                floor = %self.floor.processed_height(),
                ?commitment,
                "dropping finalization at or below processed height floor"
            );
            return false;
        }

        // Final guard binding the block header to its certificate round.
        //
        // The per-ingress checks (direct Finalized/Notarized delivery) reject
        // mismatches early, but a `(block, finalization)` pair becomes trusted
        // storage here regardless of which path produced it — including paths
        // that bypass those checks: a finalization cached first then the block
        // fetched later by digest (`Key::Block`), a consensus finalization
        // matched against a locally-found block, a notarized block paired with
        // a cached finalization, checkpoint restart, and gap repair. Enforcing
        // the binding at this join point ensures every order gets the same
        // protection. Normal blocks bind epoch and view exactly; a same-digest
        // reproposal of the epoch-terminal block may carry an older header view
        // than the certificate (see `header_view_binds_to_round`).
        if let Some(finalization) = &finalization {
            let certified_round = finalization.round();
            if finalization.proposal.payload != commitment
                || block.epoch() != certified_round.epoch()
                || !header_view_binds_to_round(
                    &self.epocher,
                    block.height().get(),
                    block.view().get(),
                    certified_round.view().get(),
                )
            {
                warn!(
                    ?certified_round,
                    block_height = %block.height(),
                    block_epoch = %block.epoch(),
                    block_view = %block.view(),
                    ?commitment,
                    "rejecting finalization store with header/certificate round mismatch"
                );
                return false;
            }
        }

        // The finalized-block archive is immutable: a duplicate index is silently
        // ignored on put. If a *different* block already occupies this height
        // (stale data-dir reuse, interrupted repair, corruption), the fresh block
        // put below would be dropped while the finalization archive accepts the
        // certificate, leaving them misbound. Reject the write so the two archives
        // can never reach a (stale block, fresh certificate) state. A re-delivery
        // of the same block is idempotent and proceeds.
        if let Some(existing) = self.get_finalized_block(height).await
            && existing.digest() != commitment
        {
            error!(
                target: "critical",
                %height,
                existing = ?existing.digest(),
                incoming = ?commitment,
                "finalized-block archive already holds a different block at this \
                 height; refusing to store a mismatched finalization"
            );
            return false;
        }

        self.notify_subscribers(commitment, &block);

        #[cfg(feature = "prom")]
        let store_start = Instant::now();

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            async {
                self.finalized_blocks.put(block).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put(height, commitment, finalization)
                        .await
                        .map_err(Box::new)?;
                }
                Ok::<_, BoxedError>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        self.dispatch_gate.defer(height);

        #[cfg(feature = "prom")]
        {
            let store_duration = store_start.elapsed().as_micros() as f64;
            histogram!("syncer_block_store_duration_micros").record(store_duration);
            counter!("syncer_blocks_stored_total").increment(1);
        }

        // Update metrics and send tip update to application
        if height > self.tip {
            let gap = height.get() - self.tip.get();
            if gap > 1 {
                debug!(
                    previous_tip = %self.tip,
                    new_tip = %height,
                    gap,
                    "tip advanced by multiple blocks (catch-up)"
                );
            }
            application.report(Update::Tip(height.get(), commitment));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        true
    }

    /// Get the latest finalized block information (height and commitment tuple).
    async fn get_latest(&mut self) -> Option<(Height, B::Digest)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((height, finalization.proposal.payload))
    }

    // -------------------- Mixed Storage --------------------

    /// Looks for a block anywhere in local storage.
    async fn find_block<K: PublicKey>(
        &self,
        buffer: &buffered::Mailbox<K, B>,
        commitment: B::Digest,
    ) -> Option<B> {
        // Check buffer.
        if let Some(block) = buffer.get(commitment).await {
            return Some((*block).clone());
        }
        // Check verified / notarized blocks via cache manager.
        if let Some(block) = self.cache.find_block(commitment).await {
            return Some(block);
        }
        // Check finalized blocks.
        match self.finalized_blocks.get(ArchiveID::Key(&commitment)).await {
            Ok(block) => block, // may be None
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive.
    ///
    /// Writes are buffered. Returns `true` if this call wrote repaired blocks and
    /// needs a subsequent [`sync_finalized`](Self::sync_finalized) or
    /// [`start_finalized_sync`](Self::start_finalized_sync).
    async fn try_repair_gaps<R, K>(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut R,
        application: &mut impl Reporter<Activity = Update<B, P::Scheme, A>>,
    ) -> bool
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
        K: PublicKey,
    {
        // Gap repair needs a known processed floor. A floor transition may
        // jump the lower bound once its anchor block arrives.
        if self.floor.blocks_progress() {
            return false;
        }

        let mut wrote = false;
        let start = self.floor.processed_height().next();
        'cache_repair: loop {
            let (gap_start, Some(gap_end)) = self.finalized_blocks.next_gap(start) else {
                // No gaps detected
                return wrote;
            };

            // Attempt to repair the gap backwards from the end of the gap, using
            // blocks from our local storage.
            let Some(mut cursor) = self.get_finalized_block(gap_end).await else {
                panic!("gapped block missing that should exist: {gap_end}");
            };

            // Compute the lower bound of the recursive repair.
            let gap_start = gap_start.map(|s| s.next()).unwrap_or(start);

            // Iterate backwards, repairing blocks as we go.
            while cursor.height() > gap_start {
                let commitment = cursor.parent();
                if let Some(block) = self.find_block(buffer, commitment).await {
                    let finalization = self.cache.get_finalization_for(commitment).await;
                    wrote |= self
                        .store_finalization(
                            block.height(),
                            commitment,
                            block.clone(),
                            finalization,
                            application,
                        )
                        .await;
                    debug!(
                        height = %block.height(),
                        gap_start = %gap_start,
                        gap_end = %gap_end,
                        "repaired missing block from local storage"
                    );
                    cursor = block;
                } else {
                    // Request the next missing block by commitment, bounding the
                    // request by the parent height derived from the child block.
                    let parent_height = cursor
                        .height()
                        .previous()
                        .expect("cursor above gap start has a parent");
                    debug!(
                        ?commitment,
                        target_height = %parent_height,
                        "requesting missing block from network for gap repair"
                    );
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_height(commitment, parent_height),
                        )
                        .ignore();
                    break 'cache_repair;
                }
            }
        }

        // Request any finalizations for missing items in the archive, up to
        // the `max_repair` quota.
        let missing_items = self
            .finalized_blocks
            .missing_items(start, self.max_repair.get());
        let requests: Vec<_> = missing_items.into_iter().map(Request::finalized).collect();
        if !requests.is_empty() {
            self.floor
                .fetch_all_if_permitted(resolver, requests)
                .ignore();
        }
        wrote
    }

    /// Buffers a processed height update in memory and metrics. Does NOT sync
    /// to durable storage. Sync metadata after buffered updates to make them durable.
    fn update_processed_height<R>(&mut self, height: Height, resolver: &mut R)
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
    {
        self.stream.acknowledge(height);
        self.floor.set_processed_height(height);
        let _ = self
            .processed_height
            .try_set(self.floor.processed_height().get());

        // Prune any existing requests below the new floor.
        resolver.retain(handler::above_height_floor::<B::Digest>(height));
    }

    /// Buffers a processed round update in memory and prunes round-bound requests.
    async fn update_processed_round<R>(&mut self, height: Height, resolver: &mut R)
    where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
    {
        let Some(finalization) = self.get_finalization_by_height(height).await else {
            return;
        };
        self.update_processed_round_floor(height, finalization.round(), resolver)
            .await;
    }

    /// Buffers a processed round floor update in memory and prunes round-bound requests.
    async fn update_processed_round_floor<R>(
        &mut self,
        height: Height,
        round: Round,
        resolver: &mut R,
    ) where
        R: Resolver<Key = Key<B::Digest>, Subscriber = Annotation>,
    {
        if height > self.floor.processed_height() || round <= self.floor.processed_round() {
            return;
        }

        let previous = self.floor.processed_round();
        self.floor.set_processed_round(round);

        // Retain view-indexed cache data for a window behind the previously
        // processed finalized block.
        let prune_round = Round::new(
            previous.epoch(),
            previous.view().saturating_sub(self.view_retention_timeout),
        );
        self.cache.prune_by_view(prune_round).await;

        // Prune round-bound requests at or below the processed round.
        resolver.retain(handler::above_round_floor::<B::Digest>(
            self.floor.processed_round(),
        ));
    }

    /// Prunes finalized blocks and certificates below the given height.
    async fn prune_finalized_archives(&mut self, height: Height) -> Result<(), BoxedError> {
        try_join!(
            async {
                self.finalized_blocks
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }

    /// Prunes finalized archives and height-indexed certified cache data below the durable floor.
    async fn prune_after_floor(&mut self, height: Height) -> Result<(), BoxedError> {
        let cache = &mut self.cache;
        let finalized_blocks = &mut self.finalized_blocks;
        let finalizations_by_height = &mut self.finalizations_by_height;
        try_join!(
            async {
                cache.prune_by_height(height).await;
                Ok::<_, BoxedError>(())
            },
            async {
                finalized_blocks.prune(height).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::header_view_binds_to_round;
    use commonware_consensus::types::FixedEpocher;
    use std::num::NonZeroU64;

    // Epoch length 10: epoch E spans heights [E*10, E*10 + 9], so the last block
    // of an epoch is E*10 + 9 (e.g. height 9 for epoch 0, height 19 for epoch 1).
    fn epocher() -> FixedEpocher {
        FixedEpocher::new(NonZeroU64::new(10).unwrap())
    }

    /// Regression for the sync/import side of "bind blocks to round": header view
    /// must equal the certified view, EXCEPT for a same-digest reproposal of the
    /// epoch-terminal block, where the reused bytes carry the original (earlier)
    /// view. Without the exception, catch-up rejects valid boundary reproposal
    /// certificates; without the strict check, a non-terminal block could carry a
    /// header view that disagrees with the round it was certified in.
    #[test]
    fn header_view_binding_relaxes_only_for_epoch_terminal_reproposals() {
        let e = epocher();
        const NON_TERMINAL: u64 = 5; // mid-epoch 0
        const TERMINAL: u64 = 9; // last block of epoch 0

        // Matching views always bind, terminal or not.
        assert!(header_view_binds_to_round(&e, NON_TERMINAL, 5, 5));
        assert!(header_view_binds_to_round(&e, TERMINAL, 9, 9));

        // Non-terminal block whose header view disagrees with the certified view
        // is rejected — this is the core invariant the issue is about.
        assert!(!header_view_binds_to_round(&e, NON_TERMINAL, 5, 7));

        // Epoch-terminal block re-certified in a LATER view is accepted: this is
        // the same-digest boundary reproposal that live verification accepts.
        assert!(header_view_binds_to_round(&e, TERMINAL, 9, 12));

        // But a terminal block whose header view is AHEAD of the certified view is
        // still rejected (a header view can never lead its certificate).
        assert!(!header_view_binds_to_round(&e, TERMINAL, 12, 9));
    }
}
