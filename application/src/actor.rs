use crate::{
    ApplicationConfig,
    ingress::{Mailbox, Message},
};
use anyhow::{Context, Result, anyhow};
use commonware_codec::EncodeSize;
use commonware_macros::select;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_utils::SystemTimeExt;
use commonware_utils::channel::mpsc;
use futures::{
    FutureExt,
    future::{self, Either, try_join},
};
use rand::Rng;
use tokio_util::sync::CancellationToken;

use commonware_consensus::simplex::Plan;
use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::types::{Epoch, Epocher, Round, View};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{PublicKey, Signer};
use std::marker::PhantomData;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use summit_finalizer::FinalizerMailbox;
use tracing::{debug, error, info, warn};

#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use summit_syncer::ingress::mailbox::Mailbox as SyncerMailbox;
use summit_types::{Block, BlockAuxData, Digest, EngineClient};

/// How long to wait before retrying check_payload when Reth returns SYNCING during certify.
const CERTIFY_SYNCING_RETRY: Duration = Duration::from_millis(100);

fn proposal_timestamp_wait(
    now_millis: u64,
    min_child_timestamp: u64,
    allowed_timestamp_future_ms: u64,
) -> Duration {
    // Verifiers accept timestamps up to `now + allowed_timestamp_future_ms`.
    // If the minimum monotonic child timestamp is beyond that bound, wait just
    // long enough for it to enter the verifier's future window.
    let max_allowed_timestamp = now_millis.saturating_add(allowed_timestamp_future_ms);
    Duration::from_millis(min_child_timestamp.saturating_sub(max_allowed_timestamp))
}

fn select_proposal_timestamp(now_millis: u64, min_child_timestamp: u64) -> u64 {
    // Once `min_child_timestamp` is inside the verifier future window, choose
    // the later of local time and `parent.timestamp + 1` to preserve monotonicity.
    now_millis.max(min_child_timestamp)
}

/// Whether the wait required to bring the monotonic child timestamp into the
/// verifier future window exceeds the leader window. When true the block could
/// not be notarized before the leader rotates anyway, so the proposal should be
/// abandoned rather than waited out (which would also tie up the application
/// actor, delaying verify/certify handling).
fn proposal_wait_exceeds_leader_window(wait: Duration, leader_timeout: Duration) -> bool {
    wait > leader_timeout
}

pub struct Actor<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    S: Scheme<Digest>,
    P: PublicKey,
    K: Signer,
    V: Variant,
    ES: Epocher,
> {
    context: ContextCell<R>,
    mailbox: mpsc::Receiver<Message<P>>,
    engine_client: C,
    genesis_hash: [u8; 32],
    max_message_size_bytes: u32,
    epocher: ES,
    cancellation_token: CancellationToken,
    leader_timeout: Duration,
    #[cfg(feature = "permissioned")]
    paused: Arc<AtomicBool>,
    _scheme_marker: PhantomData<S>,
    _key_marker: PhantomData<P>,
    _signer_marker: PhantomData<K>,
    _variant_marker: PhantomData<V>,
}

impl<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    S: Scheme<Digest, PublicKey = P>,
    P: PublicKey,
    K: Signer,
    V: Variant,
    ES: Epocher,
> Actor<R, C, S, P, K, V, ES>
{
    pub async fn new(context: R, cfg: ApplicationConfig<C, ES>) -> (Self, Mailbox<P>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);

        let genesis_hash = cfg.genesis_hash;

        (
            Self {
                context: ContextCell::new(context),
                mailbox: rx,
                engine_client: cfg.engine_client,
                genesis_hash,
                max_message_size_bytes: cfg.max_message_size_bytes,
                epocher: cfg.epocher,
                cancellation_token: cfg.cancellation_token,
                leader_timeout: cfg.leader_timeout,
                #[cfg(feature = "permissioned")]
                paused: cfg.paused,
                _scheme_marker: PhantomData,
                _key_marker: PhantomData,
                _signer_marker: PhantomData,
                _variant_marker: PhantomData,
            },
            Mailbox::new(tx),
        )
    }

    pub fn start(
        mut self,
        syncer: SyncerMailbox<S, Block>,
        finalizer: FinalizerMailbox<S, Block>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(syncer, finalizer))
    }

    pub async fn run(
        mut self,
        mut syncer: SyncerMailbox<S, Block>,
        mut finalizer: FinalizerMailbox<S, Block>,
    ) {
        let rand_id: u8 = rand::random();
        let mut signal = self.context.stopped().fuse();
        let cancellation_token = self.cancellation_token.clone();
        loop {
            select! {
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        break;
                    };
                    match message {
                        Message::Genesis { response, epoch } => {
                            if epoch.get() == 0 {
                                let _ = response.send(self.genesis_hash.into());
                            } else {
                                let epoch_genesis_hash = finalizer
                                    .get_epoch_genesis_hash(epoch.get())
                                    .await
                                    .await
                                    .expect("failed to get epoch genesis hash from finalizer");
                                let _ = response.send(epoch_genesis_hash.into());
                            }
                        }
                        Message::Propose {
                            round,
                            parent,
                            mut response,
                        } => {
                            #[cfg(feature = "permissioned")]
                            if self.paused.load(Ordering::Relaxed) {
                                warn!("consensus paused, skipping proposal for round {round}");
                                continue;
                            }

                            debug!("{rand_id} application: Handling message Propose for round {} (epoch {}, view {}), parent view: {}",
                                round, round.epoch(), round.view(), parent.0);

                            #[cfg(feature = "prom")]
                            let proposal_start = std::time::Instant::now();

                            select! {
                                    res = self.handle_proposal(parent, &mut syncer, &mut finalizer, round) => {
                                        match res {
                                            Ok(block) => {
                                                let digest = block.digest();
                                                let height = block.height();
                                                let tx_count = block.payload.payload_inner.payload_inner.transactions.len();

                                                info!(
                                                    height,
                                                    epoch = round.epoch().get(),
                                                    view = round.view().get(),
                                                    tx_count,
                                                    "proposed block"
                                                );

                                                // Return the digest to consensus immediately. The
                                                // block is already built, so caching and broadcasting
                                                // via the syncer is auxiliary work that must not sit on
                                                // the proposal response path or block the application
                                                // loop behind a full or slow syncer mailbox.
                                                // It runs off the loop with guaranteed (not lossy)
                                                // delivery so the block is still reliably cached and
                                                // broadcast.
                                                let _ = response.send(digest);

                                                self.context.child("proposed").spawn({
                                                    let mut syncer = syncer.clone();
                                                    move |_| async move {
                                                        if !syncer.proposed(round, block).await {
                                                            warn!(?round, "syncer dropped proposed-block durability ack");
                                                        }
                                                    }
                                                });
                                            },
                                            Err(e) => warn!("Failed to create a block for round {round}: {e}")
                                        }
                                    },
                                    _ = response.closed() => {
                                        // simplex dropped receiver
                                        #[cfg(feature = "prom")]
                                        {
                                            let elapsed = proposal_start.elapsed();
                                            warn!(
                                                round = ?round,
                                                parent_view = parent.0.get(),
                                                parent_digest = ?parent.1,
                                                elapsed_ms = elapsed.as_millis(),
                                                "proposal aborted - consensus timed out waiting for block (possible notarize-nullify race)"
                                            );
                                            counter!("proposal_timeout_total").increment(1);
                                            histogram!("proposal_timeout_elapsed_ms").record(elapsed.as_millis() as f64);
                                        }

                                        #[cfg(not(feature = "prom"))]
                                        warn!(
                                            round = ?round,
                                            parent_view = parent.0.get(),
                                            parent_digest = ?parent.1,
                                            "proposal aborted - consensus timed out waiting for block (possible notarize-nullify race)"
                                        );
                                    }
                            }
                        }
                        Message::Broadcast { payload, plan } => {
                            #[cfg(feature = "permissioned")]
                            if self.paused.load(Ordering::Relaxed) {
                                warn!("consensus paused, skipping broadcast");
                                continue;
                            }

                            match plan {
                                // Our own proposal was already handed to syncer.proposed()
                                // at propose time (dispatched off the loop right after the
                                // digest was returned), which caches and broadcasts it.
                                Plan::Propose { .. } => {
                                    debug!(?payload, "{rand_id} Broadcast(Propose): already broadcast at propose time");
                                }
                                // Push the certified block to voters consensus has
                                // identified as missing it (ForwardingPolicy::SilentVoters).
                                // `forward` is a synchronous, non-blocking enqueue into the
                                // overflow-buffered syncer mailbox, so it can run directly on
                                // the application loop without blocking later
                                // Propose/Verify/Certify messages.
                                Plan::Forward { round, recipients } => {
                                    debug!(?round, "{rand_id} Broadcast(Forward): forwarding to silent voters");
                                    let _ = syncer.forward(round, payload, recipients);
                                }
                            }
                        }

                        Message::Certify {
                            round,
                            payload,
                            mut response,
                        } => {
                            #[cfg(feature = "permissioned")]
                            if self.paused.load(Ordering::Relaxed) {
                                warn!("consensus paused, rejecting certify for round {round}");
                                let _ = response.send(false);
                                continue;
                            }

                            debug!("{rand_id} application: Handling message Certify for round {} (epoch {}, view {})",
                                round, round.epoch(), round.view());

                            self.context.child("certify").spawn({
                                let mut syncer = syncer.clone();
                                let mut finalizer_clone = finalizer.clone();
                                let mut engine_client = self.engine_client.clone();
                                let genesis_hash = self.genesis_hash;
                                let max_message_size_bytes = self.max_message_size_bytes;
                                move |context| async move {
                                    // Subscribe inside the task; the enqueue is synchronous and
                                    // non-blocking (overflow-buffered syncer mailbox).
                                    let block_request = syncer.subscribe(Some(round), payload);
                                    let work = async {
                                        let Ok(block) = block_request.await else {
                                            warn!(?round, "certify: failed to receive block from syncer");
                                            return false;
                                        };

                                        if let Some((block_size_bytes, max_block_size_bytes)) =
                                            block_size_limit_violation(
                                                &block,
                                                max_message_size_bytes,
                                            )
                                        {
                                            warn!(
                                                ?round,
                                                height = block.height(),
                                                block_size_bytes,
                                                max_block_size_bytes,
                                                max_message_size_bytes,
                                                "certify: block violates P2P block size limit"
                                            );
                                            return false;
                                        }

                                        // Wait for parent to be executed so its state is in Reth
                                        // before check_payload runs on the child.
                                        let parent_digest = block.parent();
                                        if parent_digest != genesis_hash.into() {
                                            let parent_height = block.height().saturating_sub(1);
                                            // `notify_at_height` blocks while the finalizer is
                                            // merely behind (it resolves true once the parent is
                                            // executed). A false/dropped result means the
                                            // finalizer does not have this parent on its chain, which
                                            // indicates a non-canonical fork, a digest mismatch,
                                            // or the request was dropped.
                                            let parent_confirmed = finalizer_clone
                                                .notify_at_height(parent_height, parent_digest)
                                                .await
                                                .await
                                                .unwrap_or(false);
                                            if !parent_confirmed {
                                                warn!(
                                                    ?round,
                                                    parent_height,
                                                    ?parent_digest,
                                                    "certify: finalizer did not confirm parent on its chain (superseded, fork, or digest mismatch)"
                                                );
                                                return false;
                                            }
                                        }

                                        #[cfg(feature = "prom")]
                                        let check_start = std::time::Instant::now();

                                        let valid = loop {
                                            let status = match engine_client.check_payload(&block).await {
                                                Ok(status) => status,
                                                Err(e) => {
                                                    error!(
                                                        target: "critical",
                                                        ?round,
                                                        height = block.height(),
                                                        "certify: engine client error on check_payload: {e}"
                                                    );
                                                    #[cfg(feature = "prom")]
                                                    counter!("critical_errors_total", "reason" => "engine_client_error", "severity" => "critical")
                                                        .increment(1);
                                                    break false;
                                                }
                                            };
                                            if status.is_syncing() {
                                                warn!(
                                                    ?round,
                                                    height = block.height(),
                                                    "certify: execution client returned SYNCING, retrying"
                                                );
                                                #[cfg(feature = "prom")]
                                                counter!("certify_syncing_total").increment(1);
                                                context.sleep(CERTIFY_SYNCING_RETRY).await;
                                                continue;
                                            }
                                            break status.is_valid();
                                        };

                                        #[cfg(feature = "prom")]
                                        {
                                            let elapsed = check_start.elapsed().as_millis() as f64;
                                            histogram!("certify_check_payload_duration_millis").record(elapsed);
                                            if !valid {
                                                counter!("certify_invalid_total").increment(1);
                                            }
                                        }

                                        if !valid {
                                            warn!(
                                                ?round,
                                                height = block.height(),
                                                "certify: payload rejected by execution client"
                                            );
                                        }
                                        valid
                                    };

                                    select! {
                                        result = work => {
                                            let _ = response.send(result);
                                        },
                                        _ = response.closed() => {
                                            warn!("certify aborted for round {round}");
                                        }
                                    }
                                }
                            });
                        }

                        Message::Verify {
                            round,
                            parent,
                            payload,
                            mut response,
                        } => {
                            #[cfg(feature = "permissioned")]
                            if self.paused.load(Ordering::Relaxed) {
                                warn!("consensus paused, rejecting verify for round {round}");
                                let _ = response.send(false);
                                continue;
                            }

                            debug!("{rand_id} application: Handling message Verify for round {} (epoch {}, view {}), parent view: {}",
                                round, round.epoch(), round.view(), parent.0);

                            // The parent view signed into the proposal context, captured
                            // before `parent` is moved into the verify task below (the task's
                            // `move` closure copies this Copy `u64` for `handle_verify`).
                            let signed_parent_view = parent.0.get();

                            // Wait for the blocks in a separate task: the subscribe enqueues
                            // are non-blocking, but awaiting their responses on the
                            // application loop would block it from dequeuing later consensus
                            // messages until the blocks arrive.
                            let genesis_hash = self.genesis_hash;
                            self.context.child("verify").spawn({
                                let mut syncer = syncer.clone();
                                let mut finalizer_clone = finalizer.clone();
                                let epocher = self.epocher.clone();
                                let max_message_size_bytes = self.max_message_size_bytes;
                                move |context| async move {
                                    // Subscribe to blocks (will wait for them if not available)
                                    let parent_request = if parent.1 == genesis_hash.into() {
                                        Either::Left(future::ready(Ok(Block::genesis(genesis_hash))))
                                    } else {
                                        let parent_round = if parent.0.get() == 0 {
                                            // Parent view is 0, which means that this is the first block of the epoch
                                            None
                                        } else {
                                            Some(Round::new(round.epoch(), parent.0))
                                        };
                                        Either::Right(syncer.subscribe(parent_round, parent.1))
                                    };
                                    let block_request = syncer.subscribe(Some(round), payload);

                                    let requester = try_join(parent_request, block_request);
                                    select! {
                                        result = requester => {
                                            // The syncer drops (cancels) a block subscription for a
                                            // round older than its last_processed_round, so a stale
                                            // verify path can see the request canceled. Treat that as
                                            // a terminal "cannot verify" (vote false) rather than an
                                            // invariant violation.
                                            let Ok((parent, block)) = result else {
                                                warn!(?round, "verify aborted: block subscription canceled (likely stale round)");
                                                let _ = response.send(false);
                                                return;
                                            };

                                            let parent_digest = parent.digest();
                                            let parent_height = parent.height();

                                            // Wait for the parent to be executed so its state is
                                            // available for aux_data. `notify_at_height` blocks
                                            // while the finalizer is merely behind (it resolves
                                            // true once the parent is executed). A false/dropped
                                            // result means the finalizer does not have this parent
                                            // on its chain, which indicates a non-canonical fork, a
                                            // digest mismatch, or the request was dropped.
                                            let parent_confirmed = finalizer_clone
                                                .notify_at_height(parent_height, parent_digest)
                                                .await
                                                .await
                                                .unwrap_or(false);

                                            if !parent_confirmed {
                                                warn!(
                                                    ?round,
                                                    parent_height,
                                                    ?parent_digest,
                                                    "verify: finalizer did not confirm parent on its chain (superseded, fork, or digest mismatch)"
                                                );
                                                let _ = response.send(false);
                                                return;
                                            }

                                            // Request aux data for the block we're verifying
                                            #[cfg(feature = "prom")]
                                            let aux_data_start = std::time::Instant::now();
                                            let maybe_aux_data = finalizer_clone
                                                .get_aux_data(parent_height + 1, parent_digest)
                                                .await
                                                .await
                                                .expect("Finalizer dropped");

                                            if let Some(aux_data) = maybe_aux_data {
                                                #[cfg(feature = "prom")]
                                                {
                                                    let aux_data_duration = aux_data_start.elapsed().as_millis() as f64;
                                                    histogram!("handle_verify_aux_data_duration_millis").record(aux_data_duration);
                                                }

                                                let now_millis = context.current().epoch_millis();
                                                if handle_verify(
                                                    round,
                                                    &block,
                                                    parent,
                                                    signed_parent_view,
                                                    &epocher,
                                                    &aux_data,
                                                    now_millis,
                                                    max_message_size_bytes,
                                                ) {
                                                    // Respond to consensus first. The vote is decided,
                                                    // so persisting and broadcasting the valid block via
                                                    // the syncer is auxiliary work that must not sit on
                                                    // the vote response path behind a full or slow
                                                    // syncer mailbox. This task already runs off the
                                                    // application loop, so awaiting the send after
                                                    // responding blocks nothing consensus critical.
                                                    let _ = response.send(true);

                                                    // persist valid block off the vote response path
                                                    if !syncer.verified(round, block).await {
                                                        warn!(?round, "syncer dropped verified-block durability ack");
                                                    }
                                                } else {
                                                    info!("Unsuccessful vote for round {round} because the block is invalid");
                                                    let _ = response.send(false);
                                                }
                                            } else {
                                                info!(
                                                    "Unsuccessful vote for round {round} because of an outdated height notification",
                                                );
                                                let _ = response.send(false);
                                            }
                                        },
                                        _ = response.closed() => {
                                            warn!("verify aborted for round {round}");
                                        }
                                    }
                                }
                            });
                        }
                    }
                },
                _ = cancellation_token.cancelled() => {
                    info!("application received cancellation signal, exiting");
                    break;
                },
                sig = &mut signal => {
                    info!("runtime terminated, shutting down application: {}", sig.unwrap());
                    break;
                }
            }
        }
    }

    fn ensure_proposed_block_within_p2p_limit(&self, block: &Block, round: Round) -> Result<()> {
        if let Some((block_size_bytes, max_block_size_bytes)) =
            block_size_limit_violation(block, self.max_message_size_bytes)
        {
            return Err(anyhow!(
                "proposed block violates P2P block size limit for round {round} at height {}: block size {block_size_bytes} bytes must be smaller than {max_block_size_bytes} bytes (max_message_size_bytes = {})",
                block.height(),
                self.max_message_size_bytes,
            ));
        }

        Ok(())
    }

    async fn handle_proposal(
        &mut self,
        parent: (View, Digest),
        syncer: &mut SyncerMailbox<S, Block>,
        finalizer: &mut FinalizerMailbox<S, Block>,
        round: Round,
    ) -> Result<Block> {
        #[cfg(feature = "prom")]
        let proposal_start = std::time::Instant::now();

        // STEP 1: Get the parent block
        debug!(
            ?round,
            parent_view = parent.0.get(),
            parent_digest = ?parent.1,
            "proposal step 1: fetching parent block"
        );
        #[cfg(feature = "prom")]
        let parent_fetch_start = std::time::Instant::now();
        let parent_block = if parent.1 == self.genesis_hash.into() {
            Either::Left(future::ready(Ok(Block::genesis(self.genesis_hash))))
        } else {
            let parent_round = if parent.0.get() == 0 {
                // Parent view is 0, which means that this is the first block of the epoch
                None
            } else {
                Some(Round::new(round.epoch(), parent.0))
            };
            Either::Right(
                syncer
                    .subscribe(parent_round, parent.1)
                    .map(|x| x.context("parent block subscription canceled")),
            )
        };
        // The syncer cancels (drops) a subscription for a round older than its
        // last_processed_round. Propagate that as an Err so the Propose handler
        // aborts the proposal gracefully instead of panicking.
        let parent_block = parent_block.await?;

        #[cfg(feature = "prom")]
        {
            let parent_fetch_duration = parent_fetch_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_parent_fetch_duration_millis")
                .record(parent_fetch_duration);
        }

        // STEP 2: Wait for finalizer notification
        debug!(
            ?round,
            parent_height = parent_block.height(),
            parent_digest = ?parent_block.digest(),
            "proposal step 2: waiting for finalizer notification"
        );
        #[cfg(feature = "prom")]
        let finalizer_wait_start = std::time::Instant::now();
        // now that we have the parent additionally await for that to be executed by the finalizer
        let parent_height = parent_block.height();
        let parent_digest = parent_block.digest();
        let rx = finalizer
            .notify_at_height(parent_height, parent_digest)
            .await;
        // await for notification
        if !rx.await.expect("Finalizer dropped") {
            debug!(
                "Aborting block proposal for epoch {} and height {} because of an outdated height notification",
                round.epoch().get(),
                parent_height + 1,
            );
            return Err(anyhow!(
                "Aborting block proposal for epoch {} and height {} because of an outdated height notification",
                round.epoch().get(),
                parent_height + 1,
            ));
        }
        #[cfg(feature = "prom")]
        {
            let finalizer_wait_duration = finalizer_wait_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_finalizer_wait_duration_millis")
                .record(finalizer_wait_duration);
        }

        // STEP 3: Request aux data (withdrawals, checkpoint hash, header hash)
        debug!(
            ?round,
            parent_height, "proposal step 3: requesting aux data"
        );
        #[cfg(feature = "prom")]
        let aux_data_start = std::time::Instant::now();
        let maybe_aux_data = finalizer
            .get_aux_data(parent_height + 1, parent_digest)
            .await
            .await
            .expect("Finalizer dropped");

        let Some(aux_data) = maybe_aux_data else {
            debug!(
                "Aborting block proposal for epoch {} and height {} because of an outdated aux data request",
                round.epoch().get(),
                parent_height + 1,
            );
            return Err(anyhow!(
                "Aborting block proposal for epoch {} and height {} because of an outdated aux data request",
                round.epoch().get(),
                parent_height + 1,
            ));
        };

        #[cfg(feature = "prom")]
        {
            let aux_data_duration = aux_data_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_aux_data_duration_millis").record(aux_data_duration);
        }

        if aux_data.epoch != round.epoch().get() {
            // This might happen because the finalizer notifies the orchestrator at the end of an
            // epoch to shut down Simplex. While Simplex is being shutdown, it will still continue to produce blocks.
            return Err(anyhow!(
                "Aborting block proposal for height {} and epoch {}. Current epoch is {}",
                parent_height + 1,
                round.epoch().get(),
                aux_data.epoch,
            ));
        }

        // Special case: If the parent block is the last block in the epoch,
        // re-propose it as to not produce any blocks that will be cut out
        // by the epoch transition.
        let last_in_epoch = self
            .epocher
            .last(Epoch::new(aux_data.epoch))
            .expect("epoch should exist");
        if parent_block.height() == last_in_epoch.get() {
            debug!(round = ?round, digest = ?parent_block.digest(), "re-proposed parent block at epoch boundary");
            self.ensure_proposed_block_within_p2p_limit(&parent_block, round)?;
            return Ok(parent_block);
        }

        let pending_withdrawals = aux_data.withdrawals;
        let checkpoint_hash = aux_data.checkpoint_hash;

        let min_child_timestamp = parent_block
            .timestamp()
            .checked_add(1)
            .ok_or_else(|| anyhow!("parent timestamp overflow"))?;

        // If the wait needed to bring `min_child_timestamp` into the verifier
        // future window exceeds the leader window, abandon the proposal now. The
        // block could not be notarized before the leader rotates, and sleeping
        // that long inside the actor loop would also delay verify/certify
        // handling. This abandons proposal creation only; it never bypasses the
        // timestamp wait below — when we do proceed, we still build only once
        // `parent.timestamp() + 1` is inside the verifier future window.
        let initial_wait = proposal_timestamp_wait(
            self.context.current().epoch_millis(),
            min_child_timestamp,
            aux_data.allowed_timestamp_future_ms,
        );
        if proposal_wait_exceeds_leader_window(initial_wait, self.leader_timeout) {
            return Err(anyhow!(
                "proposal timestamp wait {}ms exceeds leader timeout {}ms for round {round}; \
                 abandoning proposal",
                initial_wait.as_millis(),
                self.leader_timeout.as_millis()
            ));
        }

        let current = loop {
            // Do not ask the engine to build a payload until the timestamp we
            // must use to be greater than the parent is also acceptable to peers.
            let now_millis = self.context.current().epoch_millis();
            let wait = proposal_timestamp_wait(
                now_millis,
                min_child_timestamp,
                aux_data.allowed_timestamp_future_ms,
            );
            if wait.is_zero() {
                break select_proposal_timestamp(now_millis, min_child_timestamp);
            }
            debug!(
                ?round,
                parent_height,
                wait_ms = wait.as_millis(),
                "waiting for proposal timestamp to enter verifier future window"
            );
            self.context.sleep(wait).await;
        };

        // STEP 4: Start building block (Engine Client)
        debug!(
            ?round,
            parent_height,
            epoch = aux_data.epoch,
            "proposal step 4: building block via engine client"
        );
        #[cfg(feature = "prom")]
        let start_building_start = std::time::Instant::now();

        //  aux_data.forkchoice.head_block_hash = parent_block.eth_block_hash().into();

        // Add the EIP-4895 withdrawals (re-clamped payouts) to the block.
        let withdrawals = pending_withdrawals;
        let payload_id = {
            #[cfg(feature = "bench")]
            {
                self.engine_client
                    .start_building_block(
                        aux_data.forkchoice,
                        // Using millis for the timestamp is done on purpose.
                        // This is handled downstream in seismic-reth and seismic-revm.
                        current,
                        withdrawals,
                        aux_data.suggested_fee_recipient,
                        None,
                        parent_block.height(),
                    )
                    .await
            }
            #[cfg(not(feature = "bench"))]
            {
                self.engine_client
                    .start_building_block(
                        aux_data.forkchoice,
                        current,
                        withdrawals,
                        aux_data.suggested_fee_recipient,
                        Some(aux_data.state_root.into()),
                    )
                    .await
            }
        }
        .map_err(|e| anyhow!("engine client error on start_building_block: {e}"))?
        .ok_or(anyhow!("Unable to build payload"))?;

        #[cfg(feature = "prom")]
        {
            let start_building_duration = start_building_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_start_building_duration_millis")
                .record(start_building_duration);
        }

        self.context.sleep(Duration::from_millis(50)).await;

        // STEP 5: Get payload (Engine Client)
        #[cfg(feature = "prom")]
        let get_payload_start = std::time::Instant::now();
        let payload_envelope = self
            .engine_client
            .get_payload(payload_id)
            .await
            .map_err(|e| anyhow!("engine client error on get_payload: {e}"))?;
        #[cfg(feature = "prom")]
        {
            let get_payload_duration = get_payload_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_get_payload_duration_millis").record(get_payload_duration);
        }

        // STEP 6: Compute block digest
        #[cfg(feature = "prom")]
        let compute_digest_start = std::time::Instant::now();

        // EIP-7685 requires the request list to be ordered by request type byte in
        // ascending order. Sort defensively so a block we author is spec-compliant
        // even if the execution client returns the list out of order (e.g. the
        // protocol-param type 0xFF before withdrawals 0x01 / consolidations 0x02).
        // This is safe: the EL's `requests_hash` sorts internally, so reordering the
        // raw list does not change the committed EL block hash.
        let mut execution_requests = payload_envelope.execution_requests.to_vec();
        execution_requests.sort_by_key(|req| req.first().copied().unwrap_or(0));

        let block = Block::compute_digest(
            parent_block.digest(),
            parent_block.height() + 1,
            current,
            payload_envelope.envelope_inner.execution_payload,
            execution_requests,
            round.epoch().get(),
            round.view().get(),
            checkpoint_hash,
            aux_data.header_hash,
            aux_data.added_validators,
            aux_data.removed_validators,
            aux_data.state_root,
        );

        #[cfg(feature = "prom")]
        {
            let compute_digest_duration = compute_digest_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_compute_digest_duration_millis")
                .record(compute_digest_duration);
        }

        #[cfg(feature = "prom")]
        {
            let proposal_duration = proposal_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_duration_millis").record(proposal_duration);
        }
        self.ensure_proposed_block_within_p2p_limit(&block, round)?;
        Ok(block)
    }
}

impl<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    S: Scheme<Digest>,
    P: PublicKey,
    K: Signer,
    V: Variant,
    ES: Epocher,
> Drop for Actor<R, C, S, P, K, V, ES>
{
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}

/// Returns `true` if the EIP-7685 execution-request list is ordered by request
/// type byte in strictly ascending order, with no empty or request_data-less
/// elements.
///
/// The engine API requires request-list elements to be sorted by type
/// (`OutOfOrderExecutionRequest` / `DuplicatedExecutionRequestType` otherwise) and
/// to carry non-empty request data (`EmptyExecutionRequest` otherwise, for
/// elements of one byte or shorter). Seismic's protocol-param request (type
/// `0xFF`) is the maximum type, so it must come last. We sort the list we
/// propose; this predicate lets us reject a peer's block that violates these
/// rules rather than relaying it into a payload the EL will refuse. A single
/// type byte with no data must be caught here, since the EL would treat it as
/// a fatal engine error rather than a block-level invalid payload.
fn execution_requests_ascending(requests: &[impl AsRef<[u8]>]) -> bool {
    let mut prev: Option<u8> = None;
    for req in requests {
        let req = req.as_ref();
        // A bare type byte has no request_data. The EL rejects it with
        // `EmptyExecutionRequest`, so surface it as a block rejection here.
        if req.len() <= 1 {
            return false;
        }
        let request_type = req[0];
        if prev.is_some_and(|p| request_type <= p) {
            // Out of order or a duplicate request type.
            return false;
        }
        prev = Some(request_type);
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn handle_verify<ES: Epocher>(
    round: Round,
    block: &Block,
    parent: Block,
    // The parent view signed into the Commonware proposal context
    // (`context.parent.0`), bound below to the fetched parent block's decoded view.
    signed_parent_view: u64,
    epocher: &ES,
    aux_data: &BlockAuxData,
    now_millis: u64,
    max_message_size_bytes: u32,
) -> bool {
    if round.epoch().get() != aux_data.epoch {
        warn!(
            "epoch mismatch: simplex epoch {}, finalizer epoch: {}",
            round.epoch().get(),
            aux_data.epoch
        );
        return false;
    }
    if let Some((block_size_bytes, max_block_size_bytes)) =
        block_size_limit_violation(block, max_message_size_bytes)
    {
        warn!(
            height = block.height(),
            block_size_bytes,
            max_block_size_bytes,
            max_message_size_bytes,
            "verify: block violates P2P block size limit"
        );
        return false;
    }
    // You can only re-propose the same block iff it's the last height in the epoch.
    let last_in_epoch = epocher
        .last(Epoch::new(aux_data.epoch))
        .expect("epoch should exist")
        .get();
    if parent.digest() == block.digest() {
        return block.height() == last_in_epoch;
    }
    // Bind the signed Commonware parent view to the fetched parent block's
    // decoded view so the certificate's ancestry and the Summit header chain
    // agree. The same-digest boundary re-proposal handled above (already
    // returned) is exempt, since the terminal block is re-certified at a later
    // view than its decoded view.
    //
    // The signed parent view of 0 (the `parent.0 == 0` sentinel) is only
    // legitimate when the child actually opens an epoch: its parent is either
    // the genesis block or the previous epoch's terminal block, which lives in
    // a different view space. We must not let the sentinel blanket-skip the
    // binding, or a mid-epoch proposal could set parent view 0 to bypass it
    // entirely. Epochs are contiguous height ranges of length >= 1 (`DynamicEpocher`
    // rejects zero-length segments), so an epoch opener's parent always sits in
    // the immediately preceding epoch. We compare against `round.epoch()` (the
    // trusted consensus value) rather than `block.epoch()` (an attacker-controlled
    // header field only validated against the round below).
    if signed_parent_view == 0 {
        let opens_epoch = parent.height() == 0 || parent.epoch() + 1 == round.epoch().get();
        if !opens_epoch {
            warn!(
                parent_epoch = parent.epoch(),
                round_epoch = round.epoch().get(),
                "signed parent view 0 on a block that does not open an epoch"
            );
            return false;
        }
    } else if parent.epoch() != round.epoch().get() || parent.view() != signed_parent_view {
        warn!(
            signed_parent_view,
            parent_view = parent.view(),
            parent_epoch = parent.epoch(),
            round_epoch = round.epoch().get(),
            "parent view mismatch: signed proposal parent view does not match the fetched parent block"
        );
        return false;
    }
    if block.height() > last_in_epoch {
        warn!(
            block_height = block.height(),
            last_in_epoch, "rejecting non-reproposal child past epoch boundary"
        );
        return false;
    }
    // Basic structural validation
    if block.view() != round.view().get() {
        warn!(
            "block view mismatch: expected: {}, received: {}",
            round.view().get(),
            block.view()
        );
        return false;
    }
    if block.epoch() != round.epoch().get() {
        warn!(
            "block epoch mismatch: expected: {}, received: {}",
            round.epoch().get(),
            block.epoch()
        );
        return false;
    }
    if block.parent() != parent.digest() {
        warn!(
            "block parent mismatch: expected: {}, received: {}",
            parent.digest(),
            block.parent()
        );
        return false;
    }
    if block.eth_parent_hash() != parent.eth_block_hash() {
        warn!(
            expected = ?parent.eth_block_hash(),
            actual = ?block.eth_parent_hash(),
            "eth_parent_hash mismatch"
        );
        return false;
    }
    if block.height() != parent.height() + 1 {
        warn!(
            "block height mismatch: expected: {}, received: {}",
            parent.height() + 1,
            block.height()
        );
        return false;
    }
    if block.timestamp() <= parent.timestamp() {
        warn!(
            "block timestamp not increasing: parent timestamp is {}, block timestamp is {}",
            parent.timestamp(),
            block.timestamp()
        );
        return false;
    }
    if block.timestamp() > now_millis + aux_data.allowed_timestamp_future_ms {
        warn!(
            block_timestamp = block.timestamp(),
            now_millis,
            allowed_timestamp_future_ms = aux_data.allowed_timestamp_future_ms,
            "block timestamp too far in the future"
        );
        return false;
    }
    if block.header.prev_epoch_header_hash() != aux_data.header_hash {
        warn!(
            "prev_epoch_header_hash mismatch: expected: {:?}, received: {:?}",
            aux_data.header_hash,
            block.header.prev_epoch_header_hash()
        );
        return false;
    }

    // Bind the embedded EL payload's metadata to the Summit header.
    let payload_block_number = block.payload.payload_inner.payload_inner.block_number;
    if payload_block_number != block.height() {
        warn!(
            header_height = block.height(),
            payload_block_number, "payload.block_number does not match header.height"
        );
        return false;
    }
    let payload_timestamp = block.payload.payload_inner.payload_inner.timestamp;
    if payload_timestamp != block.timestamp() {
        warn!(
            header_timestamp = block.timestamp(),
            payload_timestamp, "payload.timestamp does not match header.timestamp"
        );
        return false;
    }

    // Validate consensus trie state root
    if block.header.parent_beacon_block_root() != aux_data.state_root {
        warn!(
            expected = ?aux_data.state_root,
            actual = ?block.header.parent_beacon_block_root(),
            "parent_beacon_block_root mismatch"
        );
        return false;
    }

    // Validate fee recipient against treasury when set. When treasury is zero
    // the policy falls back to the proposer's withdrawal credentials.
    // In this case the proposer may choose any withdrawal credentials, so
    // the check is only performed when the treasure address is non-zero.
    if !aux_data.treasury_address.is_zero() {
        let actual_fee_recipient = block.payload.payload_inner.payload_inner.fee_recipient;
        if actual_fee_recipient != aux_data.treasury_address {
            warn!(
                expected = ?aux_data.treasury_address,
                actual = ?actual_fee_recipient,
                "fee_recipient does not match treasury_address"
            );
            return false;
        }
    }

    // Validate checkpoint_hash (None means [0; 32], matching Block::compute_digest)
    let expected_checkpoint_hash: Digest =
        aux_data.checkpoint_hash.unwrap_or_else(|| [0; 32].into());
    if block.header.checkpoint_hash() != expected_checkpoint_hash {
        warn!(
            expected = ?expected_checkpoint_hash,
            actual = ?block.header.checkpoint_hash(),
            "checkpoint_hash mismatch"
        );
        return false;
    }

    // Validate added_validators
    let added_validators = block.header.added_validators();
    if added_validators != aux_data.added_validators {
        warn!(
            expected_count = aux_data.added_validators.len(),
            actual_count = added_validators.len(),
            "added_validators mismatch"
        );
        return false;
    }

    // Validate removed_validators
    let removed_validators = block.header.removed_validators();
    if removed_validators != aux_data.removed_validators {
        warn!(
            expected_count = aux_data.removed_validators.len(),
            actual_count = removed_validators.len(),
            "removed_validators mismatch"
        );
        return false;
    }

    // Validate withdrawals: the block's EIP-4895 withdrawals must equal the
    // re-clamped payouts the finalizer emitted into the aux data.
    let expected_withdrawals: &[_] = &aux_data.withdrawals;
    let actual_withdrawals: &[_] = &block.payload.payload_inner.withdrawals;
    if actual_withdrawals != expected_withdrawals {
        warn!(
            expected_count = expected_withdrawals.len(),
            actual_count = actual_withdrawals.len(),
            "withdrawals mismatch"
        );
        return false;
    }

    // Validate EIP-7685 execution-request ordering. A block whose request list is
    // not strictly ascending by type byte (e.g. the protocol-param type 0xFF before
    // withdrawals/consolidations) is rejected by the execution client during
    // replay, so vote it down here rather than relaying it into consensus.
    if !execution_requests_ascending(&block.execution_requests) {
        warn!(
            height = block.height(),
            "execution requests are not ascending by type byte; rejecting block"
        );
        return false;
    }

    // Summit does not derive consensus randomness for the EL: honest
    // proposers always set prev_randao to zero in PayloadAttributes.
    let payload_prev_randao = block.payload.payload_inner.payload_inner.prev_randao;
    if !payload_prev_randao.is_zero() {
        warn!(
            actual = ?payload_prev_randao,
            "payload prev_randao must be zero"
        );
        return false;
    }

    // Summit does not currently support blob transactions. Reject any
    // payload that consumed blob gas — if blob support is enabled later,
    // the V4 payload envelope's blob bundle / kzg commitments must also be
    // committed into the Block and threaded into EngineClient::check_payload
    // so engine_newPayloadV4 receives non-empty versioned_hashes.
    if block.payload.blob_gas_used > 0 {
        warn!(
            blob_gas_used = block.payload.blob_gas_used,
            "rejecting block: payload contains blob-bearing transactions"
        );
        return false;
    }

    true
}

/// The largest encoded block we allow consensus to propose/verify, expressed as
/// half the P2P message budget.
///
/// The cap exists because finalized data is repaired through single-message
/// resolver responses (see `syncer`): a bare `block.encode()` for `Request::Block`,
/// and `(finalization, block).encode()` / `(notarization, block).encode()` for the
/// finalized/notarized requests. If any such response exceeds
/// `max_message_size_bytes`, a lagging or checkpoint-joining peer can never repair
/// that height — every serve fails the same size check. Bounding the block at
/// consensus time (propose *and* verify, so even a Byzantine proposer can't get an
/// oversized block finalized) keeps every response servable.
///
/// Why `/2` specifically: the response is `block + certificate + framing`, so the
/// half not used by the block must cover everything else. That overhead is
/// dominated by a small constant plus a term linear in the validator count `N`:
///
/// - `Proposal` metadata: `round` (epoch u64 + view u64 = 16) + `parent` view (8)
///   + `payload` digest (32) = **56 bytes**, fixed.
/// - certificate: one aggregated BLS signature (MinPk → a single G2 element,
///   **96 bytes**, constant — signatures aggregate, they do not grow with `N`)
///   plus the `Signers` set, which is a `BitMap<1>` = **⌈N/8⌉ bytes** (one bit per
///   validator) and a small length field.
/// - tuple / codec framing (the block's 4-byte length prefix, bitmap length
///   varint): a handful of bytes.
///
/// So the non-block overhead is `~165 + ⌈N/8⌉` bytes, and the full response stays
/// under `max_message_size_bytes` whenever `⌈N/8⌉ + ~165 <= max/2`, i.e. roughly
/// `N <= 4 * max_message_size_bytes`. For any realistic cap (≥ ~1 MiB → ~4M
/// validators; even a 64 KiB cap → ~256k) this holds with orders of magnitude of
/// margin. The only term that scales with `N` is the 1-bit-per-validator bitmap;
/// if a non-aggregating signature scheme were ever substituted (overhead becoming
/// `O(N * sig_len)`), this `/2` headroom would need to be revisited.
fn max_block_size_bytes(max_message_size_bytes: u32) -> usize {
    usize::try_from(max_message_size_bytes / 2)
        .expect("u32 will always fit into usize on 32/64-bit targets")
}

fn block_size_limit_violation(
    block: &Block,
    max_message_size_bytes: u32,
) -> Option<(usize, usize)> {
    let block_size_bytes = block.encode_size();
    let max_block_size_bytes = max_block_size_bytes(max_message_size_bytes);
    if block_size_bytes < max_block_size_bytes {
        return None;
    }

    Some((block_size_bytes, max_block_size_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use alloy_rpc_types_engine::{
        ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState,
    };
    use commonware_consensus::types::FixedEpocher;
    use std::num::NonZeroU64;

    const EPOCH_LENGTH: u64 = 10;

    #[test]
    fn execution_requests_ascending_accepts_sorted_rejects_unsorted() {
        // Each element is `[request_type_byte, ..data]`.
        let req = |ty: u8| vec![ty, 0xaa, 0xbb];

        // Empty and single-element lists are trivially ordered.
        let empty: &[Vec<u8>] = &[];
        assert!(execution_requests_ascending(empty));
        assert!(execution_requests_ascending(&[req(0xFF)]));

        // Canonical order: deposit (0x00), withdrawal (0x01), consolidation (0x02),
        // protocol-param (0xFF).
        assert!(execution_requests_ascending(&[
            req(0x00),
            req(0x01),
            req(0x02),
            req(0xFF)
        ]));

        // The #300 case: protocol-param (0xFF) ahead of withdrawals/consolidations.
        assert!(!execution_requests_ascending(&[
            req(0x00),
            req(0xFF),
            req(0x01),
            req(0x02)
        ]));

        // Duplicate request type is rejected.
        assert!(!execution_requests_ascending(&[req(0x01), req(0x01)]));

        // An element with no type byte is malformed.
        assert!(!execution_requests_ascending(&[Vec::<u8>::new()]));

        // A bare type byte with no request_data is also malformed; the EL
        // rejects it as "EmptyExecutionRequest".
        assert!(!execution_requests_ascending(&[vec![0x00]]));
        assert!(!execution_requests_ascending(&[vec![0x01]]));
        assert!(!execution_requests_ascending(&[vec![0xFF]]));
    }

    fn empty_payload(height: u64, parent_hash: [u8; 32], timestamp: u64) -> ExecutionPayloadV3 {
        let mut block_hash = [0u8; 32];
        block_hash[0..8].copy_from_slice(&height.to_le_bytes());
        ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas: U256::from(1_000_000_000u64),
                    block_number: height,
                    block_hash: block_hash.into(),
                    logs_bloom: Default::default(),
                    extra_data: Default::default(),
                    gas_limit: 30_000_000,
                    gas_used: 0,
                    timestamp,
                    fee_recipient: Default::default(),
                    parent_hash: if height == 0 {
                        [0u8; 32].into()
                    } else {
                        parent_hash.into()
                    },
                    prev_randao: Default::default(),
                    receipts_root: Default::default(),
                    state_root: Default::default(),
                    transactions: Vec::new(),
                },
                withdrawals: Vec::new(),
            },
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    fn make_block(parent: Digest, height: u64, epoch: u64, view: u64, timestamp: u64) -> Block {
        make_block_with_eth_parent(parent, parent.0, height, epoch, view, timestamp)
    }

    fn make_block_with_eth_parent(
        parent: Digest,
        eth_parent_hash: [u8; 32],
        height: u64,
        epoch: u64,
        view: u64,
        timestamp: u64,
    ) -> Block {
        let payload = empty_payload(height, eth_parent_hash, timestamp);
        Block::compute_digest(
            parent,
            height,
            timestamp,
            payload,
            Vec::new(),
            epoch,
            view,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        )
    }

    fn make_aux_data(epoch: u64) -> BlockAuxData {
        BlockAuxData {
            epoch,
            withdrawals: Vec::new(),
            checkpoint_hash: None,
            header_hash: [0u8; 32].into(),
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
            forkchoice: ForkchoiceState {
                head_block_hash: [0u8; 32].into(),
                safe_block_hash: [0u8; 32].into(),
                finalized_block_hash: [0u8; 32].into(),
            },
            suggested_fee_recipient: Default::default(),
            treasury_address: Default::default(),
            state_root: [0u8; 32],
            allowed_timestamp_future_ms: u64::MAX / 2,
        }
    }

    fn epocher() -> FixedEpocher {
        FixedEpocher::new(NonZeroU64::new(EPOCH_LENGTH).unwrap())
    }

    /// A re-proposal of the epoch-terminal parent (identical digest, same
    /// height) must be accepted: that is the only allowed shape past the
    /// epoch boundary.
    #[test]
    fn accepts_same_digest_reproposal_at_epoch_terminal_parent() {
        let last_height = EPOCH_LENGTH - 1; // block 9 with epoch_length 10
        let parent = make_block(
            [0u8; 32].into(),
            last_height,
            0,
            last_height,
            last_height * 12,
        );
        let block = parent.clone();
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "re-proposal of the epoch-terminal block must be accepted"
        );
    }

    /// A Byzantine proposer can craft a non-reproposal child whose parent is
    /// the epoch-terminal block. handle_verify must reject it — honest
    /// proposers re-propose the terminal block instead of building a normal
    /// child past the boundary, and the verifier must enforce the same rule.
    #[test]
    fn rejects_non_reproposal_child_after_epoch_terminal_parent() {
        let last_height = EPOCH_LENGTH - 1; // block 9
        let parent = make_block(
            [0u8; 32].into(),
            last_height,
            0,
            last_height,
            last_height * 12,
        );
        // A Byzantine "ordinary" child at parent.height + 1 (block 10) with
        // a fresh digest. parent continuity and height+1 continuity hold, so
        // the structural checks pass; the only thing that can reject this is
        // an epoch-boundary check.
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            last_height + 1,
            0,
            last_height + 1,
            (last_height + 1) * 12,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "non-reproposal child whose parent is the epoch-terminal block \
             must be rejected"
        );
    }

    /// Sanity: an ordinary child inside the epoch is still accepted (so the
    /// added check doesn't over-reject).
    #[test]
    fn accepts_ordinary_child_inside_epoch() {
        let parent_height = 3; // mid-epoch 0
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "ordinary child inside the parent's epoch must be accepted"
        );
    }

    /// Parent-view binding: the parent view signed into the Commonware proposal
    /// context must match the decoded view of the fetched parent block. An
    /// ordinary child whose signed parent view disagrees with the parent block's
    /// own view must be rejected.
    #[test]
    fn rejects_parent_view_mismatch() {
        let parent_height = 3; // mid-epoch 0, decoded parent view == 3
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        // Signed parent view (7) disagrees with the parent block's decoded view (3).
        let mismatched_parent_view = parent.view() + 1;
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                mismatched_parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "child whose signed parent view disagrees with the parent block's \
             decoded view must be rejected"
        );
    }

    /// Sanity companion to `rejects_parent_view_mismatch`: a matching signed
    /// parent view must still be accepted (the binding check must not
    /// over-reject honest proposals).
    #[test]
    fn accepts_matching_parent_view() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "child whose signed parent view matches the parent block must be accepted"
        );
    }

    /// The child block's own view must match the proposal round view; a block
    /// whose decoded view disagrees with its certifying round is rejected.
    #[test]
    fn rejects_child_view_mismatch() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        // Child decoded view (4) but certified at round view 5.
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );
        let aux_data = make_aux_data(0);

        let parent_view = parent.view();
        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view() + 1));
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "child whose decoded view disagrees with the proposal round must be rejected"
        );
    }

    /// The same-digest boundary re-proposal is the one legitimate case where the
    /// parent block's decoded view need not equal the signed parent view (the
    /// terminal block can be re-certified at a later view). The re-proposal
    /// carve-out must keep accepting it even when the signed parent view differs,
    /// so the parent-view binding check must not break epoch boundaries.
    #[test]
    fn accepts_reproposal_despite_parent_view_mismatch() {
        let last_height = EPOCH_LENGTH - 1; // block 9, decoded view 9
        let parent = make_block(
            [0u8; 32].into(),
            last_height,
            0,
            last_height,
            last_height * 12,
        );
        let block = parent.clone();
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        // Terminal block re-certified at a later view than its decoded view (9).
        let later_parent_view = parent.view() + 3;
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                later_parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "same-digest boundary re-proposal must be accepted even when the \
             signed parent view differs from the block's decoded view"
        );
    }

    /// The first block of an epoch carries a signed parent view of 0 (the
    /// `parent.0 == 0` sentinel) while its parent (the previous epoch's terminal
    /// block) has a non-zero decoded view in a different view space. The
    /// parent-view binding must be skipped in that case, or every epoch's
    /// opening block would be rejected.
    ///
    /// The parent here is epoch 0's terminal block (height `EPOCH_LENGTH - 1`)
    /// and the child opens epoch 1 (height `EPOCH_LENGTH`), so the parent's
    /// epoch is exactly one less than the round epoch — the defining shape of an
    /// epoch opener.
    #[test]
    fn accepts_zero_signed_parent_view_for_epoch_opener() {
        let parent_height = EPOCH_LENGTH - 1; // epoch 0 terminal, decoded view 9
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        // Epoch 1's opener: a fresh Simplex instance restarts views at 1.
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            EPOCH_LENGTH,
            1,
            1,
            EPOCH_LENGTH * 12,
        );
        let aux_data = make_aux_data(1);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        // Sentinel parent view 0 must bypass the binding despite parent.view() == 9,
        // because the parent's epoch (0) is exactly one less than the round epoch (1).
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                0,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "a signed parent view of 0 on a genuine epoch opener must bypass the \
             parent-view binding"
        );
    }

    /// Regression for the #313 bypass: the signed-parent-view-0 sentinel must not
    /// blanket-skip the binding. A mid-epoch block (parent and child in the same
    /// epoch) whose proposer sets the signed parent view to 0 must be rejected —
    /// otherwise the sentinel becomes a universal escape hatch around the
    /// parent-view check.
    #[test]
    fn rejects_zero_signed_parent_view_mid_epoch() {
        let parent_height = 3; // mid-epoch 0, decoded view 3
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        let block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        // The child stays inside epoch 0 (parent.epoch + 1 != round.epoch), so a
        // signed parent view of 0 is not a legitimate epoch-opener sentinel.
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                0,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "a signed parent view of 0 on a mid-epoch block must be rejected"
        );
    }

    /// Construct a block where the Summit header carries one set of
    /// (height, timestamp) but the embedded EL payload reports a different
    /// (block_number, timestamp). Honest proposal keeps these matched; a
    /// Byzantine proposer is not constrained to do so.
    #[allow(clippy::too_many_arguments)]
    fn make_block_with_payload_metadata(
        parent: Digest,
        eth_parent_hash: [u8; 32],
        header_height: u64,
        header_timestamp: u64,
        payload_block_number: u64,
        payload_timestamp: u64,
        epoch: u64,
        view: u64,
    ) -> Block {
        // Use the parent's EL block hash as the payload parent_hash so the block
        // passes the eth_parent_hash check and the rejection is genuinely due to
        // the CL/EL metadata binding under test, not an earlier linkage check.
        let payload = empty_payload(payload_block_number, eth_parent_hash, payload_timestamp);
        Block::compute_digest(
            parent,
            header_height,
            header_timestamp,
            payload,
            Vec::new(),
            epoch,
            view,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        )
    }

    /// A block whose Summit header.height does not match the embedded EL
    /// payload.block_number must be rejected. Otherwise consensus would
    /// certify a header describing one height while the EL executes under a
    /// different block number — breaking the one-to-one CL/EL meaning of a
    /// Summit block.
    #[test]
    fn rejects_block_with_payload_block_number_mismatch() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;
        // payload.block_number disagrees with header.height
        let payload_block_number = header_height + 5;

        let block = make_block_with_payload_metadata(
            parent.digest(),
            parent.eth_block_hash(),
            header_height,
            header_timestamp,
            payload_block_number,
            header_timestamp,
            0,
            header_height,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let signed_parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                signed_parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "block with payload.block_number ({}) != header.height ({}) must be rejected",
            payload_block_number,
            header_height
        );
    }

    /// A block whose Summit header.timestamp does not match the embedded EL
    /// payload.timestamp must be rejected. Otherwise CL timestamp policy
    /// (wall-clock bounds, monotonicity) can be bypassed: the header carries
    /// a benign timestamp while the EL payload executes under a different
    /// one that descendants and recovery flows trust.
    #[test]
    fn rejects_block_with_payload_timestamp_mismatch() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;
        // payload.timestamp disagrees with header.timestamp
        let payload_timestamp = header_timestamp + 1_000_000;

        let block = make_block_with_payload_metadata(
            parent.digest(),
            parent.eth_block_hash(),
            header_height,
            header_timestamp,
            header_height,
            payload_timestamp,
            0,
            header_height,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let signed_parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                signed_parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "block with payload.timestamp ({}) != header.timestamp ({}) must be rejected",
            payload_timestamp,
            header_timestamp
        );
    }

    #[test]
    fn proposal_timestamp_waits_until_parent_child_timestamp_is_in_future_window() {
        let now_millis = 1_000_000;
        let allowed_timestamp_future_ms = 1_000;
        let min_child_timestamp = now_millis + allowed_timestamp_future_ms + 1;

        let wait =
            proposal_timestamp_wait(now_millis, min_child_timestamp, allowed_timestamp_future_ms);
        assert_eq!(wait, Duration::from_millis(1));

        let after_wait = now_millis + wait.as_millis() as u64;
        let selected = select_proposal_timestamp(after_wait, min_child_timestamp);

        assert_eq!(selected, min_child_timestamp);
        assert!(selected <= after_wait + allowed_timestamp_future_ms);
    }

    #[test]
    fn proposal_timestamp_does_not_wait_when_local_time_is_valid() {
        let now_millis = 1_000_000;
        let min_child_timestamp = now_millis - 10;
        let allowed_timestamp_future_ms = 1_000;

        let wait =
            proposal_timestamp_wait(now_millis, min_child_timestamp, allowed_timestamp_future_ms);
        assert!(wait.is_zero());
        assert_eq!(
            select_proposal_timestamp(now_millis, min_child_timestamp),
            now_millis
        );
    }

    #[test]
    fn proposal_aborts_when_wait_exceeds_leader_window() {
        // Parent timestamp so far ahead that the wait to enter the verifier
        // window is longer than the leader window: the proposal must be abandoned.
        let now_millis = 1_000_000;
        let allowed_timestamp_future_ms = 1_000;
        let leader_timeout = Duration::from_millis(2_000);
        let min_child_timestamp = now_millis + allowed_timestamp_future_ms + 5_000;

        let wait =
            proposal_timestamp_wait(now_millis, min_child_timestamp, allowed_timestamp_future_ms);
        assert_eq!(wait, Duration::from_millis(5_000));
        assert!(proposal_wait_exceeds_leader_window(wait, leader_timeout));
    }

    #[test]
    fn proposal_does_not_abort_when_wait_within_leader_window() {
        // The required wait is inside the leader window, so the proposal proceeds
        // (and waits) rather than aborting.
        let now_millis = 1_000_000;
        let allowed_timestamp_future_ms = 1_000;
        let leader_timeout = Duration::from_millis(2_000);
        let min_child_timestamp = now_millis + allowed_timestamp_future_ms + 1;

        let wait =
            proposal_timestamp_wait(now_millis, min_child_timestamp, allowed_timestamp_future_ms);
        assert_eq!(wait, Duration::from_millis(1));
        assert!(!proposal_wait_exceeds_leader_window(wait, leader_timeout));
    }

    /// Summit does not currently support blob transactions. A block whose EL
    /// payload consumed blob gas must be rejected at verify time — otherwise the
    /// empty `versioned_hashes` passed to engine_newPayloadV4 in
    /// `EngineClient::check_payload` would diverge CL/EL on any blob-bearing
    /// payload that consensus accepted. Built as a control (the same block with
    /// no blob gas verifies) so only `blob_gas_used` gates the result.
    #[test]
    fn rejects_block_with_blob_gas_used() {
        let parent_height = 3; // mid-epoch 0
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );
        let mut block = make_block_with_eth_parent(
            parent.digest(),
            parent.eth_block_hash(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );
        let aux_data = make_aux_data(0);
        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();

        // Control: the ordinary child verifies with no blob gas.
        assert!(
            handle_verify(
                round,
                &block,
                parent.clone(),
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "control: ordinary child must verify when no blob gas is consumed"
        );

        // Same block now reporting blob-gas consumption: must be rejected.
        block.payload.blob_gas_used = 131_072; // one blob's worth of gas
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "block whose payload consumed blob gas must be rejected"
        );
    }

    /// A Byzantine proposer can produce an otherwise valid execution payload
    /// whose fee_recipient differs from the treasury address that Summit policy
    /// mandates. The execution engine validates EL rules but not Summit's
    /// aux-data invariants, so handle_verify must reject the payload to prevent
    /// fee redirection.
    #[test]
    fn rejects_block_with_fee_recipient_mismatch_when_treasury_set() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;

        // Otherwise-valid child, but with an attacker-chosen fee recipient.
        let attacker_recipient = Address::from([0xAB; 20]);
        let mut payload = empty_payload(header_height, parent.eth_block_hash(), header_timestamp);
        payload.payload_inner.payload_inner.fee_recipient = attacker_recipient;
        let block = Block::compute_digest(
            parent.digest(),
            header_height,
            header_timestamp,
            payload,
            Vec::new(),
            0,
            header_height,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        // Honest aux data: treasury is set and disagrees with the payload.
        let treasury = Address::from([0xCC; 20]);
        let mut aux_data = make_aux_data(0);
        aux_data.treasury_address = treasury;
        aux_data.suggested_fee_recipient = treasury;

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "block whose payload fee_recipient ({attacker_recipient:?}) does not match \
             the treasury address ({treasury:?}) must be rejected"
        );
    }

    /// Sanity companion: when treasury is set and the payload fee_recipient
    /// matches it, the block must still verify — the check must not over-reject
    /// honest blocks.
    #[test]
    fn accepts_block_with_matching_fee_recipient_when_treasury_set() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;

        let treasury = Address::from([0xCC; 20]);
        let mut payload = empty_payload(header_height, parent.eth_block_hash(), header_timestamp);
        payload.payload_inner.payload_inner.fee_recipient = treasury;
        let block = Block::compute_digest(
            parent.digest(),
            header_height,
            header_timestamp,
            payload,
            Vec::new(),
            0,
            header_height,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        let mut aux_data = make_aux_data(0);
        aux_data.treasury_address = treasury;
        aux_data.suggested_fee_recipient = treasury;

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "block whose payload fee_recipient matches the treasury address must be accepted"
        );
    }

    /// A Byzantine proposer can produce an otherwise valid execution
    /// payload whose prev_randao is attacker-chosen. The EL accepts any
    /// 32-byte value there, so handle_verify must reject non-zero
    /// prev_randao to prevent biased PREVRANDAO output on-chain.
    #[test]
    fn rejects_block_with_nonzero_prev_randao() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;

        let mut payload = empty_payload(header_height, parent.eth_block_hash(), header_timestamp);
        payload.payload_inner.payload_inner.prev_randao = [0xAB; 32].into();

        let block = Block::compute_digest(
            parent.digest(),
            header_height,
            header_timestamp,
            payload,
            Vec::new(),
            0,
            header_height,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        let aux_data = make_aux_data(0);
        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "block whose payload prev_randao is non-zero must be rejected"
        );
    }

    /// Sanity: a payload built honestly with prev_randao = 0 must verify.
    #[test]
    fn accepts_block_with_zero_prev_randao() {
        let parent_height = 3;
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        let header_height = parent_height + 1;
        let header_timestamp = header_height * 12;

        // empty_payload leaves prev_randao = Default::default() (all zeros).
        let payload = empty_payload(header_height, parent.eth_block_hash(), header_timestamp);

        let block = Block::compute_digest(
            parent.digest(),
            header_height,
            header_timestamp,
            payload,
            Vec::new(),
            0,
            header_height,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        let aux_data = make_aux_data(0);
        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX,
            ),
            "honest block with prev_randao = 0 must be accepted"
        );
    }

    /// handle_verify must reject a block whose `checkpoint_hash` disagrees with
    /// the verifying node's locally-derived `aux_data.checkpoint_hash`. An honest
    /// validator only votes for a block whose checkpoint_hash matches the
    /// checkpoint it computed from its own canonical state, so a finalized
    /// terminal header's checkpoint_hash provably commits to the canonical
    /// state an honest supermajority agreed on. This is the consensus-layer
    /// binding that makes checkpoint-state injection (extra accounts, funds,
    /// params) unreachable on the verified import path: such bytes change the
    /// checkpoint digest and would never be signed.
    ///
    /// This mirrors `accepts_ordinary_child_inside_epoch` exactly, changing only
    /// the block's checkpoint_hash, so the checkpoint_hash check is the sole
    /// cause of the flip from accept to reject.
    #[test]
    fn rejects_block_with_mismatched_checkpoint_hash() {
        let parent_height = 3; // mid-epoch 0
        let parent = make_block(
            [0u8; 32].into(),
            parent_height,
            0,
            parent_height,
            parent_height * 12,
        );

        // Identical to the accepted ordinary child, except it carries an
        // attacker-chosen checkpoint_hash instead of the expected `None`.
        let height = parent_height + 1;
        let timestamp = height * 12;
        let payload = empty_payload(height, parent.eth_block_hash(), timestamp);
        let block = Block::compute_digest(
            parent.digest(),
            height,
            timestamp,
            payload,
            Vec::new(),
            0,
            height,
            Some([7u8; 32].into()), // <-- disagrees with aux_data.checkpoint_hash (None)
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        // The verifying node derived no checkpoint at this height (None = [0; 32]).
        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        let parent_view = parent.view();
        assert!(
            !handle_verify(
                round,
                &block,
                parent,
                parent_view,
                &epocher(),
                &aux_data,
                u64::MAX / 4,
                u32::MAX
            ),
            "block whose checkpoint_hash disagrees with the locally-derived \
             aux_data.checkpoint_hash must be rejected"
        );
    }
}
