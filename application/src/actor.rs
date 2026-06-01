use crate::{
    ApplicationConfig,
    ingress::{Mailbox, Message},
};
use anyhow::{Context, Result, anyhow};
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

use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::types::{Epoch, Epocher, Round, View};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{PublicKey, Signer};
use std::marker::PhantomData;
#[cfg(feature = "permissioned")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use summit_finalizer::FinalizerMailbox;
use tracing::{debug, error, info, warn};

#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use summit_syncer::ingress::mailbox::Mailbox as SyncerMailbox;
use summit_types::{Block, BlockAuxData, Digest, EngineClient};

/// How long to wait before retrying check_payload when Reth returns SYNCING during certify.
const CERTIFY_SYNCING_RETRY: Duration = Duration::from_millis(100);

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
    mailbox: mpsc::Receiver<Message>,
    engine_client: C,
    built_block: Arc<Mutex<Option<(Block, Round)>>>,
    genesis_hash: [u8; 32],
    epocher: ES,
    cancellation_token: CancellationToken,
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
    S: Scheme<Digest>,
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
                built_block: Arc::new(Mutex::new(None)),
                genesis_hash,
                epocher: cfg.epocher,
                cancellation_token: cfg.cancellation_token,
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
        spawn_cell!(self.context, self.run(syncer, finalizer).await)
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

                            let built = self.built_block.clone();
                            #[cfg(feature = "prom")]
                            let proposal_start = std::time::Instant::now();

                            select! {
                                    res = self.handle_proposal(parent, &mut syncer, &mut finalizer, round) => {
                                        match res {
                                            Ok(block) => {
                                                // store block
                                                let digest = block.digest();
                                                let height = block.height();
                                                let tx_count = block.payload.payload_inner.payload_inner.transactions.len();
                                                {
                                                    let mut built = built.lock().expect("locked poisoned");
                                                    *built = Some((block.clone(), round));
                                                }

                                                info!(
                                                    height,
                                                    epoch = round.epoch().get(),
                                                    view = round.view().get(),
                                                    tx_count,
                                                    "proposed block"
                                                );

                                                // send block to syncer for caching and broadcasting
                                                syncer.proposed(round, block).await;

                                                // send digest to consensus
                                                let _ = response.send(digest);
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
                        Message::Broadcast { payload: _ } => {
                            #[cfg(feature = "permissioned")]
                            if self.paused.load(Ordering::Relaxed) {
                                warn!("consensus paused, skipping broadcast");
                                continue;
                            }

                            info!("{rand_id} Handling message Broadcast");

                            let built_block = self.built_block.lock().expect("poisoned lock").take();

                            if let Some((block, round)) = built_block {
                                syncer.proposed(round, block).await;
                            } else {
                                warn!("Asked to broadcast a block without one built");
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

                            let block_request = syncer.subscribe(Some(round), payload).await;

                            self.context.with_label("certify").spawn({
                                let mut finalizer_clone = finalizer.clone();
                                let mut engine_client = self.engine_client.clone();
                                let genesis_hash = self.genesis_hash;
                                move |context| async move {
                                    let work = async {
                                        let Ok(block) = block_request.await else {
                                            warn!(?round, "certify: failed to receive block from syncer");
                                            return false;
                                        };

                                        // Wait for parent to be executed so its state is in Reth
                                        // before check_payload runs on the child.
                                        let parent_digest = block.parent();
                                        if parent_digest != genesis_hash.into() {
                                            let parent_height = block.height().saturating_sub(1);
                                            let parent_executed = finalizer_clone
                                                .notify_at_height(parent_height, parent_digest)
                                                .await
                                                .await
                                                .unwrap_or(false);
                                            if !parent_executed {
                                                warn!(
                                                    ?round,
                                                    parent_height,
                                                    ?parent_digest,
                                                    "certify: parent block not executed by finalizer"
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

                            // Subscribe to blocks (will wait for them if not available)
                            let parent_request = if parent.1 == self.genesis_hash.into() {
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
                                        .await,
                                )
                            };
                            let block_request = syncer.subscribe(Some(round), payload).await;

                            // Wait for the blocks to be available or the request to be canceled in a separate task (to
                            // continue processing other messages)
                            self.context.with_label("verify").spawn({
                                let mut syncer = syncer.clone();
                                let mut finalizer_clone = finalizer.clone();
                                let epocher = self.epocher.clone();
                                move |context| async move {
                                    let requester = try_join(parent_request, block_request);
                                    select! {
                                        result = requester => {
                                            let (parent, block) = result.unwrap();

                                            let parent_digest = parent.digest();
                                            let parent_height = parent.height();

                                            // Wait for parent block to be executed by finalizer
                                            // This ensures the parent's state is available for aux_data
                                            let parent_executed = finalizer_clone
                                                .notify_at_height(parent_height, parent_digest)
                                                .await
                                                .await
                                                .unwrap_or(false);

                                            if !parent_executed {
                                                warn!(
                                                    ?round,
                                                    parent_height,
                                                    ?parent_digest,
                                                    "parent block not executed by finalizer"
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
                                                if handle_verify(round, &block, parent, &epocher, &aux_data, now_millis) {
                                                    // persist valid block
                                                    syncer.verified(round, block).await;

                                                    // respond
                                                    let _ = response.send(true);
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
                    .await
                    .map(|x| x.context("")),
            )
        };
        let parent_block = parent_block.await.expect("sender dropped");

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
            return Ok(parent_block);
        }

        let pending_withdrawals = aux_data.withdrawals;
        let checkpoint_hash = aux_data.checkpoint_hash;

        let mut current = self.context.current().epoch_millis();
        if current <= parent_block.timestamp() {
            current = parent_block.timestamp() + 1;
        }

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

        // Add pending withdrawals to the block
        let withdrawals = pending_withdrawals.into_iter().map(|w| w.inner).collect();
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

        let block = Block::compute_digest(
            parent_block.digest(),
            parent_block.height() + 1,
            current,
            payload_envelope.envelope_inner.execution_payload,
            payload_envelope.execution_requests.to_vec(),
            payload_envelope.envelope_inner.block_value,
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

fn handle_verify<ES: Epocher>(
    round: Round,
    block: &Block,
    parent: Block,
    epocher: &ES,
    aux_data: &BlockAuxData,
    now_millis: u64,
) -> bool {
    if round.epoch().get() != aux_data.epoch {
        warn!(
            "epoch mismatch: simplex epoch {}, finalizer epoch: {}",
            round.epoch().get(),
            aux_data.epoch
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
    if block.height() > last_in_epoch {
        warn!(
            block_height = block.height(),
            last_in_epoch, "rejecting non-reproposal child past epoch boundary"
        );
        return false;
    }
    // Basic structural validation
    if block.parent() != parent.digest() {
        warn!(
            "block parent mismatch: expected {}, received: {}",
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
            "block height mismatch: expected {}, received: {}",
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

    // Validate consensus trie state root
    if block.header.parent_beacon_block_root != aux_data.state_root {
        warn!(
            expected = ?aux_data.state_root,
            actual = ?block.header.parent_beacon_block_root,
            "parent_beacon_block_root mismatch"
        );
        return false;
    }

    // Validate checkpoint_hash (None means [0; 32], matching Block::compute_digest)
    let expected_checkpoint_hash: Digest =
        aux_data.checkpoint_hash.unwrap_or_else(|| [0; 32].into());
    if block.header.checkpoint_hash != expected_checkpoint_hash {
        warn!(
            expected = ?expected_checkpoint_hash,
            actual = ?block.header.checkpoint_hash,
            "checkpoint_hash mismatch"
        );
        return false;
    }

    // Validate added_validators
    if block.header.added_validators != aux_data.added_validators {
        warn!(
            expected_count = aux_data.added_validators.len(),
            actual_count = block.header.added_validators.len(),
            "added_validators mismatch"
        );
        return false;
    }

    // Validate removed_validators
    if block.header.removed_validators != aux_data.removed_validators {
        warn!(
            expected_count = aux_data.removed_validators.len(),
            actual_count = block.header.removed_validators.len(),
            "removed_validators mismatch"
        );
        return false;
    }

    // Validate withdrawals
    let expected_withdrawals: Vec<_> = aux_data.withdrawals.iter().map(|w| w.inner).collect();
    let actual_withdrawals: &[_] = &block.payload.payload_inner.withdrawals;
    if actual_withdrawals != expected_withdrawals.as_slice() {
        warn!(
            expected_count = expected_withdrawals.len(),
            actual_count = actual_withdrawals.len(),
            "withdrawals mismatch"
        );
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_rpc_types_engine::{
        ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState,
    };
    use commonware_consensus::types::FixedEpocher;
    use std::num::NonZeroU64;

    const EPOCH_LENGTH: u64 = 10;

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
        let parent_bytes: [u8; 32] = parent.0;
        let payload = empty_payload(height, parent_bytes, timestamp);
        Block::compute_digest(
            parent,
            height,
            timestamp,
            payload,
            Vec::new(),
            U256::ZERO,
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
        assert!(
            handle_verify(round, &block, parent, &epocher(), &aux_data, u64::MAX / 4),
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
        let block = make_block(
            parent.digest(),
            last_height + 1,
            0,
            last_height + 1,
            (last_height + 1) * 12,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        assert!(
            !handle_verify(round, &block, parent, &epocher(), &aux_data, u64::MAX / 4),
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
        let block = make_block(
            parent.digest(),
            parent_height + 1,
            0,
            parent_height + 1,
            (parent_height + 1) * 12,
        );

        let aux_data = make_aux_data(0);

        let round = Round::new(Epoch::new(aux_data.epoch), View::new(block.view()));
        assert!(
            handle_verify(round, &block, parent, &epocher(), &aux_data, u64::MAX / 4),
            "ordinary child inside the parent's epoch must be accepted"
        );
    }
}
