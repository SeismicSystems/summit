use crate::{
    ApplicationConfig,
    ingress::{Mailbox, Message},
};
use anyhow::{Context, Result, anyhow};
use commonware_macros::select;
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_utils::SystemTimeExt;
use futures::{
    FutureExt, StreamExt as _,
    channel::{mpsc, oneshot},
    future::{self, Either, try_join},
};
use rand::Rng;
use tokio_util::sync::CancellationToken;

use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_consensus::types::{Round, View};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{PublicKey, Signer};
use futures::task::Poll;
use std::marker::PhantomData;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use summit_finalizer::FinalizerMailbox;
use tracing::{debug, error, info, warn};

#[cfg(feature = "prom")]
use metrics::histogram;
use summit_syncer::ingress::mailbox::Mailbox as SyncerMailbox;
use summit_types::{Block, Digest, EngineClient};

// Define a future that checks if the oneshot channel is closed using a mutable reference
struct ChannelClosedFuture<'a, T> {
    sender: &'a mut oneshot::Sender<T>,
}

impl<T> Future for ChannelClosedFuture<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut futures::task::Context<'_>) -> Poll<Self::Output> {
        // Use poll_canceled to check if the receiver has dropped the channel
        match self.sender.poll_canceled(cx) {
            Poll::Ready(()) => Poll::Ready(()), // Receiver dropped, channel closed
            Poll::Pending => Poll::Pending,     // Channel still open
        }
    }
}

// Helper function to create the future using a mutable reference
fn oneshot_closed_future<T>(sender: &mut oneshot::Sender<T>) -> ChannelClosedFuture<'_, T> {
    ChannelClosedFuture { sender }
}

pub struct Actor<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    S: Scheme,
    P: PublicKey,
    K: Signer,
    V: Variant,
> {
    context: ContextCell<R>,
    mailbox: mpsc::Receiver<Message>,
    engine_client: C,
    built_block: Arc<Mutex<Option<Block<K, V>>>>,
    genesis_hash: [u8; 32],
    cancellation_token: CancellationToken,
    _scheme_marker: PhantomData<S>,
    _key_marker: PhantomData<P>,
    _signer_marker: PhantomData<K>,
    _variant_marker: PhantomData<V>,
}

impl<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    S: Scheme,
    P: PublicKey,
    K: Signer,
    V: Variant,
> Actor<R, C, S, P, K, V>
{
    pub async fn new(context: R, cfg: ApplicationConfig<C>) -> (Self, Mailbox<P>) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);

        let genesis_hash = cfg.genesis_hash;

        (
            Self {
                context: ContextCell::new(context),
                mailbox: rx,
                engine_client: cfg.engine_client,
                built_block: Arc::new(Mutex::new(None)),
                genesis_hash,
                cancellation_token: cfg.cancellation_token,
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
        syncer: SyncerMailbox<S, Block<K, V>>,
        finalizer: FinalizerMailbox<S, Block<K, V>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(syncer, finalizer).await)
    }

    pub async fn run(
        mut self,
        mut syncer: SyncerMailbox<S, Block<K, V>>,
        mut finalizer: FinalizerMailbox<S, Block<K, V>>,
    ) {
        let rand_id: u8 = rand::random();
        let mut signal = self.context.stopped().fuse();
        let cancellation_token = self.cancellation_token.clone();
        loop {
            select! {
                message = self.mailbox.next() => {
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
                            debug!("{rand_id} application: Handling message Propose for round {} (epoch {}, view {}), parent height: {}",
                                round, round.epoch(), round.view(), parent.0);

                            let built = self.built_block.clone();
                            select! {
                                    res = self.handle_proposal((parent.0.get(), parent.1), &mut syncer, &mut finalizer, round) => {
                                        match res {
                                            Ok(block) => {
                                                // store block
                                                let digest = block.digest();
                                                {
                                                    let mut built = built.lock().expect("locked poisoned");
                                                    *built = Some(block);
                                                }

                                                // send digest to consensus
                                                let _ = response.send(digest);
                                            },
                                            Err(e) => warn!("Failed to create a block for round {round}: {e}")
                                        }
                                    },
                                    _ = oneshot_closed_future(&mut response) => {
                                        // simplex dropped receiver
                                        warn!("proposal aborted for round {round}");
                                    }
                            }
                        }
                        Message::Broadcast { payload } => {
                            info!("{rand_id} Handling message Broadcast");
                            let Some(built_block) =
                                self.built_block.lock().expect("poisoned mutex").clone()
                            else {
                                warn!("Asked to broadcast a block with no built block");
                                continue;
                            };
                            // todo(dalton): This should be a hard assert but for testing im just going to log
                            if payload != built_block.digest() {
                                error!(
                                    "The payload we were asked to broadcast is different then our built block"
                                );
                            }

                            syncer.broadcast(built_block).await;
                        }

                        Message::Verify {
                            round,
                            parent,
                            payload,
                            mut response,
                        } => {
                            debug!("{rand_id} application: Handling message Verify for round {} (epoch {}, view {}), parent height: {}",
                                round, round.epoch(), round.view(), parent.0);

                            // Subscribe to blocks (will wait for them if not available)
                            let parent_request = if parent.1 == self.genesis_hash.into() {
                                Either::Left(future::ready(Ok(Block::genesis(self.genesis_hash))))
                            } else {
                                let parent_round = if parent.0.get() == 0 {
                                    // Parent view is 0, which means that this is the first block of the epoch
                                    // TODO(matthias): verify that the parent view of the first block is always 0 (nullify)
                                    None
                                } else {
                                    Some(Round::new(round.epoch(), parent.0))
                                };
                                Either::Right(
                                    syncer
                                        .subscribe(parent_round, parent.1)
                                        .await,
                                )
                                //Either::Right(syncer.subscribe(None, parent.1).await)
                            };
                            let block_request = syncer.subscribe(Some(round), payload).await;

                            // Wait for the blocks to be available or the request to be cancelled in a separate task (to
                            // continue processing other messages)

                            self.context.with_label("verify").spawn({
                                let mut syncer = syncer.clone();
                                move |_| async move {
                                    let requester = try_join(parent_request, block_request);
                                    select! {
                                        result = requester => {
                                            let (parent, block) = result.unwrap();

                                            if handle_verify(&block, parent) {
                                                // persist valid block
                                                syncer.verified(round, block).await;

                                                // respond
                                                let _ = response.send(true);
                                            } else {
                                                info!("Unsuccessful vote for round {round}");
                                                let _ = response.send(false);
                                            }
                                        },
                                        _ = oneshot_closed_future(&mut response) => {
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
        parent: (u64, Digest),
        syncer: &mut SyncerMailbox<S, Block<K, V>>,
        finalizer: &mut FinalizerMailbox<S, Block<K, V>>,
        round: Round,
    ) -> Result<Block<K, V>> {
        #[cfg(feature = "prom")]
        let proposal_start = std::time::Instant::now();

        // STEP 1: Get the parent block
        #[cfg(feature = "prom")]
        let parent_fetch_start = std::time::Instant::now();
        let parent_request = if parent.1 == self.genesis_hash.into() {
            Either::Left(future::ready(Ok(Block::genesis(self.genesis_hash))))
        } else {
            let parent_round = if parent.0 == 0 {
                // Parent view is 0, which means that this is the first block of the epoch
                // TODO(matthias): verify that the parent view of the first block is always 0 (nullify)
                None
            } else {
                Some(Round::new(round.epoch(), View::new(parent.0)))
            };
            Either::Right(
                syncer
                    .subscribe(parent_round, parent.1)
                    .await
                    .map(|x| x.context("")),
            )
        };
        let parent = parent_request.await.expect("sender dropped");

        #[cfg(feature = "prom")]
        {
            let parent_fetch_duration = parent_fetch_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_parent_fetch_duration_millis")
                .record(parent_fetch_duration);
        }

        // STEP 2: Wait for finalizer notification
        #[cfg(feature = "prom")]
        let finalizer_wait_start = std::time::Instant::now();
        // now that we have the parent additionally await for that to be executed by the finalizer
        let rx = finalizer.notify_at_height(parent.height()).await;
        // await for notification
        rx.await.expect("Finalizer dropped");
        #[cfg(feature = "prom")]
        {
            let finalizer_wait_duration = finalizer_wait_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_finalizer_wait_duration_millis")
                .record(finalizer_wait_duration);
        }

        // STEP 3: Request aux data (withdrawals, checkpoint hash, header hash)
        #[cfg(feature = "prom")]
        let aux_data_start = std::time::Instant::now();
        let aux_data = finalizer
            .get_aux_data(parent.height() + 1)
            .await
            .await
            .expect("Finalizer dropped");
        #[cfg(feature = "prom")]
        {
            let aux_data_duration = aux_data_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_aux_data_duration_millis").record(aux_data_duration);
        }

        if aux_data.epoch != round.epoch().get() {
            // This might happen because the finalizer notifies the orchestrator at the end of an
            // epoch to shut down Simplex. While Simplex is being shutdown, it will still continue to produce blocks.
            return Err(anyhow!(
                "Aborting block proposal for epoch {}. Current epoch is {}",
                aux_data.epoch,
                aux_data.epoch
            ));
        }

        let pending_withdrawals = aux_data.withdrawals;
        let checkpoint_hash = aux_data.checkpoint_hash;

        let mut current = self.context.current().epoch_millis();
        if current <= parent.timestamp() {
            current = parent.timestamp() + 1;
        }

        // STEP 4: Start building block (Engine Client)
        #[cfg(feature = "prom")]
        let start_building_start = std::time::Instant::now();

        // Add pending withdrawals to the block
        let withdrawals = pending_withdrawals.into_iter().map(|w| w.inner).collect();
        let payload_id = {
            #[cfg(any(feature = "bench", feature = "base-bench"))]
            {
                self.engine_client
                    .start_building_block(
                        aux_data.forkchoice,
                        current,
                        withdrawals,
                        parent.height(),
                    )
                    .await
            }
            #[cfg(not(any(feature = "bench", feature = "base-bench")))]
            {
                self.engine_client
                    .start_building_block(aux_data.forkchoice, current, withdrawals)
                    .await
            }
        }
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
        let payload_envelope = self.engine_client.get_payload(payload_id).await;
        #[cfg(feature = "prom")]
        {
            let get_payload_duration = get_payload_start.elapsed().as_millis() as f64;
            histogram!("handle_proposal_get_payload_duration_millis").record(get_payload_duration);
        }

        // STEP 6: Compute block digest
        #[cfg(feature = "prom")]
        let compute_digest_start = std::time::Instant::now();

        let block = Block::compute_digest(
            parent.digest(),
            parent.height() + 1,
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
    S: Scheme,
    P: PublicKey,
    K: Signer,
    V: Variant,
> Drop for Actor<R, C, S, P, K, V>
{
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}

fn handle_verify<K: Signer, V: Variant>(block: &Block<K, V>, parent: Block<K, V>) -> bool {
    if block.parent() != parent.digest() {
        return false;
    }
    if block.height() != parent.height() + 1 {
        return false;
    }
    if block.timestamp() <= parent.timestamp() {
        return false;
    }

    true
}
