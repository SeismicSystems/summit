use crate::{
    ApplicationConfig,
    engine_client::EngineClient,
    finalizer::{Finalizer, FinalizerMailbox},
    ingress::{Mailbox, Message},
};
use alloy_rpc_types_engine::ForkchoiceState;
use anyhow::{Result, anyhow};
use commonware_consensus::marshal;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_utils::SystemTimeExt;
use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
    future::{self, Either, try_join},
};
use rand::Rng;

use futures::task::{Context, Poll};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use summit_types::{Block, Digest};
use tracing::{error, info, warn};

// Define a future that checks if the oneshot channel is closed using a mutable reference
struct ChannelClosedFuture<'a, T> {
    sender: &'a mut oneshot::Sender<T>,
}

impl<T> futures::Future for ChannelClosedFuture<'_, T> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
> {
    context: R,
    mailbox: mpsc::Receiver<Message>,
    engine_client: C,
    forkchoice: Arc<Mutex<ForkchoiceState>>,
    built_block: Arc<Mutex<Option<Block>>>,
    finalizer: Option<Finalizer<R, C>>,
    tx_height_notify: mpsc::Sender<(u64, oneshot::Sender<()>)>,
    genesis_hash: [u8; 32],
}

impl<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng, C: EngineClient>
    Actor<R, C>
{
    pub async fn new(context: R, cfg: ApplicationConfig<C>) -> (Self, Mailbox, FinalizerMailbox) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);

        let genesis_hash = cfg.genesis_hash;
        let forkchoice = Arc::new(Mutex::new(ForkchoiceState {
            head_block_hash: genesis_hash.into(),
            safe_block_hash: genesis_hash.into(),
            finalized_block_hash: genesis_hash.into(),
        }));

        let (finalizer, finalizer_mailbox, tx_height_notify) = Finalizer::new(
            context.with_label("finalizer"),
            cfg.engine_client.clone(),
            cfg.registry,
            forkchoice.clone(),
            cfg.partition_prefix,
            cfg.validator_onboarding_interval,
            cfg.validator_onboarding_limit_per_block,
            cfg.validator_minimum_stake,
        )
        .await;

        (
            Self {
                context,
                mailbox: rx,
                engine_client: cfg.engine_client,
                forkchoice,
                built_block: Arc::new(Mutex::new(None)),
                finalizer: Some(finalizer),
                tx_height_notify,
                genesis_hash,
            },
            Mailbox::new(tx),
            finalizer_mailbox,
        )
    }

    pub fn start(mut self, marshal: marshal::Mailbox<MinPk, Block>) -> Handle<()> {
        self.context.spawn_ref()(self.run(marshal))
    }

    pub async fn run(mut self, mut marshal: marshal::Mailbox<MinPk, Block>) {
        self.finalizer.take().expect("no finalizer").start();

        let rand_id: u8 = rand::random();
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { response } => {
                    info!("Handling message Genesis");
                    let _ = response.send(self.genesis_hash.into());
                }
                Message::Propose {
                    view,
                    parent,
                    mut response,
                } => {
                    info!("{rand_id} Handling message Propose view: {}", view);

                    let built = self.built_block.clone();
                    select! {
                            res = self.handle_proposal(parent, &mut marshal) => {
                                match res {
                                    Ok(block) => {
                                        // store block
                                        let digest = block.digest;
                                        {
                                            let mut built = built.lock().expect("locked poisoned");
                                            *built = Some(block);
                                        }

                                        // send digest to consensus
                                        let _ = response.send(digest);
                                    },
                                    Err(e) => warn!("Failed to create a block for height {view}: {e}")
                                }
                            },
                            _ = oneshot_closed_future(&mut response) => {
                                // simplex dropped reciever
                                warn!(view, "proposal aborted");
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
                    if payload != built_block.digest {
                        error!(
                            "The payload we were asked to broadcast is different then our built block"
                        );
                    }

                    marshal.broadcast(built_block).await;
                }

                Message::Verify {
                    view,
                    parent,
                    payload,
                    mut response,
                } => {
                    info!("{rand_id} Handling message Verify view: {}", view);
                    // Get the parent block
                    let parent_request = if parent.1 == self.genesis_hash.into() {
                        Either::Left(future::ready(Ok(Block::genesis(self.genesis_hash))))
                    } else {
                        Either::Right(marshal.subscribe(Some(parent.0), parent.1).await)
                    };

                    let block_request = marshal.subscribe(None, payload).await;

                    // Wait for the blocks to be available or the request to be cancelled in a separate task (to
                    // continue processing other messages)
                    self.context.with_label("verify").spawn({
                        let mut marshal = marshal.clone();
                        move |_| async move {
                            let requester = try_join(parent_request, block_request);
                            select! {
                                result = requester => {
                                    let (parent, block) = result.unwrap();
                                    if handle_verify(&block, parent) {

                                        // persist valid block
                                        marshal.verified(view, block).await;

                                        // respond
                                        let _ = response.send(true);
                                    } else {
                                        info!("Unsucceful vote");
                                        let _ = response.send(false);
                                    }
                                },
                                _ = oneshot_closed_future(&mut response) => {
                                    warn!(view, "verify aborted");
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    async fn handle_proposal(
        &mut self,
        parent: (u64, Digest),
        marshal: &mut marshal::Mailbox<MinPk, Block>,
    ) -> Result<Block> {
        // Get the parent block
        let parent_request = if parent.1 == self.genesis_hash.into() {
            Either::Left(future::ready(Ok(Block::genesis(self.genesis_hash))))
        } else {
            Either::Right(marshal.subscribe(Some(parent.0), parent.1).await)
        };

        let parent = parent_request.await.unwrap();

        // now that we have the parent additionally await for that to be executed by the finalizer
        let (tx, rx) = oneshot::channel();
        self.tx_height_notify
            .try_send((parent.height, tx))
            .expect("finalizer dropped");

        // await for notification
        rx.await.expect("Finalizer dropped");

        let mut current = self.context.current().epoch_millis();
        if current <= parent.timestamp {
            current = parent.timestamp + 1;
        }
        let forkchoice_clone;
        {
            forkchoice_clone = *self.forkchoice.lock().expect("poisoned");
        }

        let payload_id = self
            .engine_client
            .start_building_block(forkchoice_clone, current)
            .await
            .ok_or(anyhow!("Unable to build payload"))?;

        self.context.sleep(Duration::from_millis(50)).await;

        let payload_envelope = self.engine_client.get_payload(payload_id).await;

        let block = Block::compute_digest(
            parent.digest,
            parent.height + 1,
            current,
            payload_envelope.envelope_inner.execution_payload,
            payload_envelope.execution_requests.to_vec(),
            payload_envelope.envelope_inner.block_value,
        );

        Ok(block)
    }
}

fn handle_verify(block: &Block, parent: Block) -> bool {
    if block.eth_parent_hash() != parent.eth_block_hash() {
        return false;
    }
    if block.parent != parent.digest {
        return false;
    }
    if block.height != parent.height + 1 {
        return false;
    }
    if block.timestamp <= parent.timestamp {
        return false;
    }
    true
}
