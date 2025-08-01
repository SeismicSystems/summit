use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::Reporter;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{hex, sequence::FixedBytes};
use futures::{
    SinkExt as _, StreamExt,
    channel::{mpsc, oneshot},
};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use rand::Rng;
use summit_types::Block;
use tracing::{info, warn};

use crate::engine_client::EngineClient;

const LATEST_KEY: [u8; 1] = [0u8];

pub struct Finalizer<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng> {
    context: R,

    last_indexed: u64,

    height_notifier: HeightNotifier,

    height_notify_mailbox: mpsc::Receiver<(u64, oneshot::Sender<()>)>,

    engine_client: EngineClient,

    forkchoice: Arc<Mutex<ForkchoiceState>>,

    rx_finalizer_mailbox: mpsc::Receiver<(Block, oneshot::Sender<()>)>,
}

impl<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng> Finalizer<R> {
    pub async fn new(
        context: R,
        engine_client: EngineClient,
        forkchoice: Arc<Mutex<ForkchoiceState>>,
        db_prefix: String,
    ) -> (
        Self,
        FinalizerMailbox,
        mpsc::Sender<(u64, oneshot::Sender<()>)>,
    ) {
        // Initialize finalizer metadata
        let metadata: Metadata<R, FixedBytes<1>, u64> = Metadata::init(
            context.with_label("finalizer_metadata"),
            metadata::Config {
                partition: format!("{}-finalizer_metadata", db_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("Failed to initialize finalizer metadata");

        let last_indexed = *metadata.get(&FixedBytes::new(LATEST_KEY)).unwrap_or(&0);

        let (tx_height_notify, height_notify_mailbox) = mpsc::channel(1000);

        let (tx_finalizer, rx_finalizer_mailbox) = mpsc::channel(1); // todo(dalton) there should only ever be one message in this channel since we block but lets verify this

        (
            Self {
                context,
                last_indexed,
                height_notifier: HeightNotifier::new(),
                height_notify_mailbox,
                engine_client,
                forkchoice,
                rx_finalizer_mailbox,
            },
            FinalizerMailbox::new(tx_finalizer),
            tx_height_notify,
        )
    }

    pub fn start(mut self) {
        self.context.spawn(move |_| async move {
            #[cfg(feature = "prom")]
            let mut last_committed_timestamp: Option<std::time::Instant> = None;
            loop {
                select! {
                    mail = self.height_notify_mailbox.next() => {
                        let (height, sender) = mail.expect("height notify mailbox dropped");

                        if self.last_indexed >= height {
                            let _ = sender.send(());
                            continue;
                        }

                        self.height_notifier.register(height, sender);
                    },

                    msg = self.rx_finalizer_mailbox.next() => {
                        let Some((block, notifier)) = msg else {
                            warn!("All senders to finalizer dropped");
                            break;
                        };

                        // check the payload
                        let payload_status = self.engine_client.check_payload(&block).await;

                        if payload_status.is_valid() {
                            let eth_hash = block.eth_block_hash();
                            let new_height = block.height;
                            info!("Commiting block 0x{} for height {}", hex(&eth_hash), new_height);

                            let forkchoice = ForkchoiceState {
                                head_block_hash: eth_hash.into(),
                                safe_block_hash: eth_hash.into(),
                                finalized_block_hash: eth_hash.into()
                            };

                            #[cfg(feature = "prom")]
                            {
                                let num_tx =
                                    block.payload.payload_inner.payload_inner.transactions.len();
                                counter!("tx_committed_total").increment(num_tx as u64);
                                counter!("blocks_committed_total").increment(1);
                                if let Some(last_committed) = last_committed_timestamp {
                                    let block_delta = last_committed.elapsed().as_millis() as f64;
                                    histogram!("block_time_millis").record(block_delta);
                                }
                                last_committed_timestamp = Some(std::time::Instant::now());
                            }

                            self.engine_client.commit_hash(forkchoice).await;

                            self.last_indexed = new_height;

                            *self.forkchoice.lock().expect("poisoned") = forkchoice;

                            self.height_notifier.notify_up_to(new_height);

                            info!(new_height, "finalized block");
                        }

                        let _ = notifier.send(());
                    },
                }
            }
        });
    }
}

struct HeightNotifier {
    pending: BTreeMap<u64, Vec<oneshot::Sender<()>>>,
}

impl HeightNotifier {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
        }
    }

    fn register(&mut self, height: u64, sender: oneshot::Sender<()>) {
        self.pending.entry(height).or_default().push(sender);
    }

    fn notify_up_to(&mut self, current_height: u64) {
        // Split off all entries <= current_height
        let to_notify = self.pending.split_off(&(current_height + 1));
        // The original map now contains only entries > current_height
        // Swap them back
        let remaining = std::mem::replace(&mut self.pending, to_notify);

        // Notify all the split-off entries
        for (_, senders) in remaining {
            for sender in senders {
                let _ = sender.send(()); // Ignore if receiver dropped
            }
        }
    }
}

#[derive(Clone)]
pub struct FinalizerMailbox {
    sender: mpsc::Sender<(Block, oneshot::Sender<()>)>,
}

impl FinalizerMailbox {
    pub fn new(sender: mpsc::Sender<(Block, oneshot::Sender<()>)>) -> Self {
        Self { sender }
    }
}

impl Reporter for FinalizerMailbox {
    type Activity = Block;

    async fn report(&mut self, activity: Self::Activity) {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send((activity, tx)).await;

        // wait until finalization finishes
        let _ = rx.await;
    }
}
