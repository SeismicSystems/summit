use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{hex, sequence::FixedBytes};
use futures::{
    StreamExt,
    channel::{mpsc, oneshot},
};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use rand::Rng;
use summit_syncer::Orchestrator;
use tracing::{debug, info};

use crate::engine_client::EngineClient;

const LATEST_KEY: [u8; 1] = [0u8];

pub struct Finalizer<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng> {
    context: R,

    last_indexed: u64,

    height_notifier: HeightNotifier,

    metadata: Metadata<R, FixedBytes<1>, u64>,

    height_notify_mailbox: mpsc::Receiver<(u64, oneshot::Sender<()>)>,

    engine_client: EngineClient,

    forkchoice: Arc<Mutex<ForkchoiceState>>,
}

impl<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng> Finalizer<R> {
    pub async fn new(
        context: R,
        engine_client: EngineClient,
        forkchoice: Arc<Mutex<ForkchoiceState>>,
        db_prefix: String,
    ) -> (Self, mpsc::Sender<(u64, oneshot::Sender<()>)>) {
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

        (
            Self {
                context,
                last_indexed,
                height_notifier: HeightNotifier::new(),
                metadata,
                height_notify_mailbox,
                engine_client,
                forkchoice,
            },
            tx_height_notify,
        )
    }

    pub fn start(mut self, mut orchestrator: Orchestrator, mut rx_new_block: mpsc::Receiver<()>) {
        self.context.spawn(move |_| async move {
            // check if the orchestrator has our next block
            let latest_key = FixedBytes::new(LATEST_KEY);
            #[cfg(feature = "prom")]
            let mut last_committed_timestamp: Option<std::time::Instant> = None;
            loop {
                // Check if the next block is available
                let next = self.last_indexed + 1;
                if let Some(block) = orchestrator.get(next).await {
                    // check the payload
                    let payload_status = self.engine_client.check_payload(&block).await;

                    if payload_status.is_valid() {
                        // its valid so commit the block
                        let eth_hash = block.eth_block_hash();
                        info!("Commiting block 0x{} for height {}", hex(&eth_hash), next);

                        let forkchoice = ForkchoiceState {
                            head_block_hash: eth_hash.into(),
                            safe_block_hash: eth_hash.into(),
                            finalized_block_hash: eth_hash.into(),
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

                        *self.forkchoice.lock().expect("poisoned") = forkchoice;

                        self.metadata.put(latest_key.clone(), next);
                        self.metadata
                            .sync()
                            .await
                            .expect("Failed to sync finalizer");

                        // Update the latest indexed
                        //self.contiguous_height.set(next as i64);
                        self.last_indexed = next;

                        // notify any waiters that height changed
                        self.height_notifier.notify_up_to(next);

                        info!(height = next, "indexed finalized block");

                        orchestrator.processed(next, block.digest).await;
                        continue;
                    }
                }

                // Try to connect to our latest handled block (may not exist finalizations for some heights)
                if orchestrator.repair(next).await {
                    continue;
                }

                // If nothing to do, wait for some message from someone that the finalized store was updated
                debug!(height = next, "waiting to index finalized block");
                select! {
                    mail = self.height_notify_mailbox.next() => {
                        let (height, sender) = mail.expect("height notify mailbox dropped");

                        if self.last_indexed >= height {
                            let _ = sender.send(());
                            continue;
                        }

                        self.height_notifier.register(height, sender);
                    },

                    _ = rx_new_block.next() => {
                        continue;
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
