use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::Registry;
use crate::engine_client::EngineClient;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::Reporter;
use commonware_macros::select;
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{Config, Metadata};
use commonware_storage::translator::TwoCap;
use commonware_utils::{NZU64, NZUsize};
use commonware_utils::{hex, sequence::FixedBytes};
use futures::{
    SinkExt as _, StreamExt,
    channel::{mpsc, oneshot},
};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
use rand::Rng;
use summit_types::Block;
use summit_types::execution_request::{DepositRequest, ExecutionRequest, WithdrawalRequest};
use summit_utils::persistent_queue::{Config as PersistentQueueConfig, PersistentQueue};
use tracing::{info, warn};

const LATEST_KEY: [u8; 1] = [0u8];
const PAGE_SIZE: usize = 77;
const PAGE_CACHE_SIZE: usize = 9;

pub struct Finalizer<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
> {
    context: R,

    height_notifier: HeightNotifier,

    height_notify_mailbox: mpsc::Receiver<(u64, oneshot::Sender<()>)>,

    engine_client: C,

    registry: Registry,

    forkchoice: Arc<Mutex<ForkchoiceState>>,

    rx_finalizer_mailbox: mpsc::Receiver<(Block, oneshot::Sender<()>)>,

    deposit_queue: PersistentQueue<R, DepositRequest>,

    withdrawal_queue: PersistentQueue<R, WithdrawalRequest>,

    accounts: Metadata<R, FixedBytes<48>, DepositRequest>,

    state_variables: Metadata<R, FixedBytes<1>, u64>,

    validator_onboarding_interval: u64,

    validator_onboarding_limit_per_block: usize,

    validator_minimum_stake: u64, // in gwei
}

impl<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng, C: EngineClient>
    Finalizer<R, C>
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        context: R,
        engine_client: C,
        registry: Registry,
        forkchoice: Arc<Mutex<ForkchoiceState>>,
        db_prefix: String,
        validator_onboarding_interval: u64,
        validator_onboarding_limit_per_block: usize,
        validator_minimum_stake: u64,
    ) -> (
        Self,
        FinalizerMailbox,
        mpsc::Sender<(u64, oneshot::Sender<()>)>,
    ) {
        let deposit_queue_cfg = PersistentQueueConfig {
            log_journal_partition: format!("{db_prefix}-finalizer_deposit_queue-log"),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!("{db_prefix}-finalizer_deposit_queue-locations"),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        };
        let deposit_queue = PersistentQueue::<R, DepositRequest>::new(
            context.with_label("finalizer_deposit_queue"),
            deposit_queue_cfg,
        )
        .await;

        let withdrawal_queue_cfg = PersistentQueueConfig {
            log_journal_partition: format!("{db_prefix}-finalizer_withdrawal_queue-log"),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!(
                "{db_prefix}-finalizer_withdrawal_queue-locations"
            ),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        };
        let withdrawal_queue = PersistentQueue::<R, WithdrawalRequest>::new(
            context.with_label("finalizer_withdrawal_queue"),
            withdrawal_queue_cfg,
        )
        .await;

        let accounts: Metadata<R, FixedBytes<48>, DepositRequest> = Metadata::init(
            context.with_label("finalizer_accounts"),
            Config {
                partition: format!("{db_prefix}-finalizer_accounts"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize account metadata");

        let state_variables: Metadata<R, FixedBytes<1>, u64> = Metadata::init(
            context.with_label("finalizer_state"),
            Config {
                partition: format!("{db_prefix}-finalizer_state"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize state variables metadata");

        let (tx_height_notify, height_notify_mailbox) = mpsc::channel(1000);

        let (tx_finalizer, rx_finalizer_mailbox) = mpsc::channel(1); // todo(dalton) there should only ever be one message in this channel since we block but lets verify this

        (
            Self {
                context,
                height_notifier: HeightNotifier::new(),
                height_notify_mailbox,
                engine_client,
                registry,
                forkchoice,
                rx_finalizer_mailbox,
                deposit_queue,
                withdrawal_queue,
                accounts,
                state_variables,
                validator_onboarding_interval,
                validator_onboarding_limit_per_block,
                validator_minimum_stake,
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

                        let last_indexed = *self.state_variables.get(&FixedBytes::new(LATEST_KEY)).unwrap_or(&0);
                        if last_indexed >= height {
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
                        let new_height = block.height;
                        if payload_status.is_valid() {
                            let eth_hash = block.eth_block_hash();

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

                            *self.forkchoice.lock().expect("poisoned") = forkchoice;

                            // Parse execution requests
                            for request_bytes in block.execution_requests {
                                match ExecutionRequest::try_from(request_bytes.as_ref()) {
                                    Ok(execution_request) => {
                                        match execution_request {
                                            ExecutionRequest::Deposit(deposit_request) => {
                                                self.deposit_queue.push(deposit_request).await;
                                            }
                                            ExecutionRequest::Withdrawal(withdrawal_request) => {
                                                self.withdrawal_queue.push(withdrawal_request).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse execution request: {}", e);
                                    }
                                }
                            }

                            // Add validators that deposited to the validator set
                            let last_indexed = *self.state_variables.get(&FixedBytes::new(LATEST_KEY)).unwrap_or(&0);
                            if last_indexed % self.validator_onboarding_interval == 0 {
                                for _ in 0..self.validator_onboarding_limit_per_block {
                                    if let Some(request) = self.deposit_queue.peek().await {
                                        let mut validator_balance = 0;
                                        if let Some(account) = self.accounts.get_mut(&FixedBytes::new(request.bls_pubkey)) {
                                            // Since we only remove the request from the queue after processing it,
                                            // it can happen that the binary crashes, and then we will process the same request twice.
                                            // If the index matches, we are processing the same request that we already processed. In that
                                            // case we won't increment the balance.
                                            if request.index > account.index {
                                                account.amount += request.amount;
                                                validator_balance += account.amount;

                                            }
                                        } else {
                                            self.accounts.put(FixedBytes::new(request.bls_pubkey), request.clone());
                                            validator_balance += request.amount;
                                        }
                                        if validator_balance > self.validator_minimum_stake {
                                            if let Err(e) = self.registry.add_participant(request.ed25519_pubkey.clone(), last_indexed) {
                                                // This only happens if the key already exists
                                                warn!("Failed to add validator: {}", e);
                                            }
                                        }

                                        // Only remove the request from the queue after we processed and stored it
                                        let _ = self.deposit_queue.pop().await;
                                    }

                                }
                            }

                            // TODO(matthias): verify what happens if the binary shuts down before storing the deposits to disk.
                            // I think it should be okay, because we only set `last_indexed` after writing to disk.

                            info!(new_height, "finalized block");
                        }

                        self.state_variables.put(FixedBytes::new(LATEST_KEY), new_height);
                        self.height_notifier.notify_up_to(new_height);
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
