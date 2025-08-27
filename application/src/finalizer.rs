use crate::Registry;
use crate::db::{Config as StateConfig, FinalizerState};
use crate::engine_client::EngineClient;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
#[cfg(debug_assertions)]
use alloy_primitives::hex;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::Reporter;
use commonware_macros::select;
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::translator::TwoCap;
use commonware_utils::hex;
use commonware_utils::{NZU64, NZUsize};
use futures::{
    SinkExt as _, StreamExt,
    channel::{mpsc, oneshot},
};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
#[cfg(debug_assertions)]
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use summit_types::Block;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::execution_request::ExecutionRequest;
use summit_types::withdrawal::PendingWithdrawal;
use tracing::{info, warn};

const PAGE_SIZE: usize = 77;
const PAGE_CACHE_SIZE: usize = 9;
const REGISTRY_CHANGE_VIEW_DELTA: u64 = 3;

pub struct Finalizer<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
> {
    context: R,

    height_notifier: HeightNotifier,

    height_notify_mailbox: mpsc::Receiver<(u64, oneshot::Sender<()>)>,

    pending_withdrawal_mailbox: mpsc::Receiver<(u64, oneshot::Sender<Vec<PendingWithdrawal>>)>,

    engine_client: C,

    registry: Registry,

    forkchoice: Arc<Mutex<ForkchoiceState>>,

    rx_finalizer_mailbox: mpsc::Receiver<(Block, oneshot::Sender<()>)>,

    state: FinalizerState<R>,

    validator_onboarding_interval: u64,

    validator_onboarding_limit_per_block: usize,

    validator_minimum_stake: u64, // in gwei

    validator_withdrawal_period: u64, // in blocks

    validator_max_withdrawals_per_block: usize,
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
        validator_withdrawal_period: u64,
        validator_max_withdrawals_per_block: usize,
    ) -> (
        Self,
        FinalizerMailbox,
        mpsc::Sender<(u64, oneshot::Sender<()>)>,
        mpsc::Sender<(u64, oneshot::Sender<Vec<PendingWithdrawal>>)>,
    ) {
        let state_cfg = StateConfig {
            log_journal_partition: format!("{db_prefix}-finalizer_state-log"),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            locations_journal_partition: format!("{db_prefix}-finalizer_state-locations"),
            locations_items_per_blob: NZU64!(4),
            translator: TwoCap,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        };
        let state = FinalizerState::new(context.with_label("finalizer_state"), state_cfg).await;

        let (tx_height_notify, height_notify_mailbox) = mpsc::channel(1000);
        let (tx_pending_withdrawal, pending_withdrawal_mailbox) = mpsc::channel(1000);

        let (tx_finalizer, rx_finalizer_mailbox) = mpsc::channel(1); // todo(dalton) there should only ever be one message in this channel since we block but lets verify this

        (
            Self {
                context,
                height_notifier: HeightNotifier::new(),
                height_notify_mailbox,
                pending_withdrawal_mailbox,
                engine_client,
                registry,
                forkchoice,
                rx_finalizer_mailbox,
                state,
                validator_onboarding_interval,
                validator_onboarding_limit_per_block,
                validator_minimum_stake,
                validator_withdrawal_period,
                validator_max_withdrawals_per_block,
            },
            FinalizerMailbox::new(tx_finalizer),
            tx_height_notify,
            tx_pending_withdrawal,
        )
    }

    pub fn start(mut self) {
        self.context.spawn(move |ctx| async move {
            #[cfg(feature = "prom")]
            let mut last_committed_timestamp: Option<std::time::Instant> = None;
            loop {
                select! {
                    mail = self.height_notify_mailbox.next() => {
                        let (height, sender) = mail.expect("height notify mailbox dropped");

                        let last_indexed = self.state.get_latest_height().await;
                        if last_indexed >= height {
                            let _ = sender.send(());
                            continue;
                        }

                        self.height_notifier.register(height, sender);
                    },

                    mail = self.pending_withdrawal_mailbox.next() => {
                        let (height, sender) = mail.expect("pending withdrawal mailbox dropped");

                        // TODO(matthias): the height notify should take care of the synchronization, but verify this
                        // Get ready withdrawals at the current height
                        let ready_withdrawals = self.state
                            .get_next_ready_withdrawals(height, self.validator_max_withdrawals_per_block)
                            .await;
                        let _ = sender.send(ready_withdrawals);
                    },

                    msg = self.rx_finalizer_mailbox.next() => {
                        let Some((block, notifier)) = msg else {
                            warn!("All senders to finalizer dropped");
                            break;
                        };

                        // check the payload
                        let payload_status = self.engine_client.check_payload(&block).await;
                        let new_height = block.height;

                        // Verify withdrawal requests that were included in the block
                        // Make sure that the included withdrawals match the expected withdrawals
                        let pending_withdrawals = self.state
                            .get_next_ready_withdrawals(new_height, self.validator_max_withdrawals_per_block)
                            .await;
                        let expected_withdrawals: Vec<Withdrawal> =
                            pending_withdrawals.into_iter().map(|w| w.inner).collect();

                        if payload_status.is_valid() && block.payload.payload_inner.withdrawals == expected_withdrawals {
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
                                                self.state.push_deposit(deposit_request).await;
                                            }
                                            ExecutionRequest::Withdrawal(mut withdrawal_request) => {
                                                // Only add the withdrawal request if the validator exists and has sufficient balance
                                                if let Some(mut account) = self.state.get_account(&withdrawal_request.validator_pubkey).await {
                                                    // Check that the validator is active and hasn't submitted an exit request
                                                    if matches!(account.status, ValidatorStatus::Inactive | ValidatorStatus::SubmittedExitRequest) {
                                                        continue; // Skip this withdrawal request
                                                    }

                                                    // The balance minus any pending withdrawals have to be larger than the amount of the withdrawal request
                                                    if account.balance - account.pending_withdrawal_amount < withdrawal_request.amount {
                                                        continue; // Skip this withdrawal request
                                                    }

                                                    // The source address must match the validators withdrawal address
                                                    if withdrawal_request.source_address != account.withdrawal_credentials {
                                                        continue; // Skip this withdrawal request
                                                    }

                                                    // If after this withdrawal the validator balance would be less than the
                                                    // minimum stake, then the full validator balance is withdrawn.
                                                    if account.balance - account.pending_withdrawal_amount - withdrawal_request.amount < self.validator_minimum_stake {
                                                        // Check the remaining balance and set the withdrawal amount accordingly
                                                        let remaining_balance = account.balance - account.pending_withdrawal_amount;
                                                        withdrawal_request.amount = remaining_balance;
                                                        account.status = ValidatorStatus::SubmittedExitRequest;
                                                    }

                                                    account.pending_withdrawal_amount += withdrawal_request.amount;
                                                    self.state.set_account(&withdrawal_request.validator_pubkey, account).await;
                                                    self.state.push_withdrawal_request(withdrawal_request.clone(), new_height + self.validator_withdrawal_period).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse execution request: {}", e);
                                    }
                                }
                            }

                            // Add validators that deposited to the validator set
                            let mut add_validators = Vec::new();
                            let last_indexed = self.state.get_latest_height().await;
                            if last_indexed % self.validator_onboarding_interval == 0 {
                                for _ in 0..self.validator_onboarding_limit_per_block {
                                    if let Some(request) = self.state.pop_deposit().await {
                                        let mut validator_balance = 0;
                                        let mut account_exists = false;
                                        if let Some(mut account) = self.state.get_account(&request.bls_pubkey).await {
                                            if request.index > account.last_deposit_index {
                                                account.balance += request.amount;
                                                account.last_deposit_index = request.index;
                                                #[allow(unused)]
                                                #[cfg(debug_assertions)]
                                                {
                                                    validator_balance = account.balance;
                                                }
                                                account.last_deposit_index = request.index;
                                                validator_balance = account.balance;
                                                self.state.set_account(&request.bls_pubkey, account).await;
                                                account_exists = true;
                                            }
                                        } else {
                                            // Validate the withdrawal credentials format
                                            // Eth1 withdrawal credentials: 0x01 + 11 zero bytes + 20 bytes Ethereum address
                                            if request.withdrawal_credentials.len() != 32 {
                                                warn!("Invalid withdrawal credentials length: {} bytes, expected 32", request.withdrawal_credentials.len());
                                                continue; // Skip this deposit
                                            }
                                            // Check prefix is 0x01 (Eth1 withdrawal)
                                            if request.withdrawal_credentials[0] != 0x01 {
                                                warn!("Invalid withdrawal credentials prefix: 0x{:02x}, expected 0x01", request.withdrawal_credentials[0]);
                                                continue; // Skip this deposit
                                            }
                                            // Check 11 zero bytes after the prefix
                                            if !request.withdrawal_credentials[1..12].iter().all(|&b| b == 0) {
                                                warn!("Invalid withdrawal credentials format: non-zero bytes in positions 1-11");
                                                continue; // Skip this deposit
                                            }

                                            // Create new ValidatorAccount from DepositRequest
                                            let new_account = ValidatorAccount {
                                                ed25519_pubkey: request.ed25519_pubkey.clone(),
                                                withdrawal_credentials: Address::from_slice(&request.withdrawal_credentials[12..32]), // Take last 20 bytes
                                                balance: request.amount,
                                                pending_withdrawal_amount: 0,
                                                status: ValidatorStatus::Active,
                                                last_deposit_index: request.index,
                                            };
                                            self.state.set_account(&request.bls_pubkey, new_account).await;
                                            validator_balance = request.amount;

                                        }
                                        #[cfg(debug_assertions)]
                                        {
                                            let gauge: Gauge = Gauge::default();
                                            gauge.set(validator_balance as i64);
                                            ctx.register(
                                                format!("<creds>{}</creds><ed_key>{}</ed_key><bls_key>{}</bls_key>_deposit_validator_balance",
                                                hex::encode(request.withdrawal_credentials), request.ed25519_pubkey, hex::encode(request.bls_pubkey)),
                                                "Validator balance",
                                                gauge
                                            );
                                        }
                                        if !account_exists && validator_balance >= self.validator_minimum_stake {
                                            // If the node shuts down, before the account changes are committed,
                                            // then everything should work normally, because the registry is not persisted to disk
                                            add_validators.push(request.ed25519_pubkey.clone());
                                        }
                                    }
                                }
                            }

                            // Remove pending withdrawals that are included in the committed block
                            let mut remove_validators = Vec::new();
                            for withdrawal in block.payload.payload_inner.withdrawals {
                                let pending_withdrawal = self.state.pop_withdrawal().await;
                                // TODO(matthias): these checks should never fail. we have to make sure that these withdrawals are
                                // verified when the block is verified. it is too late when the block is committed.
                                let pending_withdrawal = pending_withdrawal.expect("pending withdrawal must be in state");
                                assert_eq!(pending_withdrawal.inner, withdrawal);

                                if let Some(mut account) = self.state.get_account(&pending_withdrawal.bls_pubkey).await {
                                    if account.balance >= withdrawal.amount {
                                        // This check should never fail, because we checked the balance when
                                        // adding the pending withdrawal to the queue
                                        account.balance = account.balance.saturating_sub(withdrawal.amount);
                                        account.pending_withdrawal_amount = account.pending_withdrawal_amount.saturating_sub(withdrawal.amount);

                                        #[cfg(debug_assertions)]
                                        {
                                            let gauge: Gauge = Gauge::default();
                                            gauge.set(account.balance as i64);
                                            ctx.register(
                                                format!("<creds>{}</creds><ed_key>{}</ed_key><bls_key>{}</bls_key>_withdrawal_validator_balance",
                                                hex::encode(account.withdrawal_credentials), account.ed25519_pubkey, hex::encode(pending_withdrawal.bls_pubkey)),
                                                "Validator balance",
                                                gauge
                                            );
                                        }

                                        // If the remaining balance is 0, mark the validator as inactive.
                                        // An argument can be made from removing the validator account from the DB here.
                                        if account.balance == 0 {
                                            account.status = ValidatorStatus::Inactive;
                                            remove_validators.push(account.ed25519_pubkey.clone());
                                        }

                                        self.state.set_account(&pending_withdrawal.bls_pubkey, account).await;
                                    }
                                }
                            }

                            // We collect two lists, one for validators we want to add, and the other for validators we want to remove.
                            // This is done so that the registry is updated atomically.
                            if !add_validators.is_empty() || !remove_validators.is_empty() {
                                self.registry.update_registry(block.view + REGISTRY_CHANGE_VIEW_DELTA, add_validators, remove_validators);
                            }

                            // TODO(matthias): verify what happens if the binary shuts down before storing the deposits to disk.
                            // I think it should be okay, because we only set `last_indexed` after writing to disk.

                            info!(new_height, "finalized block");
                        }

                        // This will commit all changes to the state db
                        #[cfg(debug_assertions)]
                        {
                            let gauge: Gauge = Gauge::default();
                            gauge.set(new_height as i64);
                            ctx.register(
                                "height",
                                "chain height",
                                gauge
                            );
                        }
                        self.state.set_latest_height(new_height).await;
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
