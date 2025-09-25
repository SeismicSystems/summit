use crate::Registry;
use crate::db::{Config as StateConfig, FinalizerState};
use crate::engine_client::EngineClient;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
#[cfg(debug_assertions)]
use alloy_primitives::hex;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::{DecodeExt as _, ReadExt};
use commonware_consensus::Reporter;
use commonware_cryptography::Verifier;
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
use std::num::NonZero;
use std::time::Instant;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::execution_request::ExecutionRequest;
use summit_types::utils::{is_last_block_of_epoch, is_penultimate_block_of_epoch};
use summit_types::{
    Block, BlockAuxData, BlockEnvelope, Digest, FinalizedHeader, PublicKey, Signature,
};
use tracing::{info, warn};

type AuxDataRequest = (u64, oneshot::Sender<BlockAuxData>);

const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

pub struct Finalizer<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
> {
    context: R,

    height_notifier: HeightNotifier,

    height_notify_mailbox: mpsc::Receiver<(u64, oneshot::Sender<()>)>,

    aux_data_mailbox: mpsc::Receiver<AuxDataRequest>,

    engine_client: C,

    registry: Registry,

    forkchoice: Arc<Mutex<ForkchoiceState>>,

    rx_finalizer_mailbox: mpsc::Receiver<(BlockEnvelope, oneshot::Sender<()>)>,

    db: FinalizerState<R>,

    state: ConsensusState,

    validator_onboarding_limit_per_block: usize,

    validator_minimum_stake: u64, // in gwei

    validator_withdrawal_period: u64, // in blocks

    validator_max_withdrawals_per_block: usize,

    epoch_num_blocks: u64,

    genesis_hash: [u8; 32],

    protocol_version_digest: Digest,

    pending_checkpoint: Option<Checkpoint>,

    added_validators: Vec<PublicKey>,

    removed_validators: Vec<PublicKey>,
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
        validator_onboarding_limit_per_block: usize,
        validator_minimum_stake: u64,
        validator_withdrawal_period: u64,
        validator_max_withdrawals_per_block: usize,
        epoch_num_blocks: u64,
        genesis_hash: [u8; 32],
        protocol_version: u32,
        buffer_pool: PoolRef,
    ) -> (
        Self,
        FinalizerMailbox,
        mpsc::Sender<(u64, oneshot::Sender<()>)>,
        mpsc::Sender<AuxDataRequest>,
    ) {
        let state_cfg = StateConfig {
            log_journal_partition: format!("{db_prefix}-finalizer_state-log"),
            log_write_buffer: WRITE_BUFFER,
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(262_144),
            locations_journal_partition: format!("{db_prefix}-finalizer_state-locations"),
            locations_items_per_blob: NZU64!(262_144), // todo: No reference for this config option look into this
            translator: TwoCap,
            buffer_pool,
        };
        let db = FinalizerState::new(context.with_label("finalizer_state"), state_cfg).await;

        let (tx_height_notify, height_notify_mailbox) = mpsc::channel(1000);
        let (tx_aux_data, aux_data_mailbox) = mpsc::channel(1000);

        let (tx_finalizer, rx_finalizer_mailbox) = mpsc::channel(1); // todo(dalton) there should only ever be one message in this channel since we block but lets verify this

        let mut finalizer = Self {
            context,
            height_notifier: HeightNotifier::new(),
            height_notify_mailbox,
            aux_data_mailbox,
            engine_client,
            registry,
            forkchoice,
            rx_finalizer_mailbox,
            db,
            state: ConsensusState::default(),
            validator_onboarding_limit_per_block,
            validator_minimum_stake,
            validator_withdrawal_period,
            validator_max_withdrawals_per_block,
            epoch_num_blocks,
            genesis_hash,
            protocol_version_digest: commonware_cryptography::sha256::hash(
                &protocol_version.to_le_bytes(),
            ),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        // Try to load the latest ConsensusState from database
        if let Some(loaded_state) = finalizer.db.get_latest_consensus_state().await {
            finalizer.state = loaded_state;
        }

        (
            finalizer,
            FinalizerMailbox::new(tx_finalizer),
            tx_height_notify,
            tx_aux_data,
        )
    }

    pub fn start(mut self) {
        self.context.clone().spawn(move |
            #[cfg_attr(not(debug_assertions), allow(unused_variables))] ctx
            | async move {
            let mut last_committed_timestamp: Option<Instant> = None;
            loop {
                select! {
                    mail = self.height_notify_mailbox.next() => {
                        let (height, sender) = mail.expect("height notify mailbox dropped");

                        let last_indexed = self.state.get_latest_height();
                        if last_indexed >= height {
                            let _ = sender.send(());
                            continue;
                        }

                        self.height_notifier.register(height, sender);
                    },

                    mail = self.aux_data_mailbox.next() => {
                        let (height, sender) = mail.expect("aux data mailbox dropped");
                        self.handle_aux_data_mailbox(&ctx, height, sender).await;
                    },

                    msg = self.rx_finalizer_mailbox.next() => {
                        let Some((envelope, notifier)) = msg else {
                            warn!("All senders to finalizer dropped");
                            break;
                        };

                        self.handle_execution_block(&ctx, notifier, envelope, &mut last_committed_timestamp).await;
                    },
                }
            }
        });
    }

    async fn handle_execution_block(
        &mut self,
        ctx: &R,
        notifier: oneshot::Sender<()>,
        envelope: BlockEnvelope,
        #[cfg(feature = "prom")] last_committed_timestamp: &mut Option<Instant>,
        #[cfg(not(feature = "prom"))] _last_committed_timestamp: &mut Option<Instant>,
    ) {
        let BlockEnvelope { block, finalized } = envelope;
        // check the payload
        let payload_status = self.engine_client.check_payload(&block).await;
        let new_height = block.height();

        // Verify withdrawal requests that were included in the block
        // Make sure that the included withdrawals match the expected withdrawals
        let expected_withdrawals: Vec<Withdrawal> =
            if is_last_block_of_epoch(new_height, self.epoch_num_blocks) {
                let pending_withdrawals = self.state.get_next_ready_withdrawals(
                    new_height,
                    self.validator_max_withdrawals_per_block,
                );
                pending_withdrawals.into_iter().map(|w| w.inner).collect()
            } else {
                vec![]
            };
        if payload_status.is_valid()
            && block.payload.payload_inner.withdrawals == expected_withdrawals
        {
            let eth_hash = block.eth_block_hash();

            info!(
                "Commiting block 0x{} for height {}",
                hex(&eth_hash),
                new_height
            );

            let forkchoice = ForkchoiceState {
                head_block_hash: eth_hash.into(),
                safe_block_hash: eth_hash.into(),
                finalized_block_hash: eth_hash.into(),
            };

            #[cfg(feature = "prom")]
            {
                let num_tx = block.payload.payload_inner.payload_inner.transactions.len();
                counter!("tx_committed_total").increment(num_tx as u64);
                counter!("blocks_committed_total").increment(1);
                if let Some(last_committed) = last_committed_timestamp {
                    let block_delta = last_committed.elapsed().as_millis() as f64;
                    histogram!("block_time_millis").record(block_delta);
                }
                *last_committed_timestamp = Some(Instant::now());
            }

            self.engine_client.commit_hash(forkchoice).await;

            *self.forkchoice.lock().expect("poisoned") = forkchoice;

            // Parse execution requests
            self.parse_execution_requests(ctx, &block, new_height).await;

            // Add validators that deposited to the validator set
            self.process_execution_requests(ctx, &block, new_height)
                .await;

            #[cfg(debug_assertions)]
            {
                let gauge: Gauge = Gauge::default();
                gauge.set(new_height as i64);
                ctx.register("height", "chain height", gauge);
            }
            self.state.set_latest_height(new_height);

            // Periodically persist state to database as a blob
            // We build the checkpoint one height before the epoch end which
            // allows the validators to sign the checkpoint hash in the last block
            // of the epoch
            if is_penultimate_block_of_epoch(new_height, self.epoch_num_blocks) {
                let checkpoint = Checkpoint::new(&self.state);
                self.pending_checkpoint = Some(checkpoint);
            }

            // Store finalizes checkpoint to database
            if is_last_block_of_epoch(new_height, self.epoch_num_blocks) {
                let view = block.view();
                if let Some(finalized) = finalized {
                    // The finalized signatures should always be included on the last block
                    // of the epoch. However, there is an edge case, where the block after
                    // last block of the epoch arrived out of order.
                    // This is not critical and will likely never happen on all validators
                    // at the same time.
                    // TODO(matthias): figure out a good solution for making checkpoints available
                    debug_assert!(block.header.digest == finalized.proposal.payload);

                    // Store the finalized block header in the database
                    let finalized_header = FinalizedHeader {
                        header: block.header,
                        finalized,
                    };
                    self.db
                        .store_finalized_header(new_height, &finalized_header)
                        .await;

                    #[cfg(debug_assertions)]
                    {
                        let gauge: Gauge = Gauge::default();
                        gauge.set(new_height as i64);
                        ctx.register(
                            format!("<header>{}</header><prev_header>{}</prev_header>_finalized_header_stored",
                                    hex::encode(finalized_header.header.digest), hex::encode(finalized_header.header.prev_epoch_header_hash)),
                            "chain height",
                            gauge
                        );
                    }
                }

                // Add and remove validators for the next epoch
                if !self.added_validators.is_empty() || !self.removed_validators.is_empty() {
                    self.registry.update_registry(
                        // TODO(matthias): do we still need the DELTA?
                        //block.view() + REGISTRY_CHANGE_VIEW_DELTA,
                        view,
                        std::mem::take(&mut self.added_validators),
                        std::mem::take(&mut self.removed_validators),
                    );
                }

                let checkpoint = self
                    .pending_checkpoint
                    .as_ref()
                    .expect("this checkpoint was stored last height");
                self.db.store_finalized_checkpoint(checkpoint).await;
                self.db.store_consensus_state(new_height, &self.state).await;
                // This will commit all changes to the state db
                self.db.commit().await;

                #[cfg(debug_assertions)]
                {
                    let gauge: Gauge = Gauge::default();
                    gauge.set(new_height as i64);
                    ctx.register("consensus_state_stored", "chain height", gauge);
                }
            }

            self.height_notifier.notify_up_to(new_height);
            let _ = notifier.send(());

            info!(new_height, "finalized block");
        }
    }

    async fn parse_execution_requests(&mut self, ctx: &R, block: &Block, new_height: u64) {
        for request_bytes in &block.execution_requests {
            match ExecutionRequest::try_from_eth_bytes(request_bytes.as_ref()) {
                Ok(execution_request) => {
                    match execution_request {
                        ExecutionRequest::Deposit(deposit_request) => {
                            let message = deposit_request.as_message(self.protocol_version_digest);

                            let mut signature_bytes = &deposit_request.signature[..];
                            let Ok(signature) = Signature::read(&mut signature_bytes) else {
                                info!(
                                    "Failed to parse signature from deposit request: {deposit_request:?}"
                                );
                                continue; // Skip this deposit request
                            };
                            if !deposit_request.pubkey.verify(None, &message, &signature) {
                                #[cfg(debug_assertions)]
                                {
                                    let gauge: Gauge = Gauge::default();
                                    gauge.set(new_height as i64);
                                    ctx.register(
                                        format!(
                                            "<pubkey>{}</pubkey>_deposit_request_invalid_sig",
                                            hex::encode(&deposit_request.pubkey)
                                        ),
                                        "height",
                                        gauge,
                                    );
                                }
                                info!(
                                    "Failed to verify signature from deposit request: {deposit_request:?}"
                                );
                                continue; // Skip this deposit request
                            }

                            self.state.push_deposit(deposit_request);
                        }
                        ExecutionRequest::Withdrawal(mut withdrawal_request) => {
                            // Only add the withdrawal request if the validator exists and has sufficient balance
                            if let Some(mut account) = self
                                .state
                                .get_account(&withdrawal_request.validator_pubkey)
                                .cloned()
                            {
                                // Check that the validator is active and hasn't submitted an exit request
                                if matches!(
                                    account.status,
                                    ValidatorStatus::Inactive
                                        | ValidatorStatus::SubmittedExitRequest
                                ) {
                                    continue; // Skip this withdrawal request
                                }

                                // The balance minus any pending withdrawals have to be larger than the amount of the withdrawal request
                                if account.balance - account.pending_withdrawal_amount
                                    < withdrawal_request.amount
                                {
                                    continue; // Skip this withdrawal request
                                }

                                // The source address must match the validators withdrawal address
                                if withdrawal_request.source_address
                                    != account.withdrawal_credentials
                                {
                                    continue; // Skip this withdrawal request
                                }

                                // If after this withdrawal the validator balance would be less than the
                                // minimum stake, then the full validator balance is withdrawn.
                                if account.balance
                                    - account.pending_withdrawal_amount
                                    - withdrawal_request.amount
                                    < self.validator_minimum_stake
                                {
                                    // Check the remaining balance and set the withdrawal amount accordingly
                                    let remaining_balance =
                                        account.balance - account.pending_withdrawal_amount;
                                    withdrawal_request.amount = remaining_balance;
                                    account.status = ValidatorStatus::SubmittedExitRequest;
                                }

                                account.pending_withdrawal_amount += withdrawal_request.amount;
                                self.state
                                    .set_account(withdrawal_request.validator_pubkey, account);
                                self.state.push_withdrawal_request(
                                    withdrawal_request.clone(),
                                    new_height + self.validator_withdrawal_period,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse execution request: {}", e);
                }
            }
        }
    }

    async fn process_execution_requests(&mut self, ctx: &R, block: &Block, new_height: u64) {
        if is_penultimate_block_of_epoch(new_height, self.epoch_num_blocks) {
            for _ in 0..self.validator_onboarding_limit_per_block {
                if let Some(request) = self.state.pop_deposit() {
                    let mut validator_balance = 0;
                    let mut account_exists = false;
                    if let Some(mut account) = self
                        .state
                        .get_account(request.pubkey.as_ref().try_into().unwrap())
                        .cloned()
                    {
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
                            self.state
                                .set_account(request.pubkey.as_ref().try_into().unwrap(), account);
                            account_exists = true;
                        }
                    } else {
                        // Validate the withdrawal credentials format
                        // Eth1 withdrawal credentials: 0x01 + 11 zero bytes + 20 bytes Ethereum address
                        if request.withdrawal_credentials.len() != 32 {
                            warn!(
                                "Invalid withdrawal credentials length: {} bytes, expected 32",
                                request.withdrawal_credentials.len()
                            );
                            continue; // Skip this deposit
                        }
                        // Check prefix is 0x01 (Eth1 withdrawal)
                        if request.withdrawal_credentials[0] != 0x01 {
                            warn!(
                                "Invalid withdrawal credentials prefix: 0x{:02x}, expected 0x01",
                                request.withdrawal_credentials[0]
                            );
                            continue; // Skip this deposit
                        }
                        // Check 11 zero bytes after the prefix
                        if !request.withdrawal_credentials[1..12]
                            .iter()
                            .all(|&b| b == 0)
                        {
                            warn!(
                                "Invalid withdrawal credentials format: non-zero bytes in positions 1-11"
                            );
                            continue; // Skip this deposit
                        }

                        // Create new ValidatorAccount from DepositRequest
                        let new_account = ValidatorAccount {
                            withdrawal_credentials: Address::from_slice(
                                &request.withdrawal_credentials[12..32],
                            ), // Take last 20 bytes
                            balance: request.amount,
                            pending_withdrawal_amount: 0,
                            status: ValidatorStatus::Active,
                            last_deposit_index: request.index,
                        };
                        self.state
                            .set_account(request.pubkey.as_ref().try_into().unwrap(), new_account);
                        validator_balance = request.amount;
                    }
                    if !account_exists && validator_balance >= self.validator_minimum_stake {
                        // If the node shuts down, before the account changes are committed,
                        // then everything should work normally, because the registry is not persisted to disk
                        self.added_validators.push(request.pubkey.clone());
                    }
                    #[cfg(debug_assertions)]
                    {
                        let gauge: Gauge = Gauge::default();
                        gauge.set(validator_balance as i64);
                        ctx.register(
                            format!("<registry>{}</registry><creds>{}</creds><pubkey>{}</pubkey>_deposit_validator_balance",
                                    !account_exists && validator_balance >= self.validator_minimum_stake,
                                    hex::encode(request.withdrawal_credentials), hex::encode(request.pubkey)),
                            "Validator balance",
                            gauge
                        );
                    }
                }
            }
        }

        // Remove pending withdrawals that are included in the committed block
        for withdrawal in &block.payload.payload_inner.withdrawals {
            let pending_withdrawal = self.state.pop_withdrawal();
            // TODO(matthias): these checks should never fail. we have to make sure that these withdrawals are
            // verified when the block is verified. it is too late when the block is committed.
            let pending_withdrawal =
                pending_withdrawal.expect("pending withdrawal must be in state");
            assert_eq!(pending_withdrawal.inner, *withdrawal);

            if let Some(mut account) = self.state.get_account(&pending_withdrawal.pubkey).cloned()
                && account.balance >= withdrawal.amount
            {
                // This check should never fail, because we checked the balance when
                // adding the pending withdrawal to the queue
                account.balance = account.balance.saturating_sub(withdrawal.amount);
                account.pending_withdrawal_amount = account
                    .pending_withdrawal_amount
                    .saturating_sub(withdrawal.amount);

                #[cfg(debug_assertions)]
                {
                    let gauge: Gauge = Gauge::default();
                    gauge.set(account.balance as i64);
                    ctx.register(
                        format!(
                            "<creds>{}</creds><pubkey>{}</pubkey>_withdrawal_validator_balance",
                            hex::encode(account.withdrawal_credentials),
                            hex::encode(pending_withdrawal.pubkey)
                        ),
                        "Validator balance",
                        gauge,
                    );
                }

                // If the remaining balance is 0, remove the validator account from the state.
                if account.balance == 0 {
                    self.state.remove_account(&pending_withdrawal.pubkey);
                    self.removed_validators
                        .push(PublicKey::decode(&pending_withdrawal.pubkey[..]).unwrap()); // todo(dalton) remove unwrap
                } else {
                    self.state.set_account(pending_withdrawal.pubkey, account);
                }
            }
        }
    }

    async fn handle_aux_data_mailbox(
        &mut self,
        _ctx: &R,
        height: u64,
        sender: oneshot::Sender<BlockAuxData>,
    ) {
        // TODO(matthias): the height notify should take care of the synchronization, but verify this
        // Get ready withdrawals at the current height

        // Create checkpoint if we're at an epoch boundary.
        // The consensus state is saved every `epoch_num_blocks` blocks.
        // The proposed block will contain the checkpoint that was saved at the previous height.
        let aux_data = if is_last_block_of_epoch(height, self.epoch_num_blocks) {
            // TODO(matthias): revisit this expect when the ckpt isn't in the DB
            let checkpoint_hash = if let Some(checkpoint) = &self.pending_checkpoint {
                checkpoint.digest
            } else {
                unreachable!("pending checkpoint was calculated at the previous height")
            };
            // TODO(matthias): should we verify the ckpt height against the `height` variable?

            // This is not the header from the last block, but the header from
            // the block that contains the last checkpoint
            let prev_header_hash =
                if let Some(finalized_header) = self.db.get_most_recent_finalized_header().await {
                    finalized_header.header.digest
                } else {
                    self.genesis_hash.into()
                };

            // Only submit withdrawals at the end of an epoch
            let ready_withdrawals = self
                .state
                .get_next_ready_withdrawals(height, self.validator_max_withdrawals_per_block);
            BlockAuxData {
                withdrawals: ready_withdrawals,
                checkpoint_hash: Some(checkpoint_hash),
                header_hash: prev_header_hash,
                added_validators: self.added_validators.clone(),
                removed_validators: self.removed_validators.clone(),
            }
        } else {
            BlockAuxData {
                withdrawals: vec![],
                checkpoint_hash: None,
                header_hash: [0; 32].into(),
                added_validators: vec![],
                removed_validators: vec![],
            }
        };
        let _ = sender.send(aux_data);
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
    sender: mpsc::Sender<(BlockEnvelope, oneshot::Sender<()>)>,
}

impl FinalizerMailbox {
    pub fn new(sender: mpsc::Sender<(BlockEnvelope, oneshot::Sender<()>)>) -> Self {
        Self { sender }
    }
}

impl Reporter for FinalizerMailbox {
    type Activity = BlockEnvelope;

    async fn report(&mut self, activity: Self::Activity) {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send((activity, tx)).await;

        // wait until finalization finishes
        let _ = rx.await;
    }
}
