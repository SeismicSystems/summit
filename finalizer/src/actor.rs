use crate::config::ProtocolConsts;
use crate::db::{Config as StateConfig, FinalizerState};
use crate::{FinalizerConfig, FinalizerMailbox, FinalizerMessage};
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
#[allow(unused)]
use commonware_codec::{DecodeExt as _, ReadExt as _, Write as _};
use commonware_consensus::Reporter;
use commonware_consensus::simplex::scheme::bls12381_multisig;
use commonware_consensus::simplex::types::Finalization;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{Digestible, Hasher, Sha256, Signer, Verifier as _, bls12381};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::translator::EightCap;
use commonware_utils::acknowledgement::{Acknowledgement, Exact};
use commonware_utils::{NZU64, NZUsize, hex};
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt as _, select};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
#[cfg(debug_assertions)]
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::num::NonZero;
use std::time::Instant;
use summit_orchestrator::Message;
use summit_syncer::Update;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state_query::{ConsensusStateRequest, ConsensusStateResponse};
use summit_types::execution_request::{DepositRequest, ExecutionRequest, WithdrawalRequest};
use summit_types::network_oracle::NetworkOracle;
use summit_types::protocol_params::ProtocolParam;
use summit_types::scheme::EpochTransition;
use summit_types::ssz_state_tree::SszProof;
use summit_types::ssz_tree_key::SszStateKey;
use summit_types::utils::{
    is_first_block_of_epoch, is_last_block_of_epoch, is_penultimate_block_of_epoch,
    parse_withdrawal_credentials,
};
use summit_types::{
    AddedValidator, Block, BlockAuxData, Digest, FinalizedHeader, PublicKey, Signature,
};
use summit_types::{EngineClient, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositRejectionReason {
    Refund,
    InvalidSignature,
}

fn deposit_refund_key(domain_tag: u8, withdrawal_address: Address, deposit_index: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = domain_tag;
    key[1..9].copy_from_slice(&deposit_index.to_le_bytes());
    key[12..32].copy_from_slice(withdrawal_address.as_ref());
    key
}

fn refunded_deposit_key(withdrawal_address: Address, deposit_index: u64) -> [u8; 32] {
    deposit_refund_key(0xFE, withdrawal_address, deposit_index)
}

fn invalid_signature_refund_key(withdrawal_address: Address, deposit_index: u64) -> [u8; 32] {
    deposit_refund_key(0xFF, withdrawal_address, deposit_index)
}

/// Tracks the consensus state for a notarized (but not yet finalized) block
#[derive(Clone, Debug)]
struct ForkState {
    block_digest: Digest,
    consensus_state: ConsensusState,
}

pub struct Finalizer<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    O: NetworkOracle<PublicKey>,
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
> {
    mailbox: mpsc::Receiver<FinalizerMessage<bls12381_multisig::Scheme<PublicKey, V>, Block>>,
    pending_height_notifys: BTreeMap<(u64, Digest), Vec<oneshot::Sender<bool>>>,
    context: ContextCell<R>,
    engine_client: C,
    db: FinalizerState<R, V>,

    // Canonical state (finalized) - contains latest_height
    canonical_state: ConsensusState,

    // Fork states (notarized but not yet finalized)
    fork_states: BTreeMap<u64, BTreeMap<Digest, ForkState>>,

    // Orphaned notarized blocks that arrived before their parent
    orphaned_blocks: BTreeMap<u64, HashMap<Digest, Vec<Block>>>,

    genesis_hash: [u8; 32],
    protocol_consts: ProtocolConsts,
    protocol_version_digest: Digest,
    oracle: O,
    node_public_key: PublicKey,
    validator_exit: bool,
    cancellation_token: CancellationToken,
    _signer_marker: PhantomData<S>,
    _variant_marker: PhantomData<V>,
    #[cfg(debug_assertions)]
    height_gauge: Gauge,
    #[cfg(debug_assertions)]
    consensus_state_stored_gauge: Gauge,
}

impl<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    O: NetworkOracle<PublicKey>,
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
> Finalizer<R, C, O, S, V>
{
    pub async fn new(
        context: R,
        cfg: FinalizerConfig<C, O, V>,
    ) -> (
        Self,
        ConsensusState,
        FinalizerMailbox<bls12381_multisig::Scheme<PublicKey, V>, Block>,
    ) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let state_cfg = StateConfig {
            log_partition: format!("{}-finalizer_state-log", cfg.db_prefix),
            log_write_buffer: WRITE_BUFFER,
            log_compression: None,
            log_codec_config: ((), ()),
            log_items_per_section: NZU64!(262_144),
            translator: EightCap,
            page_cache: cfg.page_cache,
        };

        let db =
            FinalizerState::<R, V>::new(context.with_label("finalizer_state"), state_cfg).await;

        // Check if the state exists in the database. Otherwise, use the initial state.
        // The initial state could be from the genesis or a checkpoint.
        // If we want to load a checkpoint, we have to make sure that the DB is cleared.
        let state = if let Some(state) = db.get_latest_consensus_state().await {
            info!(
                epoch = state.get_epoch(),
                height = state.get_latest_height(),
                num_validators = state.num_validators(),
                "loaded consensus state from database"
            );
            state
        } else {
            info!(
                epoch = cfg.initial_state.get_epoch(),
                height = cfg.initial_state.get_latest_height(),
                num_validators = cfg.initial_state.num_validators(),
                epoch_length = cfg.initial_state.get_epocher().current_length(),
                "using provided initial state (no state found in database)"
            );
            cfg.initial_state
        };

        // Register debug gauges before moving context into ContextCell
        #[cfg(debug_assertions)]
        let height_gauge = {
            let gauge: Gauge = Gauge::default();
            context.register("height", "chain height", gauge.clone());
            gauge
        };
        #[cfg(debug_assertions)]
        let consensus_state_stored_gauge = {
            let gauge: Gauge = Gauge::default();
            context.register(
                "consensus_state_stored",
                "consensus state stored",
                gauge.clone(),
            );
            gauge
        };

        (
            Self {
                context: ContextCell::new(context),
                mailbox: rx,
                engine_client: cfg.engine_client,
                oracle: cfg.oracle,
                pending_height_notifys: BTreeMap::new(),
                db,
                canonical_state: state.clone(),
                fork_states: BTreeMap::new(),
                orphaned_blocks: BTreeMap::new(),
                genesis_hash: cfg.genesis_hash,
                protocol_consts: cfg.protocol_consts,
                protocol_version_digest: Sha256::hash(&cfg.protocol_version.to_le_bytes()),
                node_public_key: cfg.node_public_key,
                validator_exit: false,
                cancellation_token: cfg.cancellation_token,
                _signer_marker: PhantomData,
                _variant_marker: PhantomData,
                #[cfg(debug_assertions)]
                height_gauge,
                #[cfg(debug_assertions)]
                consensus_state_stored_gauge,
            },
            state,
            FinalizerMailbox::new(tx),
        )
    }

    pub fn start(mut self, orchestrator_mailbox: summit_orchestrator::Mailbox) -> Handle<()> {
        spawn_cell!(self.context, self.run(orchestrator_mailbox).await)
    }

    pub async fn run(mut self, mut orchestrator_mailbox: summit_orchestrator::Mailbox) {
        let mut last_committed_timestamp: Option<Instant> = None;
        let mut signal = self.context.stopped().fuse();
        let cancellation_token = self.cancellation_token.clone();

        // Initialize the current epoch with the validator set
        // This ensures the orchestrator can start consensus immediately
        let active_validators = self.canonical_state.get_active_validators();
        let network_keys: Vec<_> = active_validators
            .iter()
            .map(|(node_key, _)| node_key.clone())
            .collect();
        self.oracle
            .track(self.canonical_state.get_epoch(), network_keys)
            .await;

        orchestrator_mailbox
            .report(Message::Enter(EpochTransition {
                epoch: Epoch::new(self.canonical_state.get_epoch()),
                validator_keys: active_validators,
            }))
            .await;

        // Send initial forkchoice to the execution client so it knows the chain
        // head and can start P2P sync. Then wait for sync to complete before
        // replaying any blocks. Without this, catch-up blocks fail because the
        // execution client doesn't have them yet.
        {
            let forkchoice = self.canonical_state.get_forkchoice();
            if !forkchoice.head_block_hash.is_zero() {
                info!(
                    head = %forkchoice.head_block_hash,
                    "sending initial forkchoice update to execution client, waiting for sync..."
                );
                loop {
                    let status = self.engine_client.commit_hash(*forkchoice).await;
                    if status.is_valid() {
                        info!("execution client synced to checkpoint head, ready to replay blocks");
                        break;
                    } else if status.is_syncing() {
                        warn!("execution client still syncing, waiting 5s...");
                        self.context.sleep(std::time::Duration::from_secs(5)).await;
                    } else {
                        panic!("finalizer started with invalid forkchoice");
                    }
                }
            }
        }

        loop {
            if self.validator_exit
                && is_first_block_of_epoch(
                    self.canonical_state.get_epocher(),
                    self.canonical_state.get_latest_height(),
                )
            {
                // If the validator was removed from the committee, trigger coordinated shutdown
                info!("Validator no longer on the committee, shutting down");
                self.cancellation_token.cancel();
                break;
            }
            select! {
                mailbox_message = self.mailbox.next() => {
                    let mail = mailbox_message.expect("Finalizer mailbox closed");
                    match mail {
                        FinalizerMessage::SyncerUpdate { update } => {
                            match update {
                                Update::Tip(_height, _digest) => {
                                    // I don't think we need this
                                }
                                Update::FinalizedBlock((block, finalization), ack_tx) => {
                                    self.handle_finalized_block(ack_tx, block, finalization, &mut orchestrator_mailbox, &mut last_committed_timestamp).await;
                                }
                                Update::NotarizedBlock(block) => {
                                    self.handle_notarized_block(block).await;
                                }
                            }
                        },
                        FinalizerMessage::NotifyAtHeight { height, block_digest, response } => {
                            if self.canonical_state.get_latest_height() > height {
                                // This block proposal is trying to build a block at height + 1,
                                // but the canonical chain is already at height + 1 (or higher),
                                // so the proposal should be aborted.
                                let _ = response.send(false);
                                warn!(
                                    "Aborting height notification for height {} and digest {} at epoch {} and height {} because the height is outdated",
                                    height,
                                    block_digest,
                                    self.canonical_state.get_epoch(),
                                    self.canonical_state.get_latest_height()
                                );
                            } else if height == self.canonical_state.get_latest_height() {
                                // If the height matches the height of the canonical chain,
                                // we check if the digest matches the head of the canonical chain.
                                // If the digests don't match, then the proposal should be aborted.
                                if block_digest == self.canonical_state.get_head_digest() {
                                    let _ = response.send(true);
                                } else {
                                    let _ = response.send(false);
                                    warn!(
                                        "Aborting height notification for height {} and digest {} at epoch {} and height {} because the head digest is {}",
                                        height,
                                        block_digest,
                                        self.canonical_state.get_epoch(),
                                        self.canonical_state.get_latest_height(),
                                        self.canonical_state.get_head_digest()
                                    );
                                }
                            } else {
                                // If the block was already executed on one of the forks,
                                // we send the notification immediately, otherwise we store the request
                                if self.fork_states.get(&height)
                                        .map(|forks| forks.contains_key(&block_digest))
                                        .unwrap_or(false) {
                                    let _ = response.send(true);
                                } else {
                                    self.pending_height_notifys.entry((height, block_digest)).or_default().push(response);
                                }
                            }
                        },
                        FinalizerMessage::GetAuxData { height, parent_digest, response } => {
                            self.handle_aux_data_mailbox(height, parent_digest, response).await;
                        },
                        FinalizerMessage::GetEpochGenesisHash { epoch, response } => {
                            // The finalizer sends a message to the orchestrator to start the new epoch.
                            // The orchestrator will start the new Simplex instance, which will then request
                            // the epoch genesis hash from the finalizer.
                            // Since the finalizer increments `self.canonical_state.epoch` before sending the message to the
                            // orchestrator, the finalizer should never receive a GetEpochGenesisHash request for the wrong epoch.
                            if epoch != self.canonical_state.get_epoch() {
                                error!("Finalizer received epoch genesis hash request from a diffent epoch. This should not happen and is a bug. Our epoch: {}, requested epoch {}", self.canonical_state.get_epoch(), epoch);
                            }
                            let _ = response.send(self.canonical_state.get_epoch_genesis_hash());
                        },
                        FinalizerMessage::QueryState { request, response } => {
                            self.handle_consensus_state_query(request, response).await;
                        },
                    }
                }
                _ = cancellation_token.cancelled().fuse() => {
                    info!("finalizer received cancellation signal, exiting");
                    break;
                },
                sig = &mut signal => {
                    info!("runtime terminated, shutting down finalizer: {}", sig.unwrap());
                    break;
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    async fn handle_finalized_block(
        &mut self,
        ack_tx: Exact,
        block: Block,
        finalization: Option<
            Finalization<bls12381_multisig::Scheme<PublicKey, V>, <Block as Digestible>::Digest>,
        >,
        orchestrator_mailbox: &mut summit_orchestrator::Mailbox,
        #[allow(unused_variables)] last_committed_timestamp: &mut Option<Instant>,
    ) {
        let height = block.height();
        let block_digest = block.digest();

        // Try to find the fork state for this block (if it was notarized before finalization)
        if let Some(fork_state) = self
            .fork_states
            .get(&height)
            .and_then(|forks_at_height| forks_at_height.get(&block_digest))
        {
            // Block was already executed when notarized, reuse the fork state
            debug_assert_eq!(
                fork_state.block_digest, block_digest,
                "Fork state digest mismatch: expected {:?}, stored {:?}",
                block_digest, fork_state.block_digest
            );
            debug!(
                height,
                ?block_digest,
                "reusing fork state for finalized block"
            );
            self.canonical_state = fork_state.consensus_state.clone();
        } else {
            // Block was not notarized before finalization (catch-up or missed notarization)
            // Execute it now on canonical state
            debug!(
                height,
                ?block_digest,
                "executing finalized block directly (no prior fork state)"
            );
            execute_block(
                &mut self.engine_client,
                &self.context,
                &block,
                &mut self.canonical_state,
                &self.protocol_consts,
                self.protocol_version_digest,
            )
            .await;
        }

        #[cfg(debug_assertions)]
        self.height_gauge.set(height as i64);

        self.canonical_state.set_forkchoice_safe_and_finalized(
            self.canonical_state.get_forkchoice().head_block_hash,
        );

        // Prune fork states at or below finalized height
        let total_forks = self.fork_states.len();
        self.fork_states.retain(|&h, _| h > height);
        let remaining_forks = self.fork_states.len();
        let num_pruned_forks = total_forks - remaining_forks;
        if num_pruned_forks > 0 {
            debug!(height, pruned = num_pruned_forks, "pruned fork states");
        }

        // Prune orphaned blocks at or below finalized height
        let total_orphans = self.orphaned_blocks.len();
        self.orphaned_blocks.retain(|&h, _| h > height);
        let remaining_orphans = self.orphaned_blocks.len();
        let num_pruned_orphans = total_orphans - remaining_orphans;
        if num_pruned_orphans > 0 {
            debug!(
                height,
                pruned = num_pruned_orphans,
                "pruned orphaned blocks"
            );
        }

        self.engine_client
            .commit_hash(*self.canonical_state.get_forkchoice())
            .await;

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

        let new_height = block.height();
        self.height_notify_up_to(new_height, block_digest);
        ack_tx.acknowledge();
        info!(
            new_height,
            epoch = self.canonical_state.get_epoch(),
            "executed block"
        );

        let new_height = block.height();
        let mut epoch_change = false; // Store finalizes checkpoint to database
        if is_last_block_of_epoch(self.canonical_state.get_epocher(), new_height) {
            // The syncer will always send the last block of an epoch together with
            // the finalization.
            let finalization = finalization
                .expect("finalization is always included for the last block of an epoch");
            debug_assert!(block.header.digest == finalization.proposal.payload);
            // Get participant count from the certificate signers
            let participant_count = finalization.certificate.signers.len();

            // Store the finalized block header in the database
            let finalized_header =
                FinalizedHeader::new(block.header.clone(), finalization, participant_count);

            #[cfg(feature = "prom")]
            let header_start = Instant::now();
            self.db
                .store_finalized_header(self.canonical_state.get_epoch(), &finalized_header)
                .await;
            #[cfg(feature = "prom")]
            {
                let header_duration = header_start.elapsed().as_micros() as f64;
                histogram!("finalizer_db_finalized_header_write_micros").record(header_duration);
            }

            #[cfg(debug_assertions)]
            {
                let gauge: Gauge = Gauge::default();
                gauge.set(new_height as i64);
                self.context.register(
                    format!(
                        "<header>{}</header><prev_header>{}</prev_header>_finalized_header_stored",
                        hex::encode(finalized_header.header.digest),
                        hex::encode(finalized_header.header.prev_epoch_header_hash)
                    ),
                    "chain height",
                    gauge,
                );
            }

            // Apply protocol parameter changes
            let stake_changed = self.canonical_state.apply_protocol_parameter_changes();

            // Build the committee for the next epoch.
            self.validator_exit = self.update_validator_committee(stake_changed);

            #[cfg(feature = "prom")]
            let db_operations_start = Instant::now();
            // This pending checkpoint should always exist, because it was created at the previous height.
            // The only case where the pending checkpoint doesn't exist here is if the node checkpointed.
            // The checkpoint is created at the penultimate block of the epoch, and finalized at the last
            // block. So if a node checkpoints, it will start at the height of the penultimate block.
            if let Some(checkpoint) = &self.canonical_state.take_pending_checkpoint() {
                debug!(
                    epoch = self.canonical_state.get_epoch(),
                    checkpoint_digest = ?checkpoint.digest,
                    "storing finalized checkpoint to database"
                );
                #[cfg(feature = "prom")]
                let checkpoint_start = Instant::now();
                self.db
                    .store_finalized_checkpoint(
                        self.canonical_state.get_epoch(),
                        checkpoint,
                        block.clone(),
                    )
                    .await;
                #[cfg(feature = "prom")]
                {
                    let checkpoint_duration = checkpoint_start.elapsed().as_micros() as f64;
                    histogram!("finalizer_db_checkpoint_write_micros").record(checkpoint_duration);
                }
            }

            // Increment epoch
            let next_epoch = self.canonical_state.get_epoch() + 1;
            self.canonical_state.set_epoch(next_epoch);
            self.canonical_state
                .get_epocher()
                .advance_epoch(Epoch::new(next_epoch));
            // Set the epoch genesis hash for the next epoch
            self.canonical_state
                .set_epoch_genesis_hash(block.digest().0);

            let active_count = self.canonical_state.get_active_validators().len();
            let joining_count = self
                .canonical_state
                .validator_accounts_iter()
                .filter(|(_, a)| a.status == ValidatorStatus::Joining)
                .count();
            info!(
                epoch = self.canonical_state.get_epoch(),
                active_validators = active_count,
                joining_validators = joining_count,
                "transitioned to new epoch"
            );

            #[cfg(feature = "prom")]
            let consensus_state_start = Instant::now();
            self.db
                .store_consensus_state(self.canonical_state.get_epoch(), &self.canonical_state)
                .await;
            #[cfg(feature = "prom")]
            {
                let consensus_state_duration = consensus_state_start.elapsed().as_micros() as f64;
                histogram!("finalizer_db_consensus_state_write_micros")
                    .record(consensus_state_duration);
            }
            #[cfg(debug_assertions)]
            self.consensus_state_stored_gauge.set(new_height as i64);

            // This will commit all changes to the state db
            #[cfg(feature = "prom")]
            let commit_start = Instant::now();
            self.db.commit().await;
            #[cfg(feature = "prom")]
            {
                let commit_duration = commit_start.elapsed().as_micros() as f64;
                histogram!("finalizer_db_commit_micros").record(commit_duration);
                let db_operations_duration = db_operations_start.elapsed().as_millis() as f64;
                histogram!("database_operations_duration_millis").record(db_operations_duration);
                counter!("finalizer_epochs_completed_total").increment(1);
            }

            // Clear the added and removed validators
            let current_epoch = self.canonical_state.get_epoch();
            self.canonical_state
                .remove_added_validators_for_epoch(current_epoch);
            if self.canonical_state.has_removed_validators() {
                self.canonical_state.clear_removed_validators();
            }

            // Create the list of validators for the p2p network for the next epoch.
            // We also include the validators that already staked and are waiting to join the committee.
            let active_validators = self.canonical_state.get_active_or_joining_validators();
            let network_keys = active_validators
                .iter()
                .map(|(node_key, _)| node_key.clone())
                .collect();
            self.oracle
                .track(self.canonical_state.get_epoch(), network_keys)
                .await;

            // Send the new validator list to the orchestrator and start the Simplex engine
            // for the new epoch
            let active_validators = self.canonical_state.get_active_validators();
            debug!(
                epoch = self.canonical_state.get_epoch(),
                num_active_validators = active_validators.len(),
                "signaling orchestrator to enter new epoch"
            );

            orchestrator_mailbox
                .report(Message::Enter(EpochTransition {
                    epoch: Epoch::new(self.canonical_state.get_epoch()),
                    validator_keys: active_validators,
                }))
                .await;
            epoch_change = true;
        }

        if epoch_change {
            // Shut down the Simplex engine for the old epoch
            debug!(
                old_epoch = self.canonical_state.get_epoch() - 1,
                "signaling orchestrator to exit old epoch"
            );
            orchestrator_mailbox
                .report(Message::Exit(Epoch::new(
                    self.canonical_state.get_epoch() - 1,
                )))
                .await;
        }
        let tx_count = block.payload.payload_inner.payload_inner.transactions.len();
        info!(
            new_height,
            view = block.view(),
            epoch = self.canonical_state.get_epoch(),
            tx_count,
            "finalized block"
        );

        // After advancing canonical, re-adopt orphaned blocks at height+1
        // whose parent is the block that was just finalized.
        let orphaned_children = self
            .orphaned_blocks
            .get_mut(&(height + 1))
            .and_then(|children_map| children_map.remove(&block_digest));
        if let Some(children_map) = self.orphaned_blocks.get(&(height + 1))
            && children_map.is_empty()
        {
            self.orphaned_blocks.remove(&(height + 1));
        }
        if let Some(children) = orphaned_children {
            info!(
                height,
                num_children = children.len(),
                "re-adopting orphaned blocks after finalization"
            );
            for child in children {
                self.handle_notarized_block(child).await;
            }
        }
    }

    async fn handle_notarized_block(&mut self, block: Block) {
        let mut to_process = vec![block];

        while let Some(block) = to_process.pop() {
            let height = block.height();
            let parent_digest = block.parent();
            let block_digest = block.digest();

            // Ignore blocks at or below canonical height
            if height <= self.canonical_state.get_latest_height() {
                debug!(
                    height,
                    "ignoring notarized block at or below canonical height"
                );
                continue;
            }

            // Find and clone parent state: either canonical (if parent was finalized) or a fork state
            let parent_state = if height == self.canonical_state.get_latest_height() + 1 {
                // Parent should be the canonical block (was finalized)
                // Verify parent digest matches canonical head (skip check at genesis)
                if self.canonical_state.get_latest_height() > 0
                    && parent_digest != self.canonical_state.get_head_digest()
                {
                    // Block is on a dead fork, discard it
                    debug!(
                        height,
                        ?parent_digest,
                        canonical_head = ?self.canonical_state.get_head_digest(),
                        "discarding notarized block on dead fork (parent mismatch with canonical)"
                    );
                    continue;
                }
                Some(self.canonical_state.clone())
            } else {
                // Parent should be in fork_states
                self.fork_states
                    .get(&(height - 1))
                    .and_then(|forks_at_parent| {
                        let parent_fork = forks_at_parent.get(&parent_digest)?;
                        debug_assert_eq!(
                            parent_fork.block_digest,
                            parent_digest,
                            "Parent fork state digest mismatch at height {}: expected {:?}, stored {:?}",
                            height - 1,
                            parent_digest,
                            parent_fork.block_digest
                        );
                        Some(parent_fork.consensus_state.clone())
                    })
            };

            // If we can't find the parent, buffer as orphaned
            let Some(mut fork_state) = parent_state else {
                debug!(
                    height,
                    ?parent_digest,
                    "buffering orphaned notarized block - parent not found"
                );
                self.orphaned_blocks
                    .entry(height)
                    .or_default()
                    .entry(parent_digest)
                    .or_default()
                    .push(block);
                continue;
            };

            // Execute the block into the cloned parent state
            execute_block(
                &mut self.engine_client,
                &self.context,
                &block,
                &mut fork_state,
                &self.protocol_consts,
                self.protocol_version_digest,
            )
            .await;

            // Store the new fork state
            self.fork_states.entry(height).or_default().insert(
                block_digest,
                ForkState {
                    block_digest,
                    consensus_state: fork_state.clone(),
                },
            );

            // Commit this fork to reth so validators can build/verify blocks on top of it
            // Keep the canonical finalized chain unchanged by using canonical finalized hash
            let fork_forkchoice = ForkchoiceState {
                head_block_hash: fork_state.get_forkchoice().head_block_hash,
                safe_block_hash: self.canonical_state.get_forkchoice().finalized_block_hash,
                finalized_block_hash: self.canonical_state.get_forkchoice().finalized_block_hash,
            };
            self.engine_client.commit_hash(fork_forkchoice).await;

            let total_fork_count: usize = self.fork_states.values().map(|f| f.len()).sum();
            info!(
                height,
                view = block.view(),
                ?block_digest,
                "executed notarized block into fork"
            );
            trace!(
                height,
                total_fork_states = total_fork_count,
                heights_tracked = self.fork_states.len(),
                "fork state summary"
            );
            self.height_notify_up_to(height, block_digest);

            // Add orphaned children to the processing queue
            if let Some(children) = self
                .orphaned_blocks
                .get(&(height + 1))
                .and_then(|children_map| children_map.get(&block_digest))
            {
                debug!(
                    height,
                    num_children = children.len(),
                    "queueing orphaned children"
                );
                to_process.extend(children.clone());
            }
        }
    }

    fn height_notify_up_to(&mut self, height: u64, block_digest: Digest) {
        // Notify only waiters for this specific (height, digest) pair
        if let Some(senders) = self.pending_height_notifys.remove(&(height, block_digest)) {
            for sender in senders {
                let _ = sender.send(true); // Ignore if receiver dropped
            }
        }
    }

    async fn handle_aux_data_mailbox(
        &mut self,
        height: u64,
        parent_digest: Digest,
        sender: oneshot::Sender<Option<BlockAuxData>>,
    ) {
        // We're building a block at `height`, so we need state from parent at `height - 1`
        let parent_height = height - 1;

        // Look up the specific parent block's state
        let state = if let Some(fork_state) = self
            .fork_states
            .get(&parent_height)
            .and_then(|forks| forks.get(&parent_digest))
        {
            &fork_state.consensus_state
        } else if parent_height == self.canonical_state.get_latest_height()
            && parent_digest == self.canonical_state.get_head_digest()
        {
            // If not in forks, check if the height and digest match those of the canonical chain
            &self.canonical_state
        } else {
            warn!(
                "Aborted aux data request with parent height {} and parent digest {} for block that doesn't connect to any forks or the canonical chain. Canonical height {} and head digest {}",
                parent_height,
                parent_digest,
                self.canonical_state.get_latest_height(),
                self.canonical_state.get_head_digest(),
            );
            let _ = sender.send(None);
            return;
        };

        let treasury_address = state.get_treasury_address();
        // The zero address is a sentinel value.
        // If the treasury address is the zero address, the suggested_fee_recipient will be
        // set to the validator's withdrawal credentials.
        let suggested_fee_recipient = if treasury_address.is_zero() {
            state
                .get_account(
                    self.node_public_key
                        .as_ref()
                        .try_into()
                        .expect("Safe: Ed pub key always 32 bytes"),
                )
                .map(|account| account.withdrawal_credentials)
                .unwrap_or_default()
        } else {
            treasury_address
        };

        // Create checkpoint if we're at an epoch boundary.
        // The consensus state is saved every `epoch_num_blocks` blocks.
        // The proposed block will contain the checkpoint that was saved at the previous height.
        let is_last = is_last_block_of_epoch(self.canonical_state.get_epocher(), height);
        let aux_data = if is_last {
            // The pending_checkpoint should have been set when processing the penultimate block.
            // If it's None, we can't propose the last block (e.g., node restarted from checkpoint).
            // Return None to let another validators propose/validate this block.
            let Some(checkpoint) = state.get_pending_checkpoint() else {
                warn!(
                    height,
                    "pending_checkpoint is None at last block of epoch, aborting aux data request"
                );
                let _ = sender.send(None);
                return;
            };
            let checkpoint_hash = checkpoint.digest;

            // This is not the header from the last block, but the header from
            // the block that contains the last checkpoint
            let prev_header_hash =
                if let Some(finalized_header) = self.db.get_most_recent_finalized_header().await {
                    finalized_header.header.digest
                } else {
                    self.genesis_hash.into()
                };

            // Only submit withdrawals at the end of an epoch
            let current_epoch = state.get_epoch();
            let ready_withdrawals = state
                .get_withdrawals_for_epoch(current_epoch)
                .into_iter()
                .cloned()
                .collect();
            let next_epoch = state.get_epoch() + 1;

            BlockAuxData {
                epoch: state.get_epoch(),
                withdrawals: ready_withdrawals,
                checkpoint_hash: Some(checkpoint_hash),
                header_hash: prev_header_hash,
                // The block proposer needs the validators that will be added in the next epoch
                added_validators: state
                    .get_added_validators(next_epoch)
                    .cloned()
                    .unwrap_or_default(),
                removed_validators: state.get_removed_validators().clone(),
                forkchoice: *state.get_forkchoice(),
                suggested_fee_recipient,
                state_root: state.get_state_root(),
                allowed_timestamp_future_ms: state.get_allowed_timestamp_future_ms(),
            }
        } else {
            BlockAuxData {
                epoch: state.get_epoch(),
                withdrawals: vec![],
                checkpoint_hash: None,
                header_hash: [0; 32].into(),
                added_validators: vec![],
                removed_validators: vec![],
                forkchoice: *state.get_forkchoice(),
                suggested_fee_recipient,
                state_root: state.get_state_root(),
                allowed_timestamp_future_ms: state.get_allowed_timestamp_future_ms(),
            }
        };
        trace!(
            height,
            epoch = aux_data.epoch,
            num_withdrawals = aux_data.withdrawals.len(),
            has_checkpoint = aux_data.checkpoint_hash.is_some(),
            "prepared aux data for block proposal"
        );
        let _ = sender.send(Some(aux_data));
    }

    async fn handle_consensus_state_query(
        &self,
        consensus_state_request: ConsensusStateRequest,
        sender: oneshot::Sender<ConsensusStateResponse<bls12381_multisig::Scheme<PublicKey, V>>>,
    ) {
        match consensus_state_request {
            ConsensusStateRequest::GetLatestCheckpoint => {
                let checkpoint = self.db.get_latest_finalized_checkpoint().await;
                let _ = sender.send(ConsensusStateResponse::LatestCheckpoint(checkpoint));
            }
            ConsensusStateRequest::GetCheckpoint(epoch) => {
                let checkpoint = self.db.get_finalized_checkpoint(epoch).await;
                let _ = sender.send(ConsensusStateResponse::Checkpoint(checkpoint));
            }
            ConsensusStateRequest::GetLatestHeight => {
                let height = self.canonical_state.get_latest_height();
                let _ = sender.send(ConsensusStateResponse::LatestHeight(height));
            }
            ConsensusStateRequest::GetLatestEpoch => {
                let epoch = self.canonical_state.get_epoch();
                let _ = sender.send(ConsensusStateResponse::LatestEpoch(epoch));
            }
            ConsensusStateRequest::GetValidatorBalance(public_key) => {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&public_key);

                let balance = self.canonical_state.get_account(&key_bytes).map(|account| {
                    account.balance
                        + self
                            .canonical_state
                            .get_pending_withdrawal_amount(&key_bytes)
                });
                let _ = sender.send(ConsensusStateResponse::ValidatorBalance(balance));
            }
            ConsensusStateRequest::GetValidatorAccount(public_key) => {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&public_key);

                let account = self.canonical_state.get_account(&key_bytes).cloned();
                let _ = sender.send(ConsensusStateResponse::ValidatorAccount(account));
            }
            ConsensusStateRequest::GetFinalizedHeader(epoch) => {
                let header = self.db.get_finalized_header(epoch).await;
                let _ = sender.send(ConsensusStateResponse::FinalizedHeader(header));
            }
            ConsensusStateRequest::GetMinimumStake => {
                let stake = self.canonical_state.get_minimum_stake();
                let _ = sender.send(ConsensusStateResponse::MinimumStake(stake));
            }
            ConsensusStateRequest::GetMaximumStake => {
                let stake = self.canonical_state.get_maximum_stake();
                let _ = sender.send(ConsensusStateResponse::MaximumStake(stake));
            }
            ConsensusStateRequest::GetEpochLength => {
                let length = self.canonical_state.get_epocher().current_length();
                let _ = sender.send(ConsensusStateResponse::EpochLength(length));
            }
            ConsensusStateRequest::GetAllowedTimestampFuture => {
                let ms = self.canonical_state.get_allowed_timestamp_future_ms();
                let _ = sender.send(ConsensusStateResponse::AllowedTimestampFuture(ms));
            }
            ConsensusStateRequest::GetTreasuryAddress => {
                let address = self.canonical_state.get_treasury_address();
                let _ = sender.send(ConsensusStateResponse::TreasuryAddress(address));
            }
            ConsensusStateRequest::GetMaxDepositsPerEpoch => {
                let value = self.canonical_state.get_max_deposits_per_epoch();
                let _ = sender.send(ConsensusStateResponse::MaxDepositsPerEpoch(value));
            }
            ConsensusStateRequest::GetEpochBounds(epoch) => {
                let bounds = self
                    .canonical_state
                    .get_epocher()
                    .epoch_bounds(Epoch::new(epoch))
                    .map(|(first, last)| (first.get(), last.get()));
                let _ = sender.send(ConsensusStateResponse::EpochBounds(bounds));
            }
            ConsensusStateRequest::GetDeposit(index) => {
                let deposit = self.canonical_state.get_deposit(index).cloned();
                let _ = sender.send(ConsensusStateResponse::Deposit(deposit));
            }
            ConsensusStateRequest::GetDepositCount => {
                let count = self.canonical_state.deposit_count();
                let _ = sender.send(ConsensusStateResponse::DepositCount(count));
            }
            ConsensusStateRequest::GetWithdrawal(pubkey) => {
                let withdrawal = self.canonical_state.get_withdrawal(&pubkey).cloned();
                let _ = sender.send(ConsensusStateResponse::Withdrawal(withdrawal));
            }
            ConsensusStateRequest::GetStateRoot => {
                let root = self.canonical_state.get_state_root();
                let el_block_number = self.canonical_state.get_proof_el_block_number();
                let _ = sender.send(ConsensusStateResponse::StateRoot {
                    root,
                    el_block_number,
                });
            }
            ConsensusStateRequest::GenerateStateProof(keys) => {
                let proof_tree = self.canonical_state.proof_tree();
                let proofs: Vec<SszProof> = keys
                    .iter()
                    .filter_map(|key| match key {
                        SszStateKey::Scalar(leaf_index) => {
                            Some(proof_tree.generate_scalar_proof(*leaf_index))
                        }
                        SszStateKey::Validator(pubkey) => proof_tree.generate_validator_proof(
                            pubkey,
                            self.canonical_state.proof_validator_keys(),
                        ),
                        SszStateKey::ValidatorField(pubkey, field_index) => proof_tree
                            .generate_validator_field_proof(
                                pubkey,
                                *field_index,
                                self.canonical_state.proof_validator_keys(),
                            ),
                        SszStateKey::Deposit(index) => proof_tree.generate_deposit_proof(*index),
                        SszStateKey::DepositField(index, field_index) => {
                            proof_tree.generate_deposit_field_proof(*index, *field_index)
                        }
                        SszStateKey::Withdrawal(pubkey) => {
                            proof_tree.generate_withdrawal_proof_by_key(pubkey)
                        }
                        SszStateKey::WithdrawalField(pubkey, field_index) => {
                            proof_tree.generate_withdrawal_field_proof_by_key(pubkey, *field_index)
                        }
                        SszStateKey::ProtocolParam(index) => {
                            proof_tree.generate_protocol_param_proof(*index)
                        }
                        SszStateKey::ProtocolParamField(index, field_index) => {
                            proof_tree.generate_protocol_param_field_proof(*index, *field_index)
                        }
                        SszStateKey::AddedValidator(index) => {
                            proof_tree.generate_added_validator_proof(*index)
                        }
                        SszStateKey::AddedValidatorField(index, field_index) => {
                            proof_tree.generate_added_validator_field_proof(*index, *field_index)
                        }
                        SszStateKey::RemovedValidator(index) => {
                            proof_tree.generate_removed_validator_proof(*index)
                        }
                    })
                    .collect();
                let root = self.canonical_state.get_state_root();
                let el_block_number = self.canonical_state.get_proof_el_block_number();
                let _ = sender.send(ConsensusStateResponse::StateProof {
                    root,
                    el_block_number,
                    proofs,
                });
            }
        }
    }

    fn update_validator_committee(&mut self, stake_changed: bool) -> bool {
        // Add and remove validators for the next epoch
        let mut validator_exit = false;
        let next_epoch = self.canonical_state.get_epoch() + 1;
        if self.canonical_state.has_added_validators(next_epoch)
            || !self.canonical_state.get_removed_validators().is_empty()
        {
            // Activate validators for the coming epoch.
            // Clone to release the immutable borrow on canonical_state so we can call set_account.
            if let Some(added_validators) = self
                .canonical_state
                .get_added_validators(next_epoch)
                .cloned()
            {
                for validator in &added_validators {
                    let key_bytes: [u8; 32] = validator.node_key.as_ref().try_into().unwrap();
                    let mut account = self
                        .canonical_state
                        .get_account(&key_bytes)
                        .expect(
                            "only validators with accounts are added to the added_validators queue",
                        )
                        .clone();
                    account.status = ValidatorStatus::Active;
                    self.canonical_state.set_account(key_bytes, account);
                    info!(
                        next_epoch,
                        validator = hex::encode(key_bytes),
                        "activated validator for next epoch"
                    );
                }
            }

            let removed_validators = self.canonical_state.get_removed_validators().clone();
            for key in &removed_validators {
                // Check if this node exits the validator set
                if key == &self.node_public_key {
                    validator_exit = true;
                    warn!(next_epoch, "this node is being removed from validator set");
                }

                let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
                if let Some(mut account) = self.canonical_state.get_account(&key_bytes).cloned() {
                    account.status = ValidatorStatus::Inactive;
                    self.canonical_state.set_account(key_bytes, account);
                    info!(
                        next_epoch,
                        validator = hex::encode(key_bytes),
                        "deactivated validator"
                    );
                }
            }
        }

        // Check stake bounds independently of validator additions/removals
        if stake_changed {
            // In case the min or max stake parameters changed, we check that the balance of
            // all validators is in the allowed range [min_stake, max_stake]
            // Withdrawals happen at the end of the current epoch (last block)
            let withdrawal_epoch = self.canonical_state.get_epoch() + 1;

            let validators_to_process: Vec<([u8; 32], u64, Address)> = self
                .canonical_state
                .validator_accounts_iter()
                .filter_map(|(key, acc)| {
                    if acc.balance < self.canonical_state.get_minimum_stake()
                        || acc.balance > self.canonical_state.get_maximum_stake()
                    {
                        Some((*key, acc.balance, acc.withdrawal_credentials))
                    } else {
                        None
                    }
                })
                .collect();

            for (key, balance, withdrawal_credentials) in validators_to_process {
                if balance < self.canonical_state.get_minimum_stake() {
                    // Remove the validator from the committee and withdraw the full balance
                    // Update account first: move balance to pending_withdrawal_amount
                    if let Some(mut account) = self.canonical_state.get_account(&key).cloned() {
                        account.status = ValidatorStatus::Inactive;
                        account.balance = 0;
                        account.has_pending_withdrawal = true;
                        self.canonical_state.set_account(key, account);
                    }

                    info!(
                        validator = hex::encode(key),
                        balance,
                        min_stake = self.canonical_state.get_minimum_stake(),
                        "validator below minimum stake, scheduling full withdrawal"
                    );

                    let withdrawal_request = WithdrawalRequest {
                        source_address: withdrawal_credentials,
                        validator_pubkey: key,
                        amount: balance,
                    };
                    self.canonical_state.push_withdrawal_request(
                        withdrawal_request,
                        withdrawal_epoch,
                        balance,
                    );
                } else if balance > self.canonical_state.get_maximum_stake() {
                    // Withdraw the portion of the balance exceeding `validator_maximum_stake`
                    let excess_amount = balance - self.canonical_state.get_maximum_stake();

                    // Move excess from balance
                    if let Some(mut account) = self.canonical_state.get_account(&key).cloned() {
                        account.balance -= excess_amount;
                        account.has_pending_withdrawal = true;
                        self.canonical_state.set_account(key, account);
                    }

                    info!(
                        validator = hex::encode(key),
                        balance,
                        max_stake = self.canonical_state.get_maximum_stake(),
                        excess_amount,
                        "validator above maximum stake, scheduling partial withdrawal"
                    );

                    let withdrawal_request = WithdrawalRequest {
                        source_address: withdrawal_credentials,
                        validator_pubkey: key,
                        amount: excess_amount,
                    };
                    self.canonical_state.push_withdrawal_request(
                        withdrawal_request,
                        withdrawal_epoch,
                        excess_amount,
                    );
                }
            }
        }

        validator_exit
    }
}

/// Core execution logic that applies a block's state transitions to any ConsensusState.
///
/// This method:
/// - Calls check_payload on the engine client (validates and optimistically executes the block on the EVM)
/// - Applies consensus-layer state transitions (deposits, withdrawals, validators)
/// - Updates the forkchoice head
/// - Creates checkpoints at epoch boundaries
///
/// This does NOT handle epoch transitions (activate validators, increment epoch).
/// Epoch transitions only happen at finalization since the last block of an epoch
/// is always finalized (never notarized+nullified).
async fn execute_block<
    C: EngineClient,
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    engine_client: &mut C,
    context: &ContextCell<R>,
    block: &Block,
    state: &mut ConsensusState,
    consts: &ProtocolConsts,
    protocol_version_digest: Digest,
) {
    #[cfg(feature = "prom")]
    let block_processing_start = Instant::now();

    // check the payload
    #[cfg(feature = "prom")]
    let payload_check_start = Instant::now();
    let payload_status = loop {
        let status = engine_client.check_payload(block).await;

        if status.is_syncing() {
            error!(
                height = block.height(),
                "execution client returned SYNCING, sending forkchoice update to trigger sync and retrying..."
            );

            context.sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        break status;
    };

    let new_height = block.height();

    #[cfg(feature = "prom")]
    {
        let payload_check_duration = payload_check_start.elapsed().as_millis() as f64;
        histogram!("payload_check_duration_millis").record(payload_check_duration);
    }

    // Validate block against execution layer state
    // Note: withdrawals are validated in the application layer before voting
    if payload_status.is_valid() {
        let eth_hash = block.eth_block_hash();
        let tx_count = block.payload.payload_inner.payload_inner.transactions.len();
        info!(
            new_height,
            epoch = state.get_epoch(),
            tx_count,
            eth_hash = hex(&eth_hash),
            "committing block to execution layer"
        );

        state.set_forkchoice_head(eth_hash.into());

        // Parse execution requests
        #[cfg(feature = "prom")]
        let parse_requests_start = Instant::now();
        parse_execution_requests(
            context,
            block,
            new_height,
            state,
            protocol_version_digest,
            consts,
        )
        .await;

        #[cfg(feature = "prom")]
        {
            let parse_requests_duration = parse_requests_start.elapsed().as_millis() as f64;
            histogram!("parse_execution_requests_duration_millis").record(parse_requests_duration);
        }

        // Add validators that deposited to the validator set
        #[cfg(feature = "prom")]
        let process_requests_start = Instant::now();
        process_execution_requests(context, block, new_height, state, consts).await;
        #[cfg(feature = "prom")]
        {
            let process_requests_duration = process_requests_start.elapsed().as_millis() as f64;
            histogram!("process_execution_requests_duration_millis")
                .record(process_requests_duration);
        }
    } else {
        let payload_valid = payload_status.is_valid();
        let parent_matches = state.get_forkchoice().head_block_hash == block.eth_parent_hash();
        warn!(
            new_height,
            payload_valid,
            parent_matches,
            "block validation failed, not executing but keeping in chain"
        );
    }

    state.set_latest_height(new_height);
    state.set_view(block.view());
    state.set_head_digest(block.digest());
    assert_eq!(block.epoch(), state.get_epoch());

    // Periodically persist state to database as a blob
    // We build the checkpoint one height before the epoch end which
    // allows the validators to sign the checkpoint hash in the last block
    // of the epoch
    if is_penultimate_block_of_epoch(state.get_epocher(), new_height) {
        #[cfg(feature = "prom")]
        let checkpoint_creation_start = Instant::now();
        let checkpoint = Checkpoint::new(state);
        debug!(
            new_height,
            epoch = state.get_epoch(),
            checkpoint_digest = ?checkpoint.digest,
            "created checkpoint at penultimate block of epoch"
        );
        state.set_pending_checkpoint(Some(checkpoint));

        #[cfg(feature = "prom")]
        {
            let checkpoint_creation_duration =
                checkpoint_creation_start.elapsed().as_millis() as f64;
            histogram!("checkpoint_creation_duration_millis").record(checkpoint_creation_duration);
        }
    }

    #[cfg(feature = "prom")]
    {
        let total_block_processing_duration = block_processing_start.elapsed().as_millis() as f64;
        histogram!("total_block_processing_duration_millis")
            .record(total_block_processing_duration);
        counter!("blocks_processed_total").increment(1);
    }

    // Normalize safe/finalized to head before capturing the root. Fork states
    // inherit canonical's safe/finalized at clone time, which varies depending
    // on when the block is processed. Since the SSZ tree includes forkchoice
    // hashes, the state root must not depend on processing order.
    state.set_forkchoice_safe_and_finalized(state.get_forkchoice().head_block_hash);

    // Freeze the trie root so that subsequent finalization mutations
    // (epoch transitions, forkchoice updates) don't alter the captured value.
    let el_block_number = block.payload.payload_inner.payload_inner.block_number;
    state.capture_state_root(el_block_number);
}

async fn parse_execution_requests<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block,
    new_height: u64,
    state: &mut ConsensusState,
    protocol_version_digest: Digest,
    consts: &ProtocolConsts,
) {
    // Combine any pending execution requests with the current block's requests
    let mut all_requests = state.take_pending_execution_requests();
    all_requests.extend(block.execution_requests.iter().cloned());

    for request_bytes in &all_requests {
        match ExecutionRequest::try_from_eth_entry(request_bytes.as_ref()) {
            Ok(execution_requests) => {
                for execution_request in execution_requests {
                    match execution_request {
                        ExecutionRequest::Deposit(deposit_request) => {
                            match verify_deposit_request(
                                context,
                                &deposit_request,
                                state,
                                protocol_version_digest,
                                new_height,
                                state.get_minimum_stake(),
                                state.get_maximum_stake(),
                            ) {
                                Ok(()) => {
                                    // Mark account as having a pending deposit
                                    let validator_pubkey: [u8; 32] =
                                        deposit_request.node_pubkey.as_ref().try_into().unwrap();
                                    if let Some(mut account) =
                                        state.get_account(&validator_pubkey).cloned()
                                    {
                                        account.has_pending_deposit = true;
                                        state.set_account(validator_pubkey, account);
                                    } else {
                                        // Create account early with Inactive status for new validators
                                        let withdrawal_credentials =
                                            match parse_withdrawal_credentials(
                                                deposit_request.withdrawal_credentials,
                                            ) {
                                                Ok(withdrawal_credentials) => {
                                                    withdrawal_credentials
                                                }
                                                Err(e) => {
                                                    // The deposited funds would be lost in this case.
                                                    // The deposit contract verifies that the withdrawal credentials
                                                    // follow the expected format, so this should never happen.
                                                    warn!(
                                                        "Failed to parse withdrawal credentials: {e}"
                                                    );
                                                    continue;
                                                }
                                            };
                                        let new_account = ValidatorAccount {
                                            consensus_public_key: deposit_request
                                                .consensus_pubkey
                                                .clone(),
                                            withdrawal_credentials,
                                            balance: 0, // Balance will be set when deposit is processed
                                            status: ValidatorStatus::Inactive,
                                            has_pending_deposit: true,
                                            has_pending_withdrawal: false,
                                            joining_epoch: 0, // Will be set when deposit is processed
                                            last_deposit_index: deposit_request.index,
                                        };
                                        state.set_account(validator_pubkey, new_account);
                                    }
                                    state.push_deposit(deposit_request.clone());
                                }
                                Err(reason) => {
                                    let withdrawal_credentials = match parse_withdrawal_credentials(
                                        deposit_request.withdrawal_credentials,
                                    ) {
                                        Ok(withdrawal_credentials) => withdrawal_credentials,
                                        Err(e) => {
                                            // The deposited funds would be lost in this case.
                                            // The deposit contract verifies that the withdrawal credentials
                                            // follow the expected format, so this should never happen.
                                            warn!("Failed to parse withdrawal credentials: {e}");
                                            continue;
                                        }
                                    };

                                    let refund_pubkey = match reason {
                                        DepositRejectionReason::Refund => refunded_deposit_key(
                                            withdrawal_credentials,
                                            deposit_request.index,
                                        ),
                                        DepositRejectionReason::InvalidSignature => {
                                            invalid_signature_refund_key(
                                                withdrawal_credentials,
                                                deposit_request.index,
                                            )
                                        }
                                    };
                                    let withdrawal_request = WithdrawalRequest {
                                        source_address: withdrawal_credentials,
                                        validator_pubkey: refund_pubkey,
                                        amount: deposit_request.amount,
                                    };
                                    let withdrawal_epoch =
                                        state.get_epoch() + consts.validator_withdrawal_num_epochs;

                                    state.push_withdrawal_request(
                                        withdrawal_request.clone(),
                                        withdrawal_epoch,
                                        0, // deposit was never credited to balance
                                    );
                                }
                            }
                        }
                        ExecutionRequest::Withdrawal(mut withdrawal_request) => {
                            // Only add the withdrawal request if the validator exists and has sufficient balance
                            if let Some(mut account) = state
                                .get_account(&withdrawal_request.validator_pubkey)
                                .cloned()
                            {
                                // If the validator already has a pending deposit request, we skip this withdrawal request
                                if account.has_pending_deposit {
                                    info!(
                                        "Skipping withdrawal request because the validator has a pending deposit request: {withdrawal_request:?}"
                                    );
                                    continue; // Skip this withdrawal request
                                }

                                // If the validator already has a pending withdrawal request, we skip this withdrawal request
                                if account.has_pending_withdrawal {
                                    info!(
                                        "Skipping withdrawal request because the validator already has a pending withdrawal request: {withdrawal_request:?}"
                                    );
                                    continue; // Skip this withdrawal request
                                }

                                // The balance minus any pending withdrawals have to be larger than the amount of the withdrawal request
                                if account.balance < withdrawal_request.amount {
                                    info!(
                                        "Skipping withdrawal request due to insufficient balance: {withdrawal_request:?}"
                                    );
                                    continue; // Skip this withdrawal request
                                }

                                // The source address must match the validators withdrawal address
                                if withdrawal_request.source_address
                                    != account.withdrawal_credentials
                                {
                                    info!(
                                        "Skipping withdrawal request because the source address doesn't match the withdrawal credentials: {withdrawal_request:?}"
                                    );
                                    continue; // Skip this withdrawal request
                                }

                                // Skip the request if the public key is malformatted
                                let Ok(public_key) =
                                    PublicKey::decode(&withdrawal_request.validator_pubkey[..])
                                else {
                                    info!(
                                        "Skipping withdrawal request because the public key is malformatted: {withdrawal_request:?}"
                                    );
                                    continue; // Skip this withdrawal request
                                };

                                // We don't support partial withdrawals, so the withdrawal amount will be
                                // set to the entire balance
                                let remaining_balance = account.balance;
                                withdrawal_request.amount = remaining_balance;

                                // If the validator is in the warm-up phase after depositing the stake
                                // and before joining the committee, then the onboarding is aborted
                                if account.joining_epoch > state.get_epoch() {
                                    // Cancel validator's pending activation
                                    if state
                                        .remove_added_validator(account.joining_epoch, &public_key)
                                    {
                                        info!(
                                            validator = ?public_key,
                                            activation_epoch = account.joining_epoch,
                                            current_epoch = state.get_epoch(),
                                            "cancelled pending validator activation due to withdrawal request"
                                        );
                                    }
                                } else if is_last_block_of_epoch(state.get_epocher(), new_height) {
                                    // On the last block of an epoch, buffer the withdrawal request
                                    // to be processed at the penultimate block of the next epoch.
                                    // This ensures the validator is included in removed_validators
                                    // which can be properly reflected in the header.
                                    info!(
                                        validator =
                                            hex::encode(withdrawal_request.validator_pubkey),
                                        current_epoch = state.get_epoch(),
                                        "buffering withdrawal request for active validator on last block of epoch"
                                    );
                                    let mut deferred_request = vec![0x01];
                                    withdrawal_request.write(&mut deferred_request);
                                    state.push_pending_execution_request(deferred_request.into());
                                    continue;
                                } else {
                                    // Validator is already active - add to removed_validators
                                    state.push_removed_validator(public_key);
                                    account.status = ValidatorStatus::SubmittedExitRequest;
                                }

                                // Move balance out
                                account.balance = 0;
                                account.has_pending_withdrawal = true;
                                state.set_account(withdrawal_request.validator_pubkey, account);

                                // The withdrawal will be completed in `validator_withdrawal_num_epochs` epochs
                                let withdrawal_epoch =
                                    state.get_epoch() + consts.validator_withdrawal_num_epochs;
                                info!(
                                    validator = hex::encode(withdrawal_request.validator_pubkey),
                                    amount = remaining_balance,
                                    withdrawal_epoch,
                                    current_epoch = state.get_epoch(),
                                    "scheduled full withdrawal for validator"
                                );
                                state.push_withdrawal_request(
                                    withdrawal_request.clone(),
                                    withdrawal_epoch,
                                    remaining_balance,
                                );
                            }
                        }
                        ExecutionRequest::ProtocolParam(protocol_param_request) => {
                            info!("Received protocol param request: {protocol_param_request:?}");

                            match ProtocolParam::try_from(protocol_param_request) {
                                Ok(protocol_param) => {
                                    info!("Adding protocol param change: {protocol_param:?}");
                                    state.push_protocol_param_change(protocol_param);
                                }
                                Err(e) => {
                                    warn!("Failed to parse protocol param request: {e}");
                                }
                            }
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

async fn process_execution_requests<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block,
    new_height: u64,
    state: &mut ConsensusState,
    consts: &ProtocolConsts,
) {
    if is_penultimate_block_of_epoch(state.get_epocher(), new_height) {
        for _ in 0..state.get_max_deposits_per_epoch() as usize {
            if let Some(request) = state.pop_deposit() {
                let node_pubkey_bytes: [u8; 32] = request.node_pubkey.as_ref().try_into().unwrap();

                // Account should always exist (created early in parse_execution_requests)
                let Some(mut account) = state.get_account(&node_pubkey_bytes).cloned() else {
                    warn!("Deposit request has no corresponding account, skipping: {request:?}");
                    continue;
                };

                // Clear the pending deposit flag since we're processing it now
                account.has_pending_deposit = false;

                if account.status == ValidatorStatus::Inactive {
                    // New validator: account was created early with Inactive status
                    let new_balance = request.amount;

                    // Revalidate in case stake bounds changed since deposit was parsed
                    if new_balance < state.get_minimum_stake()
                        || new_balance > state.get_maximum_stake()
                    {
                        info!(
                            "New validator deposit {} outside valid range [{}, {}], initiating refund: {request:?}",
                            new_balance,
                            state.get_minimum_stake(),
                            state.get_maximum_stake()
                        );
                        let withdrawal_request = WithdrawalRequest {
                            source_address: account.withdrawal_credentials,
                            validator_pubkey: node_pubkey_bytes,
                            amount: request.amount,
                        };
                        let withdrawal_epoch =
                            state.get_epoch() + consts.validator_withdrawal_num_epochs;
                        state.push_withdrawal_request(
                            withdrawal_request,
                            withdrawal_epoch,
                            0, // deposit was never credited
                        );
                        // Remove the inactive account since validator won't be joining
                        state.remove_account(&node_pubkey_bytes);
                        continue;
                    }

                    // Activate the new validator
                    let activation_epoch = state.get_epoch() + consts.validator_num_warm_up_epochs;
                    let consensus_key = account.consensus_public_key.clone();
                    account.balance = new_balance;
                    account.status = ValidatorStatus::Joining;
                    account.joining_epoch = activation_epoch;
                    account.last_deposit_index = request.index;
                    state.set_account(node_pubkey_bytes, account);

                    state.add_validator(
                        activation_epoch,
                        AddedValidator {
                            node_key: request.node_pubkey.clone(),
                            consensus_key,
                        },
                    );

                    info!(
                        validator = hex::encode(node_pubkey_bytes),
                        balance = new_balance,
                        activation_epoch,
                        current_epoch = state.get_epoch(),
                        "processing new validator deposit"
                    );

                    #[cfg(debug_assertions)]
                    {
                        use commonware_codec::Encode;
                        let gauge: Gauge = Gauge::default();
                        gauge.set(request.amount as i64);
                        context.register(
                            format!(
                                "<creds>{}</creds><pubkey>{}</pubkey>_<index>{}</index>_deposit_validator_balance",
                                hex::encode(request.withdrawal_credentials),
                                hex::encode(request.node_pubkey.encode()),
                                request.index,
                            ),
                            "Validator balance",
                            gauge,
                        );
                    }
                } else {
                    // Top-up deposit for existing validator
                    let new_balance = account.balance + request.amount;

                    // Check if new balance would be within valid range
                    if new_balance >= state.get_minimum_stake()
                        && new_balance <= state.get_maximum_stake()
                    {
                        info!(
                            validator = hex::encode(node_pubkey_bytes),
                            previous_balance = account.balance,
                            deposit_amount = request.amount,
                            new_balance,
                            "processing top-up deposit for existing validator"
                        );
                        account.balance = new_balance;
                        state.set_account(node_pubkey_bytes, account);
                    } else {
                        // Invalid: new balance outside range, initiate immediate withdrawal
                        info!(
                            "Top-up deposit would result in balance {} outside valid range [{}, {}], initiating immediate withdrawal: {request:?}",
                            new_balance,
                            state.get_minimum_stake(),
                            state.get_maximum_stake()
                        );
                        let withdrawal_request = WithdrawalRequest {
                            source_address: account.withdrawal_credentials,
                            validator_pubkey: node_pubkey_bytes,
                            amount: request.amount,
                        };
                        let withdrawal_epoch =
                            state.get_epoch() + consts.validator_withdrawal_num_epochs;

                        state.push_withdrawal_request(
                            withdrawal_request,
                            withdrawal_epoch,
                            0, // top-up deposit was never credited to balance
                        );
                        // Persist the has_pending_deposit = false change
                        state.set_account(node_pubkey_bytes, account);
                    }
                }
            }
        }
    }

    // Remove pending withdrawals that are included in the committed block
    if !block.payload.payload_inner.withdrawals.is_empty() {
        debug!(
            new_height,
            num_withdrawals = block.payload.payload_inner.withdrawals.len(),
            "processing withdrawals from committed block"
        );
    }
    for withdrawal in &block.payload.payload_inner.withdrawals {
        let current_epoch = state.get_epoch();
        let pending_withdrawal = state.pop_withdrawal(current_epoch);
        // these checks should never fail. we have to make sure that these withdrawals are
        // verified when the block is verified. it is too late when the block is committed.
        let pending_withdrawal = pending_withdrawal.expect("pending withdrawal must be in state");
        assert_eq!(pending_withdrawal.inner, *withdrawal);

        // If balance_deduction is 0, this is an immediate refund of a rejected deposit.
        // No account modifications needed - the money was never part of the account.
        // Note: if a deposit request with an invalid amount (below minimum or above maximum stake) was submitted,
        // a withdrawal request will be initiated immediately, without creating a validator account.
        // These are the cases where we process a withdrawal request without having a validator account
        // stored in the consensus state.
        if pending_withdrawal.balance_deduction == 0 {
            continue;
        }

        // For balance_deduction > 0, the money was moved from balance when the withdrawal
        // was created. The balance_deduction is tracked on the PendingWithdrawal in the queue.
        if let Some(mut account) = state.get_account(&pending_withdrawal.pubkey).cloned() {
            account.has_pending_withdrawal = false;

            #[cfg(debug_assertions)]
            {
                let gauge: Gauge = Gauge::default();
                gauge.set(account.balance as i64);
                context.register(
                    format!(
                        "<creds>{}</creds><pubkey>{}</pubkey><height>{}</height>_withdrawal_validator_balance",
                        hex::encode(account.withdrawal_credentials),
                        hex::encode(pending_withdrawal.pubkey),
                        state.get_latest_height(),
                    ),
                    "Validator balance",
                    gauge,
                );
            }

            // If balance is 0, remove the validator account.
            if account.balance == 0 {
                info!(
                    validator = hex::encode(pending_withdrawal.pubkey),
                    "removing validator account after full withdrawal"
                );
                state.remove_account(&pending_withdrawal.pubkey);
            } else {
                state.set_account(pending_withdrawal.pubkey, account);
            }
        }
    }
}

fn verify_deposit_request<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng>(
    #[allow(unused)] context: &ContextCell<R>,
    deposit_request: &DepositRequest,
    state: &ConsensusState,
    protocol_version_digest: Digest,
    #[allow(unused)] new_height: u64,
    validator_minimum_stake: u64,
    validator_maximum_stake: u64,
) -> Result<(), DepositRejectionReason> {
    // Check if validator already exists
    let validator_pubkey: [u8; 32] = deposit_request.node_pubkey.as_ref().try_into().unwrap();
    let account = state.get_account(&validator_pubkey);
    let existing_balance = account.map(|acc| acc.balance).unwrap_or(0);

    // Check for pending deposit or withdrawal (only if account exists)
    if let Some(acc) = account {
        if acc.has_pending_deposit {
            info!(
                "Skipping deposit request because the validator already has a pending deposit request: {deposit_request:?}"
            );
            return Err(DepositRejectionReason::Refund);
        }
        if acc.has_pending_withdrawal {
            info!(
                "Skipping deposit request because the validator already has a pending withdrawal request: {deposit_request:?}"
            );
            return Err(DepositRejectionReason::Refund);
        }
    }

    let new_balance = existing_balance + deposit_request.amount;

    // Validate that new balance is within valid range
    if new_balance < validator_minimum_stake || new_balance > validator_maximum_stake {
        info!(
            "Deposit would result in balance {} outside valid range [{}, {}] (existing: {}, deposit: {}), initiating immediate withdrawal: {deposit_request:?}",
            new_balance,
            validator_minimum_stake,
            validator_maximum_stake,
            existing_balance,
            deposit_request.amount
        );
        return Err(DepositRejectionReason::Refund);
    }

    let message = deposit_request.as_message(protocol_version_digest);

    let mut node_signature_bytes = &deposit_request.node_signature[..];
    let Ok(node_signature) = Signature::read(&mut node_signature_bytes) else {
        info!("Failed to parse node signature from deposit request: {deposit_request:?}");
        return Err(DepositRejectionReason::InvalidSignature);
    };
    if !deposit_request
        .node_pubkey
        .verify(&[], &message, &node_signature)
    {
        #[cfg(debug_assertions)]
        {
            let gauge: Gauge = Gauge::default();
            gauge.set(new_height as i64);
            context.register(
                format!(
                    "<pubkey>{}</pubkey>_deposit_request_invalid_node_sig",
                    hex::encode(&deposit_request.node_pubkey)
                ),
                "height",
                gauge,
            );
        }
        info!("Failed to verify node signature from deposit request: {deposit_request:?}");
        return Err(DepositRejectionReason::InvalidSignature);
    }

    let mut consensus_signature_bytes = &deposit_request.consensus_signature[..];
    let Ok(consensus_signature) = bls12381::Signature::read(&mut consensus_signature_bytes) else {
        info!("Failed to parse consensus signature from deposit request: {deposit_request:?}");
        return Err(DepositRejectionReason::InvalidSignature);
    };
    if !deposit_request
        .consensus_pubkey
        .verify(&[], &message, &consensus_signature)
    {
        #[cfg(debug_assertions)]
        {
            let gauge: Gauge = Gauge::default();
            gauge.set(new_height as i64);
            context.register(
                format!(
                    "<pubkey>{}</pubkey>_deposit_request_invalid_consensus_sig",
                    hex::encode(&deposit_request.consensus_pubkey)
                ),
                "height",
                gauge,
            );
        }
        info!("Failed to verify consensus signature from deposit request: {deposit_request:?}");
        return Err(DepositRejectionReason::InvalidSignature);
    }
    Ok(())
}

impl<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    O: NetworkOracle<PublicKey>,
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
> Drop for Finalizer<R, C, O, S, V>
{
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}
