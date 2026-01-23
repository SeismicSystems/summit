use crate::db::{Config as StateConfig, FinalizerState};
use crate::{FinalizerConfig, FinalizerMailbox, FinalizerMessage};
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
#[allow(unused)]
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::Reporter;
use commonware_consensus::simplex::scheme::bls12381_multisig;
use commonware_consensus::simplex::types::Finalization;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{Digestible, Hasher, Sha256, Signer, Verifier as _, bls12381};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::translator::TwoCap;
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
use summit_types::utils::{
    is_first_block_of_epoch, is_last_block_of_epoch, is_penultimate_block_of_epoch,
    parse_withdrawal_credentials,
};
use summit_types::{Block, BlockAuxData, Digest, FinalizedHeader, PublicKey, Signature};
use summit_types::{EngineClient, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

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
    epoch_num_of_blocks: u64,
    protocol_version_digest: Digest,
    validator_withdrawal_num_epochs: u64, // in epochs
    validator_onboarding_limit_per_block: usize,
    validator_num_warm_up_epochs: u64,
    oracle: O,
    orchestrator_mailbox: summit_orchestrator::Mailbox,
    node_public_key: PublicKey,
    validator_exit: bool,
    cancellation_token: CancellationToken,
    _signer_marker: PhantomData<S>,
    _variant_marker: PhantomData<V>,
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
        let (tx, rx) = mpsc::channel(cfg.mailbox_size); // todo(dalton) pull mailbox size from config
        let state_cfg = StateConfig {
            log_partition: format!("{}-finalizer_state-log", cfg.db_prefix),
            log_write_buffer: WRITE_BUFFER,
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(262_144),
            translator: TwoCap,
            buffer_pool: cfg.buffer_pool,
        };

        let db =
            FinalizerState::<R, V>::new(context.with_label("finalizer_state"), state_cfg).await;

        // Check if the state exists in the database. Otherwise, use the initial state.
        // The initial state could be from the genesis or a checkpoint.
        // If we want to load a checkpoint, we have to make sure that the DB is cleared.
        let state = if let Some(state) = db.get_latest_consensus_state().await {
            info!(
                "Loading consensus state from database at epoch {} and height {}",
                state.epoch, state.latest_height
            );
            state
        } else {
            info!(
                "Consensus state not found in database, using provided state with epoch {} and height {} - epoch_num_of_blocks: {}",
                cfg.initial_state.epoch, cfg.initial_state.latest_height, cfg.epoch_num_of_blocks
            );
            cfg.initial_state
        };

        (
            Self {
                context: ContextCell::new(context),
                mailbox: rx,
                engine_client: cfg.engine_client,
                oracle: cfg.oracle,
                orchestrator_mailbox: cfg.orchestrator_mailbox,
                pending_height_notifys: BTreeMap::new(),
                epoch_num_of_blocks: cfg.epoch_num_of_blocks,
                db,
                canonical_state: state.clone(),
                fork_states: BTreeMap::new(),
                orphaned_blocks: BTreeMap::new(),
                genesis_hash: cfg.genesis_hash,
                protocol_version_digest: Sha256::hash(&cfg.protocol_version.to_le_bytes()),
                validator_withdrawal_num_epochs: cfg.validator_withdrawal_num_epochs,
                validator_onboarding_limit_per_block: cfg.validator_onboarding_limit_per_block,
                validator_num_warm_up_epochs: cfg.validator_num_warm_up_epochs,
                node_public_key: cfg.node_public_key,
                validator_exit: false,
                cancellation_token: cfg.cancellation_token,
                _signer_marker: PhantomData,
                _variant_marker: PhantomData,
            },
            state,
            FinalizerMailbox::new(tx),
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    pub async fn run(mut self) {
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
            .register(self.canonical_state.epoch, network_keys)
            .await;

        self.orchestrator_mailbox
            .report(Message::Enter(EpochTransition {
                epoch: Epoch::new(self.canonical_state.epoch),
                validator_keys: active_validators,
            }))
            .await;

        loop {
            if self.validator_exit
                && is_first_block_of_epoch(
                    self.epoch_num_of_blocks,
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
                                    self.handle_finalized_block(ack_tx, block, finalization, &mut last_committed_timestamp).await;
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
                            // TODO(matthias): verify that this can never happen
                            assert_eq!(epoch, self.canonical_state.epoch);
                            let _ = response.send(self.canonical_state.epoch_genesis_hash);
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
                self.epoch_num_of_blocks,
                self.protocol_version_digest,
                self.validator_onboarding_limit_per_block,
                self.validator_num_warm_up_epochs,
                self.validator_withdrawal_num_epochs,
            )
            .await;
        }

        self.canonical_state.forkchoice.safe_block_hash =
            self.canonical_state.forkchoice.head_block_hash;
        self.canonical_state.forkchoice.finalized_block_hash =
            self.canonical_state.forkchoice.head_block_hash;

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
            .commit_hash(self.canonical_state.forkchoice)
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
        info!(new_height, self.canonical_state.epoch, "executed block");

        let new_height = block.height();
        let mut epoch_change = false; // Store finalizes checkpoint to database
        if is_last_block_of_epoch(self.epoch_num_of_blocks, new_height) {
            if let Some(finalization) = finalization {
                // The finalized signatures should always be included on the last block
                // of the epoch. However, there is an edge case, where the block after
                // last block of the epoch arrived out of order.
                // This is not critical and will likely never happen on all validators
                // at the same time.
                // TODO(matthias): figure out a good solution for making checkpoints available
                debug_assert!(block.header.digest == finalization.proposal.payload);

                // Get participant count from the certificate signers
                let participant_count = finalization.certificate.signers.len();

                // Store the finalized block header in the database
                let finalized_header =
                    FinalizedHeader::new(block.header.clone(), finalization, participant_count);

                self.db
                    .store_finalized_header(new_height, &finalized_header)
                    .await;

                #[cfg(debug_assertions)]
                {
                    let gauge: Gauge = Gauge::default();
                    gauge.set(new_height as i64);
                    self.context.register(
                        format!("<header>{}</header><prev_header>{}</prev_header>_finalized_header_stored",
                                hex::encode(finalized_header.header.digest), hex::encode(finalized_header.header.prev_epoch_header_hash)),
                        "chain height",
                        gauge
                    );
                }
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
            // TODO(matthias): verify this
            if let Some(checkpoint) = &self.canonical_state.pending_checkpoint {
                self.db
                    .store_finalized_checkpoint(
                        self.canonical_state.epoch,
                        checkpoint,
                        block.clone(),
                    )
                    .await;
            }

            // Increment epoch
            self.canonical_state.epoch += 1;
            // Set the epoch genesis hash for the next epoch
            self.canonical_state.epoch_genesis_hash = block.digest().0;

            self.db
                .store_consensus_state(new_height, &self.canonical_state)
                .await;
            // This will commit all changes to the state db
            self.db.commit().await;
            #[cfg(feature = "prom")]
            {
                let db_operations_duration = db_operations_start.elapsed().as_millis() as f64;
                histogram!("database_operations_duration_millis").record(db_operations_duration);
            }

            // Clear the added and removed validators
            self.canonical_state
                .added_validators
                .remove(&self.canonical_state.epoch);
            if !self.canonical_state.removed_validators.is_empty() {
                self.canonical_state.removed_validators.clear();
            }

            // Create the list of validators for the p2p network for the next epoch.
            // We also include the validators that already staked and are waiting to join the committee.
            let active_validators = self.canonical_state.get_active_or_joining_validators();
            let network_keys = active_validators
                .iter()
                .map(|(node_key, _)| node_key.clone())
                .collect();
            self.oracle
                .register(self.canonical_state.epoch, network_keys)
                .await;

            // Send the new validator list to the orchestrator amd start the Simplex engine
            // for the new epoch
            let active_validators = self.canonical_state.get_active_validators();

            self.orchestrator_mailbox
                .report(Message::Enter(EpochTransition {
                    epoch: Epoch::new(self.canonical_state.epoch),
                    validator_keys: active_validators,
                }))
                .await;
            epoch_change = true;

            #[cfg(debug_assertions)]
            {
                let gauge: Gauge = Gauge::default();
                gauge.set(new_height as i64);
                self.context
                    .register("consensus_state_stored", "chain height", gauge);
            }
        }

        if epoch_change {
            // Shut down the Simplex engine for the old epoch
            self.orchestrator_mailbox
                .report(Message::Exit(Epoch::new(self.canonical_state.epoch - 1)))
                .await;
        }
        info!(new_height, self.canonical_state.epoch, "finalized block");
    }

    async fn handle_notarized_block(&mut self, block: Block) {
        let mut to_process = vec![block];

        while let Some(block) = to_process.pop() {
            let height = block.height();
            let parent_digest = block.parent();
            let block_digest = block.digest();

            // Ignore blocks at or below canonical height
            if height <= self.canonical_state.latest_height {
                debug!(
                    height,
                    "ignoring notarized block at or below canonical height"
                );
                continue;
            }

            // Find and clone parent state: either canonical (if parent was finalized) or a fork state
            let parent_state = if height == self.canonical_state.latest_height + 1 {
                // Parent should be the canonical block (was finalized)
                // Verify parent digest matches canonical head (skip check at genesis)
                if self.canonical_state.latest_height > 0
                    && parent_digest != self.canonical_state.head_digest
                {
                    // Block is on a dead fork, discard it
                    debug!(
                        height,
                        ?parent_digest,
                        canonical_head = ?self.canonical_state.head_digest,
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
                self.epoch_num_of_blocks,
                self.protocol_version_digest,
                self.validator_onboarding_limit_per_block,
                self.validator_num_warm_up_epochs,
                self.validator_withdrawal_num_epochs,
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
                head_block_hash: fork_state.forkchoice.head_block_hash,
                safe_block_hash: self.canonical_state.forkchoice.finalized_block_hash,
                finalized_block_hash: self.canonical_state.forkchoice.finalized_block_hash,
            };
            self.engine_client.commit_hash(fork_forkchoice).await;

            info!(height, ?block_digest, "executed notarized block into fork");
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

        // Create checkpoint if we're at an epoch boundary.
        // The consensus state is saved every `epoch_num_blocks` blocks.
        // The proposed block will contain the checkpoint that was saved at the previous height.
        let is_last = is_last_block_of_epoch(self.epoch_num_of_blocks, height);
        let aux_data = if is_last {
            // TODO(matthias): revisit this expect when the ckpt isn't in the DB
            let checkpoint_hash = if let Some(checkpoint) = &state.pending_checkpoint {
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
            let current_epoch = state.epoch;
            let ready_withdrawals = state
                .get_withdrawals_for_epoch(current_epoch)
                .map(|queue| queue.iter().cloned().collect())
                .unwrap_or_default();
            let next_epoch = state.epoch;
            BlockAuxData {
                epoch: state.epoch,
                withdrawals: ready_withdrawals,
                checkpoint_hash: Some(checkpoint_hash),
                header_hash: prev_header_hash,
                // The block proposer needs the validators that will be added in the next epoch
                added_validators: state
                    .added_validators
                    .get(&next_epoch)
                    .cloned()
                    .unwrap_or_default(),
                removed_validators: state.removed_validators.clone(),
                forkchoice: state.forkchoice,
            }
        } else {
            BlockAuxData {
                epoch: state.epoch,
                withdrawals: vec![],
                checkpoint_hash: None,
                header_hash: [0; 32].into(),
                added_validators: vec![],
                removed_validators: vec![],
                forkchoice: state.forkchoice,
            }
        };
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

                let balance = self
                    .canonical_state
                    .validator_accounts
                    .get(&key_bytes)
                    .map(|account| account.balance + account.pending_withdrawal_amount);
                let _ = sender.send(ConsensusStateResponse::ValidatorBalance(balance));
            }
            ConsensusStateRequest::GetValidatorAccount(public_key) => {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&public_key);

                let account = self
                    .canonical_state
                    .validator_accounts
                    .get(&key_bytes)
                    .cloned();
                let _ = sender.send(ConsensusStateResponse::ValidatorAccount(account));
            }
            ConsensusStateRequest::GetFinalizedHeader(height) => {
                let header = self.db.get_finalized_header(height).await;
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
        }
    }

    fn update_validator_committee(&mut self, stake_changed: bool) -> bool {
        // Add and remove validators for the next epoch
        let mut validator_exit = false;
        let next_epoch = self.canonical_state.epoch + 1;
        if self
            .canonical_state
            .added_validators
            .contains_key(&next_epoch)
            || !self.canonical_state.removed_validators.is_empty()
        {
            // Activate validators for the coming epoch.
            if let Some(added_validators) = self.canonical_state.added_validators.get(&next_epoch) {
                for key in added_validators {
                    let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
                    let account = self
                        .canonical_state
                        .validator_accounts
                        .get_mut(&key_bytes)
                        .expect(
                            "only validators with accounts are added to the added_validators queue",
                        );
                    account.status = ValidatorStatus::Active;
                }
            }

            for key in self.canonical_state.removed_validators.iter() {
                // Check if this node exits the validator set
                if key == &self.node_public_key {
                    validator_exit = true;
                }

                // TODO(matthias): I think this is not necessary. Inactive accounts will be removed after withdrawing.
                let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
                if let Some(account) = self.canonical_state.validator_accounts.get_mut(&key_bytes) {
                    account.status = ValidatorStatus::Inactive;
                }
            }
        }

        // Check stake bounds independently of validator additions/removals
        if stake_changed {
            // In case the min or max stake parameters changed, we check that the balance of
            // all validators is in the allowed range [min_stake, max_stake]
            // Withdrawals happen at the end of the current epoch (last block)
            let withdrawal_epoch = self.canonical_state.epoch + 1;

            let validators_to_process: Vec<([u8; 32], u64, Address)> = self
                .canonical_state
                .validator_accounts
                .iter()
                .filter_map(|(key, acc)| {
                    if acc.balance < self.canonical_state.validator_minimum_stake
                        || acc.balance > self.canonical_state.validator_maximum_stake
                    {
                        Some((*key, acc.balance, acc.withdrawal_credentials))
                    } else {
                        None
                    }
                })
                .collect();

            for (key, balance, withdrawal_credentials) in validators_to_process {
                if balance < self.canonical_state.validator_minimum_stake {
                    // Remove the validator from the committee and withdraw the full balance
                    // Update account first: move balance to pending_withdrawal_amount
                    if let Some(account) = self.canonical_state.validator_accounts.get_mut(&key) {
                        account.status = ValidatorStatus::Inactive;
                        account.balance = 0;
                        account.pending_withdrawal_amount += balance;
                        account.has_pending_withdrawal = true;
                    }

                    let withdrawal_request = WithdrawalRequest {
                        source_address: withdrawal_credentials,
                        validator_pubkey: key,
                        amount: balance,
                    };
                    self.canonical_state.push_withdrawal_request(
                        withdrawal_request,
                        withdrawal_epoch,
                        true, // subtract_balance
                    );
                } else if balance > self.canonical_state.validator_maximum_stake {
                    // Withdraw the portion of the balance exceeding `validator_maximum_stake`
                    let excess_amount = balance - self.canonical_state.validator_maximum_stake;

                    // Move excess from balance to pending_withdrawal_amount
                    if let Some(account) = self.canonical_state.validator_accounts.get_mut(&key) {
                        account.balance -= excess_amount;
                        account.pending_withdrawal_amount += excess_amount;
                        account.has_pending_withdrawal = true;
                    }

                    let withdrawal_request = WithdrawalRequest {
                        source_address: withdrawal_credentials,
                        validator_pubkey: key,
                        amount: excess_amount,
                    };
                    self.canonical_state.push_withdrawal_request(
                        withdrawal_request,
                        withdrawal_epoch,
                        true, // subtract_balance
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
#[allow(clippy::too_many_arguments)]
async fn execute_block<
    C: EngineClient,
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    engine_client: &mut C,
    context: &ContextCell<R>,
    block: &Block,
    state: &mut ConsensusState,
    epoch_num_of_blocks: u64,
    protocol_version_digest: Digest,
    validator_onboarding_limit_per_block: usize,
    validator_num_warm_up_epochs: u64,
    validator_withdrawal_num_epochs: u64,
) {
    #[cfg(feature = "prom")]
    let block_processing_start = Instant::now();

    // check the payload
    #[cfg(feature = "prom")]
    let payload_check_start = Instant::now();
    let payload_status = engine_client.check_payload(block).await;
    let new_height = block.height();

    #[cfg(feature = "prom")]
    {
        let payload_check_duration = payload_check_start.elapsed().as_millis() as f64;
        histogram!("payload_check_duration_millis").record(payload_check_duration);
    }

    // Verify withdrawal requests that were included in the block
    // Make sure that the included withdrawals match the expected withdrawals
    let expected_withdrawals: Vec<Withdrawal> =
        if is_last_block_of_epoch(epoch_num_of_blocks, new_height) {
            let current_epoch = state.epoch;
            state
                .get_withdrawals_for_epoch(current_epoch)
                .map(|queue| queue.iter().map(|w| w.inner).collect())
                .unwrap_or_default()
        } else {
            vec![]
        };

    // Validate block against state
    if payload_status.is_valid()
        && block.payload.payload_inner.withdrawals == expected_withdrawals
        && state.forkchoice.head_block_hash == block.eth_parent_hash()
    {
        let eth_hash = block.eth_block_hash();
        info!(
            "Commiting block 0x{} for height {}",
            hex(&eth_hash),
            new_height
        );

        state.forkchoice.head_block_hash = eth_hash.into();

        // Parse execution requests
        #[cfg(feature = "prom")]
        let parse_requests_start = Instant::now();
        parse_execution_requests(
            context,
            block,
            new_height,
            state,
            protocol_version_digest,
            validator_withdrawal_num_epochs,
            state.validator_minimum_stake,
            state.validator_maximum_stake,
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
        process_execution_requests(
            context,
            block,
            new_height,
            state,
            epoch_num_of_blocks,
            validator_onboarding_limit_per_block,
            validator_num_warm_up_epochs,
            validator_withdrawal_num_epochs,
            state.validator_minimum_stake,
            state.validator_maximum_stake,
        )
        .await;
        #[cfg(feature = "prom")]
        {
            let process_requests_duration = process_requests_start.elapsed().as_millis() as f64;
            histogram!("process_execution_requests_duration_millis")
                .record(process_requests_duration);
        }
    } else {
        warn!(
            "Height: {new_height} contains invalid eth payload. Not executing but keeping part of chain"
        );
    }

    #[cfg(debug_assertions)]
    {
        let gauge: Gauge = Gauge::default();
        gauge.set(new_height as i64);
        context.register("height", "chain height", gauge);
    }
    state.set_latest_height(new_height);
    state.set_view(block.view());
    state.head_digest = block.digest();
    assert_eq!(block.epoch(), state.epoch);

    // Periodically persist state to database as a blob
    // We build the checkpoint one height before the epoch end which
    // allows the validators to sign the checkpoint hash in the last block
    // of the epoch
    if is_penultimate_block_of_epoch(epoch_num_of_blocks, new_height) {
        #[cfg(feature = "prom")]
        let checkpoint_creation_start = Instant::now();
        let checkpoint = Checkpoint::new(state);
        state.pending_checkpoint = Some(checkpoint);

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
}

#[allow(clippy::too_many_arguments)]
async fn parse_execution_requests<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block,
    new_height: u64,
    state: &mut ConsensusState,
    protocol_version_digest: Digest,
    validator_withdrawal_num_epochs: u64,
    validator_minimum_stake: u64,
    validator_maximum_stake: u64,
) {
    for request_bytes in &block.execution_requests {
        match ExecutionRequest::try_from_eth_bytes(request_bytes.as_ref()) {
            Ok(execution_request) => {
                match execution_request {
                    ExecutionRequest::Deposit(deposit_request) => {
                        if verify_deposit_request(
                            context,
                            &deposit_request,
                            state,
                            protocol_version_digest,
                            new_height,
                            validator_minimum_stake,
                            validator_maximum_stake,
                        ) {
                            // Mark account as having a pending deposit
                            let validator_pubkey: [u8; 32] =
                                deposit_request.node_pubkey.as_ref().try_into().unwrap();
                            if let Some(account) =
                                state.validator_accounts.get_mut(&validator_pubkey)
                            {
                                account.has_pending_deposit = true;
                            } else {
                                // Create account early with Inactive status for new validators
                                let withdrawal_credentials = match parse_withdrawal_credentials(
                                    deposit_request.withdrawal_credentials,
                                ) {
                                    Ok(withdrawal_credentials) => withdrawal_credentials,
                                    Err(e) => {
                                        warn!("Failed to parse withdrawal credentials: {e}");
                                        continue;
                                    }
                                };
                                let new_account = ValidatorAccount {
                                    consensus_public_key: deposit_request.consensus_pubkey.clone(),
                                    withdrawal_credentials,
                                    balance: 0, // Balance will be set when deposit is processed
                                    pending_withdrawal_amount: 0,
                                    status: ValidatorStatus::Inactive,
                                    has_pending_deposit: true,
                                    has_pending_withdrawal: false,
                                    joining_epoch: 0, // Will be set when deposit is processed
                                    last_deposit_index: deposit_request.index,
                                };
                                state.set_account(validator_pubkey, new_account);
                            }
                            state.push_deposit(deposit_request.clone());
                        } else {
                            // If the signatures fail, we create an immediate withdrawal request for the deposited amount.
                            // Since the signatures are invalid, the validator cannot be added to the committee.
                            // However, the deposited funds are still burned in the deposit contract, so we have to withdraw them.
                            let withdrawal_credentials = match parse_withdrawal_credentials(
                                deposit_request.withdrawal_credentials,
                            ) {
                                Ok(withdrawal_credentials) => withdrawal_credentials,
                                Err(e) => {
                                    warn!("Failed to parse withdrawal credentials: {e}");
                                    continue;
                                }
                            };

                            let validator_pubkey: [u8; 32] =
                                deposit_request.node_pubkey.as_ref().try_into().unwrap();
                            let withdrawal_request = WithdrawalRequest {
                                source_address: withdrawal_credentials,
                                validator_pubkey,
                                amount: deposit_request.amount,
                            };
                            let withdrawal_epoch = state.epoch + validator_withdrawal_num_epochs;

                            state.push_withdrawal_request(
                                withdrawal_request.clone(),
                                withdrawal_epoch,
                                false, // subtract_balance: deposit was never credited to balance
                            );
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
                            if withdrawal_request.source_address != account.withdrawal_credentials {
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
                            if account.joining_epoch > state.epoch {
                                // Cancel validator's pending activation
                                if let Some(validators) =
                                    state.added_validators.get_mut(&account.joining_epoch)
                                    && let Some(pos) =
                                        validators.iter().position(|v| v == &public_key)
                                {
                                    validators.remove(pos);
                                    info!(
                                        validator = ?public_key,
                                        activation_epoch = account.joining_epoch,
                                        current_epoch = state.epoch,
                                        "cancelled pending validator activation due to withdrawal request"
                                    );
                                }
                            } else {
                                // Validator is already active - add to removed_validators
                                state.removed_validators.push(public_key);
                                account.status = ValidatorStatus::SubmittedExitRequest;
                            }

                            // Move balance to pending_withdrawal_amount
                            account.balance = 0;
                            account.pending_withdrawal_amount += remaining_balance;
                            account.has_pending_withdrawal = true;
                            state.set_account(withdrawal_request.validator_pubkey, account);

                            // The withdrawal will be completed in `validator_withdrawal_num_epochs` epochs
                            let withdrawal_epoch = state.epoch + validator_withdrawal_num_epochs;
                            state.push_withdrawal_request(
                                withdrawal_request.clone(),
                                withdrawal_epoch,
                                true, // subtract_balance
                            );
                        }
                    }
                    ExecutionRequest::ProtocolParam(protocol_param_request) => {
                        info!("Received protocol param request: {protocol_param_request:?}");

                        match ProtocolParam::try_from(protocol_param_request) {
                            Ok(protocol_param) => {
                                info!("Adding protocol param change: {protocol_param:?}");
                                state.protocol_param_changes.push(protocol_param);
                            }
                            Err(e) => {
                                warn!("Failed to parse protocol param request: {e}");
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

#[allow(clippy::too_many_arguments)]
async fn process_execution_requests<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block,
    new_height: u64,
    state: &mut ConsensusState,
    epoch_num_of_blocks: u64,
    validator_onboarding_limit_per_block: usize,
    validator_num_warm_up_epochs: u64,
    validator_withdrawal_num_epochs: u64,
    validator_minimum_stake: u64,
    validator_maximum_stake: u64,
) {
    if is_penultimate_block_of_epoch(epoch_num_of_blocks, new_height) {
        for _ in 0..validator_onboarding_limit_per_block {
            if let Some(request) = state.pop_deposit() {
                let node_pubkey_bytes: [u8; 32] = request.node_pubkey.as_ref().try_into().unwrap();

                // Account should always exist (created early in parse_execution_requests)
                let Some(account) = state.validator_accounts.get_mut(&node_pubkey_bytes) else {
                    warn!("Deposit request has no corresponding account, skipping: {request:?}");
                    continue;
                };

                // Clear the pending deposit flag since we're processing it now
                account.has_pending_deposit = false;

                if account.status == ValidatorStatus::Inactive {
                    // New validator: account was created early with Inactive status
                    let new_balance = request.amount;

                    // Revalidate in case stake bounds changed since deposit was parsed
                    if new_balance < validator_minimum_stake
                        || new_balance > validator_maximum_stake
                    {
                        info!(
                            "New validator deposit {} outside valid range [{}, {}], initiating refund: {request:?}",
                            new_balance, validator_minimum_stake, validator_maximum_stake
                        );
                        let withdrawal_request = WithdrawalRequest {
                            source_address: account.withdrawal_credentials,
                            validator_pubkey: node_pubkey_bytes,
                            amount: request.amount,
                        };
                        let withdrawal_epoch = state.epoch + validator_withdrawal_num_epochs;
                        state.push_withdrawal_request(
                            withdrawal_request,
                            withdrawal_epoch,
                            false, // subtract_balance: deposit was never credited
                        );
                        // Remove the inactive account since validator won't be joining
                        state.remove_account(&node_pubkey_bytes);
                        continue;
                    }

                    // Activate the new validator
                    let activation_epoch = state.epoch + validator_num_warm_up_epochs;
                    account.balance = new_balance;
                    account.status = ValidatorStatus::Joining;
                    account.joining_epoch = activation_epoch;
                    account.last_deposit_index = request.index;

                    state.add_validator(activation_epoch, request.node_pubkey.clone());

                    info!(
                        "Processing new validator deposit. Balance: {}, activation epoch: {}",
                        new_balance, activation_epoch
                    );

                    #[cfg(debug_assertions)]
                    {
                        use commonware_codec::Encode;
                        let gauge: Gauge = Gauge::default();
                        gauge.set(request.amount as i64);
                        context.register(
                            format!(
                                "<creds>{}</creds><pubkey>{}</pubkey>_deposit_validator_balance",
                                hex::encode(request.withdrawal_credentials),
                                hex::encode(request.node_pubkey.encode())
                            ),
                            "Validator balance",
                            gauge,
                        );
                    }
                } else {
                    // Top-up deposit for existing validator
                    let new_balance = account.balance + request.amount;

                    // Check if new balance would be within valid range
                    if new_balance >= validator_minimum_stake
                        && new_balance <= validator_maximum_stake
                    {
                        info!(
                            "Processing top-up deposit for existing validator. Current balance: {}, deposit: {}, new balance: {}",
                            account.balance, request.amount, new_balance
                        );
                        account.balance = new_balance;
                    } else {
                        // Invalid: new balance outside range, initiate immediate withdrawal
                        info!(
                            "Top-up deposit would result in balance {} outside valid range [{}, {}], initiating immediate withdrawal: {request:?}",
                            new_balance, validator_minimum_stake, validator_maximum_stake
                        );
                        let withdrawal_request = WithdrawalRequest {
                            source_address: account.withdrawal_credentials,
                            validator_pubkey: node_pubkey_bytes,
                            amount: request.amount,
                        };
                        let withdrawal_epoch = state.epoch + validator_withdrawal_num_epochs;

                        state.push_withdrawal_request(
                            withdrawal_request,
                            withdrawal_epoch,
                            false, // subtract_balance: top-up deposit was never credited to balance
                        );
                    }
                }
            }
        }
    }

    // Remove pending withdrawals that are included in the committed block
    for withdrawal in &block.payload.payload_inner.withdrawals {
        let current_epoch = state.epoch;
        let pending_withdrawal = state.pop_withdrawal(current_epoch);
        // TODO(matthias): these checks should never fail. we have to make sure that these withdrawals are
        // verified when the block is verified. it is too late when the block is committed.
        let pending_withdrawal = pending_withdrawal.expect("pending withdrawal must be in state");
        assert_eq!(pending_withdrawal.inner, *withdrawal);

        // If subtract_balance is false, this is an immediate refund of a rejected deposit.
        // No account modifications needed - the money was never part of the account.
        // Note: if a deposit request with an invalid amount (below minimum or above maximum stake) was submitted,
        // a withdrawal request will be initiated immediately, without creating a validator account.
        // These are the cases where we process a withdrawal request without having a validator account
        // stored in the consensus state.
        if !pending_withdrawal.subtract_balance {
            continue;
        }

        // For subtract_balance = true, the money was moved from balance to pending_withdrawal_amount
        // at creation time. Now we subtract from pending_withdrawal_amount.
        if let Some(mut account) = state.get_account(&pending_withdrawal.pubkey).cloned() {
            account.pending_withdrawal_amount = account
                .pending_withdrawal_amount
                .saturating_sub(withdrawal.amount);
            account.has_pending_withdrawal = false;

            #[cfg(debug_assertions)]
            {
                let gauge: Gauge = Gauge::default();
                gauge.set(account.balance as i64);
                context.register(
                    format!(
                        "<creds>{}</creds><pubkey>{}</pubkey>_withdrawal_validator_balance",
                        hex::encode(account.withdrawal_credentials),
                        hex::encode(pending_withdrawal.pubkey)
                    ),
                    "Validator balance",
                    gauge,
                );
            }

            // If both balance and pending_withdrawal_amount are 0, remove the validator account.
            if account.balance == 0 && account.pending_withdrawal_amount == 0 {
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
) -> bool {
    // Check if validator already exists
    let validator_pubkey: [u8; 32] = deposit_request.node_pubkey.as_ref().try_into().unwrap();
    let account = state.validator_accounts.get(&validator_pubkey);
    let existing_balance = account.map(|acc| acc.balance).unwrap_or(0);

    // Check for pending deposit or withdrawal (only if account exists)
    if let Some(acc) = account {
        if acc.has_pending_deposit {
            info!(
                "Skipping deposit request because the validator already has a pending deposit request: {deposit_request:?}"
            );
            return false;
        }
        if acc.has_pending_withdrawal {
            info!(
                "Skipping deposit request because the validator already has a pending withdrawal request: {deposit_request:?}"
            );
            return false;
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
        return false;
    }

    let message = deposit_request.as_message(protocol_version_digest);

    let mut node_signature_bytes = &deposit_request.node_signature[..];
    let Ok(node_signature) = Signature::read(&mut node_signature_bytes) else {
        info!("Failed to parse node signature from deposit request: {deposit_request:?}");
        return false;
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
        return false;
    }

    let mut consensus_signature_bytes = &deposit_request.consensus_signature[..];
    let Ok(consensus_signature) = bls12381::Signature::read(&mut consensus_signature_bytes) else {
        info!("Failed to parse consensus signature from deposit request: {deposit_request:?}");
        return false;
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
        return false;
    }
    true
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
