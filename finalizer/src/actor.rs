use crate::archive::backup_with_enclave;
use crate::db::{Config as StateConfig, FinalizerState};
use crate::{FinalizerConfig, FinalizerMailbox, FinalizerMessage};
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
#[allow(unused)]
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_codec::{Read as CodecRead, Write as CodecWrite};
use commonware_consensus::Reporter;
use commonware_consensus::simplex::signing_scheme::bls12381_multisig;
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
use summit_types::execution_request::ExecutionRequest;
use summit_types::network_oracle::NetworkOracle;
use summit_types::scheme::EpochTransition;
use summit_types::utils::{is_last_block_of_epoch, is_penultimate_block_of_epoch};
use summit_types::{Block, BlockAuxData, Digest, FinalizedHeader, PublicKey, Signature};
use summit_types::{EngineClient, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

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
    archive_mode: bool,
    mailbox: mpsc::Receiver<FinalizerMessage<bls12381_multisig::Scheme<PublicKey, V>, Block<S, V>>>,
    pending_height_notifys: BTreeMap<(u64, Digest), Vec<oneshot::Sender<()>>>,
    context: ContextCell<R>,
    engine_client: C,
    db: FinalizerState<R, V>,

    // Canonical state (finalized) - contains latest_height
    canonical_state: ConsensusState,

    // Fork states (notarized but not yet finalized)
    fork_states: BTreeMap<u64, BTreeMap<Digest, ForkState>>,

    // Orphaned notarized blocks that arrived before their parent
    orphaned_blocks: BTreeMap<u64, HashMap<Digest, Vec<Block<S, V>>>>,

    genesis_hash: [u8; 32],
    validator_max_withdrawals_per_block: usize,
    epoch_num_of_blocks: u64,
    protocol_version_digest: Digest,
    validator_minimum_stake: u64,     // in gwei
    validator_withdrawal_period: u64, // in blocks
    validator_onboarding_limit_per_block: usize,
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
        FinalizerMailbox<bls12381_multisig::Scheme<PublicKey, V>, Block<S, V>>,
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
                archive_mode: cfg.archive_mode,
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
                validator_max_withdrawals_per_block: cfg.validator_max_withdrawals_per_block,
                genesis_hash: cfg.genesis_hash,
                protocol_version_digest: Sha256::hash(&cfg.protocol_version.to_le_bytes()),
                validator_minimum_stake: cfg.validator_minimum_stake,
                validator_withdrawal_period: cfg.validator_withdrawal_period,
                validator_onboarding_limit_per_block: cfg.validator_onboarding_limit_per_block,
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
            if self.validator_exit {
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
                            // Check if this specific block has been executed (either canonical or fork)
                            let executed = if self.canonical_state.get_latest_height() >= height {
                                // Block could be canonical - we don't track canonical block digests per height,
                                // so we assume if canonical height >= height, the block is executed
                                true
                            } else {
                                // Check if it exists in fork states
                                self.fork_states.get(&height)
                                    .map(|forks| forks.contains_key(&block_digest))
                                    .unwrap_or(false)
                            };

                            if executed {
                                let _ = response.send(());
                                continue;
                            }
                            self.pending_height_notifys.entry((height, block_digest)).or_default().push(response);
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
        block: Block<S, V>,
        finalization: Option<
            Finalization<
                bls12381_multisig::Scheme<PublicKey, V>,
                <Block<S, V> as Digestible>::Digest,
            >,
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
                self.validator_max_withdrawals_per_block,
                self.protocol_version_digest,
                self.validator_minimum_stake,
                self.validator_withdrawal_period,
                self.validator_onboarding_limit_per_block,
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
                // Convert to concrete BLS scheme type by encoding and decoding
                let finalized_header =
                    FinalizedHeader::new(block.header.clone(), finalization, participant_count);
                let mut buf = Vec::new();
                finalized_header.write(&mut buf);
                let concrete_header = <FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, V>> as CodecRead>::read_cfg(&mut buf.as_slice(), &())
                    .expect("failed to convert finalized header to concrete type");
                self.db
                    .store_finalized_header(new_height, &concrete_header)
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

            // Add and remove validators for the next epoch
            if !self.canonical_state.added_validators.is_empty()
                || !self.canonical_state.removed_validators.is_empty()
            {
                // TODO(matthias): we can probably find a way to do this without iterating over the joining validators
                // Activate validators that staked this epoch.
                for key in self.canonical_state.added_validators.iter() {
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

                for key in self.canonical_state.removed_validators.iter() {
                    // TODO(matthias): I think this is not necessary. Inactive accounts will be removed after withdrawing.
                    let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
                    if let Some(account) =
                        self.canonical_state.validator_accounts.get_mut(&key_bytes)
                    {
                        account.status = ValidatorStatus::Inactive;
                    }
                }

                // If the node's public key is contained in the removed validator list,
                // trigger an exit
                if self
                    .canonical_state
                    .removed_validators
                    .iter()
                    .any(|pk| pk == &self.node_public_key)
                {
                    self.validator_exit = true;
                }
            }

            if self.archive_mode {
                // Should always be there
                if let Some(checkpoint) = &self.canonical_state.pending_checkpoint {
                    if let Err(e) =
                        backup_with_enclave(self.canonical_state.epoch, checkpoint.clone())
                    {
                        // This shouldnt be critical but it should be logged
                        error!("Unable to backup with enclave: {}", e);
                    }
                }
            }

            #[cfg(feature = "prom")]
            let db_operations_start = Instant::now();
            // This pending checkpoint should always exist, because it was created at the previous height.
            // The only case where the pending checkpoint doesn't exist here is if the node checkpointed.
            // The checkpoint is created at the penultimate block of the epoch, and finalized at the last
            // block. So if a node checkpoints, it will start at the height of the penultimate block.
            // TODO(matthias): verify this
            if let Some(checkpoint) = &self.canonical_state.pending_checkpoint {
                self.db
                    .store_finalized_checkpoint(self.canonical_state.epoch, checkpoint)
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

            // Create the list of validators for the new epoch
            let active_validators = self.canonical_state.get_active_validators();
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

            // Only clear the added and removed validators after saving the state to disk
            if !self.canonical_state.added_validators.is_empty() {
                self.canonical_state.added_validators.clear();
            }
            if !self.canonical_state.removed_validators.is_empty() {
                self.canonical_state.removed_validators.clear();
            }

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

    async fn handle_notarized_block(&mut self, block: Block<S, V>) {
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
                self.validator_max_withdrawals_per_block,
                self.protocol_version_digest,
                self.validator_minimum_stake,
                self.validator_withdrawal_period,
                self.validator_onboarding_limit_per_block,
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
                let _ = sender.send(()); // Ignore if receiver dropped
            }
        }
    }

    async fn handle_aux_data_mailbox(
        &mut self,
        height: u64,
        parent_digest: Digest,
        sender: oneshot::Sender<BlockAuxData>,
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
        } else {
            // If not in forks, it must be canonical (or parent height = 0)
            &self.canonical_state
        };

        // Create checkpoint if we're at an epoch boundary.
        // The consensus state is saved every `epoch_num_blocks` blocks.
        // The proposed block will contain the checkpoint that was saved at the previous height.
        let aux_data = if is_last_block_of_epoch(self.epoch_num_of_blocks, height) {
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
            let ready_withdrawals =
                state.get_next_ready_withdrawals(height, self.validator_max_withdrawals_per_block);
            BlockAuxData {
                epoch: state.epoch,
                withdrawals: ready_withdrawals,
                checkpoint_hash: Some(checkpoint_hash),
                header_hash: prev_header_hash,
                added_validators: state.added_validators.clone(),
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
        let _ = sender.send(aux_data);
    }

    async fn handle_consensus_state_query(
        &self,
        consensus_state_request: ConsensusStateRequest,
        sender: oneshot::Sender<ConsensusStateResponse>,
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
            ConsensusStateRequest::GetValidatorBalance(public_key) => {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&public_key);

                let balance = self
                    .canonical_state
                    .validator_accounts
                    .get(&key_bytes)
                    .map(|account| account.balance);
                let _ = sender.send(ConsensusStateResponse::ValidatorBalance(balance));
            }
        }
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
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    engine_client: &mut C,
    context: &ContextCell<R>,
    block: &Block<S, V>,
    state: &mut ConsensusState,
    epoch_num_of_blocks: u64,
    validator_max_withdrawals_per_block: usize,
    protocol_version_digest: Digest,
    validator_minimum_stake: u64,
    validator_withdrawal_period: u64,
    validator_onboarding_limit_per_block: usize,
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
            let pending_withdrawals =
                state.get_next_ready_withdrawals(new_height, validator_max_withdrawals_per_block);
            pending_withdrawals.into_iter().map(|w| w.inner).collect()
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
            validator_minimum_stake,
            validator_withdrawal_period,
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
            validator_minimum_stake,
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

async fn parse_execution_requests<
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block<S, V>,
    new_height: u64,
    state: &mut ConsensusState,
    protocol_version_digest: Digest,
    validator_minimum_stake: u64,
    validator_withdrawal_period: u64,
) {
    for request_bytes in &block.execution_requests {
        match ExecutionRequest::try_from_eth_bytes(request_bytes.as_ref()) {
            Ok(execution_request) => {
                match execution_request {
                    ExecutionRequest::Deposit(deposit_request) => {
                        let message = deposit_request.as_message(protocol_version_digest);

                        let mut node_signature_bytes = &deposit_request.node_signature[..];
                        let Ok(node_signature) = Signature::read(&mut node_signature_bytes) else {
                            info!(
                                "Failed to parse node signature from deposit request: {deposit_request:?}"
                            );
                            continue; // Skip this deposit request
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
                            info!(
                                "Failed to verify node signature from deposit request: {deposit_request:?}"
                            );
                            continue; // Skip this deposit request
                        }

                        let mut consensus_signature_bytes =
                            &deposit_request.consensus_signature[..];
                        let Ok(consensus_signature) =
                            bls12381::Signature::read(&mut consensus_signature_bytes)
                        else {
                            info!(
                                "Failed to parse consensus signature from deposit request: {deposit_request:?}"
                            );
                            continue; // Skip this deposit request
                        };
                        if !deposit_request.consensus_pubkey.verify(
                            &[],
                            &message,
                            &consensus_signature,
                        ) {
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
                            info!(
                                "Failed to verify consensus signature from deposit request: {deposit_request:?}"
                            );
                            continue; // Skip this deposit request
                        }
                        state.push_deposit(deposit_request);
                    }
                    ExecutionRequest::Withdrawal(mut withdrawal_request) => {
                        // Only add the withdrawal request if the validator exists and has sufficient balance
                        if let Some(mut account) = state
                            .get_account(&withdrawal_request.validator_pubkey)
                            .cloned()
                        {
                            // If the validator already submitted an exit request, we skip this withdrawal request
                            if matches!(account.status, ValidatorStatus::SubmittedExitRequest) {
                                info!(
                                    "Failed to parse withdrawal request because the validator already submitted a request: {withdrawal_request:?}"
                                );
                                continue; // Skip this withdrawal request
                            }

                            // The balance minus any pending withdrawals have to be larger than the amount of the withdrawal request
                            if account.balance - account.pending_withdrawal_amount
                                < withdrawal_request.amount
                            {
                                info!(
                                    "Failed to parse withdrawal request due to insufficient balance: {withdrawal_request:?}"
                                );
                                continue; // Skip this withdrawal request
                            }

                            // The source address must match the validators withdrawal address
                            if withdrawal_request.source_address != account.withdrawal_credentials {
                                info!(
                                    "Failed to parse withdrawal request because the source address doesn't match the withdrawal credentials: {withdrawal_request:?}"
                                );
                                continue; // Skip this withdrawal request
                            }
                            // If after this withdrawal the validator balance would be less than the
                            // minimum stake, then the full validator balance is withdrawn.
                            if account.balance
                                - account.pending_withdrawal_amount
                                - withdrawal_request.amount
                                < validator_minimum_stake
                            {
                                // Check the remaining balance and set the withdrawal amount accordingly
                                let remaining_balance =
                                    account.balance - account.pending_withdrawal_amount;
                                withdrawal_request.amount = remaining_balance;
                                account.status = ValidatorStatus::SubmittedExitRequest;
                            }

                            account.pending_withdrawal_amount += withdrawal_request.amount;
                            state.set_account(withdrawal_request.validator_pubkey, account);
                            state.push_withdrawal_request(
                                withdrawal_request.clone(),
                                new_height + validator_withdrawal_period,
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

async fn process_execution_requests<
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block<S, V>,
    new_height: u64,
    state: &mut ConsensusState,
    epoch_num_of_blocks: u64,
    validator_onboarding_limit_per_block: usize,
    validator_minimum_stake: u64,
) {
    if is_penultimate_block_of_epoch(epoch_num_of_blocks, new_height) {
        for _ in 0..validator_onboarding_limit_per_block {
            if let Some(request) = state.pop_deposit() {
                let mut validator_balance = 0;
                let mut account_exists = false;
                if let Some(mut account) = state
                    .get_account(request.node_pubkey.as_ref().try_into().unwrap())
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
                        state
                            .set_account(request.node_pubkey.as_ref().try_into().unwrap(), account);
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
                        consensus_public_key: request.consensus_pubkey.clone(),
                        withdrawal_credentials: Address::from_slice(
                            &request.withdrawal_credentials[12..32],
                        ), // Take last 20 bytes
                        balance: request.amount,
                        pending_withdrawal_amount: 0,
                        status: ValidatorStatus::Inactive,
                        last_deposit_index: request.index,
                    };
                    state.set_account(
                        request.node_pubkey.as_ref().try_into().unwrap(),
                        new_account,
                    );
                    validator_balance = request.amount;
                }
                if !account_exists && validator_balance >= validator_minimum_stake {
                    // If the node shuts down, before the account changes are committed,
                    // then everything should work normally, because the registry is not persisted to disk
                    state.added_validators.push(request.node_pubkey.clone());
                }
                #[cfg(debug_assertions)]
                {
                    use commonware_codec::Encode;
                    let gauge: Gauge = Gauge::default();
                    gauge.set(validator_balance as i64);
                    context.register(
                        format!("<registry>{}</registry><creds>{}</creds><pubkey>{}</pubkey>_deposit_validator_balance",
                                !account_exists && validator_balance >= validator_minimum_stake,
                                hex::encode(request.withdrawal_credentials), hex::encode(request.node_pubkey.encode())),
                        "Validator balance",
                        gauge
                    );
                }
            }
        }
    }

    // Remove pending withdrawals that are included in the committed block
    for withdrawal in &block.payload.payload_inner.withdrawals {
        let pending_withdrawal = state.pop_withdrawal();
        // TODO(matthias): these checks should never fail. we have to make sure that these withdrawals are
        // verified when the block is verified. it is too late when the block is committed.
        let pending_withdrawal = pending_withdrawal.expect("pending withdrawal must be in state");
        assert_eq!(pending_withdrawal.inner, *withdrawal);

        if let Some(mut account) = state.get_account(&pending_withdrawal.pubkey).cloned()
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

            // If the remaining balance is 0, remove the validator account from the state.
            if account.balance == 0 {
                state.remove_account(&pending_withdrawal.pubkey);
                state
                    .removed_validators
                    .push(PublicKey::decode(&pending_withdrawal.pubkey[..]).unwrap()); // todo(dalton) remove unwrap
            } else {
                state.set_account(pending_withdrawal.pubkey, account);
            }
        }
    }
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
