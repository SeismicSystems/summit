use crate::config::ProtocolConsts;
use crate::db::{Config as StateConfig, FinalizerState};
use crate::{FinalizerConfig, FinalizerMailbox, FinalizerMessage};
use alloy_rpc_types_engine::ForkchoiceState;
use anyhow::{Result, anyhow};
#[allow(unused)]
use commonware_codec::{DecodeExt as _, ReadExt as _, Write as _};
use commonware_consensus::Reporter;
use commonware_consensus::simplex::scheme::bls12381_multisig;
use commonware_consensus::simplex::types::Finalization;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{Digestible, Signer};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, Storage, spawn_cell};
use commonware_storage::translator::EightCap;
use commonware_utils::acknowledgement::{Acknowledgement, Exact};
use commonware_utils::{NZU64, NZUsize, hex};
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt as _, select_biased};
#[cfg(feature = "prom")]
use metrics::{counter, histogram};
#[cfg(debug_assertions)]
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::marker::PhantomData;
use std::num::NonZero;
use std::time::{Duration, Instant};
use summit_orchestrator::Message;
use summit_syncer::Update;
use summit_types::account::ValidatorStatus;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state_query::{
    ConsensusStateQuery, ConsensusStateRequest, ConsensusStateResponse,
};
use summit_types::ext_private_key::derive_observer_keys;
use summit_types::network_oracle::NetworkOracle;
use summit_types::scheme::EpochTransition;
use summit_types::ssz_state_tree::{SszStateTree, StateProofEntry};
use summit_types::ssz_tree_key::SszStateKey;
use summit_types::utils::{
    is_first_block_of_epoch, is_last_block_of_epoch, is_penultimate_block_of_epoch,
};
use summit_types::{
    Block, BlockAuxData, Digest, FinalizedHeader, PublicKey, deposit_signature_domain,
};
use summit_types::{EngineClient, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024);

type FinalizerScheme<V> = bls12381_multisig::Scheme<PublicKey, V>;
type StateQueryResponse<V> = ConsensusStateResponse<FinalizerScheme<V>>;
type StateQueryMessage<V> = (
    ConsensusStateRequest,
    oneshot::Sender<StateQueryResponse<V>>,
);

/// Generate one proof slot per requested key, preserving positional alignment:
/// the i-th result corresponds to the i-th key, and a key that resolves to no
/// proof (missing collection entry, etc.) yields `None` rather than being
/// dropped. Callers rely on this one-result-per-key invariant — see #260/#267 —
/// so this must stay a `map` (not `filter_map`) into `Vec<Option<StateProofEntry>>`.
///
/// By-pubkey field requests (`ValidatorField`/`WithdrawalField`) return a keyed
/// entry carrying the item's key-leaf proof in `key`, so a consumer can bind the
/// field to the requested pubkey (see `KeyedFieldProof`). All other requests
/// carry a single proof in `field` with `key: None`.
fn generate_state_proofs(
    proof_tree: &SszStateTree,
    validator_keys: &[[u8; 32]],
    keys: &[SszStateKey],
) -> Vec<Option<StateProofEntry>> {
    keys.iter()
        .map(|key| match key {
            SszStateKey::Scalar(leaf_index) => Some(StateProofEntry {
                field: proof_tree.generate_scalar_proof(*leaf_index),
                key: None,
            }),
            SszStateKey::Validator(pubkey) => proof_tree
                .generate_validator_proof(pubkey, validator_keys)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::ValidatorField(pubkey, field_index) => proof_tree
                .generate_validator_keyed_field_proof(pubkey, *field_index, validator_keys)
                .map(|kp| StateProofEntry {
                    field: kp.field,
                    key: Some(kp.key),
                }),
            SszStateKey::Deposit(index) => proof_tree
                .generate_deposit_proof(*index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::DepositField(index, field_index) => proof_tree
                .generate_deposit_field_proof(*index, *field_index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::Withdrawal(pubkey) => proof_tree
                .generate_withdrawal_proof_by_key(pubkey)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::WithdrawalField(pubkey, field_index) => proof_tree
                .generate_withdrawal_keyed_field_proof_by_key(pubkey, *field_index)
                .map(|kp| StateProofEntry {
                    field: kp.field,
                    key: Some(kp.key),
                }),
            SszStateKey::ProtocolParam(index) => proof_tree
                .generate_protocol_param_proof(*index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::ProtocolParamField(index, field_index) => proof_tree
                .generate_protocol_param_field_proof(*index, *field_index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::AddedValidator(index) => proof_tree
                .generate_added_validator_proof(*index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::AddedValidatorField(index, field_index) => proof_tree
                .generate_added_validator_field_proof(*index, *field_index)
                .map(|field| StateProofEntry { field, key: None }),
            SszStateKey::RemovedValidator(index) => proof_tree
                .generate_removed_validator_proof(*index)
                .map(|field| StateProofEntry { field, key: None }),
        })
        .collect()
}

/// Tracks the consensus state for a notarized (but not yet finalized) block
#[derive(Clone, Debug)]
struct ForkState {
    block_digest: Digest,
    parent_digest: Digest,
    consensus_state: ConsensusState,
}

/// Result of attempting to apply a block to the execution layer.
#[derive(Debug)]
enum ExecuteOutcome {
    /// The EL accepted the payload and `state` has been advanced.
    Applied,
    /// The EL rejected the payload as invalid. `state` is unchanged.
    /// Caller decides the policy (discard a notarized fork, shut down on a finalized block).
    InvalidPayload,
    /// The EL returned SYNCING. `state` is unchanged. Caller must buffer the
    /// block and retry later.
    Syncing,
}

/// Send a forkchoice update to the execution client and map its response to an
/// [`ExecuteOutcome`], so the SYNCING/INVALID/VALID gating is identical everywhere a
/// forkchoice is committed (block execution and the notarized→finalized reuse path).
/// `SYNCING` → `Syncing` (caller buffers and retries; nothing should be mutated before
/// calling this), non-valid → `InvalidPayload`, `VALID` → `Applied`.
async fn commit_forkchoice<C: EngineClient>(
    engine_client: &mut C,
    forkchoice: ForkchoiceState,
    height: u64,
) -> Result<ExecuteOutcome, summit_types::EngineClientError> {
    let status = engine_client.commit_hash(forkchoice).await?;
    if status.is_syncing() {
        debug!(
            height,
            "execution client returned SYNCING on forkchoice update; deferring block for later retry"
        );
        return Ok(ExecuteOutcome::Syncing);
    }
    if !status.is_valid() {
        warn!(
            height,
            ?status,
            "execution client returned non-valid forkchoice update"
        );
        return Ok(ExecuteOutcome::InvalidPayload);
    }
    Ok(ExecuteOutcome::Applied)
}

/// Result of a single attempt to handle a notarized or finalized block.
///
/// Critical errors that should shut the validator down are returned as
/// `Err(anyhow)` and are not represented here.
///
/// The type parameter `E` carries the deferred entry back to the caller on
/// `Buffered`. The finalized handler uses `E = PendingFinalized<V>` so the
/// caller can place the entry at the correct end of the buffer (drain →
/// push_front to preserve height order; mailbox → push_back). The notarized
/// handler uses `E = ()` and pushes internally. The `orphaned_blocks`
/// mechanism re-resolves out-of-order dependencies on its own.
#[derive(Debug)]
enum HandleOutcome<E = ()> {
    /// The block was applied (or correctly discarded as an outdated / dead-fork
    /// block). No further attempt is needed.
    Applied,
    /// The execution layer returned SYNCING. The caller must re-queue the
    /// carried entry (finalized) or knows the handler already did (notarized).
    Buffered(E),
}

/// A finalized block waiting for the execution layer to finish SYNCING.
struct PendingFinalized<V: Variant> {
    block: Block,
    finalization: Option<
        Finalization<bls12381_multisig::Scheme<PublicKey, V>, <Block as Digestible>::Digest>,
    >,
    ack: Exact,
    /// When the entry was first enqueued. Observability only — not used for bounding.
    first_attempt_at: Instant,
}

/// A notarized block waiting for the execution layer to finish SYNCING.
///
/// We deliberately do not capture the parent's consensus state here. The drain
/// path re-invokes `handle_notarized_block`, which re-resolves the parent from
/// the current canonical / fork state.
struct PendingNotarized {
    block: Block,
    /// When the entry was first enqueued. Observability only.
    first_attempt_at: Instant,
}

pub struct Finalizer<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
    C: EngineClient,
    O: NetworkOracle<PublicKey>,
    S: Signer<PublicKey = PublicKey>,
    V: Variant,
> {
    mailbox: mpsc::Receiver<FinalizerMessage<bls12381_multisig::Scheme<PublicKey, V>, Block>>,
    state_query: mpsc::Receiver<StateQueryMessage<V>>,
    pending_height_notifys: BTreeMap<(u64, Digest), Vec<oneshot::Sender<bool>>>,
    context: ContextCell<R>,
    engine_client: C,
    db: FinalizerState<R, V>,

    // Canonical state (finalized) - contains latest_height
    canonical_state: ConsensusState,

    // Fork states (notarized but not yet finalized)
    fork_states: BTreeMap<u64, BTreeMap<Digest, ForkState>>,

    // Tombstones for fork states that were executed before a conflicting
    // ancestor finalized. Later NotifyAtHeight calls for these digests should
    // fail immediately instead of being stored as waiters for a block that can
    // no longer become canonical-compatible.
    dead_fork_digests: HashSet<(u64, Digest)>,

    // Orphaned notarized blocks that arrived before their parent
    orphaned_blocks: BTreeMap<u64, HashMap<Digest, Vec<Block>>>,

    // Finalized blocks deferred because the EL returned SYNCING.
    // FIFO, drained in arrival (= height) order by `drain_pending`.
    pending_finalized: VecDeque<PendingFinalized<V>>,

    // Notarized blocks deferred because the EL returned SYNCING.
    // FIFO; each entry is retried independently because forks have independent
    // parent states which are re-resolved by `handle_notarized_block` on drain.
    pending_notarized: VecDeque<PendingNotarized>,
    // Membership set for deduping `pending_notarized` by block digest.
    pending_notarized_keys: HashSet<Digest>,

    // Whether either buffer has crossed the warn threshold since the last
    // time it was empty. Edge-triggered to avoid log spam on every tick.
    pending_warn_active: bool,

    // How often `drain_pending` runs while the EL is recovering from SYNCING.
    drain_interval: Duration,

    // Soft threshold for emitting a warn log when either pending buffer grows.
    // No cap is enforced; observability only.
    buffered_blocks_warn_threshold: usize,
    // Hard cap for unique deferred notarized blocks while the EL is SYNCING.
    pending_notarized_max: usize,

    genesis_hash: [u8; 32],
    protocol_consts: ProtocolConsts,
    deposit_signature_domain: Digest,
    oracle: O,
    node_public_key: PublicKey,

    /// Chain bound domain (`chain_domain(config_digest)`) used to derive the
    /// authorized observer child keys. Must match the domain the live P2P
    /// observer signer is derived with (see node startup), or observers will
    /// not be authenticated. Distinct from the raw deposit namespace, which is
    /// already folded into `deposit_signature_domain`.
    observer_domain: Vec<u8>,
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
        ConsensusStateQuery<bls12381_multisig::Scheme<PublicKey, V>>,
    ) {
        let (tx, rx) = mpsc::channel(cfg.mailbox_size);
        let (state_query, state_query_rx) = ConsensusStateQuery::new(cfg.mailbox_size);
        let state_cfg = StateConfig {
            log: commonware_storage::journal::contiguous::variable::Config {
                partition: format!("{}-finalizer_state-log", cfg.db_prefix),
                write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: ((), ()),
                items_per_section: NZU64!(262_144),
                page_cache: cfg.page_cache,
            },
            translator: EightCap,
        };

        let db = FinalizerState::<R, V>::new(
            context.with_label("finalizer_state"),
            state_cfg,
            cfg.cancellation_token.clone(),
        )
        .await;

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

        let shared_state = state.clone_with_shared_epocher();

        (
            Self {
                context: ContextCell::new(context),
                mailbox: rx,
                state_query: state_query_rx,
                engine_client: cfg.engine_client,
                oracle: cfg.oracle,
                pending_height_notifys: BTreeMap::new(),
                db,
                canonical_state: state,
                fork_states: BTreeMap::new(),
                dead_fork_digests: HashSet::new(),
                orphaned_blocks: BTreeMap::new(),
                pending_finalized: VecDeque::new(),
                pending_notarized: VecDeque::new(),
                pending_notarized_keys: HashSet::new(),
                pending_warn_active: false,
                drain_interval: cfg.drain_interval,
                buffered_blocks_warn_threshold: cfg.buffered_blocks_warn_threshold,
                pending_notarized_max: cfg.pending_notarized_max,
                genesis_hash: cfg.genesis_hash,
                protocol_consts: cfg.protocol_consts,
                deposit_signature_domain: deposit_signature_domain(
                    cfg.genesis_hash,
                    &cfg.namespace,
                ),
                node_public_key: cfg.node_public_key,
                observer_domain: cfg.observer_domain,
                validator_exit: false,
                cancellation_token: cfg.cancellation_token,
                _signer_marker: PhantomData,
                _variant_marker: PhantomData,
                #[cfg(debug_assertions)]
                height_gauge,
                #[cfg(debug_assertions)]
                consensus_state_stored_gauge,
            },
            shared_state,
            FinalizerMailbox::new(tx),
            state_query,
        )
    }

    pub fn start(mut self, orchestrator_mailbox: summit_orchestrator::Mailbox) -> Handle<()> {
        spawn_cell!(self.context, self.run(orchestrator_mailbox).await)
    }

    pub async fn run(mut self, mut orchestrator_mailbox: summit_orchestrator::Mailbox) {
        let mut last_committed_timestamp: Option<Instant> = None;
        let mut signal = self.context.stopped().fuse();
        let cancellation_token = self.cancellation_token.clone();
        let (_, empty_state_query) = mpsc::channel(1);
        let mut state_query = Some(std::mem::replace(&mut self.state_query, empty_state_query));

        // Initialize the current epoch with the validator set
        // This ensures the orchestrator can start consensus immediately
        let current_epoch_validators = self.canonical_state.get_current_epoch_validators();
        let network_keys: Vec<_> = current_epoch_validators
            .iter()
            .map(|(node_key, _)| node_key.clone())
            .collect();
        let observer_keys = derive_observer_keys(
            &network_keys,
            &self.observer_domain,
            self.canonical_state.get_observers_per_validator(),
        );
        self.oracle
            .track(
                self.canonical_state.get_epoch(),
                network_keys,
                observer_keys,
            )
            .await;

        orchestrator_mailbox
            .report(Message::Enter(EpochTransition {
                epoch: Epoch::new(self.canonical_state.get_epoch()),
                validator_keys: current_epoch_validators,
            }))
            .await;

        // Send initial forkchoice to the execution client so it knows the
        // chain head and can start P2P sync.
        // We do not block the actor here waiting for SYNCING to resolve.
        //
        // If the EL is still SYNCING, we fall through and enter the main
        // mailbox loop immediately. The first finalized or notarized block
        // we receive goes through `execute_block`, whose own SYNCING-aware
        // retry path absorbs the catch-up window. Meanwhile the actor
        // remains responsive to RPC/aux-data queries against the
        // checkpoint-loaded `canonical_state`, and to cancellation /
        // runtime-stop signals.
        {
            let forkchoice = self.canonical_state.get_forkchoice();
            if !forkchoice.head_block_hash.is_zero() {
                info!(
                    head = %forkchoice.head_block_hash,
                    "sending initial forkchoice update to execution client"
                );
                match self.engine_client.commit_hash(*forkchoice).await {
                    Ok(status) if status.is_valid() => {
                        info!(
                            "execution client already synced to checkpoint head, \
                             ready to replay blocks"
                        );
                    }
                    Ok(status) if status.is_syncing() => {
                        warn!(
                            "execution client SYNCING toward checkpoint head; \
                             entering main loop now, block-application retries \
                             will cover the catch-up window"
                        );
                    }
                    Ok(status) => {
                        // INVALID (or any non-Valid/Syncing PayloadStatus) is
                        // a critical mismatch. The checkpoint head is not a
                        // valid block on the EL side. This validator cannot
                        // safely continue.
                        error!(
                            target: "critical",
                            ?forkchoice,
                            ?status,
                            height = self.canonical_state.get_latest_height(),
                            epoch = self.canonical_state.get_epoch(),
                            "finalizer started with invalid forkchoice"
                        );
                        #[cfg(feature = "prom")]
                        counter!(
                            "critical_errors_total",
                            "reason" => "invalid_forkchoice",
                            "severity" => "critical"
                        )
                        .increment(1);
                        self.cancellation_token.cancel();
                        return;
                    }
                    Err(e) => {
                        error!(
                            target: "critical",
                            "engine client error on initial forkchoice update: {e}"
                        );
                        #[cfg(feature = "prom")]
                        counter!(
                            "critical_errors_total",
                            "reason" => "engine_client_error",
                            "severity" => "critical"
                        )
                        .increment(1);
                        self.cancellation_token.cancel();
                        return;
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
            let query_message = async {
                match state_query.as_mut() {
                    Some(state_query) => state_query.next().await,
                    None => std::future::pending().await,
                }
            }
            .fuse();
            futures::pin_mut!(query_message);

            select_biased! {
                mailbox_message = self.mailbox.next() => {
                    let mail = mailbox_message.expect("Finalizer mailbox closed");
                    match mail {
                        FinalizerMessage::SyncerUpdate { update } => {
                            match update {
                                Update::Tip(_height, _digest) => {
                                    // I don't think we need this
                                }
                                Update::FinalizedBlock((block, finalization), ack_tx) => {
                                    let entry = PendingFinalized {
                                        block,
                                        finalization,
                                        ack: ack_tx,
                                        first_attempt_at: Instant::now(),
                                    };
                                    // Preserve arrival order: if there are
                                    // already buffered finalized blocks, the
                                    // EL won't make progress on this one
                                    // either. Enqueue without attempting,
                                    // both to avoid a wasted check_payload
                                    // and to keep the buffer in height order.
                                    if !self.pending_finalized.is_empty() {
                                        self.pending_finalized.push_back(entry);
                                        self.update_pending_warn();
                                    } else {
                                        match self.handle_finalized_block(entry, &mut orchestrator_mailbox, &mut last_committed_timestamp).await {
                                            Ok(HandleOutcome::Applied) => {}
                                            Ok(HandleOutcome::Buffered(entry)) => {
                                                // First-time arrival; buffer was empty so push_back is correct.
                                                self.pending_finalized.push_back(entry);
                                                self.update_pending_warn();
                                            }
                                            Err(err) => {
                                                info!(?err, "finalizer triggering graceful shutdown");
                                                self.cancellation_token.cancel();
                                                break;
                                            }
                                        }
                                    }
                                }
                                Update::NotarizedBlock(block) => {
                                    if let Err(err) = self.handle_notarized_block(block).await {
                                        info!(?err, "finalizer triggering graceful shutdown");
                                        self.cancellation_token.cancel();
                                        break;
                                    }
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
                                if self.dead_fork_digests.contains(&(height, block_digest)) {
                                    let _ = response.send(false);
                                } else if self.fork_states.get(&height)
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
                            // Serve the genesis hash keyed to the requested epoch, not just
                            // the current canonical one. During recovery/catch-up a stale
                            // Enter(epoch) can be drained after the finalizer has already
                            // advanced, so the requesting engine must still get its own
                            // epoch's genesis (the digest that roots that epoch's consensus);
                            // answering with the current epoch's genesis would root an
                            // old-epoch engine in the wrong digest.
                            let current = self.canonical_state.get_epoch();
                            let genesis = if epoch == current {
                                // Current epoch: held in canonical state (in-memory).
                                Some(self.canonical_state.get_epoch_genesis_hash())
                            } else if epoch == 0 {
                                // Epoch 0 is rooted at the configured genesis hash.
                                Some(self.genesis_hash)
                            } else if epoch < current {
                                // Past epoch: its genesis is the digest of the last block of
                                // epoch-1, which is a durable finalized header.
                                self.db
                                    .get_finalized_header(epoch - 1)
                                    .await
                                    .map(|h| h.header().get_digest().0)
                            } else {
                                // Future epoch we have not reached: no genesis to serve.
                                None
                            };

                            match genesis {
                                Some(hash) => {
                                    let _ = response.send(hash);
                                }
                                None => {
                                    // Decline rather than return a wrong genesis: dropping
                                    // `response` surfaces an error to the caller.
                                    error!(
                                        target: "critical",
                                        current,
                                        requested = epoch,
                                        "cannot serve epoch genesis hash for requested epoch; declining"
                                    );
                                    #[cfg(feature = "prom")]
                                    counter!("critical_errors_total", "reason" => "epoch_genesis_unavailable", "severity" => "critical").increment(1);
                                }
                            }
                        },
                        FinalizerMessage::QueryState { request, response } => {
                            self.handle_consensus_state_query(request, response).await;
                        },
                    }
                }
                _ = self.context.sleep(self.drain_interval).fuse() => {
                    // Retry blocks that were deferred because the EL was SYNCING.
                    if let Err(err) = self.drain_pending(&mut orchestrator_mailbox, &mut last_committed_timestamp).await {
                        info!(?err, "finalizer triggering graceful shutdown");
                        self.cancellation_token.cancel();
                        break;
                    }
                }
                _ = cancellation_token.cancelled().fuse() => {
                    info!("finalizer received cancellation signal, exiting");
                    break;
                },
                sig = &mut signal => {
                    info!("runtime terminated, shutting down finalizer: {}", sig.unwrap());
                    break;
                },
                query_message = query_message => {
                    match query_message {
                        Some((request, response)) => {
                            self.handle_consensus_state_query(request, response).await;
                        }
                        None => {
                            warn!("finalizer state query mailbox closed");
                            state_query = None;
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    async fn handle_finalized_block(
        &mut self,
        entry: PendingFinalized<V>,
        orchestrator_mailbox: &mut summit_orchestrator::Mailbox,
        #[allow(unused_variables)] last_committed_timestamp: &mut Option<Instant>,
    ) -> Result<HandleOutcome<PendingFinalized<V>>> {
        let PendingFinalized {
            block,
            finalization,
            ack: ack_tx,
            first_attempt_at,
        } = entry;
        let height = block.height();
        let block_digest = block.digest();

        // Idempotence guard. The syncer contract is at-least-once (see `summit-syncer`
        // docs), so a finalized block may be re-delivered after it was already applied
        // (restart/recovery/replay paths). The notarized path ignores blocks at or below
        // canonical height; the finalized path must do the same. We must still ACK the
        // duplicate so the syncer's pending-ack pipeline doesn't stall, and we must NOT
        // re-execute it — re-execution would re-run the EL payload check, re-process
        // deposits/withdrawals, regress the height, or trip the epoch assertion in
        // `execute_block` when the canonical state has already advanced past an epoch
        // boundary.
        let latest_height = self.canonical_state.get_latest_height();
        if height <= latest_height {
            // At the canonical head the digest is known, so a mismatch here means two
            // different blocks were finalized at the same height — a consensus safety
            // violation we must surface rather than silently skip or re-execute.
            if height == latest_height && block_digest != self.canonical_state.get_head_digest() {
                error!(
                    target: "critical",
                    height,
                    ?block_digest,
                    head_digest = ?self.canonical_state.get_head_digest(),
                    "received a conflicting finalized block at the canonical head height"
                );
                #[cfg(feature = "prom")]
                counter!(
                    "critical_errors_total",
                    "reason" => "conflicting_finalization",
                    "severity" => "critical"
                )
                .increment(1);
                return Err(anyhow!(
                    "conflicting finalized block at height {height}: got {block_digest:?}, \
                     canonical head is {:?}",
                    self.canonical_state.get_head_digest()
                ));
            }
            debug!(
                height,
                ?block_digest,
                latest_height,
                "ignoring duplicate finalized block at or below canonical height"
            );
            ack_tx.acknowledge();
            return Ok(HandleOutcome::Applied);
        }

        // Release enforced block/certificate binding, run before any state change.
        //
        // The syncer pairs the finalized block and its finalization by height from
        // two independently keyed immutable archives (and the block archive
        // silently keeps a stale entry on a duplicate index). If that pairing is
        // ever inconsistent, we fail stop before executing the block, committing
        // forkchoice, notifying the finalized height, or acking, never after, so a
        // misbound pair can poison neither execution client canonical state nor the
        // exported finalized header and checkpoint material. The normal syncer path
        // now prevents this from reaching us; this is the last resort backstop.
        //
        // A block at an epoch boundary always carries a finalization; we
        // defensively bind any finalization that reaches another path too.
        if let Some(finalization) = &finalization
            && block_digest != finalization.proposal.payload
        {
            error!(
                target: "critical",
                height,
                header = ?block_digest,
                certified = ?finalization.proposal.payload,
                "finalized block does not match its finalization certificate; \
                 refusing to execute or store a misbound finalized block"
            );
            #[cfg(feature = "prom")]
            counter!(
                "critical_errors_total",
                "reason" => "finalized_certificate_mismatch",
                "severity" => "critical"
            )
            .increment(1);
            return Err(anyhow!(
                "finalized block/certificate digest mismatch at height {height}"
            ));
        }

        // Simplex guarantees the finalized chain is linear, so the
        // next finalized block must extend our canonical head. A mismatch means a
        // consensus safety violation (>=1/3 Byzantine finalizing a block conflicting
        // with an already-finalized ancestor) or local divergence. Halt rather than
        // execute a non-canonical block onto canonical state.
        let canonical_height = self.canonical_state.get_latest_height();
        let canonical_head = self.canonical_state.get_head_digest();

        if height != canonical_height + 1 || block.parent() != canonical_head {
            error!(
                target: "critical",
                height,
                ?block_digest,
                block_parent = ?block.parent(),
                ?canonical_head,
                canonical_height,
                "finalized block does not extend canonical head; refusing to apply"
            );
            #[cfg(feature = "prom")]
            counter!(
                "critical_errors_total",
                "reason" => "finalized_block_non_canonical",
                "severity" => "critical"
            )
            .increment(1);
            return Err(anyhow!(
                "finalized block at height {height} (digest {block_digest:?}) has parent {:?} \
                 but canonical head is {canonical_head:?}; consensus safety violation or divergence",
                block.parent()
            ));
        }

        // Try to find the fork state for this block (if it was notarized before finalization)
        if let Some(fork_state) = self
            .fork_states
            .get(&height)
            .and_then(|forks_at_height| forks_at_height.get(&block_digest))
        {
            // Block was already executed when notarized, reuse the fork state
            assert_eq!(
                fork_state.block_digest, block_digest,
                "Fork state digest mismatch at height {height}: expected {:?}, stored {:?}",
                block_digest, fork_state.block_digest
            );
            debug!(
                height,
                ?block_digest,
                "reusing fork state for finalized block"
            );

            // At notarization the EL accepted this block as head with
            // safe=finalized=old_canonical_finalized. Now that it is finalized we must
            // send and gate the canonical finalized forkchoice (head=safe=finalized=B)
            // before promoting the fork state to canonical / notifying waiters — the
            // direct path below does this inside `execute_block`, the reuse path must
            // mirror it. Gate BEFORE mutating `canonical_state` so a SYNCING retry
            // replays cleanly with state untouched.
            let eth_hash = block.eth_block_hash();
            match commit_forkchoice(
                &mut self.engine_client,
                ForkchoiceState {
                    head_block_hash: eth_hash.into(),
                    safe_block_hash: eth_hash.into(),
                    finalized_block_hash: eth_hash.into(),
                },
                height,
            )
            .await
            {
                Ok(ExecuteOutcome::Applied) => {}
                Ok(ExecuteOutcome::Syncing) => {
                    debug!(
                        height,
                        ?block_digest,
                        "deferring finalized block: execution layer is SYNCING on finalized forkchoice"
                    );
                    return Ok(HandleOutcome::Buffered(PendingFinalized {
                        block,
                        finalization,
                        ack: ack_tx,
                        first_attempt_at,
                    }));
                }
                Ok(ExecuteOutcome::InvalidPayload) => {
                    // The EL accepted the payload at notarization but won't adopt the
                    // finalized forkchoice for it: an EL/CL inconsistency on a finalized
                    // block. This validator cannot continue safely.
                    error!(
                        target: "critical",
                        height,
                        ?block_digest,
                        "execution client returned non-valid finalized forkchoice for reused block"
                    );
                    #[cfg(feature = "prom")]
                    counter!(
                        "critical_errors_total",
                        "reason" => "finalized_forkchoice_invalid",
                        "severity" => "critical"
                    )
                    .increment(1);
                    return Err(anyhow!(
                        "non-valid finalized forkchoice for finalized block at height {height} \
                         with digest {block_digest:?}"
                    ));
                }
                Err(e) => {
                    error!(target: "critical", height, "engine client error on finalized forkchoice for reused block: {e}");
                    #[cfg(feature = "prom")]
                    counter!("critical_errors_total", "reason" => "engine_client_error", "severity" => "critical")
                        .increment(1);
                    return Err(anyhow!(
                        "engine client error on finalized forkchoice at height {height}: {e}"
                    ));
                }
            }

            let live_epocher = self.canonical_state.get_epocher().clone();
            live_epocher.replace_with(fork_state.consensus_state.get_epocher());
            self.canonical_state = fork_state.consensus_state.clone_with_epocher(live_epocher);
        } else {
            // Catch-up finalized block: it was not notarized before finalization,
            // so it never passed the notarized path's parent check. The syncer
            // delivers finalized blocks by height + certificate without verifying
            // parent linkage, so a validly-certified block whose parent is not the
            // canonical finalized head (cross-deployment cert replay, a corrupted
            // or foreign archive) would otherwise execute onto canonical state and
            // advance the node onto an impossible history. It must extend the head.
            let head_digest = self.canonical_state.get_head_digest();
            if block.parent() != head_digest {
                error!(
                    target: "critical",
                    height,
                    ?block_digest,
                    parent = ?block.parent(),
                    canonical_head = ?head_digest,
                    "finalized block does not extend the canonical head; refusing to execute"
                );
                #[cfg(feature = "prom")]
                counter!(
                    "critical_errors_total",
                    "reason" => "finalized_wrong_parent",
                    "severity" => "critical"
                )
                .increment(1);
                return Err(anyhow!(
                    "finalized block at height {height} parent {:?} does not extend canonical head {:?}",
                    block.parent(),
                    head_digest
                ));
            }

            // Block was not notarized before finalization (catch-up or missed notarization)
            // Execute it now on canonical state
            debug!(
                height,
                ?block_digest,
                "executing finalized block directly (no prior fork state)"
            );
            let outcome = match execute_block(
                &mut self.engine_client,
                &self.context,
                &block,
                &mut self.canonical_state,
                &self.protocol_consts,
                self.deposit_signature_domain,
                // canonical path: instant finality (safe = finalized = head)
                None,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(e) => {
                    error!(target: "critical", height, "engine client error while executing finalized block: {e}");
                    #[cfg(feature = "prom")]
                    counter!("critical_errors_total", "reason" => "engine_client_error", "severity" => "critical")
                        .increment(1);
                    return Err(anyhow!(
                        "engine client error while executing finalized block at height {height}: {e}"
                    ));
                }
            };
            match outcome {
                ExecuteOutcome::Applied => {}
                ExecuteOutcome::Syncing => {
                    // The EL is still catching up. Return the entry to the
                    // caller; the caller decides where in `pending_finalized`
                    // it goes. Drain re-pushes to the front to preserve
                    // arrival order, mailbox pushes to the back.
                    debug!(
                        height,
                        ?block_digest,
                        "deferring finalized block: execution layer is SYNCING"
                    );
                    return Ok(HandleOutcome::Buffered(PendingFinalized {
                        block,
                        finalization,
                        ack: ack_tx,
                        first_attempt_at,
                    }));
                }
                ExecuteOutcome::InvalidPayload => {
                    // Network finalized a block whose payload the local Reth instance rejects. Either
                    // Reth has diverged (bug, corruption, restart loss) or a byzantine
                    // quorum certified an invalid payload. In either case, this validator
                    // cannot continue safely.
                    error!(
                        target: "critical",
                        height,
                        ?block_digest,
                        "finalized block payload rejected by execution client"
                    );
                    #[cfg(feature = "prom")]
                    counter!(
                        "critical_errors_total",
                        "reason" => "finalized_block_invalid",
                        "severity" => "critical"
                    )
                    .increment(1);
                    return Err(anyhow!(
                        "finalized block at height {height} with digest {block_digest:?} \
                         was rejected by the execution client"
                    ));
                }
            }
        }

        #[cfg(debug_assertions)]
        self.height_gauge.set(height as i64);

        self.canonical_state.set_forkchoice_safe_and_finalized(
            self.canonical_state.get_forkchoice().head_block_hash,
        );

        // Prune fork states at or below finalized height
        let total_forks = self.fork_states.len();
        self.fork_states.retain(|&h, _| h > height);
        self.prune_fork_states_not_descending_from(height, block_digest);
        self.dead_fork_digests
            .retain(|(dead_height, _)| *dead_height > height);
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

        // Forkchoice was already committed (and its status gated) inside
        // `execute_block` before any state mutation.

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
        let current_epoch = self.canonical_state.get_epoch();
        self.height_notify_finalized_up_to(new_height, block_digest);

        let mut epoch_change = false; // Store finalizes checkpoint to database
        if is_last_block_of_epoch(self.canonical_state.get_epocher(), new_height) {
            // The syncer will always send the last block of an epoch together with
            // the finalization.
            let finalization = finalization
                .expect("finalization is always included for the last block of an epoch");
            // Get participant count from the certificate signers
            let participant_count = finalization.certificate.signers.len();

            // Store the finalized block header in the database. The binding
            // between the block header and this finalization was already verified
            // at the top of this function, before any state change, so construct
            // directly.
            let finalized_header = FinalizedHeader::new_unchecked(
                block.header.clone(),
                finalization,
                participant_count,
            );

            #[cfg(feature = "prom")]
            let header_start = Instant::now();
            self.db
                .store_finalized_header(self.canonical_state.get_epoch(), &finalized_header)
                .await?;
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
                        hex::encode(finalized_header.header().get_digest()),
                        hex::encode(finalized_header.header().prev_epoch_header_hash())
                    ),
                    "chain height",
                    gauge,
                );
            }

            // Apply pending protocol parameter changes durably at the boundary.
            // Stake-bound enforcement now happens in enforce_minimum_stake during
            // the penultimate-block processing, so the returned flag is unused.
            if let Err(e) = self.canonical_state.apply_protocol_parameter_changes() {
                warn!("skipping invalid protocol parameter changes at epoch boundary: {e}");
            }

            // Build the committee for the next epoch.
            self.validator_exit = self.update_validator_committee();

            // Withdrawals that exceeded this epoch's per-epoch cap need no
            // rescheduling: they stay in the queue with their original (earliest)
            // epoch and are picked up next epoch via the `epoch <= current` due
            // check. Explicitly rescheduling them here would be an O(backlog) scan
            // plus a full withdrawal-subtree rebuild at every boundary for no
            // change in behavior.

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
                    .await?;
                #[cfg(feature = "prom")]
                {
                    let checkpoint_duration = checkpoint_start.elapsed().as_micros() as f64;
                    histogram!("finalizer_db_checkpoint_write_micros").record(checkpoint_duration);
                }
            }

            // Increment epoch
            let next_epoch = self.canonical_state.get_epoch() + 1;
            self.canonical_state.set_epoch(next_epoch);
            // Commonware views are epoch-local: the new epoch starts voting at
            // view 1 (view 0 is the epoch genesis).
            self.canonical_state.set_view(0);
            self.canonical_state
                .get_epocher()
                .advance_epoch(Epoch::new(next_epoch));
            // Set the epoch genesis hash for the next epoch
            self.canonical_state
                .set_epoch_genesis_hash(block.digest().0);
            // The active-exit budget is reset inside apply_committee_transition (run
            // earlier this block), so no explicit reset is needed here.

            // Clear transition deltas before persisting the next-epoch consensus state.
            self.canonical_state
                .remove_added_validators_for_epoch(next_epoch);
            if self.canonical_state.has_removed_validators() {
                self.canonical_state.clear_removed_validators();
            }

            // Re-capture the state/proof root AFTER the epoch-transition mutations
            // and delta cleanup, and BEFORE persisting. execute_block captured the
            // root before these boundary side effects ran, so its snapshot is stale
            // here. Capturing now makes both the first block of the new epoch (via
            // aux-data parent_beacon_block_root) and the durable consensus state
            // committed just below carry the post-transition root, so a node that
            // restarts at the boundary agrees with peers on the advertised root.
            self.canonical_state
                .capture_state_root(block.payload.payload_inner.payload_inner.block_number);

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
                .await?;
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
            self.db.commit().await?;
            #[cfg(feature = "prom")]
            {
                let commit_duration = commit_start.elapsed().as_micros() as f64;
                histogram!("finalizer_db_commit_micros").record(commit_duration);
                let db_operations_duration = db_operations_start.elapsed().as_millis() as f64;
                histogram!("database_operations_duration_millis").record(db_operations_duration);
                counter!("finalizer_epochs_completed_total").increment(1);
            }

            ack_tx.acknowledge();

            // Create the peer sets for the next epoch's P2P network.
            //
            // Only active validators go into the PRIMARY set: the backfill
            // resolver draws its fetch sources from primary, so a peer that is
            // merely warming up (Joining) must not be selectable as a source it
            // may be unable to serve. Joining validators are tracked as SECONDARY
            // instead, connectable for warm-up but not a backfill source, and
            // are promoted to primary automatically once they become active in a
            // later epoch transition. Observers are derived from the full active
            // or joining set so a joining validator's observer children still
            // connect during warm-up.
            let active_node_keys: Vec<_> = self
                .canonical_state
                .get_active_validators()
                .iter()
                .map(|(node_key, _)| node_key.clone())
                .collect();
            let active_or_joining_node_keys: Vec<_> = self
                .canonical_state
                .get_active_or_joining_validators()
                .iter()
                .map(|(node_key, _)| node_key.clone())
                .collect();
            let joining_node_keys: Vec<_> = active_or_joining_node_keys
                .iter()
                .filter(|key| !active_node_keys.contains(key))
                .cloned()
                .collect();
            let observer_keys = derive_observer_keys(
                &active_or_joining_node_keys,
                &self.observer_domain,
                self.canonical_state.get_observers_per_validator(),
            );
            let secondary_keys: Vec<_> =
                joining_node_keys.into_iter().chain(observer_keys).collect();
            self.oracle
                .track(
                    self.canonical_state.get_epoch(),
                    active_node_keys,
                    secondary_keys,
                )
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
        } else {
            // Every block needs to be ack'ed.
            // On the last block of an epoch we send the ack before updating the oracle and
            // reporting to the orchestrator, because those calls might be blocking.
            ack_tx.acknowledge();
        }

        info!(new_height, epoch = current_epoch, "executed block");

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
                // Propagate engine-client errors as critical shutdown; Buffered
                // is fine to ignore — the child is in `pending_notarized` now
                // and the drain timer will retry it.
                self.handle_notarized_block(child).await?;
            }
        }
        Ok(HandleOutcome::Applied)
    }

    async fn handle_notarized_block(&mut self, block: Block) -> Result<HandleOutcome> {
        let mut to_process = vec![block];
        // If any iteration defers a block because the EL is SYNCING, signal
        // `Buffered` so callers (including the drain timer) know to stop
        // burning further attempts against the same SYNCING EL.
        let mut outcome: HandleOutcome = HandleOutcome::Applied;

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
            if self.dead_fork_digests.contains(&(height, block_digest)) {
                debug!(
                    height,
                    ?block_digest,
                    "ignoring notarized block on dead fork"
                );
                continue;
            }
            if self
                .fork_states
                .get(&height)
                .is_some_and(|f| f.contains_key(&block_digest))
            {
                debug!(
                    height,
                    ?block_digest,
                    "skipping already-processed notarized block"
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

            // Execute the block into the cloned parent state. If the payload is invalid,
            // discard the block: certify will reject it on every honest validator, no
            // certify quorum will form, and no descendant can build on it (find_parent
            // gates on certified). The fork is dead; skip fork-state creation.
            // Fork path: head is this block, but safe/finalized stay at the
            // canonical finalized hash so the EL never finalizes a speculative fork.
            let fork_finalized = self.canonical_state.get_forkchoice().finalized_block_hash;
            let exec_outcome = match execute_block(
                &mut self.engine_client,
                &self.context,
                &block,
                &mut fork_state,
                &self.protocol_consts,
                self.deposit_signature_domain,
                Some(fork_finalized),
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    error!(target: "critical", height, ?block_digest, "engine client error while executing notarized block: {e}");
                    #[cfg(feature = "prom")]
                    counter!("critical_errors_total", "reason" => "engine_client_error", "severity" => "critical")
                        .increment(1);
                    return Err(anyhow!(
                        "engine client error while executing notarized block at height {height}: {e}"
                    ));
                }
            };
            match exec_outcome {
                ExecuteOutcome::Applied => {}
                ExecuteOutcome::Syncing => {
                    debug!(
                        height,
                        ?block_digest,
                        "deferring notarized block: execution layer is SYNCING"
                    );
                    if self.pending_notarized_keys.contains(&block_digest) {
                        debug!(
                            height,
                            ?block_digest,
                            "notarized block already pending while EL is SYNCING"
                        );
                    } else if self.pending_notarized.len() >= self.pending_notarized_max {
                        error!(
                            target: "critical",
                            height,
                            ?block_digest,
                            pending_notarized = self.pending_notarized.len(),
                            pending_notarized_max = self.pending_notarized_max,
                            "pending notarized buffer reached hard cap while execution layer is SYNCING"
                        );
                        #[cfg(feature = "prom")]
                        counter!("critical_errors_total", "reason" => "pending_notarized_cap", "severity" => "critical")
                            .increment(1);
                        return Err(anyhow!(
                            "pending notarized buffer reached hard cap {} while executing block at height {}",
                            self.pending_notarized_max,
                            height
                        ));
                    } else {
                        self.pending_notarized_keys.insert(block_digest);
                        self.pending_notarized.push_back(PendingNotarized {
                            block,
                            first_attempt_at: Instant::now(),
                        });
                        self.update_pending_warn();
                    }
                    outcome = HandleOutcome::Buffered(());
                    // The next block in `to_process` will be processed.
                    // Potential orphaned children of the current block won't
                    // be added to `to_process`, since the current block has to be
                    // executed before them.
                    continue;
                }
                ExecuteOutcome::InvalidPayload => {
                    warn!(
                        height,
                        ?block_digest,
                        "discarding notarized block with invalid payload"
                    );
                    #[cfg(feature = "prom")]
                    counter!("notarized_block_invalid_total").increment(1);
                    continue;
                }
            }

            // Store the new fork state
            self.fork_states.entry(height).or_default().insert(
                block_digest,
                ForkState {
                    block_digest,
                    parent_digest,
                    consensus_state: fork_state.clone(),
                },
            );

            // The fork forkchoice was already committed to reth (and its status
            // gated) inside `execute_block`, so validators can build/verify on it.

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
            self.height_notify_executed(height, block_digest);

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

        Ok(outcome)
    }

    /// Retry any finalized / notarized blocks that were deferred because the
    /// execution layer returned SYNCING. Called from the `drain_interval`
    /// timer arm of the main `select!`.
    ///
    /// Finalized blocks must drain in arrival (= height) order, so we stop at
    /// the first re-buffered entry. Notarized blocks go through the same EL;
    /// once one of them re-buffers, we know the EL is still SYNCING and stop.
    async fn drain_pending(
        &mut self,
        orchestrator_mailbox: &mut summit_orchestrator::Mailbox,
        last_committed_timestamp: &mut Option<Instant>,
    ) -> Result<()> {
        while let Some(entry) = self.pending_finalized.pop_front() {
            match self
                .handle_finalized_block(entry, orchestrator_mailbox, last_committed_timestamp)
                .await?
            {
                HandleOutcome::Applied => continue,
                HandleOutcome::Buffered(entry) => {
                    // EL is still SYNCING. Put the entry back at the FRONT
                    // so the buffer stays in arrival (= height) order. Don't
                    // try further finalized entries (they require this one
                    // applied first) and don't try notarized entries (same
                    // EL, same answer).
                    self.pending_finalized.push_front(entry);
                    self.update_pending_warn();
                    return Ok(());
                }
            }
        }

        while let Some(entry) = self.pending_notarized.pop_front() {
            let block_digest = entry.block.digest();
            self.pending_notarized_keys.remove(&block_digest);
            match self.handle_notarized_block(entry.block).await? {
                HandleOutcome::Applied => continue,
                HandleOutcome::Buffered(()) => {
                    self.update_pending_warn();
                    return Ok(());
                }
            }
        }

        // Drained both buffers cleanly. Allow the warn to fire again if a
        // subsequent SYNCING window pushes the buffer back over the threshold.
        self.update_pending_warn();
        Ok(())
    }

    /// Emit gauges for the pending-buffer sizes and edge-trigger a warn log
    /// when either crosses `buffered_blocks_warn_threshold` (once per crossing,
    /// not every tick).
    fn update_pending_warn(&mut self) {
        let finalized_len = self.pending_finalized.len();
        let notarized_len = self.pending_notarized.len();

        #[cfg(feature = "prom")]
        {
            metrics::gauge!("pending_finalized_blocks").set(finalized_len as f64);
            metrics::gauge!("pending_notarized_blocks").set(notarized_len as f64);
        }

        let over_threshold = finalized_len >= self.buffered_blocks_warn_threshold
            || notarized_len >= self.buffered_blocks_warn_threshold;
        if over_threshold && !self.pending_warn_active {
            // Age of the oldest buffered entry — gives the operator a sense
            // of "how long has the EL been stuck" alongside the count.
            let now = Instant::now();
            let oldest_finalized_age_secs = self
                .pending_finalized
                .front()
                .map(|e| now.saturating_duration_since(e.first_attempt_at).as_secs());
            let oldest_notarized_age_secs = self
                .pending_notarized
                .front()
                .map(|e| now.saturating_duration_since(e.first_attempt_at).as_secs());
            warn!(
                pending_finalized = finalized_len,
                pending_notarized = notarized_len,
                ?oldest_finalized_age_secs,
                ?oldest_notarized_age_secs,
                threshold = self.buffered_blocks_warn_threshold,
                "execution-layer SYNCING is backing up the finalizer buffer"
            );
            self.pending_warn_active = true;
        } else if !over_threshold && self.pending_warn_active {
            // Edge-reset so a subsequent crossing fires the warn again.
            self.pending_warn_active = false;
        }
    }

    fn prune_fork_states_not_descending_from(&mut self, height: u64, block_digest: Digest) {
        let heights: Vec<u64> = self
            .fork_states
            .range((height + 1)..)
            .map(|(&height, _)| height)
            .collect();
        let mut live_parents = HashSet::from([block_digest]);
        let mut empty_heights = Vec::new();
        let mut dead_forks = Vec::new();

        for fork_height in heights {
            let Some(forks) = self.fork_states.get_mut(&fork_height) else {
                continue;
            };

            forks.retain(|&fork_digest, fork_state| {
                let descends_from_canonical = live_parents.contains(&fork_state.parent_digest);
                if !descends_from_canonical {
                    dead_forks.push((fork_height, fork_digest));
                }
                descends_from_canonical
            });
            live_parents = forks.keys().copied().collect();

            if forks.is_empty() {
                empty_heights.push(fork_height);
            }
        }

        for fork_height in empty_heights {
            self.fork_states.remove(&fork_height);
        }
        for (fork_height, fork_digest) in dead_forks {
            self.dead_fork_digests.insert((fork_height, fork_digest));
            if let Some(senders) = self
                .pending_height_notifys
                .remove(&(fork_height, fork_digest))
            {
                for sender in senders {
                    let _ = sender.send(false);
                }
            }
        }
    }

    fn height_notify_executed(&mut self, height: u64, block_digest: Digest) {
        // Notify only waiters for this specific (height, digest) pair
        if let Some(senders) = self.pending_height_notifys.remove(&(height, block_digest)) {
            for sender in senders {
                let _ = sender.send(true); // Ignore if receiver dropped
            }
        }
    }

    fn height_notify_finalized_up_to(&mut self, height: u64, block_digest: Digest) {
        let pending = std::mem::take(&mut self.pending_height_notifys);

        for ((waiter_height, waiter_digest), senders) in pending {
            if waiter_height > height {
                self.pending_height_notifys
                    .insert((waiter_height, waiter_digest), senders);
                continue;
            }

            let block_executed = waiter_height == height && waiter_digest == block_digest;
            for sender in senders {
                let _ = sender.send(block_executed); // Ignore if receiver dropped
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

        // Build on the selected parent head, but keep the EL safe/finalized hashes
        // pinned to the canonical finalized block. A stored fork state has its
        // safe/finalized normalized to its own head (so the SSZ root is independent
        // of processing order, see `execute_block`); exposing that verbatim would tell
        // the EL that a notarized-but-unfinalized fork head is finalized.
        let forkchoice = ForkchoiceState {
            head_block_hash: state.get_forkchoice().head_block_hash,
            safe_block_hash: self.canonical_state.get_forkchoice().finalized_block_hash,
            finalized_block_hash: self.canonical_state.get_forkchoice().finalized_block_hash,
        };

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
                    finalized_header.header().get_digest()
                } else {
                    self.genesis_hash.into()
                };

            // The re-clamped EIP-4895 payouts for the terminal block, under the
            // single per-epoch total cap with validator exits taking strict
            // priority over deposit refunds (#226). Commit applies the same set.
            let ready_withdrawals = state.emit_withdrawal_payouts(state.get_epoch());
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
                forkchoice,
                suggested_fee_recipient,
                treasury_address,
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
                forkchoice,
                suggested_fee_recipient,
                treasury_address,
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

                // Balance is not debited until payout, so account.balance already
                // reflects the current balance including any not-yet-paid queued
                // withdrawal. Reporting balance + pending would double-count.
                let balance = self
                    .canonical_state
                    .get_account(&key_bytes)
                    .map(|account| account.balance);
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
            ConsensusStateRequest::GetMaxWithdrawalsPerEpoch => {
                let value = self.canonical_state.get_max_withdrawals_per_epoch();
                let _ = sender.send(ConsensusStateResponse::MaxWithdrawalsPerEpoch(value));
            }
            ConsensusStateRequest::GetObserversPerValidator => {
                let value = self.canonical_state.get_observers_per_validator();
                let _ = sender.send(ConsensusStateResponse::ObserversPerValidator(value));
            }
            ConsensusStateRequest::GetMinimumValidatorCount => {
                let value = self.canonical_state.get_minimum_validator_count();
                let _ = sender.send(ConsensusStateResponse::MinimumValidatorCount(value));
            }
            ConsensusStateRequest::GetInvalidDepositTax => {
                let value = self.canonical_state.get_invalid_deposit_tax();
                let _ = sender.send(ConsensusStateResponse::InvalidDepositTax(value));
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
            ConsensusStateRequest::GenerateStateProof(keys, permit) => {
                let proof_tree = self.canonical_state.proof_tree_snapshot();
                let validator_keys = self.canonical_state.proof_validator_keys_snapshot();
                let root = self.canonical_state.get_state_root();
                let el_block_number = self.canonical_state.get_proof_el_block_number();
                self.context
                    .with_label("state_proof")
                    .shared(true)
                    .spawn(move |_| async move {
                        let proofs = generate_state_proofs(
                            proof_tree.as_ref(),
                            validator_keys.as_slice(),
                            &keys,
                        );
                        let _ = sender.send(ConsensusStateResponse::StateProof {
                            root,
                            el_block_number,
                            proofs,
                        });
                        // Release the rpc concurrency permit (if any) only now
                        // that the proof work has actually finished. The permit
                        // must be consumed inside this detached task because
                        // moving it here is what ties the in-flight-proof count
                        // to real work. If it instead dropped on the rpc handler
                        // future, a caller could connect, wait for the spawn,
                        // disconnect, and repeat to pile up proof tasks under a
                        // slot count that reads as idle. The explicit drop also
                        // forces the move closure to capture it rather than
                        // dropping it on the finalizer loop when the match arm
                        // ends.
                        drop(permit);
                    });
            }
        }
    }

    fn update_validator_committee(&mut self) -> bool {
        // Apply the staged committee deltas: activate added validators and route
        // removed ones out (FullPayoutPending for voluntary exits, Inactive for
        // stake-bound removals). Returns whether this node was removed so the
        // caller can coordinate its own shutdown.
        self.canonical_state
            .apply_committee_transition(&self.node_public_key)
    }
}

/// Core execution logic that applies a block's state transitions to any ConsensusState.
///
/// This method:
/// - Calls `check_payload` on the engine client to validate the block on the EVM.
/// - On `SYNCING`: returns `ExecuteOutcome::Syncing` *without mutating `state`*. The
///   caller is responsible for buffering the block and retrying later — looping inline
///   here would starve the finalizer's mailbox.
/// - On `INVALID` (or any other non-`VALID` payload status that isn't `SYNCING`):
///   returns `ExecuteOutcome::InvalidPayload` without mutating `state`. The caller
///   decides the policy (discard a notarized fork, shut down on a finalized block).
/// - On `VALID`: applies consensus-layer state transitions (deposits, withdrawals,
///   validators), updates the forkchoice head, creates checkpoints at epoch boundaries,
///   and returns `ExecuteOutcome::Applied`.
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
    deposit_signature_domain: Digest,
    // forkchoice safe/finalized hash for this block's EL commit: `None` on the
    // canonical path (instant finality → safe = finalized = head), or the
    // canonical finalized hash for a speculative notarized fork.
    fork_finalized: Option<alloy_primitives::B256>,
) -> Result<ExecuteOutcome, summit_types::EngineClientError> {
    #[cfg(feature = "prom")]
    let block_processing_start = Instant::now();

    // check the payload
    #[cfg(feature = "prom")]
    let payload_check_start = Instant::now();
    let payload_status = engine_client.check_payload(block).await?;

    let new_height = block.height();

    #[cfg(feature = "prom")]
    {
        let payload_check_duration = payload_check_start.elapsed().as_millis() as f64;
        histogram!("payload_check_duration_millis").record(payload_check_duration);
    }

    // The EL is still catching up. Don't mutate `state`; the caller buffers and
    // we'll retry on the next drain tick.
    if payload_status.is_syncing() {
        debug!(
            height = new_height,
            "execution client returned SYNCING; deferring block for later retry"
        );
        return Ok(ExecuteOutcome::Syncing);
    }

    // Validate block against execution layer state
    // Note: withdrawals are validated in the application layer before voting
    if !payload_status.is_valid() {
        return Ok(ExecuteOutcome::InvalidPayload);
    }

    let eth_hash = block.eth_block_hash();
    let tx_count = block.payload.payload_inner.payload_inner.transactions.len();
    info!(
        new_height,
        epoch = state.get_epoch(),
        tx_count,
        eth_hash = hex(&eth_hash),
        "committing block to execution layer"
    );

    // EL forkchoice handoff, gated as part of block execution and BEFORE the
    // in-state forkchoice update and request processing below. Placing it here
    // means a SYNCING/INVALID forkchoice reuses the same buffer/abort handling as
    // check_payload, and a SYNCING retry replays cleanly because `state` is still
    // untouched. Only the head varies per block; safe/finalized follow the path.
    let safe_finalized = match fork_finalized {
        Some(finalized) => finalized, // notarized fork: keep the canonical finalized
        None => eth_hash.into(),      // canonical: instant finality (safe = finalized = head)
    };
    // A non-valid forkchoice here is an EL/CL inconsistency (the EL accepted the
    // payload as VALID but won't adopt the forkchoice for it), surfaced like an
    // invalid payload: the finalized path shuts down, the fork path discards.
    match commit_forkchoice(
        engine_client,
        ForkchoiceState {
            head_block_hash: eth_hash.into(),
            safe_block_hash: safe_finalized,
            finalized_block_hash: safe_finalized,
        },
        new_height,
    )
    .await?
    {
        ExecuteOutcome::Applied => {}
        other => return Ok(other),
    }

    state.set_forkchoice_head(eth_hash.into());

    // Buffer this block's raw execution requests. They are parsed and processed
    // in a single pass at the epoch end (penultimate block), so requests landing
    // on the last block naturally defer into the next epoch.
    state.buffer_execution_requests(&block.execution_requests);

    // Process the buffered requests (epoch end), apply payouts, and complete the
    // epoch's stake/committee bookkeeping.
    #[cfg(feature = "prom")]
    let process_requests_start = Instant::now();
    process_execution_requests(
        context,
        block,
        new_height,
        state,
        deposit_signature_domain,
        consts,
    )
    .await;
    #[cfg(feature = "prom")]
    {
        let process_requests_duration = process_requests_start.elapsed().as_millis() as f64;
        histogram!("process_execution_requests_duration_millis").record(process_requests_duration);
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

    // Freeze the trie root for the next block. Epoch-boundary finalization
    // re-captures after applying transition mutations.
    let el_block_number = block.payload.payload_inner.payload_inner.block_number;
    state.capture_state_root(el_block_number);

    Ok(ExecuteOutcome::Applied)
}

async fn process_execution_requests<
    R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng,
>(
    #[allow(unused)] context: &ContextCell<R>,
    block: &Block,
    new_height: u64,
    state: &mut ConsensusState,
    deposit_signature_domain: Digest,
    consts: &ProtocolConsts,
) {
    // At the penultimate block, process the epoch's buffered execution requests
    // in one pass (deposits verified/credited/activated, withdrawal requests
    // validated and enqueued, protocol params batched) and enforce any pending
    // minimum stake change against the committee.
    if is_penultimate_block_of_epoch(state.get_epocher(), new_height) {
        state.process_buffered_requests(
            deposit_signature_domain,
            consts.validator_num_warm_up_epochs,
            consts.validator_withdrawal_num_epochs,
        );
        state.enforce_minimum_stake();
    }

    // On the terminal block, apply the EIP-4895 payouts the block carries: debit
    // balances, remove drained accounts, and consume the queue entries. These
    // payouts were emitted from this same state at build time and pinned by the
    // verifier, so they must equal what the block paid out.
    if is_last_block_of_epoch(state.get_epocher(), new_height) {
        state.apply_withdrawal_payouts(state.get_epoch(), &block.payload.payload_inner.withdrawals);
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
