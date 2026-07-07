use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::checkpoint::Checkpoint;
use crate::dynamic_epocher::DynamicEpocher;
use crate::execution_request::{
    DepositRequest, ExecutionRequest, ParsedExecutionRequest, WithdrawalRequest,
};
use crate::header::AddedValidator;
use crate::protocol_params::{
    DEFAULT_MINIMUM_VALIDATOR_COUNT, MAX_INVALID_DEPOSIT_TAX, MIN_ALLOWED_TIMESTAMP_FUTURE_MS,
    ProtocolParam,
};
use crate::ssz_state_tree::SszStateTree;
use crate::utils::{invalid_deposit_refund_split, parse_withdrawal_credentials};
use crate::withdrawal::{PendingWithdrawal, WithdrawalKind, WithdrawalQueue};
use crate::{Digest, PublicKey};
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::ed25519::Signature;
use commonware_cryptography::{Verifier as _, bls12381, sha256};
#[cfg(feature = "prom")]
use metrics::histogram;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::num::NonZeroU64;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Why a deposit was rejected during epoch end processing. Recorded for
/// diagnostics; every rejection routes through the taxed refund so invalid
/// deposits cannot be a free DoS vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositRejectionReason {
    /// A key check failed after valid signatures: the consensus key does not
    /// match the existing account, or it already belongs to a different
    /// account.
    KeyMismatch,
    /// The node (Ed25519) signature failed verification. Checked before the
    /// consensus signature, so this is also what a deposit with both signatures
    /// invalid reports.
    InvalidNodeSignature,
    /// The consensus (BLS) signature failed verification, after a valid node
    /// signature.
    InvalidConsensusSignature,
    /// The deposit's Ed25519 or BLS key bytes did not decode.
    MalformedKey,
}

#[derive(Debug)]
pub struct ConsensusState {
    pub(crate) epoch: u64,
    pub(crate) view: u64,
    pub(crate) latest_height: u64,
    pub(crate) head_digest: Digest,
    pub(crate) deposit_queue: VecDeque<DepositRequest>,
    pub(crate) withdrawal_queue: WithdrawalQueue,
    pub(crate) validator_accounts: BTreeMap<[u8; 32], ValidatorAccount>,
    pub(crate) protocol_param_changes: Vec<ProtocolParam>,
    pub(crate) pending_checkpoint: Option<Checkpoint>,
    pub(crate) added_validators: BTreeMap<u64, Vec<AddedValidator>>,
    pub(crate) removed_validators: Vec<PublicKey>,
    /// Execution requests that need to be deferred. Currently this only applies to
    /// withdrawal requests received in the last block of an epoch.
    pub(crate) pending_execution_requests: Vec<alloy_primitives::Bytes>,
    pub(crate) forkchoice: ForkchoiceState,
    pub(crate) epoch_genesis_hash: [u8; 32],
    pub(crate) validator_minimum_stake: u64, // in gwei
    pub(crate) allowed_timestamp_future_ms: u64,
    pub(crate) treasury_address: Address,
    pub(crate) max_deposits_per_epoch: u64,
    pub(crate) max_withdrawals_per_epoch: u64,
    pub(crate) observers_per_validator: u32,
    pub(crate) minimum_validator_count: u64,
    pub(crate) pending_active_validator_exits: u64,
    pub(crate) invalid_deposit_tax: u64,
    pub(crate) epocher: DynamicEpocher,

    /// In-memory SSZ binary Merkle tree over the entire consensus state.
    /// Not serialized — rebuilt from data fields on deserialization.
    pub(crate) ssz_tree: SszStateTree,

    /// Frozen snapshot of `ssz_tree` at `capture_state_root()` time.
    /// Proofs are generated from this tree so they verify against the on-chain root.
    /// Not serialized — rebuilt alongside `ssz_tree`.
    pub(crate) proof_tree: Arc<SszStateTree>,

    /// Frozen snapshot of validator pubkeys (sorted) at `capture_state_root()` time.
    /// Needed for positional index lookups when generating validator proofs.
    pub(crate) proof_validator_keys: Arc<Vec<[u8; 32]>>,

    // Withdrawal proof lookup is handled by the pubkey index stored in SszStateTree itself.
    // The frozen proof_tree contains the withdrawal_pubkey_index from capture time.
    /// Snapshot of `ssz_tree.root()` captured for the next block's parent root.
    /// Not serialized — set via `capture_state_root()` after block execution, and
    /// re-captured after epoch-boundary finalization mutations.
    pub(crate) state_root: [u8; 32],

    /// The EL (Reth) block number at the time `capture_state_root()` was called.
    /// The state root appears on-chain in EL block `proof_el_block_number + 1`.
    pub(crate) proof_el_block_number: u64,

    /// Serialized snapshot of this `ConsensusState` taken at `capture_state_root()`
    /// time, with the snapshot's own `captured_bytes` cleared to prevent recursion.
    /// On restart, decoding the inner state and reading its `proof_tree` yields the
    /// capture-time proof tree exactly, so a restarted validator agrees with uninterrupted peers on
    /// `state_root` (and hence on `parent_beacon_block_root`).
    /// `None` only before the first `capture_state_root` call.
    pub(crate) captured_bytes: Option<Vec<u8>>,
}

impl Clone for ConsensusState {
    fn clone(&self) -> Self {
        self.clone_with_epocher(self.epocher.snapshot())
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        let mut s = Self {
            epoch: 0,
            view: 0,
            latest_height: 0,
            head_digest: sha256::Digest([0u8; 32]),
            deposit_queue: Default::default(),
            withdrawal_queue: Default::default(),
            protocol_param_changes: Default::default(),
            validator_accounts: Default::default(),
            pending_checkpoint: None,
            added_validators: Default::default(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            // Must stay within the protocol-parameter bound (see ProtocolParam::validate
            // and the decode guard in read_cfg); genesis would reject anything below
            // MIN_ALLOWED_TIMESTAMP_FUTURE_MS, so the default sits at that floor.
            allowed_timestamp_future_ms: MIN_ALLOWED_TIMESTAMP_FUTURE_MS,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: DEFAULT_MINIMUM_VALIDATOR_COUNT,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(1).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            proof_validator_keys: Arc::new(Vec::new()),
            captured_bytes: None,

            state_root: [0u8; 32],
            proof_el_block_number: 0,
        };
        s.rebuild_ssz_tree();
        s
    }
}

impl ConsensusState {
    /// Clones state data while installing the supplied epocher handle.
    ///
    /// Most consensus snapshots should use `Clone`, which isolates the epoch
    /// schedule. This is only for paths that deliberately control how the
    /// cloned state participates in live epoch schedule propagation.
    pub fn clone_with_epocher(&self, epocher: DynamicEpocher) -> Self {
        Self {
            epoch: self.epoch,
            view: self.view,
            latest_height: self.latest_height,
            head_digest: self.head_digest,
            deposit_queue: self.deposit_queue.clone(),
            withdrawal_queue: self.withdrawal_queue.clone(),
            validator_accounts: self.validator_accounts.clone(),
            protocol_param_changes: self.protocol_param_changes.clone(),
            pending_checkpoint: self.pending_checkpoint.clone(),
            added_validators: self.added_validators.clone(),
            removed_validators: self.removed_validators.clone(),
            pending_execution_requests: self.pending_execution_requests.clone(),
            forkchoice: self.forkchoice,
            epoch_genesis_hash: self.epoch_genesis_hash,
            validator_minimum_stake: self.validator_minimum_stake,
            allowed_timestamp_future_ms: self.allowed_timestamp_future_ms,
            treasury_address: self.treasury_address,
            max_deposits_per_epoch: self.max_deposits_per_epoch,
            max_withdrawals_per_epoch: self.max_withdrawals_per_epoch,
            observers_per_validator: self.observers_per_validator,
            minimum_validator_count: self.minimum_validator_count,
            pending_active_validator_exits: self.pending_active_validator_exits,
            invalid_deposit_tax: self.invalid_deposit_tax,
            epocher,
            ssz_tree: self.ssz_tree.clone(),
            proof_tree: self.proof_tree.clone(),
            proof_validator_keys: self.proof_validator_keys.clone(),
            captured_bytes: self.captured_bytes.clone(),
            state_root: self.state_root,
            proof_el_block_number: self.proof_el_block_number,
        }
    }

    /// Clones state data while retaining the same live epocher handle.
    ///
    /// Most consensus snapshots should use `Clone`, which isolates the epoch
    /// schedule. This is only for actor wiring that intentionally shares the
    /// canonical epocher across components.
    pub fn clone_with_shared_epocher(&self) -> Self {
        self.clone_with_epocher(self.epocher.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        forkchoice: ForkchoiceState,
        validator_minimum_stake: u64,
        epoch_length: NonZeroU64,
        allowed_timestamp_future_ms: u64,
        treasury_address: Address,
        max_deposits_per_epoch: u64,
        max_withdrawals_per_epoch: u64,
        observers_per_validator: u32,
        minimum_validator_count: u64,
        invalid_deposit_tax: u64,
    ) -> Self {
        let mut s = Self {
            epoch: 0,
            view: 0,
            latest_height: 0,
            head_digest: (*forkchoice.head_block_hash).into(),
            deposit_queue: Default::default(),
            withdrawal_queue: Default::default(),
            protocol_param_changes: Default::default(),
            validator_accounts: Default::default(),
            pending_checkpoint: None,
            added_validators: Default::default(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice,
            epoch_genesis_hash: forkchoice.head_block_hash.into(),
            validator_minimum_stake,
            allowed_timestamp_future_ms,
            treasury_address,
            max_deposits_per_epoch,
            max_withdrawals_per_epoch,
            observers_per_validator,
            minimum_validator_count,
            pending_active_validator_exits: 0,
            invalid_deposit_tax,
            epocher: DynamicEpocher::new(epoch_length),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            proof_validator_keys: Arc::new(Vec::new()),
            captured_bytes: None,

            state_root: [0u8; 32],
            proof_el_block_number: 0,
        };
        s.rebuild_ssz_tree();
        s
    }

    // State variable operations
    pub fn get_epocher(&self) -> &DynamicEpocher {
        &self.epocher
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.ssz_tree.set_epoch(epoch);
    }

    pub fn get_view(&self) -> u64 {
        self.view
    }

    pub fn set_view(&mut self, view: u64) {
        self.view = view;
        self.ssz_tree.set_view(view);
    }

    pub fn get_latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn set_latest_height(&mut self, height: u64) {
        self.latest_height = height;
        self.ssz_tree.set_latest_height(height);
    }

    pub fn get_next_withdrawal_index(&self) -> u64 {
        self.withdrawal_queue.next_index()
    }

    pub fn get_head_digest(&self) -> Digest {
        self.head_digest
    }

    pub fn get_minimum_stake(&self) -> u64 {
        self.validator_minimum_stake
    }

    /// Returns the minimum stake that *will* apply after the queued protocol-parameter
    /// changes are drained at the next epoch boundary. If no `MinimumStake` change is
    /// queued, returns the currently-active value.
    pub fn prospective_minimum_stake(&self) -> u64 {
        self.protocol_param_changes
            .iter()
            .rev()
            .find_map(|p| match p {
                ProtocolParam::MinimumStake(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(self.validator_minimum_stake)
    }

    /// Returns the minimum validator count that *will* apply after the queued
    /// protocol-parameter changes are drained at the next epoch boundary. If no
    /// `MinimumValidatorCount` change is queued, returns the currently-active value.
    ///
    /// Removals (voluntary exits and stake-bound force-removals) staged this epoch
    /// only take effect next epoch — at the same boundary a queued
    /// `MinimumValidatorCount` change applies. Floor checks therefore use this
    /// prospective value so a same-epoch raise is honored before it is formally
    /// applied, and a lowering doesn't over-restrict.
    pub fn prospective_minimum_validator_count(&self) -> u64 {
        self.protocol_param_changes
            .iter()
            .rev()
            .find_map(|p| match p {
                ProtocolParam::MinimumValidatorCount(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(self.minimum_validator_count)
    }

    pub fn set_minimum_stake(&mut self, stake: u64) {
        self.validator_minimum_stake = stake;
        self.ssz_tree.set_validator_minimum_stake(stake);
    }

    pub fn get_allowed_timestamp_future_ms(&self) -> u64 {
        self.allowed_timestamp_future_ms
    }

    pub fn set_allowed_timestamp_future_ms(&mut self, ms: u64) {
        self.allowed_timestamp_future_ms = ms;
        self.ssz_tree.set_allowed_timestamp_future_ms(ms);
    }

    pub fn get_max_deposits_per_epoch(&self) -> u64 {
        self.max_deposits_per_epoch
    }

    pub fn set_max_deposits_per_epoch(&mut self, value: u64) {
        self.max_deposits_per_epoch = value;
        self.ssz_tree.set_max_deposits_per_epoch(value);
    }

    pub fn get_max_withdrawals_per_epoch(&self) -> u64 {
        self.max_withdrawals_per_epoch
    }

    pub fn set_max_withdrawals_per_epoch(&mut self, value: u64) {
        self.max_withdrawals_per_epoch = value;
        self.ssz_tree.set_max_withdrawals_per_epoch(value);
    }

    pub fn get_observers_per_validator(&self) -> u32 {
        self.observers_per_validator
    }

    pub fn set_observers_per_validator(&mut self, value: u32) {
        self.observers_per_validator = value;
        self.ssz_tree.set_observers_per_validator(value);
    }

    pub fn get_minimum_validator_count(&self) -> u64 {
        self.minimum_validator_count
    }

    pub fn set_minimum_validator_count(&mut self, value: u64) {
        self.minimum_validator_count = value;
        self.ssz_tree.set_minimum_validator_count(value);
    }

    pub fn get_pending_active_validator_exits(&self) -> u64 {
        self.pending_active_validator_exits
    }

    pub fn increment_pending_active_validator_exits(&mut self) {
        self.pending_active_validator_exits = self.pending_active_validator_exits.saturating_add(1);
        self.ssz_tree
            .set_pending_active_validator_exits(self.pending_active_validator_exits);
    }

    pub fn reset_pending_active_validator_exits(&mut self) {
        self.pending_active_validator_exits = 0;
        self.ssz_tree.set_pending_active_validator_exits(0);
    }

    pub fn get_invalid_deposit_tax(&self) -> u64 {
        self.invalid_deposit_tax
    }

    pub fn set_invalid_deposit_tax(&mut self, value: u64) {
        self.invalid_deposit_tax = value;
        self.ssz_tree.set_invalid_deposit_tax(value);
    }

    pub fn get_treasury_address(&self) -> Address {
        self.treasury_address
    }

    pub fn set_treasury_address(&mut self, address: Address) {
        self.treasury_address = address;
        self.ssz_tree.set_treasury_address(&address);
    }

    pub fn get_pending_checkpoint(&self) -> Option<&Checkpoint> {
        self.pending_checkpoint.as_ref()
    }

    pub fn set_next_withdrawal_index(&mut self, index: u64) {
        self.withdrawal_queue.set_next_index(index);
        self.ssz_tree.set_next_withdrawal_index(index);
    }

    pub fn set_pending_checkpoint(&mut self, checkpoint: Option<Checkpoint>) {
        self.pending_checkpoint = checkpoint;
        self.ssz_tree
            .set_pending_checkpoint_digest(self.pending_checkpoint.as_ref().map(|cp| cp.digest.0));
    }

    pub fn get_added_validators(&self, epoch: u64) -> Option<&Vec<AddedValidator>> {
        self.added_validators.get(&epoch)
    }

    pub fn add_validator(&mut self, epoch: u64, validator: AddedValidator) {
        self.added_validators
            .entry(epoch)
            .or_default()
            .push(validator);
        self.ssz_tree
            .rebuild_added_validators(&self.added_validators);
    }

    pub fn get_removed_validators(&self) -> &Vec<PublicKey> {
        &self.removed_validators
    }

    pub fn set_removed_validators(&mut self, validators: Vec<PublicKey>) {
        self.removed_validators = validators;
        self.ssz_tree
            .rebuild_removed_validators(&self.removed_validators);
    }

    pub fn get_forkchoice(&self) -> &ForkchoiceState {
        &self.forkchoice
    }

    pub fn set_forkchoice(&mut self, forkchoice: ForkchoiceState) {
        self.forkchoice = forkchoice;
        self.ssz_tree
            .set_forkchoice_head_block_hash(&forkchoice.head_block_hash.0);
        self.ssz_tree
            .set_forkchoice_safe_block_hash(&forkchoice.safe_block_hash.0);
        self.ssz_tree
            .set_forkchoice_finalized_block_hash(&forkchoice.finalized_block_hash.0);
    }

    pub fn get_epoch_genesis_hash(&self) -> [u8; 32] {
        self.epoch_genesis_hash
    }

    pub fn set_epoch_genesis_hash(&mut self, hash: [u8; 32]) {
        self.epoch_genesis_hash = hash;
        self.ssz_tree.set_epoch_genesis_hash(&hash);
    }

    pub fn set_head_digest(&mut self, digest: Digest) {
        self.head_digest = digest;
        self.ssz_tree.set_head_digest(&digest.0);
    }

    pub fn set_forkchoice_head(&mut self, hash: alloy_primitives::B256) {
        self.forkchoice.head_block_hash = hash;
        self.ssz_tree.set_forkchoice_head_block_hash(&hash.0);
    }

    pub fn set_forkchoice_safe_and_finalized(&mut self, hash: alloy_primitives::B256) {
        self.forkchoice.safe_block_hash = hash;
        self.forkchoice.finalized_block_hash = hash;
        self.ssz_tree.set_forkchoice_safe_block_hash(&hash.0);
        self.ssz_tree.set_forkchoice_finalized_block_hash(&hash.0);
    }

    pub fn take_pending_checkpoint(&mut self) -> Option<Checkpoint> {
        let taken = self.pending_checkpoint.take();
        self.ssz_tree.set_pending_checkpoint_digest(None);
        taken
    }

    pub fn push_protocol_param_change(&mut self, param: ProtocolParam) {
        self.protocol_param_changes.push(param);
        self.ssz_tree
            .rebuild_protocol_params(&self.protocol_param_changes);
    }

    /// appends a batch of protocol param changes and rebuilds the param subtree
    /// at most once. rebuild_protocol_params reallocates and reroots the whole
    /// pending param subtree, so calling push_protocol_param_change per record
    /// is o(n^2) over a grouped batch. callers that decode several records from
    /// one block should accumulate them and flush through here instead.
    pub fn push_protocol_param_changes(&mut self, params: impl IntoIterator<Item = ProtocolParam>) {
        let before = self.protocol_param_changes.len();
        self.protocol_param_changes.extend(params);
        if self.protocol_param_changes.len() != before {
            self.ssz_tree
                .rebuild_protocol_params(&self.protocol_param_changes);
        }
    }

    pub fn push_removed_validator(&mut self, pubkey: PublicKey) {
        self.removed_validators.push(pubkey);
        self.ssz_tree
            .rebuild_removed_validators(&self.removed_validators);
    }

    pub fn clear_removed_validators(&mut self) {
        self.removed_validators.clear();
        self.ssz_tree
            .rebuild_removed_validators(&self.removed_validators);
    }

    pub fn has_removed_validators(&self) -> bool {
        !self.removed_validators.is_empty()
    }

    pub fn has_added_validators(&self, epoch: u64) -> bool {
        self.added_validators.contains_key(&epoch)
    }

    pub fn remove_added_validators_for_epoch(&mut self, epoch: u64) -> Option<Vec<AddedValidator>> {
        let validators = self.added_validators.remove(&epoch)?;
        self.ssz_tree
            .rebuild_added_validators(&self.added_validators);
        Some(validators)
    }

    pub fn remove_added_validator(&mut self, epoch: u64, pubkey: &PublicKey) -> bool {
        let removed = if let Some(validators) = self.added_validators.get_mut(&epoch)
            && let Some(pos) = validators.iter().position(|v| v.node_key == *pubkey)
        {
            validators.remove(pos);
            true
        } else {
            false
        };
        if !removed {
            return false;
        }
        // Drop the epoch key once its last scheduled activation is removed. An
        // empty entry and an absent entry must not commit to different roots, so
        // the map is kept canonical.
        if self
            .added_validators
            .get(&epoch)
            .is_some_and(|validators| validators.is_empty())
        {
            self.added_validators.remove(&epoch);
        }
        self.ssz_tree
            .rebuild_added_validators(&self.added_validators);
        true
    }

    pub fn take_pending_execution_requests(&mut self) -> Vec<alloy_primitives::Bytes> {
        let taken = std::mem::take(&mut self.pending_execution_requests);
        self.ssz_tree
            .rebuild_pending_execution_requests(&self.pending_execution_requests);
        taken
    }

    pub fn push_pending_execution_request(&mut self, request: alloy_primitives::Bytes) {
        self.pending_execution_requests.push(request);
        self.ssz_tree
            .rebuild_pending_execution_requests(&self.pending_execution_requests);
    }

    /// Buffer a block's raw execution requests for processing at epoch end.
    ///
    /// This is the parse time intake. Requests are appended verbatim. There is no
    /// decode, no validation, and no account or balance change here. They are
    /// decoded and applied in a single pass by the epoch end processing step,
    /// which then clears the buffer. The whole batch is appended and the SSZ
    /// subtree is rebuilt once.
    pub fn buffer_execution_requests(&mut self, requests: &[alloy_primitives::Bytes]) {
        if requests.is_empty() {
            return;
        }
        self.pending_execution_requests
            .extend(requests.iter().cloned());
        self.ssz_tree
            .rebuild_pending_execution_requests(&self.pending_execution_requests);
    }

    pub fn pending_execution_requests(&self) -> &[alloy_primitives::Bytes] {
        &self.pending_execution_requests
    }

    // Account operations
    pub fn get_account(&self, pubkey: &[u8; 32]) -> Option<&ValidatorAccount> {
        self.validator_accounts.get(pubkey)
    }

    pub fn set_account(&mut self, pubkey: [u8; 32], account: ValidatorAccount) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        let is_update = self.validator_accounts.contains_key(&pubkey);
        if is_update {
            self.validator_accounts.insert(pubkey, account.clone());
            // Incremental: update only this validator's 8 leaves — O(8 · log n)
            let slot = self
                .validator_accounts
                .keys()
                .position(|k| k == &pubkey)
                .expect("key was just inserted");
            self.ssz_tree
                .update_validator_at_slot(slot, &pubkey, &account);
        } else {
            // Insert into BTreeMap first to determine positional slot
            self.validator_accounts.insert(pubkey, account.clone());
            let slot = self
                .validator_accounts
                .keys()
                .position(|k| k == &pubkey)
                .expect("key was just inserted");
            self.ssz_tree
                .insert_validator_at_slot(slot, &pubkey, &account);
        }

        #[cfg(feature = "prom")]
        histogram!("ssz_set_account_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn remove_account(&mut self, pubkey: &[u8; 32]) -> Option<ValidatorAccount> {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        // Find slot before removing from BTreeMap
        let slot = self.validator_accounts.keys().position(|k| k == pubkey);
        let removed = self.validator_accounts.remove(pubkey);
        if let (Some(slot), Some(_)) = (slot, &removed) {
            self.ssz_tree.remove_validator_at_slot(slot);
        }

        #[cfg(feature = "prom")]
        histogram!("ssz_remove_account_micros").record(start.elapsed().as_micros() as f64);

        removed
    }

    pub fn num_validators(&self) -> usize {
        self.validator_accounts.len()
    }

    pub fn validator_accounts_iter(&self) -> impl Iterator<Item = (&[u8; 32], &ValidatorAccount)> {
        self.validator_accounts.iter()
    }

    pub fn set_validator_accounts(&mut self, accounts: BTreeMap<[u8; 32], ValidatorAccount>) {
        self.validator_accounts = accounts;
        self.rebuild_ssz_tree();
    }

    /// Returns a reference to the live SSZ state tree.
    pub fn ssz_tree(&self) -> &SszStateTree {
        &self.ssz_tree
    }

    /// Snapshot the current tree root and freeze a proof-able copy.
    /// Called after `execute_block`, and again after epoch-boundary finalization
    /// mutations, so the captured value matches the root exposed to the next
    /// block as `parent_beacon_block_root`.
    ///
    /// `el_block_number` is the Reth block number from the execution payload
    /// that was just processed. The state root will appear on-chain in EL
    /// block `el_block_number + 1`.
    pub fn capture_state_root(&mut self, el_block_number: u64) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        // Refresh the dynamic-epoch-schedule leaf here: the epocher uses interior
        // mutability and can change (epoch advance, length update) without going
        // through a ConsensusState setter, so this commit point is the reliable
        // place to bind its current value into the root.
        self.ssz_tree
            .set_dynamic_epoch_schedule(&self.epocher.encode());

        self.state_root = self.ssz_tree.root();
        self.proof_tree = Arc::new(self.ssz_tree.clone());
        self.proof_validator_keys = Arc::new(self.validator_accounts.keys().copied().collect());
        self.proof_el_block_number = el_block_number;

        // Snapshot the entire state so a restart can rebuild `proof_tree`
        // from the capture-time data fields even after the live state has
        // been mutated (epoch transitions in particular). Clear the
        // snapshot's own `captured_bytes` first to prevent recursive nesting.
        let mut snapshot = self.clone();
        snapshot.captured_bytes = None;
        let bytes = commonware_codec::Encode::encode(&snapshot);
        self.captured_bytes = Some(bytes.to_vec());

        #[cfg(feature = "prom")]
        histogram!("ssz_capture_state_root_micros").record(start.elapsed().as_micros() as f64);
    }

    /// Returns the frozen tree snapshot for proof generation.
    /// Proofs from this tree verify against the on-chain `parent_beacon_block_root`.
    pub fn proof_tree(&self) -> &SszStateTree {
        self.proof_tree.as_ref()
    }

    /// Returns a shareable frozen proof tree snapshot.
    pub fn proof_tree_snapshot(&self) -> Arc<SszStateTree> {
        Arc::clone(&self.proof_tree)
    }

    /// Returns the frozen validator pubkeys (sorted) for proof generation.
    /// Needed for positional index lookups when generating validator proofs.
    pub fn proof_validator_keys(&self) -> &[[u8; 32]] {
        self.proof_validator_keys.as_slice()
    }

    /// Returns a shareable frozen validator-key snapshot for proof generation.
    pub fn proof_validator_keys_snapshot(&self) -> Arc<Vec<[u8; 32]>> {
        Arc::clone(&self.proof_validator_keys)
    }

    /// Returns the EL block number at the time the proof tree was captured.
    /// The state root appears on-chain in EL block `proof_el_block_number + 1`.
    pub fn get_proof_el_block_number(&self) -> u64 {
        self.proof_el_block_number
    }

    /// Returns the state root captured by `capture_state_root()`.
    pub fn get_state_root(&self) -> [u8; 32] {
        self.state_root
    }

    // Deposit queue operations
    /// Validate a deposit request at epoch end processing time.
    ///
    /// Signatures are verified first, and the cheap node signature check runs
    /// before the expensive BLS verify. Only after both signatures verify do we
    /// run the key checks: the consensus key must match an existing account, and
    /// it must not already belong to a different account (cross account BLS
    /// uniqueness, so the orchestrator's BiMap cannot collide). Every rejection
    /// is refunded through the taxed path (see refund_deposit), so consuming a
    /// slot of the per epoch processing cap always has a cost.
    ///
    /// There is no minimum or maximum balance check here. A below minimum deposit
    /// is kept (the account stays inactive with the credited balance), and there is
    /// no upper bound on stake. Crediting and activation happen in the caller after
    /// this returns Ok.
    pub fn verify_deposit_request(
        &self,
        deposit_request: &DepositRequest,
        deposit_signature_domain: Digest,
    ) -> Result<(), DepositRejectionReason> {
        let validator_pubkey: [u8; 32] = deposit_request.node_pubkey.as_ref().try_into().unwrap();
        let message = deposit_request.as_message(deposit_signature_domain);

        // Verify signatures first. The node signature is checked before the
        // consensus signature, so a deposit with both invalid reports
        // InvalidNodeSignature and the expensive BLS verify is skipped.
        let mut node_signature_bytes = &deposit_request.node_signature[..];
        let Ok(node_signature) = Signature::read(&mut node_signature_bytes) else {
            return Err(DepositRejectionReason::InvalidNodeSignature);
        };
        if !deposit_request
            .node_pubkey
            .verify(&[], &message, &node_signature)
        {
            return Err(DepositRejectionReason::InvalidNodeSignature);
        }

        let mut consensus_signature_bytes = &deposit_request.consensus_signature[..];
        let Ok(consensus_signature) = bls12381::Signature::read(&mut consensus_signature_bytes)
        else {
            return Err(DepositRejectionReason::InvalidConsensusSignature);
        };
        if !deposit_request
            .consensus_pubkey
            .verify(&[], &message, &consensus_signature)
        {
            return Err(DepositRejectionReason::InvalidConsensusSignature);
        }

        // Key checks run only after valid signatures. A top up must carry the
        // same BLS consensus key already on the account.
        if let Some(acc) = self.get_account(&validator_pubkey)
            && acc.consensus_public_key != deposit_request.consensus_pubkey
        {
            return Err(DepositRejectionReason::KeyMismatch);
        }

        // The consensus key must not already belong to a different validator.
        for (key, acc) in self.validator_accounts_iter() {
            if key != &validator_pubkey
                && acc.consensus_public_key == deposit_request.consensus_pubkey
            {
                return Err(DepositRejectionReason::KeyMismatch);
            }
        }

        Ok(())
    }

    /// Enqueue a refund for a deposit rejected before any balance was credited.
    ///
    /// The refund pays to the deposit's withdrawal address with a zero pubkey
    /// (refunds are not validator withdrawals, so they carry no validator key).
    /// Every rejected deposit is taxed: a fraction is sent to the treasury and
    /// the rest refunded, so invalid deposits cannot be a free DoS vector.
    pub fn refund_deposit(
        &mut self,
        withdrawal_credentials: [u8; 32],
        amount: u64,
        reason: DepositRejectionReason,
        withdrawal_num_epochs: u64,
    ) {
        let withdrawal_address = match parse_withdrawal_credentials(withdrawal_credentials) {
            Ok(address) => address,
            Err(e) => {
                // The deposit contract validates the credential format, so this
                // should not happen. The funds are lost if it does.
                error!(
                    target: "critical",
                    amount,
                    "failed to parse withdrawal credentials for deposit refund: {e}"
                );
                return;
            }
        };

        let withdrawal_epoch = self.get_epoch() + withdrawal_num_epochs;
        let (refund_amount, tax_amount) =
            invalid_deposit_refund_split(amount, self.get_invalid_deposit_tax());
        info!(
            ?reason,
            amount, refund_amount, tax_amount, "refunding rejected deposit"
        );

        if refund_amount > 0 {
            self.push_refund_withdrawal_request(
                WithdrawalRequest {
                    source_address: withdrawal_address,
                    validator_pubkey: [0u8; 32],
                    amount: refund_amount,
                },
                withdrawal_epoch,
            );
        }
        if tax_amount > 0 {
            let treasury_address = self.get_treasury_address();
            self.push_refund_withdrawal_request(
                WithdrawalRequest {
                    source_address: treasury_address,
                    validator_pubkey: [0u8; 32],
                    amount: tax_amount,
                },
                withdrawal_epoch,
            );
        }
    }

    pub fn push_deposit(&mut self, request: DepositRequest) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.ssz_tree.push_deposit(&request);
        self.deposit_queue.push_back(request);

        #[cfg(feature = "prom")]
        histogram!("ssz_push_deposit_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn get_deposit(&self, index: usize) -> Option<&DepositRequest> {
        self.deposit_queue.get(index)
    }

    pub fn deposit_count(&self) -> usize {
        self.deposit_queue.len()
    }

    pub fn pop_deposit(&mut self) -> Option<DepositRequest> {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        let request = self.deposit_queue.pop_front()?;
        self.ssz_tree.pop_deposit(&self.deposit_queue);

        #[cfg(feature = "prom")]
        histogram!("ssz_pop_deposit_micros").record(start.elapsed().as_micros() as f64);

        Some(request)
    }

    /// pops the front deposit without touching the ssz tree.
    ///
    /// front removal shifts every remaining item, so ssz_tree.pop_deposit
    /// rebuilds the whole deposit subtree. when draining up to the per epoch
    /// cap that is one full rebuild per pop, which is o(cap * backlog). callers
    /// that drain a capped batch should pop through here and call
    /// rebuild_deposit_tree once after the loop instead. the deposit subtree
    /// root is stale until that flush, so this must only be used in a sequence
    /// that ends in rebuild_deposit_tree before the state root is read.
    pub fn pop_deposit_deferred(&mut self) -> Option<DepositRequest> {
        self.deposit_queue.pop_front()
    }

    /// rebuilds the deposit subtree from the current queue in a single pass.
    /// pairs with pop_deposit_deferred to collapse a capped drain into one
    /// rebuild.
    pub fn rebuild_deposit_tree(&mut self) {
        self.ssz_tree.rebuild_deposits(&self.deposit_queue);
    }

    /// Process queued deposits, draining up to the per epoch cap.
    ///
    /// For each deposit: verify it (a rejected deposit is refunded by reason and
    /// skipped); create the account if it does not exist; credit the balance; and
    /// if an inactive validator reaches the minimum stake, schedule its activation
    /// after the warm up. A below minimum deposit is kept (the account stays
    /// inactive with the credited balance). A validator that is mid full exit
    /// (SubmittedExitRequest) only has the balance credited, which folds into its
    /// pending exit payout; it is not re activated. The deposit subtree is rebuilt
    /// once after the batch.
    pub fn process_deposits(
        &mut self,
        deposit_signature_domain: Digest,
        warm_up_epochs: u64,
        withdrawal_num_epochs: u64,
    ) {
        let mut drained_any = false;
        for _ in 0..self.get_max_deposits_per_epoch() as usize {
            let Some(request) = self.pop_deposit_deferred() else {
                break;
            };
            drained_any = true;

            if let Err(reason) = self.verify_deposit_request(&request, deposit_signature_domain) {
                self.refund_deposit(
                    request.withdrawal_credentials,
                    request.amount,
                    reason,
                    withdrawal_num_epochs,
                );
                continue;
            }

            let node_pubkey_bytes: [u8; 32] = request.node_pubkey.as_ref().try_into().unwrap();

            let mut account = match self.get_account(&node_pubkey_bytes) {
                Some(account) => account.clone(),
                None => {
                    // The account may not exist yet (first deposit) or may have been
                    // removed by a completed exit. Create it from the deposit.
                    let Ok(withdrawal_credentials) =
                        parse_withdrawal_credentials(request.withdrawal_credentials)
                    else {
                        error!(
                            target: "critical",
                            "failed to parse withdrawal credentials for new validator deposit"
                        );
                        continue;
                    };
                    ValidatorAccount {
                        consensus_public_key: request.consensus_pubkey.clone(),
                        withdrawal_credentials,
                        balance: 0,
                        status: ValidatorStatus::Inactive,
                        joining_epoch: 0,
                        last_deposit_index: request.index,
                    }
                }
            };

            account.balance = account.balance.saturating_add(request.amount);
            account.last_deposit_index = request.index;

            // Behavior by status, now that the balance is credited:
            //   Inactive at or above the minimum stake: schedule activation after
            //     the warm up (the branch below).
            //   Inactive below the minimum stake: stays inactive, keeping the
            //     credited balance until a later deposit lifts it to the minimum.
            //   Active or Joining: a top up. Balance credited, status unchanged
            //     (an Active validator stays in the committee, a Joining one stays
            //     scheduled to activate).
            //   SubmittedExitRequest or FullPayoutPending: a full exit is in
            //     progress. Balance is credited only and folds into the pending
            //     exit payout; the validator is not re activated.
            if account.status == ValidatorStatus::Inactive
                && account.balance >= self.get_minimum_stake()
            {
                let activation_epoch = self.get_epoch() + warm_up_epochs;
                account.status = ValidatorStatus::Joining;
                account.joining_epoch = activation_epoch;
                let consensus_key = account.consensus_public_key.clone();
                let node_key = request.node_pubkey.clone();
                self.set_account(node_pubkey_bytes, account);
                self.add_validator(
                    activation_epoch,
                    AddedValidator {
                        node_key,
                        consensus_key,
                    },
                );
            } else {
                self.set_account(node_pubkey_bytes, account);
            }
        }

        if drained_any {
            self.rebuild_deposit_tree();
        }
    }

    /// Process the buffered execution requests for the epoch in a single pass.
    ///
    /// Takes and clears the raw request buffer, decodes each entry, and routes it:
    /// deposits go to the deposit queue, withdrawal requests are validated and
    /// enqueued, protocol param requests are batched, and a malformed deposit chunk
    /// is refunded. After routing, the batched protocol param changes are queued
    /// and the deposit queue is drained up to the per epoch cap. Withdrawal
    /// enqueues defer any needed subtree rebuild to a single batch rebuild after
    /// the routing loop.
    ///
    /// Requests that arrive after this runs (on the last block of the epoch) stay
    /// buffered and are processed in the next epoch, which is the last block
    /// deferral.
    pub fn process_buffered_requests(
        &mut self,
        deposit_signature_domain: Digest,
        warm_up_epochs: u64,
        withdrawal_num_epochs: u64,
    ) {
        let buffered = self.take_pending_execution_requests();
        let mut protocol_param_batch: Vec<ProtocolParam> = Vec::new();
        let mut withdrawal_tree_stale = false;

        for entry in &buffered {
            match ExecutionRequest::parse_eth_entry(entry.as_ref()) {
                Ok(parsed_requests) => {
                    for parsed in parsed_requests {
                        match parsed {
                            ParsedExecutionRequest::Valid(ExecutionRequest::Deposit(deposit)) => {
                                self.push_deposit(deposit);
                            }
                            ParsedExecutionRequest::Valid(ExecutionRequest::Withdrawal(
                                withdrawal,
                            )) => {
                                withdrawal_tree_stale |= self.apply_withdrawal_request_deferred(
                                    withdrawal,
                                    withdrawal_num_epochs,
                                );
                            }
                            ParsedExecutionRequest::Valid(ExecutionRequest::ProtocolParam(
                                param_request,
                            )) => match ProtocolParam::try_from(param_request) {
                                Ok(param) => protocol_param_batch.push(param),
                                Err(e) => warn!("failed to parse protocol param request: {e}"),
                            },
                            ParsedExecutionRequest::MalformedDeposit(chunk) => {
                                self.refund_deposit(
                                    chunk.withdrawal_credentials,
                                    chunk.amount,
                                    DepositRejectionReason::MalformedKey,
                                    withdrawal_num_epochs,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("failed to parse execution request entry: {e}");
                }
            }
        }

        // Withdrawal pushes that landed mid sequence (a refund was queued)
        // deferred their subtree sync; collapse them into one rebuild. Runs
        // before process_deposits so its refund pushes append onto an accurate
        // tree.
        if withdrawal_tree_stale {
            self.rebuild_withdrawal_tree();
        }

        // Queue the decoded protocol param changes in one subtree rebuild.
        if !protocol_param_batch.is_empty() {
            self.push_protocol_param_changes(protocol_param_batch);
        }

        // Drain the deposit queue (verify, credit, activate) up to the cap.
        self.process_deposits(
            deposit_signature_domain,
            warm_up_epochs,
            withdrawal_num_epochs,
        );
    }

    /// Enforce a pending minimum stake increase.
    ///
    /// Run at the penultimate block after the buffered requests are processed, so
    /// this epoch's voluntary exits are already staged in removed_validators. A
    /// pending MinimumStake change is applied only if enough validators are
    /// retained: the count of active validators at or above the new minimum,
    /// excluding those already exiting this epoch, must stay at or above the
    /// minimum validator count. If too few would remain, the change is rejected
    /// (dropped from the pending params so the old minimum persists) and nothing
    /// is removed. Otherwise every active or joining validator below the new
    /// minimum leaves the committee: active ones via removed_validators, joining
    /// ones by cancelling their activation. Removed validators keep their balance
    /// and can withdraw it later. No per removal guard is needed because the
    /// retention check already guarantees the floor.
    pub fn enforce_minimum_stake(&mut self) {
        // Only act when a new minimum stake is pending.
        let has_minimum_stake_change = self
            .protocol_param_changes
            .iter()
            .any(|p| matches!(p, ProtocolParam::MinimumStake(_)));
        if !has_minimum_stake_change {
            return;
        }

        let prospective_min = self.prospective_minimum_stake();
        let current_epoch = self.get_epoch();
        let already_removed: HashSet<[u8; 32]> = self
            .get_removed_validators()
            .iter()
            .filter_map(|pk| pk.as_ref().try_into().ok())
            .collect();

        // Retained validators: active, at or above the new minimum, and not already
        // exiting this epoch.
        let mut retained = 0u64;
        for (key, account) in self.validator_accounts_iter() {
            if account.status == ValidatorStatus::Active
                && account.balance >= prospective_min
                && !already_removed.contains(key)
            {
                retained += 1;
            }
        }

        if retained < self.prospective_minimum_validator_count() {
            // Too few validators would remain. Reject the minimum stake change so
            // the old minimum persists, and remove nobody.
            self.protocol_param_changes
                .retain(|p| !matches!(p, ProtocolParam::MinimumStake(_)));
            self.ssz_tree
                .rebuild_protocol_params(&self.protocol_param_changes);
            return;
        }

        // Viable: remove every active or joining validator below the new minimum.
        let candidates: Vec<([u8; 32], u64, ValidatorStatus)> = self
            .validator_accounts_iter()
            .filter_map(|(key, account)| {
                if account.balance >= prospective_min {
                    return None;
                }
                match account.status {
                    ValidatorStatus::Active | ValidatorStatus::Joining => {
                        Some((*key, account.joining_epoch, account.status.clone()))
                    }
                    _ => None,
                }
            })
            .collect();

        for (key, joining_epoch, status) in candidates {
            let Ok(public_key) = PublicKey::decode(&key[..]) else {
                continue;
            };
            if already_removed.contains(&key) {
                continue;
            }
            match status {
                ValidatorStatus::Joining if joining_epoch > current_epoch => {
                    self.remove_added_validator(joining_epoch, &public_key);
                    // Cancelling the pending activation returns the account to
                    // Inactive so it is not left stuck as Joining with no scheduled
                    // activation (it never re-activates on its own). This mirrors
                    // the joining-validator cancel path in apply_withdrawal_request.
                    if let Some(mut account) = self.get_account(&key).cloned() {
                        account.status = ValidatorStatus::Inactive;
                        self.set_account(key, account);
                    }
                }
                ValidatorStatus::Active => {
                    self.push_removed_validator(public_key);
                    self.increment_pending_active_validator_exits();
                }
                _ => {}
            }
        }
    }

    // Withdrawal queue operations
    pub fn push_withdrawal_request(&mut self, request: WithdrawalRequest, withdrawal_epoch: u64) {
        self.push_withdrawal_request_with_kind(
            request,
            withdrawal_epoch,
            WithdrawalKind::Validator,
            false,
        );
    }

    pub fn push_refund_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_epoch: u64,
    ) {
        self.push_withdrawal_request_with_kind(
            request,
            withdrawal_epoch,
            WithdrawalKind::DepositRefund,
            false,
        );
    }

    /// rebuilds the withdrawal subtree from the current queue in a single pass.
    /// pairs with the deferred push mode to collapse a batch of mid sequence
    /// pushes into one rebuild.
    pub fn rebuild_withdrawal_tree(&mut self) {
        self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);
    }

    /// Push an entry onto the withdrawal queue and sync the SSZ tree.
    ///
    /// With `defer_rebuild` set, a push that would need a full subtree rebuild
    /// skips it and returns true instead; the caller must run
    /// `rebuild_withdrawal_tree` once the batch is done. The tree is stale in
    /// between, so this must not escape a single processing pass.
    fn push_withdrawal_request_with_kind(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_epoch: u64,
        kind: WithdrawalKind,
        defer_rebuild: bool,
    ) -> bool {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.withdrawal_queue
            .push_request_with_kind(request, withdrawal_epoch, kind)
            .expect("withdrawal kind must match queue");
        // push_request_with_kind increments next_index — sync the scalar leaf.
        self.ssz_tree
            .set_next_withdrawal_index(self.withdrawal_queue.next_index());

        // The combined SSZ order is [validators ++ refunds]. A new validator entry
        // lands before the refunds, so it is an end-append only when no refunds are
        // queued; otherwise the combined sequence shifts and must be rebuilt. A
        // refund always appends at the very end.
        let mut rebuild_deferred = false;
        if kind == WithdrawalKind::Validator
            && self
                .withdrawal_queue
                .back(WithdrawalKind::DepositRefund)
                .is_some()
        {
            if defer_rebuild {
                rebuild_deferred = true;
            } else {
                self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);
            }
        } else {
            let item = self
                .withdrawal_queue
                .back(kind)
                .expect("entry was just pushed")
                .clone();
            self.ssz_tree.push_withdrawal(&item);
        }

        #[cfg(feature = "prom")]
        histogram!("ssz_push_withdrawal_request_micros").record(start.elapsed().as_micros() as f64);

        rebuild_deferred
    }

    pub fn push_withdrawal(&mut self, request: PendingWithdrawal) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.withdrawal_queue.push(request.clone());
        self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);

        #[cfg(feature = "prom")]
        histogram!("ssz_push_withdrawal_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn peek_withdrawal(&self, withdrawal_epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue.peek(withdrawal_epoch)
    }

    /// Apply an EIP 7002 withdrawal request against the validator set.
    ///
    /// Called at epoch end from the buffered request processing pass, once per
    /// decoded withdrawal request. It validates the request and enqueues a
    /// pending withdrawal. It never changes the balance. The balance is reduced
    /// only at payout, when the matching withdrawal lands in a finalized block,
    /// re clamped against the balance at that time.
    ///
    /// An amount of 0 is a full exit: the validator is removed from the committee
    /// at the end of the epoch and the full remaining balance is paid out at the
    /// scheduled epoch. A positive amount is a partial withdrawal, clamped so the
    /// remaining balance stays at or above the minimum stake (skipped if there is
    /// nothing above the minimum to withdraw). The enqueued entry stores 0 for a
    /// full exit and the clamped amount for a partial, so the payout can tell them
    /// apart.
    pub fn apply_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_num_epochs: u64,
    ) {
        if self.apply_withdrawal_request_deferred(request, withdrawal_num_epochs) {
            self.rebuild_withdrawal_tree();
        }
    }

    /// Deferred variant of `apply_withdrawal_request` for batch processing.
    /// Returns true when the enqueued entry landed mid sequence and the
    /// withdrawal subtree is stale; the caller must run
    /// `rebuild_withdrawal_tree` once after the batch.
    pub(crate) fn apply_withdrawal_request_deferred(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_num_epochs: u64,
    ) -> bool {
        let Some(mut account) = self.get_account(&request.validator_pubkey).cloned() else {
            // No such validator. Drop the request.
            return false;
        };

        let pubkey = request.validator_pubkey;
        let withdrawal_credentials = account.withdrawal_credentials;

        // The request is authorized only by the validator's own withdrawal address.
        if request.source_address != withdrawal_credentials {
            return false;
        }

        // A full exit is already in progress: an active exit still serving this
        // epoch, or a payout pending after it left the committee. Ignore further
        // requests.
        if matches!(
            account.status,
            ValidatorStatus::SubmittedExitRequest | ValidatorStatus::FullPayoutPending
        ) {
            return false;
        }

        let current_epoch = self.get_epoch();
        let withdrawal_epoch = current_epoch + withdrawal_num_epochs;

        // A joining validator that withdraws cancels its pending activation and is
        // then handled as inactive. It never entered the committee, so no
        // removed_validators delta is needed.
        if account.status == ValidatorStatus::Joining {
            if account.joining_epoch > current_epoch
                && let Ok(public_key) = PublicKey::decode(&pubkey[..])
            {
                self.remove_added_validator(account.joining_epoch, &public_key);
            }
            account.status = ValidatorStatus::Inactive;
            self.set_account(pubkey, account.clone());
        }

        // Enqueue a payout. The balance is not changed here. It is reduced at payout
        // and re clamped against the balance at that time. Returns whether the
        // subtree rebuild was deferred.
        let enqueue = |state: &mut Self, amount: u64| -> bool {
            state.push_withdrawal_request_with_kind(
                WithdrawalRequest {
                    source_address: withdrawal_credentials,
                    validator_pubkey: pubkey,
                    amount,
                },
                withdrawal_epoch,
                WithdrawalKind::Validator,
                true,
            )
        };

        match account.status {
            ValidatorStatus::Active => {
                if request.amount == 0 {
                    // Full exit. Respect the minimum validator count: skip if removing
                    // this validator would drop the active set below the floor.
                    if !self.can_accept_active_validator_exit() {
                        return false;
                    }
                    let Ok(public_key) = PublicKey::decode(&pubkey[..]) else {
                        return false;
                    };
                    self.push_removed_validator(public_key);
                    self.increment_pending_active_validator_exits();
                    // Still serving this epoch. The boundary moves it to
                    // FullPayoutPending when it leaves the committee.
                    account.status = ValidatorStatus::SubmittedExitRequest;
                    self.set_account(pubkey, account);
                    // Full exit marker: amount 0. The payout pays the live balance.
                    enqueue(self, 0)
                } else {
                    // Partial. Keep the remaining balance at or above the minimum. The
                    // enqueue gate only enforces that the result is positive.
                    let withdrawable = account.balance.saturating_sub(self.get_minimum_stake());
                    let amount = request.amount.min(withdrawable);
                    if amount == 0 {
                        return false;
                    }
                    enqueue(self, amount)
                }
            }
            ValidatorStatus::Inactive => {
                // Not in the committee, so there is no minimum floor and no committee
                // removal. The validator withdraws its retained balance.
                if request.amount == 0 {
                    // Full exit of the retained balance. FullPayoutPending stops
                    // further requests and keeps deposit processing from auto
                    // rejoining the validator while the payout is pending.
                    account.status = ValidatorStatus::FullPayoutPending;
                    self.set_account(pubkey, account);
                    enqueue(self, 0)
                } else {
                    let amount = request.amount.min(account.balance);
                    if amount == 0 {
                        return false;
                    }
                    enqueue(self, amount)
                }
            }
            // SubmittedExitRequest and FullPayoutPending are handled by the early
            // return above.
            _ => false,
        }
    }

    pub fn pop_withdrawal(&mut self, withdrawal_epoch: u64) -> Option<PendingWithdrawal> {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        let w = self.withdrawal_queue.pop(withdrawal_epoch)?;
        // Front removal shifts the flat subtree, so rebuild it. (The finalizer drains
        // a capped prefix per block; batching this into one rebuild is a follow-up.)
        self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);

        #[cfg(feature = "prom")]
        histogram!("ssz_pop_withdrawal_micros").record(start.elapsed().as_micros() as f64);

        Some(w)
    }

    pub fn get_withdrawal(&self, pubkey: &[u8; 32]) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue.get_withdrawal(pubkey)
    }

    /// Get all pending withdrawals for a specific epoch
    pub fn get_withdrawals_for_epoch(&self, epoch: u64) -> Vec<&PendingWithdrawal> {
        self.withdrawal_queue.get_for_epoch(epoch)
    }

    /// Payout amount for one due withdrawal against `balance`, the validator's
    /// available balance at this point in the sweep. Deposit refunds pay their
    /// fixed amount and ignore the balance. A validator full exit (marker amount
    /// 0) pays the entire balance. A partial pays up to its requested amount
    /// while keeping an active validator at or above the minimum stake.
    fn withdrawal_payout_amount(
        entry: &PendingWithdrawal,
        balance: u64,
        active: bool,
        min_stake: u64,
    ) -> u64 {
        match entry.kind {
            WithdrawalKind::DepositRefund => entry.inner.amount,
            WithdrawalKind::Validator => {
                if entry.inner.amount == 0 {
                    balance
                } else {
                    let floor = if active { min_stake } else { 0 };
                    entry.inner.amount.min(balance.saturating_sub(floor))
                }
            }
        }
    }

    /// Compute the EIP 4895 withdrawals to emit for the epoch, re clamping each
    /// against the live balance. Read only: used at block build and verify. The
    /// balance is debited later at apply_withdrawal_payouts. Validator exits take
    /// priority over deposit refunds under the single per epoch total cap.
    ///
    /// Multiple due withdrawals for the same validator are clamped sequentially
    /// via a transient running balance, so concurrent partials keep an active
    /// validator at or above the minimum stake. A partial that clamps to zero is
    /// dropped: it is not emitted here and is consumed at apply.
    ///
    /// Partials clamp against the prospective minimum stake, not the outgoing
    /// one. Payouts run on the terminal block, one block after
    /// enforce_minimum_stake retained the committee against a pending change
    /// and one block before the boundary applies it. Clamping against the old
    /// minimum would let a partial drain a retained validator below a pending
    /// raise, stranding it Active under the new minimum with no later
    /// re enforcement.
    pub fn emit_withdrawal_payouts(&self, epoch: u64) -> Vec<Withdrawal> {
        let min_stake = self.prospective_minimum_stake();
        let max_total = self.get_max_withdrawals_per_epoch() as usize;
        let mut running: HashMap<[u8; 32], u64> = HashMap::new();
        let mut payouts = Vec::new();
        for entry in self
            .withdrawal_queue
            .get_for_epoch_with_total_cap(epoch, max_total)
        {
            if entry.kind == WithdrawalKind::DepositRefund {
                // Refund of a rejected deposit: the money was never in an account.
                payouts.push(entry.inner);
                continue;
            }
            let Some(account) = self.get_account(&entry.pubkey) else {
                // Account is gone (already fully paid out). Nothing to pay.
                continue;
            };
            let balance = *running.entry(entry.pubkey).or_insert(account.balance);
            let active = account.status == ValidatorStatus::Active;
            let payout = Self::withdrawal_payout_amount(entry, balance, active, min_stake);
            running.insert(entry.pubkey, balance.saturating_sub(payout));
            if payout > 0 {
                let mut withdrawal = entry.inner;
                withdrawal.amount = payout;
                payouts.push(withdrawal);
            }
        }
        payouts
    }

    /// Apply the withdrawal payouts that a finalized block paid out. Mirrors
    /// emit_withdrawal_payouts against the live balance: debits each validator
    /// payout, removes drained accounts, and consumes every processed entry
    /// (including partials that clamp to zero). Refund payouts touch no balance.
    /// Run at commit, once the matching block has been finalized.
    ///
    /// `block_withdrawals` is the EIP 4895 withdrawal list carried by the block
    /// being committed. It must equal what this state would emit; the assert pins
    /// the debits to exactly what the execution layer paid out, so a payload that
    /// disagrees with the deterministic computation halts the node rather than
    /// silently diverging the consensus balance from the execution layer.
    /// Verification enforces the same equality before finalize, so this is
    /// defense in depth.
    pub fn apply_withdrawal_payouts(&mut self, epoch: u64, block_withdrawals: &[Withdrawal]) {
        assert_eq!(
            self.emit_withdrawal_payouts(epoch).as_slice(),
            block_withdrawals,
            "block withdrawals must match the payouts emitted from consensus state"
        );

        let min_stake = self.prospective_minimum_stake();
        let max_total = self.get_max_withdrawals_per_epoch() as usize;
        let indices: Vec<u64> = self
            .withdrawal_queue
            .get_for_epoch_with_total_cap(epoch, max_total)
            .iter()
            .map(|entry| entry.inner.index)
            .collect();

        let mut drained_any = false;
        for index in indices {
            // Pop straight from the queue without rebuilding the withdrawal subtree
            // per pop; the whole capped batch is rebuilt once below. This keeps the
            // consensus-critical commit at O(backlog) rather than O(cap · backlog)
            // (#362).
            let Some(entry) = self.withdrawal_queue.pop_by_index(epoch, index) else {
                continue;
            };
            drained_any = true;
            if entry.kind == WithdrawalKind::DepositRefund {
                continue;
            }
            let Some(mut account) = self.get_account(&entry.pubkey).cloned() else {
                continue;
            };
            let active = account.status == ValidatorStatus::Active;
            let payout = Self::withdrawal_payout_amount(&entry, account.balance, active, min_stake);
            account.balance = account.balance.saturating_sub(payout);
            if account.balance == 0 {
                self.remove_account(&entry.pubkey);
            } else {
                self.set_account(entry.pubkey, account);
            }
        }
        // Rebuild the withdrawal SSZ subtree once for the whole capped batch, instead
        // of once per popped entry (#362).
        if drained_any {
            self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);
        }
    }

    /// Get the number of pending withdrawals for a specific epoch
    pub fn get_withdrawal_count_for_epoch(&self, epoch: u64) -> usize {
        self.withdrawal_queue.count_for_epoch(epoch)
    }

    /// Apply the staged committee deltas at an epoch boundary, mutating account
    /// statuses for the upcoming epoch. Validators scheduled to be added become
    /// Active. Removed validators leave the committee: a voluntary full exit
    /// (staged as SubmittedExitRequest, whole balance committed to a pending
    /// payout) becomes FullPayoutPending and cannot rejoin, while any other
    /// removal (a stake-bound removal that keeps its balance) becomes Inactive
    /// and may rejoin via a later deposit.
    ///
    /// Returns whether `node_public_key` was among the removed validators, so the
    /// caller can coordinate its own shutdown. This method only mutates consensus
    /// state. Persisting the result and notifying the orchestrator stay with the
    /// caller.
    pub fn apply_committee_transition(&mut self, node_public_key: &PublicKey) -> bool {
        let next_epoch = self.get_epoch() + 1;

        // The per-epoch active-exit budget is consumed by the exits this transition
        // applies, so reset it here for the coming epoch. Done unconditionally (and
        // before the no-deltas early return) so it never depends on there being
        // removed validators to clear.
        self.reset_pending_active_validator_exits();

        if !self.has_added_validators(next_epoch) && self.get_removed_validators().is_empty() {
            return false;
        }

        // Activate the validators scheduled for the coming epoch.
        if let Some(added_validators) = self.get_added_validators(next_epoch).cloned() {
            for validator in &added_validators {
                let key_bytes: [u8; 32] = validator.node_key.as_ref().try_into().unwrap();
                let mut account = self
                    .get_account(&key_bytes)
                    .expect("only validators with accounts are added to the added_validators queue")
                    .clone();
                account.status = ValidatorStatus::Active;
                self.set_account(key_bytes, account);
            }
            info!(
                next_epoch,
                "activated validators scheduled for the next epoch"
            );
        }

        // Move removed validators out of the committee, routing by departure reason.
        let mut validator_exit = false;
        let removed_validators = self.get_removed_validators().clone();
        for key in &removed_validators {
            if key == node_public_key {
                validator_exit = true;
                warn!(
                    next_epoch,
                    "this node is being removed from the validator set"
                );
            }
            let key_bytes: [u8; 32] = key.as_ref().try_into().unwrap();
            if let Some(mut account) = self.get_account(&key_bytes).cloned() {
                account.status = match account.status {
                    ValidatorStatus::SubmittedExitRequest => ValidatorStatus::FullPayoutPending,
                    _ => ValidatorStatus::Inactive,
                };
                self.set_account(key_bytes, account);
            }
        }
        validator_exit
    }

    pub fn get_validator_keys(&self) -> Vec<(PublicKey, bls12381::PublicKey)> {
        let mut peers: Vec<(PublicKey, bls12381::PublicKey)> = self
            .validator_accounts
            .iter()
            .filter(|(_, acc)| !acc.status.is_out_of_committee())
            .map(|(v, acc)| {
                let mut key_bytes = &v[..];
                let node_public_key =
                    PublicKey::read(&mut key_bytes).expect("failed to parse public key");
                let consensus_public_key = acc.consensus_public_key.clone();
                (node_public_key, consensus_public_key)
            })
            .collect();
        peers.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        peers
    }

    pub fn get_active_validators(&self) -> Vec<(PublicKey, bls12381::PublicKey)> {
        let mut peers: Vec<(PublicKey, bls12381::PublicKey)> = self
            .validator_accounts
            .iter()
            .filter(|(_, acc)| acc.status == ValidatorStatus::Active)
            .map(|(v, acc)| {
                let mut key_bytes = &v[..];
                let node_public_key =
                    PublicKey::read(&mut key_bytes).expect("failed to parse public key");
                let consensus_public_key = acc.consensus_public_key.clone();
                (node_public_key, consensus_public_key)
            })
            .collect();
        peers.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        peers
    }

    pub fn get_current_epoch_validators(&self) -> Vec<(PublicKey, bls12381::PublicKey)> {
        let mut peers: Vec<(PublicKey, bls12381::PublicKey)> = self
            .validator_accounts
            .iter()
            .filter(|(_, acc)| acc.status.is_current_epoch_signer())
            .map(|(v, acc)| {
                let mut key_bytes = &v[..];
                let node_public_key =
                    PublicKey::read(&mut key_bytes).expect("failed to parse public key");
                let consensus_public_key = acc.consensus_public_key.clone();
                (node_public_key, consensus_public_key)
            })
            .collect();
        peers.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        peers
    }

    pub fn current_epoch_active_validator_count(&self) -> u64 {
        self.validator_accounts
            .values()
            .filter(|acc| {
                matches!(
                    acc.status,
                    ValidatorStatus::Active | ValidatorStatus::SubmittedExitRequest
                )
            })
            .count() as u64
    }

    pub fn can_accept_active_validator_exit(&self) -> bool {
        self.current_epoch_active_validator_count()
            .saturating_sub(self.pending_active_validator_exits.saturating_add(1))
            >= self.prospective_minimum_validator_count()
    }

    pub fn get_active_or_joining_validators(&self) -> Vec<(PublicKey, bls12381::PublicKey)> {
        let mut peers: Vec<(PublicKey, bls12381::PublicKey)> = self
            .validator_accounts
            .iter()
            .filter(|(_, acc)| {
                acc.status == ValidatorStatus::Active || acc.status == ValidatorStatus::Joining
            })
            .map(|(v, acc)| {
                let mut key_bytes = &v[..];
                let node_public_key =
                    PublicKey::read(&mut key_bytes).expect("failed to parse public key");
                let consensus_public_key = acc.consensus_public_key.clone();
                (node_public_key, consensus_public_key)
            })
            .collect();
        peers.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        peers
    }

    pub fn apply_protocol_parameter_changes(&mut self) -> Result<bool, Error> {
        let mut minimum_stake_changed = false;
        for param in self.protocol_param_changes.drain(0..) {
            match param {
                ProtocolParam::MinimumStake(min_stake) => {
                    self.validator_minimum_stake = min_stake;
                    self.ssz_tree.set_validator_minimum_stake(min_stake);
                    minimum_stake_changed = true;
                }
                ProtocolParam::EpochLength(length) => {
                    let new_length = NonZeroU64::new(length)
                        .expect("EpochLength must be nonzero (validated at parse time)");
                    self.epocher
                        .update_length(new_length)
                        .expect("failed to update epoch length");
                }
                ProtocolParam::AllowedTimestampFuture(ms) => {
                    self.allowed_timestamp_future_ms = ms;
                    self.ssz_tree.set_allowed_timestamp_future_ms(ms);
                }
                ProtocolParam::TreasuryAddress(address) => {
                    self.treasury_address = address;
                    self.ssz_tree.set_treasury_address(&address);
                }
                ProtocolParam::MaxDepositsPerEpoch(value) => {
                    self.max_deposits_per_epoch = value;
                    self.ssz_tree.set_max_deposits_per_epoch(value);
                }
                ProtocolParam::MaxWithdrawalsPerEpoch(value) => {
                    self.max_withdrawals_per_epoch = value;
                    self.ssz_tree.set_max_withdrawals_per_epoch(value);
                }
                ProtocolParam::ObserversPerValidator(value) => {
                    // Bounded by MAX_OBSERVERS_PER_VALIDATOR (256) at parse time.
                    let value =
                        u32::try_from(value).expect("observers_per_validator must fit in u32");
                    self.observers_per_validator = value;
                    self.ssz_tree.set_observers_per_validator(value);
                }
                ProtocolParam::MinimumValidatorCount(value) => {
                    self.minimum_validator_count = value;
                    self.ssz_tree.set_minimum_validator_count(value);
                }
                ProtocolParam::InvalidDepositTax(value) => {
                    if value > MAX_INVALID_DEPOSIT_TAX {
                        continue;
                    }
                    self.invalid_deposit_tax = value;
                    self.ssz_tree.set_invalid_deposit_tax(value);
                }
            }
        }
        // Protocol param changes have been consumed — update the (now empty) collection root
        self.ssz_tree
            .rebuild_protocol_params(&self.protocol_param_changes);
        Ok(minimum_stake_changed)
    }

    /// Rebuild the entire SSZ state tree from scratch.
    ///
    /// Called on deserialization and when bulk-replacing state (e.g. `set_validator_accounts`).
    pub fn rebuild_ssz_tree(&mut self) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.ssz_tree.rebuild(
            self.epoch,
            self.view,
            self.latest_height,
            &self.head_digest.0,
            &self.epoch_genesis_hash,
            self.validator_minimum_stake,
            self.allowed_timestamp_future_ms,
            self.withdrawal_queue.next_index(),
            &self.forkchoice.head_block_hash.0,
            &self.forkchoice.safe_block_hash.0,
            &self.forkchoice.finalized_block_hash.0,
            &self.validator_accounts,
            &self.deposit_queue,
            &self.withdrawal_queue,
            &self.protocol_param_changes,
            &self.added_validators,
            &self.removed_validators,
            &self.treasury_address,
            self.max_deposits_per_epoch,
            self.max_withdrawals_per_epoch,
            self.observers_per_validator,
            &self.pending_execution_requests,
            self.pending_checkpoint.as_ref().map(|cp| cp.digest.0),
            &self.epocher.encode(),
            self.minimum_validator_count,
            self.pending_active_validator_exits,
            self.invalid_deposit_tax,
        );

        // Capture root and freeze proof tree so get_state_root() / proof_tree() are valid
        // after deserialization or bulk reset. proof_validator_keys is frozen
        // alongside the proof_tree so positional validator proofs line up with the
        // committee the snapshot commits to. the decode with capture path overrides
        // these from the capture time snapshot afterwards, so this is only the
        // baseline for construction, bulk reset, and capture less restarts.
        self.state_root = self.ssz_tree.root();
        self.proof_tree = Arc::new(self.ssz_tree.clone());
        self.proof_validator_keys = Arc::new(self.validator_accounts.keys().copied().collect());

        #[cfg(feature = "prom")]
        histogram!("ssz_rebuild_tree_micros").record(start.elapsed().as_micros() as f64);
    }
}

impl EncodeSize for ConsensusState {
    fn encode_size(&self) -> usize {
        8 // epoch
        + 8 // view
        + 8 // latest_height
        + 4 // deposit_queue length
        + self.deposit_queue.iter().map(|req| req.encode_size()).sum::<usize>()
        + self.withdrawal_queue.encode_size()
        + 4 // protocol_param_changes length
        + self.protocol_param_changes.iter().map(|param| param.encode_size()).sum::<usize>()
        + 4 // validator_accounts length
        + self.validator_accounts.iter().map(|(key, account)| key.len() + account.encode_size()).sum::<usize>()
        + 1 // pending_checkpoint presence flag
        + self.pending_checkpoint.as_ref().map_or(0, |cp| cp.encode_size())
        + 4 // added_validators length
        + self.added_validators.values().map(|validators| 8 + 4 + validators.iter().map(|av| av.node_key.encode_size() + av.consensus_key.encode_size()).sum::<usize>()).sum::<usize>()
        + 4 // removed_validators length
        + self.removed_validators.iter().map(|pk| pk.encode_size()).sum::<usize>()
        + 4 // pending_execution_requests length
        + self.pending_execution_requests.iter().map(|req| 4 + req.len()).sum::<usize>()
        + 32 // forkchoice.head_block_hash
        + 32 // forkchoice.safe_block_hash
        + 32 // forkchoice.finalized_block_hash
        + 32 // epoch_genesis_hash
        + 32 // head_digest
        + 8 // validator_minimum_stake
        + 8 // allowed_timestamp_future_ms
        + 20 // treasury_address
        + 8 // proof_el_block_number
        + 1 // captured_bytes presence flag
        + self.captured_bytes.as_ref().map_or(0, |b| 4 + b.len())
        + 8 // max_deposits_per_epoch
        + 8 // max_withdrawals_per_epoch
        + 4 // observers_per_validator
        + 8 // minimum_validator_count
        + 8 // pending_active_validator_exits
        + 8 // invalid_deposit_tax
        + self.epocher.encode_size()
    }
}

impl Read for ConsensusState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let epoch = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        let view = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        let latest_height = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;

        let deposit_queue_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        // Never pre-size collections from the decoded length prefixes below:
        // they are attacker-controlled u32s, and `buf.remaining()` is a byte
        // count rather than an element count, so even a `min(buf.remaining())`
        // hint over-allocates by `size_of::<T>()` per slot before any element
        // is validated. Growing on push is safe — each loop reads from `buf`
        // and bails on the first `EndOfBuffer`, so only genuinely decoded
        // elements are ever allocated.
        let mut deposit_queue = VecDeque::new();
        for _ in 0..deposit_queue_len {
            deposit_queue.push_back(DepositRequest::read_cfg(buf, &())?);
        }

        let withdrawal_queue = WithdrawalQueue::read_cfg(buf, &())?;

        let protocol_param_changes_len =
            buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut protocol_param_changes = Vec::new();
        for _ in 0..protocol_param_changes_len {
            protocol_param_changes.push(crate::protocol_params::ProtocolParam::read_cfg(buf, &())?);
        }

        let validator_accounts_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut validator_accounts = BTreeMap::new();
        for _ in 0..validator_accounts_len {
            let mut key = [0u8; 32];
            buf.try_copy_to_slice(&mut key)
                .map_err(|_| Error::EndOfBuffer)?;
            let account = ValidatorAccount::read_cfg(buf, &())?;
            validator_accounts.insert(key, account);
        }

        // Read pending_checkpoint
        let has_pending_checkpoint = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)? != 0;
        let pending_checkpoint = if has_pending_checkpoint {
            Some(Checkpoint::read_cfg(buf, &())?)
        } else {
            None
        };

        // Read added_validators
        let added_validators_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut added_validators = BTreeMap::new();
        for _ in 0..added_validators_len {
            let key = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
            let validator_count = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
            let mut validators = Vec::new();
            for _ in 0..validator_count {
                let node_key = PublicKey::read_cfg(buf, &())?;
                let consensus_key = bls12381::PublicKey::read_cfg(buf, &())?;
                validators.push(AddedValidator {
                    node_key,
                    consensus_key,
                });
            }
            added_validators.insert(key, validators);
        }

        // Read removed_validators
        let removed_validators_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut removed_validators = Vec::new();
        for _ in 0..removed_validators_len {
            removed_validators.push(PublicKey::read_cfg(buf, &())?);
        }

        // Read pending_execution_requests
        let pending_execution_requests_len =
            buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut pending_execution_requests = Vec::new();
        for _ in 0..pending_execution_requests_len {
            let len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
            if len > buf.remaining() {
                return Err(Error::EndOfBuffer);
            }
            let mut bytes = vec![0u8; len];
            buf.try_copy_to_slice(&mut bytes)
                .map_err(|_| Error::EndOfBuffer)?;
            pending_execution_requests.push(alloy_primitives::Bytes::from(bytes));
        }

        // Read forkchoice
        let mut head_block_hash = [0u8; 32];
        buf.try_copy_to_slice(&mut head_block_hash)
            .map_err(|_| Error::EndOfBuffer)?;
        let mut safe_block_hash = [0u8; 32];
        buf.try_copy_to_slice(&mut safe_block_hash)
            .map_err(|_| Error::EndOfBuffer)?;
        let mut finalized_block_hash = [0u8; 32];
        buf.try_copy_to_slice(&mut finalized_block_hash)
            .map_err(|_| Error::EndOfBuffer)?;

        let forkchoice = ForkchoiceState {
            head_block_hash: head_block_hash.into(),
            safe_block_hash: safe_block_hash.into(),
            finalized_block_hash: finalized_block_hash.into(),
        };

        let mut epoch_genesis_hash = [0u8; 32];
        buf.try_copy_to_slice(&mut epoch_genesis_hash)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut head_digest_bytes = [0u8; 32];
        buf.try_copy_to_slice(&mut head_digest_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let head_digest = sha256::Digest(head_digest_bytes);

        let validator_minimum_stake = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        let allowed_timestamp_future_ms = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        // Enforce the same bound the runtime protocol-parameter path applies (see
        // ProtocolParam::validate). An out-of-range window here means a crafted or
        // tampered checkpoint/state artifact; reject it rather than boot under a
        // timestamp tolerance that genesis and live updates would refuse.
        if !(crate::protocol_params::MIN_ALLOWED_TIMESTAMP_FUTURE_MS
            ..=crate::protocol_params::MAX_ALLOWED_TIMESTAMP_FUTURE_MS)
            .contains(&allowed_timestamp_future_ms)
        {
            return Err(Error::Invalid(
                "ConsensusState",
                "allowed timestamp future out of bounds",
            ));
        }

        let mut treasury_address_bytes = [0u8; 20];
        buf.try_copy_to_slice(&mut treasury_address_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let treasury_address = Address::from(treasury_address_bytes);

        let max_deposits_per_epoch = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        // Same upper bound the runtime protocol-parameter path applies (see
        // ProtocolParam::validate). An oversized deposit cap from a crafted or
        // tampered artifact would let the penultimate-block selector admit more
        // deposits per epoch than genesis/live updates allow.
        if max_deposits_per_epoch > crate::protocol_params::MAX_MAX_DEPOSITS_PER_EPOCH {
            return Err(Error::Invalid(
                "ConsensusState",
                "max deposits per epoch out of bounds",
            ));
        }
        let max_withdrawals_per_epoch = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        // Enforce the same lower/upper bound the runtime protocol-parameter update
        // path applies (see ProtocolParam::read_cfg / try_from). Genesis and runtime
        // updates already range-check this, so an out-of-range value here means a
        // crafted checkpoint/state artifact or tampered blob. A zero cap would let
        // the epoch-final selector emit no withdrawals and roll every due exit/refund
        // forward indefinitely, so reject it at decode rather than trust it.
        if !(crate::protocol_params::MAX_WITHDRAWALS_PER_EPOCH_MIN
            ..=crate::protocol_params::MAX_WITHDRAWALS_PER_EPOCH_MAX)
            .contains(&max_withdrawals_per_epoch)
        {
            return Err(Error::Invalid(
                "ConsensusState",
                "max withdrawals per epoch out of bounds",
            ));
        }
        let observers_per_validator = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)?;
        // Same upper bound the runtime protocol-parameter path applies (see
        // ProtocolParam::validate). Caps the per-validator observer fan-out an
        // imported state can request.
        if observers_per_validator as u64 > crate::protocol_params::MAX_OBSERVERS_PER_VALIDATOR {
            return Err(Error::Invalid(
                "ConsensusState",
                "observers per validator out of bounds",
            ));
        }
        let minimum_validator_count = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        if minimum_validator_count == 0 {
            return Err(Error::Invalid(
                "ConsensusState",
                "minimum validator count out of bounds",
            ));
        }
        let pending_active_validator_exits = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        let current_epoch_active_validator_count = validator_accounts
            .values()
            .filter(|account| {
                matches!(
                    account.status,
                    ValidatorStatus::Active | ValidatorStatus::SubmittedExitRequest
                )
            })
            .count() as u64;
        if pending_active_validator_exits > current_epoch_active_validator_count {
            return Err(Error::Invalid(
                "ConsensusState",
                "pending active validator exits exceeds active validator count",
            ));
        }
        let invalid_deposit_tax = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        if invalid_deposit_tax > MAX_INVALID_DEPOSIT_TAX {
            return Err(Error::Invalid(
                "ConsensusState",
                "invalid deposit tax out of bounds",
            ));
        }

        let epocher = DynamicEpocher::read_cfg(buf, &())?;

        // Trailers added by the proof-snapshot persistence: the only
        // primitive that isn't derivable from the captured data, plus the
        // serialized capture-time snapshot itself.
        let proof_el_block_number = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        let has_captured = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)? != 0;
        let captured_bytes = if has_captured {
            let len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
            // Bound the allocation by the bytes actually available so a corrupt or
            // adversarial length prefix can't force a multi-gigabyte allocation.
            if len > buf.remaining() {
                return Err(Error::EndOfBuffer);
            }
            let mut bytes = vec![0u8; len];
            buf.try_copy_to_slice(&mut bytes)
                .map_err(|_| Error::EndOfBuffer)?;
            Some(bytes)
        } else {
            None
        };

        let mut state = Self {
            epoch,
            view,
            latest_height,
            head_digest,
            deposit_queue,
            withdrawal_queue,
            protocol_param_changes,
            validator_accounts,
            pending_checkpoint,
            added_validators,
            removed_validators,
            pending_execution_requests,
            forkchoice,
            epoch_genesis_hash,
            validator_minimum_stake,
            allowed_timestamp_future_ms,
            treasury_address,
            max_deposits_per_epoch,
            max_withdrawals_per_epoch,
            observers_per_validator,
            minimum_validator_count,
            pending_active_validator_exits,
            invalid_deposit_tax,
            epocher,
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            proof_validator_keys: Arc::new(Vec::new()),
            captured_bytes: captured_bytes.clone(),

            state_root: [0u8; 32],
            proof_el_block_number,
        };
        // Build the live tree from the post-mutation data fields. This sets
        // `state_root` and `proof_tree` from the *live* tree. We'll override
        // them below using the capture-time snapshot.
        state.rebuild_ssz_tree();

        if let Some(bytes) = captured_bytes {
            // Decode the capture-time snapshot. Its own `rebuild_ssz_tree`
            // runs as part of decode and produces the exact tree that
            // existed when `capture_state_root` ran. `state_root` and
            // `proof_validator_keys` are derived from it. Neither is
            // stored separately in the wire format.
            let inner = ConsensusState::decode(bytes.as_slice())?;
            state.proof_tree = inner.proof_tree.clone();
            state.state_root = state.proof_tree.root();
            state.proof_validator_keys =
                Arc::new(inner.validator_accounts.keys().copied().collect());
        }

        Ok(state)
    }
}

impl Write for ConsensusState {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.epoch);
        buf.put_u64(self.view);
        buf.put_u64(self.latest_height);

        buf.put_u32(self.deposit_queue.len() as u32);
        for request in &self.deposit_queue {
            request.write(buf);
        }

        self.withdrawal_queue.write(buf);

        buf.put_u32(self.protocol_param_changes.len() as u32);
        for param in &self.protocol_param_changes {
            param.write(buf);
        }

        buf.put_u32(self.validator_accounts.len() as u32);
        for (key, account) in &self.validator_accounts {
            buf.put_slice(key);
            account.write(buf);
        }

        // Write pending_checkpoint
        if let Some(checkpoint) = &self.pending_checkpoint {
            buf.put_u8(1); // has checkpoint
            checkpoint.write(buf);
        } else {
            buf.put_u8(0); // no checkpoint
        }

        // Write added_validators
        buf.put_u32(self.added_validators.len() as u32);
        for (key, validators) in &self.added_validators {
            buf.put_u64(*key);
            buf.put_u32(validators.len() as u32);
            for validator in validators {
                validator.node_key.write(buf);
                validator.consensus_key.write(buf);
            }
        }

        // Write removed_validators
        buf.put_u32(self.removed_validators.len() as u32);
        for validator in &self.removed_validators {
            validator.write(buf);
        }

        // Write pending_execution_requests
        buf.put_u32(self.pending_execution_requests.len() as u32);
        for request in &self.pending_execution_requests {
            buf.put_u32(request.len() as u32);
            buf.put_slice(request);
        }

        // Write forkchoice
        buf.put_slice(self.forkchoice.head_block_hash.as_slice());
        buf.put_slice(self.forkchoice.safe_block_hash.as_slice());
        buf.put_slice(self.forkchoice.finalized_block_hash.as_slice());

        // Write epoch_genesis_hash
        buf.put_slice(&self.epoch_genesis_hash);

        // Write head_digest
        buf.put_slice(&self.head_digest.0);

        // Write validator minimum stake
        buf.put_u64(self.validator_minimum_stake);
        buf.put_u64(self.allowed_timestamp_future_ms);

        // Write treasury_address
        buf.put_slice(self.treasury_address.as_slice());

        // Write max_deposits_per_epoch
        buf.put_u64(self.max_deposits_per_epoch);

        // Write max_withdrawals_per_epoch
        buf.put_u64(self.max_withdrawals_per_epoch);

        // Write observers_per_validator
        buf.put_u32(self.observers_per_validator);

        // Write minimum_validator_count
        buf.put_u64(self.minimum_validator_count);

        // Write pending_active_validator_exits
        buf.put_u64(self.pending_active_validator_exits);

        // Write invalid_deposit_tax
        buf.put_u64(self.invalid_deposit_tax);

        // Write epocher
        self.epocher.write(buf);

        // Write proof_el_block_number (not derivable from consensus data —
        // it's a parameter passed into `capture_state_root`).
        buf.put_u64(self.proof_el_block_number);

        // Write captured_bytes (serialized capture-time snapshot, used on
        // Read to rebuild `proof_tree` exactly). `state_root` and
        // `proof_validator_keys` are derived from the rebuilt tree on Read,
        // so they don't need separate persistence.
        match &self.captured_bytes {
            Some(bytes) => {
                buf.put_u8(1);
                buf.put_u32(bytes.len() as u32);
                buf.put_slice(bytes);
            }
            None => buf.put_u8(0),
        }
    }
}

impl TryFrom<Checkpoint> for ConsensusState {
    type Error = Error;

    fn try_from(checkpoint: Checkpoint) -> Result<Self, Self::Error> {
        Self::try_from(&checkpoint)
    }
}

#[cfg(test)]
mod tests;
