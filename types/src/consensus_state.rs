use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::checkpoint::Checkpoint;
use crate::dynamic_epocher::DynamicEpocher;
use crate::execution_request::{DepositRequest, WithdrawalRequest};
use crate::header::AddedValidator;
use crate::protocol_params::{DEFAULT_MINIMUM_VALIDATOR_COUNT, ProtocolParam};
use crate::ssz_state_tree::SszStateTree;
use crate::withdrawal::{PendingWithdrawal, WithdrawalQueue};
use crate::{Digest, PublicKey};
use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{bls12381, sha256};
#[cfg(feature = "prom")]
use metrics::histogram;
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;

const INVALID_STAKE_INTERVAL: &str =
    "validator_minimum_stake must be less than or equal to validator_maximum_stake";

fn validate_stake_interval(minimum_stake: u64, maximum_stake: u64) -> Result<(), Error> {
    if minimum_stake <= maximum_stake {
        Ok(())
    } else {
        Err(Error::Invalid("ConsensusState", INVALID_STAKE_INTERVAL))
    }
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
    pub(crate) validator_maximum_stake: u64, // in gwei
    pub(crate) allowed_timestamp_future_ms: u64,
    pub(crate) treasury_address: Address,
    pub(crate) max_deposits_per_epoch: u64,
    pub(crate) max_withdrawals_per_epoch: u64,
    pub(crate) observers_per_validator: u32,
    pub(crate) minimum_validator_count: u64,
    pub(crate) pending_active_validator_exits: u64,
    pub(crate) epocher: DynamicEpocher,

    /// In-memory SSZ binary Merkle tree over the entire consensus state.
    /// Not serialized — rebuilt from data fields on deserialization.
    pub(crate) ssz_tree: SszStateTree,

    /// Frozen snapshot of `ssz_tree` at `capture_state_root()` time.
    /// Proofs are generated from this tree so they verify against the on-chain root.
    /// Not serialized — rebuilt alongside `ssz_tree`.
    pub(crate) proof_tree: SszStateTree,

    /// Frozen snapshot of validator pubkeys (sorted) at `capture_state_root()` time.
    /// Needed for positional index lookups when generating validator proofs.
    pub(crate) proof_validator_keys: Vec<[u8; 32]>,

    // Withdrawal proof lookup is handled by the pubkey index stored in SszStateTree itself.
    // The frozen proof_tree contains the withdrawal_pubkey_index from capture time.
    /// Snapshot of `ssz_tree.root()` captured after block execution.
    /// Not serialized — set via `capture_state_root()` in the finalizer after `execute_block`.
    /// Survives finalization mutations (which change the live tree but not this field).
    pub(crate) state_root: [u8; 32],

    /// The EL (Reth) block number at the time `capture_state_root()` was called.
    /// The state root appears on-chain in EL block `proof_el_block_number + 1`.
    pub(crate) proof_el_block_number: u64,
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
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
            allowed_timestamp_future_ms: 50,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: DEFAULT_MINIMUM_VALIDATOR_COUNT,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(1).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: SszStateTree::default(),
            proof_validator_keys: Vec::new(),

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
            validator_maximum_stake: self.validator_maximum_stake,
            allowed_timestamp_future_ms: self.allowed_timestamp_future_ms,
            treasury_address: self.treasury_address,
            max_deposits_per_epoch: self.max_deposits_per_epoch,
            max_withdrawals_per_epoch: self.max_withdrawals_per_epoch,
            observers_per_validator: self.observers_per_validator,
            minimum_validator_count: self.minimum_validator_count,
            pending_active_validator_exits: self.pending_active_validator_exits,
            epocher,
            ssz_tree: self.ssz_tree.clone(),
            proof_tree: self.proof_tree.clone(),
            proof_validator_keys: self.proof_validator_keys.clone(),
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
        validator_maximum_stake: u64,
        epoch_length: NonZeroU64,
        allowed_timestamp_future_ms: u64,
        treasury_address: Address,
        max_deposits_per_epoch: u64,
        max_withdrawals_per_epoch: u64,
        observers_per_validator: u32,
        minimum_validator_count: u64,
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
            validator_maximum_stake,
            allowed_timestamp_future_ms,
            treasury_address,
            max_deposits_per_epoch,
            max_withdrawals_per_epoch,
            observers_per_validator,
            minimum_validator_count,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(epoch_length),
            ssz_tree: SszStateTree::default(),
            proof_tree: SszStateTree::default(),
            proof_validator_keys: Vec::new(),

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

    pub fn get_maximum_stake(&self) -> u64 {
        self.validator_maximum_stake
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

    /// Returns the maximum stake that *will* apply after the queued protocol-parameter
    /// changes are drained at the next epoch boundary. If no `MaximumStake` change is
    /// queued, returns the currently-active value.
    pub fn prospective_maximum_stake(&self) -> u64 {
        self.protocol_param_changes
            .iter()
            .rev()
            .find_map(|p| match p {
                ProtocolParam::MaximumStake(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(self.validator_maximum_stake)
    }

    /// Whether a `MinimumStake` or `MaximumStake` change is queued for application at
    /// the next epoch boundary.
    pub fn has_pending_stake_bound_change(&self) -> bool {
        self.protocol_param_changes.iter().any(|p| {
            matches!(
                p,
                ProtocolParam::MinimumStake(_) | ProtocolParam::MaximumStake(_)
            )
        })
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

    pub fn set_maximum_stake(&mut self, stake: u64) {
        self.validator_maximum_stake = stake;
        self.ssz_tree.set_validator_maximum_stake(stake);
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

    pub fn get_head_digest_ref(&self) -> &Digest {
        &self.head_digest
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
        if let Some(validators) = self.added_validators.get_mut(&epoch)
            && let Some(pos) = validators.iter().position(|v| v.node_key == *pubkey)
        {
            validators.remove(pos);
            self.ssz_tree
                .rebuild_added_validators(&self.added_validators);
            return true;
        }
        false
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
            self.ssz_tree.update_validator_at_slot(slot, &account);
        } else {
            // Insert into BTreeMap first to determine positional slot
            self.validator_accounts.insert(pubkey, account.clone());
            let slot = self
                .validator_accounts
                .keys()
                .position(|k| k == &pubkey)
                .expect("key was just inserted");
            self.ssz_tree.insert_validator_at_slot(slot, &account);
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
    /// Called after `execute_block` so that subsequent finalization mutations
    /// don't alter the captured value or the proof tree.
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
        self.proof_tree = self.ssz_tree.clone();
        self.proof_validator_keys = self.validator_accounts.keys().copied().collect();
        self.proof_el_block_number = el_block_number;

        #[cfg(feature = "prom")]
        histogram!("ssz_capture_state_root_micros").record(start.elapsed().as_micros() as f64);
    }

    /// Returns the frozen tree snapshot for proof generation.
    /// Proofs from this tree verify against the on-chain `parent_beacon_block_root`.
    pub fn proof_tree(&self) -> &SszStateTree {
        &self.proof_tree
    }

    /// Returns the frozen validator pubkeys (sorted) for proof generation.
    /// Needed for positional index lookups when generating validator proofs.
    pub fn proof_validator_keys(&self) -> &[[u8; 32]] {
        &self.proof_validator_keys
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
    pub fn push_deposit(&mut self, request: DepositRequest) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.ssz_tree.push_deposit(&request);
        self.deposit_queue.push_back(request);

        #[cfg(feature = "prom")]
        histogram!("ssz_push_deposit_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn peek_deposit(&self) -> Option<&DepositRequest> {
        self.deposit_queue.front()
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

    // Withdrawal queue operations
    pub fn push_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_epoch: u64,
        balance_deduction: u64,
    ) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        let pubkey = request.validator_pubkey;
        let is_merge = self.withdrawal_queue.get_withdrawal(&pubkey).is_some();
        self.withdrawal_queue
            .push_request(request, withdrawal_epoch, balance_deduction);
        // push_request() may increment next_index internally — sync the scalar leaf
        self.ssz_tree
            .set_next_withdrawal_index(self.withdrawal_queue.next_index());
        if is_merge {
            // Fields updated in place — just refresh the existing item's leaves
            self.ssz_tree
                .update_withdrawal(self.withdrawal_queue.get_withdrawal(&pubkey).unwrap());
        } else {
            // New item appended to the epoch
            self.ssz_tree
                .push_withdrawal(self.withdrawal_queue.get_withdrawal(&pubkey).unwrap());
        }

        #[cfg(feature = "prom")]
        histogram!("ssz_push_withdrawal_request_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn push_withdrawal(&mut self, request: PendingWithdrawal) {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        self.withdrawal_queue.push(request.clone());
        self.ssz_tree.push_withdrawal(&request);

        #[cfg(feature = "prom")]
        histogram!("ssz_push_withdrawal_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn peek_withdrawal(&self, withdrawal_epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue.peek(withdrawal_epoch)
    }

    pub fn pop_withdrawal(&mut self, withdrawal_epoch: u64) -> Option<PendingWithdrawal> {
        #[cfg(feature = "prom")]
        let start = std::time::Instant::now();

        let w = self.withdrawal_queue.pop(withdrawal_epoch)?;
        self.ssz_tree
            .pop_withdrawal(withdrawal_epoch, &w.pubkey, &self.withdrawal_queue);

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

    /// Get the number of pending withdrawals for a specific epoch
    pub fn get_withdrawal_count_for_epoch(&self, epoch: u64) -> usize {
        self.withdrawal_queue.count_for_epoch(epoch)
    }

    /// Move remaining withdrawals from one epoch to another.
    pub fn reschedule_withdrawal_epoch(&mut self, from_epoch: u64, to_epoch: u64) {
        self.withdrawal_queue.reschedule_epoch(from_epoch, to_epoch);
        self.ssz_tree.rebuild_withdrawals(&self.withdrawal_queue);
    }

    /// Get all epochs that have pending withdrawals
    pub fn get_epochs_with_withdrawals(&self) -> Vec<u64> {
        self.withdrawal_queue.epochs_with_withdrawals()
    }

    /// Get the pending withdrawal amount (balance_deduction) for a specific validator.
    pub fn get_pending_withdrawal_amount(&self, pubkey: &[u8; 32]) -> u64 {
        self.withdrawal_queue.balance_deduction_for(pubkey)
    }

    pub fn get_validator_keys(&self) -> Vec<(PublicKey, bls12381::PublicKey)> {
        let mut peers: Vec<(PublicKey, bls12381::PublicKey)> = self
            .validator_accounts
            .iter()
            .filter(|(_, acc)| !(acc.status == ValidatorStatus::Inactive))
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

    pub fn get_active_validators_as<BLS: Clone>(&self) -> Vec<(PublicKey, BLS)>
    where
        bls12381::PublicKey: Into<BLS>,
    {
        self.get_active_validators()
            .into_iter()
            .map(|(pk, bls_pk)| (pk, bls_pk.into()))
            .collect()
    }

    pub fn apply_protocol_parameter_changes(&mut self) -> Result<bool, Error> {
        let prospective_minimum_stake = self.prospective_minimum_stake();
        let prospective_maximum_stake = self.prospective_maximum_stake();
        if let Err(err) =
            validate_stake_interval(prospective_minimum_stake, prospective_maximum_stake)
        {
            self.protocol_param_changes.clear();
            self.ssz_tree
                .rebuild_protocol_params(&self.protocol_param_changes);
            return Err(err);
        }

        let mut min_or_max_stake_changed = false;
        for param in self.protocol_param_changes.drain(0..) {
            match param {
                ProtocolParam::MinimumStake(min_stake) => {
                    self.validator_minimum_stake = min_stake;
                    self.ssz_tree.set_validator_minimum_stake(min_stake);
                    min_or_max_stake_changed = true;
                }
                ProtocolParam::MaximumStake(max_stake) => {
                    self.validator_maximum_stake = max_stake;
                    self.ssz_tree.set_validator_maximum_stake(max_stake);
                    min_or_max_stake_changed = true;
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
            }
        }
        // Protocol param changes have been consumed — update the (now empty) collection root
        self.ssz_tree
            .rebuild_protocol_params(&self.protocol_param_changes);
        Ok(min_or_max_stake_changed)
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
            self.validator_maximum_stake,
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
        );

        // Capture root and freeze proof tree so get_state_root() / proof_tree() are valid
        // after deserialization or bulk reset.
        self.state_root = self.ssz_tree.root();
        self.proof_tree = self.ssz_tree.clone();

        #[cfg(feature = "prom")]
        histogram!("ssz_rebuild_tree_micros").record(start.elapsed().as_micros() as f64);
    }

    pub fn validator_is_joining(&self, node_pubkey: &PublicKey) -> bool {
        let validator_pubkey: [u8; 32] = node_pubkey.as_ref().try_into().unwrap();
        self.validator_accounts
            .get(&validator_pubkey)
            .map(|acc| acc.status == ValidatorStatus::Joining)
            .unwrap_or(false)
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
        + 8 // validator_maximum_stake
        + 8 // allowed_timestamp_future_ms
        + 20 // treasury_address
        + 8 // max_deposits_per_epoch
        + 8 // max_withdrawals_per_epoch
        + 4 // observers_per_validator
        + 8 // minimum_validator_count
        + 8 // pending_active_validator_exits
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
        let mut deposit_queue = VecDeque::with_capacity(deposit_queue_len.min(buf.remaining()));
        for _ in 0..deposit_queue_len {
            deposit_queue.push_back(DepositRequest::read_cfg(buf, &())?);
        }

        let withdrawal_queue = WithdrawalQueue::read_cfg(buf, &())?;

        let protocol_param_changes_len =
            buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut protocol_param_changes =
            Vec::with_capacity(protocol_param_changes_len.min(buf.remaining()));
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
            let mut validators = Vec::with_capacity(validator_count.min(buf.remaining()));
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
        let mut removed_validators =
            Vec::with_capacity(removed_validators_len.min(buf.remaining()));
        for _ in 0..removed_validators_len {
            removed_validators.push(PublicKey::read_cfg(buf, &())?);
        }

        // Read pending_execution_requests
        let pending_execution_requests_len =
            buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut pending_execution_requests =
            Vec::with_capacity(pending_execution_requests_len.min(buf.remaining()));
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
        let validator_maximum_stake = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        validate_stake_interval(validator_minimum_stake, validator_maximum_stake)?;
        let allowed_timestamp_future_ms = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;

        let mut treasury_address_bytes = [0u8; 20];
        buf.try_copy_to_slice(&mut treasury_address_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let treasury_address = Address::from(treasury_address_bytes);

        let max_deposits_per_epoch = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
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

        let epocher = DynamicEpocher::read_cfg(buf, &())?;

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
            validator_maximum_stake,
            allowed_timestamp_future_ms,
            treasury_address,
            max_deposits_per_epoch,
            max_withdrawals_per_epoch,
            observers_per_validator,
            minimum_validator_count,
            pending_active_validator_exits,
            epocher,
            ssz_tree: SszStateTree::default(),
            proof_tree: SszStateTree::default(),
            proof_validator_keys: Vec::new(),

            state_root: [0u8; 32],
            proof_el_block_number: 0,
        };
        state.rebuild_ssz_tree();
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

        // Write validator stake bounds
        buf.put_u64(self.validator_minimum_stake);
        buf.put_u64(self.validator_maximum_stake);
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

        // Write epocher
        self.epocher.write(buf);
    }
}

impl TryFrom<Checkpoint> for ConsensusState {
    type Error = Error;

    fn try_from(checkpoint: Checkpoint) -> Result<Self, Self::Error> {
        Self::try_from(&checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKey;
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::execution_request::DepositRequest;
    use crate::ssz_state_tree;
    use crate::withdrawal::PendingWithdrawal;

    use alloy_eips::eip4895::Withdrawal;
    use alloy_primitives::Address;
    use commonware_codec::{DecodeExt, Encode, ReadExt};
    use commonware_consensus::types::{Epoch, Epocher, Height};
    use commonware_cryptography::{Signer, bls12381, ed25519};

    #[test]
    fn test_read_truncated_input_returns_err() {
        // Empty buffer — must not panic.
        let empty: &[u8] = &[];
        assert!(matches!(
            ConsensusState::read(&mut empty.as_ref()),
            Err(Error::EndOfBuffer)
        ));

        // Arbitrary short prefixes: each must return EndOfBuffer (not panic).
        for n in 0..64 {
            let data = vec![0xABu8; n];
            let res = ConsensusState::read(&mut data.as_ref());
            assert!(
                res.is_err(),
                "{n}-byte prefix should not successfully decode",
            );
        }
    }

    fn create_test_deposit_request(index: u64, amount: u64) -> DepositRequest {
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01; // Eth1 withdrawal prefix
        for i in 0..20 {
            withdrawal_credentials[12 + i] = index as u8;
        }

        let consensus_key = bls12381::PrivateKey::from_seed(index);
        DepositRequest {
            node_pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            consensus_pubkey: consensus_key.public_key(),
            withdrawal_credentials,
            amount,
            node_signature: [index as u8; 64],
            consensus_signature: [index as u8; 96],
            index,
        }
    }

    fn create_test_withdrawal(index: u64, amount: u64, epoch: u64) -> PendingWithdrawal {
        PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: index * 10,
                address: Address::from([index as u8; 20]),
                amount,
            },
            pubkey: [index as u8; 32],
            balance_deduction: amount,
            epoch,
        }
    }

    fn create_test_validator_account(index: u64, balance: u64) -> ValidatorAccount {
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([index as u8; 20]),
            balance,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: index,
        }
    }

    #[test]
    fn test_serialization_deserialization_empty() {
        let original_state = ConsensusState::default();

        let mut encoded = original_state.encode();
        let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

        assert_eq!(decoded_state.epoch, original_state.epoch);
        assert_eq!(decoded_state.view, original_state.view);
        assert_eq!(decoded_state.latest_height, original_state.latest_height);
        assert_eq!(
            decoded_state.get_next_withdrawal_index(),
            original_state.get_next_withdrawal_index()
        );
        assert_eq!(
            decoded_state.deposit_queue.len(),
            original_state.deposit_queue.len()
        );
        assert_eq!(
            decoded_state.withdrawal_queue,
            original_state.withdrawal_queue
        );
        assert_eq!(
            decoded_state.validator_accounts.len(),
            original_state.validator_accounts.len()
        );
        assert_eq!(
            decoded_state.epoch_genesis_hash,
            original_state.epoch_genesis_hash
        );
        assert_eq!(
            decoded_state.get_minimum_validator_count(),
            DEFAULT_MINIMUM_VALIDATOR_COUNT
        );
        assert_eq!(decoded_state.get_pending_active_validator_exits(), 0);
    }

    #[test]
    fn active_exit_counter_preserves_minimum_validator_count() {
        let mut state = ConsensusState::default();
        state.set_minimum_validator_count(3);

        for i in 0..4 {
            state.set_account(
                [i as u8 + 1; 32],
                create_test_validator_account(i as u64 + 1, 32_000_000_000),
            );
        }

        assert!(state.can_accept_active_validator_exit());
        state.increment_pending_active_validator_exits();
        assert!(!state.can_accept_active_validator_exit());

        let mut exiting_account = state.get_account(&[1u8; 32]).unwrap().clone();
        exiting_account.status = ValidatorStatus::SubmittedExitRequest;
        state.set_account([1u8; 32], exiting_account);
        assert_eq!(state.current_epoch_active_validator_count(), 4);
        assert!(!state.can_accept_active_validator_exit());

        let refund = create_test_withdrawal(99, 1, 0);
        state.push_withdrawal(refund);
        assert_eq!(state.get_withdrawal_count_for_epoch(0), 1);
        assert!(!state.can_accept_active_validator_exit());

        state.reset_pending_active_validator_exits();
        assert!(state.can_accept_active_validator_exit());
    }

    #[test]
    fn exit_floor_honors_queued_minimum_validator_count_raise() {
        // Removals staged this epoch take effect next epoch, at the same boundary
        // a queued MinimumValidatorCount change applies — so the floor check must
        // use the prospective value, not the current one.
        let mut state = ConsensusState::default();
        state.set_minimum_validator_count(2);
        for i in 0..3u8 {
            state.set_account(
                [i + 1; 32],
                create_test_validator_account(i as u64 + 1, 32_000_000_000),
            );
        }

        // 3 active, floor 2: one exit is acceptable (3 - 1 >= 2).
        assert!(state.can_accept_active_validator_exit());

        // Queue a raise to floor 3. The prospective floor now governs: 3 - 1 = 2 < 3.
        state.push_protocol_param_change(ProtocolParam::MinimumValidatorCount(3));
        assert_eq!(state.prospective_minimum_validator_count(), 3);
        assert!(!state.can_accept_active_validator_exit());

        // A queued lowering is likewise honored before it is applied.
        state.protocol_param_changes.clear();
        state.push_protocol_param_change(ProtocolParam::MinimumValidatorCount(1));
        assert_eq!(state.prospective_minimum_validator_count(), 1);
        assert!(state.can_accept_active_validator_exit());
    }

    #[test]
    fn test_clone_preserves_epoch_schedule_snapshot() {
        let state = ConsensusState::new(
            ForkchoiceState::default(),
            0,
            0,
            NonZeroU64::new(10).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            0,
        );
        state.get_epocher().advance_epoch(Epoch::new(0));

        let cloned = state.clone();
        let cloned_epoch_two_bounds_before = (
            cloned.get_epocher().first(Epoch::new(2)),
            cloned.get_epocher().last(Epoch::new(2)),
        );

        state
            .get_epocher()
            .update_length(NonZeroU64::new(20).unwrap())
            .unwrap();
        state.get_epocher().advance_epoch(Epoch::new(2));

        assert_eq!(
            (
                cloned.get_epocher().first(Epoch::new(2)),
                cloned.get_epocher().last(Epoch::new(2)),
            ),
            cloned_epoch_two_bounds_before,
            "cloned consensus state must retain the epoch schedule captured at clone time",
        );
    }

    #[test]
    fn test_serialization_deserialization_populated() {
        let mut original_state = ConsensusState::new(
            ForkchoiceState::default(),
            0,
            0,
            NonZeroU64::new(100).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            DEFAULT_MINIMUM_VALIDATOR_COUNT,
        );

        original_state.set_epoch(7);
        original_state.get_epocher().advance_epoch(Epoch::new(0));
        original_state
            .get_epocher()
            .update_length(NonZeroU64::new(200).unwrap())
            .unwrap();
        original_state.get_epocher().advance_epoch(Epoch::new(7));
        original_state.set_view(123);
        original_state.set_latest_height(42);
        original_state.set_next_withdrawal_index(5);
        original_state.set_epoch_genesis_hash([42u8; 32]);

        let deposit1 = create_test_deposit_request(1, 32000000000);
        let deposit2 = create_test_deposit_request(2, 16000000000);
        original_state.push_deposit(deposit1);
        original_state.push_deposit(deposit2);

        let withdrawal1 = create_test_withdrawal(1, 16000000000, 10);
        let withdrawal2 = create_test_withdrawal(2, 24000000000, 11);
        original_state.push_withdrawal(withdrawal1);
        original_state.push_withdrawal(withdrawal2);

        // Add protocol param changes
        original_state.push_protocol_param_change(
            crate::protocol_params::ProtocolParam::MinimumStake(40_000_000_000),
        );
        original_state.push_protocol_param_change(
            crate::protocol_params::ProtocolParam::MaximumStake(80_000_000_000),
        );
        original_state
            .push_protocol_param_change(crate::protocol_params::ProtocolParam::EpochLength(500));

        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];
        let account1 = create_test_validator_account(1, 32000000000);
        let account2 = create_test_validator_account(2, 64000000000);
        original_state.set_account(pubkey1, account1);
        original_state.set_account(pubkey2, account2);

        // Add validators scheduled for future epochs
        let validator1 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(10).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
        };
        let validator2 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(20).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
        };
        let validator3 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(30).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(30).public_key(),
        };
        let validator4 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(40).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(40).public_key(),
        };

        // Schedule validators for epoch 9 (current epoch + 2)
        original_state.add_validator(9, validator1.clone());
        original_state.add_validator(9, validator2.clone());

        // Schedule validators for epoch 10
        original_state.add_validator(10, validator3.clone());

        // Schedule validators for epoch 11
        original_state.add_validator(11, validator4.clone());

        let mut encoded = original_state.encode();
        let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

        assert_eq!(decoded_state.epoch, original_state.epoch);
        assert_eq!(decoded_state.view, original_state.view);
        assert_eq!(decoded_state.latest_height, original_state.latest_height);
        assert_eq!(
            decoded_state.get_next_withdrawal_index(),
            original_state.get_next_withdrawal_index()
        );
        assert_eq!(
            decoded_state.epoch_genesis_hash,
            original_state.epoch_genesis_hash
        );

        assert_eq!(decoded_state.deposit_queue.len(), 2);
        assert_eq!(decoded_state.deposit_queue[0].amount, 32000000000);
        assert_eq!(decoded_state.deposit_queue[1].amount, 16000000000);

        // Check withdrawal_queue - should have 2 epochs with withdrawals
        assert_eq!(decoded_state.withdrawal_queue.num_epochs(), 2);

        // Check epoch 10 withdrawal
        let epoch10_withdrawals = decoded_state.get_withdrawals_for_epoch(10);
        assert_eq!(epoch10_withdrawals.len(), 1);
        assert_eq!(epoch10_withdrawals[0].inner.index, 1);
        assert_eq!(epoch10_withdrawals[0].inner.amount, 16000000000);

        // Check epoch 11 withdrawal
        let epoch11_withdrawals = decoded_state.get_withdrawals_for_epoch(11);
        assert_eq!(epoch11_withdrawals.len(), 1);
        assert_eq!(epoch11_withdrawals[0].inner.index, 2);
        assert_eq!(epoch11_withdrawals[0].inner.amount, 24000000000);

        // Verify protocol_param_changes
        assert_eq!(decoded_state.protocol_param_changes.len(), 3);
        match &decoded_state.protocol_param_changes[0] {
            crate::protocol_params::ProtocolParam::MinimumStake(value) => {
                assert_eq!(*value, 40_000_000_000)
            }
            _ => panic!("Expected MinimumStake variant"),
        }
        match &decoded_state.protocol_param_changes[1] {
            crate::protocol_params::ProtocolParam::MaximumStake(value) => {
                assert_eq!(*value, 80_000_000_000)
            }
            _ => panic!("Expected MaximumStake variant"),
        }
        match &decoded_state.protocol_param_changes[2] {
            crate::protocol_params::ProtocolParam::EpochLength(value) => {
                assert_eq!(*value, 500)
            }
            _ => panic!("Expected EpochLength variant"),
        }

        assert_eq!(decoded_state.validator_accounts.len(), 2);
        let decoded_account1 = decoded_state.validator_accounts.get(&pubkey1).unwrap();
        assert_eq!(decoded_account1.balance, 32000000000);
        assert_eq!(decoded_account1.last_deposit_index, 1);
        let decoded_account2 = decoded_state.validator_accounts.get(&pubkey2).unwrap();
        assert_eq!(decoded_account2.balance, 64000000000);
        assert_eq!(decoded_account2.last_deposit_index, 2);

        // Verify added_validators
        assert_eq!(decoded_state.added_validators.len(), 3);

        // Check epoch 9 has 2 validators
        let epoch9_validators = decoded_state.get_added_validators(9).unwrap();
        assert_eq!(epoch9_validators.len(), 2);

        // Check epoch 10 has 1 validator
        let epoch10_validators = decoded_state.get_added_validators(10).unwrap();
        assert_eq!(epoch10_validators.len(), 1);

        // Check epoch 11 has 1 validator
        let epoch11_validators = decoded_state.get_added_validators(11).unwrap();
        assert_eq!(epoch11_validators.len(), 1);

        // Check that epoch 8 returns None (no validators scheduled)
        assert!(decoded_state.get_added_validators(8).is_none());

        // Verify epocher round-trips correctly
        let epocher = decoded_state.get_epocher();
        assert_eq!(epocher.current_length(), 200);
        // Epoch 0-1: length 100, epoch 2+: length 200
        assert_eq!(epocher.first(Epoch::new(0)), Some(Height::new(0)));
        assert_eq!(epocher.last(Epoch::new(1)), Some(Height::new(199)));
        assert_eq!(epocher.first(Epoch::new(2)), Some(Height::new(200)));
        assert_eq!(epocher.last(Epoch::new(2)), Some(Height::new(399)));
    }

    #[test]
    fn test_encode_size_accuracy() {
        let mut state = ConsensusState::default();

        state.set_epoch(3);
        state.set_view(456);
        state.set_latest_height(42);
        state.set_next_withdrawal_index(5);

        let deposit = create_test_deposit_request(1, 32000000000);
        state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000, 5);
        state.push_withdrawal(withdrawal);

        // Add protocol param changes
        state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
            50_000_000_000,
        ));
        state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MaximumStake(
            100_000_000_000,
        ));

        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32000000000);
        state.set_account(pubkey, account);

        // Add validators scheduled for future epochs
        let validator1 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(10).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
        };
        let validator2 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(20).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
        };
        let validator3 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(30).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(30).public_key(),
        };

        state.add_validator(5, validator1.clone());
        state.add_validator(6, validator2.clone());
        state.add_validator(6, validator3.clone());

        let predicted_size = state.encode_size();
        let actual_encoded = state.encode();
        let actual_size = actual_encoded.len();

        assert_eq!(predicted_size, actual_size);
    }

    #[test]
    fn pending_execution_requests_bind_into_captured_state_root() {
        let mut state = ConsensusState::default();
        state.rebuild_ssz_tree();
        state.capture_state_root(0);
        let before = state.get_state_root();

        // Buffering a deferred request via the production mutator must change the
        // captured state root (the mutator keeps the SSZ subtree in sync).
        state.push_pending_execution_request(alloy_primitives::Bytes::from(vec![0xAAu8; 40]));
        state.capture_state_root(0);
        let after = state.get_state_root();
        assert_ne!(
            before, after,
            "pushing a pending execution request must change the captured state root"
        );

        // Draining them restores the prior (empty-collection) root.
        let taken = state.take_pending_execution_requests();
        assert_eq!(taken.len(), 1);
        state.capture_state_root(0);
        assert_eq!(
            state.get_state_root(),
            before,
            "draining pending requests must restore the prior state root"
        );
    }

    #[test]
    fn pending_checkpoint_binds_into_captured_state_root() {
        let mut state = ConsensusState::default();
        state.rebuild_ssz_tree();
        state.capture_state_root(0);
        let before = state.get_state_root();

        // Setting the pending checkpoint via the production mutator binds its digest
        // into the captured state root.
        let checkpoint = Checkpoint::new(&state);
        state.set_pending_checkpoint(Some(checkpoint));
        state.capture_state_root(0);
        let after = state.get_state_root();
        assert_ne!(
            before, after,
            "setting a pending checkpoint must change the captured state root"
        );

        // Taking it restores the prior (no-checkpoint) root.
        let taken = state.take_pending_checkpoint();
        assert!(taken.is_some());
        state.capture_state_root(0);
        assert_eq!(
            state.get_state_root(),
            before,
            "taking the pending checkpoint must restore the prior state root"
        );
    }

    #[test]
    fn dynamic_epoch_schedule_binds_into_captured_state_root() {
        use std::num::NonZeroU64;

        let mut state = ConsensusState::default();
        state.rebuild_ssz_tree();
        state.capture_state_root(0);
        let before = state.get_state_root();

        // Mutate the epoch schedule through interior mutability — no `&mut
        // ConsensusState` setter is involved — and confirm the captured root still
        // changes, via the refresh in `capture_state_root`.
        state
            .get_epocher()
            .update_length(NonZeroU64::new(20).unwrap())
            .expect("update_length should succeed");
        state.capture_state_root(0);

        assert_ne!(
            before,
            state.get_state_root(),
            "an epoch-schedule change must change the captured state root"
        );
    }

    #[test]
    fn test_protocol_param_changes_serialization() {
        let mut state = ConsensusState::default();

        // Add various protocol param changes
        state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
            32_000_000_000,
        ));
        state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MaximumStake(
            64_000_000_000,
        ));
        state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
            40_000_000_000,
        ));

        let mut encoded = state.encode();
        let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

        assert_eq!(
            decoded_state.protocol_param_changes.len(),
            state.protocol_param_changes.len()
        );
        assert_eq!(decoded_state.protocol_param_changes.len(), 3);

        match &decoded_state.protocol_param_changes[0] {
            crate::protocol_params::ProtocolParam::MinimumStake(value) => {
                assert_eq!(*value, 32_000_000_000)
            }
            _ => panic!("Expected MinimumStake variant"),
        }

        match &decoded_state.protocol_param_changes[1] {
            crate::protocol_params::ProtocolParam::MaximumStake(value) => {
                assert_eq!(*value, 64_000_000_000)
            }
            _ => panic!("Expected MaximumStake variant"),
        }

        match &decoded_state.protocol_param_changes[2] {
            crate::protocol_params::ProtocolParam::MinimumStake(value) => {
                assert_eq!(*value, 40_000_000_000)
            }
            _ => panic!("Expected MinimumStake variant"),
        }

        // Verify encode_size is correct
        let predicted_size = state.encode_size();
        let actual_size = state.encode().len();
        assert_eq!(predicted_size, actual_size);
    }

    #[test]
    fn test_decode_rejects_out_of_range_max_withdrawals_per_epoch() {
        use crate::protocol_params::{
            MAX_WITHDRAWALS_PER_EPOCH_MAX, MAX_WITHDRAWALS_PER_EPOCH_MIN,
        };

        // Honest nodes only ever serialize a cap within [MIN, MAX] — genesis and
        // runtime updates both range-check it. A decoded state outside that range
        // can only come from a crafted checkpoint/state artifact or a tampered DB
        // blob. The finalizer trusts this cap as authoritative (a zero cap silently
        // drops every due withdrawal), so decoding must reject it rather than let
        // the node start/restore from it.

        // Valid boundary values must still decode.
        for valid in [MAX_WITHDRAWALS_PER_EPOCH_MIN, MAX_WITHDRAWALS_PER_EPOCH_MAX] {
            let mut state = ConsensusState::default();
            state.max_withdrawals_per_epoch = valid;
            let encoded = state.encode();
            let decoded = ConsensusState::read(&mut encoded.as_ref()).unwrap_or_else(|_| {
                panic!("valid max_withdrawals_per_epoch {valid} should decode")
            });
            assert_eq!(decoded.max_withdrawals_per_epoch, valid);
        }

        // Out-of-range values (0 below MIN, MAX+1 above MAX) must be rejected.
        for invalid in [0, MAX_WITHDRAWALS_PER_EPOCH_MAX + 1] {
            let mut state = ConsensusState::default();
            state.max_withdrawals_per_epoch = invalid;
            let encoded = state.encode();
            assert!(
                ConsensusState::read(&mut encoded.as_ref()).is_err(),
                "max_withdrawals_per_epoch {invalid} should be rejected on decode"
            );
        }
    }

    #[test]
    fn test_account_operations() {
        let mut state = ConsensusState::default();
        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32000000000);

        // Test that account doesn't exist initially
        assert!(state.get_account(&pubkey).is_none());

        // Test setting account
        state.set_account(pubkey, account.clone());
        let retrieved_account = state.get_account(&pubkey);
        assert!(retrieved_account.is_some());
        assert_eq!(retrieved_account.unwrap().balance, account.balance);

        // Test removing account
        let removed_account = state.remove_account(&pubkey);
        assert!(removed_account.is_some());
        assert_eq!(removed_account.unwrap().balance, account.balance);

        // Test that account no longer exists
        assert!(state.get_account(&pubkey).is_none());

        // Test removing non-existent account
        let non_existent = state.remove_account(&pubkey);
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_try_from_checkpoint() {
        // Create a populated ConsensusState
        let mut original_state = ConsensusState::default();
        original_state.set_epoch(5);
        original_state.set_view(789);
        original_state.set_latest_height(100);
        original_state.set_next_withdrawal_index(42);
        original_state.set_epoch_genesis_hash([99u8; 32]);

        // Add some data
        let deposit = create_test_deposit_request(1, 32000000000);
        original_state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000, 7);
        original_state.push_withdrawal(withdrawal);

        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32000000000);
        original_state.set_account(pubkey, account);

        // Convert to checkpoint
        let checkpoint = Checkpoint::new(&original_state);

        // Convert back to ConsensusState
        let restored_state: ConsensusState = checkpoint
            .try_into()
            .expect("Failed to convert checkpoint back to ConsensusState");

        // Verify the data matches
        assert_eq!(restored_state.epoch, original_state.epoch);
        assert_eq!(restored_state.view, original_state.view);
        assert_eq!(restored_state.latest_height, original_state.latest_height);
        assert_eq!(
            restored_state.get_next_withdrawal_index(),
            original_state.get_next_withdrawal_index()
        );
        assert_eq!(
            restored_state.epoch_genesis_hash,
            original_state.epoch_genesis_hash
        );
        assert_eq!(
            restored_state.deposit_queue.len(),
            original_state.deposit_queue.len()
        );
        assert_eq!(
            restored_state.withdrawal_queue,
            original_state.withdrawal_queue
        );
        assert_eq!(
            restored_state.validator_accounts.len(),
            original_state.validator_accounts.len()
        );

        // Check specific values
        assert_eq!(restored_state.deposit_queue[0].amount, 32000000000);
        let epoch7_withdrawals = restored_state.get_withdrawals_for_epoch(7);
        assert_eq!(epoch7_withdrawals[0].inner.amount, 16000000000);

        let restored_account = restored_state.get_account(&pubkey).unwrap();
        assert_eq!(restored_account.balance, 32000000000);
        assert_eq!(restored_account.last_deposit_index, 1);
    }

    // ---- SSZ state tree integration tests ----

    #[test]
    fn test_ssz_scalar_setters_update_root() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        state.set_epoch(10);
        assert_ne!(state.ssz_tree().root(), root_before);

        let r1 = state.ssz_tree().root();
        state.set_view(99);
        assert_ne!(state.ssz_tree().root(), r1);

        let r2 = state.ssz_tree().root();
        state.set_latest_height(500);
        assert_ne!(state.ssz_tree().root(), r2);

        let r3 = state.ssz_tree().root();
        state.set_head_digest(sha256::Digest([0xAB; 32]));
        assert_ne!(state.ssz_tree().root(), r3);

        let r4 = state.ssz_tree().root();
        state.set_epoch_genesis_hash([0xCD; 32]);
        assert_ne!(state.ssz_tree().root(), r4);

        let r5 = state.ssz_tree().root();
        state.set_minimum_stake(16_000_000_000);
        assert_ne!(state.ssz_tree().root(), r5);

        let r6 = state.ssz_tree().root();
        state.set_maximum_stake(64_000_000_000);
        assert_ne!(state.ssz_tree().root(), r6);

        let r7 = state.ssz_tree().root();
        state.set_next_withdrawal_index(42);
        assert_ne!(state.ssz_tree().root(), r7);
    }

    #[test]
    fn test_ssz_scalar_proof_verifies() {
        let mut state = ConsensusState::default();
        state.set_epoch(10);
        state.set_view(99);

        let tree = state.ssz_tree();
        let root = tree.root();
        let proof = tree.generate_scalar_proof(ssz_state_tree::EPOCH);
        assert!(proof.verify(&root));

        let proof_view = tree.generate_scalar_proof(ssz_state_tree::VIEW);
        assert!(proof_view.verify(&root));
    }

    #[test]
    fn test_ssz_forkchoice_updates() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        let fcs = ForkchoiceState {
            head_block_hash: [0x11; 32].into(),
            safe_block_hash: [0x22; 32].into(),
            finalized_block_hash: [0x33; 32].into(),
        };
        state.set_forkchoice(fcs);
        assert_ne!(state.ssz_tree().root(), root_before);

        let r1 = state.ssz_tree().root();

        // Partial setters
        state.set_forkchoice_head([0xAA; 32].into());
        assert_ne!(state.ssz_tree().root(), r1);

        let r2 = state.ssz_tree().root();
        state.set_forkchoice_safe_and_finalized([0xBB; 32].into());
        assert_ne!(state.ssz_tree().root(), r2);
    }

    #[test]
    fn test_ssz_validator_account_lifecycle() {
        let mut state = ConsensusState::default();
        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32_000_000_000);

        let root_before = state.ssz_tree().root();

        // Insert
        state.set_account(pubkey, account.clone());
        assert_ne!(state.ssz_tree().root(), root_before);

        // Verify proof
        let tree = state.ssz_tree();
        let root = tree.root();
        let keys = [pubkey];
        let proof = tree.generate_validator_proof(&pubkey, &keys).unwrap();
        assert!(proof.verify(&root));

        // Update balance
        let mut updated = account.clone();
        updated.balance = 48_000_000_000;
        state.set_account(pubkey, updated);
        assert_ne!(state.ssz_tree().root(), root);

        // Remove
        let root_with_account = state.ssz_tree().root();
        state.remove_account(&pubkey);
        assert_ne!(state.ssz_tree().root(), root_with_account);

        // Validator proof should return None for removed pubkey
        assert!(
            state
                .ssz_tree()
                .generate_validator_proof(&pubkey, &[])
                .is_none()
        );
    }

    #[test]
    fn test_ssz_deposit_queue_operations() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        let deposit = create_test_deposit_request(1, 32_000_000_000);
        state.push_deposit(deposit.clone());
        assert_ne!(state.ssz_tree().root(), root_before);

        let root_with_deposit = state.ssz_tree().root();

        // Pop deposit changes root
        let popped = state.pop_deposit().unwrap();
        assert_eq!(popped.amount, 32_000_000_000);
        assert_ne!(state.ssz_tree().root(), root_with_deposit);
    }

    #[test]
    fn test_ssz_withdrawal_queue_operations() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        let withdrawal = create_test_withdrawal(1, 16_000_000_000, 5);
        state.push_withdrawal(withdrawal);
        assert_ne!(state.ssz_tree().root(), root_before);

        let root_with_withdrawal = state.ssz_tree().root();

        // Pop withdrawal changes root
        let popped = state.pop_withdrawal(5).unwrap();
        assert_eq!(popped.inner.amount, 16_000_000_000);
        assert_ne!(state.ssz_tree().root(), root_with_withdrawal);
    }

    #[test]
    fn test_ssz_added_removed_validators() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        let validator = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(10).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
        };

        // add_validator changes root
        state.add_validator(5, validator.clone());
        assert_ne!(state.ssz_tree().root(), root_before);

        let root_with_added = state.ssz_tree().root();

        // remove_added_validators_for_epoch changes root
        state.remove_added_validators_for_epoch(5);
        assert_ne!(state.ssz_tree().root(), root_with_added);

        // push_removed_validator / clear_removed_validators
        let removed_pk = ed25519::PrivateKey::from_seed(20).public_key();
        let r1 = state.ssz_tree().root();
        state.push_removed_validator(removed_pk);
        assert_ne!(state.ssz_tree().root(), r1);

        let r2 = state.ssz_tree().root();
        state.clear_removed_validators();
        assert_ne!(state.ssz_tree().root(), r2);
    }

    #[test]
    fn test_ssz_protocol_param_changes() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();

        state.push_protocol_param_change(ProtocolParam::MinimumStake(40_000_000_000));
        assert_ne!(state.ssz_tree().root(), root_before);

        let r1 = state.ssz_tree().root();
        state.push_protocol_param_change(ProtocolParam::MaximumStake(80_000_000_000));
        assert_ne!(state.ssz_tree().root(), r1);

        // apply_protocol_parameter_changes consumes them
        let changed = state.apply_protocol_parameter_changes().unwrap();
        assert!(changed);
        assert_eq!(state.get_minimum_stake(), 40_000_000_000);
        assert_eq!(state.get_maximum_stake(), 80_000_000_000);
    }

    #[test]
    fn protocol_param_batch_accepts_valid_final_stake_interval() {
        let mut state = ConsensusState::default();
        state.push_protocol_param_change(ProtocolParam::MaximumStake(20_000_000_000));
        state.push_protocol_param_change(ProtocolParam::MinimumStake(10_000_000_000));

        let changed = state.apply_protocol_parameter_changes().unwrap();

        assert!(changed);
        assert_eq!(state.get_minimum_stake(), 10_000_000_000);
        assert_eq!(state.get_maximum_stake(), 20_000_000_000);
    }

    #[test]
    fn protocol_param_batch_rejects_inverted_final_stake_interval() {
        let mut state = ConsensusState::default();
        let root_before = state.ssz_tree().root();
        state.push_protocol_param_change(ProtocolParam::MinimumStake(80_000_000_000));

        let err = state.apply_protocol_parameter_changes().unwrap_err();

        assert!(matches!(err, Error::Invalid("ConsensusState", _)));
        assert_eq!(state.get_minimum_stake(), 32_000_000_000);
        assert_eq!(state.get_maximum_stake(), 32_000_000_000);
        assert_eq!(state.ssz_tree().root(), root_before);
        assert_eq!(state.protocol_param_changes.len(), 0);
    }

    #[test]
    fn consensus_state_decode_rejects_inverted_stake_interval() {
        let mut state = ConsensusState::default();
        state.validator_minimum_stake = 80_000_000_000;
        state.validator_maximum_stake = 32_000_000_000;

        let mut encoded = state.encode();
        let err = ConsensusState::decode(&mut encoded).unwrap_err();

        assert!(matches!(err, Error::Invalid("ConsensusState", _)));
    }

    #[test]
    fn test_ssz_rebuild_matches_incremental() {
        let mut state = ConsensusState::default();

        // Build up state incrementally through setters
        state.set_epoch(7);
        state.set_view(42);
        state.set_latest_height(100);
        state.set_head_digest(sha256::Digest([0xAB; 32]));
        state.set_epoch_genesis_hash([0xCD; 32]);
        state.set_minimum_stake(16_000_000_000);
        state.set_maximum_stake(64_000_000_000);
        state.set_next_withdrawal_index(5);
        state.set_forkchoice(ForkchoiceState {
            head_block_hash: [0x11; 32].into(),
            safe_block_hash: [0x22; 32].into(),
            finalized_block_hash: [0x33; 32].into(),
        });

        let pubkey = [1u8; 32];
        state.set_account(pubkey, create_test_validator_account(1, 32_000_000_000));

        let deposit = create_test_deposit_request(1, 32_000_000_000);
        state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16_000_000_000, 5);
        state.push_withdrawal(withdrawal);

        let incremental_root = state.ssz_tree().root();

        // Rebuild from scratch
        state.rebuild_ssz_tree();
        let rebuilt_root = state.ssz_tree().root();

        assert_eq!(incremental_root, rebuilt_root);
    }

    #[test]
    fn test_ssz_root_survives_serialization_roundtrip() {
        let mut state = ConsensusState::default();

        state.set_epoch(5);
        state.set_view(99);
        state.set_latest_height(200);
        state.set_next_withdrawal_index(10);
        state.set_epoch_genesis_hash([0xFF; 32]);
        state.set_forkchoice(ForkchoiceState {
            head_block_hash: [0xAA; 32].into(),
            safe_block_hash: [0xBB; 32].into(),
            finalized_block_hash: [0xCC; 32].into(),
        });

        let pubkey = [1u8; 32];
        state.set_account(pubkey, create_test_validator_account(1, 32_000_000_000));

        let deposit = create_test_deposit_request(1, 32_000_000_000);
        state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16_000_000_000, 7);
        state.push_withdrawal(withdrawal);

        let original_root = state.ssz_tree().root();

        // Round-trip through serialization
        let mut encoded = state.encode();
        let decoded = ConsensusState::decode(&mut encoded).unwrap();

        assert_eq!(decoded.ssz_tree().root(), original_root);
    }

    #[test]
    fn test_ssz_set_validator_accounts_rebuilds() {
        let mut state = ConsensusState::default();
        state.set_epoch(3);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        let root_before = state.ssz_tree().root();

        // Bulk replace validator accounts
        let mut new_accounts = BTreeMap::new();
        new_accounts.insert([2u8; 32], create_test_validator_account(2, 64_000_000_000));
        new_accounts.insert([3u8; 32], create_test_validator_account(3, 48_000_000_000));
        state.set_validator_accounts(new_accounts);

        assert_ne!(state.ssz_tree().root(), root_before);

        // New validators have proofs
        let tree = state.ssz_tree();
        let root = tree.root();
        let keys = [[2u8; 32], [3u8; 32]];
        let proof = tree.generate_validator_proof(&[2u8; 32], &keys).unwrap();
        assert!(proof.verify(&root));

        // Old validator is gone
        assert!(tree.generate_validator_proof(&[1u8; 32], &keys).is_none());
    }

    #[test]
    fn test_ssz_clone_independence() {
        let mut state = ConsensusState::default();
        state.set_epoch(5);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        let cloned = state.clone();
        let root_before = cloned.ssz_tree().root();

        // Mutate original
        state.set_epoch(99);
        state.set_account([2u8; 32], create_test_validator_account(2, 64_000_000_000));

        // Clone is unaffected
        assert_eq!(cloned.ssz_tree().root(), root_before);
    }

    #[test]
    fn test_ssz_capture_and_proof_tree() {
        let mut state = ConsensusState::default();
        state.set_epoch(5);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        // Capture state root
        state.capture_state_root(100);
        let captured_root = state.get_state_root();
        assert_eq!(captured_root, state.proof_tree().root());
        assert_eq!(state.get_proof_el_block_number(), 100);

        // Mutate the live tree
        state.set_epoch(99);
        assert_ne!(state.ssz_tree().root(), captured_root);

        // Proof tree is still frozen at the captured state
        assert_eq!(state.proof_tree().root(), captured_root);

        // Proof still verifies against captured root
        let proof = state
            .proof_tree()
            .generate_validator_proof(&[1u8; 32], state.proof_validator_keys())
            .unwrap();
        assert!(proof.verify(&captured_root));
    }

    #[test]
    fn test_ssz_push_withdrawal_request_keeps_next_index_in_sync() {
        use crate::execution_request::WithdrawalRequest;

        let mut state = ConsensusState::default();
        state.set_epoch(1);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        // push_withdrawal_request internally calls WithdrawalQueue::push_request
        // which increments next_index. The SSZ tree's NEXT_WITHDRAWAL_INDEX leaf
        // must stay in sync.
        let request = WithdrawalRequest {
            source_address: alloy_primitives::Address::from([0xAA; 20]),
            validator_pubkey: [1u8; 32],
            amount: 16_000_000_000,
        };
        state.push_withdrawal_request(request, 5, 16_000_000_000);

        let incremental_root = state.ssz_tree().root();

        // Rebuild must produce the same root
        state.rebuild_ssz_tree();
        let rebuilt_root = state.ssz_tree().root();

        assert_eq!(
            incremental_root, rebuilt_root,
            "push_withdrawal_request must keep NEXT_WITHDRAWAL_INDEX in sync with rebuild"
        );
    }

    /// Simulate the full block execution lifecycle and check that
    /// incremental SSZ tree matches rebuild at every step.
    #[test]
    fn test_ssz_full_block_lifecycle_matches_rebuild() {
        use crate::execution_request::WithdrawalRequest;
        use crate::header::AddedValidator;
        use crate::protocol_params::ProtocolParam;
        use commonware_cryptography::Signer;

        // Derive valid Ed25519 pubkeys from seeds
        let ed_keys: Vec<ed25519::PrivateKey> = (1..=5u64)
            .map(|i| ed25519::PrivateKey::from_seed(i))
            .collect();
        let pubkeys: Vec<[u8; 32]> = ed_keys
            .iter()
            .map(|k| k.public_key().as_ref().try_into().unwrap())
            .collect();

        // --- Genesis setup (mimics get_initial_state in args.rs) ---
        let forkchoice = ForkchoiceState {
            head_block_hash: [0xAA; 32].into(),
            safe_block_hash: [0xAA; 32].into(),
            finalized_block_hash: [0xAA; 32].into(),
        };
        let mut state = ConsensusState::new(
            forkchoice,
            32_000_000_000,
            32_000_000_000,
            NonZeroU64::new(10).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            DEFAULT_MINIMUM_VALIDATOR_COUNT,
        );

        // Add 4 genesis validators (like the testnet)
        for i in 0..4 {
            state.set_account(
                pubkeys[i],
                create_test_validator_account(i as u64 + 1, 32_000_000_000),
            );
        }

        // Check: after genesis setup, incremental matches rebuild
        let genesis_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            genesis_root,
            state.ssz_tree().root(),
            "genesis: incremental != rebuild"
        );

        // --- Simulate execute_block for height 1 ---
        state.set_forkchoice_head([0xBB; 32].into());
        state.set_latest_height(1);
        state.set_view(1);
        state.set_head_digest([0xCC; 32].into());
        state.capture_state_root(100);

        let block1_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            block1_root,
            state.ssz_tree().root(),
            "block 1: incremental != rebuild"
        );

        // --- Simulate finalization (forkchoice update after capture) ---
        state.set_forkchoice_safe_and_finalized([0xBB; 32].into());

        let post_finalization_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            post_finalization_root,
            state.ssz_tree().root(),
            "post-finalization: incremental != rebuild"
        );

        // --- Simulate execute_block for height 2 (with a deposit) ---
        state.set_forkchoice_head([0xDD; 32].into());

        // Push a deposit request
        let deposit = create_test_deposit_request(1, 32_000_000_000);
        state.push_deposit(deposit);

        state.set_latest_height(2);
        state.set_view(2);
        state.set_head_digest([0xEE; 32].into());
        state.capture_state_root(101);

        let block2_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            block2_root,
            state.ssz_tree().root(),
            "block 2: incremental != rebuild"
        );

        // --- Simulate execute_block for height 3 (pop deposit, push withdrawal) ---
        state.set_forkchoice_head([0xFF; 32].into());

        // Pop the deposit
        let _ = state.pop_deposit();

        // Process the deposit: create a new validator
        let new_pubkey = pubkeys[4];
        let mut new_account = create_test_validator_account(5, 32_000_000_000);
        new_account.status = ValidatorStatus::Joining;
        new_account.joining_epoch = 2;
        state.set_account(new_pubkey, new_account);

        // Add to added_validators
        let node_key = ed_keys[4].public_key();
        let consensus_key = bls12381::PrivateKey::from_seed(5).public_key();
        state.add_validator(
            2,
            AddedValidator {
                node_key,
                consensus_key,
            },
        );

        state.set_latest_height(3);
        state.set_view(3);
        state.set_head_digest([0x11; 32].into());
        state.capture_state_root(102);

        let block3_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            block3_root,
            state.ssz_tree().root(),
            "block 3: incremental != rebuild"
        );

        // --- Simulate epoch transition ---
        // Apply protocol param changes (none in this case)
        state.apply_protocol_parameter_changes().unwrap();

        // Activate the joining validator
        let mut account = state.get_account(&new_pubkey).unwrap().clone();
        account.status = ValidatorStatus::Active;
        state.set_account(new_pubkey, account);

        // Clear added/removed validators
        state.remove_added_validators_for_epoch(2);
        state.clear_removed_validators();

        // Increment epoch
        state.set_epoch(2);
        state.set_epoch_genesis_hash([0x22; 32]);

        let epoch_transition_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            epoch_transition_root,
            state.ssz_tree().root(),
            "epoch transition: incremental != rebuild"
        );

        // --- Simulate withdrawal request ---
        let wr = WithdrawalRequest {
            source_address: alloy_primitives::Address::from([0xAA; 20]),
            validator_pubkey: pubkeys[0],
            amount: 32_000_000_000,
        };
        state.push_withdrawal_request(wr, 4, 32_000_000_000);

        // Mark validator as exiting
        let mut account = state.get_account(&pubkeys[0]).unwrap().clone();
        account.balance = 0;
        account.has_pending_withdrawal = true;
        account.status = ValidatorStatus::Inactive;
        state.set_account(pubkeys[0], account);

        state.push_removed_validator(ed_keys[0].public_key());

        let withdrawal_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            withdrawal_root,
            state.ssz_tree().root(),
            "withdrawal: incremental != rebuild"
        );

        // --- Simulate protocol param change ---
        state.push_protocol_param_change(ProtocolParam::MinimumStake(16_000_000_000));
        state.apply_protocol_parameter_changes().unwrap();

        let param_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            param_root,
            state.ssz_tree().root(),
            "protocol param: incremental != rebuild"
        );

        // --- Remove validator account ---
        state.remove_account(&pubkeys[0]);

        let remove_root = state.ssz_tree().root();
        state.rebuild_ssz_tree();
        assert_eq!(
            remove_root,
            state.ssz_tree().root(),
            "remove validator: incremental != rebuild"
        );
    }

    #[test]
    fn test_reschedule_withdrawal_epoch_updates_ssz_root() {
        let mut state = ConsensusState::default();

        // Add two withdrawals in epoch 5 and one in epoch 6
        let w1 = create_test_withdrawal(1, 100, 5);
        let w2 = create_test_withdrawal(2, 200, 5);
        let w3 = create_test_withdrawal(3, 300, 6);
        state.push_withdrawal(w1);
        state.push_withdrawal(w2);
        state.push_withdrawal(w3);

        let root_before = state.ssz_tree().root();

        // Reschedule epoch 5 → epoch 6
        state.reschedule_withdrawal_epoch(5, 6);

        // Root should change
        let root_after = state.ssz_tree().root();
        assert_ne!(
            root_before, root_after,
            "root should change after rescheduling"
        );

        // Verify incremental update matches full rebuild
        state.rebuild_ssz_tree();
        assert_eq!(
            root_after,
            state.ssz_tree().root(),
            "incremental reschedule root should match full rebuild"
        );
    }
}
