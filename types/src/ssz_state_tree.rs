//! Two-level SSZ binary Merkle tree for ConsensusState.
//!
//! The top-level tree has 32 leaf slots (17 used, depth 5). Scalar fields
//! occupy leaves 0–10. Collection roots occupy leaves 11–16.
//!
//! The validator accounts collection uses a dedicated subtree (`SszTree`)
//! where each validator occupies 8 contiguous leaves (one per field),
//! forming a depth-3 per-validator sub-subtree. This enables field-level
//! Merkle proofs (e.g., proving just the balance) in addition to whole-
//! account proofs.
//!
//! Validator slot assignment is purely positional: the i-th entry in
//! `BTreeMap<[u8; 32], ValidatorAccount>` iteration order occupies
//! leaves `[i*8 .. i*8+7]`. The subtree is rebuilt from scratch on
//! every mutation for determinism.

use crate::PublicKey;
use crate::account::ValidatorAccount;
use crate::execution_request::DepositRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::ssz_hash::{SszHashTreeRoot, hash_fixed_bytes_64, hash_fixed_bytes_96};
use crate::ssz_tree::{SszTree, mix_in_length};
use crate::withdrawal::PendingWithdrawal;
use crate::withdrawal::WithdrawalQueue;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

// --- Top-level leaf indices ---

pub const EPOCH: usize = 0;
pub const VIEW: usize = 1;
pub const LATEST_HEIGHT: usize = 2;
pub const HEAD_DIGEST: usize = 3;
pub const EPOCH_GENESIS_HASH: usize = 4;
pub const VALIDATOR_MINIMUM_STAKE: usize = 5;
pub const VALIDATOR_MAXIMUM_STAKE: usize = 6;
pub const NEXT_WITHDRAWAL_INDEX: usize = 7;
pub const FORKCHOICE_HEAD_BLOCK_HASH: usize = 8;
pub const FORKCHOICE_SAFE_BLOCK_HASH: usize = 9;
pub const FORKCHOICE_FINALIZED_BLOCK_HASH: usize = 10;
pub const VALIDATOR_ACCOUNTS_ROOT: usize = 11;
pub const DEPOSIT_QUEUE_ROOT: usize = 12;
pub const WITHDRAWAL_QUEUE_ROOT: usize = 13;
pub const PROTOCOL_PARAM_CHANGES_ROOT: usize = 14;
pub const ADDED_VALIDATORS_ROOT: usize = 15;
pub const REMOVED_VALIDATORS_ROOT: usize = 16;

/// Number of used leaf slots in the top-level tree.
pub const NUM_TOP_LEAVES: usize = 17;

// --- Validator field indices (within each validator's 8-leaf subtree) ---

pub const VALIDATOR_FIELD_CONSENSUS_PUBKEY: usize = 0;
pub const VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS: usize = 1;
pub const VALIDATOR_FIELD_BALANCE: usize = 2;
pub const VALIDATOR_FIELD_STATUS: usize = 3;
pub const VALIDATOR_FIELD_HAS_PENDING_DEPOSIT: usize = 4;
pub const VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL: usize = 5;
pub const VALIDATOR_FIELD_JOINING_EPOCH: usize = 6;
pub const VALIDATOR_FIELD_LAST_DEPOSIT_INDEX: usize = 7;

/// Number of SSZ fields per ValidatorAccount (8 fields = depth-3 subtree).
pub const VALIDATOR_FIELDS_PER_ACCOUNT: usize = 8;

// --- Deposit field indices (within each deposit's 8-leaf subtree) ---

pub const DEPOSIT_FIELD_NODE_PUBKEY: usize = 0;
pub const DEPOSIT_FIELD_CONSENSUS_PUBKEY: usize = 1;
pub const DEPOSIT_FIELD_WITHDRAWAL_CREDENTIALS: usize = 2;
pub const DEPOSIT_FIELD_AMOUNT: usize = 3;
pub const DEPOSIT_FIELD_NODE_SIGNATURE: usize = 4;
pub const DEPOSIT_FIELD_CONSENSUS_SIGNATURE: usize = 5;
pub const DEPOSIT_FIELD_INDEX: usize = 6;
// leaf 7 is unused (zero hash padding for 7-field container in 8-leaf subtree)

/// Number of SSZ leaves per DepositRequest (7 fields → 8 leaves, depth-3 subtree).
pub const DEPOSIT_FIELDS_PER_ITEM: usize = 8;

// --- Withdrawal field indices (within each withdrawal's 8-leaf subtree) ---

pub const WITHDRAWAL_FIELD_INDEX: usize = 0;
pub const WITHDRAWAL_FIELD_VALIDATOR_INDEX: usize = 1;
pub const WITHDRAWAL_FIELD_ADDRESS: usize = 2;
pub const WITHDRAWAL_FIELD_AMOUNT: usize = 3;
pub const WITHDRAWAL_FIELD_PUBKEY: usize = 4;
pub const WITHDRAWAL_FIELD_BALANCE_DEDUCTION: usize = 5;
pub const WITHDRAWAL_FIELD_EPOCH: usize = 6;
// leaf 7 is unused (zero hash padding for 7-field container in 8-leaf subtree)

/// Number of SSZ leaves per PendingWithdrawal (7 fields → 8 leaves, depth-3 subtree).
pub const WITHDRAWAL_FIELDS_PER_ITEM: usize = 8;

// --- Protocol parameter field indices (within each param's 2-leaf subtree) ---

pub const PROTOCOL_PARAM_FIELD_TAG: usize = 0;
pub const PROTOCOL_PARAM_FIELD_VALUE: usize = 1;

/// Number of SSZ leaves per ProtocolParam (2 fields = depth-1 subtree).
pub const PROTOCOL_PARAM_FIELDS_PER_ITEM: usize = 2;

// --- Added validator field indices (within each added validator's 2-leaf subtree) ---

pub const ADDED_VALIDATOR_FIELD_NODE_KEY: usize = 0;
pub const ADDED_VALIDATOR_FIELD_CONSENSUS_KEY: usize = 1;

/// Number of SSZ leaves per AddedValidator (2 fields = depth-1 subtree).
pub const ADDED_VALIDATOR_FIELDS_PER_ITEM: usize = 2;

/// Two-level SSZ state tree mirroring ConsensusState.
#[derive(Clone, Debug)]
pub struct SszStateTree {
    /// Top-level tree: 32 leaves (depth 5), 17 used.
    top: SszTree,

    /// Validator accounts subtree. Rebuilt from BTreeMap on every mutation.
    validator_tree: SszTree,
    /// Number of active validators (= number of leaves set in the subtree).
    validator_count: usize,

    /// Deposit queue subtree.
    deposit_tree: SszTree,
    deposit_count: usize,

    /// Withdrawal queue subtree.
    withdrawal_tree: SszTree,
    withdrawal_count: usize,

    /// Protocol parameter changes subtree.
    protocol_param_tree: SszTree,
    protocol_param_count: usize,

    /// Added validators subtree (flattened across all epochs).
    added_validator_tree: SszTree,
    added_validator_count: usize,

    /// Removed validators subtree.
    removed_validator_tree: SszTree,
    removed_validator_count: usize,
}

impl SszStateTree {
    pub fn new() -> Self {
        Self {
            top: SszTree::new(NUM_TOP_LEAVES),
            validator_tree: SszTree::new(1),
            validator_count: 0,
            deposit_tree: SszTree::new(1),
            deposit_count: 0,
            withdrawal_tree: SszTree::new(1),
            withdrawal_count: 0,
            protocol_param_tree: SszTree::new(1),
            protocol_param_count: 0,
            added_validator_tree: SszTree::new(1),
            added_validator_count: 0,
            removed_validator_tree: SszTree::new(1),
            removed_validator_count: 0,
        }
    }

    /// Returns the state root (top-level tree root).
    pub fn root(&self) -> [u8; 32] {
        self.top.root()
    }

    // --- Scalar field setters ---

    pub fn set_epoch(&mut self, epoch: u64) {
        self.top.set_leaf(EPOCH, epoch.hash_tree_root());
    }

    pub fn set_view(&mut self, view: u64) {
        self.top.set_leaf(VIEW, view.hash_tree_root());
    }

    pub fn set_latest_height(&mut self, height: u64) {
        self.top.set_leaf(LATEST_HEIGHT, height.hash_tree_root());
    }

    pub fn set_head_digest(&mut self, digest: &[u8; 32]) {
        self.top.set_leaf(HEAD_DIGEST, *digest);
    }

    pub fn set_epoch_genesis_hash(&mut self, hash: &[u8; 32]) {
        self.top.set_leaf(EPOCH_GENESIS_HASH, *hash);
    }

    pub fn set_validator_minimum_stake(&mut self, stake: u64) {
        self.top
            .set_leaf(VALIDATOR_MINIMUM_STAKE, stake.hash_tree_root());
    }

    pub fn set_validator_maximum_stake(&mut self, stake: u64) {
        self.top
            .set_leaf(VALIDATOR_MAXIMUM_STAKE, stake.hash_tree_root());
    }

    pub fn set_next_withdrawal_index(&mut self, index: u64) {
        self.top
            .set_leaf(NEXT_WITHDRAWAL_INDEX, index.hash_tree_root());
    }

    pub fn set_forkchoice_head_block_hash(&mut self, hash: &[u8; 32]) {
        self.top.set_leaf(FORKCHOICE_HEAD_BLOCK_HASH, *hash);
    }

    pub fn set_forkchoice_safe_block_hash(&mut self, hash: &[u8; 32]) {
        self.top.set_leaf(FORKCHOICE_SAFE_BLOCK_HASH, *hash);
    }

    pub fn set_forkchoice_finalized_block_hash(&mut self, hash: &[u8; 32]) {
        self.top.set_leaf(FORKCHOICE_FINALIZED_BLOCK_HASH, *hash);
    }

    // --- Validator subtree ---

    /// Rebuild the validator subtree from the full validator accounts map.
    ///
    /// Each validator occupies 8 contiguous leaves (one per field) in the subtree,
    /// forming a depth-3 per-validator sub-subtree. Slot assignment is purely
    /// positional: the i-th entry in BTreeMap iteration order occupies leaves
    /// `[i*8 .. i*8+7]`.
    pub fn rebuild_validators(&mut self, accounts: &BTreeMap<[u8; 32], ValidatorAccount>) {
        let count = accounts.len();
        let leaf_count = (count * VALIDATOR_FIELDS_PER_ACCOUNT).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, account) in accounts.values().enumerate() {
            Self::set_validator_fields(&mut tree, i, account);
        }
        self.validator_tree = tree;
        self.validator_count = count;
        self.update_validator_collection_root();
    }

    /// Set the 8 field leaves for validator at positional slot `i`.
    fn set_validator_fields(tree: &mut SszTree, slot: usize, account: &ValidatorAccount) {
        let base = slot * VALIDATOR_FIELDS_PER_ACCOUNT;
        tree.set_leaf(
            base + VALIDATOR_FIELD_CONSENSUS_PUBKEY,
            account.consensus_public_key.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS,
            account.withdrawal_credentials.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_BALANCE,
            account.balance.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_STATUS,
            account.status.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_HAS_PENDING_DEPOSIT,
            account.has_pending_deposit.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL,
            account.has_pending_withdrawal.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_JOINING_EPOCH,
            account.joining_epoch.hash_tree_root(),
        );
        tree.set_leaf(
            base + VALIDATOR_FIELD_LAST_DEPOSIT_INDEX,
            account.last_deposit_index.hash_tree_root(),
        );
    }

    /// Update a single validator's fields in-place (incremental).
    ///
    /// The validator must already exist at the given `slot`. Only the changed
    /// leaves are rehashed — O(8 · log n) instead of O(N · 8) for a full rebuild.
    pub fn update_validator_at_slot(&mut self, slot: usize, account: &ValidatorAccount) {
        Self::set_validator_fields(&mut self.validator_tree, slot, account);
        self.update_validator_collection_root();
    }

    /// Insert a new validator at positional `slot`, shifting existing validators right.
    ///
    /// Grows the tree if needed. Copies shifted validators' subtree nodes via memmove
    /// (no rehash), then writes the new validator's 8 field leaves and rehashes only
    /// the upper tree. O(N) memcpy + O(N/8) SHA256 instead of O(N*8*log(N*8)).
    pub fn insert_validator_at_slot(&mut self, slot: usize, account: &ValidatorAccount) {
        let new_count = self.validator_count + 1;
        let needed = new_count * VALIDATOR_FIELDS_PER_ACCOUNT;
        self.validator_tree.grow(needed);

        // Shift validators [slot..count) right by 1 block
        let to_shift = self.validator_count - slot;
        self.validator_tree
            .shift_blocks_right(slot, to_shift, VALIDATOR_FIELDS_PER_ACCOUNT);

        // Write new validator's 8 field leaves (no per-leaf rehash)
        Self::set_validator_fields_no_rehash(&mut self.validator_tree, slot, account);

        // Rehash from leaf parents up through the entire tree
        self.validator_tree
            .rehash_from(self.validator_tree.capacity() / 2);

        self.validator_count = new_count;
        self.update_validator_collection_root();
    }

    /// Remove the validator at positional `slot`, shifting subsequent validators left.
    ///
    /// O(N) memcpy + O(N/8) SHA256.
    pub fn remove_validator_at_slot(&mut self, slot: usize) {
        assert!(slot < self.validator_count, "slot out of range");
        let to_shift = self.validator_count - slot - 1;
        self.validator_tree
            .shift_blocks_left(slot, to_shift, VALIDATOR_FIELDS_PER_ACCOUNT);

        // Zero the last validator's leaves (shift_blocks_left skips when count=0)
        let last_slot = self.validator_count - 1;
        let base = last_slot * VALIDATOR_FIELDS_PER_ACCOUNT;
        for i in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
            self.validator_tree.set_leaf_no_rehash(base + i, [0u8; 32]);
        }

        self.validator_count -= 1;

        // Shrink tree if the new count fits in a smaller capacity.
        // This ensures the tree capacity matches what rebuild_validators would produce.
        // shrink() does its own rehash, so we only need a separate rehash if not shrinking.
        let needed = (self.validator_count * VALIDATOR_FIELDS_PER_ACCOUNT).max(1);
        let target_capacity = needed.next_power_of_two();
        if target_capacity < self.validator_tree.capacity() {
            self.validator_tree.shrink(needed);
        } else {
            self.validator_tree
                .rehash_from(self.validator_tree.capacity() / 2);
        }

        self.update_validator_collection_root();
    }

    /// Set the 8 field leaves without triggering per-leaf rehash.
    fn set_validator_fields_no_rehash(tree: &mut SszTree, slot: usize, account: &ValidatorAccount) {
        let base = slot * VALIDATOR_FIELDS_PER_ACCOUNT;
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_CONSENSUS_PUBKEY,
            account.consensus_public_key.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS,
            account.withdrawal_credentials.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_BALANCE,
            account.balance.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_STATUS,
            account.status.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_HAS_PENDING_DEPOSIT,
            account.has_pending_deposit.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL,
            account.has_pending_withdrawal.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_JOINING_EPOCH,
            account.joining_epoch.hash_tree_root(),
        );
        tree.set_leaf_no_rehash(
            base + VALIDATOR_FIELD_LAST_DEPOSIT_INDEX,
            account.last_deposit_index.hash_tree_root(),
        );
    }

    /// Get the positional index of a validator pubkey within sorted keys.
    pub fn get_validator_index(keys: &[[u8; 32]], pubkey: &[u8; 32]) -> Option<usize> {
        keys.iter().position(|k| k == pubkey)
    }

    /// Number of validators in the subtree.
    pub fn validator_count(&self) -> usize {
        self.validator_count
    }

    fn update_validator_collection_root(&mut self) {
        let subtree_root = self.validator_tree.root();
        let collection_root = mix_in_length(subtree_root, self.validator_count);
        self.top.set_leaf(VALIDATOR_ACCOUNTS_ROOT, collection_root);
    }

    // --- Deposit queue subtree ---

    /// Rebuild the deposit queue subtree from current contents.
    ///
    /// Each deposit occupies 8 contiguous leaves (one per field), forming
    /// a depth-3 per-deposit sub-subtree, enabling field-level proofs.
    pub fn rebuild_deposits(&mut self, deposits: &VecDeque<DepositRequest>) {
        let count = deposits.len();
        let leaf_count = (count * DEPOSIT_FIELDS_PER_ITEM).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, deposit) in deposits.iter().enumerate() {
            Self::set_deposit_fields(&mut tree, i, deposit);
        }
        self.deposit_tree = tree;
        self.deposit_count = count;
        self.update_deposit_collection_root();
    }

    /// Set the 8 field leaves for deposit at positional slot `i`.
    fn set_deposit_fields(tree: &mut SszTree, slot: usize, deposit: &DepositRequest) {
        let base = slot * DEPOSIT_FIELDS_PER_ITEM;
        tree.set_leaf(
            base + DEPOSIT_FIELD_NODE_PUBKEY,
            deposit.node_pubkey.hash_tree_root(),
        );
        tree.set_leaf(
            base + DEPOSIT_FIELD_CONSENSUS_PUBKEY,
            deposit.consensus_pubkey.hash_tree_root(),
        );
        tree.set_leaf(
            base + DEPOSIT_FIELD_WITHDRAWAL_CREDENTIALS,
            deposit.withdrawal_credentials.hash_tree_root(),
        );
        tree.set_leaf(base + DEPOSIT_FIELD_AMOUNT, deposit.amount.hash_tree_root());
        tree.set_leaf(
            base + DEPOSIT_FIELD_NODE_SIGNATURE,
            hash_fixed_bytes_64(&deposit.node_signature),
        );
        tree.set_leaf(
            base + DEPOSIT_FIELD_CONSENSUS_SIGNATURE,
            hash_fixed_bytes_96(&deposit.consensus_signature),
        );
        tree.set_leaf(base + DEPOSIT_FIELD_INDEX, deposit.index.hash_tree_root());
        // leaf 7 remains zero (SSZ padding for 7-field container in 8-leaf subtree)
    }

    fn update_deposit_collection_root(&mut self) {
        let subtree_root = self.deposit_tree.root();
        let collection_root = mix_in_length(subtree_root, self.deposit_count);
        self.top.set_leaf(DEPOSIT_QUEUE_ROOT, collection_root);
    }

    /// Number of deposits in the subtree.
    pub fn deposit_count(&self) -> usize {
        self.deposit_count
    }

    // --- Withdrawal queue subtree ---

    /// Rebuild the withdrawal queue subtree from current contents.
    ///
    /// Each withdrawal occupies 8 contiguous leaves (one per field), forming
    /// a depth-3 per-withdrawal sub-subtree, enabling field-level proofs.
    pub fn rebuild_withdrawals(&mut self, queue: &WithdrawalQueue) {
        let items: Vec<&PendingWithdrawal> = queue.withdrawals_iter().map(|(_, w)| w).collect();
        let count = items.len();
        let leaf_count = (count * WITHDRAWAL_FIELDS_PER_ITEM).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, withdrawal) in items.iter().enumerate() {
            Self::set_withdrawal_fields(&mut tree, i, withdrawal);
        }
        self.withdrawal_tree = tree;
        self.withdrawal_count = count;
        self.update_withdrawal_collection_root();
    }

    /// Set the 8 field leaves for withdrawal at positional slot `i`.
    fn set_withdrawal_fields(tree: &mut SszTree, slot: usize, withdrawal: &PendingWithdrawal) {
        let base = slot * WITHDRAWAL_FIELDS_PER_ITEM;
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_INDEX,
            withdrawal.inner.index.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_VALIDATOR_INDEX,
            withdrawal.inner.validator_index.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_ADDRESS,
            withdrawal.inner.address.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_AMOUNT,
            withdrawal.inner.amount.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_PUBKEY,
            withdrawal.pubkey.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_BALANCE_DEDUCTION,
            withdrawal.balance_deduction.hash_tree_root(),
        );
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_EPOCH,
            withdrawal.epoch.hash_tree_root(),
        );
        // leaf 7 remains zero (SSZ padding for 7-field container in 8-leaf subtree)
    }

    fn update_withdrawal_collection_root(&mut self) {
        let subtree_root = self.withdrawal_tree.root();
        let collection_root = mix_in_length(subtree_root, self.withdrawal_count);
        self.top.set_leaf(WITHDRAWAL_QUEUE_ROOT, collection_root);
    }

    /// Number of withdrawals in the subtree.
    pub fn withdrawal_count(&self) -> usize {
        self.withdrawal_count
    }

    /// Rebuild protocol parameter changes subtree.
    ///
    /// Each protocol param occupies 2 contiguous leaves (tag, value),
    /// forming a depth-1 per-param sub-subtree, enabling field-level proofs.
    pub fn rebuild_protocol_params(&mut self, params: &[ProtocolParam]) {
        let count = params.len();
        let leaf_count = (count * PROTOCOL_PARAM_FIELDS_PER_ITEM).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, param) in params.iter().enumerate() {
            Self::set_protocol_param_fields(&mut tree, i, param);
        }
        self.protocol_param_tree = tree;
        self.protocol_param_count = count;
        self.update_protocol_param_collection_root();
    }

    /// Set the 2 field leaves for protocol param at positional slot `i`.
    fn set_protocol_param_fields(tree: &mut SszTree, slot: usize, param: &ProtocolParam) {
        let base = slot * PROTOCOL_PARAM_FIELDS_PER_ITEM;
        let (tag, value) = match param {
            ProtocolParam::MinimumStake(v) => (0u64, *v),
            ProtocolParam::MaximumStake(v) => (1u64, *v),
        };
        tree.set_leaf(base + PROTOCOL_PARAM_FIELD_TAG, tag.hash_tree_root());
        tree.set_leaf(base + PROTOCOL_PARAM_FIELD_VALUE, value.hash_tree_root());
    }

    fn update_protocol_param_collection_root(&mut self) {
        let subtree_root = self.protocol_param_tree.root();
        let collection_root = mix_in_length(subtree_root, self.protocol_param_count);
        self.top
            .set_leaf(PROTOCOL_PARAM_CHANGES_ROOT, collection_root);
    }

    /// Number of protocol parameter changes in the subtree.
    pub fn protocol_param_count(&self) -> usize {
        self.protocol_param_count
    }

    /// Rebuild added validators subtree (flattened across all epochs).
    ///
    /// Each added validator occupies 2 contiguous leaves (node_key, consensus_key),
    /// forming a depth-1 per-item sub-subtree, enabling field-level proofs.
    pub fn rebuild_added_validators(&mut self, validators: &BTreeMap<u64, Vec<AddedValidator>>) {
        let items: Vec<&AddedValidator> = validators.values().flat_map(|v| v.iter()).collect();
        let count = items.len();
        let leaf_count = (count * ADDED_VALIDATOR_FIELDS_PER_ITEM).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, av) in items.iter().enumerate() {
            Self::set_added_validator_fields(&mut tree, i, av);
        }
        self.added_validator_tree = tree;
        self.added_validator_count = count;
        self.update_added_validator_collection_root();
    }

    /// Set the 2 field leaves for added validator at positional slot `i`.
    fn set_added_validator_fields(tree: &mut SszTree, slot: usize, av: &AddedValidator) {
        let base = slot * ADDED_VALIDATOR_FIELDS_PER_ITEM;
        tree.set_leaf(
            base + ADDED_VALIDATOR_FIELD_NODE_KEY,
            av.node_key.hash_tree_root(),
        );
        tree.set_leaf(
            base + ADDED_VALIDATOR_FIELD_CONSENSUS_KEY,
            av.consensus_key.hash_tree_root(),
        );
    }

    fn update_added_validator_collection_root(&mut self) {
        let subtree_root = self.added_validator_tree.root();
        let collection_root = mix_in_length(subtree_root, self.added_validator_count);
        self.top.set_leaf(ADDED_VALIDATORS_ROOT, collection_root);
    }

    /// Number of added validators in the subtree.
    pub fn added_validator_count(&self) -> usize {
        self.added_validator_count
    }

    /// Rebuild removed validators subtree.
    pub fn rebuild_removed_validators(&mut self, validators: &[PublicKey]) {
        let count = validators.len();
        let capacity = count.max(1);
        let mut tree = SszTree::new(capacity);
        for (i, v) in validators.iter().enumerate() {
            tree.set_leaf(i, v.hash_tree_root());
        }
        self.removed_validator_tree = tree;
        self.removed_validator_count = count;
        self.update_removed_validator_collection_root();
    }

    fn update_removed_validator_collection_root(&mut self) {
        let subtree_root = self.removed_validator_tree.root();
        let collection_root = mix_in_length(subtree_root, self.removed_validator_count);
        self.top.set_leaf(REMOVED_VALIDATORS_ROOT, collection_root);
    }

    /// Number of removed validators in the subtree.
    pub fn removed_validator_count(&self) -> usize {
        self.removed_validator_count
    }

    // --- Rebuild from scratch ---

    /// Rebuild the entire tree from consensus state data.
    #[allow(clippy::too_many_arguments)]
    pub fn rebuild(
        &mut self,
        epoch: u64,
        view: u64,
        latest_height: u64,
        head_digest: &[u8; 32],
        epoch_genesis_hash: &[u8; 32],
        validator_minimum_stake: u64,
        validator_maximum_stake: u64,
        next_withdrawal_index: u64,
        forkchoice_head: &[u8; 32],
        forkchoice_safe: &[u8; 32],
        forkchoice_finalized: &[u8; 32],
        validator_accounts: &BTreeMap<[u8; 32], ValidatorAccount>,
        deposit_queue: &VecDeque<DepositRequest>,
        withdrawal_queue: &WithdrawalQueue,
        protocol_param_changes: &[ProtocolParam],
        added_validators: &BTreeMap<u64, Vec<AddedValidator>>,
        removed_validators: &[PublicKey],
    ) {
        *self = Self::new();

        // Scalar fields
        self.set_epoch(epoch);
        self.set_view(view);
        self.set_latest_height(latest_height);
        self.set_head_digest(head_digest);
        self.set_epoch_genesis_hash(epoch_genesis_hash);
        self.set_validator_minimum_stake(validator_minimum_stake);
        self.set_validator_maximum_stake(validator_maximum_stake);
        self.set_next_withdrawal_index(next_withdrawal_index);
        self.set_forkchoice_head_block_hash(forkchoice_head);
        self.set_forkchoice_safe_block_hash(forkchoice_safe);
        self.set_forkchoice_finalized_block_hash(forkchoice_finalized);

        // Validators
        self.rebuild_validators(validator_accounts);

        // Other collections
        self.rebuild_deposits(deposit_queue);
        self.rebuild_withdrawals(withdrawal_queue);
        self.rebuild_protocol_params(protocol_param_changes);
        self.rebuild_added_validators(added_validators);
        self.rebuild_removed_validators(removed_validators);
    }

    // --- Proof generation ---

    /// Compose a generalized index for a collection element.
    ///
    /// Given the top-level leaf index of the collection root and the
    /// item's index within the subtree, computes the single generalized
    /// index that addresses the item in the full state tree.
    fn compose_collection_gindex(
        &self,
        top_leaf_index: usize,
        subtree: &SszTree,
        item_index: usize,
    ) -> u64 {
        let td = self.top.depth();
        let sd = subtree.depth();
        let top_gindex = (1u64 << td) + top_leaf_index as u64;
        // The subtree root is the left child of the mix_in_length node,
        // so the item sits at depth (sd + 1) below the top-level leaf.
        (top_gindex << (sd + 1)) | (item_index as u64)
    }

    /// Build a unified branch for a collection element proof.
    ///
    /// Concatenates: subtree siblings + length sibling (mix_in_length) + top-level siblings.
    fn build_collection_branch(
        &self,
        top_leaf_index: usize,
        subtree: &SszTree,
        item_index: usize,
        collection_length: usize,
    ) -> Vec<[u8; 32]> {
        let mut branch = subtree.generate_proof(item_index);
        // mix_in_length sibling: LE u64 length padded to 32 bytes
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(collection_length as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(top_leaf_index));
        branch
    }

    /// Generate a proof for a top-level scalar field.
    pub fn generate_scalar_proof(&self, leaf_index: usize) -> SszProof {
        let gindex = (1u64 << self.top.depth()) + leaf_index as u64;
        SszProof {
            gindex,
            leaf: self.top.get_leaf(leaf_index),
            branch: self.top.generate_proof(leaf_index),
        }
    }

    /// Generate a proof for a validator account (whole account).
    ///
    /// The proof leaf is `hash_tree_root(ValidatorAccount)`, which is the
    /// internal node at the root of the validator's 8-field subtree. The
    /// proof branch is shorter by 3 compared to a field-level proof.
    ///
    /// Returns `None` if the pubkey is not in the keys.
    pub fn generate_validator_proof(
        &self,
        pubkey: &[u8; 32],
        keys: &[[u8; 32]],
    ) -> Option<SszProof> {
        let slot = Self::get_validator_index(keys, pubkey)?;
        let (gindex, node_value, branch) = self.validator_account_proof(slot);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a proof for a single field of a validator account.
    ///
    /// `field_index` is one of the `VALIDATOR_FIELD_*` constants (0–7).
    /// The proof goes from the field leaf all the way to the state root.
    ///
    /// Returns `None` if the pubkey is not in the keys.
    pub fn generate_validator_field_proof(
        &self,
        pubkey: &[u8; 32],
        field_index: usize,
        keys: &[[u8; 32]],
    ) -> Option<SszProof> {
        assert!(
            field_index < VALIDATOR_FIELDS_PER_ACCOUNT,
            "field_index out of range"
        );
        let slot = Self::get_validator_index(keys, pubkey)?;
        let leaf_index = slot * VALIDATOR_FIELDS_PER_ACCOUNT + field_index;
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                VALIDATOR_ACCOUNTS_ROOT,
                &self.validator_tree,
                leaf_index,
            ),
            leaf: self.validator_tree.get_leaf(leaf_index),
            branch: self.build_collection_branch(
                VALIDATOR_ACCOUNTS_ROOT,
                &self.validator_tree,
                leaf_index,
                self.validator_count,
            ),
        })
    }

    /// Build a proof for the whole validator at positional `slot`.
    ///
    /// Returns (gindex, node_value, branch) where the node is the
    /// per-validator subtree root (3 levels above the field leaves).
    fn validator_account_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.validator_tree.depth();
        // Per-validator root is at depth (sd - 3) in the subtree.
        // Its 1-based tree index is: capacity / 8 + slot
        let node_index = self.validator_tree.capacity() / VALIDATOR_FIELDS_PER_ACCOUNT + slot;
        let node_value = self.validator_tree.get_node(node_index);

        // Generalized index: top_gindex << (sd - 2) | slot
        // (sd - 2 = (sd - 3) levels in subtree + 1 for mix_in_length)
        let td = self.top.depth();
        let top_gindex = (1u64 << td) + VALIDATOR_ACCOUNTS_ROOT as u64;
        let gindex = (top_gindex << (sd - 2)) | (slot as u64);

        // Branch: subtree proof from internal node + mix_in_length sibling + top proof
        let mut branch = self.validator_tree.generate_proof_from_node(node_index);
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(self.validator_count as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(VALIDATOR_ACCOUNTS_ROOT));

        (gindex, node_value, branch)
    }

    /// Generate a proof for a deposit identified by node pubkey.
    pub fn generate_deposit_proof_by_key(
        &self,
        node_pubkey: &PublicKey,
        deposits: &VecDeque<DepositRequest>,
    ) -> Option<SszProof> {
        let index = deposits
            .iter()
            .position(|d| &d.node_pubkey == node_pubkey)?;
        self.generate_deposit_proof(index)
    }

    /// Generate a proof for a withdrawal identified by validator pubkey.
    pub fn generate_withdrawal_proof_by_key(
        &self,
        pubkey: &[u8; 32],
        queue: &WithdrawalQueue,
    ) -> Option<SszProof> {
        let index = queue.withdrawals_iter().position(|(k, _)| k == pubkey)?;
        self.generate_withdrawal_proof(index)
    }

    /// Generate a proof for a deposit at a given queue index (whole deposit).
    ///
    /// The proof leaf is the per-deposit subtree root (internal node 3 levels
    /// above the field leaves). The branch is 3 elements shorter than a
    /// field-level proof.
    pub fn generate_deposit_proof(&self, index: usize) -> Option<SszProof> {
        if index >= self.deposit_count {
            return None;
        }
        let (gindex, node_value, branch) = self.deposit_item_proof(index);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a proof for a single field of a deposit at a given queue index.
    pub fn generate_deposit_field_proof(
        &self,
        index: usize,
        field_index: usize,
    ) -> Option<SszProof> {
        if index >= self.deposit_count || field_index >= DEPOSIT_FIELDS_PER_ITEM {
            return None;
        }
        let leaf_index = index * DEPOSIT_FIELDS_PER_ITEM + field_index;
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                DEPOSIT_QUEUE_ROOT,
                &self.deposit_tree,
                leaf_index,
            ),
            leaf: self.deposit_tree.get_leaf(leaf_index),
            branch: self.build_collection_branch(
                DEPOSIT_QUEUE_ROOT,
                &self.deposit_tree,
                leaf_index,
                self.deposit_count,
            ),
        })
    }

    /// Generate a field-level proof for a deposit identified by node pubkey.
    pub fn generate_deposit_field_proof_by_key(
        &self,
        node_pubkey: &PublicKey,
        field_index: usize,
        deposits: &VecDeque<DepositRequest>,
    ) -> Option<SszProof> {
        let index = deposits
            .iter()
            .position(|d| &d.node_pubkey == node_pubkey)?;
        self.generate_deposit_field_proof(index, field_index)
    }

    /// Internal helper: produce (gindex, node_value, branch) for a whole-deposit proof.
    fn deposit_item_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.deposit_tree.depth();
        let node_index = self.deposit_tree.capacity() / DEPOSIT_FIELDS_PER_ITEM + slot;
        let node_value = self.deposit_tree.get_node(node_index);

        let td = self.top.depth();
        let top_gindex = (1u64 << td) + DEPOSIT_QUEUE_ROOT as u64;
        let gindex = (top_gindex << (sd - 2)) | (slot as u64);

        let mut branch = self.deposit_tree.generate_proof_from_node(node_index);
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(self.deposit_count as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(DEPOSIT_QUEUE_ROOT));

        (gindex, node_value, branch)
    }

    /// Generate a proof for a withdrawal at a given queue index (whole withdrawal).
    ///
    /// The proof leaf is the per-withdrawal subtree root (internal node 3 levels
    /// above the field leaves). The branch is 3 elements shorter than a
    /// field-level proof.
    pub fn generate_withdrawal_proof(&self, index: usize) -> Option<SszProof> {
        if index >= self.withdrawal_count {
            return None;
        }
        let (gindex, node_value, branch) = self.withdrawal_item_proof(index);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a proof for a single field of a withdrawal at a given queue index.
    pub fn generate_withdrawal_field_proof(
        &self,
        index: usize,
        field_index: usize,
    ) -> Option<SszProof> {
        if index >= self.withdrawal_count || field_index >= WITHDRAWAL_FIELDS_PER_ITEM {
            return None;
        }
        let leaf_index = index * WITHDRAWAL_FIELDS_PER_ITEM + field_index;
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                WITHDRAWAL_QUEUE_ROOT,
                &self.withdrawal_tree,
                leaf_index,
            ),
            leaf: self.withdrawal_tree.get_leaf(leaf_index),
            branch: self.build_collection_branch(
                WITHDRAWAL_QUEUE_ROOT,
                &self.withdrawal_tree,
                leaf_index,
                self.withdrawal_count,
            ),
        })
    }

    /// Generate a field-level proof for a withdrawal identified by validator pubkey.
    pub fn generate_withdrawal_field_proof_by_key(
        &self,
        pubkey: &[u8; 32],
        field_index: usize,
        queue: &WithdrawalQueue,
    ) -> Option<SszProof> {
        let index = queue.withdrawals_iter().position(|(k, _)| k == pubkey)?;
        self.generate_withdrawal_field_proof(index, field_index)
    }

    /// Internal helper: produce (gindex, node_value, branch) for a whole-withdrawal proof.
    fn withdrawal_item_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.withdrawal_tree.depth();
        let node_index = self.withdrawal_tree.capacity() / WITHDRAWAL_FIELDS_PER_ITEM + slot;
        let node_value = self.withdrawal_tree.get_node(node_index);

        let td = self.top.depth();
        let top_gindex = (1u64 << td) + WITHDRAWAL_QUEUE_ROOT as u64;
        let gindex = (top_gindex << (sd - 2)) | (slot as u64);

        let mut branch = self.withdrawal_tree.generate_proof_from_node(node_index);
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(self.withdrawal_count as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(WITHDRAWAL_QUEUE_ROOT));

        (gindex, node_value, branch)
    }

    /// Generate a proof for a protocol parameter change at a given index.
    /// Generate a proof for a protocol parameter change at a given index (whole param).
    ///
    /// The proof leaf is the per-param subtree root (internal node 1 level
    /// above the field leaves). The branch is 1 element shorter than a
    /// field-level proof.
    pub fn generate_protocol_param_proof(&self, index: usize) -> Option<SszProof> {
        if index >= self.protocol_param_count {
            return None;
        }
        let (gindex, node_value, branch) = self.protocol_param_item_proof(index);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a proof for a single field of a protocol parameter change.
    pub fn generate_protocol_param_field_proof(
        &self,
        index: usize,
        field_index: usize,
    ) -> Option<SszProof> {
        if index >= self.protocol_param_count || field_index >= PROTOCOL_PARAM_FIELDS_PER_ITEM {
            return None;
        }
        let leaf_index = index * PROTOCOL_PARAM_FIELDS_PER_ITEM + field_index;
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                PROTOCOL_PARAM_CHANGES_ROOT,
                &self.protocol_param_tree,
                leaf_index,
            ),
            leaf: self.protocol_param_tree.get_leaf(leaf_index),
            branch: self.build_collection_branch(
                PROTOCOL_PARAM_CHANGES_ROOT,
                &self.protocol_param_tree,
                leaf_index,
                self.protocol_param_count,
            ),
        })
    }

    /// Internal helper: produce (gindex, node_value, branch) for a whole-param proof.
    fn protocol_param_item_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.protocol_param_tree.depth();
        let node_index =
            self.protocol_param_tree.capacity() / PROTOCOL_PARAM_FIELDS_PER_ITEM + slot;
        let node_value = self.protocol_param_tree.get_node(node_index);

        let td = self.top.depth();
        let top_gindex = (1u64 << td) + PROTOCOL_PARAM_CHANGES_ROOT as u64;
        let gindex = (top_gindex << sd) | (slot as u64);

        let mut branch = self
            .protocol_param_tree
            .generate_proof_from_node(node_index);
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(self.protocol_param_count as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(PROTOCOL_PARAM_CHANGES_ROOT));

        (gindex, node_value, branch)
    }

    /// Generate a proof for an added validator identified by node key.
    ///
    /// Searches the flattened added-validators list (epochs in ascending
    /// order, then insertion order within each epoch) for a matching
    /// `node_key` and returns the proof for the first match.
    pub fn generate_added_validator_proof_by_key(
        &self,
        node_key: &PublicKey,
        added_validators: &BTreeMap<u64, Vec<AddedValidator>>,
    ) -> Option<SszProof> {
        let index = added_validators
            .values()
            .flat_map(|v| v.iter())
            .position(|av| &av.node_key == node_key)?;
        self.generate_added_validator_proof(index)
    }

    /// Generate a proof for a removed validator identified by node key.
    ///
    /// Searches the removed-validators list for a matching key and
    /// returns the proof for the first match.
    pub fn generate_removed_validator_proof_by_key(
        &self,
        node_key: &PublicKey,
        removed_validators: &[PublicKey],
    ) -> Option<SszProof> {
        let index = removed_validators.iter().position(|k| k == node_key)?;
        self.generate_removed_validator_proof(index)
    }

    /// Generate a proof for an added validator at a given flattened index (whole item).
    ///
    /// The proof leaf is the per-item subtree root (internal node 1 level
    /// above the field leaves). The branch is 1 element shorter than a
    /// field-level proof.
    pub fn generate_added_validator_proof(&self, index: usize) -> Option<SszProof> {
        if index >= self.added_validator_count {
            return None;
        }
        let (gindex, node_value, branch) = self.added_validator_item_proof(index);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a proof for a single field of an added validator.
    pub fn generate_added_validator_field_proof(
        &self,
        index: usize,
        field_index: usize,
    ) -> Option<SszProof> {
        if index >= self.added_validator_count || field_index >= ADDED_VALIDATOR_FIELDS_PER_ITEM {
            return None;
        }
        let leaf_index = index * ADDED_VALIDATOR_FIELDS_PER_ITEM + field_index;
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                ADDED_VALIDATORS_ROOT,
                &self.added_validator_tree,
                leaf_index,
            ),
            leaf: self.added_validator_tree.get_leaf(leaf_index),
            branch: self.build_collection_branch(
                ADDED_VALIDATORS_ROOT,
                &self.added_validator_tree,
                leaf_index,
                self.added_validator_count,
            ),
        })
    }

    /// Generate a field-level proof for an added validator identified by node key.
    pub fn generate_added_validator_field_proof_by_key(
        &self,
        node_key: &PublicKey,
        field_index: usize,
        added_validators: &BTreeMap<u64, Vec<AddedValidator>>,
    ) -> Option<SszProof> {
        let index = added_validators
            .values()
            .flat_map(|v| v.iter())
            .position(|av| &av.node_key == node_key)?;
        self.generate_added_validator_field_proof(index, field_index)
    }

    /// Internal helper: produce (gindex, node_value, branch) for a whole-added-validator proof.
    fn added_validator_item_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.added_validator_tree.depth();
        let node_index =
            self.added_validator_tree.capacity() / ADDED_VALIDATOR_FIELDS_PER_ITEM + slot;
        let node_value = self.added_validator_tree.get_node(node_index);

        let td = self.top.depth();
        let top_gindex = (1u64 << td) + ADDED_VALIDATORS_ROOT as u64;
        let gindex = (top_gindex << sd) | (slot as u64);

        let mut branch = self
            .added_validator_tree
            .generate_proof_from_node(node_index);
        let mut length_bytes = [0u8; 32];
        length_bytes[0..8].copy_from_slice(&(self.added_validator_count as u64).to_le_bytes());
        branch.push(length_bytes);
        branch.extend_from_slice(&self.top.generate_proof(ADDED_VALIDATORS_ROOT));

        (gindex, node_value, branch)
    }

    /// Generate a proof for a removed validator at a given index.
    pub fn generate_removed_validator_proof(&self, index: usize) -> Option<SszProof> {
        if index >= self.removed_validator_count {
            return None;
        }
        Some(SszProof {
            gindex: self.compose_collection_gindex(
                REMOVED_VALIDATORS_ROOT,
                &self.removed_validator_tree,
                index,
            ),
            leaf: self.removed_validator_tree.get_leaf(index),
            branch: self.build_collection_branch(
                REMOVED_VALIDATORS_ROOT,
                &self.removed_validator_tree,
                index,
                self.removed_validator_count,
            ),
        })
    }

    /// Validator subtree depth.
    pub fn validator_tree_depth(&self) -> usize {
        self.validator_tree.depth()
    }

    /// Top-level tree depth.
    pub fn top_tree_depth(&self) -> usize {
        self.top.depth()
    }
}

impl Default for SszStateTree {
    fn default() -> Self {
        Self::new()
    }
}

// --- Proof types ---

/// Unified SSZ Merkle proof using a generalized index.
///
/// The generalized index encodes the full path from root to leaf,
/// including any nested subtrees and mix_in_length layers.
/// This handles both scalar fields and collection elements uniformly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SszProof {
    /// Generalized index of the leaf in the full state tree.
    pub gindex: u64,
    /// The 32-byte leaf value (hash_tree_root of the proven element).
    pub leaf: [u8; 32],
    /// Sibling hashes from leaf to root (bottom-up).
    pub branch: Vec<[u8; 32]>,
}

impl SszProof {
    /// Verify this proof against a state root.
    pub fn verify(&self, state_root: &[u8; 32]) -> bool {
        SszTree::verify_proof_gindex(state_root, self.gindex, &self.leaf, &self.branch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::execution_request::DepositRequest;
    use crate::withdrawal::{PendingWithdrawal, WithdrawalQueue};
    use alloy_eips::eip4895::Withdrawal;
    use alloy_primitives::Address;
    use commonware_cryptography::Signer;
    use commonware_cryptography::{bls12381, ed25519};

    fn make_validator(seed: u64) -> ([u8; 32], ValidatorAccount) {
        let mut pubkey = [0u8; 32];
        pubkey[0..8].copy_from_slice(&seed.to_le_bytes());
        let consensus_key = bls12381::PrivateKey::from_seed(seed).public_key();
        let account = ValidatorAccount {
            consensus_public_key: consensus_key,
            withdrawal_credentials: Address::from([seed as u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 0,
        };
        (pubkey, account)
    }

    #[test]
    fn new_tree_deterministic() {
        assert_eq!(SszStateTree::new().root(), SszStateTree::new().root());
    }

    #[test]
    fn set_epoch_changes_root() {
        let mut tree = SszStateTree::new();
        let r0 = tree.root();
        tree.set_epoch(42);
        assert_ne!(tree.root(), r0);
    }

    #[test]
    fn set_epoch_deterministic() {
        let mut a = SszStateTree::new();
        let mut b = SszStateTree::new();
        a.set_epoch(42);
        b.set_epoch(42);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn different_epochs_different_roots() {
        let mut a = SszStateTree::new();
        let mut b = SszStateTree::new();
        a.set_epoch(1);
        b.set_epoch(2);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn each_scalar_field_changes_root() {
        let mut tree = SszStateTree::new();
        let r0 = tree.root();

        tree.set_view(1);
        assert_ne!(tree.root(), r0);
        let r1 = tree.root();

        tree.set_latest_height(5);
        assert_ne!(tree.root(), r1);
        let r2 = tree.root();

        tree.set_head_digest(&[1u8; 32]);
        assert_ne!(tree.root(), r2);
        let r3 = tree.root();

        tree.set_epoch_genesis_hash(&[2u8; 32]);
        assert_ne!(tree.root(), r3);
        let r4 = tree.root();

        tree.set_validator_minimum_stake(100);
        assert_ne!(tree.root(), r4);
        let r5 = tree.root();

        tree.set_validator_maximum_stake(200);
        assert_ne!(tree.root(), r5);
        let r6 = tree.root();

        tree.set_next_withdrawal_index(7);
        assert_ne!(tree.root(), r6);
        let r7 = tree.root();

        tree.set_forkchoice_head_block_hash(&[3u8; 32]);
        assert_ne!(tree.root(), r7);
        let r8 = tree.root();

        tree.set_forkchoice_safe_block_hash(&[4u8; 32]);
        assert_ne!(tree.root(), r8);
        let r9 = tree.root();

        tree.set_forkchoice_finalized_block_hash(&[5u8; 32]);
        assert_ne!(tree.root(), r9);
    }

    #[test]
    fn add_validator_changes_root() {
        let mut tree = SszStateTree::new();
        let r0 = tree.root();
        let (pk, acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc);
        tree.rebuild_validators(&accounts);
        assert_ne!(tree.root(), r0);
    }

    #[test]
    fn update_validator_balance_changes_root() {
        let mut tree = SszStateTree::new();
        let (pk, mut acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc.clone());
        tree.rebuild_validators(&accounts);
        let r1 = tree.root();

        acc.balance = 64_000_000_000;
        accounts.insert(pk, acc);
        tree.rebuild_validators(&accounts);
        assert_ne!(tree.root(), r1);
    }

    #[test]
    fn remove_validator_changes_root() {
        let mut tree = SszStateTree::new();
        let (pk, acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc);
        tree.rebuild_validators(&accounts);
        let r1 = tree.root();

        accounts.remove(&pk);
        tree.rebuild_validators(&accounts);
        assert_ne!(tree.root(), r1);
        assert_eq!(tree.validator_count(), 0);
    }

    #[test]
    fn scalar_proof_verifies() {
        let mut tree = SszStateTree::new();
        tree.set_epoch(42);
        tree.set_view(7);
        tree.set_latest_height(100);

        let root = tree.root();
        let proof = tree.generate_scalar_proof(EPOCH);
        assert!(proof.verify(&root));
        // Check gindex: top depth is 5, EPOCH is leaf 0 → gindex = 32
        assert_eq!(proof.gindex, (1u64 << tree.top_tree_depth()) + EPOCH as u64);

        let proof_view = tree.generate_scalar_proof(VIEW);
        assert!(proof_view.verify(&root));
    }

    #[test]
    fn scalar_proof_fails_wrong_root() {
        let mut tree = SszStateTree::new();
        tree.set_epoch(42);
        let proof = tree.generate_scalar_proof(EPOCH);
        assert!(!proof.verify(&[0xFF; 32]));
    }

    #[test]
    fn validator_proof_verifies() {
        let mut tree = SszStateTree::new();
        let (pk1, acc1) = make_validator(1);
        let (pk2, acc2) = make_validator(2);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk1, acc1);
        accounts.insert(pk2, acc2);
        tree.rebuild_validators(&accounts);

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let proof = tree.generate_validator_proof(&pk1, &keys).unwrap();
        assert!(proof.verify(&root));
    }

    #[test]
    fn validator_proof_fails_wrong_root() {
        let mut tree = SszStateTree::new();
        let (pk, acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc);
        tree.rebuild_validators(&accounts);

        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let proof = tree.generate_validator_proof(&pk, &keys).unwrap();
        assert!(!proof.verify(&[0xFF; 32]));
    }

    #[test]
    fn validator_proof_unknown_pubkey_returns_none() {
        let tree = SszStateTree::new();
        assert!(tree.generate_validator_proof(&[99u8; 32], &[]).is_none());
    }

    #[test]
    fn rebuild_matches_incremental() {
        let (pk1, acc1) = make_validator(1);
        let (pk2, acc2) = make_validator(2);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk1, acc1);
        accounts.insert(pk2, acc2);

        // Build incrementally
        let mut inc = SszStateTree::new();
        inc.set_epoch(10);
        inc.set_view(3);
        inc.set_latest_height(100);
        inc.set_head_digest(&[0xAA; 32]);
        inc.set_epoch_genesis_hash(&[0xBB; 32]);
        inc.set_validator_minimum_stake(32_000_000_000);
        inc.set_validator_maximum_stake(64_000_000_000);
        inc.set_next_withdrawal_index(5);
        inc.set_forkchoice_head_block_hash(&[0xCC; 32]);
        inc.set_forkchoice_safe_block_hash(&[0xDD; 32]);
        inc.set_forkchoice_finalized_block_hash(&[0xEE; 32]);
        inc.rebuild_validators(&accounts);
        inc.rebuild_deposits(&VecDeque::new());
        inc.rebuild_withdrawals(&WithdrawalQueue::default());
        inc.rebuild_protocol_params(&[]);
        inc.rebuild_added_validators(&BTreeMap::new());
        inc.rebuild_removed_validators(&[]);

        // Build via rebuild
        let mut rb = SszStateTree::new();
        rb.rebuild(
            10,
            3,
            100,
            &[0xAA; 32],
            &[0xBB; 32],
            32_000_000_000,
            64_000_000_000,
            5,
            &[0xCC; 32],
            &[0xDD; 32],
            &[0xEE; 32],
            &accounts,
            &VecDeque::new(),
            &WithdrawalQueue::default(),
            &[],
            &BTreeMap::new(),
            &[],
        );

        assert_eq!(inc.root(), rb.root());
    }

    #[test]
    fn rebuild_proof_still_valid() {
        let (pk1, acc1) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk1, acc1);

        let mut tree = SszStateTree::new();
        tree.rebuild(
            1,
            0,
            0,
            &[0u8; 32],
            &[0u8; 32],
            32_000_000_000,
            32_000_000_000,
            0,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &accounts,
            &VecDeque::new(),
            &WithdrawalQueue::default(),
            &[],
            &BTreeMap::new(),
            &[],
        );

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let proof = tree.generate_validator_proof(&pk1, &keys).unwrap();
        assert!(proof.verify(&root));

        let scalar_proof = tree.generate_scalar_proof(EPOCH);
        assert!(scalar_proof.verify(&root));
    }

    #[test]
    fn many_validators_proof() {
        let mut tree = SszStateTree::new();
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=100u64).map(|i| make_validator(i)).collect();

        let mut accounts = BTreeMap::new();
        for (pk, acc) in &validators {
            accounts.insert(*pk, acc.clone());
        }
        tree.rebuild_validators(&accounts);

        let root = tree.root();
        assert_eq!(tree.validator_count(), 100);

        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        // Verify proof for each validator
        for (pk, _) in &validators {
            let proof = tree.generate_validator_proof(pk, &keys).unwrap();
            assert!(proof.verify(&root), "proof failed for validator");
        }
    }

    #[test]
    fn add_remove_add_consistent() {
        let mut tree = SszStateTree::new();
        let (pk1, acc1) = make_validator(1);
        let (pk2, acc2) = make_validator(2);
        let (pk3, acc3) = make_validator(3);

        let mut accounts = BTreeMap::new();
        accounts.insert(pk1, acc1);
        accounts.insert(pk2, acc2);
        tree.rebuild_validators(&accounts);

        // Remove pk1, add pk3
        accounts.remove(&pk1);
        accounts.insert(pk3, acc3);
        tree.rebuild_validators(&accounts);
        assert_eq!(tree.validator_count(), 2);

        // Verify proofs still work
        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let proof2 = tree.generate_validator_proof(&pk2, &keys).unwrap();
        assert!(proof2.verify(&root));
        let proof3 = tree.generate_validator_proof(&pk3, &keys).unwrap();
        assert!(proof3.verify(&root));
        assert!(tree.generate_validator_proof(&pk1, &keys).is_none());
    }

    #[test]
    fn deposit_proof_verifies() {
        let deposit = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let mut deposits = VecDeque::new();
        deposits.push_back(deposit);

        let mut tree = SszStateTree::new();
        tree.rebuild_deposits(&deposits);
        // Also set a scalar so the root isn't trivial
        tree.set_epoch(1);

        let root = tree.root();
        let proof = tree.generate_deposit_proof(0).unwrap();
        assert!(proof.verify(&root));
    }

    #[test]
    fn deposit_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        assert!(tree.generate_deposit_proof(0).is_none());
    }

    #[test]
    fn withdrawal_proof_verifies() {
        let mut queue = WithdrawalQueue::default();
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: pk1,
            balance_deduction: 1_000_000_000,
            epoch: 1,
        });
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 1,
                address: Address::from([0x22; 20]),
                amount: 2_000_000_000,
            },
            pubkey: pk2,
            balance_deduction: 2_000_000_000,
            epoch: 1,
        });

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);
        tree.set_epoch(5);

        let root = tree.root();

        let proof1 = tree.generate_withdrawal_proof_by_key(&pk1, &queue).unwrap();
        assert!(proof1.verify(&root));

        let proof2 = tree.generate_withdrawal_proof_by_key(&pk2, &queue).unwrap();
        assert!(proof2.verify(&root));
    }

    #[test]
    fn withdrawal_proof_unknown_key() {
        let tree = SszStateTree::new();
        assert!(tree.generate_withdrawal_proof(0).is_none());
    }

    #[test]
    fn deposit_field_proof_verifies() {
        let deposit = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let mut deposits = VecDeque::new();
        deposits.push_back(deposit);

        let mut tree = SszStateTree::new();
        tree.rebuild_deposits(&deposits);
        tree.set_epoch(1);

        let root = tree.root();

        // Verify field proofs for every field
        for field_idx in 0..DEPOSIT_FIELDS_PER_ITEM {
            let proof = tree.generate_deposit_field_proof(0, field_idx).unwrap();
            assert!(
                proof.verify(&root),
                "deposit field proof failed for field {field_idx}"
            );
        }

        // Field proof branch is 3 elements longer than whole-item proof
        let item_proof = tree.generate_deposit_proof(0).unwrap();
        let field_proof = tree
            .generate_deposit_field_proof(0, DEPOSIT_FIELD_AMOUNT)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 3,
            "field branch should be 3 longer than item branch"
        );
    }

    #[test]
    fn deposit_item_proof_leaf_matches_hash_tree_root() {
        let deposit = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let mut deposits = VecDeque::new();
        deposits.push_back(deposit.clone());

        let mut tree = SszStateTree::new();
        tree.rebuild_deposits(&deposits);

        let proof = tree.generate_deposit_proof(0).unwrap();
        assert_eq!(proof.leaf, deposit.hash_tree_root());
    }

    #[test]
    fn deposit_field_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        assert!(tree.generate_deposit_field_proof(0, 0).is_none());

        // Invalid field index

        let deposit = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let mut deposits = VecDeque::new();
        deposits.push_back(deposit);
        let mut tree = SszStateTree::new();
        tree.rebuild_deposits(&deposits);
        assert!(tree.generate_deposit_field_proof(0, 8).is_none());
    }

    #[test]
    fn withdrawal_field_proof_verifies() {
        let mut queue = WithdrawalQueue::default();
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: pk1,
            balance_deduction: 1_000_000_000,
            epoch: 1,
        });
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 1,
                address: Address::from([0x22; 20]),
                amount: 2_000_000_000,
            },
            pubkey: pk2,
            balance_deduction: 2_000_000_000,
            epoch: 1,
        });

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);
        tree.set_epoch(5);

        let root = tree.root();

        // Verify field proofs for every withdrawal, every field
        for i in 0..2 {
            for field_idx in 0..WITHDRAWAL_FIELDS_PER_ITEM {
                let proof = tree.generate_withdrawal_field_proof(i, field_idx).unwrap();
                assert!(
                    proof.verify(&root),
                    "withdrawal {i} field proof failed for field {field_idx}"
                );
            }
        }

        // Field proof branch is 3 elements longer than whole-item proof
        let item_proof = tree.generate_withdrawal_proof(0).unwrap();
        let field_proof = tree
            .generate_withdrawal_field_proof(0, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 3,
            "field branch should be 3 longer than item branch"
        );
    }

    #[test]
    fn withdrawal_item_proof_leaf_matches_hash_tree_root() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
        };
        let mut queue = WithdrawalQueue::default();
        queue.push(withdrawal.clone());

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);

        let proof = tree.generate_withdrawal_proof(0).unwrap();
        assert_eq!(proof.leaf, withdrawal.hash_tree_root());
    }

    #[test]
    fn withdrawal_field_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        assert!(tree.generate_withdrawal_field_proof(0, 0).is_none());
    }

    #[test]
    fn validator_field_proof_verifies() {
        let mut tree = SszStateTree::new();
        let (pk1, acc1) = make_validator(1);
        let (pk2, acc2) = make_validator(2);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk1, acc1.clone());
        accounts.insert(pk2, acc2);
        tree.rebuild_validators(&accounts);

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        // Prove each field of validator pk1
        for field_idx in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
            let proof = tree
                .generate_validator_field_proof(&pk1, field_idx, &keys)
                .unwrap();
            assert!(
                proof.verify(&root),
                "field proof failed for field {field_idx}"
            );
        }
    }

    #[test]
    fn validator_field_proof_has_correct_leaf() {
        let mut tree = SszStateTree::new();
        let (pk, acc) = make_validator(42);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc.clone());
        tree.rebuild_validators(&accounts);

        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        // Balance field should have the SSZ hash_tree_root of the balance
        let balance_proof = tree
            .generate_validator_field_proof(&pk, VALIDATOR_FIELD_BALANCE, &keys)
            .unwrap();
        assert_eq!(balance_proof.leaf, acc.balance.hash_tree_root());

        // Status field
        let status_proof = tree
            .generate_validator_field_proof(&pk, VALIDATOR_FIELD_STATUS, &keys)
            .unwrap();
        assert_eq!(status_proof.leaf, acc.status.hash_tree_root());
    }

    #[test]
    fn validator_field_proof_longer_than_account_proof() {
        let mut tree = SszStateTree::new();
        let (pk, acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc);
        tree.rebuild_validators(&accounts);

        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let account_proof = tree.generate_validator_proof(&pk, &keys).unwrap();
        let field_proof = tree.generate_validator_field_proof(&pk, 0, &keys).unwrap();

        // Field proof branch is 3 elements longer (depth-3 per-validator subtree)
        assert_eq!(
            field_proof.branch.len(),
            account_proof.branch.len() + 3,
            "field branch should be 3 longer than account branch"
        );
    }

    #[test]
    fn validator_account_proof_leaf_matches_hash_tree_root() {
        let mut tree = SszStateTree::new();
        let (pk, acc) = make_validator(1);
        let mut accounts = BTreeMap::new();
        accounts.insert(pk, acc.clone());
        tree.rebuild_validators(&accounts);

        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
        let proof = tree.generate_validator_proof(&pk, &keys).unwrap();

        // The proof leaf should be hash_tree_root(account), computed from the
        // internal node which is the root of the 8-field subtree
        assert_eq!(proof.leaf, acc.hash_tree_root());
    }

    #[test]
    fn many_validators_field_proofs() {
        let mut tree = SszStateTree::new();
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=20u64).map(|i| make_validator(i)).collect();
        let mut accounts = BTreeMap::new();
        for (pk, acc) in &validators {
            accounts.insert(*pk, acc.clone());
        }
        tree.rebuild_validators(&accounts);

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        // Verify field proofs for every validator, every field
        for (pk, _) in &validators {
            for field_idx in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
                let proof = tree
                    .generate_validator_field_proof(pk, field_idx, &keys)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "field proof failed for field {field_idx}"
                );
            }
        }
    }

    /// Helper: build a tree from accounts using rebuild_validators (the reference path).
    fn rebuild_tree(accounts: &BTreeMap<[u8; 32], ValidatorAccount>) -> SszStateTree {
        let mut tree = SszStateTree::new();
        tree.rebuild_validators(accounts);
        tree
    }

    // ── Insert / remove tests ──────────────────────────────────────────

    /// Insert N validators one-by-one and compare against full rebuild.
    fn assert_incremental_insert_matches_rebuild(count: u64) {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=count).map(|i| make_validator(i)).collect();

        let mut inc_tree = SszStateTree::new();
        let mut accounts = BTreeMap::new();
        for (pk, acc) in &validators {
            accounts.insert(*pk, acc.clone());
            let slot = accounts.keys().position(|k| k == pk).unwrap();
            inc_tree.insert_validator_at_slot(slot, acc);
        }

        let ref_tree = rebuild_tree(&accounts);
        assert_eq!(
            inc_tree.root(),
            ref_tree.root(),
            "insert: incremental != rebuild after inserting {count} validators",
        );
    }

    #[test]
    fn insert_matches_rebuild_1() {
        assert_incremental_insert_matches_rebuild(1);
    }

    #[test]
    fn insert_matches_rebuild_2() {
        assert_incremental_insert_matches_rebuild(2);
    }

    #[test]
    fn insert_matches_rebuild_7() {
        assert_incremental_insert_matches_rebuild(7);
    }

    #[test]
    fn insert_matches_rebuild_8() {
        assert_incremental_insert_matches_rebuild(8);
    }

    #[test]
    fn insert_matches_rebuild_9() {
        assert_incremental_insert_matches_rebuild(9);
    }

    #[test]
    fn insert_matches_rebuild_16() {
        assert_incremental_insert_matches_rebuild(16);
    }

    #[test]
    fn insert_matches_rebuild_17() {
        assert_incremental_insert_matches_rebuild(17);
    }

    #[test]
    fn insert_matches_rebuild_100() {
        assert_incremental_insert_matches_rebuild(100);
    }

    /// Insert a single validator at every possible slot position in a tree
    /// of size N and verify each matches rebuild.
    #[test]
    fn insert_at_every_position() {
        let base_validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=8u64).map(|i| make_validator(i)).collect();
        let base_accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            base_validators.iter().cloned().collect();

        // Insert a new validator — its BTreeMap slot depends on its pubkey,
        // so we try many seeds to cover different insertion positions.
        for seed in 100..120u64 {
            let (new_pk, new_acc) = make_validator(seed);
            let mut accounts = base_accounts.clone();
            accounts.insert(new_pk, new_acc.clone());
            let slot = accounts.keys().position(|k| k == &new_pk).unwrap();

            let mut tree = rebuild_tree(&base_accounts);
            tree.insert_validator_at_slot(slot, &new_acc);

            let ref_tree = rebuild_tree(&accounts);
            assert_eq!(
                tree.root(),
                ref_tree.root(),
                "insert seed {seed} at slot {slot}: incremental != rebuild",
            );
        }
    }

    /// Remove every validator one-by-one from a tree and compare each
    /// intermediate state against a full rebuild.
    #[test]
    fn remove_all_one_by_one() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=10u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        // Remove in BTreeMap order (first key each time) to test slot 0 removal repeatedly
        while !accounts.is_empty() {
            let pk = *accounts.keys().next().unwrap();
            let slot = accounts.keys().position(|k| k == &pk).unwrap();
            accounts.remove(&pk);
            tree.remove_validator_at_slot(slot);

            let ref_tree = rebuild_tree(&accounts);
            assert_eq!(
                tree.validator_count(),
                accounts.len(),
                "count mismatch after removing, {} remaining",
                accounts.len()
            );
            assert_eq!(
                tree.root(),
                ref_tree.root(),
                "remove: incremental != rebuild with {} remaining",
                accounts.len()
            );
        }
    }

    /// Remove from the last slot each time (shrinking from the end).
    #[test]
    fn remove_from_end_one_by_one() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=10u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        while !accounts.is_empty() {
            let pk = *accounts.keys().next_back().unwrap();
            let slot = accounts.len() - 1;
            accounts.remove(&pk);
            tree.remove_validator_at_slot(slot);

            let ref_tree = rebuild_tree(&accounts);
            assert_eq!(
                tree.root(),
                ref_tree.root(),
                "remove from end: incremental != rebuild with {} remaining",
                accounts.len()
            );
        }
    }

    /// Remove a single validator at every possible slot position.
    #[test]
    fn remove_at_every_position() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=10u64).map(|i| make_validator(i)).collect();
        let accounts: BTreeMap<[u8; 32], ValidatorAccount> = validators.iter().cloned().collect();
        let sorted_keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        for slot in 0..sorted_keys.len() {
            let mut accs = accounts.clone();
            let mut tree = rebuild_tree(&accs);
            accs.remove(&sorted_keys[slot]);
            tree.remove_validator_at_slot(slot);

            let ref_tree = rebuild_tree(&accs);
            assert_eq!(
                tree.root(),
                ref_tree.root(),
                "remove at slot {slot}/{}: incremental != rebuild",
                sorted_keys.len()
            );
        }
    }

    /// Removals that cross power-of-two capacity boundaries (shrink triggers).
    #[test]
    fn remove_across_capacity_boundaries() {
        // 9→8 (capacity 128→64 leaves), 5→4 (64→32), 3→2 (32→16), 2→1 (16→8)
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=9u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        while accounts.len() > 1 {
            // Always remove the last key (end slot)
            let pk = *accounts.keys().next_back().unwrap();
            let slot = accounts.len() - 1;
            accounts.remove(&pk);
            tree.remove_validator_at_slot(slot);

            let ref_tree = rebuild_tree(&accounts);
            assert_eq!(
                tree.root(),
                ref_tree.root(),
                "shrink boundary: incremental != rebuild at {} validators",
                accounts.len()
            );
        }
    }

    /// Insert then remove the same validator — root should match original.
    #[test]
    fn insert_remove_round_trip() {
        for base_count in [1u64, 3, 7, 8, 15, 16] {
            let validators: Vec<([u8; 32], ValidatorAccount)> =
                (1..=base_count).map(|i| make_validator(i)).collect();
            let accounts: BTreeMap<[u8; 32], ValidatorAccount> =
                validators.iter().cloned().collect();
            let tree = rebuild_tree(&accounts);
            let original_root = tree.root();

            let (new_pk, new_acc) = make_validator(99);
            let mut modified = tree.clone();
            let mut modified_accounts = accounts.clone();
            modified_accounts.insert(new_pk, new_acc.clone());
            let slot = modified_accounts.keys().position(|k| k == &new_pk).unwrap();
            modified.insert_validator_at_slot(slot, &new_acc);

            assert_ne!(
                modified.root(),
                original_root,
                "root should change after insert (base_count={base_count})"
            );

            modified_accounts.remove(&new_pk);
            modified.remove_validator_at_slot(slot);

            assert_eq!(
                modified.root(),
                original_root,
                "round trip failed (base_count={base_count})"
            );
        }
    }

    /// Remove then re-insert the same validator — root should match original.
    #[test]
    fn remove_insert_round_trip() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=8u64).map(|i| make_validator(i)).collect();
        let accounts: BTreeMap<[u8; 32], ValidatorAccount> = validators.iter().cloned().collect();
        let sorted_keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        for slot in 0..sorted_keys.len() {
            let tree = rebuild_tree(&accounts);
            let original_root = tree.root();

            let pk = sorted_keys[slot];
            let acc = accounts[&pk].clone();

            let mut modified = tree.clone();
            modified.remove_validator_at_slot(slot);
            modified.insert_validator_at_slot(slot, &acc);

            assert_eq!(
                modified.root(),
                original_root,
                "remove+re-insert at slot {slot}: root changed"
            );
        }
    }

    /// Insert two validators, then remove them in reverse order.
    #[test]
    fn insert_two_remove_two_round_trip() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=5u64).map(|i| make_validator(i)).collect();
        let accounts: BTreeMap<[u8; 32], ValidatorAccount> = validators.iter().cloned().collect();
        let tree = rebuild_tree(&accounts);
        let original_root = tree.root();

        let (pk_a, acc_a) = make_validator(50);
        let (pk_b, acc_b) = make_validator(60);

        let mut modified = tree.clone();
        let mut modified_accounts = accounts.clone();

        // Insert A
        modified_accounts.insert(pk_a, acc_a.clone());
        let slot_a = modified_accounts.keys().position(|k| k == &pk_a).unwrap();
        modified.insert_validator_at_slot(slot_a, &acc_a);

        // Insert B
        modified_accounts.insert(pk_b, acc_b.clone());
        let slot_b = modified_accounts.keys().position(|k| k == &pk_b).unwrap();
        modified.insert_validator_at_slot(slot_b, &acc_b);

        // Verify intermediate state matches rebuild
        let ref_tree = rebuild_tree(&modified_accounts);
        assert_eq!(
            modified.root(),
            ref_tree.root(),
            "after 2 inserts: mismatch"
        );

        // Remove B then A
        let slot_b = modified_accounts.keys().position(|k| k == &pk_b).unwrap();
        modified_accounts.remove(&pk_b);
        modified.remove_validator_at_slot(slot_b);

        let slot_a = modified_accounts.keys().position(|k| k == &pk_a).unwrap();
        modified_accounts.remove(&pk_a);
        modified.remove_validator_at_slot(slot_a);

        assert_eq!(
            modified.root(),
            original_root,
            "insert 2 then remove 2: round trip failed"
        );
    }

    /// Insert a validator, then update its balance, verify matches rebuild.
    #[test]
    fn insert_then_update_matches_rebuild() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=5u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        // Insert new validator
        let (new_pk, mut new_acc) = make_validator(42);
        accounts.insert(new_pk, new_acc.clone());
        let slot = accounts.keys().position(|k| k == &new_pk).unwrap();
        tree.insert_validator_at_slot(slot, &new_acc);

        // Update its balance
        new_acc.balance = 64_000_000_000;
        accounts.insert(new_pk, new_acc.clone());
        tree.update_validator_at_slot(slot, &new_acc);

        let ref_tree = rebuild_tree(&accounts);
        assert_eq!(
            tree.root(),
            ref_tree.root(),
            "insert + update: incremental != rebuild"
        );
    }

    /// Grow from 0 to 20 via incremental inserts, crossing multiple
    /// capacity doublings (8→16→32→64→128→256 leaves).
    #[test]
    fn grow_across_multiple_doublings() {
        let mut inc_tree = SszStateTree::new();
        let mut accounts = BTreeMap::new();

        for i in 1..=20u64 {
            let (pk, acc) = make_validator(i);
            accounts.insert(pk, acc.clone());
            let slot = accounts.keys().position(|k| k == &pk).unwrap();
            inc_tree.insert_validator_at_slot(slot, &acc);

            let ref_tree = rebuild_tree(&accounts);
            assert_eq!(
                inc_tree.root(),
                ref_tree.root(),
                "grow: mismatch at {i} validators"
            );
        }
    }

    /// Interleaved inserts and removes — random-ish operation sequence.
    #[test]
    fn interleaved_insert_remove() {
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> = BTreeMap::new();
        let mut tree = SszStateTree::new();

        // Insert 5
        for i in 1..=5u64 {
            let (pk, acc) = make_validator(i);
            accounts.insert(pk, acc.clone());
            let slot = accounts.keys().position(|k| k == &pk).unwrap();
            tree.insert_validator_at_slot(slot, &acc);
        }

        // Remove 2nd
        let pk2 = {
            let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
            keys[1]
        };
        accounts.remove(&pk2);
        tree.remove_validator_at_slot(1);

        // Insert 3 more
        for i in 10..=12u64 {
            let (pk, acc) = make_validator(i);
            accounts.insert(pk, acc.clone());
            let slot = accounts.keys().position(|k| k == &pk).unwrap();
            tree.insert_validator_at_slot(slot, &acc);
        }

        // Remove first
        let pk0 = *accounts.keys().next().unwrap();
        accounts.remove(&pk0);
        tree.remove_validator_at_slot(0);

        // Remove last
        let pk_last = *accounts.keys().next_back().unwrap();
        let last_slot = accounts.len() - 1;
        accounts.remove(&pk_last);
        tree.remove_validator_at_slot(last_slot);

        // Insert 2 more
        for i in 20..=21u64 {
            let (pk, acc) = make_validator(i);
            accounts.insert(pk, acc.clone());
            let slot = accounts.keys().position(|k| k == &pk).unwrap();
            tree.insert_validator_at_slot(slot, &acc);
        }

        let ref_tree = rebuild_tree(&accounts);
        assert_eq!(
            tree.root(),
            ref_tree.root(),
            "interleaved: incremental != rebuild ({} validators)",
            accounts.len()
        );
        assert_eq!(tree.validator_count(), accounts.len());
    }

    /// Proofs generated after incremental insert must verify against root.
    #[test]
    fn proofs_valid_after_insert() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=5u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        let (new_pk, new_acc) = make_validator(42);
        accounts.insert(new_pk, new_acc.clone());
        let slot = accounts.keys().position(|k| k == &new_pk).unwrap();
        tree.insert_validator_at_slot(slot, &new_acc);

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        // Verify proofs for every validator (including the newly inserted one)
        for pk in &keys {
            for field_idx in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
                let proof = tree
                    .generate_validator_field_proof(pk, field_idx, &keys)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "proof failed for pk {:?} field {field_idx} after insert",
                    &pk[..4]
                );
            }
        }
    }

    // ── Collection subtree proof tests ─────────────────────────────────

    #[test]
    fn protocol_param_proof_verifies() {
        let params = vec![
            ProtocolParam::MinimumStake(1_000_000),
            ProtocolParam::MaximumStake(64_000_000_000),
            ProtocolParam::MinimumStake(2_000_000),
        ];
        let mut tree = SszStateTree::new();
        tree.rebuild_protocol_params(&params);
        let root = tree.root();

        for i in 0..params.len() {
            let proof = tree.generate_protocol_param_proof(i).unwrap();
            assert_eq!(proof.leaf, params[i].hash_tree_root());
            assert!(proof.verify(&root), "protocol param proof {i} failed");
        }

        assert!(tree.generate_protocol_param_proof(params.len()).is_none());
    }

    #[test]
    fn added_validator_proof_verifies() {
        let mut added: BTreeMap<u64, Vec<AddedValidator>> = BTreeMap::new();
        for epoch in [1u64, 3, 5] {
            let mut epoch_validators = Vec::new();
            for seed in 0..3u64 {
                let node_key = ed25519::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                let consensus_key =
                    bls12381::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                epoch_validators.push(AddedValidator {
                    node_key,
                    consensus_key,
                });
            }
            added.insert(epoch, epoch_validators);
        }

        let mut tree = SszStateTree::new();
        tree.rebuild_added_validators(&added);
        let root = tree.root();

        // Flattened items
        let items: Vec<AddedValidator> = added.values().flat_map(|v| v.iter().cloned()).collect();

        for i in 0..items.len() {
            let proof = tree.generate_added_validator_proof(i).unwrap();
            assert_eq!(proof.leaf, items[i].hash_tree_root());
            assert!(proof.verify(&root), "added validator proof {i} failed");
        }

        assert!(tree.generate_added_validator_proof(items.len()).is_none());
    }

    #[test]
    fn removed_validator_proof_verifies() {
        let removed: Vec<PublicKey> = (0..5u64)
            .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
            .collect();

        let mut tree = SszStateTree::new();
        tree.rebuild_removed_validators(&removed);
        let root = tree.root();

        for i in 0..removed.len() {
            let proof = tree.generate_removed_validator_proof(i).unwrap();
            assert_eq!(proof.leaf, removed[i].hash_tree_root());
            assert!(proof.verify(&root), "removed validator proof {i} failed");
        }

        assert!(
            tree.generate_removed_validator_proof(removed.len())
                .is_none()
        );
    }

    #[test]
    fn added_validator_proof_by_key() {
        let mut added: BTreeMap<u64, Vec<AddedValidator>> = BTreeMap::new();
        for epoch in [1u64, 3] {
            let mut epoch_validators = Vec::new();
            for seed in 0..2u64 {
                let node_key = ed25519::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                let consensus_key =
                    bls12381::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                epoch_validators.push(AddedValidator {
                    node_key,
                    consensus_key,
                });
            }
            added.insert(epoch, epoch_validators);
        }

        let mut tree = SszStateTree::new();
        tree.rebuild_added_validators(&added);
        let root = tree.root();

        // Look up by node key of the second validator in epoch 3 (flattened index 3)
        let target_key = &added[&3][1].node_key;
        let proof = tree
            .generate_added_validator_proof_by_key(target_key, &added)
            .unwrap();
        assert_eq!(proof.leaf, added[&3][1].hash_tree_root());
        assert!(proof.verify(&root));

        // Unknown key returns None
        let unknown_key = ed25519::PrivateKey::from_seed(9999).public_key();
        assert!(
            tree.generate_added_validator_proof_by_key(&unknown_key, &added)
                .is_none()
        );
    }

    #[test]
    fn removed_validator_proof_by_key() {
        let removed: Vec<PublicKey> = (0..4u64)
            .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
            .collect();

        let mut tree = SszStateTree::new();
        tree.rebuild_removed_validators(&removed);
        let root = tree.root();

        // Look up by key
        let proof = tree
            .generate_removed_validator_proof_by_key(&removed[2], &removed)
            .unwrap();
        assert_eq!(proof.leaf, removed[2].hash_tree_root());
        assert!(proof.verify(&root));

        // Unknown key returns None
        let unknown_key = ed25519::PrivateKey::from_seed(9999).public_key();
        assert!(
            tree.generate_removed_validator_proof_by_key(&unknown_key, &removed)
                .is_none()
        );
    }

    #[test]
    fn protocol_param_field_proof_verifies() {
        let params = vec![
            ProtocolParam::MinimumStake(1_000_000),
            ProtocolParam::MaximumStake(64_000_000_000),
        ];
        let mut tree = SszStateTree::new();
        tree.rebuild_protocol_params(&params);
        tree.set_epoch(1);
        let root = tree.root();

        // Verify field proofs for every param, every field
        for i in 0..params.len() {
            for field_idx in 0..PROTOCOL_PARAM_FIELDS_PER_ITEM {
                let proof = tree
                    .generate_protocol_param_field_proof(i, field_idx)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "protocol param {i} field {field_idx} proof failed"
                );
            }
        }

        // Field proof branch is 1 element longer than whole-item proof
        let item_proof = tree.generate_protocol_param_proof(0).unwrap();
        let field_proof = tree
            .generate_protocol_param_field_proof(0, PROTOCOL_PARAM_FIELD_VALUE)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 1,
            "field branch should be 1 longer than item branch"
        );

        // Out of bounds
        assert!(tree.generate_protocol_param_field_proof(0, 2).is_none());
        assert!(
            tree.generate_protocol_param_field_proof(params.len(), 0)
                .is_none()
        );
    }

    #[test]
    fn protocol_param_item_proof_leaf_matches_hash_tree_root() {
        let params = vec![ProtocolParam::MinimumStake(1_000_000)];
        let mut tree = SszStateTree::new();
        tree.rebuild_protocol_params(&params);

        let proof = tree.generate_protocol_param_proof(0).unwrap();
        assert_eq!(proof.leaf, params[0].hash_tree_root());
    }

    #[test]
    fn added_validator_field_proof_verifies() {
        let mut added: BTreeMap<u64, Vec<AddedValidator>> = BTreeMap::new();
        for epoch in [1u64, 3] {
            let mut epoch_validators = Vec::new();
            for seed in 0..2u64 {
                let node_key = ed25519::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                let consensus_key =
                    bls12381::PrivateKey::from_seed(epoch * 100 + seed).public_key();
                epoch_validators.push(AddedValidator {
                    node_key,
                    consensus_key,
                });
            }
            added.insert(epoch, epoch_validators);
        }

        let mut tree = SszStateTree::new();
        tree.rebuild_added_validators(&added);
        tree.set_epoch(1);
        let root = tree.root();

        let count = added.values().map(|v| v.len()).sum::<usize>();

        // Verify field proofs for every item, every field
        for i in 0..count {
            for field_idx in 0..ADDED_VALIDATOR_FIELDS_PER_ITEM {
                let proof = tree
                    .generate_added_validator_field_proof(i, field_idx)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "added validator {i} field {field_idx} proof failed"
                );
            }
        }

        // Field proof branch is 1 element longer than whole-item proof
        let item_proof = tree.generate_added_validator_proof(0).unwrap();
        let field_proof = tree
            .generate_added_validator_field_proof(0, ADDED_VALIDATOR_FIELD_NODE_KEY)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 1,
            "field branch should be 1 longer than item branch"
        );

        // Out of bounds
        assert!(tree.generate_added_validator_field_proof(0, 2).is_none());
        assert!(
            tree.generate_added_validator_field_proof(count, 0)
                .is_none()
        );
    }

    #[test]
    fn added_validator_item_proof_leaf_matches_hash_tree_root() {
        let av = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
        };
        let mut added: BTreeMap<u64, Vec<AddedValidator>> = BTreeMap::new();
        added.insert(1, vec![av.clone()]);

        let mut tree = SszStateTree::new();
        tree.rebuild_added_validators(&added);

        let proof = tree.generate_added_validator_proof(0).unwrap();
        assert_eq!(proof.leaf, av.hash_tree_root());
    }

    #[test]
    fn empty_collection_proofs_return_none() {
        let tree = SszStateTree::new();
        assert!(tree.generate_protocol_param_proof(0).is_none());
        assert!(tree.generate_added_validator_proof(0).is_none());
        assert!(tree.generate_removed_validator_proof(0).is_none());
    }

    #[test]
    fn collection_proof_after_rebuild() {
        let mut tree = SszStateTree::new();

        // First build
        let params_v1 = vec![ProtocolParam::MinimumStake(1_000)];
        tree.rebuild_protocol_params(&params_v1);
        let root_v1 = tree.root();
        let proof_v1 = tree.generate_protocol_param_proof(0).unwrap();
        assert!(proof_v1.verify(&root_v1));

        // Rebuild with different data
        let params_v2 = vec![
            ProtocolParam::MinimumStake(2_000),
            ProtocolParam::MaximumStake(99_000),
        ];
        tree.rebuild_protocol_params(&params_v2);
        let root_v2 = tree.root();

        assert_ne!(root_v1, root_v2);
        // Old proof should NOT verify against new root
        assert!(!proof_v1.verify(&root_v2));
        // New proofs should verify
        for i in 0..params_v2.len() {
            let proof = tree.generate_protocol_param_proof(i).unwrap();
            assert!(proof.verify(&root_v2), "v2 proof {i} failed");
        }

        // Single-element removed validators
        let removed = vec![ed25519::PrivateKey::from_seed(42).public_key()];
        tree.rebuild_removed_validators(&removed);
        let root_v3 = tree.root();
        let proof = tree.generate_removed_validator_proof(0).unwrap();
        assert!(proof.verify(&root_v3));
    }

    /// Proofs generated after incremental remove must verify against root.
    #[test]
    fn proofs_valid_after_remove() {
        let validators: Vec<([u8; 32], ValidatorAccount)> =
            (1..=6u64).map(|i| make_validator(i)).collect();
        let mut accounts: BTreeMap<[u8; 32], ValidatorAccount> =
            validators.iter().cloned().collect();
        let mut tree = rebuild_tree(&accounts);

        // Remove the 3rd validator
        let pk = {
            let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();
            keys[2]
        };
        let slot = accounts.keys().position(|k| k == &pk).unwrap();
        accounts.remove(&pk);
        tree.remove_validator_at_slot(slot);

        let root = tree.root();
        let keys: Vec<[u8; 32]> = accounts.keys().copied().collect();

        for pk in &keys {
            for field_idx in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
                let proof = tree
                    .generate_validator_field_proof(pk, field_idx, &keys)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "proof failed for pk {:?} field {field_idx} after remove",
                    &pk[..4]
                );
            }
        }
    }
}
