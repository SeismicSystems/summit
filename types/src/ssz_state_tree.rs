//! Two-level SSZ binary Merkle tree for ConsensusState.
//!
//! The top-level tree has 32 leaf slots (28 used, depth 5). Scalar fields and
//! collection roots are assigned to fixed leaf indices — see the field-index
//! and `*_ROOT` constants below for the authoritative layout. Each collection
//! root (validator accounts, deposit/withdrawal queues, protocol-param changes,
//! added/removed validators, pending execution requests) is
//! `mix_in_length(subtree_root, count)`.
//!
//! The validator accounts collection uses a dedicated subtree (`SszTree`)
//! where each validator occupies 16 contiguous leaves (9 fields incl. the node
//! pubkey/map key, padded to a depth-4 per-validator sub-subtree). This enables
//! field-level Merkle proofs (e.g., proving just the balance) in addition to
//! whole-account proofs, and binds the validator's identity (node pubkey) into
//! the root and its proofs.
//!
//! Validator slot assignment is purely positional: the i-th entry in
//! `BTreeMap<[u8; 32], ValidatorAccount>` iteration order occupies
//! leaves `[i*16 .. i*16+15]`. The subtree is rebuilt from scratch on
//! every mutation for determinism.

use crate::PublicKey;
use crate::account::ValidatorAccount;
use crate::execution_request::DepositRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::ssz_hash::{SszHashTreeRoot, hash_byte_list, hash_fixed_bytes_64, hash_fixed_bytes_96};
use crate::ssz_tree::{SszTree, mix_in_length};
use crate::withdrawal::{PendingWithdrawal, WithdrawalQueue};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

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
pub const ALLOWED_TIMESTAMP_FUTURE_MS: usize = 11;
pub const VALIDATOR_ACCOUNTS_ROOT: usize = 12;
pub const DEPOSIT_QUEUE_ROOT: usize = 13;
pub const WITHDRAWAL_QUEUE_ROOT: usize = 14;
pub const PROTOCOL_PARAM_CHANGES_ROOT: usize = 15;
pub const ADDED_VALIDATORS_ROOT: usize = 16;
pub const REMOVED_VALIDATORS_ROOT: usize = 17;
pub const TREASURY_ADDRESS: usize = 18;
pub const MAX_DEPOSITS_PER_EPOCH: usize = 19;
pub const MAX_WITHDRAWALS_PER_EPOCH: usize = 20;
pub const OBSERVERS_PER_VALIDATOR: usize = 21;
pub const PENDING_EXECUTION_REQUESTS_ROOT: usize = 22;
pub const PENDING_CHECKPOINT: usize = 23;
pub const DYNAMIC_EPOCH_SCHEDULE: usize = 24;
pub const MINIMUM_VALIDATOR_COUNT: usize = 25;
pub const PENDING_ACTIVE_VALIDATOR_EXITS: usize = 26;
pub const INVALID_WITHDRAWAL_TAX: usize = 27;

/// Number of used leaf slots in the top-level tree.
pub const NUM_TOP_LEAVES: usize = 28;

// --- Validator field indices (within each validator's 8-leaf subtree) ---

pub const VALIDATOR_FIELD_CONSENSUS_PUBKEY: usize = 0;
pub const VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS: usize = 1;
pub const VALIDATOR_FIELD_BALANCE: usize = 2;
pub const VALIDATOR_FIELD_STATUS: usize = 3;
pub const VALIDATOR_FIELD_HAS_PENDING_DEPOSIT: usize = 4;
pub const VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL: usize = 5;
pub const VALIDATOR_FIELD_JOINING_EPOCH: usize = 6;
pub const VALIDATOR_FIELD_LAST_DEPOSIT_INDEX: usize = 7;
/// The node public key — the `BTreeMap` key the account belongs to. Committed as
/// a leaf so the validator's identity is bound into the root and its proofs.
pub const VALIDATOR_FIELD_NODE_PUBKEY: usize = 8;

/// Leaves per validator: 9 fields padded to the next power of two (16 leaves,
/// depth-4 subtree). Leaves 9–15 are zero padding.
pub const VALIDATOR_FIELDS_PER_ACCOUNT: usize = 16;

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
pub const WITHDRAWAL_FIELD_KIND: usize = 7;

/// Number of SSZ leaves per PendingWithdrawal (8 fields → 8 leaves, depth-3 subtree).
pub const WITHDRAWAL_FIELDS_PER_ITEM: usize = 8;

// --- Protocol parameter field indices (within each param's 2-leaf subtree) ---

pub const PROTOCOL_PARAM_FIELD_TAG: usize = 0;
pub const PROTOCOL_PARAM_FIELD_VALUE: usize = 1;

/// Number of SSZ leaves per ProtocolParam (2 fields = depth-1 subtree).
pub const PROTOCOL_PARAM_FIELDS_PER_ITEM: usize = 2;

// --- Added validator field indices (within each added validator's 2-leaf subtree) ---

pub const ADDED_VALIDATOR_FIELD_NODE_KEY: usize = 0;
pub const ADDED_VALIDATOR_FIELD_CONSENSUS_KEY: usize = 1;
/// The activation epoch — the `BTreeMap` key this scheduled addition belongs to.
/// Committed per item so the epoch is bound even though the value list is flattened.
pub const ADDED_VALIDATOR_FIELD_EPOCH: usize = 2;

/// Number of SSZ leaves per AddedValidator: 3 fields padded to the next power of
/// two (4 leaves, depth-2 subtree). Leaf 3 is zero padding.
pub const ADDED_VALIDATOR_FIELDS_PER_ITEM: usize = 4;

/// Two-level SSZ state tree mirroring ConsensusState.
#[derive(Clone, Debug)]
pub struct SszStateTree {
    /// Top-level tree: 32 leaves (depth 5), 27 used.
    top: SszTree,

    /// Validator accounts subtree. Rebuilt from BTreeMap on every mutation.
    validator_tree: SszTree,
    /// Number of active validators (= number of leaves set in the subtree).
    validator_count: usize,

    /// Deposit queue subtree.
    deposit_tree: SszTree,
    deposit_count: usize,

    /// Epoch-level tree for withdrawal queue: each leaf is
    /// `mix_in_length(per_epoch_subtree.root(), per_epoch_withdrawal_count)`.
    withdrawal_epoch_tree: SszTree,
    /// Per-epoch subtrees (8 field leaves per withdrawal), parallel to `withdrawal_epoch_keys`.
    withdrawal_epoch_subtrees: Vec<SszTree>,
    /// Per-epoch withdrawal counts, parallel to `withdrawal_epoch_subtrees`.
    withdrawal_epoch_counts: Vec<usize>,
    /// Sorted epoch keys for positional lookup.
    withdrawal_epoch_keys: Vec<u64>,
    /// Pubkey → (epoch_slot, item_slot) for O(1) proof lookup.
    withdrawal_pubkey_index: HashMap<[u8; 32], (usize, usize)>,

    /// Protocol parameter changes subtree.
    protocol_param_tree: SszTree,
    protocol_param_count: usize,

    /// Added validators subtree (flattened across all epochs).
    added_validator_tree: SszTree,
    added_validator_count: usize,

    /// Removed validators subtree.
    removed_validator_tree: SszTree,
    removed_validator_count: usize,

    /// Pending execution requests subtree (one leaf per deferred request blob).
    pending_execution_request_tree: SszTree,
    pending_execution_request_count: usize,
}

impl SszStateTree {
    pub fn new() -> Self {
        Self {
            top: SszTree::new(NUM_TOP_LEAVES),
            validator_tree: SszTree::new(1),
            validator_count: 0,
            deposit_tree: SszTree::new(1),
            deposit_count: 0,
            withdrawal_epoch_tree: SszTree::new(1),
            withdrawal_epoch_subtrees: Vec::new(),
            withdrawal_epoch_counts: Vec::new(),
            withdrawal_epoch_keys: Vec::new(),
            withdrawal_pubkey_index: HashMap::new(),
            protocol_param_tree: SszTree::new(1),
            protocol_param_count: 0,
            added_validator_tree: SszTree::new(1),
            added_validator_count: 0,
            removed_validator_tree: SszTree::new(1),
            removed_validator_count: 0,
            pending_execution_request_tree: SszTree::new(1),
            pending_execution_request_count: 0,
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

    pub fn set_allowed_timestamp_future_ms(&mut self, ms: u64) {
        self.top
            .set_leaf(ALLOWED_TIMESTAMP_FUTURE_MS, ms.hash_tree_root());
    }

    pub fn set_max_deposits_per_epoch(&mut self, value: u64) {
        self.top
            .set_leaf(MAX_DEPOSITS_PER_EPOCH, value.hash_tree_root());
    }

    pub fn set_max_withdrawals_per_epoch(&mut self, value: u64) {
        self.top
            .set_leaf(MAX_WITHDRAWALS_PER_EPOCH, value.hash_tree_root());
    }

    pub fn set_observers_per_validator(&mut self, value: u32) {
        self.top
            .set_leaf(OBSERVERS_PER_VALIDATOR, value.hash_tree_root());
    }

    /// Set the pending-checkpoint leaf to the checkpoint digest (the value that
    /// becomes the boundary `checkpoint_hash`), or the zero hash when absent. A
    /// single scalar leaf — no subtree or proof support, since the pending
    /// checkpoint only needs to be bound into the root, not proven on-chain. The
    /// digest already commits the checkpoint data via SHA-256.
    pub fn set_pending_checkpoint_digest(&mut self, digest: Option<[u8; 32]>) {
        self.top
            .set_leaf(PENDING_CHECKPOINT, digest.unwrap_or([0u8; 32]));
    }

    /// Set the dynamic-epoch-schedule leaf to the SSZ byte-list root of the
    /// encoded `DynamicEpocher`. A single scalar leaf — no subtree or proof
    /// support, since the schedule only needs to be bound into the root, not
    /// proven on-chain. Because the epocher uses interior mutability and can be
    /// changed (epoch advance, length update) without going through a
    /// `ConsensusState` setter, this is refreshed at `capture_state_root` (and in
    /// `rebuild`) rather than maintained incrementally.
    pub fn set_dynamic_epoch_schedule(&mut self, encoded_schedule: &[u8]) {
        self.top
            .set_leaf(DYNAMIC_EPOCH_SCHEDULE, hash_byte_list(encoded_schedule));
    }

    pub fn set_minimum_validator_count(&mut self, value: u64) {
        self.top
            .set_leaf(MINIMUM_VALIDATOR_COUNT, value.hash_tree_root());
    }

    pub fn set_pending_active_validator_exits(&mut self, value: u64) {
        self.top
            .set_leaf(PENDING_ACTIVE_VALIDATOR_EXITS, value.hash_tree_root());
    }

    pub fn set_invalid_withdrawal_tax(&mut self, value: u64) {
        self.top
            .set_leaf(INVALID_WITHDRAWAL_TAX, value.hash_tree_root());
    }

    pub fn set_treasury_address(&mut self, address: &Address) {
        self.top
            .set_leaf(TREASURY_ADDRESS, address.hash_tree_root());
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
    /// Each validator occupies 16 contiguous leaves (8 fields incl. the
    /// `node_pubkey` map key, plus zero padding) in the subtree, forming a
    /// depth-4 per-validator sub-subtree. Slot assignment is purely positional:
    /// the i-th entry in BTreeMap iteration order occupies leaves
    /// `[i*16 .. i*16+15]`.
    pub fn rebuild_validators(&mut self, accounts: &BTreeMap<[u8; 32], ValidatorAccount>) {
        let count = accounts.len();
        let leaf_count = (count * VALIDATOR_FIELDS_PER_ACCOUNT).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, (node_pubkey, account)) in accounts.iter().enumerate() {
            Self::set_validator_fields(&mut tree, i, node_pubkey, account);
        }
        self.validator_tree = tree;
        self.validator_count = count;
        self.update_validator_collection_root();
    }

    /// Set the validator's 9 field leaves (node-pubkey key + 8 account fields,
    /// padded to a 16-leaf depth-4 subtree) at positional slot `i`.
    fn set_validator_fields(
        tree: &mut SszTree,
        slot: usize,
        node_pubkey: &[u8; 32],
        account: &ValidatorAccount,
    ) {
        let base = slot * VALIDATOR_FIELDS_PER_ACCOUNT;
        tree.set_leaf(base + VALIDATOR_FIELD_NODE_PUBKEY, *node_pubkey);
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
    pub fn update_validator_at_slot(
        &mut self,
        slot: usize,
        node_pubkey: &[u8; 32],
        account: &ValidatorAccount,
    ) {
        Self::set_validator_fields(&mut self.validator_tree, slot, node_pubkey, account);
        self.update_validator_collection_root();
    }

    /// Insert a new validator at positional `slot`, shifting existing validators right.
    ///
    /// Grows the tree if needed. Copies shifted validators' subtree nodes via memmove
    /// (no rehash), then writes the new validator's 9 field leaves and rehashes only
    /// the new slot's subtree plus upper ancestors. O(N) memcpy + O(N/8) SHA256.
    pub fn insert_validator_at_slot(
        &mut self,
        slot: usize,
        node_pubkey: &[u8; 32],
        account: &ValidatorAccount,
    ) {
        let new_count = self.validator_count + 1;
        let needed = new_count * VALIDATOR_FIELDS_PER_ACCOUNT;
        self.validator_tree.grow(needed);

        // Shift validators [slot..count) right by 1 block
        let to_shift = self.validator_count - slot;
        self.validator_tree
            .shift_blocks_right(slot, to_shift, VALIDATOR_FIELDS_PER_ACCOUNT);

        // Write new validator's field leaves (no per-leaf rehash)
        Self::set_validator_fields_no_rehash(&mut self.validator_tree, slot, node_pubkey, account);

        // Rehash only the new validator's subtree (4 internal levels above its 16 leaves)
        self.validator_tree
            .rehash_block(slot, VALIDATOR_FIELDS_PER_ACCOUNT);

        // Rehash upper levels from the affected position upward.
        // shift_blocks_right already copied the per-validator subtree nodes (4 levels),
        // so only levels above the subtree root need recomputation.
        let subtree_root_level = self.validator_tree.capacity() / VALIDATOR_FIELDS_PER_ACCOUNT;
        let affected_node = subtree_root_level + slot;
        let parent_level = subtree_root_level / 2;
        let parent_node = affected_node / 2;
        self.validator_tree
            .rehash_from_position(parent_level, parent_node);

        self.validator_count = new_count;
        self.update_validator_collection_root();
    }

    /// Remove the validator at positional `slot`, shifting subsequent validators left.
    ///
    /// O(N) memcpy + O(N/8) SHA256 for the shift, then partial rehash of upper levels.
    pub fn remove_validator_at_slot(&mut self, slot: usize) {
        assert!(slot < self.validator_count, "slot out of range");
        let to_shift = self.validator_count - slot - 1;
        self.validator_tree
            .shift_blocks_left(slot, to_shift, VALIDATOR_FIELDS_PER_ACCOUNT);

        if to_shift == 0 {
            // Edge case: removing the last validator. shift_blocks_left was a no-op.
            // Zero the slot's leaves and rehash its subtree manually.
            let base = slot * VALIDATOR_FIELDS_PER_ACCOUNT;
            for i in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
                self.validator_tree.set_leaf_no_rehash(base + i, [0u8; 32]);
            }
            self.validator_tree
                .rehash_block(slot, VALIDATOR_FIELDS_PER_ACCOUNT);
        } else {
            // shift_blocks_left zeros the vacated last block with [0u8; 32] at all levels,
            // but internal nodes should be ZERO_HASHES. Rehash the vacated block's subtree.
            let vacated_slot = self.validator_count - 1;
            self.validator_tree
                .rehash_block(vacated_slot, VALIDATOR_FIELDS_PER_ACCOUNT);
        }

        self.validator_count -= 1;

        // Shrink tree if the new count fits in a smaller capacity.
        // shrink() does its own full rehash, so we only need partial rehash if not shrinking.
        let needed = (self.validator_count * VALIDATOR_FIELDS_PER_ACCOUNT).max(1);
        let target_capacity = needed.next_power_of_two();
        if target_capacity < self.validator_tree.capacity() {
            self.validator_tree.shrink(needed);
        } else {
            // shift_blocks_left copied all 4 per-validator subtree levels, so only
            // levels above the subtree root need recomputation from the affected slot.
            let subtree_root_level = self.validator_tree.capacity() / VALIDATOR_FIELDS_PER_ACCOUNT;
            let affected_node = subtree_root_level + slot;
            let parent_level = subtree_root_level / 2;
            let parent_node = affected_node / 2;
            self.validator_tree
                .rehash_from_position(parent_level, parent_node);
        }

        self.update_validator_collection_root();
    }

    /// Set the validator's 9 field leaves (node-pubkey key + 8 account fields)
    /// without triggering per-leaf rehash.
    fn set_validator_fields_no_rehash(
        tree: &mut SszTree,
        slot: usize,
        node_pubkey: &[u8; 32],
        account: &ValidatorAccount,
    ) {
        let base = slot * VALIDATOR_FIELDS_PER_ACCOUNT;
        tree.set_leaf_no_rehash(base + VALIDATOR_FIELD_NODE_PUBKEY, *node_pubkey);
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

    /// Incrementally update the tree after a deposit is pushed to the back.
    ///
    /// Grows the subtree if needed, sets the 8 field leaves for the new item,
    /// and recomputes the collection root.
    pub fn push_deposit(&mut self, deposit: &DepositRequest) {
        let slot = self.deposit_count;
        let needed = (slot + 1) * DEPOSIT_FIELDS_PER_ITEM;
        self.deposit_tree.grow(needed);
        Self::set_deposit_fields(&mut self.deposit_tree, slot, deposit);
        self.deposit_count += 1;
        self.update_deposit_collection_root();
    }

    /// Incrementally update the tree after a deposit is popped from the front.
    ///
    /// Since items shift forward, the subtree is rebuilt from the remaining deposits.
    pub fn pop_deposit(&mut self, deposits: &VecDeque<DepositRequest>) {
        self.rebuild_deposits(deposits);
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

    /// Rebuild the withdrawal queue as per-epoch subtrees.
    ///
    /// Structure: epoch_tree → per-epoch subtree → 8 field leaves per withdrawal.
    /// Each epoch leaf = `mix_in_length(per_epoch_tree.root(), per_epoch_count)`.
    /// Top-level = `mix_in_length(epoch_tree.root(), epoch_count)`.
    pub fn rebuild_withdrawals(&mut self, queue: &WithdrawalQueue) {
        let epochs = queue.epochs_with_withdrawals();
        let epoch_count = epochs.len();

        let mut epoch_subtrees = Vec::with_capacity(epoch_count);
        let mut epoch_counts = Vec::with_capacity(epoch_count);
        let mut pubkey_index = HashMap::new();

        let mut epoch_tree = SszTree::new(epoch_count.max(1));

        for (epoch_slot, &epoch) in epochs.iter().enumerate() {
            let withdrawals = queue.get_for_epoch(epoch);
            let count = withdrawals.len();
            let leaf_count = (count * WITHDRAWAL_FIELDS_PER_ITEM).max(1);
            let mut subtree = SszTree::new(leaf_count);

            for (item_slot, withdrawal) in withdrawals.iter().enumerate() {
                Self::set_withdrawal_fields(&mut subtree, item_slot, withdrawal);
                pubkey_index.insert(withdrawal.pubkey, (epoch_slot, item_slot));
            }

            let epoch_leaf = mix_in_length(subtree.root(), count);
            epoch_tree.set_leaf(epoch_slot, epoch_leaf);

            epoch_subtrees.push(subtree);
            epoch_counts.push(count);
        }

        self.withdrawal_epoch_tree = epoch_tree;
        self.withdrawal_epoch_subtrees = epoch_subtrees;
        self.withdrawal_epoch_counts = epoch_counts;
        self.withdrawal_epoch_keys = epochs;
        self.withdrawal_pubkey_index = pubkey_index;
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
        tree.set_leaf(
            base + WITHDRAWAL_FIELD_KIND,
            withdrawal.kind.hash_tree_root(),
        );
    }

    /// Incrementally update the tree after a withdrawal's fields changed (merge case).
    ///
    /// The pubkey must already exist in the tree. Only the affected item's 8 leaves
    /// and the epoch leaf are recomputed.
    pub fn update_withdrawal(&mut self, withdrawal: &PendingWithdrawal) {
        let Some(&(epoch_slot, item_slot)) = self.withdrawal_pubkey_index.get(&withdrawal.pubkey)
        else {
            return;
        };
        let subtree = &mut self.withdrawal_epoch_subtrees[epoch_slot];
        Self::set_withdrawal_fields(subtree, item_slot, withdrawal);
        self.refresh_withdrawal_epoch_leaf(epoch_slot);
    }

    /// Incrementally update the tree after a new withdrawal is appended to an epoch.
    ///
    /// If the epoch is new, a new subtree and epoch-tree leaf are created.
    /// If the epoch already exists, the item is appended to the end of its subtree.
    pub fn push_withdrawal(&mut self, withdrawal: &PendingWithdrawal) {
        let epoch = withdrawal.epoch;

        let epoch_slot = match self.withdrawal_epoch_keys.binary_search(&epoch) {
            Ok(slot) => {
                // Existing epoch — append item to its subtree
                let count = self.withdrawal_epoch_counts[slot];
                let new_count = count + 1;
                let needed = new_count * WITHDRAWAL_FIELDS_PER_ITEM;
                let subtree = &mut self.withdrawal_epoch_subtrees[slot];
                subtree.grow(needed);
                Self::set_withdrawal_fields(subtree, count, withdrawal);
                self.withdrawal_epoch_counts[slot] = new_count;
                self.withdrawal_pubkey_index
                    .insert(withdrawal.pubkey, (slot, count));
                slot
            }
            Err(insert_pos) => {
                // New epoch — create subtree, insert into epoch-level structures
                let mut subtree = SszTree::new(WITHDRAWAL_FIELDS_PER_ITEM);
                Self::set_withdrawal_fields(&mut subtree, 0, withdrawal);

                self.withdrawal_epoch_keys.insert(insert_pos, epoch);
                self.withdrawal_epoch_subtrees.insert(insert_pos, subtree);
                self.withdrawal_epoch_counts.insert(insert_pos, 1);

                // Pubkey indices for epochs after insert_pos shift right by 1
                for (_, (es, _)) in self.withdrawal_pubkey_index.iter_mut() {
                    if *es >= insert_pos {
                        *es += 1;
                    }
                }
                self.withdrawal_pubkey_index
                    .insert(withdrawal.pubkey, (insert_pos, 0));

                // Rebuild epoch tree: all leaves shift after insert_pos
                self.rebuild_withdrawal_epoch_tree();
                self.update_withdrawal_collection_root();
                return;
            }
        };

        self.refresh_withdrawal_epoch_leaf(epoch_slot);
    }

    /// Incrementally update the tree after a withdrawal is popped from the front of an epoch.
    ///
    /// If the epoch becomes empty, its subtree and epoch-tree leaf are removed.
    /// Otherwise, the epoch's subtree is rebuilt (items shift forward).
    pub fn pop_withdrawal(
        &mut self,
        epoch: u64,
        popped_pubkey: &[u8; 32],
        queue: &WithdrawalQueue,
    ) {
        self.withdrawal_pubkey_index.remove(popped_pubkey);

        let Ok(epoch_slot) = self.withdrawal_epoch_keys.binary_search(&epoch) else {
            return;
        };

        let old_count = self.withdrawal_epoch_counts[epoch_slot];
        if old_count <= 1 {
            // Epoch is now empty — remove it
            self.withdrawal_epoch_keys.remove(epoch_slot);
            self.withdrawal_epoch_subtrees.remove(epoch_slot);
            self.withdrawal_epoch_counts.remove(epoch_slot);

            // Pubkey indices for epochs after epoch_slot shift left by 1
            for (_, (es, _)) in self.withdrawal_pubkey_index.iter_mut() {
                if *es > epoch_slot {
                    *es -= 1;
                }
            }

            self.rebuild_withdrawal_epoch_tree();
            self.update_withdrawal_collection_root();
            return;
        }

        // Rebuild just this epoch's subtree — items shifted after pop_front
        let withdrawals = queue.get_for_epoch(epoch);
        let new_count = withdrawals.len();
        let leaf_count = (new_count * WITHDRAWAL_FIELDS_PER_ITEM).max(1);
        let mut subtree = SszTree::new(leaf_count);
        for (item_slot, w) in withdrawals.iter().enumerate() {
            Self::set_withdrawal_fields(&mut subtree, item_slot, w);
            self.withdrawal_pubkey_index
                .insert(w.pubkey, (epoch_slot, item_slot));
        }
        self.withdrawal_epoch_subtrees[epoch_slot] = subtree;
        self.withdrawal_epoch_counts[epoch_slot] = new_count;
        self.refresh_withdrawal_epoch_leaf(epoch_slot);
    }

    /// Recompute the epoch-tree leaf for a single epoch slot and propagate to collection root.
    fn refresh_withdrawal_epoch_leaf(&mut self, epoch_slot: usize) {
        let subtree = &self.withdrawal_epoch_subtrees[epoch_slot];
        let count = self.withdrawal_epoch_counts[epoch_slot];
        let epoch_leaf = mix_in_length(subtree.root(), count);
        self.withdrawal_epoch_tree.set_leaf(epoch_slot, epoch_leaf);
        self.update_withdrawal_collection_root();
    }

    /// Rebuild the epoch-level tree from all current epoch subtrees.
    ///
    /// Called when epochs are added or removed (structural change).
    fn rebuild_withdrawal_epoch_tree(&mut self) {
        let epoch_count = self.withdrawal_epoch_keys.len();
        let mut epoch_tree = SszTree::new(epoch_count.max(1));
        for (slot, subtree) in self.withdrawal_epoch_subtrees.iter().enumerate() {
            let count = self.withdrawal_epoch_counts[slot];
            epoch_tree.set_leaf(slot, mix_in_length(subtree.root(), count));
        }
        self.withdrawal_epoch_tree = epoch_tree;
    }

    fn update_withdrawal_collection_root(&mut self) {
        let epoch_count = self.withdrawal_epoch_keys.len();
        let collection_root = mix_in_length(self.withdrawal_epoch_tree.root(), epoch_count);
        self.top.set_leaf(WITHDRAWAL_QUEUE_ROOT, collection_root);
    }

    /// Number of epochs with pending withdrawals.
    pub fn withdrawal_epoch_count(&self) -> usize {
        self.withdrawal_epoch_keys.len()
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
        let (tag, value_hash) = match param {
            ProtocolParam::MinimumStake(v) => (0u64, v.hash_tree_root()),
            ProtocolParam::MaximumStake(v) => (1u64, v.hash_tree_root()),
            ProtocolParam::EpochLength(v) => (2u64, v.hash_tree_root()),
            ProtocolParam::AllowedTimestampFuture(v) => (3u64, v.hash_tree_root()),
            ProtocolParam::TreasuryAddress(addr) => (4u64, addr.hash_tree_root()),
            ProtocolParam::MaxDepositsPerEpoch(v) => (5u64, v.hash_tree_root()),
            ProtocolParam::MaxWithdrawalsPerEpoch(v) => (6u64, v.hash_tree_root()),
            ProtocolParam::ObserversPerValidator(v) => (7u64, v.hash_tree_root()),
            ProtocolParam::MinimumValidatorCount(v) => (8u64, v.hash_tree_root()),
            ProtocolParam::InvalidWithdrawalTax(v) => (9u64, v.hash_tree_root()),
        };
        tree.set_leaf(base + PROTOCOL_PARAM_FIELD_TAG, tag.hash_tree_root());
        tree.set_leaf(base + PROTOCOL_PARAM_FIELD_VALUE, value_hash);
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
    /// Each added validator occupies 4 contiguous leaves (node_key, consensus_key,
    /// epoch map key, and zero padding), forming a depth-2 per-item sub-subtree,
    /// enabling field-level proofs.
    pub fn rebuild_added_validators(&mut self, validators: &BTreeMap<u64, Vec<AddedValidator>>) {
        let items: Vec<(u64, &AddedValidator)> = validators
            .iter()
            .flat_map(|(epoch, v)| v.iter().map(move |av| (*epoch, av)))
            .collect();
        let count = items.len();
        let leaf_count = (count * ADDED_VALIDATOR_FIELDS_PER_ITEM).max(1);
        let mut tree = SszTree::new(leaf_count);
        for (i, (epoch, av)) in items.iter().enumerate() {
            Self::set_added_validator_fields(&mut tree, i, *epoch, av);
        }
        self.added_validator_tree = tree;
        self.added_validator_count = count;
        self.update_added_validator_collection_root();
    }

    /// Set the 2 field leaves for added validator at positional slot `i`.
    fn set_added_validator_fields(
        tree: &mut SszTree,
        slot: usize,
        epoch: u64,
        av: &AddedValidator,
    ) {
        let base = slot * ADDED_VALIDATOR_FIELDS_PER_ITEM;
        tree.set_leaf(
            base + ADDED_VALIDATOR_FIELD_NODE_KEY,
            av.node_key.hash_tree_root(),
        );
        tree.set_leaf(
            base + ADDED_VALIDATOR_FIELD_CONSENSUS_KEY,
            av.consensus_key.hash_tree_root(),
        );
        tree.set_leaf(base + ADDED_VALIDATOR_FIELD_EPOCH, epoch.hash_tree_root());
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

    /// Rebuild the pending-execution-requests subtree. Each deferred request is an
    /// opaque byte blob hashed as an SSZ byte list; the collection root mixes in the
    /// request count. Binds deferred deposits/withdrawals/exits into the state root.
    pub fn rebuild_pending_execution_requests(&mut self, requests: &[alloy_primitives::Bytes]) {
        let count = requests.len();
        let capacity = count.max(1);
        let mut tree = SszTree::new(capacity);
        for (i, req) in requests.iter().enumerate() {
            tree.set_leaf(i, hash_byte_list(req));
        }
        self.pending_execution_request_tree = tree;
        self.pending_execution_request_count = count;
        self.update_pending_execution_request_collection_root();
    }

    fn update_pending_execution_request_collection_root(&mut self) {
        let subtree_root = self.pending_execution_request_tree.root();
        let collection_root = mix_in_length(subtree_root, self.pending_execution_request_count);
        self.top
            .set_leaf(PENDING_EXECUTION_REQUESTS_ROOT, collection_root);
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
        allowed_timestamp_future_ms: u64,
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
        treasury_address: &Address,
        max_deposits_per_epoch: u64,
        max_withdrawals_per_epoch: u64,
        observers_per_validator: u32,
        pending_execution_requests: &[alloy_primitives::Bytes],
        pending_checkpoint_digest: Option<[u8; 32]>,
        dynamic_epoch_schedule: &[u8],
        minimum_validator_count: u64,
        pending_active_validator_exits: u64,
        invalid_withdrawal_tax: u64,
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
        self.set_allowed_timestamp_future_ms(allowed_timestamp_future_ms);
        self.set_next_withdrawal_index(next_withdrawal_index);
        self.set_forkchoice_head_block_hash(forkchoice_head);
        self.set_forkchoice_safe_block_hash(forkchoice_safe);
        self.set_forkchoice_finalized_block_hash(forkchoice_finalized);
        self.set_treasury_address(treasury_address);
        self.set_max_deposits_per_epoch(max_deposits_per_epoch);
        self.set_max_withdrawals_per_epoch(max_withdrawals_per_epoch);
        self.set_observers_per_validator(observers_per_validator);
        self.set_minimum_validator_count(minimum_validator_count);
        self.set_pending_active_validator_exits(pending_active_validator_exits);
        self.set_invalid_withdrawal_tax(invalid_withdrawal_tax);

        // Validators
        self.rebuild_validators(validator_accounts);

        // Other collections
        self.rebuild_deposits(deposit_queue);
        self.rebuild_withdrawals(withdrawal_queue);
        self.rebuild_protocol_params(protocol_param_changes);
        self.rebuild_added_validators(added_validators);
        self.rebuild_removed_validators(removed_validators);
        self.rebuild_pending_execution_requests(pending_execution_requests);
        self.set_pending_checkpoint_digest(pending_checkpoint_digest);
        self.set_dynamic_epoch_schedule(dynamic_epoch_schedule);
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

    /// Generate a field-level proof for a validator identified by node pubkey,
    /// bound to that pubkey via a companion proof of the item's node-pubkey leaf.
    ///
    /// Unlike [`Self::generate_validator_field_proof`], the returned
    /// [`KeyedFieldProof`] lets a trustless consumer confirm the field belongs
    /// to the requested validator rather than to some other account under the
    /// same root. Verify with
    /// `proof.verify(root, pubkey, VALIDATOR_FIELDS_PER_ACCOUNT, VALIDATOR_FIELD_NODE_PUBKEY)`.
    pub fn generate_validator_keyed_field_proof(
        &self,
        pubkey: &[u8; 32],
        field_index: usize,
        keys: &[[u8; 32]],
    ) -> Option<KeyedFieldProof> {
        let field = self.generate_validator_field_proof(pubkey, field_index, keys)?;
        let key = self.generate_validator_field_proof(pubkey, VALIDATOR_FIELD_NODE_PUBKEY, keys)?;
        Some(KeyedFieldProof { field, key })
    }

    /// Build a proof for the whole validator at positional `slot`.
    ///
    /// Returns (gindex, node_value, branch) where the node is the
    /// per-validator subtree root (4 levels above the field leaves).
    fn validator_account_proof(&self, slot: usize) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let sd = self.validator_tree.depth();
        // Per-validator root is at depth (sd - 4) in the subtree (16 leaves/item).
        // Its 1-based tree index is: capacity / VALIDATOR_FIELDS_PER_ACCOUNT + slot
        let node_index = self.validator_tree.capacity() / VALIDATOR_FIELDS_PER_ACCOUNT + slot;
        let node_value = self.validator_tree.get_node(node_index);

        // Generalized index: descend from the top leaf to the per-validator subtree
        // root, which sits `log_block` levels above the field leaves. That is
        // `(sd - log_block)` subtree levels + 1 for the mix_in_length node.
        let log_block = VALIDATOR_FIELDS_PER_ACCOUNT.ilog2() as usize;
        let td = self.top.depth();
        let top_gindex = (1u64 << td) + VALIDATOR_ACCOUNTS_ROOT as u64;
        let gindex = (top_gindex << (sd - log_block + 1)) | (slot as u64);

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

    /// Generate a proof for a withdrawal identified by validator pubkey (O(1) lookup).
    pub fn generate_withdrawal_proof_by_key(&self, pubkey: &[u8; 32]) -> Option<SszProof> {
        let &(epoch_slot, item_slot) = self.withdrawal_pubkey_index.get(pubkey)?;
        self.generate_withdrawal_proof(epoch_slot, item_slot)
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

    /// Generate a whole-withdrawal proof by (epoch_slot, item_slot).
    ///
    /// The proof leaf is the per-withdrawal subtree root (internal node 3 levels
    /// above the field leaves) in the per-epoch subtree.
    pub fn generate_withdrawal_proof(
        &self,
        epoch_slot: usize,
        item_slot: usize,
    ) -> Option<SszProof> {
        if epoch_slot >= self.withdrawal_epoch_keys.len() {
            return None;
        }
        if item_slot >= self.withdrawal_epoch_counts[epoch_slot] {
            return None;
        }
        let (gindex, node_value, branch) = self.withdrawal_epoch_item_proof(epoch_slot, item_slot);
        Some(SszProof {
            gindex,
            leaf: node_value,
            branch,
        })
    }

    /// Generate a field-level proof for a withdrawal by (epoch_slot, item_slot, field_index).
    pub fn generate_withdrawal_field_proof(
        &self,
        epoch_slot: usize,
        item_slot: usize,
        field_index: usize,
    ) -> Option<SszProof> {
        if epoch_slot >= self.withdrawal_epoch_keys.len() {
            return None;
        }
        if item_slot >= self.withdrawal_epoch_counts[epoch_slot] {
            return None;
        }
        if field_index >= WITHDRAWAL_FIELDS_PER_ITEM {
            return None;
        }
        let subtree = &self.withdrawal_epoch_subtrees[epoch_slot];
        let per_epoch_count = self.withdrawal_epoch_counts[epoch_slot];
        let epoch_count = self.withdrawal_epoch_keys.len();
        let leaf_index = item_slot * WITHDRAWAL_FIELDS_PER_ITEM + field_index;

        let gindex = self.compose_withdrawal_field_gindex(subtree, epoch_slot, leaf_index);
        let leaf = subtree.get_leaf(leaf_index);
        let branch = self.build_withdrawal_branch_from_leaf(
            subtree,
            epoch_slot,
            leaf_index,
            per_epoch_count,
            epoch_count,
        );

        Some(SszProof {
            gindex,
            leaf,
            branch,
        })
    }

    /// Generate a field-level proof for a withdrawal identified by validator pubkey (O(1) lookup).
    pub fn generate_withdrawal_field_proof_by_key(
        &self,
        pubkey: &[u8; 32],
        field_index: usize,
    ) -> Option<SszProof> {
        let &(epoch_slot, item_slot) = self.withdrawal_pubkey_index.get(pubkey)?;
        self.generate_withdrawal_field_proof(epoch_slot, item_slot, field_index)
    }

    /// Generate a field-level proof for a withdrawal identified by pubkey,
    /// bound to that pubkey via a companion proof of the item's pubkey leaf.
    ///
    /// Unlike [`Self::generate_withdrawal_field_proof_by_key`], the returned
    /// [`KeyedFieldProof`] lets a trustless consumer confirm the field belongs
    /// to the requested pubkey rather than to some other withdrawal under the
    /// same root. Verify with
    /// `proof.verify(root, pubkey, WITHDRAWAL_FIELDS_PER_ITEM, WITHDRAWAL_FIELD_PUBKEY)`.
    pub fn generate_withdrawal_keyed_field_proof_by_key(
        &self,
        pubkey: &[u8; 32],
        field_index: usize,
    ) -> Option<KeyedFieldProof> {
        let &(epoch_slot, item_slot) = self.withdrawal_pubkey_index.get(pubkey)?;
        let field = self.generate_withdrawal_field_proof(epoch_slot, item_slot, field_index)?;
        let key =
            self.generate_withdrawal_field_proof(epoch_slot, item_slot, WITHDRAWAL_FIELD_PUBKEY)?;
        Some(KeyedFieldProof { field, key })
    }

    /// Internal helper: produce (gindex, node_value, branch) for a whole-withdrawal proof.
    ///
    /// Three-level branch: per-epoch subtree (from internal node) +
    /// per-epoch length + epoch tree + epoch count length + top tree.
    fn withdrawal_epoch_item_proof(
        &self,
        epoch_slot: usize,
        item_slot: usize,
    ) -> (u64, [u8; 32], Vec<[u8; 32]>) {
        let subtree = &self.withdrawal_epoch_subtrees[epoch_slot];
        let per_epoch_count = self.withdrawal_epoch_counts[epoch_slot];
        let epoch_count = self.withdrawal_epoch_keys.len();

        // Per-withdrawal subtree root: 3 levels above field leaves
        let node_index = subtree.capacity() / WITHDRAWAL_FIELDS_PER_ITEM + item_slot;
        let node_value = subtree.get_node(node_index);

        let gindex = self.compose_withdrawal_item_gindex(subtree, epoch_slot, item_slot);

        let mut branch = subtree.generate_proof_from_node(node_index);
        // Per-epoch mix_in_length sibling
        let mut per_epoch_len = [0u8; 32];
        per_epoch_len[0..8].copy_from_slice(&(per_epoch_count as u64).to_le_bytes());
        branch.push(per_epoch_len);
        // Epoch tree siblings
        branch.extend_from_slice(&self.withdrawal_epoch_tree.generate_proof(epoch_slot));
        // Epoch count mix_in_length sibling
        let mut epoch_len = [0u8; 32];
        epoch_len[0..8].copy_from_slice(&(epoch_count as u64).to_le_bytes());
        branch.push(epoch_len);
        // Top tree siblings
        branch.extend_from_slice(&self.top.generate_proof(WITHDRAWAL_QUEUE_ROOT));

        (gindex, node_value, branch)
    }

    /// Compose gindex for a whole-withdrawal proof (per-item subtree root).
    fn compose_withdrawal_item_gindex(
        &self,
        subtree: &SszTree,
        epoch_slot: usize,
        item_slot: usize,
    ) -> u64 {
        let td = self.top.depth();
        let ed = self.withdrawal_epoch_tree.depth();
        let sd = subtree.depth();

        // Top-level gindex for WITHDRAWAL_QUEUE_ROOT
        let top_gindex = (1u64 << td) + WITHDRAWAL_QUEUE_ROOT as u64;
        // Descend through epoch-level mix_in_length (+1) and epoch tree
        let epoch_gindex = (top_gindex << (ed + 1)) | (epoch_slot as u64);
        // Descend through per-epoch mix_in_length (+1) to per-item subtree root
        // Per-item root is at depth (sd - 3) in subtree, so (sd - 3 + 1) = (sd - 2) levels
        (epoch_gindex << (sd - 2)) | (item_slot as u64)
    }

    /// Compose gindex for a withdrawal field proof (leaf in per-epoch subtree).
    fn compose_withdrawal_field_gindex(
        &self,
        subtree: &SszTree,
        epoch_slot: usize,
        leaf_index: usize,
    ) -> u64 {
        let td = self.top.depth();
        let ed = self.withdrawal_epoch_tree.depth();
        let sd = subtree.depth();

        let top_gindex = (1u64 << td) + WITHDRAWAL_QUEUE_ROOT as u64;
        let epoch_gindex = (top_gindex << (ed + 1)) | (epoch_slot as u64);
        // Descend through per-epoch mix_in_length (+1) to leaf
        (epoch_gindex << (sd + 1)) | (leaf_index as u64)
    }

    /// Build branch for a withdrawal field proof starting from a leaf.
    fn build_withdrawal_branch_from_leaf(
        &self,
        subtree: &SszTree,
        epoch_slot: usize,
        leaf_index: usize,
        per_epoch_count: usize,
        epoch_count: usize,
    ) -> Vec<[u8; 32]> {
        let mut branch = subtree.generate_proof(leaf_index);
        // Per-epoch mix_in_length sibling
        let mut per_epoch_len = [0u8; 32];
        per_epoch_len[0..8].copy_from_slice(&(per_epoch_count as u64).to_le_bytes());
        branch.push(per_epoch_len);
        // Epoch tree siblings
        branch.extend_from_slice(&self.withdrawal_epoch_tree.generate_proof(epoch_slot));
        // Epoch count mix_in_length sibling
        let mut epoch_len = [0u8; 32];
        epoch_len[0..8].copy_from_slice(&(epoch_count as u64).to_le_bytes());
        branch.push(epoch_len);
        // Top tree siblings
        branch.extend_from_slice(&self.top.generate_proof(WITHDRAWAL_QUEUE_ROOT));
        branch
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
    /// The proof leaf is the per-item subtree root (internal node 2 levels
    /// above the field leaves, since each item is a depth-2 / 4-leaf subtree).
    /// The branch is 2 elements shorter than a field-level proof.
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

        // Descend to the per-item subtree root, `log_block` levels above the field
        // leaves: `(sd - log_block)` subtree levels + 1 for the mix_in_length node.
        let log_block = ADDED_VALIDATOR_FIELDS_PER_ITEM.ilog2() as usize;
        let td = self.top.depth();
        let top_gindex = (1u64 << td) + ADDED_VALIDATORS_ROOT as u64;
        let gindex = (top_gindex << (sd - log_block + 1)) | (slot as u64);

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

/// A field-level proof bound to the collection item it belongs to.
///
/// A bare [`SszProof`] for a single field authenticates only that *some*
/// positional leaf exists under the root — it does not prove the field belongs
/// to the requested key (pubkey). For by-pubkey field proofs
/// (`withdrawal_field:`/`validator_field:`) the selector is resolved to a
/// position *server-side*, so a malicious provider could answer with the same
/// field from a *different* item under the same root and the branch would still
/// verify. `KeyedFieldProof` closes that gap by carrying a second proof of the
/// item's key leaf; [`KeyedFieldProof::verify`] checks both leaves authenticate
/// against the root, that the key leaf equals the requested key, that the key
/// proof addresses the canonical key field within its item (not just any field
/// that happens to hash to the key), and that the field and key leaves belong to
/// the *same* collection item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyedFieldProof {
    /// Proof of the requested field leaf.
    pub field: SszProof,
    /// Proof of the item's key (pubkey) leaf, binding `field` to the request.
    pub key: SszProof,
}

impl KeyedFieldProof {
    /// Verify that `field` is bound to `expected_key` under `state_root`.
    ///
    /// `fields_per_item` is the number of leaves per collection item (a power of
    /// two: [`WITHDRAWAL_FIELDS_PER_ITEM`] for withdrawals,
    /// [`VALIDATOR_FIELDS_PER_ACCOUNT`] for validator accounts). `key_field_index`
    /// is the canonical key-field selector within an item
    /// ([`WITHDRAWAL_FIELD_PUBKEY`] for withdrawals,
    /// [`VALIDATOR_FIELD_NODE_PUBKEY`] for validator accounts). Returns `true`
    /// only when all of the following hold:
    /// 1. both `field` and `key` authenticate against `state_root`,
    /// 2. the key leaf equals `hash_tree_root(expected_key)` (for a 32-byte key
    ///    this is the key itself),
    /// 3. the key proof addresses the canonical key field within its item (its
    ///    field-selector bits equal `key_field_index`), so the binding cannot
    ///    rest on some other field that merely happens to hash to the key, and
    /// 4. `field` and `key` resolve to the same item — i.e. their generalized
    ///    indices agree once the low `log2(fields_per_item)` field-selector bits
    ///    are dropped.
    pub fn verify(
        &self,
        state_root: &[u8; 32],
        expected_key: &[u8; 32],
        fields_per_item: usize,
        key_field_index: usize,
    ) -> bool {
        if !fields_per_item.is_power_of_two() {
            return false;
        }
        if !self.field.verify(state_root) || !self.key.verify(state_root) {
            return false;
        }
        if self.key.leaf != expected_key.hash_tree_root() {
            return false;
        }
        // The bottom `log2(fields_per_item)` bits of a gindex are the field
        // selector within the item. Require the key proof to address the
        // canonical key field, not just any field whose leaf equals the key.
        if (self.key.gindex & (fields_per_item as u64 - 1)) != key_field_index as u64 {
            return false;
        }
        // Shifting those selector bits off yields the item's subtree-root
        // gindex. Equal item roots ⟺ same item.
        let shift = fields_per_item.ilog2();
        (self.field.gindex >> shift) == (self.key.gindex >> shift)
    }
}

/// A single entry in a `GenerateStateProof` response.
///
/// `key` is `Some` only for by-pubkey field proofs, where it carries the item's
/// key-leaf proof so the consumer can bind the field to the requested pubkey via
/// [`KeyedFieldProof::verify`]. For scalar, whole-item, and index-addressed
/// proofs it is `None` and `field` stands alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateProofEntry {
    /// Proof of the requested leaf (field, scalar, or whole-item root).
    pub field: SszProof,
    /// For by-pubkey field requests, proof of the item's key leaf.
    pub key: Option<SszProof>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::execution_request::DepositRequest;
    use crate::withdrawal::{PendingWithdrawal, WithdrawalKind, WithdrawalQueue};
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

        tree.set_allowed_timestamp_future_ms(5_000);
        assert_ne!(tree.root(), r6);
        let r7 = tree.root();

        tree.set_next_withdrawal_index(7);
        assert_ne!(tree.root(), r7);
        let r8 = tree.root();

        tree.set_forkchoice_head_block_hash(&[3u8; 32]);
        assert_ne!(tree.root(), r8);
        let r9 = tree.root();

        tree.set_forkchoice_safe_block_hash(&[4u8; 32]);
        assert_ne!(tree.root(), r9);
        let r10 = tree.root();

        tree.set_forkchoice_finalized_block_hash(&[5u8; 32]);
        assert_ne!(tree.root(), r10);
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
        inc.set_allowed_timestamp_future_ms(10_000);
        inc.set_next_withdrawal_index(5);
        inc.set_forkchoice_head_block_hash(&[0xCC; 32]);
        inc.set_forkchoice_safe_block_hash(&[0xDD; 32]);
        inc.set_forkchoice_finalized_block_hash(&[0xEE; 32]);
        inc.set_treasury_address(&Address::ZERO);
        inc.set_max_deposits_per_epoch(3);
        inc.set_max_withdrawals_per_epoch(16);
        inc.set_observers_per_validator(5);
        inc.set_minimum_validator_count(3);
        inc.set_pending_active_validator_exits(0);
        inc.set_invalid_withdrawal_tax(0);
        inc.rebuild_validators(&accounts);
        inc.rebuild_deposits(&VecDeque::new());
        inc.rebuild_withdrawals(&WithdrawalQueue::default());
        inc.rebuild_protocol_params(&[]);
        inc.rebuild_added_validators(&BTreeMap::new());
        inc.rebuild_removed_validators(&[]);
        inc.rebuild_pending_execution_requests(&[]);
        inc.set_pending_checkpoint_digest(None);
        inc.set_dynamic_epoch_schedule(&[]);

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
            10_000,
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
            &Address::ZERO,
            3,
            16,
            5,
            &[],
            None,
            &[],
            3,
            0,
            0,
        );

        assert_eq!(inc.root(), rb.root());
    }

    #[test]
    fn pending_execution_requests_affect_root() {
        let mut tree = SszStateTree::new();
        tree.rebuild_pending_execution_requests(&[]);
        let empty_root = tree.root();

        // Adding a deferred request changes the state root.
        tree.rebuild_pending_execution_requests(&[alloy_primitives::Bytes::from(vec![1u8, 2, 3])]);
        let one_root = tree.root();
        assert_ne!(
            empty_root, one_root,
            "a pending execution request must be bound into the state root"
        );

        // Changing only the request contents changes the root.
        tree.rebuild_pending_execution_requests(&[alloy_primitives::Bytes::from(vec![4u8, 5, 6])]);
        assert_ne!(
            one_root,
            tree.root(),
            "different pending request contents must produce a different root"
        );

        // Clearing returns to the empty-collection root.
        tree.rebuild_pending_execution_requests(&[]);
        assert_eq!(empty_root, tree.root());
    }

    #[test]
    fn pending_checkpoint_affects_root() {
        let mut tree = SszStateTree::new();
        tree.set_pending_checkpoint_digest(None);
        let none_root = tree.root();

        // Setting a pending checkpoint binds its digest into the root.
        tree.set_pending_checkpoint_digest(Some([0xAB; 32]));
        let some_root = tree.root();
        assert_ne!(
            none_root, some_root,
            "a pending checkpoint must be bound into the state root"
        );

        // A different digest produces a different root.
        tree.set_pending_checkpoint_digest(Some([0xCD; 32]));
        assert_ne!(
            some_root,
            tree.root(),
            "a different pending-checkpoint digest must produce a different root"
        );

        // Clearing returns to the no-checkpoint root.
        tree.set_pending_checkpoint_digest(None);
        assert_eq!(none_root, tree.root());
    }

    #[test]
    fn dynamic_epoch_schedule_affects_root() {
        let mut tree = SszStateTree::new();
        tree.set_dynamic_epoch_schedule(&[1, 2, 3]);
        let root_a = tree.root();

        // A different encoded schedule must produce a different root.
        tree.set_dynamic_epoch_schedule(&[1, 2, 4]);
        assert_ne!(
            root_a,
            tree.root(),
            "a different epoch schedule must produce a different root"
        );

        // The same encoded schedule reproduces the same root.
        tree.set_dynamic_epoch_schedule(&[1, 2, 3]);
        assert_eq!(root_a, tree.root());
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
            10_000,
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
            &Address::ZERO,
            3,
            16,
            0,
            &[],
            None,
            &[],
            3,
            0,
            0,
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
        let pk3 = [3u8; 32];
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
            kind: WithdrawalKind::Validator,
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
            kind: WithdrawalKind::Validator,
        });
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 2,
                validator_index: 2,
                address: Address::from([0x33; 20]),
                amount: 3_000_000_000,
            },
            pubkey: pk3,
            balance_deduction: 3_000_000_000,
            epoch: 2,
            kind: WithdrawalKind::Validator,
        });

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);
        tree.set_epoch(5);

        let root = tree.root();

        // By-key proofs (O(1) lookup, no queue needed)
        let proof1 = tree.generate_withdrawal_proof_by_key(&pk1).unwrap();
        assert!(proof1.verify(&root));

        let proof2 = tree.generate_withdrawal_proof_by_key(&pk2).unwrap();
        assert!(proof2.verify(&root));

        let proof3 = tree.generate_withdrawal_proof_by_key(&pk3).unwrap();
        assert!(proof3.verify(&root));

        // By index: epoch_slot=0 (epoch 1) has 2 items, epoch_slot=1 (epoch 2) has 1
        let proof_idx = tree.generate_withdrawal_proof(0, 0).unwrap();
        assert!(proof_idx.verify(&root));
        let proof_idx = tree.generate_withdrawal_proof(0, 1).unwrap();
        assert!(proof_idx.verify(&root));
        let proof_idx = tree.generate_withdrawal_proof(1, 0).unwrap();
        assert!(proof_idx.verify(&root));

        // Unknown key returns None
        let unknown = [0xFFu8; 32];
        assert!(tree.generate_withdrawal_proof_by_key(&unknown).is_none());
    }

    #[test]
    fn withdrawal_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        // No epochs at all
        assert!(tree.generate_withdrawal_proof(0, 0).is_none());

        // Build with one epoch
        let mut queue = WithdrawalQueue::default();
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        });
        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);

        // epoch_slot out of bounds
        assert!(tree.generate_withdrawal_proof(1, 0).is_none());
        // item_slot out of bounds
        assert!(tree.generate_withdrawal_proof(0, 1).is_none());
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
    fn deposit_incremental_push_matches_rebuild() {
        let d1 = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let d2 = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(2).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(2).public_key(),
            withdrawal_credentials: [0x02; 32],
            amount: 64_000_000_000,
            node_signature: [0xCC; 64],
            consensus_signature: [0xDD; 96],
            index: 1,
        };

        // Incremental: push one by one
        let mut inc = SszStateTree::new();
        inc.push_deposit(&d1);
        inc.push_deposit(&d2);

        // Full rebuild
        let mut deposits = VecDeque::new();
        deposits.push_back(d1);
        deposits.push_back(d2);
        let mut full = SszStateTree::new();
        full.rebuild_deposits(&deposits);

        assert_eq!(inc.root(), full.root());

        // Proofs from incremental tree verify
        let root = inc.root();
        for i in 0..2 {
            let proof = inc.generate_deposit_proof(i).unwrap();
            assert!(proof.verify(&root), "deposit proof {i} failed");
        }
    }

    #[test]
    fn deposit_incremental_pop_matches_rebuild() {
        let d1 = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(1).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [0x01; 32],
            amount: 32_000_000_000,
            node_signature: [0xAA; 64],
            consensus_signature: [0xBB; 96],
            index: 0,
        };
        let d2 = DepositRequest {
            node_pubkey: ed25519::PrivateKey::from_seed(2).public_key(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(2).public_key(),
            withdrawal_credentials: [0x02; 32],
            amount: 64_000_000_000,
            node_signature: [0xCC; 64],
            consensus_signature: [0xDD; 96],
            index: 1,
        };

        // Build with 2 deposits
        let mut deposits = VecDeque::new();
        deposits.push_back(d1);
        deposits.push_back(d2.clone());
        let mut inc = SszStateTree::new();
        inc.rebuild_deposits(&deposits);

        // Pop front incrementally
        deposits.pop_front();
        inc.pop_deposit(&deposits);

        // Compare to full rebuild with just d2
        let mut full = SszStateTree::new();
        full.rebuild_deposits(&deposits);
        assert_eq!(inc.root(), full.root());

        // Proof for remaining deposit verifies
        let root = inc.root();
        let proof = inc.generate_deposit_proof(0).unwrap();
        assert!(proof.verify(&root));
        assert_eq!(proof.leaf, d2.hash_tree_root());
    }

    #[test]
    fn withdrawal_field_proof_verifies() {
        let mut queue = WithdrawalQueue::default();
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let pk3 = [3u8; 32];
        // Two withdrawals in epoch 1, one in epoch 2
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
            kind: WithdrawalKind::Validator,
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
            kind: WithdrawalKind::Validator,
        });
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 2,
                validator_index: 2,
                address: Address::from([0x33; 20]),
                amount: 3_000_000_000,
            },
            pubkey: pk3,
            balance_deduction: 3_000_000_000,
            epoch: 2,
            kind: WithdrawalKind::Validator,
        });

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);
        tree.set_epoch(5);

        let root = tree.root();

        // Verify field proofs for every withdrawal in epoch 1 (epoch_slot=0), every field
        for item_slot in 0..2 {
            for field_idx in 0..WITHDRAWAL_FIELDS_PER_ITEM {
                let proof = tree
                    .generate_withdrawal_field_proof(0, item_slot, field_idx)
                    .unwrap();
                assert!(
                    proof.verify(&root),
                    "epoch 1 withdrawal {item_slot} field proof failed for field {field_idx}"
                );
            }
        }

        // Verify field proofs for the withdrawal in epoch 2 (epoch_slot=1)
        for field_idx in 0..WITHDRAWAL_FIELDS_PER_ITEM {
            let proof = tree
                .generate_withdrawal_field_proof(1, 0, field_idx)
                .unwrap();
            assert!(
                proof.verify(&root),
                "epoch 2 withdrawal 0 field proof failed for field {field_idx}"
            );
        }

        // By-key field proof (O(1) lookup)
        let proof_by_key = tree
            .generate_withdrawal_field_proof_by_key(&pk1, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        assert!(proof_by_key.verify(&root));

        // Field proof branch is 3 elements longer than whole-item proof
        let item_proof = tree.generate_withdrawal_proof(0, 0).unwrap();
        let field_proof = tree
            .generate_withdrawal_field_proof(0, 0, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 3,
            "field branch should be 3 longer than item branch"
        );
    }

    #[test]
    fn withdrawal_keyed_field_proof_binds_to_requested_pubkey() {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let mut queue = WithdrawalQueue::default();
        // Two withdrawals in the same epoch with DIFFERENT amounts.
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

        // The honest keyed proof for pk1's amount binds to pk1.
        let keyed1 = tree
            .generate_withdrawal_keyed_field_proof_by_key(&pk1, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        assert!(
            keyed1.verify(
                &root,
                &pk1,
                WITHDRAWAL_FIELDS_PER_ITEM,
                WITHDRAWAL_FIELD_PUBKEY
            ),
            "honest keyed proof should bind to its own pubkey"
        );
        assert_eq!(keyed1.field.leaf, 1_000_000_000u64.hash_tree_root());

        // It must NOT verify against a different requested pubkey.
        assert!(
            !keyed1.verify(
                &root,
                &pk2,
                WITHDRAWAL_FIELDS_PER_ITEM,
                WITHDRAWAL_FIELD_PUBKEY
            ),
            "keyed proof must not verify against a different pubkey"
        );

        // Substitution attack: a malicious provider answers a by-pk1 request
        // with pk2's amount field. The bare positional field proof still
        // verifies against the root (this is the vulnerability), ...
        let pk2_amount = tree
            .generate_withdrawal_field_proof_by_key(&pk2, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        assert!(
            pk2_amount.verify(&root),
            "pk2's positional amount proof verifies against the root unaided"
        );
        assert_eq!(pk2_amount.leaf, 2_000_000_000u64.hash_tree_root());

        // ... but pairing it with any key proof cannot bind it to pk1: the only
        // key leaf equal to pk1 lives in pk1's item, whose gindex differs from
        // pk2's field gindex, so the same-item check fails.
        let pk1_key = tree
            .generate_withdrawal_field_proof_by_key(&pk1, WITHDRAWAL_FIELD_PUBKEY)
            .unwrap();
        let forged = KeyedFieldProof {
            field: pk2_amount,
            key: pk1_key,
        };
        assert!(
            !forged.verify(
                &root,
                &pk1,
                WITHDRAWAL_FIELDS_PER_ITEM,
                WITHDRAWAL_FIELD_PUBKEY
            ),
            "substituted field from a different withdrawal must not bind to pk1"
        );

        // Canonical-selector hardening: a `key` proof addressing a NON-pubkey
        // field must be rejected even when its leaf equals the requested key and
        // it sits in the same item as `field`. Use pk1's amount field as the
        // stand-in key and request a key equal to that field's leaf: the leaf
        // and same-item checks both pass, so only the selector check rejects it.
        let pk1_amount = tree
            .generate_withdrawal_field_proof_by_key(&pk1, WITHDRAWAL_FIELD_AMOUNT)
            .unwrap();
        let amount_leaf: [u8; 32] = 1_000_000_000u64.hash_tree_root();
        assert_eq!(pk1_amount.leaf, amount_leaf);
        let mis_selected = KeyedFieldProof {
            field: pk1_amount.clone(),
            key: pk1_amount,
        };
        assert!(
            !mis_selected.verify(
                &root,
                &amount_leaf,
                WITHDRAWAL_FIELDS_PER_ITEM,
                WITHDRAWAL_FIELD_PUBKEY
            ),
            "a key proof addressing a non-pubkey field must be rejected by the selector check"
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
            kind: WithdrawalKind::Validator,
        };
        let mut queue = WithdrawalQueue::default();
        queue.push(withdrawal.clone());

        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);

        // epoch_slot=0, item_slot=0
        let proof = tree.generate_withdrawal_proof(0, 0).unwrap();
        assert_eq!(proof.leaf, withdrawal.hash_tree_root());
    }

    #[test]
    fn withdrawal_field_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        // No epochs
        assert!(tree.generate_withdrawal_field_proof(0, 0, 0).is_none());

        // Build with one withdrawal in epoch 1
        let mut queue = WithdrawalQueue::default();
        queue.push(PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        });
        let mut tree = SszStateTree::new();
        tree.rebuild_withdrawals(&queue);

        // Invalid field index
        assert!(tree.generate_withdrawal_field_proof(0, 0, 8).is_none());
        // Invalid item_slot
        assert!(tree.generate_withdrawal_field_proof(0, 1, 0).is_none());
        // Invalid epoch_slot
        assert!(tree.generate_withdrawal_field_proof(1, 0, 0).is_none());
    }

    #[test]
    fn withdrawal_incremental_push_matches_rebuild() {
        let w1 = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        let w2 = PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 1,
                address: Address::from([0x22; 20]),
                amount: 2_000_000_000,
            },
            pubkey: [2u8; 32],
            balance_deduction: 2_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        let w3 = PendingWithdrawal {
            inner: Withdrawal {
                index: 2,
                validator_index: 2,
                address: Address::from([0x33; 20]),
                amount: 3_000_000_000,
            },
            pubkey: [3u8; 32],
            balance_deduction: 3_000_000_000,
            epoch: 2,
            kind: WithdrawalKind::Validator,
        };

        // Incremental: push one by one
        let mut inc = SszStateTree::new();
        inc.push_withdrawal(&w1);
        inc.push_withdrawal(&w2); // same epoch
        inc.push_withdrawal(&w3); // new epoch

        // Full rebuild
        let mut queue = WithdrawalQueue::default();
        queue.push(w1);
        queue.push(w2);
        queue.push(w3);
        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue);

        assert_eq!(inc.root(), full.root());

        // Proofs from incremental tree verify
        let root = inc.root();
        let proof = inc.generate_withdrawal_proof_by_key(&[1u8; 32]).unwrap();
        assert!(proof.verify(&root));
        let proof = inc.generate_withdrawal_proof_by_key(&[3u8; 32]).unwrap();
        assert!(proof.verify(&root));
    }

    #[test]
    fn withdrawal_incremental_pop_matches_rebuild() {
        let w1 = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        let w2 = PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 1,
                address: Address::from([0x22; 20]),
                amount: 2_000_000_000,
            },
            pubkey: [2u8; 32],
            balance_deduction: 2_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        let w3 = PendingWithdrawal {
            inner: Withdrawal {
                index: 2,
                validator_index: 2,
                address: Address::from([0x33; 20]),
                amount: 3_000_000_000,
            },
            pubkey: [3u8; 32],
            balance_deduction: 3_000_000_000,
            epoch: 2,
            kind: WithdrawalKind::Validator,
        };

        // Start with full rebuild of 3 items
        let mut queue = WithdrawalQueue::default();
        queue.push(w1.clone());
        queue.push(w2.clone());
        queue.push(w3.clone());
        let mut inc = SszStateTree::new();
        inc.rebuild_withdrawals(&queue);

        // Pop w1 (front of epoch 1) incrementally
        queue.pop(1);
        inc.pop_withdrawal(1, &w1.pubkey, &queue);

        // Compare to full rebuild
        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue);
        assert_eq!(inc.root(), full.root());

        // Pop w2 (last in epoch 1, removes epoch) incrementally
        queue.pop(1);
        inc.pop_withdrawal(1, &w2.pubkey, &queue);

        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue);
        assert_eq!(inc.root(), full.root());

        // Pop w3 (last item, removes last epoch) incrementally
        queue.pop(2);
        inc.pop_withdrawal(2, &w3.pubkey, &queue);

        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue);
        assert_eq!(inc.root(), full.root());
    }

    #[test]
    fn withdrawal_incremental_update_matches_rebuild() {
        let w1 = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };

        let mut queue = WithdrawalQueue::default();
        queue.push(w1);
        let mut inc = SszStateTree::new();
        inc.rebuild_withdrawals(&queue);

        // Simulate a merge: amount and balance_deduction change
        let updated = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 5_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 5_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        inc.update_withdrawal(&updated);

        // Compare to full rebuild with updated data
        let mut queue2 = WithdrawalQueue::default();
        queue2.push(updated);
        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue2);
        assert_eq!(inc.root(), full.root());
    }

    #[test]
    fn withdrawal_push_new_epoch_between_existing() {
        // Push epochs 1, 3, then 2 — tests sorted insertion
        let w1 = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::from([0x11; 20]),
                amount: 1_000_000_000,
            },
            pubkey: [1u8; 32],
            balance_deduction: 1_000_000_000,
            epoch: 1,
            kind: WithdrawalKind::Validator,
        };
        let w3 = PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 1,
                address: Address::from([0x33; 20]),
                amount: 3_000_000_000,
            },
            pubkey: [3u8; 32],
            balance_deduction: 3_000_000_000,
            epoch: 3,
            kind: WithdrawalKind::Validator,
        };
        let w2 = PendingWithdrawal {
            inner: Withdrawal {
                index: 2,
                validator_index: 2,
                address: Address::from([0x22; 20]),
                amount: 2_000_000_000,
            },
            pubkey: [2u8; 32],
            balance_deduction: 2_000_000_000,
            epoch: 2,
            kind: WithdrawalKind::Validator,
        };

        let mut inc = SszStateTree::new();
        inc.push_withdrawal(&w1);
        inc.push_withdrawal(&w3);
        inc.push_withdrawal(&w2); // inserted between epoch 1 and 3

        let mut queue = WithdrawalQueue::default();
        queue.push(w1);
        queue.push(w3);
        queue.push(w2);
        let mut full = SszStateTree::new();
        full.rebuild_withdrawals(&queue);

        assert_eq!(inc.root(), full.root());

        // Verify pubkey lookups still work after epoch insertion
        let root = inc.root();
        for pk in [[1u8; 32], [2u8; 32], [3u8; 32]] {
            let proof = inc.generate_withdrawal_proof_by_key(&pk).unwrap();
            assert!(proof.verify(&root), "proof failed for pubkey {:?}", pk);
        }
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

        // Field proof branch is 4 elements longer (depth-4 per-validator subtree:
        // 9 fields incl. node pubkey, padded to 16 leaves)
        assert_eq!(
            field_proof.branch.len(),
            account_proof.branch.len() + 4,
            "field branch should be 4 longer than account branch"
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

        // The whole-account proof leaf is the per-validator subtree root: the 8
        // account fields plus the node pubkey (field 8), merkleized over 16 leaves.
        // (No longer equal to ValidatorAccount::hash_tree_root, which omits the key.)
        let expected = crate::ssz_tree::merkleize(&[
            acc.consensus_public_key.hash_tree_root(),
            acc.withdrawal_credentials.hash_tree_root(),
            acc.balance.hash_tree_root(),
            acc.status.hash_tree_root(),
            acc.has_pending_deposit.hash_tree_root(),
            acc.has_pending_withdrawal.hash_tree_root(),
            acc.joining_epoch.hash_tree_root(),
            acc.last_deposit_index.hash_tree_root(),
            pk,
        ]);
        assert_eq!(proof.leaf, expected);
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

    /// Expected per-item leaf for an added validator: node key, consensus key, and
    /// the activation epoch, merkleized over 4 leaves (matches the SSZ subtree root).
    fn added_validator_entry_root(epoch: u64, av: &AddedValidator) -> [u8; 32] {
        crate::ssz_tree::merkleize(&[
            av.node_key.hash_tree_root(),
            av.consensus_key.hash_tree_root(),
            epoch.hash_tree_root(),
        ])
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
            inc_tree.insert_validator_at_slot(slot, pk, acc);
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
            tree.insert_validator_at_slot(slot, &new_pk, &new_acc);

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
            modified.insert_validator_at_slot(slot, &new_pk, &new_acc);

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
            modified.insert_validator_at_slot(slot, &pk, &acc);

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
        modified.insert_validator_at_slot(slot_a, &pk_a, &acc_a);

        // Insert B
        modified_accounts.insert(pk_b, acc_b.clone());
        let slot_b = modified_accounts.keys().position(|k| k == &pk_b).unwrap();
        modified.insert_validator_at_slot(slot_b, &pk_b, &acc_b);

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
        tree.insert_validator_at_slot(slot, &new_pk, &new_acc);

        // Update its balance
        new_acc.balance = 64_000_000_000;
        accounts.insert(new_pk, new_acc.clone());
        tree.update_validator_at_slot(slot, &new_pk, &new_acc);

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
            inc_tree.insert_validator_at_slot(slot, &pk, &acc);

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
            tree.insert_validator_at_slot(slot, &pk, &acc);
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
            tree.insert_validator_at_slot(slot, &pk, &acc);
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
            tree.insert_validator_at_slot(slot, &pk, &acc);
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
        tree.insert_validator_at_slot(slot, &new_pk, &new_acc);

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

        // Flattened items, carrying each item's activation epoch.
        let items: Vec<(u64, AddedValidator)> = added
            .iter()
            .flat_map(|(epoch, v)| v.iter().cloned().map(move |av| (*epoch, av)))
            .collect();

        for (i, (epoch, av)) in items.iter().enumerate() {
            let proof = tree.generate_added_validator_proof(i).unwrap();
            assert_eq!(proof.leaf, added_validator_entry_root(*epoch, av));
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
        assert_eq!(proof.leaf, added_validator_entry_root(3, &added[&3][1]));
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

        // Field proof branch is 2 elements longer than whole-item proof
        // (depth-2 per-item subtree: 3 fields incl. epoch, padded to 4 leaves)
        let item_proof = tree.generate_added_validator_proof(0).unwrap();
        let field_proof = tree
            .generate_added_validator_field_proof(0, ADDED_VALIDATOR_FIELD_NODE_KEY)
            .unwrap();
        assert_eq!(
            field_proof.branch.len(),
            item_proof.branch.len() + 2,
            "field branch should be 2 longer than item branch"
        );

        // Out of bounds (fields 0..=2 are valid: node_key, consensus_key, epoch)
        assert!(tree.generate_added_validator_field_proof(0, 4).is_none());
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
        assert_eq!(proof.leaf, added_validator_entry_root(1, &av));
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
