//! Two-level SSZ binary Merkle tree for ConsensusState.
//!
//! The top-level tree has 32 leaf slots (17 used, depth 5). Scalar fields
//! occupy leaves 0–10. Collection roots occupy leaves 11–16.
//!
//! The validator accounts collection uses a dedicated subtree (`SszTree`).
//! Validator slot assignment is purely positional: the i-th entry in
//! `BTreeMap<[u8; 32], ValidatorAccount>` iteration order occupies leaf i.
//! The subtree is rebuilt from scratch on every mutation for determinism.

use crate::PublicKey;
use crate::account::ValidatorAccount;
use crate::execution_request::DepositRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::ssz_hash::SszHashTreeRoot;
use crate::ssz_tree::{SszTree, merkleize, mix_in_length};
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
    /// Slot assignment is purely positional: the i-th entry in BTreeMap
    /// iteration order (sorted by `[u8; 32]` key) occupies leaf i.
    pub fn rebuild_validators(&mut self, accounts: &BTreeMap<[u8; 32], ValidatorAccount>) {
        let count = accounts.len();
        let capacity = count.max(1);
        let mut tree = SszTree::new(capacity);
        for (i, account) in accounts.values().enumerate() {
            tree.set_leaf(i, account.hash_tree_root());
        }
        self.validator_tree = tree;
        self.validator_count = count;
        self.update_validator_collection_root();
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
    pub fn rebuild_deposits(&mut self, deposits: &VecDeque<DepositRequest>) {
        let count = deposits.len();
        let capacity = count.max(1);
        let mut tree = SszTree::new(capacity);
        for (i, deposit) in deposits.iter().enumerate() {
            tree.set_leaf(i, deposit.hash_tree_root());
        }
        self.deposit_tree = tree;
        self.deposit_count = count;
        self.update_deposit_collection_root();
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
    pub fn rebuild_withdrawals(&mut self, queue: &WithdrawalQueue) {
        let items: Vec<[u8; 32]> = queue
            .withdrawals_iter()
            .map(|(_, w)| w.hash_tree_root())
            .collect();
        let count = items.len();
        let capacity = count.max(1);
        let mut tree = SszTree::new(capacity);
        for (i, hash) in items.iter().enumerate() {
            tree.set_leaf(i, *hash);
        }
        self.withdrawal_tree = tree;
        self.withdrawal_count = count;
        self.update_withdrawal_collection_root();
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

    /// Recompute protocol param changes root.
    pub fn update_protocol_param_changes_root(&mut self, params: &[ProtocolParam]) {
        let root = collection_root_from(params.iter().map(|p| p.hash_tree_root()), params.len());
        self.top.set_leaf(PROTOCOL_PARAM_CHANGES_ROOT, root);
    }

    /// Recompute added validators root (flattened across all epochs).
    pub fn update_added_validators_root(
        &mut self,
        validators: &BTreeMap<u64, Vec<AddedValidator>>,
    ) {
        let items: Vec<[u8; 32]> = validators
            .values()
            .flat_map(|v| v.iter().map(|av| av.hash_tree_root()))
            .collect();
        let len = items.len();
        let root = collection_root_from(items.into_iter(), len);
        self.top.set_leaf(ADDED_VALIDATORS_ROOT, root);
    }

    /// Recompute removed validators root.
    pub fn update_removed_validators_root(&mut self, validators: &[PublicKey]) {
        let root = collection_root_from(
            validators.iter().map(|v| v.hash_tree_root()),
            validators.len(),
        );
        self.top.set_leaf(REMOVED_VALIDATORS_ROOT, root);
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
        self.update_protocol_param_changes_root(protocol_param_changes);
        self.update_added_validators_root(added_validators);
        self.update_removed_validators_root(removed_validators);
    }

    // --- Proof generation ---

    /// Generate a proof for a top-level scalar field.
    pub fn generate_scalar_proof(&self, leaf_index: usize) -> StateProof {
        StateProof {
            leaf_index,
            leaf_value: self.top.get_leaf(leaf_index),
            branch: self.top.generate_proof(leaf_index),
        }
    }

    /// Generate a proof for a validator account.
    ///
    /// The validator's positional index is computed from `keys`,
    /// which must be the sorted pubkeys used to build the tree.
    /// Returns `None` if the pubkey is not in the keys.
    pub fn generate_validator_proof(
        &self,
        pubkey: &[u8; 32],
        keys: &[[u8; 32]],
    ) -> Option<CollectionProof> {
        let slot = Self::get_validator_index(keys, pubkey)?;
        Some(CollectionProof {
            item_index: slot,
            leaf_value: self.validator_tree.get_leaf(slot),
            subtree_branch: self.validator_tree.generate_proof(slot),
            subtree_root: self.validator_tree.root(),
            collection_length: self.validator_count,
            top_leaf_index: VALIDATOR_ACCOUNTS_ROOT,
            top_branch: self.top.generate_proof(VALIDATOR_ACCOUNTS_ROOT),
        })
    }

    /// Generate a proof for a deposit at a given queue index.
    pub fn generate_deposit_proof(&self, index: usize) -> Option<CollectionProof> {
        if index >= self.deposit_count {
            return None;
        }
        Some(CollectionProof {
            item_index: index,
            leaf_value: self.deposit_tree.get_leaf(index),
            subtree_branch: self.deposit_tree.generate_proof(index),
            subtree_root: self.deposit_tree.root(),
            collection_length: self.deposit_count,
            top_leaf_index: DEPOSIT_QUEUE_ROOT,
            top_branch: self.top.generate_proof(DEPOSIT_QUEUE_ROOT),
        })
    }

    /// Generate a proof for a withdrawal identified by pubkey.
    pub fn generate_withdrawal_proof(
        &self,
        pubkey: &[u8; 32],
        keys: &[[u8; 32]],
    ) -> Option<CollectionProof> {
        let slot = keys.iter().position(|k| k == pubkey)?;
        if slot >= self.withdrawal_count {
            return None;
        }
        Some(CollectionProof {
            item_index: slot,
            leaf_value: self.withdrawal_tree.get_leaf(slot),
            subtree_branch: self.withdrawal_tree.generate_proof(slot),
            subtree_root: self.withdrawal_tree.root(),
            collection_length: self.withdrawal_count,
            top_leaf_index: WITHDRAWAL_QUEUE_ROOT,
            top_branch: self.top.generate_proof(WITHDRAWAL_QUEUE_ROOT),
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

/// Proof for a scalar field in the top-level tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateProof {
    pub leaf_index: usize,
    pub leaf_value: [u8; 32],
    pub branch: Vec<[u8; 32]>,
}

impl StateProof {
    /// Verify this proof against a state root.
    pub fn verify(&self, state_root: &[u8; 32], top_depth: usize) -> bool {
        SszTree::verify_proof(
            state_root,
            self.leaf_index,
            &self.leaf_value,
            &self.branch,
            top_depth,
        )
    }
}

/// Proof for an element in a collection subtree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionProof {
    /// Index of the element within the subtree.
    pub item_index: usize,
    /// Hash-tree-root of the element.
    pub leaf_value: [u8; 32],
    /// Merkle siblings from element leaf to subtree root (bottom-up).
    pub subtree_branch: Vec<[u8; 32]>,
    /// The subtree root (before mix_in_length).
    pub subtree_root: [u8; 32],
    /// Number of items in the collection (for mix_in_length).
    pub collection_length: usize,
    /// Index of the collection root in the top-level tree.
    pub top_leaf_index: usize,
    /// Merkle siblings from collection leaf to state root (bottom-up).
    pub top_branch: Vec<[u8; 32]>,
}

impl CollectionProof {
    /// Verify this proof against a state root.
    pub fn verify(&self, state_root: &[u8; 32]) -> bool {
        // 1. Verify subtree proof
        let subtree_depth = self.subtree_branch.len();
        if !SszTree::verify_proof(
            &self.subtree_root,
            self.item_index,
            &self.leaf_value,
            &self.subtree_branch,
            subtree_depth,
        ) {
            return false;
        }

        // 2. Compute collection leaf = mix_in_length(subtree_root, length)
        let collection_leaf = mix_in_length(self.subtree_root, self.collection_length);

        // 3. Verify top-level proof
        let top_depth = self.top_branch.len();
        SszTree::verify_proof(
            state_root,
            self.top_leaf_index,
            &collection_leaf,
            &self.top_branch,
            top_depth,
        )
    }
}

/// Tagged proof for a single key query (scalar or collection).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "proof_type")]
pub enum SszStateProof {
    Scalar(StateProof),
    Collection(CollectionProof),
}

/// Compute a collection root: `mix_in_length(merkleize(items), length)`.
fn collection_root_from(items: impl Iterator<Item = [u8; 32]>, length: usize) -> [u8; 32] {
    let chunks: Vec<[u8; 32]> = items.collect();
    mix_in_length(merkleize(&chunks), length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::withdrawal::WithdrawalQueue;
    use alloy_primitives::Address;
    use commonware_cryptography::Signer;
    use commonware_cryptography::bls12381;

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
        assert!(proof.verify(&root, tree.top_tree_depth()));

        let proof_view = tree.generate_scalar_proof(VIEW);
        assert!(proof_view.verify(&root, tree.top_tree_depth()));
    }

    #[test]
    fn scalar_proof_fails_wrong_root() {
        let mut tree = SszStateTree::new();
        tree.set_epoch(42);
        let proof = tree.generate_scalar_proof(EPOCH);
        assert!(!proof.verify(&[0xFF; 32], tree.top_tree_depth()));
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
        inc.update_protocol_param_changes_root(&[]);
        inc.update_added_validators_root(&BTreeMap::new());
        inc.update_removed_validators_root(&[]);

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
        assert!(scalar_proof.verify(&root, tree.top_tree_depth()));
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
        use crate::execution_request::DepositRequest;
        use commonware_cryptography::ed25519;

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
        assert_eq!(proof.top_leaf_index, DEPOSIT_QUEUE_ROOT);
    }

    #[test]
    fn deposit_proof_out_of_bounds() {
        let tree = SszStateTree::new();
        assert!(tree.generate_deposit_proof(0).is_none());
    }

    #[test]
    fn withdrawal_proof_verifies() {
        use crate::withdrawal::PendingWithdrawal;
        use alloy_eips::eip4895::Withdrawal;

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
        let keys: Vec<[u8; 32]> = queue.withdrawals_iter().map(|(k, _)| *k).collect();

        let proof1 = tree.generate_withdrawal_proof(&pk1, &keys).unwrap();
        assert!(proof1.verify(&root));
        assert_eq!(proof1.top_leaf_index, WITHDRAWAL_QUEUE_ROOT);

        let proof2 = tree.generate_withdrawal_proof(&pk2, &keys).unwrap();
        assert!(proof2.verify(&root));
    }

    #[test]
    fn withdrawal_proof_unknown_key() {
        let tree = SszStateTree::new();
        assert!(tree.generate_withdrawal_proof(&[99u8; 32], &[]).is_none());
    }
}
