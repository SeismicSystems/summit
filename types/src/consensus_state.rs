use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::checkpoint::Checkpoint;
use crate::execution_request::{DepositRequest, WithdrawalRequest};
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::state_trie::StateTrie;
use crate::state_trie_key;
use crate::withdrawal::{PendingWithdrawal, WithdrawalQueue};
use crate::{Digest, PublicKey};
use alloy_rpc_types_engine::ForkchoiceState;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{bls12381, sha256};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug)]
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

    /// In-memory Merkle Patricia Trie over validator_accounts.
    /// Not serialized — rebuilt from validator_accounts on deserialization.
    pub(crate) state_trie: StateTrie,

    /// Snapshot of `state_trie.root()` captured after block execution.
    /// Not serialized — set via `capture_state_root()` in the finalizer after `execute_block`.
    /// Survives finalization mutations (which change the live trie but not this field).
    pub(crate) state_root: [u8; 32],
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
            state_trie: StateTrie::default(),
            state_root: [0u8; 32],
        };
        s.rebuild_state_trie();
        s
    }
}

impl ConsensusState {
    pub fn new(
        forkchoice: ForkchoiceState,
        validator_minimum_stake: u64,
        validator_maximum_stake: u64,
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
            state_trie: StateTrie::default(),
            state_root: [0u8; 32],
        };
        s.rebuild_state_trie();
        s
    }

    // State variable operations
    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.state_trie.insert_u64(state_trie_key::EPOCH, epoch);
    }

    pub fn get_view(&self) -> u64 {
        self.view
    }

    pub fn set_view(&mut self, view: u64) {
        self.view = view;
        self.state_trie.insert_u64(state_trie_key::VIEW, view);
    }

    pub fn get_latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn set_latest_height(&mut self, height: u64) {
        self.latest_height = height;
        self.state_trie
            .insert_u64(state_trie_key::LATEST_HEIGHT, height);
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

    pub fn set_minimum_stake(&mut self, stake: u64) {
        self.validator_minimum_stake = stake;
        self.state_trie
            .insert_u64(state_trie_key::VALIDATOR_MINIMUM_STAKE, stake);
    }

    pub fn set_maximum_stake(&mut self, stake: u64) {
        self.validator_maximum_stake = stake;
        self.state_trie
            .insert_u64(state_trie_key::VALIDATOR_MAXIMUM_STAKE, stake);
    }

    pub fn get_pending_checkpoint(&self) -> Option<&Checkpoint> {
        self.pending_checkpoint.as_ref()
    }

    pub fn set_next_withdrawal_index(&mut self, index: u64) {
        self.withdrawal_queue.set_next_index(index);
        self.state_trie
            .insert_u64(state_trie_key::NEXT_WITHDRAWAL_INDEX, index);
    }

    pub fn set_pending_checkpoint(&mut self, checkpoint: Option<Checkpoint>) {
        self.pending_checkpoint = checkpoint;
    }

    pub fn get_added_validators(&self, epoch: u64) -> Option<&Vec<AddedValidator>> {
        self.added_validators.get(&epoch)
    }

    pub fn add_validator(&mut self, epoch: u64, validator: AddedValidator) {
        let node_key_bytes: [u8; 32] = validator.node_key.as_ref().try_into().unwrap();
        let encoded = validator.consensus_key.encode();
        self.state_trie.insert_raw(
            &state_trie_key::added_validators_consensus_key(&node_key_bytes),
            &encoded,
        );
        self.added_validators
            .entry(epoch)
            .or_default()
            .push(validator);
    }

    pub fn get_removed_validators(&self) -> &Vec<PublicKey> {
        &self.removed_validators
    }

    pub fn set_removed_validators(&mut self, validators: Vec<PublicKey>) {
        // Remove old trie entries
        for pubkey in &self.removed_validators {
            let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
            self.state_trie
                .remove_raw(&state_trie_key::removed_validators(&pubkey_bytes));
        }
        // Insert new trie entries
        for pubkey in &validators {
            let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
            self.state_trie
                .insert_raw(&state_trie_key::removed_validators(&pubkey_bytes), &[1]);
        }
        self.removed_validators = validators;
    }

    pub fn get_forkchoice(&self) -> &ForkchoiceState {
        &self.forkchoice
    }

    pub fn set_forkchoice(&mut self, forkchoice: ForkchoiceState) {
        self.forkchoice = forkchoice;
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_HEAD_BLOCK_HASH,
            &forkchoice.head_block_hash.0,
        );
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH,
            &forkchoice.safe_block_hash.0,
        );
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_FINALIZED_BLOCK_HASH,
            &forkchoice.finalized_block_hash.0,
        );
    }

    pub fn get_epoch_genesis_hash(&self) -> [u8; 32] {
        self.epoch_genesis_hash
    }

    pub fn set_epoch_genesis_hash(&mut self, hash: [u8; 32]) {
        self.epoch_genesis_hash = hash;
        self.state_trie
            .insert_hash(state_trie_key::EPOCH_GENESIS_HASH, &hash);
    }

    pub fn get_head_digest_ref(&self) -> &Digest {
        &self.head_digest
    }

    pub fn set_head_digest(&mut self, digest: Digest) {
        self.head_digest = digest;
        self.state_trie
            .insert_hash(state_trie_key::HEAD_DIGEST, &digest.0);
    }

    pub fn set_forkchoice_head(&mut self, hash: alloy_primitives::B256) {
        self.forkchoice.head_block_hash = hash;
        self.state_trie
            .insert_hash(state_trie_key::FORKCHOICE_HEAD_BLOCK_HASH, &hash.0);
    }

    pub fn set_forkchoice_safe_and_finalized(&mut self, hash: alloy_primitives::B256) {
        self.forkchoice.safe_block_hash = hash;
        self.forkchoice.finalized_block_hash = hash;
        self.state_trie
            .insert_hash(state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH, &hash.0);
        self.state_trie
            .insert_hash(state_trie_key::FORKCHOICE_FINALIZED_BLOCK_HASH, &hash.0);
    }

    pub fn take_pending_checkpoint(&mut self) -> Option<Checkpoint> {
        self.pending_checkpoint.take()
    }

    pub fn push_protocol_param_change(&mut self, param: ProtocolParam) {
        let (variant_name, value) = match &param {
            ProtocolParam::MinimumStake(v) => (b"minimum_stake" as &[u8], *v),
            ProtocolParam::MaximumStake(v) => (b"maximum_stake" as &[u8], *v),
        };
        self.state_trie.insert_u64(
            &state_trie_key::protocol_param_changes_param(variant_name),
            value,
        );
        self.protocol_param_changes.push(param);
    }

    pub fn push_removed_validator(&mut self, pubkey: PublicKey) {
        let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
        self.state_trie
            .insert_raw(&state_trie_key::removed_validators(&pubkey_bytes), &[1]);
        self.removed_validators.push(pubkey);
    }

    pub fn clear_removed_validators(&mut self) {
        for pubkey in &self.removed_validators {
            let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
            self.state_trie
                .remove_raw(&state_trie_key::removed_validators(&pubkey_bytes));
        }
        self.removed_validators.clear();
    }

    pub fn has_removed_validators(&self) -> bool {
        !self.removed_validators.is_empty()
    }

    pub fn has_added_validators(&self, epoch: u64) -> bool {
        self.added_validators.contains_key(&epoch)
    }

    pub fn remove_added_validators_for_epoch(&mut self, epoch: u64) -> Option<Vec<AddedValidator>> {
        let validators = self.added_validators.remove(&epoch)?;
        for v in &validators {
            let node_key_bytes: [u8; 32] = v.node_key.as_ref().try_into().unwrap();
            self.state_trie
                .remove_raw(&state_trie_key::added_validators_consensus_key(
                    &node_key_bytes,
                ));
        }
        Some(validators)
    }

    pub fn remove_added_validator(&mut self, epoch: u64, pubkey: &PublicKey) -> bool {
        if let Some(validators) = self.added_validators.get_mut(&epoch)
            && let Some(pos) = validators.iter().position(|v| v.node_key == *pubkey)
        {
            let removed = validators.remove(pos);
            let node_key_bytes: [u8; 32] = removed.node_key.as_ref().try_into().unwrap();
            self.state_trie
                .remove_raw(&state_trie_key::added_validators_consensus_key(
                    &node_key_bytes,
                ));
            return true;
        }
        false
    }

    pub fn take_pending_execution_requests(&mut self) -> Vec<alloy_primitives::Bytes> {
        std::mem::take(&mut self.pending_execution_requests)
    }

    pub fn push_pending_execution_request(&mut self, request: alloy_primitives::Bytes) {
        self.pending_execution_requests.push(request);
    }

    // Account operations
    pub fn get_account(&self, pubkey: &[u8; 32]) -> Option<&ValidatorAccount> {
        self.validator_accounts.get(pubkey)
    }

    pub fn set_account(&mut self, pubkey: [u8; 32], account: ValidatorAccount) {
        self.insert_validator_trie_entries(&pubkey, &account);
        self.validator_accounts.insert(pubkey, account);
    }

    pub fn remove_account(&mut self, pubkey: &[u8; 32]) -> Option<ValidatorAccount> {
        self.remove_validator_trie_entries(pubkey);
        self.validator_accounts.remove(pubkey)
    }

    pub fn num_validators(&self) -> usize {
        self.validator_accounts.len()
    }

    pub fn validator_accounts_iter(&self) -> impl Iterator<Item = (&[u8; 32], &ValidatorAccount)> {
        self.validator_accounts.iter()
    }

    pub fn set_validator_accounts(&mut self, accounts: BTreeMap<[u8; 32], ValidatorAccount>) {
        self.validator_accounts = accounts;
        self.rebuild_state_trie();
    }

    pub fn state_trie(&self) -> &StateTrie {
        &self.state_trie
    }

    /// Snapshot the current trie root. Called after `execute_block` so that
    /// subsequent finalization mutations don't alter the captured value.
    pub fn capture_state_root(&mut self) {
        self.state_root = self.state_trie.root();
    }

    /// Returns the state root captured by `capture_state_root()`.
    pub fn get_state_root(&self) -> [u8; 32] {
        self.state_root
    }

    // Deposit queue operations
    pub fn push_deposit(&mut self, request: DepositRequest) {
        self.insert_deposit_trie_entries(&request);
        self.deposit_queue.push_back(request);
    }

    pub fn peek_deposit(&self) -> Option<&DepositRequest> {
        self.deposit_queue.front()
    }

    pub fn pop_deposit(&mut self) -> Option<DepositRequest> {
        let request = self.deposit_queue.pop_front()?;
        self.remove_deposit_trie_entries(&request);
        Some(request)
    }

    // Withdrawal queue operations
    pub fn push_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_epoch: u64,
        balance_deduction: u64,
    ) {
        let pubkey = request.validator_pubkey;
        self.withdrawal_queue
            .push_request(request, withdrawal_epoch, balance_deduction);
        // After push (which may merge), clone the current state and update trie
        let w = self.withdrawal_queue.get_withdrawal(&pubkey).cloned();
        if let Some(w) = &w {
            self.insert_withdrawal_trie_entries(&pubkey, w);
        }
    }

    pub fn push_withdrawal(&mut self, request: PendingWithdrawal) {
        let pubkey = request.pubkey;
        self.withdrawal_queue.push(request);
        let w = self.withdrawal_queue.get_withdrawal(&pubkey).cloned();
        if let Some(w) = &w {
            self.insert_withdrawal_trie_entries(&pubkey, w);
        }
    }

    pub fn peek_withdrawal(&self, withdrawal_epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue.peek(withdrawal_epoch)
    }

    pub fn pop_withdrawal(&mut self, withdrawal_epoch: u64) -> Option<PendingWithdrawal> {
        let w = self.withdrawal_queue.pop(withdrawal_epoch)?;
        self.remove_withdrawal_trie_entries(&w.pubkey);
        Some(w)
    }

    /// Get all pending withdrawals for a specific epoch
    pub fn get_withdrawals_for_epoch(&self, epoch: u64) -> Vec<&PendingWithdrawal> {
        self.withdrawal_queue.get_for_epoch(epoch)
    }

    /// Get the number of pending withdrawals for a specific epoch
    pub fn get_withdrawal_count_for_epoch(&self, epoch: u64) -> usize {
        self.withdrawal_queue.count_for_epoch(epoch)
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

    pub fn apply_protocol_parameter_changes(&mut self) -> bool {
        let mut min_or_max_stake_changed = false;
        while let Some(param) = self.protocol_param_changes.pop() {
            match param {
                ProtocolParam::MinimumStake(min_stake) => {
                    self.validator_minimum_stake = min_stake;
                    self.state_trie
                        .insert_u64(state_trie_key::VALIDATOR_MINIMUM_STAKE, min_stake);
                    min_or_max_stake_changed = true;
                }
                ProtocolParam::MaximumStake(max_stake) => {
                    self.validator_maximum_stake = max_stake;
                    self.state_trie
                        .insert_u64(state_trie_key::VALIDATOR_MAXIMUM_STAKE, max_stake);
                    min_or_max_stake_changed = true;
                }
            }
        }
        // Protocol param changes have been consumed, remove their trie entries
        self.state_trie
            .remove_raw(&state_trie_key::protocol_param_changes_param(
                b"minimum_stake",
            ));
        self.state_trie
            .remove_raw(&state_trie_key::protocol_param_changes_param(
                b"maximum_stake",
            ));
        min_or_max_stake_changed
    }

    // --- Trie helper methods ---

    fn insert_validator_trie_entries(&mut self, pubkey: &[u8; 32], account: &ValidatorAccount) {
        let consensus_encoded = account.consensus_public_key.encode();
        self.state_trie.insert_raw(
            &state_trie_key::validator_account_consensus_public_key(pubkey),
            &consensus_encoded,
        );
        self.state_trie.insert_raw(
            &state_trie_key::validator_account_withdrawal_credentials(pubkey),
            account.withdrawal_credentials.as_slice(),
        );
        self.state_trie.insert_u64(
            &state_trie_key::validator_account_balance(pubkey),
            account.balance,
        );
        let status_byte = match &account.status {
            ValidatorStatus::Active => 0u8,
            ValidatorStatus::Inactive => 1,
            ValidatorStatus::SubmittedExitRequest => 2,
            ValidatorStatus::Joining => 3,
        };
        self.state_trie.insert_raw(
            &state_trie_key::validator_account_status(pubkey),
            &[status_byte],
        );
        self.state_trie.insert_bool(
            &state_trie_key::validator_account_has_pending_deposit(pubkey),
            account.has_pending_deposit,
        );
        self.state_trie.insert_bool(
            &state_trie_key::validator_account_has_pending_withdrawal(pubkey),
            account.has_pending_withdrawal,
        );
        self.state_trie.insert_u64(
            &state_trie_key::validator_account_joining_epoch(pubkey),
            account.joining_epoch,
        );
    }

    fn remove_validator_trie_entries(&mut self, pubkey: &[u8; 32]) {
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_consensus_public_key(
                pubkey,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_withdrawal_credentials(
                pubkey,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_balance(pubkey));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_status(pubkey));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_has_pending_deposit(
                pubkey,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_has_pending_withdrawal(
                pubkey,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::validator_account_joining_epoch(pubkey));
    }

    fn insert_deposit_trie_entries(&mut self, deposit: &DepositRequest) {
        let node_pubkey_bytes: [u8; 32] = deposit.node_pubkey.as_ref().try_into().unwrap();
        let consensus_encoded = deposit.consensus_pubkey.encode();
        self.state_trie.insert_raw(
            &state_trie_key::deposit_queue_request_consensus_pubkey(&node_pubkey_bytes),
            &consensus_encoded,
        );
        self.state_trie.insert_raw(
            &state_trie_key::deposit_queue_request_withdrawal_credentials(&node_pubkey_bytes),
            &deposit.withdrawal_credentials,
        );
        self.state_trie.insert_u64(
            &state_trie_key::deposit_queue_request_amount(&node_pubkey_bytes),
            deposit.amount,
        );
        self.state_trie.insert_raw(
            &state_trie_key::deposit_queue_request_node_signature(&node_pubkey_bytes),
            &deposit.node_signature,
        );
        self.state_trie.insert_raw(
            &state_trie_key::deposit_queue_request_consensus_signature(&node_pubkey_bytes),
            &deposit.consensus_signature,
        );
    }

    fn remove_deposit_trie_entries(&mut self, deposit: &DepositRequest) {
        let node_pubkey_bytes: [u8; 32] = deposit.node_pubkey.as_ref().try_into().unwrap();
        self.state_trie
            .remove_raw(&state_trie_key::deposit_queue_request_consensus_pubkey(
                &node_pubkey_bytes,
            ));
        self.state_trie.remove_raw(
            &state_trie_key::deposit_queue_request_withdrawal_credentials(&node_pubkey_bytes),
        );
        self.state_trie
            .remove_raw(&state_trie_key::deposit_queue_request_amount(
                &node_pubkey_bytes,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::deposit_queue_request_node_signature(
                &node_pubkey_bytes,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::deposit_queue_request_consensus_signature(
                &node_pubkey_bytes,
            ));
    }

    fn insert_withdrawal_trie_entries(&mut self, pubkey: &[u8; 32], w: &PendingWithdrawal) {
        self.state_trie.insert_u64(
            &state_trie_key::withdrawal_queue_request_balance_deduction(pubkey),
            w.balance_deduction,
        );
        self.state_trie.insert_raw(
            &state_trie_key::withdrawal_queue_request_address(pubkey),
            w.inner.address.as_slice(),
        );
        self.state_trie.insert_u64(
            &state_trie_key::withdrawal_queue_request_amount(pubkey),
            w.inner.amount,
        );
        self.state_trie.insert_u64(
            &state_trie_key::withdrawal_queue_request_epoch(pubkey),
            w.epoch,
        );
    }

    fn remove_withdrawal_trie_entries(&mut self, pubkey: &[u8; 32]) {
        self.state_trie
            .remove_raw(&state_trie_key::withdrawal_queue_request_balance_deduction(
                pubkey,
            ));
        self.state_trie
            .remove_raw(&state_trie_key::withdrawal_queue_request_address(pubkey));
        self.state_trie
            .remove_raw(&state_trie_key::withdrawal_queue_request_amount(pubkey));
        self.state_trie
            .remove_raw(&state_trie_key::withdrawal_queue_request_epoch(pubkey));
    }

    /// Rebuild the entire state trie from scratch.
    ///
    /// Called on deserialization and when bulk-replacing state (e.g. `set_validator_accounts`).
    pub fn rebuild_state_trie(&mut self) {
        self.state_trie = StateTrie::default();

        // Scalar fields
        self.state_trie
            .insert_u64(state_trie_key::EPOCH, self.epoch);
        self.state_trie.insert_u64(state_trie_key::VIEW, self.view);
        self.state_trie
            .insert_u64(state_trie_key::LATEST_HEIGHT, self.latest_height);
        self.state_trie
            .insert_hash(state_trie_key::HEAD_DIGEST, &self.head_digest.0);
        self.state_trie
            .insert_hash(state_trie_key::EPOCH_GENESIS_HASH, &self.epoch_genesis_hash);
        self.state_trie.insert_u64(
            state_trie_key::VALIDATOR_MINIMUM_STAKE,
            self.validator_minimum_stake,
        );
        self.state_trie.insert_u64(
            state_trie_key::VALIDATOR_MAXIMUM_STAKE,
            self.validator_maximum_stake,
        );
        self.state_trie.insert_u64(
            state_trie_key::NEXT_WITHDRAWAL_INDEX,
            self.withdrawal_queue.next_index(),
        );

        // Forkchoice
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_HEAD_BLOCK_HASH,
            &self.forkchoice.head_block_hash.0,
        );
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH,
            &self.forkchoice.safe_block_hash.0,
        );
        self.state_trie.insert_hash(
            state_trie_key::FORKCHOICE_FINALIZED_BLOCK_HASH,
            &self.forkchoice.finalized_block_hash.0,
        );

        // Deposit queue
        for deposit in &self.deposit_queue {
            let node_pubkey_bytes: [u8; 32] = deposit.node_pubkey.as_ref().try_into().unwrap();
            let consensus_encoded = deposit.consensus_pubkey.encode();
            self.state_trie.insert_raw(
                &state_trie_key::deposit_queue_request_consensus_pubkey(&node_pubkey_bytes),
                &consensus_encoded,
            );
            self.state_trie.insert_raw(
                &state_trie_key::deposit_queue_request_withdrawal_credentials(&node_pubkey_bytes),
                &deposit.withdrawal_credentials,
            );
            self.state_trie.insert_u64(
                &state_trie_key::deposit_queue_request_amount(&node_pubkey_bytes),
                deposit.amount,
            );
            self.state_trie.insert_raw(
                &state_trie_key::deposit_queue_request_node_signature(&node_pubkey_bytes),
                &deposit.node_signature,
            );
            self.state_trie.insert_raw(
                &state_trie_key::deposit_queue_request_consensus_signature(&node_pubkey_bytes),
                &deposit.consensus_signature,
            );
        }

        // Withdrawal queue
        let withdrawals: Vec<([u8; 32], PendingWithdrawal)> = self
            .withdrawal_queue
            .withdrawals_iter()
            .map(|(pk, w)| (*pk, w.clone()))
            .collect();
        for (pubkey, w) in &withdrawals {
            self.state_trie.insert_u64(
                &state_trie_key::withdrawal_queue_request_balance_deduction(pubkey),
                w.balance_deduction,
            );
            self.state_trie.insert_raw(
                &state_trie_key::withdrawal_queue_request_address(pubkey),
                w.inner.address.as_slice(),
            );
            self.state_trie.insert_u64(
                &state_trie_key::withdrawal_queue_request_amount(pubkey),
                w.inner.amount,
            );
            self.state_trie.insert_u64(
                &state_trie_key::withdrawal_queue_request_epoch(pubkey),
                w.epoch,
            );
        }

        // Validator accounts
        let accounts: Vec<([u8; 32], ValidatorAccount)> = self
            .validator_accounts
            .iter()
            .map(|(pk, acc)| (*pk, acc.clone()))
            .collect();
        for (pubkey, account) in &accounts {
            self.insert_validator_trie_entries(pubkey, account);
        }

        // Protocol param changes
        for param in &self.protocol_param_changes {
            let (variant_name, value) = match param {
                ProtocolParam::MinimumStake(v) => (b"minimum_stake" as &[u8], *v),
                ProtocolParam::MaximumStake(v) => (b"maximum_stake" as &[u8], *v),
            };
            self.state_trie.insert_u64(
                &state_trie_key::protocol_param_changes_param(variant_name),
                value,
            );
        }

        // Added validators
        for validators in self.added_validators.values() {
            for v in validators {
                let node_key_bytes: [u8; 32] = v.node_key.as_ref().try_into().unwrap();
                let encoded = v.consensus_key.encode();
                self.state_trie.insert_raw(
                    &state_trie_key::added_validators_consensus_key(&node_key_bytes),
                    &encoded,
                );
            }
        }

        // Removed validators
        for pubkey in &self.removed_validators {
            let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
            self.state_trie
                .insert_raw(&state_trie_key::removed_validators(&pubkey_bytes), &[1]);
        }

        // Capture root so get_state_root() is valid after deserialization / bulk reset
        self.state_root = self.state_trie.root();
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
    }
}

impl Read for ConsensusState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let epoch = buf.get_u64();
        let view = buf.get_u64();
        let latest_height = buf.get_u64();

        let deposit_queue_len = buf.get_u32() as usize;
        let mut deposit_queue = VecDeque::with_capacity(deposit_queue_len);
        for _ in 0..deposit_queue_len {
            deposit_queue.push_back(DepositRequest::read_cfg(buf, &())?);
        }

        let withdrawal_queue = WithdrawalQueue::read_cfg(buf, &())?;

        let protocol_param_changes_len = buf.get_u32() as usize;
        let mut protocol_param_changes = Vec::with_capacity(protocol_param_changes_len);
        for _ in 0..protocol_param_changes_len {
            protocol_param_changes.push(crate::protocol_params::ProtocolParam::read_cfg(buf, &())?);
        }

        let validator_accounts_len = buf.get_u32() as usize;
        let mut validator_accounts = BTreeMap::new();
        for _ in 0..validator_accounts_len {
            let mut key = [0u8; 32];
            buf.copy_to_slice(&mut key);
            let account = ValidatorAccount::read_cfg(buf, &())?;
            validator_accounts.insert(key, account);
        }

        // Read pending_checkpoint
        let has_pending_checkpoint = buf.get_u8() != 0;
        let pending_checkpoint = if has_pending_checkpoint {
            Some(Checkpoint::read_cfg(buf, &())?)
        } else {
            None
        };

        // Read added_validators
        let added_validators_len = buf.get_u32() as usize;
        let mut added_validators = BTreeMap::new();
        for _ in 0..added_validators_len {
            let key = buf.get_u64();
            let validator_count = buf.get_u32() as usize;
            let mut validators = Vec::with_capacity(validator_count);
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
        let removed_validators_len = buf.get_u32() as usize;
        let mut removed_validators = Vec::with_capacity(removed_validators_len);
        for _ in 0..removed_validators_len {
            removed_validators.push(PublicKey::read_cfg(buf, &())?);
        }

        // Read pending_execution_requests
        let pending_execution_requests_len = buf.get_u32() as usize;
        let mut pending_execution_requests = Vec::with_capacity(pending_execution_requests_len);
        for _ in 0..pending_execution_requests_len {
            let len = buf.get_u32() as usize;
            let mut bytes = vec![0u8; len];
            buf.copy_to_slice(&mut bytes);
            pending_execution_requests.push(alloy_primitives::Bytes::from(bytes));
        }

        // Read forkchoice
        let mut head_block_hash = [0u8; 32];
        buf.copy_to_slice(&mut head_block_hash);
        let mut safe_block_hash = [0u8; 32];
        buf.copy_to_slice(&mut safe_block_hash);
        let mut finalized_block_hash = [0u8; 32];
        buf.copy_to_slice(&mut finalized_block_hash);

        let forkchoice = ForkchoiceState {
            head_block_hash: head_block_hash.into(),
            safe_block_hash: safe_block_hash.into(),
            finalized_block_hash: finalized_block_hash.into(),
        };

        let mut epoch_genesis_hash = [0u8; 32];
        buf.copy_to_slice(&mut epoch_genesis_hash);

        let mut head_digest_bytes = [0u8; 32];
        buf.copy_to_slice(&mut head_digest_bytes);
        let head_digest = sha256::Digest(head_digest_bytes);

        let validator_minimum_stake = buf.get_u64();
        let validator_maximum_stake = buf.get_u64();

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
            state_trie: StateTrie::default(),
            state_root: [0u8; 32],
        };
        state.rebuild_state_trie();
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
    }
}

impl TryFrom<Checkpoint> for ConsensusState {
    type Error = Error;

    fn try_from(checkpoint: Checkpoint) -> Result<Self, Self::Error> {
        ConsensusState::decode(checkpoint.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKey;
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::execution_request::DepositRequest;
    use crate::withdrawal::PendingWithdrawal;

    use alloy_eips::eip4895::Withdrawal;
    use alloy_primitives::Address;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Signer, bls12381, ed25519};

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
    }

    #[test]
    fn test_serialization_deserialization_populated() {
        let mut original_state = ConsensusState::default();

        original_state.set_epoch(7);
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
        assert_eq!(decoded_state.protocol_param_changes.len(), 2);
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

    // ---- State trie integration tests ----

    /// Helper: verify a single trie key/value inclusion proof against the current root.
    fn assert_trie_proves(state: &ConsensusState, key: &[u8], value: &[u8]) {
        let trie = state.state_trie();
        let proof = trie.generate_proof(&[key]);
        assert!(
            StateTrie::verify_proof(&trie.root(), &proof, &[(key, Some(value))]),
            "inclusion proof failed for key {:?}",
            String::from_utf8_lossy(key),
        );
    }

    /// Helper: verify a trie key is absent.
    fn assert_trie_absent(state: &ConsensusState, key: &[u8]) {
        let trie = state.state_trie();
        let proof = trie.generate_proof(&[key]);
        assert!(
            StateTrie::verify_proof(&trie.root(), &proof, &[(key, None)]),
            "exclusion proof failed for key {:?}",
            String::from_utf8_lossy(key),
        );
    }

    #[test]
    fn test_trie_scalar_setters_update_trie() {
        let mut state = ConsensusState::default();
        let root_before = state.state_trie().root();

        state.set_epoch(10);
        assert_ne!(state.state_trie().root(), root_before);
        assert_trie_proves(&state, state_trie_key::EPOCH, &10u64.to_be_bytes());

        state.set_view(99);
        assert_trie_proves(&state, state_trie_key::VIEW, &99u64.to_be_bytes());

        state.set_latest_height(500);
        assert_trie_proves(&state, state_trie_key::LATEST_HEIGHT, &500u64.to_be_bytes());

        state.set_head_digest(sha256::Digest([0xAB; 32]));
        assert_trie_proves(&state, state_trie_key::HEAD_DIGEST, &[0xAB; 32]);

        state.set_epoch_genesis_hash([0xCD; 32]);
        assert_trie_proves(&state, state_trie_key::EPOCH_GENESIS_HASH, &[0xCD; 32]);

        state.set_minimum_stake(16_000_000_000);
        assert_trie_proves(
            &state,
            state_trie_key::VALIDATOR_MINIMUM_STAKE,
            &16_000_000_000u64.to_be_bytes(),
        );

        state.set_maximum_stake(64_000_000_000);
        assert_trie_proves(
            &state,
            state_trie_key::VALIDATOR_MAXIMUM_STAKE,
            &64_000_000_000u64.to_be_bytes(),
        );

        state.set_next_withdrawal_index(42);
        assert_trie_proves(
            &state,
            state_trie_key::NEXT_WITHDRAWAL_INDEX,
            &42u64.to_be_bytes(),
        );
    }

    #[test]
    fn test_trie_forkchoice_updates() {
        let mut state = ConsensusState::default();

        let fcs = ForkchoiceState {
            head_block_hash: [0x11; 32].into(),
            safe_block_hash: [0x22; 32].into(),
            finalized_block_hash: [0x33; 32].into(),
        };
        state.set_forkchoice(fcs);
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_HEAD_BLOCK_HASH,
            &[0x11; 32],
        );
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH,
            &[0x22; 32],
        );
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_FINALIZED_BLOCK_HASH,
            &[0x33; 32],
        );

        // Partial setters
        state.set_forkchoice_head([0xAA; 32].into());
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_HEAD_BLOCK_HASH,
            &[0xAA; 32],
        );
        // safe/finalized unchanged
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH,
            &[0x22; 32],
        );

        state.set_forkchoice_safe_and_finalized([0xBB; 32].into());
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_SAFE_BLOCK_HASH,
            &[0xBB; 32],
        );
        assert_trie_proves(
            &state,
            state_trie_key::FORKCHOICE_FINALIZED_BLOCK_HASH,
            &[0xBB; 32],
        );
    }

    #[test]
    fn test_trie_validator_account_lifecycle() {
        let mut state = ConsensusState::default();
        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32_000_000_000);

        // Before insertion, keys should be absent
        assert_trie_absent(&state, &state_trie_key::validator_account_balance(&pubkey));

        // Insert
        state.set_account(pubkey, account.clone());
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_balance(&pubkey),
            &32_000_000_000u64.to_be_bytes(),
        );
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_status(&pubkey),
            &[0u8], // Active = 0
        );
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_has_pending_deposit(&pubkey),
            &[0u8], // false
        );
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_has_pending_withdrawal(&pubkey),
            &[0u8], // false
        );
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_joining_epoch(&pubkey),
            &0u64.to_be_bytes(),
        );

        let root_with_account = state.state_trie().root();

        // Update balance
        let mut updated = account.clone();
        updated.balance = 48_000_000_000;
        state.set_account(pubkey, updated);
        assert_ne!(state.state_trie().root(), root_with_account);
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_balance(&pubkey),
            &48_000_000_000u64.to_be_bytes(),
        );

        // Remove
        state.remove_account(&pubkey);
        assert_trie_absent(&state, &state_trie_key::validator_account_balance(&pubkey));
        assert_trie_absent(&state, &state_trie_key::validator_account_status(&pubkey));
        assert_trie_absent(
            &state,
            &state_trie_key::validator_account_consensus_public_key(&pubkey),
        );
    }

    #[test]
    fn test_trie_deposit_queue_operations() {
        let mut state = ConsensusState::default();
        let deposit = create_test_deposit_request(1, 32_000_000_000);
        let node_pubkey_bytes: [u8; 32] = deposit.node_pubkey.as_ref().try_into().unwrap();

        // Push deposit
        state.push_deposit(deposit.clone());
        assert_trie_proves(
            &state,
            &state_trie_key::deposit_queue_request_amount(&node_pubkey_bytes),
            &32_000_000_000u64.to_be_bytes(),
        );

        let root_with_deposit = state.state_trie().root();

        // Pop deposit removes trie entries
        let popped = state.pop_deposit().unwrap();
        assert_eq!(popped.amount, 32_000_000_000);
        assert_ne!(state.state_trie().root(), root_with_deposit);
        assert_trie_absent(
            &state,
            &state_trie_key::deposit_queue_request_amount(&node_pubkey_bytes),
        );
        assert_trie_absent(
            &state,
            &state_trie_key::deposit_queue_request_consensus_pubkey(&node_pubkey_bytes),
        );
    }

    #[test]
    fn test_trie_withdrawal_queue_operations() {
        let mut state = ConsensusState::default();
        let withdrawal = create_test_withdrawal(1, 16_000_000_000, 5);
        let pubkey = withdrawal.pubkey;

        state.push_withdrawal(withdrawal);
        assert_trie_proves(
            &state,
            &state_trie_key::withdrawal_queue_request_balance_deduction(&pubkey),
            &16_000_000_000u64.to_be_bytes(),
        );
        assert_trie_proves(
            &state,
            &state_trie_key::withdrawal_queue_request_epoch(&pubkey),
            &5u64.to_be_bytes(),
        );

        let root_with_withdrawal = state.state_trie().root();

        // Pop withdrawal removes trie entries
        let popped = state.pop_withdrawal(5).unwrap();
        assert_eq!(popped.inner.amount, 16_000_000_000);
        assert_ne!(state.state_trie().root(), root_with_withdrawal);
        assert_trie_absent(
            &state,
            &state_trie_key::withdrawal_queue_request_balance_deduction(&pubkey),
        );
        assert_trie_absent(
            &state,
            &state_trie_key::withdrawal_queue_request_epoch(&pubkey),
        );
    }

    #[test]
    fn test_trie_added_removed_validators() {
        let mut state = ConsensusState::default();

        let validator = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(10).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
        };
        let node_key_bytes: [u8; 32] = validator.node_key.as_ref().try_into().unwrap();

        // add_validator inserts trie entry
        state.add_validator(5, validator.clone());
        let key = state_trie_key::added_validators_consensus_key(&node_key_bytes);
        let encoded = validator.consensus_key.encode();
        assert_trie_proves(&state, &key, &encoded);

        // remove_added_validators_for_epoch clears trie entries
        state.remove_added_validators_for_epoch(5);
        assert_trie_absent(&state, &key);

        // push_removed_validator / clear_removed_validators
        let removed_pk = ed25519::PrivateKey::from_seed(20).public_key();
        let removed_bytes: [u8; 32] = removed_pk.as_ref().try_into().unwrap();
        let removed_key = state_trie_key::removed_validators(&removed_bytes);

        state.push_removed_validator(removed_pk);
        assert_trie_proves(&state, &removed_key, &[1]);

        state.clear_removed_validators();
        assert_trie_absent(&state, &removed_key);
    }

    #[test]
    fn test_trie_remove_single_added_validator() {
        let mut state = ConsensusState::default();

        let v1 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(10).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
        };
        let v2 = AddedValidator {
            node_key: ed25519::PrivateKey::from_seed(20).public_key(),
            consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
        };
        let v1_bytes: [u8; 32] = v1.node_key.as_ref().try_into().unwrap();
        let v2_bytes: [u8; 32] = v2.node_key.as_ref().try_into().unwrap();

        state.add_validator(5, v1.clone());
        state.add_validator(5, v2.clone());

        // Remove just v1
        assert!(state.remove_added_validator(5, &v1.node_key));
        assert_trie_absent(
            &state,
            &state_trie_key::added_validators_consensus_key(&v1_bytes),
        );
        // v2 still present
        assert_trie_proves(
            &state,
            &state_trie_key::added_validators_consensus_key(&v2_bytes),
            &v2.consensus_key.encode(),
        );
    }

    #[test]
    fn test_trie_protocol_param_changes() {
        let mut state = ConsensusState::default();

        state.push_protocol_param_change(ProtocolParam::MinimumStake(40_000_000_000));
        assert_trie_proves(
            &state,
            &state_trie_key::protocol_param_changes_param(b"minimum_stake"),
            &40_000_000_000u64.to_be_bytes(),
        );

        state.push_protocol_param_change(ProtocolParam::MaximumStake(80_000_000_000));
        assert_trie_proves(
            &state,
            &state_trie_key::protocol_param_changes_param(b"maximum_stake"),
            &80_000_000_000u64.to_be_bytes(),
        );

        // apply_protocol_parameter_changes consumes them and removes trie entries
        let changed = state.apply_protocol_parameter_changes();
        assert!(changed);
        assert_trie_absent(
            &state,
            &state_trie_key::protocol_param_changes_param(b"minimum_stake"),
        );
        assert_trie_absent(
            &state,
            &state_trie_key::protocol_param_changes_param(b"maximum_stake"),
        );

        // But the scalar fields themselves are updated
        assert_trie_proves(
            &state,
            state_trie_key::VALIDATOR_MINIMUM_STAKE,
            &40_000_000_000u64.to_be_bytes(),
        );
        assert_trie_proves(
            &state,
            state_trie_key::VALIDATOR_MAXIMUM_STAKE,
            &80_000_000_000u64.to_be_bytes(),
        );
    }

    #[test]
    fn test_trie_rebuild_matches_incremental() {
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

        let incremental_root = state.state_trie().root();

        // Rebuild from scratch
        state.rebuild_state_trie();
        let rebuilt_root = state.state_trie().root();

        assert_eq!(incremental_root, rebuilt_root);
    }

    #[test]
    fn test_trie_root_survives_serialization_roundtrip() {
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

        let original_root = state.state_trie().root();

        // Round-trip through serialization
        let mut encoded = state.encode();
        let decoded = ConsensusState::decode(&mut encoded).unwrap();

        assert_eq!(decoded.state_trie().root(), original_root);
    }

    #[test]
    fn test_trie_set_validator_accounts_rebuilds() {
        let mut state = ConsensusState::default();
        state.set_epoch(3);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        let root_before = state.state_trie().root();

        // Bulk replace validator accounts
        let mut new_accounts = BTreeMap::new();
        new_accounts.insert([2u8; 32], create_test_validator_account(2, 64_000_000_000));
        new_accounts.insert([3u8; 32], create_test_validator_account(3, 48_000_000_000));
        state.set_validator_accounts(new_accounts);

        assert_ne!(state.state_trie().root(), root_before);

        // Old account gone
        assert_trie_absent(
            &state,
            &state_trie_key::validator_account_balance(&[1u8; 32]),
        );

        // New accounts present
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_balance(&[2u8; 32]),
            &64_000_000_000u64.to_be_bytes(),
        );
        assert_trie_proves(
            &state,
            &state_trie_key::validator_account_balance(&[3u8; 32]),
            &48_000_000_000u64.to_be_bytes(),
        );

        // Scalar fields survive the rebuild
        assert_trie_proves(&state, state_trie_key::EPOCH, &3u64.to_be_bytes());
    }

    #[test]
    fn test_trie_set_removed_validators_replaces() {
        let mut state = ConsensusState::default();

        let pk1 = ed25519::PrivateKey::from_seed(1).public_key();
        let pk2 = ed25519::PrivateKey::from_seed(2).public_key();
        let pk3 = ed25519::PrivateKey::from_seed(3).public_key();

        let pk1_bytes: [u8; 32] = pk1.as_ref().try_into().unwrap();
        let pk2_bytes: [u8; 32] = pk2.as_ref().try_into().unwrap();
        let pk3_bytes: [u8; 32] = pk3.as_ref().try_into().unwrap();

        // Set initial removed validators
        state.set_removed_validators(vec![pk1, pk2]);
        assert_trie_proves(
            &state,
            &state_trie_key::removed_validators(&pk1_bytes),
            &[1],
        );
        assert_trie_proves(
            &state,
            &state_trie_key::removed_validators(&pk2_bytes),
            &[1],
        );

        // Replace with a different set — old entries removed, new ones added
        state.set_removed_validators(vec![pk3]);
        assert_trie_absent(&state, &state_trie_key::removed_validators(&pk1_bytes));
        assert_trie_absent(&state, &state_trie_key::removed_validators(&pk2_bytes));
        assert_trie_proves(
            &state,
            &state_trie_key::removed_validators(&pk3_bytes),
            &[1],
        );
    }

    #[test]
    fn test_trie_multi_key_proof() {
        let mut state = ConsensusState::default();
        state.set_epoch(10);
        state.set_view(20);

        let pubkey = [1u8; 32];
        state.set_account(pubkey, create_test_validator_account(1, 32_000_000_000));

        // Prove multiple keys in a single proof
        let balance_key = state_trie_key::validator_account_balance(&pubkey);
        let trie = state.state_trie();
        let proof =
            trie.generate_proof(&[state_trie_key::EPOCH, state_trie_key::VIEW, &balance_key]);

        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[
                (state_trie_key::EPOCH, Some(&10u64.to_be_bytes())),
                (state_trie_key::VIEW, Some(&20u64.to_be_bytes())),
                (&balance_key, Some(&32_000_000_000u64.to_be_bytes())),
            ],
        ));
    }

    #[test]
    fn test_trie_clone_independence() {
        let mut state = ConsensusState::default();
        state.set_epoch(5);
        state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

        let cloned = state.clone();
        let root_before = cloned.state_trie().root();

        // Mutate original
        state.set_epoch(99);
        state.set_account([2u8; 32], create_test_validator_account(2, 64_000_000_000));

        // Clone is unaffected
        assert_eq!(cloned.state_trie().root(), root_before);
        assert_trie_proves(&cloned, state_trie_key::EPOCH, &5u64.to_be_bytes());
        assert_trie_absent(
            &cloned,
            &state_trie_key::validator_account_balance(&[2u8; 32]),
        );
    }
}
