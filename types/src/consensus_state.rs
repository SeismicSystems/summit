use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::checkpoint::Checkpoint;
use crate::execution_request::{DepositRequest, WithdrawalRequest};
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::withdrawal::PendingWithdrawal;
use crate::{Digest, PublicKey};
use alloy_eips::eip4895::Withdrawal;
use alloy_rpc_types_engine::ForkchoiceState;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{bls12381, sha256};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug)]
pub struct ConsensusState {
    pub epoch: u64,
    pub view: u64,
    pub latest_height: u64,
    pub head_digest: Digest,
    pub next_withdrawal_index: u64,
    pub deposit_queue: VecDeque<DepositRequest>,
    pub withdrawal_queue: BTreeMap<u64, VecDeque<PendingWithdrawal>>, // epoch -> withdrawals
    pub validator_accounts: BTreeMap<[u8; 32], ValidatorAccount>,
    pub protocol_param_changes: Vec<ProtocolParam>,
    pub pending_checkpoint: Option<Checkpoint>,
    pub added_validators: BTreeMap<u64, Vec<AddedValidator>>,
    pub removed_validators: Vec<PublicKey>,
    /// Execution requests that need to be deferred. Currently this only applies to
    /// withdrawal requests received in the last block of an epoch.
    pub pending_execution_requests: Vec<alloy_primitives::Bytes>,
    pub forkchoice: ForkchoiceState,
    pub epoch_genesis_hash: [u8; 32],
    pub validator_minimum_stake: u64, // in gwei
    pub validator_maximum_stake: u64, // in gwei
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            epoch: 0,
            view: 0,
            latest_height: 0,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 0,
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
        }
    }
}

impl ConsensusState {
    pub fn new(
        forkchoice: ForkchoiceState,
        validator_minimum_stake: u64,
        validator_maximum_stake: u64,
    ) -> Self {
        Self {
            forkchoice,
            epoch_genesis_hash: forkchoice.head_block_hash.into(),
            head_digest: (*forkchoice.head_block_hash).into(),
            validator_minimum_stake,
            validator_maximum_stake,
            ..Default::default()
        }
    }

    // State variable operations
    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    pub fn get_view(&self) -> u64 {
        self.view
    }

    pub fn set_view(&mut self, view: u64) {
        self.view = view;
    }

    pub fn get_latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn set_latest_height(&mut self, height: u64) {
        self.latest_height = height;
    }

    pub fn get_next_withdrawal_index(&self) -> u64 {
        self.next_withdrawal_index
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

    fn get_and_increment_withdrawal_index(&mut self) -> u64 {
        let current = self.next_withdrawal_index;
        self.next_withdrawal_index += 1;
        current
    }

    pub fn get_pending_checkpoint(&self) -> Option<&Checkpoint> {
        self.pending_checkpoint.as_ref()
    }

    pub fn set_next_withdrawal_index(&mut self, index: u64) {
        self.next_withdrawal_index = index;
    }

    pub fn set_pending_checkpoint(&mut self, checkpoint: Option<Checkpoint>) {
        self.pending_checkpoint = checkpoint;
    }

    pub fn get_added_validators(&self, epoch: u64) -> Option<&Vec<AddedValidator>> {
        self.added_validators.get(&epoch)
    }

    pub fn add_validator(&mut self, epoch: u64, validator: AddedValidator) {
        self.added_validators
            .entry(epoch)
            .or_default()
            .push(validator);
    }

    pub fn get_removed_validators(&self) -> &Vec<PublicKey> {
        &self.removed_validators
    }

    pub fn set_removed_validators(&mut self, validators: Vec<PublicKey>) {
        self.removed_validators = validators;
    }

    pub fn get_forkchoice(&self) -> &ForkchoiceState {
        &self.forkchoice
    }

    pub fn set_forkchoice(&mut self, forkchoice: ForkchoiceState) {
        self.forkchoice = forkchoice;
    }

    pub fn get_epoch_genesis_hash(&self) -> [u8; 32] {
        self.epoch_genesis_hash
    }

    pub fn set_epoch_genesis_hash(&mut self, hash: [u8; 32]) {
        self.epoch_genesis_hash = hash;
    }

    // Account operations
    pub fn get_account(&self, pubkey: &[u8; 32]) -> Option<&ValidatorAccount> {
        self.validator_accounts.get(pubkey)
    }

    pub fn set_account(&mut self, pubkey: [u8; 32], account: ValidatorAccount) {
        self.validator_accounts.insert(pubkey, account);
    }

    pub fn remove_account(&mut self, pubkey: &[u8; 32]) -> Option<ValidatorAccount> {
        self.validator_accounts.remove(pubkey)
    }

    // Deposit queue operations
    pub fn push_deposit(&mut self, request: DepositRequest) {
        self.deposit_queue.push_back(request);
    }

    pub fn peek_deposit(&self) -> Option<&DepositRequest> {
        self.deposit_queue.front()
    }

    pub fn pop_deposit(&mut self) -> Option<DepositRequest> {
        self.deposit_queue.pop_front()
    }

    // Withdrawal queue operations
    pub fn push_withdrawal_request(
        &mut self,
        request: WithdrawalRequest,
        withdrawal_epoch: u64,
        subtract_balance: bool,
    ) {
        let withdrawal_index = self.get_and_increment_withdrawal_index();

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: withdrawal_index,
                validator_index: 0,
                address: request.source_address,
                amount: request.amount,
            },
            pubkey: request.validator_pubkey,
            subtract_balance,
        };

        self.push_withdrawal(pending_withdrawal, withdrawal_epoch);
    }

    pub fn push_withdrawal(&mut self, request: PendingWithdrawal, withdrawal_epoch: u64) {
        self.withdrawal_queue
            .entry(withdrawal_epoch)
            .or_default()
            .push_back(request);
    }

    pub fn peek_withdrawal(&self, withdrawal_epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue
            .get(&withdrawal_epoch)
            .and_then(|queue| queue.front())
    }

    pub fn pop_withdrawal(&mut self, withdrawal_epoch: u64) -> Option<PendingWithdrawal> {
        if let Some(queue) = self.withdrawal_queue.get_mut(&withdrawal_epoch) {
            let withdrawal = queue.pop_front();
            // Remove the epoch entry if the queue is now empty
            if queue.is_empty() {
                self.withdrawal_queue.remove(&withdrawal_epoch);
            }
            withdrawal
        } else {
            None
        }
    }

    /// Get all pending withdrawals for a specific epoch
    pub fn get_withdrawals_for_epoch(&self, epoch: u64) -> Option<&VecDeque<PendingWithdrawal>> {
        self.withdrawal_queue.get(&epoch)
    }

    /// Get the number of pending withdrawals for a specific epoch
    pub fn get_withdrawal_count_for_epoch(&self, epoch: u64) -> usize {
        self.withdrawal_queue
            .get(&epoch)
            .map(|queue| queue.len())
            .unwrap_or(0)
    }

    /// Get all epochs that have pending withdrawals
    pub fn get_epochs_with_withdrawals(&self) -> Vec<u64> {
        self.withdrawal_queue.keys().copied().collect()
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
                    min_or_max_stake_changed = true;
                }
                ProtocolParam::MaximumStake(max_stake) => {
                    self.validator_maximum_stake = max_stake;
                    min_or_max_stake_changed = true;
                }
            }
        }
        min_or_max_stake_changed
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
        + 8 // next_withdrawal_index
        + 4 // deposit_queue length
        + self.deposit_queue.iter().map(|req| req.encode_size()).sum::<usize>()
        + 4 // withdrawal_queue epoch count
        + self.withdrawal_queue.values().map(|queue| {
            8 // epoch (u64)
            + 4 // queue length (u32)
            + queue.iter().map(|req| req.encode_size()).sum::<usize>()
        }).sum::<usize>()
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
        let next_withdrawal_index = buf.get_u64();

        let deposit_queue_len = buf.get_u32() as usize;
        let mut deposit_queue = VecDeque::with_capacity(deposit_queue_len);
        for _ in 0..deposit_queue_len {
            deposit_queue.push_back(DepositRequest::read_cfg(buf, &())?);
        }

        let withdrawal_queue_epoch_count = buf.get_u32() as usize;
        let mut withdrawal_queue = BTreeMap::new();
        for _ in 0..withdrawal_queue_epoch_count {
            let epoch = buf.get_u64();
            let queue_len = buf.get_u32() as usize;
            let mut queue = VecDeque::with_capacity(queue_len);
            for _ in 0..queue_len {
                queue.push_back(PendingWithdrawal::read_cfg(buf, &())?);
            }
            withdrawal_queue.insert(epoch, queue);
        }

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

        Ok(Self {
            epoch,
            view,
            latest_height,
            head_digest,
            next_withdrawal_index,
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
        })
    }
}

impl Write for ConsensusState {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.epoch);
        buf.put_u64(self.view);
        buf.put_u64(self.latest_height);
        buf.put_u64(self.next_withdrawal_index);

        buf.put_u32(self.deposit_queue.len() as u32);
        for request in &self.deposit_queue {
            request.write(buf);
        }

        buf.put_u32(self.withdrawal_queue.len() as u32);
        for (epoch, queue) in &self.withdrawal_queue {
            buf.put_u64(*epoch);
            buf.put_u32(queue.len() as u32);
            for request in queue {
                request.write(buf);
            }
        }

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

    fn create_test_withdrawal(index: u64, amount: u64) -> PendingWithdrawal {
        PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: index * 10,
                address: Address::from([index as u8; 20]),
                amount,
            },
            pubkey: [index as u8; 32],
            subtract_balance: true,
        }
    }

    fn create_test_validator_account(index: u64, balance: u64) -> ValidatorAccount {
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([index as u8; 20]),
            balance,
            pending_withdrawal_amount: 0,
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
            decoded_state.next_withdrawal_index,
            original_state.next_withdrawal_index
        );
        assert_eq!(
            decoded_state.deposit_queue.len(),
            original_state.deposit_queue.len()
        );
        assert_eq!(
            decoded_state.withdrawal_queue.len(),
            original_state.withdrawal_queue.len()
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

        original_state.epoch = 7;
        original_state.view = 123;
        original_state.set_latest_height(42);
        original_state.next_withdrawal_index = 5;
        original_state.epoch_genesis_hash = [42u8; 32];

        let deposit1 = create_test_deposit_request(1, 32000000000);
        let deposit2 = create_test_deposit_request(2, 16000000000);
        original_state.push_deposit(deposit1);
        original_state.push_deposit(deposit2);

        let withdrawal1 = create_test_withdrawal(1, 16000000000);
        let withdrawal2 = create_test_withdrawal(2, 24000000000);
        original_state.push_withdrawal(withdrawal1, 10); // epoch 10
        original_state.push_withdrawal(withdrawal2, 11); // epoch 11

        // Add protocol param changes
        original_state.protocol_param_changes.push(
            crate::protocol_params::ProtocolParam::MinimumStake(40_000_000_000),
        );
        original_state.protocol_param_changes.push(
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
            decoded_state.next_withdrawal_index,
            original_state.next_withdrawal_index
        );
        assert_eq!(
            decoded_state.epoch_genesis_hash,
            original_state.epoch_genesis_hash
        );

        assert_eq!(decoded_state.deposit_queue.len(), 2);
        assert_eq!(decoded_state.deposit_queue[0].amount, 32000000000);
        assert_eq!(decoded_state.deposit_queue[1].amount, 16000000000);

        // Check withdrawal_queue - should have 2 epochs with withdrawals
        assert_eq!(decoded_state.withdrawal_queue.len(), 2);

        // Check epoch 10 withdrawal
        let epoch10_withdrawals = decoded_state.get_withdrawals_for_epoch(10).unwrap();
        assert_eq!(epoch10_withdrawals.len(), 1);
        assert_eq!(epoch10_withdrawals[0].inner.index, 1);
        assert_eq!(epoch10_withdrawals[0].inner.amount, 16000000000);

        // Check epoch 11 withdrawal
        let epoch11_withdrawals = decoded_state.get_withdrawals_for_epoch(11).unwrap();
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

        state.epoch = 3;
        state.view = 456;
        state.set_latest_height(42);
        state.next_withdrawal_index = 5;

        let deposit = create_test_deposit_request(1, 32000000000);
        state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000);
        state.push_withdrawal(withdrawal, 5); // epoch 5

        // Add protocol param changes
        state
            .protocol_param_changes
            .push(crate::protocol_params::ProtocolParam::MinimumStake(
                50_000_000_000,
            ));
        state
            .protocol_param_changes
            .push(crate::protocol_params::ProtocolParam::MaximumStake(
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
        state
            .protocol_param_changes
            .push(crate::protocol_params::ProtocolParam::MinimumStake(
                32_000_000_000,
            ));
        state
            .protocol_param_changes
            .push(crate::protocol_params::ProtocolParam::MaximumStake(
                64_000_000_000,
            ));
        state
            .protocol_param_changes
            .push(crate::protocol_params::ProtocolParam::MinimumStake(
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
        original_state.epoch = 5;
        original_state.view = 789;
        original_state.set_latest_height(100);
        original_state.next_withdrawal_index = 42;
        original_state.epoch_genesis_hash = [99u8; 32];

        // Add some data
        let deposit = create_test_deposit_request(1, 32000000000);
        original_state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000);
        original_state.push_withdrawal(withdrawal, 7); // epoch 7

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
            restored_state.next_withdrawal_index,
            original_state.next_withdrawal_index
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
            restored_state.withdrawal_queue.len(),
            original_state.withdrawal_queue.len()
        );
        assert_eq!(
            restored_state.validator_accounts.len(),
            original_state.validator_accounts.len()
        );

        // Check specific values
        assert_eq!(restored_state.deposit_queue[0].amount, 32000000000);
        let epoch7_withdrawals = restored_state.get_withdrawals_for_epoch(7).unwrap();
        assert_eq!(epoch7_withdrawals[0].inner.amount, 16000000000);

        let restored_account = restored_state.get_account(&pubkey).unwrap();
        assert_eq!(restored_account.balance, 32000000000);
        assert_eq!(restored_account.last_deposit_index, 1);
    }
}
