use crate::PublicKey;
use crate::account::ValidatorAccount;
use crate::checkpoint::Checkpoint;
use crate::execution_request::{DepositRequest, WithdrawalRequest};
use crate::withdrawal::PendingWithdrawal;
use alloy_eips::eip4895::Withdrawal;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, EncodeSize, Error, Read, Write};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Default)]
pub struct ConsensusState {
    pub latest_height: u64,
    pub next_withdrawal_index: u64,
    pub deposit_queue: VecDeque<DepositRequest>,
    pub withdrawal_queue: VecDeque<PendingWithdrawal>,
    pub validator_accounts: HashMap<[u8; 32], ValidatorAccount>,
    pub pending_checkpoint: Option<Checkpoint>,
    pub added_validators: Vec<PublicKey>,
    pub removed_validators: Vec<PublicKey>,
}

impl ConsensusState {
    pub fn new() -> Self {
        Self::default()
    }

    // State variable operations
    pub fn get_latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn set_latest_height(&mut self, height: u64) {
        self.latest_height = height;
    }

    fn get_and_increment_withdrawal_index(&mut self) -> u64 {
        let current = self.next_withdrawal_index;
        self.next_withdrawal_index += 1;
        current
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
    pub fn push_withdrawal_request(&mut self, request: WithdrawalRequest, withdrawal_height: u64) {
        let withdrawal_index = self.get_and_increment_withdrawal_index();

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: withdrawal_index,
                validator_index: 0,
                address: request.source_address,
                amount: request.amount,
            },
            withdrawal_height,
            pubkey: request.validator_pubkey,
        };

        self.push_withdrawal(pending_withdrawal);
    }

    pub fn push_withdrawal(&mut self, request: PendingWithdrawal) {
        self.withdrawal_queue.push_back(request);
    }

    pub fn peek_withdrawal(&self) -> Option<&PendingWithdrawal> {
        self.withdrawal_queue.front()
    }

    pub fn pop_withdrawal(&mut self) -> Option<PendingWithdrawal> {
        self.withdrawal_queue.pop_front()
    }

    /// Get the next K pending withdrawals that are ready for processing at the given block height.
    /// Only returns withdrawals where withdrawal_height <= block_height.
    pub fn get_next_ready_withdrawals(&self, block_height: u64, k: usize) -> Vec<PendingWithdrawal>
    where
        PendingWithdrawal: Clone,
    {
        self.withdrawal_queue
            .iter()
            .filter(|withdrawal| withdrawal.withdrawal_height <= block_height)
            .take(k)
            .cloned()
            .collect()
    }
}

impl EncodeSize for ConsensusState {
    fn encode_size(&self) -> usize {
        8 // latest_height
        + 8 // next_withdrawal_index
        + 4 // deposit_queue length
        + self.deposit_queue.iter().map(|req| req.encode_size()).sum::<usize>()
        + 4 // withdrawal_queue length
        + self.withdrawal_queue.iter().map(|req| req.encode_size()).sum::<usize>()
        + 4 // validator_accounts length
        + self.validator_accounts.iter().map(|(key, account)| key.len() + account.encode_size()).sum::<usize>()
        + 1 // pending_checkpoint presence flag
        + self.pending_checkpoint.as_ref().map_or(0, |cp| cp.encode_size())
        + 4 // added_validators length
        + self.added_validators.iter().map(|pk| pk.encode_size()).sum::<usize>()
        + 4 // removed_validators length
        + self.removed_validators.iter().map(|pk| pk.encode_size()).sum::<usize>()
    }
}

impl Read for ConsensusState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let latest_height = buf.get_u64();
        let next_withdrawal_index = buf.get_u64();

        let deposit_queue_len = buf.get_u32() as usize;
        let mut deposit_queue = VecDeque::with_capacity(deposit_queue_len);
        for _ in 0..deposit_queue_len {
            deposit_queue.push_back(DepositRequest::read_cfg(buf, &())?);
        }

        let withdrawal_queue_len = buf.get_u32() as usize;
        let mut withdrawal_queue = VecDeque::with_capacity(withdrawal_queue_len);
        for _ in 0..withdrawal_queue_len {
            withdrawal_queue.push_back(PendingWithdrawal::read_cfg(buf, &())?);
        }

        let validator_accounts_len = buf.get_u32() as usize;
        let mut validator_accounts = HashMap::with_capacity(validator_accounts_len);
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
        let mut added_validators = Vec::with_capacity(added_validators_len);
        for _ in 0..added_validators_len {
            added_validators.push(PublicKey::read_cfg(buf, &())?);
        }

        // Read removed_validators
        let removed_validators_len = buf.get_u32() as usize;
        let mut removed_validators = Vec::with_capacity(removed_validators_len);
        for _ in 0..removed_validators_len {
            removed_validators.push(PublicKey::read_cfg(buf, &())?);
        }

        Ok(Self {
            latest_height,
            next_withdrawal_index,
            deposit_queue,
            withdrawal_queue,
            validator_accounts,
            pending_checkpoint,
            added_validators,
            removed_validators,
        })
    }
}

impl Write for ConsensusState {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.latest_height);
        buf.put_u64(self.next_withdrawal_index);

        buf.put_u32(self.deposit_queue.len() as u32);
        for request in &self.deposit_queue {
            request.write(buf);
        }

        buf.put_u32(self.withdrawal_queue.len() as u32);
        for request in &self.withdrawal_queue {
            request.write(buf);
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
        for validator in &self.added_validators {
            validator.write(buf);
        }

        // Write removed_validators
        buf.put_u32(self.removed_validators.len() as u32);
        for validator in &self.removed_validators {
            validator.write(buf);
        }
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

    fn create_test_deposit_request(index: u64, amount: u64) -> DepositRequest {
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01; // Eth1 withdrawal prefix
        for i in 0..20 {
            withdrawal_credentials[12 + i] = index as u8;
        }

        DepositRequest {
            pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            withdrawal_credentials,
            amount,
            signature: [index as u8; 64],
            index,
        }
    }

    fn create_test_withdrawal(
        index: u64,
        amount: u64,
        withdrawal_height: u64,
    ) -> PendingWithdrawal {
        PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: index * 10,
                address: Address::from([index as u8; 20]),
                amount,
            },
            withdrawal_height,
            pubkey: [index as u8; 32],
        }
    }

    fn create_test_validator_account(index: u64, balance: u64) -> ValidatorAccount {
        ValidatorAccount {
            withdrawal_credentials: Address::from([index as u8; 20]),
            balance,
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            last_deposit_index: index,
        }
    }

    #[test]
    fn test_serialization_deserialization_empty() {
        let original_state = ConsensusState::new();

        let mut encoded = original_state.encode();
        let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

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
    }

    #[test]
    fn test_serialization_deserialization_populated() {
        let mut original_state = ConsensusState::new();

        original_state.set_latest_height(42);
        original_state.next_withdrawal_index = 5;

        let deposit1 = create_test_deposit_request(1, 32000000000);
        let deposit2 = create_test_deposit_request(2, 16000000000);
        original_state.push_deposit(deposit1);
        original_state.push_deposit(deposit2);

        let withdrawal1 = create_test_withdrawal(1, 16000000000, 100);
        let withdrawal2 = create_test_withdrawal(2, 24000000000, 150);
        original_state.push_withdrawal(withdrawal1);
        original_state.push_withdrawal(withdrawal2);

        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];
        let account1 = create_test_validator_account(1, 32000000000);
        let account2 = create_test_validator_account(2, 64000000000);
        original_state.set_account(pubkey1, account1);
        original_state.set_account(pubkey2, account2);

        let mut encoded = original_state.encode();
        let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

        assert_eq!(decoded_state.latest_height, original_state.latest_height);
        assert_eq!(
            decoded_state.next_withdrawal_index,
            original_state.next_withdrawal_index
        );

        assert_eq!(decoded_state.deposit_queue.len(), 2);
        assert_eq!(decoded_state.deposit_queue[0].amount, 32000000000);
        assert_eq!(decoded_state.deposit_queue[1].amount, 16000000000);

        assert_eq!(decoded_state.withdrawal_queue.len(), 2);
        assert_eq!(decoded_state.withdrawal_queue[0].inner.index, 1);
        assert_eq!(decoded_state.withdrawal_queue[0].inner.amount, 16000000000);
        assert_eq!(decoded_state.withdrawal_queue[0].withdrawal_height, 100);
        assert_eq!(decoded_state.withdrawal_queue[1].inner.index, 2);
        assert_eq!(decoded_state.withdrawal_queue[1].inner.amount, 24000000000);
        assert_eq!(decoded_state.withdrawal_queue[1].withdrawal_height, 150);

        assert_eq!(decoded_state.validator_accounts.len(), 2);
        let decoded_account1 = decoded_state.validator_accounts.get(&pubkey1).unwrap();
        assert_eq!(decoded_account1.balance, 32000000000);
        assert_eq!(decoded_account1.last_deposit_index, 1);
        let decoded_account2 = decoded_state.validator_accounts.get(&pubkey2).unwrap();
        assert_eq!(decoded_account2.balance, 64000000000);
        assert_eq!(decoded_account2.last_deposit_index, 2);
    }

    #[test]
    fn test_encode_size_accuracy() {
        let mut state = ConsensusState::new();

        state.set_latest_height(42);
        state.next_withdrawal_index = 5;

        let deposit = create_test_deposit_request(1, 32000000000);
        state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000, 100);
        state.push_withdrawal(withdrawal);

        let pubkey = [1u8; 32];
        let account = create_test_validator_account(1, 32000000000);
        state.set_account(pubkey, account);

        let predicted_size = state.encode_size();
        let actual_encoded = state.encode();
        let actual_size = actual_encoded.len();

        assert_eq!(predicted_size, actual_size);
    }

    #[test]
    fn test_account_operations() {
        let mut state = ConsensusState::new();
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
        let mut original_state = ConsensusState::new();
        original_state.set_latest_height(100);
        original_state.next_withdrawal_index = 42;

        // Add some data
        let deposit = create_test_deposit_request(1, 32000000000);
        original_state.push_deposit(deposit);

        let withdrawal = create_test_withdrawal(1, 16000000000, 50);
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
        assert_eq!(restored_state.latest_height, original_state.latest_height);
        assert_eq!(
            restored_state.next_withdrawal_index,
            original_state.next_withdrawal_index
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
        assert_eq!(restored_state.withdrawal_queue[0].inner.amount, 16000000000);
        assert_eq!(restored_state.withdrawal_queue[0].withdrawal_height, 50);

        let restored_account = restored_state.get_account(&pubkey).unwrap();
        assert_eq!(restored_account.balance, 32000000000);
        assert_eq!(restored_account.last_deposit_index, 1);
    }
}
