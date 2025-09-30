use crate::Digest;
use crate::consensus_state::ConsensusState;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, Sha256};
use ssz::{Decode, Encode as SszEncode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub data: Bytes,
    pub digest: Digest,
}

impl Checkpoint {
    pub fn new(state: &ConsensusState) -> Self {
        let data = state.encode().freeze();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = hasher.finalize();
        Self { data, digest }
    }
}

impl SszEncode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset =
            <Vec<u8> as SszEncode>::ssz_fixed_len() + <[u8; 32] as SszEncode>::ssz_fixed_len();

        let mut encoder = ssz::SszEncoder::container(buf, offset);

        // Convert data from Bytes to Vec<u8>
        let data_vec: Vec<u8> = self.data.as_ref().to_vec();
        encoder.append(&data_vec);

        // Convert Digest to [u8; 32]
        let digest_array: [u8; 32] = self
            .digest
            .as_ref()
            .try_into()
            .expect("Digest should be 32 bytes");

        encoder.append(&digest_array);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let data_vec: Vec<u8> = self.data.as_ref().to_vec();

        data_vec.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET  // 1 variable-length field needs 1 offset
            + 32 // digest as [u8; 32]
    }
}

impl Decode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<u8>>()?;
        builder.register_type::<[u8; 32]>()?;

        let mut decoder = builder.build()?;

        let data: Vec<u8> = decoder.decode_next()?;
        let digest_bytes: [u8; 32] = decoder.decode_next()?;

        Ok(Self {
            data: Bytes::from(data),
            digest: Digest::from(digest_bytes),
        })
    }
}

impl EncodeSize for Checkpoint {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET
    }
}

impl Write for Checkpoint {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

impl Read for Checkpoint {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len: u32 = buf.get_u32();
        if len > buf.remaining() as u32 {
            return Err(Error::Invalid("Checkpoint", "improper encoded length"));
        }

        Self::from_ssz_bytes(buf.copy_to_bytes(len as usize).chunk())
            .map_err(|_| Error::Invalid("Checkpoint", "Unable to decode SSZ bytes for checkpoint"))
    }
}

impl TryFrom<&Checkpoint> for ConsensusState {
    type Error = Error;

    fn try_from(checkpoint: &Checkpoint) -> Result<Self, Self::Error> {
        // Verify the digest matches the data
        let mut hasher = Sha256::new();
        hasher.update(&checkpoint.data);
        let computed_digest = hasher.finalize();

        if computed_digest != checkpoint.digest {
            return Err(Error::Invalid("Checkpoint", "Digest verification failed"));
        }

        ConsensusState::read(&mut checkpoint.data.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::checkpoint::Checkpoint;
    use crate::consensus_state::ConsensusState;
    use commonware_codec::DecodeExt;
    use ssz::{Decode, Encode};
    use std::collections::{HashMap, VecDeque};

    fn parse_public_key(public_key: &str) -> commonware_cryptography::ed25519::PublicKey {
        commonware_cryptography::ed25519::PublicKey::decode(
            commonware_utils::from_hex_formatted(public_key)
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    }

    #[test]
    fn test_checkpoint_ssz_encode_decode_empty() {
        let state = ConsensusState {
            latest_height: 10,
            next_withdrawal_index: 100,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&state);

        // Test SSZ encoding/decoding
        let encoded = checkpoint.as_ssz_bytes();
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();

        // Check that all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.digest, checkpoint.digest);
    }

    #[test]
    fn test_checkpoint_ssz_encode_decode_with_populated_state() {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::execution_request::DepositRequest;
        use crate::withdrawal::PendingWithdrawal;
        use alloy_eips::eip4895::Withdrawal;
        use alloy_primitives::Address;
        use ssz::{Decode, Encode};

        // Create sample data for the populated state
        let deposit1 = DepositRequest {
            pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            signature: [42u8; 64],
            index: 100,
        };

        let deposit2 = DepositRequest {
            pubkey: parse_public_key(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            withdrawal_credentials: [2u8; 32],
            amount: 16_000_000_000, // 16 ETH in gwei
            signature: [43u8; 64],
            index: 101,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            withdrawal_height: 500,
            pubkey: [5u8; 32],
        };

        let validator_account1 = ValidatorAccount {
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            last_deposit_index: 100,
        };

        let validator_account2 = ValidatorAccount {
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000,                  // 16 ETH
            pending_withdrawal_amount: 8_000_000_000, // 8 ETH pending
            status: ValidatorStatus::SubmittedExitRequest,
            last_deposit_index: 101,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);
        deposit_queue.push_back(deposit2);

        let mut withdrawal_queue = VecDeque::new();
        withdrawal_queue.push_back(pending_withdrawal);

        let mut validator_accounts = HashMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            latest_height: 1000,
            next_withdrawal_index: 200,
            deposit_queue,
            withdrawal_queue,
            validator_accounts,
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&state);

        // Test SSZ encoding/decoding
        let encoded = checkpoint.as_ssz_bytes();
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();

        // Check that all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.digest, checkpoint.digest);

        // Verify the encoded data contains the populated state data
        assert!(encoded.len() > 100); // Should contain substantial data from the populated state
    }

    #[test]
    fn test_checkpoint_codec_encode_decode_empty() {
        use bytes::BytesMut;
        use commonware_codec::{EncodeSize, ReadExt, Write};
        use std::collections::{HashMap, VecDeque};

        let state = ConsensusState {
            latest_height: 42,
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&state);

        // Test Write
        let mut buf = BytesMut::new();
        checkpoint.write(&mut buf);

        // Test EncodeSize matches actual encoded size
        assert_eq!(buf.len(), checkpoint.encode_size());

        // Test Read
        let decoded = Checkpoint::read(&mut buf.as_ref()).unwrap();

        // Verify all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.digest, checkpoint.digest);
    }

    #[test]
    fn test_checkpoint_codec_encode_decode_with_populated_state() {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::execution_request::DepositRequest;
        use crate::withdrawal::PendingWithdrawal;
        use alloy_eips::eip4895::Withdrawal;
        use alloy_primitives::Address;
        use bytes::BytesMut;
        use commonware_codec::{EncodeSize, ReadExt, Write};

        // Create sample data for the populated state
        let deposit1 = DepositRequest {
            pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            signature: [42u8; 64],
            index: 100,
        };

        let deposit2 = DepositRequest {
            pubkey: parse_public_key(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            withdrawal_credentials: [2u8; 32],
            amount: 16_000_000_000, // 16 ETH in gwei
            signature: [43u8; 64],
            index: 101,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            withdrawal_height: 500,
            pubkey: [5u8; 32],
        };

        let validator_account1 = ValidatorAccount {
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            last_deposit_index: 100,
        };

        let validator_account2 = ValidatorAccount {
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000,                  // 16 ETH
            pending_withdrawal_amount: 8_000_000_000, // 8 ETH pending
            status: ValidatorStatus::SubmittedExitRequest,
            last_deposit_index: 101,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);
        deposit_queue.push_back(deposit2);

        let mut withdrawal_queue = VecDeque::new();
        withdrawal_queue.push_back(pending_withdrawal);

        let mut validator_accounts = HashMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            latest_height: 2000,
            next_withdrawal_index: 300,
            deposit_queue,
            withdrawal_queue,
            validator_accounts,
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&state);

        // Test Write
        let mut buf = BytesMut::new();
        checkpoint.write(&mut buf);

        // Test EncodeSize matches actual encoded size
        assert_eq!(buf.len(), checkpoint.encode_size());

        // Test Read
        let decoded = Checkpoint::read(&mut buf.as_ref()).unwrap();

        // Verify all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.digest, checkpoint.digest);

        // Verify the encoded data contains the populated state data
        assert!(buf.len() > 100); // Should contain substantial data from the populated state
    }

    #[test]
    fn test_checkpoint_encode_size_investigation() {
        use commonware_codec::EncodeSize;
        use std::collections::{HashMap, VecDeque};

        let state = ConsensusState {
            latest_height: 42,
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&state);

        let ssz_len = checkpoint.ssz_bytes_len();
        let encode_len = checkpoint.encode_size();
        let pure_ssz = checkpoint.as_ssz_bytes();

        println!("Checkpoint SSZ bytes len (calculated): {}", ssz_len);
        println!("Checkpoint Pure SSZ actual len: {}", pure_ssz.len());
        println!("Checkpoint EncodeSize: {}", encode_len);
        println!(
            "Difference (Pure SSZ - calculated SSZ): {}",
            pure_ssz.len() as i32 - ssz_len as i32
        );

        // Check if my calculation is correct
        assert_eq!(
            pure_ssz.len(),
            ssz_len,
            "SSZ calculation should match actual SSZ encoding"
        );
        assert_eq!(
            encode_len,
            pure_ssz.len() + ssz::BYTES_PER_LENGTH_OFFSET,
            "EncodeSize should be SSZ + 4-byte prefix"
        );
    }

    #[test]
    fn test_try_from_checkpoint_to_consensus_state() {
        use std::collections::{HashMap, VecDeque};

        let original_state = ConsensusState {
            latest_height: 42,
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        assert_eq!(converted_state.latest_height, original_state.latest_height);
        assert_eq!(
            converted_state.next_withdrawal_index,
            original_state.next_withdrawal_index
        );
        assert_eq!(
            converted_state.deposit_queue.len(),
            original_state.deposit_queue.len()
        );
        assert_eq!(
            converted_state.withdrawal_queue.len(),
            original_state.withdrawal_queue.len()
        );
        assert_eq!(
            converted_state.validator_accounts.len(),
            original_state.validator_accounts.len()
        );
    }

    #[test]
    fn test_try_from_checkpoint_with_corrupted_digest() {
        use std::collections::{HashMap, VecDeque};

        let original_state = ConsensusState {
            latest_height: 42,
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let mut checkpoint = Checkpoint::new(&original_state);
        // Corrupt the digest
        checkpoint.digest = [0xFF; 32].into();

        let result = ConsensusState::try_from(&checkpoint);
        assert!(result.is_err());

        if let Err(commonware_codec::Error::Invalid(entity, message)) = result {
            assert_eq!(entity, "Checkpoint");
            assert_eq!(message, "Digest verification failed");
        } else {
            panic!("Expected Invalid error with digest verification message");
        }
    }

    #[test]
    fn test_try_from_checkpoint_with_populated_state() {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::execution_request::DepositRequest;
        use crate::withdrawal::PendingWithdrawal;
        use alloy_eips::eip4895::Withdrawal;
        use alloy_primitives::Address;

        // Create sample data for the populated state
        let deposit1 = DepositRequest {
            pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            signature: [42u8; 64],
            index: 100,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            withdrawal_height: 500,
            pubkey: [5u8; 32],
        };

        let validator_account1 = ValidatorAccount {
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            last_deposit_index: 100,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);

        let mut withdrawal_queue = VecDeque::new();
        withdrawal_queue.push_back(pending_withdrawal);

        let mut validator_accounts = HashMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);

        let original_state = ConsensusState {
            latest_height: 1000,
            next_withdrawal_index: 200,
            deposit_queue,
            withdrawal_queue,
            validator_accounts,
            pending_checkpoint: None,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        // Verify all fields match
        assert_eq!(converted_state.latest_height, original_state.latest_height);
        assert_eq!(
            converted_state.next_withdrawal_index,
            original_state.next_withdrawal_index
        );
        assert_eq!(converted_state.deposit_queue.len(), 1);
        assert_eq!(converted_state.withdrawal_queue.len(), 1);
        assert_eq!(converted_state.validator_accounts.len(), 1);

        // Verify specific content
        assert_eq!(converted_state.deposit_queue[0].amount, 32_000_000_000);
        assert_eq!(
            converted_state.withdrawal_queue[0].inner.amount,
            8_000_000_000
        );
        assert_eq!(
            converted_state
                .validator_accounts
                .get(&[10u8; 32])
                .unwrap()
                .balance,
            32_000_000_000
        );
    }
}
