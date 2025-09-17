use crate::consensus_state::ConsensusState;
use crate::{Digest, PublicKey};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error, Read, Write};
use commonware_cryptography::{Hasher, Sha256};
use ssz::{Decode, Encode as SszEncode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub data: Bytes,
    pub added_validators: Vec<PublicKey>,
    pub removed_validators: Vec<PublicKey>,
    pub previous_digest: Digest,
    pub digest: Digest,
}

impl Checkpoint {
    pub fn new(
        state: &ConsensusState,
        mut added_validators: Vec<PublicKey>,
        mut removed_validators: Vec<PublicKey>,
        previous_digest: Digest,
    ) -> Self {
        let data = state.encode().freeze();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        // TODO(matthias): check if sorting is necessary
        added_validators.sort();
        removed_validators.sort();
        for validator in &added_validators {
            hasher.update(validator);
        }
        // This byte acts as a divider between the two lists
        // This is to avoid that the two lists
        // added_validators = [A, B], removed_validators = [C]
        // and
        // added_validators = [A], removed_validators = [B, C]
        // have the same hash
        hasher.update(&[0x00]);
        for validator in &removed_validators {
            hasher.update(validator);
        }
        hasher.update(&previous_digest);
        let digest = hasher.finalize();
        Self {
            data,
            added_validators,
            removed_validators,
            previous_digest,
            digest,
        }
    }
}

impl SszEncode for Checkpoint {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <Vec<u8> as SszEncode>::ssz_fixed_len()
            + <Vec<Vec<u8>> as SszEncode>::ssz_fixed_len()
            + <Vec<Vec<u8>> as SszEncode>::ssz_fixed_len()
            + <[u8; 32] as SszEncode>::ssz_fixed_len()
            + <[u8; 32] as SszEncode>::ssz_fixed_len();

        let mut encoder = ssz::SszEncoder::container(buf, offset);

        // Convert data from Bytes to Vec<u8>
        let data_vec: Vec<u8> = self.data.as_ref().to_vec();
        encoder.append(&data_vec);

        // Convert PublicKey to Vec<u8> for encoding
        let added_validators_bytes: Vec<Vec<u8>> = self
            .added_validators
            .iter()
            .map(|pk| pk.as_ref().to_vec())
            .collect();
        encoder.append(&added_validators_bytes);

        let removed_validators_bytes: Vec<Vec<u8>> = self
            .removed_validators
            .iter()
            .map(|pk| pk.as_ref().to_vec())
            .collect();
        encoder.append(&removed_validators_bytes);

        // Convert Digest to [u8; 32]
        let previous_digest_array: [u8; 32] = self
            .previous_digest
            .as_ref()
            .try_into()
            .expect("Digest should be 32 bytes");
        let digest_array: [u8; 32] = self
            .digest
            .as_ref()
            .try_into()
            .expect("Digest should be 32 bytes");

        encoder.append(&previous_digest_array);
        encoder.append(&digest_array);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let data_vec: Vec<u8> = self.data.as_ref().to_vec();
        let added_validators_bytes: Vec<Vec<u8>> = self
            .added_validators
            .iter()
            .map(|pk| pk.as_ref().to_vec())
            .collect();
        let removed_validators_bytes: Vec<Vec<u8>> = self
            .removed_validators
            .iter()
            .map(|pk| pk.as_ref().to_vec())
            .collect();

        data_vec.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET
            + added_validators_bytes.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET
            + removed_validators_bytes.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET
            + 32  // previous_digest as [u8; 32]
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
        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<[u8; 32]>()?;
        builder.register_type::<[u8; 32]>()?;

        let mut decoder = builder.build()?;

        let data: Vec<u8> = decoder.decode_next()?;
        let added_validators_bytes: Vec<Vec<u8>> = decoder.decode_next()?;
        let removed_validators_bytes: Vec<Vec<u8>> = decoder.decode_next()?;
        let previous_digest_bytes: [u8; 32] = decoder.decode_next()?;
        let digest_bytes: [u8; 32] = decoder.decode_next()?;

        // Convert bytes back to PublicKey
        use commonware_codec::DecodeExt as _;
        let added_validators: Result<Vec<PublicKey>, _> = added_validators_bytes
            .into_iter()
            .map(|bytes| PublicKey::decode(bytes.as_slice()))
            .collect();
        let removed_validators: Result<Vec<PublicKey>, _> = removed_validators_bytes
            .into_iter()
            .map(|bytes| PublicKey::decode(bytes.as_slice()))
            .collect();

        let added_validators = added_validators
            .map_err(|_| ssz::DecodeError::BytesInvalid("Invalid PublicKey bytes".to_string()))?;
        let removed_validators = removed_validators
            .map_err(|_| ssz::DecodeError::BytesInvalid("Invalid PublicKey bytes".to_string()))?;

        Ok(Self {
            data: Bytes::from(data),
            added_validators,
            removed_validators,
            previous_digest: Digest::from(previous_digest_bytes),
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
    fn test_digest() {
        let state = ConsensusState {
            latest_height: 10,
            next_withdrawal_index: 100,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let key3 =
            parse_public_key("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

        let added_validators1 = vec![key1.clone(), key2.clone()];
        let removed_validators1 = vec![key3.clone()];

        let added_validators2 = vec![key1];
        let removed_validators2 = vec![key2, key3];

        let previous_digest = [1; 32].into();

        let ckpt1 = Checkpoint::new(
            &state,
            added_validators1,
            removed_validators1,
            previous_digest,
        );
        let ckpt2 = Checkpoint::new(
            &state,
            added_validators2,
            removed_validators2,
            previous_digest,
        );

        // Make sure the digest are different
        assert_ne!(ckpt1.digest, ckpt2.digest);
    }

    #[test]
    fn test_checkpoint_ssz_encode_decode_empty() {
        let state = ConsensusState {
            latest_height: 10,
            next_withdrawal_index: 100,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let key3 =
            parse_public_key("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

        let added_validators = vec![key1.clone(), key2.clone()];
        let removed_validators = vec![key3.clone()];
        let previous_digest = [1; 32].into();

        let checkpoint = Checkpoint::new(
            &state,
            added_validators,
            removed_validators,
            previous_digest,
        );

        // Test SSZ encoding/decoding
        let encoded = checkpoint.as_ssz_bytes();
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();

        // Check that all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.added_validators, checkpoint.added_validators);
        assert_eq!(decoded.removed_validators, checkpoint.removed_validators);
        assert_eq!(decoded.previous_digest, checkpoint.previous_digest);
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
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let key3 =
            parse_public_key("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

        let added_validators = vec![key1.clone(), key2.clone()];
        let removed_validators = vec![key3.clone()];
        let previous_digest = [99u8; 32].into();

        let checkpoint = Checkpoint::new(
            &state,
            added_validators,
            removed_validators,
            previous_digest,
        );

        // Test SSZ encoding/decoding
        let encoded = checkpoint.as_ssz_bytes();
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();

        // Check that all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.added_validators, checkpoint.added_validators);
        assert_eq!(decoded.removed_validators, checkpoint.removed_validators);
        assert_eq!(decoded.previous_digest, checkpoint.previous_digest);
        assert_eq!(decoded.digest, checkpoint.digest);

        // Verify the encoded data is substantial due to populated state
        assert!(encoded.len() > 800); // Should be around 834 bytes with this populated data
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
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

        let added_validators = vec![key1.clone()];
        let removed_validators = vec![key2.clone()];
        let previous_digest = [42u8; 32].into();

        let checkpoint = Checkpoint::new(
            &state,
            added_validators,
            removed_validators,
            previous_digest,
        );

        // Test Write
        let mut buf = BytesMut::new();
        checkpoint.write(&mut buf);

        // Test EncodeSize matches actual encoded size
        assert_eq!(buf.len(), checkpoint.encode_size());

        // Test Read
        let decoded = Checkpoint::read(&mut buf.as_ref()).unwrap();

        // Verify all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.added_validators, checkpoint.added_validators);
        assert_eq!(decoded.removed_validators, checkpoint.removed_validators);
        assert_eq!(decoded.previous_digest, checkpoint.previous_digest);
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
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let key3 =
            parse_public_key("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

        let added_validators = vec![key1.clone(), key2.clone(), key3.clone()];
        let removed_validators = vec![key1.clone()]; // Remove key1
        let previous_digest = [123u8; 32].into();

        let checkpoint = Checkpoint::new(
            &state,
            added_validators,
            removed_validators,
            previous_digest,
        );

        // Test Write
        let mut buf = BytesMut::new();
        checkpoint.write(&mut buf);

        // Test EncodeSize matches actual encoded size
        assert_eq!(buf.len(), checkpoint.encode_size());

        // Test Read
        let decoded = Checkpoint::read(&mut buf.as_ref()).unwrap();

        // Verify all fields match
        assert_eq!(decoded.data, checkpoint.data);
        assert_eq!(decoded.added_validators, checkpoint.added_validators);
        assert_eq!(decoded.removed_validators, checkpoint.removed_validators);
        assert_eq!(decoded.previous_digest, checkpoint.previous_digest);
        assert_eq!(decoded.digest, checkpoint.digest);

        // Verify the encoded data is substantial due to populated state
        assert!(buf.len() > 800); // Should be substantial due to all the populated data
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
        };

        let key1 =
            parse_public_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key2 =
            parse_public_key("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

        let checkpoint = Checkpoint::new(&state, vec![key1], vec![key2], [42u8; 32].into());

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
}
