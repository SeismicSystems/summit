use crate::Digest;
use crate::account::ValidatorStatus;
use crate::consensus_state::ConsensusState;
use crate::genesis::Genesis;
use crate::header::FinalizedHeader;
use crate::scheme::MultisigScheme;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::{Hasher, Sha256, ed25519};
use commonware_parallel::Sequential;
use commonware_utils::TryCollect;
use commonware_utils::ordered::BiMap;
use rand::rngs::OsRng;
use ssz::{Decode, Encode as SszEncode};
use std::collections::BTreeSet;
use std::{error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub data: Bytes,
    pub digest: Digest,
}

impl Checkpoint {
    pub fn new(state: &ConsensusState) -> Self {
        let data = state.encode();
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

#[derive(Debug)]
pub enum CheckpointVerificationError {
    NoHeaders,
    NonContiguousEpochs { expected: u64, found: u64 },
    SignatureVerificationFailed { epoch: u64 },
    CheckpointHashMismatch,
    ValidatorSetMismatch(String),
    ValidatorSetError(String),
}

impl fmt::Display for CheckpointVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeaders => write!(f, "no finalized headers provided"),
            Self::NonContiguousEpochs { expected, found } => {
                write!(f, "expected epoch {expected}, found {found}")
            }
            Self::SignatureVerificationFailed { epoch } => {
                write!(f, "BLS signature verification failed for epoch {epoch}")
            }
            Self::CheckpointHashMismatch => {
                write!(
                    f,
                    "checkpoint hash in final header does not match checkpoint digest"
                )
            }
            Self::ValidatorSetMismatch(reason) => {
                write!(f, "validator set mismatch: {reason}")
            }
            Self::ValidatorSetError(reason) => {
                write!(f, "failed to construct validator set: {reason}")
            }
        }
    }
}

impl error::Error for CheckpointVerificationError {}

/// Verifies a checkpoint by walking the chain of finalized headers from genesis.
///
/// For each epoch, the BLS aggregate signature is verified against the known
/// validator set, and validator set changes (added/removed) are applied.
/// Finally, the checkpoint hash in the last header is compared to the checkpoint digest.
pub fn verify_checkpoint_chain(
    genesis: &Genesis,
    finalized_headers: &[FinalizedHeader<MultisigScheme>],
    checkpoint: &Checkpoint,
) -> Result<(), CheckpointVerificationError> {
    if finalized_headers.is_empty() {
        return Err(CheckpointVerificationError::NoHeaders);
    }

    // Build initial validator set from genesis
    let validators = genesis
        .get_validators()
        .map_err(|e| CheckpointVerificationError::ValidatorSetError(e.to_string()))?;

    let namespace = genesis.namespace.as_bytes().to_vec();

    // Build the participant set as Vec<(ed25519::PublicKey, MinPk::Public)>
    // so we can mutate it across epochs
    let mut participants: Vec<(ed25519::PublicKey, <MinPk as Variant>::Public)> = validators
        .iter()
        .map(|v| {
            let minpk_public: &<MinPk as Variant>::Public = v.consensus_public_key.as_ref();
            let encoded = minpk_public.encode();
            let variant_pk = <MinPk as Variant>::Public::decode(&mut encoded.as_ref())
                .expect("failed to decode BLS public key");
            (v.node_public_key.clone(), variant_pk)
        })
        .collect();
    participants.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rng = OsRng;
    let mut signing_set = participants.clone();

    for (i, finalized_header) in finalized_headers.iter().enumerate() {
        // Save the current participants — this is the signing set for this epoch
        signing_set = participants.clone();
        let expected_epoch = i as u64;
        if finalized_header.header.epoch != expected_epoch {
            return Err(CheckpointVerificationError::NonContiguousEpochs {
                expected: expected_epoch,
                found: finalized_header.header.epoch,
            });
        }

        // Build a verifier scheme for this epoch's validator set
        let bimap: BiMap<ed25519::PublicKey, <MinPk as Variant>::Public> =
            participants.iter().cloned().try_collect().map_err(|e| {
                CheckpointVerificationError::ValidatorSetError(format!(
                    "epoch {expected_epoch}: {e:?}"
                ))
            })?;

        let scheme = MultisigScheme::verifier(&namespace, bimap);

        // Verify the BLS aggregate signature
        if !finalized_header
            .finalization
            .verify(&mut rng, &scheme, &Sequential)
        {
            return Err(CheckpointVerificationError::SignatureVerificationFailed {
                epoch: expected_epoch,
            });
        }

        // Update validator set for the next epoch
        for added in &finalized_header.header.added_validators {
            let minpk_public: &<MinPk as Variant>::Public = added.consensus_key.as_ref();
            let encoded = minpk_public.encode();
            let variant_pk = <MinPk as Variant>::Public::decode(&mut encoded.as_ref())
                .expect("failed to decode BLS public key");
            participants.push((added.node_key.clone(), variant_pk));
        }
        for removed in &finalized_header.header.removed_validators {
            participants.retain(|(pk, _)| pk != removed);
        }
        participants.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // Step 2: Compute the checkpoint digest and verify it matches the last header
    let last_header = finalized_headers.last().unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&checkpoint.data);
    let computed_digest = hasher.finalize();
    if last_header.header.checkpoint_hash != computed_digest {
        return Err(CheckpointVerificationError::CheckpointHashMismatch);
    }

    // Step 3: Verify validator set consistency.
    // `signing_set` is the validator set that signed epoch n's header — this was
    // independently accumulated by walking headers from genesis. The checkpoint's
    // validator_accounts should contain exactly these validators as active.
    let checkpoint_state = ConsensusState::try_from(checkpoint).map_err(|e| {
        CheckpointVerificationError::ValidatorSetError(format!(
            "failed to deserialize checkpoint: {e}"
        ))
    })?;

    let accumulated_keys: BTreeSet<[u8; 32]> = signing_set
        .iter()
        .map(|(pk, _)| {
            pk.as_ref()
                .try_into()
                .expect("ed25519 public key should be 32 bytes")
        })
        .collect();

    // Every validator in the accumulated signing set must have an account in the
    // checkpoint, and vice versa for active accounts.
    for key in &accumulated_keys {
        match checkpoint_state.validator_accounts.get(key) {
            None => {
                return Err(CheckpointVerificationError::ValidatorSetMismatch(format!(
                    "validator {key:?} accumulated from headers but missing from checkpoint accounts"
                )));
            }
            Some(account) => {
                // The validator should be active or have submitted an exit request
                // (exit requests during the epoch don't take effect until the boundary)
                if account.status != ValidatorStatus::Active
                    && account.status != ValidatorStatus::SubmittedExitRequest
                {
                    return Err(CheckpointVerificationError::ValidatorSetMismatch(format!(
                        "validator {key:?} is in signing set but has status {:?} in checkpoint",
                        account.status
                    )));
                }
            }
        }
    }

    // Reverse check: every active validator in the checkpoint must be in the
    // accumulated signing set.
    for (key, account) in &checkpoint_state.validator_accounts {
        if account.status == ValidatorStatus::Active && !accumulated_keys.contains(key) {
            return Err(CheckpointVerificationError::ValidatorSetMismatch(format!(
                "validator {key:?} is active in checkpoint but not in accumulated signing set"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::checkpoint::Checkpoint;
    use crate::consensus_state::ConsensusState;
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Signer, bls12381, ed25519, sha256};
    use ssz::{Decode, Encode};
    use std::collections::{BTreeMap, VecDeque};

    fn parse_public_key(public_key: &str) -> ed25519::PublicKey {
        ed25519::PublicKey::decode(
            commonware_utils::from_hex_formatted(public_key)
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    }

    #[test]
    fn test_checkpoint_ssz_encode_decode_empty() {
        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 10,
            head_digest: commonware_cryptography::sha256::Digest([0u8; 32]),
            next_withdrawal_index: 100,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: BTreeMap::new(),
            validator_accounts: BTreeMap::new(),
            protocol_param_changes: Vec::new(),
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        let consensus_key1 = bls12381::PrivateKey::from_seed(100);
        let deposit1 = DepositRequest {
            node_pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            consensus_pubkey: consensus_key1.public_key(),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            node_signature: [42u8; 64],
            consensus_signature: [1u8; 96],
            index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(101);
        let deposit2 = DepositRequest {
            node_pubkey: parse_public_key(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            consensus_pubkey: consensus_key2.public_key(),
            withdrawal_credentials: [2u8; 32],
            amount: 16_000_000_000, // 16 ETH in gwei
            node_signature: [43u8; 64],
            consensus_signature: [2u8; 96],
            index: 101,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            pubkey: [5u8; 32],
            subtract_balance: true,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(2);
        let validator_account2 = ValidatorAccount {
            consensus_public_key: consensus_key2.public_key(),
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000,                  // 16 ETH
            pending_withdrawal_amount: 8_000_000_000, // 8 ETH pending
            status: ValidatorStatus::SubmittedExitRequest,
            has_pending_deposit: false,
            has_pending_withdrawal: true,
            joining_epoch: 0,
            last_deposit_index: 101,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);
        deposit_queue.push_back(deposit2);

        let mut withdrawal_queue = BTreeMap::new();
        let mut epoch_queue = VecDeque::new();
        epoch_queue.push_back(pending_withdrawal);
        withdrawal_queue.insert(5, epoch_queue); // epoch 5

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 1000,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 200,
            deposit_queue,
            withdrawal_queue,
            protocol_param_changes: Vec::new(),
            validator_accounts,
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        use std::collections::{BTreeMap, VecDeque};

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: BTreeMap::new(),
            validator_accounts: BTreeMap::new(),
            protocol_param_changes: Vec::new(),
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        let consensus_key1 = bls12381::PrivateKey::from_seed(100);
        let deposit1 = DepositRequest {
            node_pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            consensus_pubkey: consensus_key1.public_key(),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            node_signature: [42u8; 64],
            consensus_signature: [1u8; 96],
            index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(101);
        let deposit2 = DepositRequest {
            node_pubkey: parse_public_key(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            consensus_pubkey: consensus_key2.public_key(),
            withdrawal_credentials: [2u8; 32],
            amount: 16_000_000_000, // 16 ETH in gwei
            node_signature: [43u8; 64],
            consensus_signature: [2u8; 96],
            index: 101,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            pubkey: [5u8; 32],
            subtract_balance: true,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(2);
        let validator_account2 = ValidatorAccount {
            consensus_public_key: consensus_key2.public_key(),
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000,                  // 16 ETH
            pending_withdrawal_amount: 8_000_000_000, // 8 ETH pending
            status: ValidatorStatus::SubmittedExitRequest,
            has_pending_deposit: false,
            has_pending_withdrawal: true,
            joining_epoch: 0,
            last_deposit_index: 101,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);
        deposit_queue.push_back(deposit2);

        let mut withdrawal_queue = BTreeMap::new();
        let mut epoch_queue = VecDeque::new();
        epoch_queue.push_back(pending_withdrawal);
        withdrawal_queue.insert(5, epoch_queue); // epoch 5

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 2000,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 300,
            deposit_queue,
            withdrawal_queue,
            protocol_param_changes: Vec::new(),
            validator_accounts,
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        use std::collections::{BTreeMap, VecDeque};

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: BTreeMap::new(),
            validator_accounts: BTreeMap::new(),
            protocol_param_changes: Vec::new(),
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        use std::collections::{BTreeMap, VecDeque};

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: BTreeMap::new(),
            validator_accounts: BTreeMap::new(),
            protocol_param_changes: Vec::new(),
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        assert_eq!(converted_state.epoch, original_state.epoch);
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
        use std::collections::{BTreeMap, VecDeque};

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 99,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: BTreeMap::new(),
            validator_accounts: BTreeMap::new(),
            protocol_param_changes: Vec::new(),
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
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
        let consensus_key1 = bls12381::PrivateKey::from_seed(100);
        let deposit1 = DepositRequest {
            node_pubkey: parse_public_key(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            consensus_pubkey: consensus_key1.public_key(),
            withdrawal_credentials: [1u8; 32],
            amount: 32_000_000_000, // 32 ETH in gwei
            node_signature: [42u8; 64],
            consensus_signature: [1u8; 96],
            index: 100,
        };

        let pending_withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from([3u8; 20]),
                amount: 8_000_000_000, // 8 ETH in gwei
            },
            pubkey: [5u8; 32],
            subtract_balance: true,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);

        let mut withdrawal_queue = BTreeMap::new();
        let mut epoch_queue = VecDeque::new();
        epoch_queue.push_back(pending_withdrawal);
        withdrawal_queue.insert(5, epoch_queue); // epoch 5

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 1000,
            head_digest: sha256::Digest([0u8; 32]),
            next_withdrawal_index: 200,
            deposit_queue,
            withdrawal_queue,
            protocol_param_changes: Vec::new(),
            validator_accounts,
            pending_checkpoint: None,
            added_validators: BTreeMap::new(),
            removed_validators: Vec::new(),
            pending_execution_requests: Vec::new(),
            forkchoice: Default::default(),
            epoch_genesis_hash: [0u8; 32],
            validator_minimum_stake: 32_000_000_000, // 32 ETH in gwei
            validator_maximum_stake: 32_000_000_000, // 32 ETH in gwei
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        // Verify all fields match
        assert_eq!(converted_state.epoch, original_state.epoch);
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
        let epoch5_withdrawals = converted_state.get_withdrawals_for_epoch(5).unwrap();
        assert_eq!(epoch5_withdrawals[0].inner.amount, 8_000_000_000);
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
