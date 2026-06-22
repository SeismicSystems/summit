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
use commonware_utils::from_hex_formatted;
use commonware_utils::hex;
use commonware_utils::ordered::BiMap;
use rand::rngs::OsRng;
use ssz::{Decode, Encode as SszEncode};
use std::collections::BTreeSet;
use std::{error, fmt};

pub const WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS: u64 = 5;

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

        // Bind the redundant `digest` field to `data`: a decoded checkpoint must
        // satisfy `digest == sha256(data)`.
        let digest = Digest::from(digest_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&data);
        if hasher.finalize() != digest {
            return Err(ssz::DecodeError::BytesInvalid(
                "checkpoint digest does not match sha256(data)".to_string(),
            ));
        }

        Ok(Self {
            data: Bytes::from(data),
            digest,
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
        let len: u32 = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)?;
        if len as usize > buf.remaining() {
            return Err(Error::Invalid("Checkpoint", "improper encoded length"));
        }

        let mut payload = vec![0u8; len as usize];
        buf.try_copy_to_slice(&mut payload)
            .map_err(|_| Error::EndOfBuffer)?;
        Self::from_ssz_bytes(&payload)
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

        let state = ConsensusState::read(&mut checkpoint.data.as_ref())?;
        if state.get_pending_checkpoint().is_some() {
            return Err(Error::Invalid(
                "Checkpoint",
                "Pending checkpoint not allowed",
            ));
        }

        Ok(state)
    }
}

#[derive(Debug)]
pub enum CheckpointVerificationError {
    NoHeaders,
    NonContiguousEpochs {
        expected: u64,
        found: u64,
    },
    SignatureVerificationFailed {
        epoch: u64,
    },
    CheckpointHashMismatch,
    PrevEpochHeaderHashMismatch {
        epoch: u64,
    },
    InvalidGenesisHash(String),
    WeakSubjectivityEpochUnavailable {
        epoch: u64,
        highest: u64,
    },
    WeakSubjectivityHeaderDigestMismatch {
        epoch: u64,
        expected: Digest,
        found: Digest,
    },
    WeakSubjectivityCheckpointTooOld {
        checkpoint_epoch: u64,
        weak_subjectivity_epoch: u64,
        max_age_epochs: u64,
    },
    ValidatorSetMismatch(String),
    ValidatorSetError(String),
    /// A finalized header's fields do not hash to the digest signed by its
    /// finalization certificate, so the header fields are not authenticated.
    PayloadDigestMismatch {
        epoch: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeakSubjectivityHeaderDigest {
    pub epoch: u64,
    pub header_digest: Digest,
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
            Self::PrevEpochHeaderHashMismatch { epoch } => {
                write!(
                    f,
                    "prev_epoch_header_hash mismatch for epoch {epoch}: does not chain to previous finalized header"
                )
            }
            Self::InvalidGenesisHash(reason) => {
                write!(f, "invalid genesis hash: {reason}")
            }
            Self::WeakSubjectivityEpochUnavailable { epoch, highest } => {
                write!(
                    f,
                    "weak-subjectivity epoch {epoch} is not present in finalized headers; highest available epoch is {highest}"
                )
            }
            Self::WeakSubjectivityHeaderDigestMismatch {
                epoch,
                expected,
                found,
            } => {
                write!(
                    f,
                    "weak-subjectivity header digest mismatch at epoch {epoch}: expected 0x{}, found 0x{}",
                    hex(expected.as_ref()),
                    hex(found.as_ref())
                )
            }
            Self::WeakSubjectivityCheckpointTooOld {
                checkpoint_epoch,
                weak_subjectivity_epoch,
                max_age_epochs,
            } => {
                write!(
                    f,
                    "checkpoint epoch {checkpoint_epoch} is more than {max_age_epochs} epochs after weak-subjectivity epoch {weak_subjectivity_epoch}"
                )
            }
            Self::ValidatorSetMismatch(reason) => {
                write!(f, "validator set mismatch: {reason}")
            }
            Self::ValidatorSetError(reason) => {
                write!(f, "failed to construct validator set: {reason}")
            }
            Self::PayloadDigestMismatch { epoch } => {
                write!(
                    f,
                    "epoch {epoch}: header fields do not match the finalization payload digest"
                )
            }
        }
    }
}

impl error::Error for CheckpointVerificationError {}

/// Verifies a checkpoint by walking the chain of finalized headers from genesis.
///
/// This checks internal chain consistency only. Checkpoint imports should call
/// `verify_checkpoint_chain_with_weak_subjectivity` so the supplied history is
/// tied to an independently trusted recent finalized-header digest.
///
/// For each epoch, the BLS aggregate signature is verified against the known
/// validator set, and validator set changes (added/removed) are applied.
/// Finally, the checkpoint hash in the last header is compared to the checkpoint digest.
pub fn verify_checkpoint_chain(
    genesis: &Genesis,
    finalized_headers: &[FinalizedHeader<MultisigScheme>],
    checkpoint: &Checkpoint,
) -> Result<(), CheckpointVerificationError> {
    verify_checkpoint_chain_with_weak_subjectivity(genesis, finalized_headers, checkpoint, None)
}

/// Verifies a checkpoint by walking the chain of finalized headers from genesis
/// and requiring the chain to pass through an independently trusted finalized
/// header digest.
pub fn verify_checkpoint_chain_with_weak_subjectivity(
    genesis: &Genesis,
    finalized_headers: &[FinalizedHeader<MultisigScheme>],
    checkpoint: &Checkpoint,
    weak_subjectivity: Option<&WeakSubjectivityHeaderDigest>,
) -> Result<(), CheckpointVerificationError> {
    if finalized_headers.is_empty() {
        return Err(CheckpointVerificationError::NoHeaders);
    }

    // Anchor for the epoch-header chain: the first finalized header's
    // `prev_epoch_header_hash` must equal the eth genesis hash (see
    // finalizer/src/actor.rs where `prev_header_hash` falls back to
    // `self.genesis_hash` when no prior finalized header exists).
    let genesis_hash: Digest = from_hex_formatted(&genesis.eth_genesis_hash)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Digest::from)
        .ok_or_else(|| {
            CheckpointVerificationError::InvalidGenesisHash(genesis.eth_genesis_hash.clone())
        })?;

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

        // Authenticate the header's fields against the signed certificate
        // payload BEFORE trusting any of them. The certificate signs a digest;
        // recompute it from the header's own fields (ignoring any cached/seeded
        // value) and require equality. Without this, a typed `FinalizedHeader`
        // carrying a valid certificate but mutated header fields (e.g.
        // `checkpoint_hash`) would be trusted below.
        if finalized_header.header().computed_digest()
            != finalized_header.finalization().proposal.payload
        {
            return Err(CheckpointVerificationError::PayloadDigestMismatch { epoch: i as u64 });
        }

        if finalized_header.header().epoch() != expected_epoch {
            return Err(CheckpointVerificationError::NonContiguousEpochs {
                expected: expected_epoch,
                found: finalized_header.header().epoch(),
            });
        }

        // Verify the epoch-header chain links to the previous finalized header
        // (or to genesis for epoch 0).
        let expected_prev = if i == 0 {
            genesis_hash
        } else {
            finalized_headers[i - 1].header().get_digest()
        };
        if finalized_header.header().prev_epoch_header_hash() != expected_prev {
            return Err(CheckpointVerificationError::PrevEpochHeaderHashMismatch {
                epoch: expected_epoch,
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
            .finalization()
            .verify(&mut rng, &scheme, &Sequential)
        {
            return Err(CheckpointVerificationError::SignatureVerificationFailed {
                epoch: expected_epoch,
            });
        }

        // Update validator set for the next epoch
        for added in finalized_header.header().added_validators() {
            let minpk_public: &<MinPk as Variant>::Public = added.consensus_key.as_ref();
            let encoded = minpk_public.encode();
            let variant_pk = <MinPk as Variant>::Public::decode(&mut encoded.as_ref())
                .expect("failed to decode BLS public key");
            participants.push((added.node_key.clone(), variant_pk));
        }
        for removed in finalized_header.header().removed_validators() {
            participants.retain(|(pk, _)| *pk != removed);
        }
        participants.sort_by(|a, b| a.0.cmp(&b.0));
    }

    if let Some(weak_subjectivity) = weak_subjectivity {
        let Some(anchor_index) = usize::try_from(weak_subjectivity.epoch).ok() else {
            let highest = finalized_headers.len() as u64 - 1;
            return Err(
                CheckpointVerificationError::WeakSubjectivityEpochUnavailable {
                    epoch: weak_subjectivity.epoch,
                    highest,
                },
            );
        };
        let Some(anchor_header) = finalized_headers.get(anchor_index) else {
            let highest = finalized_headers.len() as u64 - 1;
            return Err(
                CheckpointVerificationError::WeakSubjectivityEpochUnavailable {
                    epoch: weak_subjectivity.epoch,
                    highest,
                },
            );
        };

        if anchor_header.header().get_digest() != weak_subjectivity.header_digest {
            return Err(
                CheckpointVerificationError::WeakSubjectivityHeaderDigestMismatch {
                    epoch: weak_subjectivity.epoch,
                    expected: weak_subjectivity.header_digest,
                    found: anchor_header.header().get_digest(),
                },
            );
        }

        let checkpoint_epoch = finalized_headers.len() as u64 - 1;
        if checkpoint_epoch - weak_subjectivity.epoch > WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS {
            return Err(
                CheckpointVerificationError::WeakSubjectivityCheckpointTooOld {
                    checkpoint_epoch,
                    weak_subjectivity_epoch: weak_subjectivity.epoch,
                    max_age_epochs: WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS,
                },
            );
        }
    }

    // Step 2: Compute the checkpoint digest and verify it matches the last header
    let last_header = finalized_headers.last().unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&checkpoint.data);
    let computed_digest = hasher.finalize();
    if last_header.header().checkpoint_hash() != computed_digest {
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
    use crate::dynamic_epocher::DynamicEpocher;
    use crate::genesis::Genesis;
    use crate::header::FinalizedHeader;
    use crate::scheme::MultisigScheme;
    use crate::ssz_state_tree::SszStateTree;
    use crate::withdrawal::WithdrawalQueue;
    use alloy_primitives::Address;
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Signer, bls12381, ed25519, sha256};
    use ssz::{Decode, Encode};
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroU64;
    use std::sync::Arc;

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
        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(100);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 10,
            head_digest: commonware_cryptography::sha256::Digest([0u8; 32]),
            deposit_queue: VecDeque::new(),
            withdrawal_queue,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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
            balance_deduction: 8_000_000_000,
            epoch: 5,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

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
            balance: 16_000_000_000, // 16 ETH

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

        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(200);
        withdrawal_queue.push(pending_withdrawal);

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 1000,
            head_digest: sha256::Digest([0u8; 32]),
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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

        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(99);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            deposit_queue: VecDeque::new(),
            withdrawal_queue,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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
            balance_deduction: 8_000_000_000,
            epoch: 5,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

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
            balance: 16_000_000_000, // 16 ETH

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

        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(300);
        withdrawal_queue.push(pending_withdrawal);

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);
        validator_accounts.insert([11u8; 32], validator_account2);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 2000,
            head_digest: sha256::Digest([0u8; 32]),
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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

        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(99);

        let state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            deposit_queue: VecDeque::new(),
            withdrawal_queue,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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
        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(99);

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            deposit_queue: VecDeque::new(),
            withdrawal_queue,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        assert_eq!(converted_state.epoch, original_state.epoch);
        assert_eq!(converted_state.latest_height, original_state.latest_height);
        assert_eq!(
            converted_state.get_next_withdrawal_index(),
            original_state.get_next_withdrawal_index()
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
        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(99);

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 42,
            head_digest: sha256::Digest([0u8; 32]),
            deposit_queue: VecDeque::new(),
            withdrawal_queue,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
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
    fn test_try_from_checkpoint_rejects_pending_checkpoint() {
        let pending_state = ConsensusState::default();
        let pending_checkpoint = Checkpoint::new(&pending_state);

        let mut outer_state = ConsensusState::default();
        outer_state.set_pending_checkpoint(Some(pending_checkpoint));

        // The outer checkpoint digest is valid for the serialized state, but
        // finalized checkpoint artifacts must not carry staged checkpoint data.
        let outer_checkpoint = Checkpoint::new(&outer_state);
        let result = ConsensusState::try_from(&outer_checkpoint);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_ssz_bytes_rejects_digest_data_mismatch() {
        // A decoded Checkpoint must satisfy `digest == sha256(data)`. Encoding a
        // checkpoint whose stored digest does not match its data and decoding it
        // must fail. This is the path `ConsensusState::read_cfg` uses to decode an
        // embedded pending_checkpoint.
        let valid = Checkpoint::new(&ConsensusState::default());
        let tampered = Checkpoint {
            data: valid.data.clone(),
            digest: [0xFF; 32].into(),
        };
        assert!(Checkpoint::from_ssz_bytes(&tampered.as_ssz_bytes()).is_err());

        // Sanity: a self-consistent checkpoint still round-trips.
        assert_eq!(
            Checkpoint::from_ssz_bytes(&valid.as_ssz_bytes()).unwrap(),
            valid
        );
    }

    #[test]
    fn test_consensus_state_decode_rejects_tampered_pending_checkpoint_digest() {
        use commonware_codec::Encode as _;

        // ConsensusState::read_cfg decodes an embedded pending_checkpoint through
        // Checkpoint::from_ssz_bytes, so a pending_checkpoint whose digest does
        // not match its data must be rejected on decode rather than trusted.
        let mut pending = Checkpoint::new(&ConsensusState::default());
        pending.digest = [0xFF; 32].into();

        let mut state = ConsensusState::default();
        state.set_pending_checkpoint(Some(pending));

        let mut encoded = state.encode();
        assert!(ConsensusState::decode(&mut encoded).is_err());
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
            balance_deduction: 8_000_000_000,
            epoch: 5,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        // Create populated state
        let mut deposit_queue = VecDeque::new();
        deposit_queue.push_back(deposit1);

        let mut withdrawal_queue = WithdrawalQueue::default();
        withdrawal_queue.set_next_index(200);
        withdrawal_queue.push(pending_withdrawal);

        let mut validator_accounts = BTreeMap::new();
        validator_accounts.insert([10u8; 32], validator_account1);

        let original_state = ConsensusState {
            epoch: 0,
            view: 0,
            latest_height: 1000,
            head_digest: sha256::Digest([0u8; 32]),
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            epocher: DynamicEpocher::new(NonZeroU64::new(10).unwrap()),
            ssz_tree: SszStateTree::default(),
            proof_tree: Arc::new(SszStateTree::default()),
            state_root: [0u8; 32],
            proof_validator_keys: Arc::new(Vec::new()),

            proof_el_block_number: 0,
            captured_bytes: None,
        };

        let checkpoint = Checkpoint::new(&original_state);
        let converted_state = ConsensusState::try_from(&checkpoint).unwrap();

        // Verify all fields match
        assert_eq!(converted_state.epoch, original_state.epoch);
        assert_eq!(converted_state.latest_height, original_state.latest_height);
        assert_eq!(
            converted_state.get_next_withdrawal_index(),
            original_state.get_next_withdrawal_index()
        );
        assert_eq!(converted_state.deposit_queue.len(), 1);
        assert_eq!(converted_state.withdrawal_queue.len(), 1);
        assert_eq!(converted_state.validator_accounts.len(), 1);

        // Verify specific content
        assert_eq!(converted_state.deposit_queue[0].amount, 32_000_000_000);
        let epoch5_withdrawals = converted_state.get_withdrawals_for_epoch(5);
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

    // Builds a single-epoch checkpoint chain: a genesis validator set, a matching
    // checkpoint, a *different* ("attacker-controlled") checkpoint, and an honest
    // finalized header whose certificate genuinely signs the honest header digest
    // and whose `checkpoint_hash` commits to the honest checkpoint.
    fn checkpoint_verification_fixture() -> (
        Genesis,
        Checkpoint,
        Checkpoint,
        FinalizedHeader<MultisigScheme>,
    ) {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::genesis::GenesisValidator;
        use crate::header::Header;
        use commonware_codec::Encode as _;
        use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::bls12381::primitives::group;
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
        use commonware_parallel::Sequential;
        use commonware_utils::TryCollect;
        use commonware_utils::hex;
        use commonware_utils::ordered::BiMap;

        let namespace = "checkpoint-typed-header-test".to_string();
        let mut genesis_validators = Vec::new();
        let mut validator_accounts = BTreeMap::new();
        let mut participants = Vec::new();
        let mut group_privates = Vec::new();

        for i in 0..4u64 {
            let node_key = ed25519::PrivateKey::from_seed(i);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(100 + i);
            let consensus_public_key = consensus_key.public_key();

            let encoded_private = consensus_key.encode();
            let group_private = group::Private::decode(&mut encoded_private.as_ref())
                .expect("BLS private key should decode as group scalar");
            group_privates.push(group_private);

            let minpk_public: &<MinPk as Variant>::Public = consensus_public_key.as_ref();
            let encoded_public = minpk_public.encode();
            let variant_public = <MinPk as Variant>::Public::decode(&mut encoded_public.as_ref())
                .expect("BLS public key should decode as MinPk public key");
            participants.push((node_public_key.clone(), variant_public));

            let withdrawal_credentials = Address::from([i as u8; 20]);
            genesis_validators.push(GenesisValidator {
                node_public_key: format!("0x{}", hex(node_public_key.as_ref())),
                consensus_public_key: format!("0x{}", hex(consensus_public_key.as_ref())),
                ip_address: format!("127.0.0.1:{}", 10_000 + i),
                withdrawal_credentials: withdrawal_credentials.to_string(),
            });

            let account = ValidatorAccount {
                consensus_public_key,
                withdrawal_credentials,
                balance: 32_000_000_000,
                status: ValidatorStatus::Active,
                has_pending_deposit: false,
                has_pending_withdrawal: false,
                joining_epoch: 0,
                last_deposit_index: 0,
            };
            let key_bytes: [u8; 32] = node_public_key
                .as_ref()
                .try_into()
                .expect("ed25519 public key should be 32 bytes");
            validator_accounts.insert(key_bytes, account);
        }

        let genesis = Genesis {
            validators: genesis_validators,
            eth_genesis_hash: format!("0x{}", "00".repeat(32)),
            leader_timeout_ms: 1_000,
            notarization_timeout_ms: 1_000,
            nullify_timeout_ms: 1_000,
            activity_timeout_views: 10,
            skip_timeout_views: 5,
            max_message_size_bytes: 1_048_576,
            namespace: namespace.clone(),
            validator_minimum_stake: 32_000_000_000,
            validator_maximum_stake: 64_000_000_000,
            blocks_per_epoch: 10,
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO.to_string(),
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 1,
        };

        let mut state = ConsensusState::new(
            Default::default(),
            32_000_000_000,
            64_000_000_000,
            NonZeroU64::new(10).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            1,
        );
        state.set_validator_accounts(validator_accounts);
        let checkpoint = Checkpoint::new(&state);

        // A distinct checkpoint the attacker would like the chain to authenticate.
        let mut tampered_state = state.clone();
        tampered_state.set_latest_height(1);
        let tampered_checkpoint = Checkpoint::new(&tampered_state);
        assert_ne!(checkpoint.digest, tampered_checkpoint.digest);

        // Honest header commits to the honest checkpoint.
        let header = Header::new(
            [0u8; 32].into(),
            0,
            0,
            0,
            0,
            [1u8; 32].into(),
            [2u8; 32].into(),
            checkpoint.digest,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        );

        participants.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        let signers: BiMap<ed25519::PublicKey, <MinPk as Variant>::Public> =
            participants.into_iter().try_collect().unwrap();
        let schemes: Vec<_> = group_privates
            .into_iter()
            .filter_map(|private| {
                MultisigScheme::signer(namespace.as_bytes(), signers.clone(), private)
            })
            .collect();

        // Certificate genuinely signs the honest header digest.
        let proposal = Proposal {
            round: Round::new(Epoch::new(0), View::new(header.view())),
            parent: View::new(header.height()),
            payload: header.get_digest(),
        };
        let finalizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization = Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("finalization should aggregate");

        let finalized_header = FinalizedHeader::new(header, finalization, schemes.len())
            .expect("honest header is bound to its certificate");

        (genesis, checkpoint, tampered_checkpoint, finalized_header)
    }

    // Closes the typed-API trust-boundary gap: a finalized header carries header
    // fields (e.g. `checkpoint_hash`) and a certificate that signs a digest. The
    // fields must be bound to the signed digest, otherwise an attacker can pair a
    // genuine certificate (signing the honest digest) with header fields that
    // point at attacker-controlled checkpoint data.
    #[test]
    fn test_checkpoint_verifier_rejects_typed_header_field_mutation() {
        use crate::header::{FinalizedHeader, FinalizedHeaderError, Header};

        let (genesis, checkpoint, tampered_checkpoint, honest) = checkpoint_verification_fixture();

        // Sanity: the honest finalized header verifies against the honest checkpoint.
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("fixture checkpoint should verify before tampering");

        // Build a header identical to the honest one EXCEPT `checkpoint_hash`,
        // which is swapped to authenticate the attacker-controlled checkpoint.
        // Reuse the ORIGINAL finalization: its certificate still signs the honest
        // header digest, so the BLS signature remains valid — only the header
        // field was mutated.
        let h = honest.header().clone();
        let tampered_header = Header::new(
            h.parent(),
            h.height(),
            h.timestamp(),
            h.epoch(),
            h.view(),
            h.payload_hash(),
            h.execution_request_hash(),
            tampered_checkpoint.digest, // <-- mutated away from the signed digest
            h.prev_epoch_header_hash(),
            h.added_validators().to_vec(),
            h.removed_validators(),
            h.parent_beacon_block_root(),
        );

        // (1) The safe constructor rejects the unbound pairing outright.
        let err = FinalizedHeader::new(
            tampered_header.clone(),
            honest.finalization().clone(),
            honest.participant_count(),
        )
        .expect_err("FinalizedHeader::new must reject a mismatched header/payload");
        assert_eq!(err, FinalizedHeaderError::PayloadDigestMismatch);

        // (2) Even if a caller bypasses the safe constructor (e.g. via
        // `new_unchecked`, simulating a post-construction field mutation that the
        // private fields otherwise prevent), the verifier itself re-derives the
        // binding and rejects it.
        let smuggled = FinalizedHeader::new_unchecked(
            tampered_header,
            honest.finalization().clone(),
            honest.participant_count(),
        );
        let result = super::verify_checkpoint_chain(
            &genesis,
            std::slice::from_ref(&smuggled),
            &tampered_checkpoint,
        );
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::PayloadDigestMismatch { epoch: 0 })
            ),
            "verifier must reject a finalized header whose checkpoint_hash was \
             mutated away from the signed certificate payload, got {result:?}"
        );
    }
}
