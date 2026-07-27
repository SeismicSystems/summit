use crate::Digest;
use crate::account::ValidatorStatus;
use crate::consensus_state::ConsensusState;
use crate::genesis::Genesis;
use crate::header::FinalizedHeader;
use crate::scheme::MultisigScheme;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::{Hasher, Sha256, ed25519};
use commonware_formatting::from_hex;
use commonware_formatting::hex;
use commonware_parallel::Sequential;
use commonware_utils::ordered::BiMap;
use commonware_utils::{TryCollect, sys_rng};
use ssz::{Decode, Encode as SszEncode};
use std::collections::BTreeMap;
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
    /// The decoded checkpoint state's consensus position (height, epoch, or head
    /// digest) is not bound to the verified terminal finalized header. The
    /// checkpoint is created at the penultimate block of an epoch, so a valid
    /// checkpoint's `latest_height` is exactly one below the terminal (last-block)
    /// header, its `head_digest` is that header's parent, and its epoch matches.
    CheckpointStatePositionMismatch(String),
    /// The decoded checkpoint's pending validator-transition queues
    /// (`added_validators` for the next epoch, `removed_validators`) do not match
    /// the validator deltas committed by the verified terminal finalized header.
    CheckpointTransitionQueueMismatch(String),
    /// A checkpoint validator account's BLS consensus key does not match the key
    /// verified for that node. For active validators this is the key accumulated
    /// from genesis and the verified finalized headers (used to check historical
    /// finalization signatures); for next-epoch joining validators it is the
    /// consensus key committed in the terminal header's `added_validators`. A
    /// mismatch means the checkpoint's stored account key — the key that actually
    /// goes live on activation — was never bound to the verified history.
    CheckpointConsensusKeyMismatch(String),
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
            Self::CheckpointStatePositionMismatch(reason) => {
                write!(
                    f,
                    "checkpoint state position not bound to terminal header: {reason}"
                )
            }
            Self::CheckpointTransitionQueueMismatch(reason) => {
                write!(
                    f,
                    "checkpoint transition queues not bound to terminal header: {reason}"
                )
            }
            Self::CheckpointConsensusKeyMismatch(reason) => {
                write!(
                    f,
                    "checkpoint consensus key not bound to terminal header: {reason}"
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
    let genesis_hash: Digest = from_hex(&genesis.eth_genesis_hash)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Digest::from)
        .ok_or_else(|| {
            CheckpointVerificationError::InvalidGenesisHash(genesis.eth_genesis_hash.clone())
        })?;

    // Build initial validator set from genesis
    let validators = genesis
        .get_validators()
        .map_err(|e| CheckpointVerificationError::ValidatorSetError(e.to_string()))?;

    // The finalization certificates were produced over the live consensus
    // domain, which is bound to immutable chain identity. The verifier must
    // reconstruct that same domain (see `chain_domain`) rather than the raw
    // configured namespace, or the aggregate signatures will not verify.
    let namespace = crate::chain_domain(genesis.config_digest()).to_vec();

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

    let mut rng = sys_rng();
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

    // Accumulate the full (node key, BLS consensus key) pairs from the verified
    // signing set. Historical finalization signatures were checked with these
    // BLS keys, so binding each checkpoint account to its accumulated BLS key
    // prevents a checkpoint from keeping a node identity and active status while
    // swapping the consensus key it never signed with.
    let accumulated: BTreeMap<[u8; 32], &<MinPk as Variant>::Public> = signing_set
        .iter()
        .map(|(pk, bls)| {
            let node_bytes: [u8; 32] = pk
                .as_ref()
                .try_into()
                .expect("ed25519 public key should be 32 bytes");
            (node_bytes, bls)
        })
        .collect();

    // Every validator in the accumulated signing set must have an account in the
    // checkpoint, and vice versa for active accounts.
    for (key, accumulated_bls) in &accumulated {
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

                // Bind the account's consensus key to the key used to verify the
                // historical finalization signatures for this node.
                let account_bls: &<MinPk as Variant>::Public =
                    account.consensus_public_key.as_ref();
                if account_bls != *accumulated_bls {
                    return Err(CheckpointVerificationError::CheckpointConsensusKeyMismatch(
                        format!(
                            "validator {key:?} consensus key in checkpoint does not match the key \
                             accumulated from the verified finalized headers"
                        ),
                    ));
                }
            }
        }
    }

    // Reverse check: every active validator in the checkpoint must be in the
    // accumulated signing set.
    for (key, account) in &checkpoint_state.validator_accounts {
        if account.status == ValidatorStatus::Active && !accumulated.contains_key(key) {
            return Err(CheckpointVerificationError::ValidatorSetMismatch(format!(
                "validator {key:?} is active in checkpoint but not in accumulated signing set"
            )));
        }
    }

    // Step 4: Consistency check on the decoded state position.
    //
    // Step 2 already authenticates the exact checkpoint bytes against the signed
    // terminal header, so the decoded fields are not attacker-malleable on this
    // path. What Step 2 cannot guarantee is that those signed bytes are
    // *internally consistent* with the header's own position fields — a buggy (or
    // colluding) checkpoint creator could sign a state whose position does not
    // match the header it is committed under. This step catches that.
    //
    // The checkpoint is created at the penultimate block of an epoch and the
    // terminal header is the last block of that epoch (see finalizer/src/actor.rs),
    // so for a well-formed checkpoint: `latest_height` is one below the terminal
    // header's height, `head_digest` is the terminal header's parent, and the
    // epoch matches. Reject any checkpoint whose decoded position does not.
    let terminal = last_header.header();
    let expected_terminal_height = checkpoint_state.get_latest_height().saturating_add(1);
    if terminal.height() != expected_terminal_height {
        return Err(
            CheckpointVerificationError::CheckpointStatePositionMismatch(format!(
                "decoded latest_height {} implies terminal height {}, but terminal header is at height {}",
                checkpoint_state.get_latest_height(),
                expected_terminal_height,
                terminal.height()
            )),
        );
    }
    if checkpoint_state.get_epoch() != terminal.epoch() {
        return Err(
            CheckpointVerificationError::CheckpointStatePositionMismatch(format!(
                "decoded epoch {} does not match terminal header epoch {}",
                checkpoint_state.get_epoch(),
                terminal.epoch()
            )),
        );
    }
    if checkpoint_state.get_head_digest() != terminal.parent() {
        return Err(
            CheckpointVerificationError::CheckpointStatePositionMismatch(format!(
                "decoded head_digest 0x{} is not the terminal header's parent 0x{}",
                hex(checkpoint_state.get_head_digest().as_ref()),
                hex(terminal.parent().as_ref())
            )),
        );
    }

    // Step 5: The embedded DynamicEpocher must actually cover the decoded
    // position. The epocher drives epoch-boundary classification (which heights
    // are first/penultimate/last of an epoch), so a schedule that does not
    // contain the decoded `epoch`/`latest_height` would make the node
    // misclassify future boundaries. Like Step 4 this is an internal-consistency
    // check the checkpoint-hash binding cannot provide: it authenticates the
    // epocher bytes but not that they agree with the rest of the state.
    let decoded_epoch = checkpoint_state.get_epoch();
    let decoded_height = checkpoint_state.get_latest_height();
    match checkpoint_state
        .get_epocher()
        .epoch_bounds(Epoch::new(decoded_epoch))
    {
        None => {
            return Err(
                CheckpointVerificationError::CheckpointStatePositionMismatch(format!(
                    "embedded epocher does not cover decoded epoch {decoded_epoch}"
                )),
            );
        }
        Some((start, end)) => {
            let (start, end) = (start.get(), end.get());
            if decoded_height < start || decoded_height > end {
                return Err(
                    CheckpointVerificationError::CheckpointStatePositionMismatch(format!(
                        "decoded latest_height {decoded_height} is outside the epocher bounds \
                         [{start}, {end}] for decoded epoch {decoded_epoch}"
                    )),
                );
            }
        }
    }

    // Step 6: Bind the pending validator-transition queues to the terminal
    // header's committed deltas. The last block of an epoch writes the state's
    // next-epoch additions (`get_added_validators(epoch + 1)`) and current
    // removals (`get_removed_validators()`) into its header (see
    // finalizer/src/actor.rs), so an honest checkpoint must reproduce exactly
    // those deltas. Without this an otherwise-verified checkpoint could carry
    // pending add/remove queues that change the next committee after import.
    let next_epoch = checkpoint_state.get_epoch() + 1;

    let mut checkpoint_added = checkpoint_state
        .get_added_validators(next_epoch)
        .cloned()
        .unwrap_or_default();
    let mut header_added = terminal.added_validators().to_vec();
    checkpoint_added.sort_by(|a, b| a.node_key.cmp(&b.node_key));
    header_added.sort_by(|a, b| a.node_key.cmp(&b.node_key));
    if checkpoint_added != header_added {
        return Err(
            CheckpointVerificationError::CheckpointTransitionQueueMismatch(format!(
                "decoded added_validators for epoch {next_epoch} ({} entries) do not match the \
                 terminal header's committed additions ({} entries)",
                checkpoint_added.len(),
                header_added.len(),
            )),
        );
    }

    // Bind each next-epoch joining validator's *account* consensus key to the
    // (now header-authenticated) `added_validators` entry. Epoch activation flips
    // the account's status to Active by node key but never copies the
    // `AddedValidator.consensus_key` onto the account (see finalizer/src/actor.rs),
    // so the account's stored consensus key is what actually goes live. Binding
    // added_validators to the header (above) is therefore not enough on its own: a
    // checkpoint could keep added_validators[next_epoch] matching the header while
    // pointing the corresponding joining account at a different BLS key, which the
    // active-validator consensus-key check (Step 3) does not cover because a
    // joining node is not in the accumulated signing set.
    for added in &header_added {
        let node_bytes: [u8; 32] = added
            .node_key
            .as_ref()
            .try_into()
            .expect("ed25519 public key should be 32 bytes");
        match checkpoint_state.validator_accounts.get(&node_bytes) {
            None => {
                return Err(CheckpointVerificationError::ValidatorSetMismatch(format!(
                    "validator {node_bytes:?} is in the committed added_validators for epoch \
                     {next_epoch} but has no account in the checkpoint"
                )));
            }
            Some(account) => {
                if account.consensus_public_key != added.consensus_key {
                    return Err(CheckpointVerificationError::CheckpointConsensusKeyMismatch(
                        format!(
                            "joining validator {node_bytes:?} account consensus key does not match \
                             the key committed in added_validators for epoch {next_epoch}"
                        ),
                    ));
                }
            }
        }
    }

    let mut checkpoint_removed = checkpoint_state.get_removed_validators().clone();
    let mut header_removed = terminal.removed_validators();
    checkpoint_removed.sort();
    header_removed.sort();
    if checkpoint_removed != header_removed {
        return Err(
            CheckpointVerificationError::CheckpointTransitionQueueMismatch(format!(
                "decoded removed_validators ({} entries) do not match the terminal header's \
                 committed removals ({} entries)",
                checkpoint_removed.len(),
                header_removed.len(),
            )),
        );
    }

    // NOTE: only the `next_epoch` (N+1) additions are bound here, because that
    // is all the terminal boundary header commits. Under the default
    // VALIDATOR_NUM_WARM_UP_EPOCHS = 2, an honest checkpoint at epoch N also
    // carries added_validators[N+2] (deposits processed during epoch N), and
    // possibly later buckets if the warm-up grows — these are NOT authenticated
    // by any header available to the verifier (the header committing N+2 is
    // epoch N+1's boundary, which postdates this chain). They therefore remain
    // *trusted* checkpoint contents and are explicitly outside the scope of
    // #216. Fully binding them requires committing the entire added_validators
    // map into the terminal header / SSZ state root (see #257/#258); a
    // checkpoint-bootstrapped node's view of committees >= N+2 is attacker-
    // influenceable until the corresponding boundary header is later verified.

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::account::{ValidatorAccount, ValidatorStatus};
    use crate::checkpoint::Checkpoint;
    use crate::consensus_state::ConsensusState;
    use crate::dynamic_epocher::DynamicEpocher;
    use crate::genesis::Genesis;
    use crate::header::FinalizedHeader;
    use crate::scheme::MultisigScheme;
    use crate::ssz_state_tree::SszStateTree;
    use crate::withdrawal::{WithdrawalKind, WithdrawalQueue};
    use alloy_primitives::Address;
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Signer, bls12381, ed25519, sha256};
    use ssz::{Decode, Encode};
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroU64;
    use std::sync::Arc;

    fn parse_public_key(public_key: &str) -> ed25519::PublicKey {
        ed25519::PublicKey::decode(
            commonware_formatting::from_hex(public_key)
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            epoch: 5,
            kind: WithdrawalKind::Validator,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

            status: ValidatorStatus::Active,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(2);
        let validator_account2 = ValidatorAccount {
            consensus_public_key: consensus_key2.public_key(),
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000, // 16 ETH

            status: ValidatorStatus::SubmittedExitRequest,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            epoch: 5,
            kind: WithdrawalKind::Validator,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

            status: ValidatorStatus::Active,
            joining_epoch: 0,
            last_deposit_index: 100,
        };

        let consensus_key2 = bls12381::PrivateKey::from_seed(2);
        let validator_account2 = ValidatorAccount {
            consensus_public_key: consensus_key2.public_key(),
            withdrawal_credentials: Address::from([8u8; 20]),
            balance: 16_000_000_000, // 16 ETH

            status: ValidatorStatus::SubmittedExitRequest,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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
            epoch: 5,
            kind: WithdrawalKind::Validator,
        };

        let consensus_key1 = bls12381::PrivateKey::from_seed(1);
        let validator_account1 = ValidatorAccount {
            consensus_public_key: consensus_key1.public_key(),
            withdrawal_credentials: Address::from([7u8; 20]),
            balance: 32_000_000_000, // 32 ETH

            status: ValidatorStatus::Active,
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
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO,
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 3,
            pending_active_validator_exits: 0,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
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

    // Builds a single-epoch checkpoint plus a terminal finalized header whose
    // certificate genuinely signs the header digest and whose `checkpoint_hash`
    // commits to that checkpoint. `apply` mutates the decoded state before the
    // checkpoint is sealed, so a test can introduce a position inconsistency that
    // is nonetheless validly committed by the terminal header; `header_height`
    // sets the terminal header's height.
    fn build_checkpoint_and_header(
        apply: impl FnOnce(&mut ConsensusState),
        header_height: u64,
    ) -> (Genesis, Checkpoint, FinalizedHeader<MultisigScheme>) {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::genesis::GenesisValidator;
        use crate::header::Header;
        use commonware_codec::Encode as _;
        use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::bls12381::primitives::group;
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
        use commonware_formatting::hex;
        use commonware_parallel::Sequential;
        use commonware_utils::TryCollect;
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
            blocks_per_epoch: 10,
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO.to_string(),
            max_deposits_per_epoch: 3,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
            minimum_validator_count: 1,
            invalid_deposit_tax: 0,
            max_pending_withdrawals_per_validator: 3,
        };

        let mut state = ConsensusState::new(
            Default::default(),
            32_000_000_000,
            NonZeroU64::new(10).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            1,
            0,
            3,
        );
        state.set_validator_accounts(validator_accounts);
        // Let the test introduce any decoded-state inconsistency before the
        // checkpoint is sealed; the header below still commits to the result.
        apply(&mut state);
        let checkpoint = Checkpoint::new(&state);

        // Mirror the finalizer's last-block header: it commits the state's
        // next-epoch additions (`get_added_validators(epoch + 1)`). Deriving this
        // from the (possibly mutated) state lets a test stage a next-epoch joining
        // validator whose committed delta matches the header while diverging the
        // stored account key. `removed_validators` stays empty here so the
        // transition-queue test can diverge it via the decoded state alone.
        let header_added = state
            .get_added_validators(state.get_epoch() + 1)
            .cloned()
            .unwrap_or_default();

        // Honest header commits to the (possibly mutated) checkpoint.
        let header = Header::new(
            [0u8; 32].into(),
            header_height,
            0,
            0,
            0,
            [1u8; 32].into(),
            [2u8; 32].into(),
            checkpoint.digest,
            [0u8; 32].into(),
            header_added,
            Vec::new(),
            [0u8; 32],
        );

        participants.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        let signers: BiMap<ed25519::PublicKey, <MinPk as Variant>::Public> =
            participants.into_iter().try_collect().unwrap();
        // Certificates must be signed over the same chain-bound consensus domain
        // that `verify_checkpoint_chain` reconstructs, not the raw namespace.
        let signing_domain = crate::chain_domain(genesis.config_digest());
        let schemes: Vec<_> = group_privates
            .into_iter()
            .filter_map(|private| {
                MultisigScheme::signer(signing_domain.as_slice(), signers.clone(), private)
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

        (genesis, checkpoint, finalized_header)
    }

    // Convenience wrapper over `build_checkpoint_and_header`: a checkpoint whose
    // decoded state sits at `state_latest_height`, a terminal header at
    // `terminal_header_height`, and a *distinct* ("attacker-controlled")
    // checkpoint at latest_height 1. An honest checkpoint sets
    // `terminal_header_height == state_latest_height + 1` (checkpoint at the
    // penultimate block, terminal header at the last block).
    fn checkpoint_verification_fixture(
        state_latest_height: u64,
        terminal_header_height: u64,
    ) -> (
        Genesis,
        Checkpoint,
        Checkpoint,
        FinalizedHeader<MultisigScheme>,
    ) {
        let (genesis, checkpoint, finalized_header) = build_checkpoint_and_header(
            |s| s.set_latest_height(state_latest_height),
            terminal_header_height,
        );
        let (_, tampered_checkpoint, _) =
            build_checkpoint_and_header(|s| s.set_latest_height(1), terminal_header_height);
        assert_ne!(checkpoint.digest, tampered_checkpoint.digest);
        (genesis, checkpoint, tampered_checkpoint, finalized_header)
    }

    // Binds the decoded checkpoint state position to the verified terminal header.
    // The terminal header authenticates the checkpoint *bytes* (sha256), but
    // without this check the decoded `ConsensusState` could advertise a consensus
    // position (height/epoch/head_digest) that does not correspond to the verified
    // header chain, letting a node start from the wrong position. The checkpoint is
    // taken at the penultimate block, so an honest checkpoint's `latest_height` is
    // exactly one below the terminal (last-block) header.
    #[test]
    fn test_checkpoint_verifier_binds_state_position_to_terminal_header() {
        // Honest: decoded state at penultimate height 5, terminal header at 6.
        let (genesis, checkpoint, _tampered, honest) = checkpoint_verification_fixture(5, 6);
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("a position-consistent checkpoint must verify");

        // Inconsistent: same decoded state (latest_height 5) but the terminal header
        // claims height 9, so latest_height + 1 (6) != 9. The bytes are still validly
        // committed by the terminal header and the validator set checks out, yet the
        // position binding must reject it.
        let (genesis, checkpoint, _tampered, mismatched) = checkpoint_verification_fixture(5, 9);
        let result = super::verify_checkpoint_chain(
            &genesis,
            std::slice::from_ref(&mismatched),
            &checkpoint,
        );
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointStatePositionMismatch(_))
            ),
            "verifier must reject a checkpoint whose decoded state position is not bound \
             to the terminal finalized header, got {result:?}"
        );
    }

    // #215: the verifier must reject a checkpoint whose decoded position or epoch
    // schedule is inconsistent with the verified terminal header — across every
    // position field, not just latest_height. Each case pairs a validly committed
    // (sha256-bound), validly certified terminal header with a decoded state that
    // disagrees on one field.
    #[test]
    fn test_checkpoint_verifier_rejects_inconsistent_decoded_position() {
        use super::CheckpointVerificationError::CheckpointStatePositionMismatch;

        // Decoded epoch disagrees with the terminal header epoch (0).
        let (genesis, checkpoint, header) = build_checkpoint_and_header(
            |s| {
                s.set_latest_height(5);
                s.set_epoch(1);
            },
            6,
        );
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&header), &checkpoint);
        assert!(
            matches!(result, Err(CheckpointStatePositionMismatch(_))),
            "decoded epoch mismatch must be rejected, got {result:?}"
        );

        // Decoded head_digest is not the terminal header's parent ([0u8; 32]).
        let (genesis, checkpoint, header) = build_checkpoint_and_header(
            |s| {
                s.set_latest_height(5);
                s.set_head_digest([9u8; 32].into());
            },
            6,
        );
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&header), &checkpoint);
        assert!(
            matches!(result, Err(CheckpointStatePositionMismatch(_))),
            "decoded head_digest mismatch must be rejected, got {result:?}"
        );

        // Decoded latest_height (50) lies outside the embedded epocher's bounds
        // for the decoded epoch (epoch 0 of a 10-block schedule), so the epocher
        // does not cover the position. The terminal header at 51 keeps the
        // latest_height/terminal-height check satisfied so the epocher coverage
        // check (Step 5) is what fires.
        let (genesis, checkpoint, _t, header) = checkpoint_verification_fixture(50, 51);
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&header), &checkpoint);
        assert!(
            matches!(result, Err(CheckpointStatePositionMismatch(_))),
            "decoded position outside the epocher bounds must be rejected, got {result:?}"
        );
    }

    // #215: fields with no independent representation in the terminal header
    // (forkchoice, epoch_genesis_hash, the epocher segments) cannot be bound to
    // header fields — they are protected solely by the checkpoint-hash binding.
    // Mutating forkchoice changes the checkpoint bytes, so the honest terminal
    // header no longer commits them and verification fails at the hash check.
    #[test]
    fn test_checkpoint_verifier_rejects_forkchoice_mutation_via_hash_binding() {
        // Honest checkpoint + terminal header at the matching penultimate position.
        let (genesis, _honest_ckpt, header) =
            build_checkpoint_and_header(|s| s.set_latest_height(5), 6);
        // A checkpoint at the same position but with a different forkchoice — same
        // height/epoch/head_digest, different bytes, hence a different digest.
        let (_g, forkchoice_mutated, _h) = build_checkpoint_and_header(
            |s| {
                s.set_latest_height(5);
                s.set_forkchoice_head(alloy_primitives::B256::repeat_byte(7));
            },
            6,
        );
        let result = super::verify_checkpoint_chain(
            &genesis,
            std::slice::from_ref(&header),
            &forkchoice_mutated,
        );
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointHashMismatch)
            ),
            "a forkchoice-mutated checkpoint must fail the hash binding, got {result:?}"
        );
    }

    // Binds the decoded checkpoint's pending validator-transition queues to the
    // terminal header's committed deltas. The terminal header authenticates the
    // checkpoint bytes (sha256) and active membership, but without this an
    // attacker whose terminal header signs the checkpoint can ship pending
    // add/remove queues that diverge from the header's committed deltas, changing
    // the next committee after import.
    #[test]
    fn test_checkpoint_verifier_binds_transition_queues_to_terminal_header() {
        // Honest: empty queues, and the terminal header commits empty deltas.
        let (genesis, checkpoint, honest) =
            build_checkpoint_and_header(|s| s.set_latest_height(5), 6);
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("a checkpoint whose queues match the terminal header must verify");

        // Divergent: the decoded checkpoint carries a pending removed-validator
        // queue, but the terminal header commits an empty removed set. The bytes
        // are still validly committed (so the hash and membership checks pass),
        // yet the transition-queue binding must reject it.
        let rogue = ed25519::PrivateKey::from_seed(99).public_key();
        let (genesis, checkpoint, mismatched) = build_checkpoint_and_header(
            |s| {
                s.set_latest_height(5);
                s.set_removed_validators(vec![rogue]);
            },
            6,
        );
        let result = super::verify_checkpoint_chain(
            &genesis,
            std::slice::from_ref(&mismatched),
            &checkpoint,
        );
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointTransitionQueueMismatch(_))
            ),
            "verifier must reject a checkpoint whose pending transition queues are not bound \
             to the terminal finalized header's committed deltas, got {result:?}"
        );
    }

    // Binds each checkpoint account's BLS consensus key to the key accumulated for
    // that node from genesis and the verified finalized headers. The verifier
    // checks finalization signatures with the full (node, BLS) pairs but
    // historically reduced the state-consistency check to node keys, so a
    // checkpoint could keep node identities and active statuses while swapping
    // consensus keys, corrupting the participant set derived after import.
    #[test]
    fn test_checkpoint_verifier_binds_consensus_keys_to_terminal_header() {
        // Honest: account consensus keys match the accumulated participant set.
        let (genesis, checkpoint, honest) =
            build_checkpoint_and_header(|s| s.set_latest_height(5), 6);
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("a checkpoint whose consensus keys match the verified set must verify");

        // Divergent: one active validator account keeps its node key and status but
        // carries a BLS consensus key it never signed with. The genesis entry and
        // signing set are built before `apply`, so they keep the real key while
        // only the stored account key is swapped. The bytes are still validly
        // committed and node-key membership checks out, yet the consensus-key
        // binding must reject it.
        let (genesis, checkpoint, tampered_keys) = build_checkpoint_and_header(
            |s| {
                s.set_latest_height(5);
                let node0: [u8; 32] = ed25519::PrivateKey::from_seed(0)
                    .public_key()
                    .as_ref()
                    .try_into()
                    .unwrap();
                s.validator_accounts
                    .get_mut(&node0)
                    .expect("validator 0 exists in the fixture")
                    .consensus_public_key = bls12381::PrivateKey::from_seed(900).public_key();
            },
            6,
        );
        let result = super::verify_checkpoint_chain(
            &genesis,
            std::slice::from_ref(&tampered_keys),
            &checkpoint,
        );
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointConsensusKeyMismatch(_))
            ),
            "verifier must reject a checkpoint whose account consensus key is not bound to the \
             key accumulated from the verified finalized headers, got {result:?}"
        );
    }

    // Binds a next-epoch *joining* validator's stored account consensus key to the
    // consensus key committed in the terminal header's `added_validators`. #216
    // binds the added_validators queue entry to the header, but epoch activation
    // flips the account to Active by node key without copying the added entry's
    // consensus key onto the account — so the account key is what goes live. A
    // joining node is not in the accumulated signing set, so the active-validator
    // check does not cover it. Without this a checkpoint could keep
    // added_validators[next_epoch] matching the header while pointing the joining
    // account at a different BLS key.
    #[test]
    fn test_checkpoint_verifier_binds_joining_account_consensus_key() {
        use crate::account::{ValidatorAccount, ValidatorStatus};
        use crate::header::AddedValidator;

        // Stages a next-epoch joining validator (a node not in the genesis signing
        // set) whose account consensus key and committed added_validators entry
        // both carry `account_bls`, while the added entry always carries
        // `added_bls`. The fixture's terminal header commits
        // `get_added_validators(next_epoch)`, so the queue entry is header-bound.
        let stage_joining = |account_bls: bls12381::PublicKey,
                             added_bls: bls12381::PublicKey|
         -> Box<dyn FnOnce(&mut ConsensusState)> {
            Box::new(move |s: &mut ConsensusState| {
                s.set_latest_height(5);
                let node = ed25519::PrivateKey::from_seed(50).public_key();
                let node_bytes: [u8; 32] = node.as_ref().try_into().unwrap();
                s.set_account(
                    node_bytes,
                    ValidatorAccount {
                        consensus_public_key: account_bls,
                        withdrawal_credentials: Address::from([50u8; 20]),
                        balance: 32_000_000_000,
                        status: ValidatorStatus::Joining,
                        joining_epoch: 1,
                        last_deposit_index: 0,
                    },
                );
                // next_epoch = decoded epoch (0) + 1.
                s.add_validator(
                    1,
                    AddedValidator {
                        node_key: node,
                        consensus_key: added_bls,
                    },
                );
            })
        };

        let real_bls = bls12381::PrivateKey::from_seed(500).public_key();
        let attacker_bls = bls12381::PrivateKey::from_seed(900).public_key();

        // Honest: the joining account key matches its committed added entry.
        let (genesis, checkpoint, honest) =
            build_checkpoint_and_header(stage_joining(real_bls.clone(), real_bls.clone()), 6);
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("a joining account whose key matches the committed added entry must verify");

        // Divergent: added_validators[next_epoch] still commits `real_bls` (so it
        // matches the header and passes the #216 queue binding), but the joining
        // account stores `attacker_bls` — the key that would go live on activation.
        let (genesis, checkpoint, tampered) =
            build_checkpoint_and_header(stage_joining(attacker_bls, real_bls), 6);
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&tampered), &checkpoint);
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointConsensusKeyMismatch(_))
            ),
            "verifier must reject a checkpoint whose joining account consensus key diverges from \
             the header-committed added_validators entry, got {result:?}"
        );
    }

    // Closes the typed-API trust-boundary gap: a finalized header carries header
    // fields (e.g. `checkpoint_hash`) and a certificate that signs a digest. The
    // fields must be bound to the signed digest, otherwise an attacker can pair a
    // genuine certificate (signing the honest digest) with header fields that
    // point at attacker-controlled checkpoint data.
    #[test]
    fn test_checkpoint_verifier_rejects_typed_header_field_mutation() {
        use crate::header::{FinalizedHeader, FinalizedHeaderError, Header};

        let (genesis, checkpoint, tampered_checkpoint, honest) =
            checkpoint_verification_fixture(0, 1);

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

    // Regression for raw header-epoch replay: the header digest commits to the
    // `epoch` field (it hashes the full SSZ encoding), so reusing a genuine
    // certificate under a header whose decoded epoch was mutated must fail the
    // payload-digest binding. Without epoch in the digest, the unsigned decoded
    // epoch could be replayed into a different slot while the certificate stayed
    // valid.
    #[test]
    fn test_checkpoint_verifier_rejects_header_epoch_mutation() {
        use crate::header::{FinalizedHeader, FinalizedHeaderError, Header};

        let (genesis, checkpoint, _tampered_checkpoint, honest) =
            checkpoint_verification_fixture(0, 1);

        // Sanity: the honest finalized header verifies against the honest checkpoint.
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("fixture checkpoint should verify before tampering");

        // Build a header identical to the honest one EXCEPT `epoch`, which is
        // bumped to a different slot. Reuse the ORIGINAL finalization: its
        // certificate still signs the honest header digest, so the BLS signature
        // remains valid — only the unsigned-looking decoded epoch was mutated.
        let h = honest.header().clone();
        let tampered_header = Header::new(
            h.parent(),
            h.height(),
            h.timestamp(),
            h.epoch() + 1, // <-- mutated away from the signed epoch
            h.view(),
            h.payload_hash(),
            h.execution_request_hash(),
            h.checkpoint_hash(),
            h.prev_epoch_header_hash(),
            h.added_validators().to_vec(),
            h.removed_validators(),
            h.parent_beacon_block_root(),
        );

        // (1) The digest commits to epoch, so the safe constructor rejects the
        // mutated-epoch header against the original certificate payload outright.
        // This holds independently of the verifier's epoch-contiguity check.
        let err = FinalizedHeader::new(
            tampered_header.clone(),
            honest.finalization().clone(),
            honest.participant_count(),
        )
        .expect_err("FinalizedHeader::new must reject a mutated-epoch header/payload");
        assert_eq!(err, FinalizedHeaderError::PayloadDigestMismatch);

        // (2) Even if a caller bypasses the safe constructor, the verifier
        // re-derives the digest from the header's fields (including epoch) and
        // rejects the replay before applying any validator deltas.
        let smuggled = FinalizedHeader::new_unchecked(
            tampered_header,
            honest.finalization().clone(),
            honest.participant_count(),
        );
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&smuggled), &checkpoint);
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::PayloadDigestMismatch { epoch: 0 })
            ),
            "verifier must reject a finalized header whose epoch was mutated away \
             from the signed certificate payload, got {result:?}"
        );
    }

    // A malicious checkpoint carries an extra attacker-controlled
    // validator account with status Joining, while the active signing set still
    // matches the finalized-header chain. The verifier's reverse membership check
    // only rejects extra *Active* accounts (extra Joining accounts are legitimate
    // for pending joiners), so the membership check alone would let it through.
    // It is instead caught by the Step 2 checkpoint-hash binding: injecting the
    // account changes the checkpoint digest, which no longer matches the
    // checkpoint_hash the honest terminal header committed to. An attacker cannot
    // append a Joining account to a checkpoint and still pair it with the genuine
    // finalized-header chain.
    #[test]
    fn test_checkpoint_verifier_rejects_extra_joining_account() {
        use crate::account::{ValidatorAccount, ValidatorStatus};

        let (genesis, checkpoint, _tampered, honest) = checkpoint_verification_fixture(0, 1);

        // Sanity: the honest checkpoint verifies against the honest finalized header.
        super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &checkpoint)
            .expect("fixture checkpoint should verify before tampering");

        // Inject an extra Joining account into the decoded state, leaving the
        // active signing set untouched.
        let mut state =
            ConsensusState::try_from(&checkpoint).expect("honest checkpoint state should decode");
        let rogue_node = ed25519::PrivateKey::from_seed(99).public_key();
        let rogue_node_bytes: [u8; 32] = rogue_node
            .as_ref()
            .try_into()
            .expect("ed25519 public key is 32 bytes");
        let rogue_account = ValidatorAccount {
            consensus_public_key: bls12381::PrivateKey::from_seed(999).public_key(),
            withdrawal_credentials: Address::from([99u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Joining,
            joining_epoch: 5,
            last_deposit_index: 0,
        };
        state.set_account(rogue_node_bytes, rogue_account);

        // Re-encoding the tampered state changes the checkpoint digest, so it no
        // longer matches the honest terminal header's committed checkpoint_hash.
        let tampered = Checkpoint::new(&state);
        let result =
            super::verify_checkpoint_chain(&genesis, std::slice::from_ref(&honest), &tampered);
        assert!(
            matches!(
                result,
                Err(super::CheckpointVerificationError::CheckpointHashMismatch)
            ),
            "verifier must reject a checkpoint carrying an extra Joining account not \
             committed by the terminal finalized header, got {result:?}"
        );
    }

    // Checkpoint data encodes the state before set_pending_checkpoint runs
    // (nested pending checkpoints are rejected at decode), so a restore has to
    // repopulate the field from the outer checkpoint and re-capture the root
    // to land in the exact state a live peer had at the penultimate block.
    // This pins the mechanism the restore path relies on: a decode-rebuilt SSZ
    // tree plus the pending digest leaf plus a capture equals the live,
    // incrementally built tree. The live root here is what the epoch terminal
    // block commits as parent_beacon_block_root.
    #[test]
    fn restored_state_with_repopulated_pending_checkpoint_matches_live() {
        let mut live = ConsensusState::new(
            Default::default(),
            32_000_000_000,
            NonZeroU64::new(10).unwrap(),
            10_000,
            Address::ZERO,
            3,
            16,
            0,
            1,
            0,
            3,
        );
        let node_key: [u8; 32] = ed25519::PrivateKey::from_seed(42)
            .public_key()
            .as_ref()
            .try_into()
            .expect("ed25519 public key is 32 bytes");
        live.set_account(
            node_key,
            ValidatorAccount {
                consensus_public_key: bls12381::PrivateKey::from_seed(42).public_key(),
                withdrawal_credentials: Address::from([3u8; 20]),
                balance: 32_000_000_000,
                status: ValidatorStatus::Active,
                joining_epoch: 0,
                last_deposit_index: 0,
            },
        );
        live.rebuild_ssz_tree();

        // The finalizer's penultimate-block flow: create the checkpoint, set
        // it as pending, then capture the root the terminal block commits.
        let checkpoint = Checkpoint::new(&live);
        live.set_pending_checkpoint(Some(checkpoint.clone()));
        live.capture_state_root(live.get_latest_height());

        // Without repopulation the restored root is missing the pending
        // checkpoint digest leaf and cannot match the live root. If this ever
        // becomes equal, the assertions below pin nothing.
        let mut restored = ConsensusState::try_from(&checkpoint).expect("checkpoint must decode");
        assert_ne!(
            restored.get_state_root(),
            live.get_state_root(),
            "a restore without repopulation must diverge from the live root"
        );

        restored.set_pending_checkpoint(Some(checkpoint.clone()));
        restored.capture_state_root(restored.get_latest_height());

        assert_eq!(
            restored.get_pending_checkpoint().map(|cp| cp.digest),
            Some(checkpoint.digest),
            "repopulation must install the restored checkpoint as pending"
        );
        assert_eq!(
            restored.get_state_root(),
            live.get_state_root(),
            "a repopulated restore must reproduce the live penultimate state root"
        );
    }
}
