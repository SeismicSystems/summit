use std::fmt;
use std::sync::OnceLock;

use crate::PublicKey;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::bls12381;
use commonware_cryptography::certificate::Scheme;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use ssz::Encode as _;
use ssz_derive::{Decode, Encode};

/// Represents a validator being added to the committee.
/// Contains both the node identity key (ed25519) and consensus signing key (BLS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddedValidator {
    /// The node's identity public key (ed25519)
    pub node_key: PublicKey,
    /// The validator's consensus signing key (BLS12-381)
    pub consensus_key: bls12381::PublicKey,
}

/// Hardfork boundary exception (July 2026 migration).
///
/// The header digest formula changed across the hardfork: the pre-fork client
/// hashed a manual concatenation of selected fields (including the
/// since-removed `block_value`), while this client hashes the header's full
/// encoding. The migration checkpoint's terminal header was finalized under
/// the old formula, so its certificate signs the old digest — a value the new
/// formula can never reproduce. [`Header::computed_digest`] therefore maps the
/// new-formula hash of that one header's exact bytes back to its pre-fork
/// digest, keeping the original finalization certificate bound to the header
/// and preserving the block's identity (parent links, archive keys) across
/// the fork.
///
/// The exception can only fire for the genuine boundary header: any change to
/// any header field changes the new-formula hash and misses the constant.
/// Both values are produced by the `write_new_checkpoint` migration test.
pub const FORK_BOUNDARY_NEW_FORMULA_DIGEST: Digest = Digest([
    183, 116, 193, 78, 120, 225, 247, 146, 142, 165, 143, 27, 163, 249, 67, 120, 97, 53, 99, 66,
    49, 84, 189, 254, 224, 79, 173, 59, 156, 76, 231, 93,
]);

/// The boundary header's pre-fork digest — what its finalization certificate
/// actually signed. See [`FORK_BOUNDARY_NEW_FORMULA_DIGEST`].
pub const FORK_BOUNDARY_OLD_DIGEST: Digest = Digest([
    38, 11, 201, 49, 65, 121, 11, 86, 225, 26, 85, 222, 140, 250, 75, 71, 23, 106, 223, 190, 10,
    55, 133, 108, 177, 108, 64, 201, 208, 133, 64, 83,
]);

#[derive(Clone, Debug, Encode, Decode)]
pub struct Header {
    parent: SszDigest,
    height: u64,
    timestamp: u64,
    epoch: u64,
    view: u64,
    payload_hash: SszDigest,
    execution_request_hash: SszDigest,
    checkpoint_hash: SszDigest,
    prev_epoch_header_hash: SszDigest,
    added_validators: Vec<AddedValidator>,
    removed_validators: Vec<SszPublicKey>,
    parent_beacon_block_root: [u8; 32],
    // precomputed digest of this header
    #[ssz(skip_serializing, skip_deserializing)]
    digest: OnceLock<Digest>,
}

impl Header {
    pub fn parent(&self) -> Digest {
        self.parent.inner
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn view(&self) -> u64 {
        self.view
    }

    pub fn payload_hash(&self) -> Digest {
        self.payload_hash.inner
    }

    pub fn execution_request_hash(&self) -> Digest {
        self.execution_request_hash.inner
    }

    pub fn checkpoint_hash(&self) -> Digest {
        self.checkpoint_hash.inner
    }

    pub fn prev_epoch_header_hash(&self) -> Digest {
        self.prev_epoch_header_hash.inner
    }

    pub fn added_validators(&self) -> &[AddedValidator] {
        &self.added_validators
    }

    pub fn removed_validators(&self) -> Vec<PublicKey> {
        self.removed_validators
            .iter()
            .map(|w| w.inner.clone())
            .collect()
    }

    pub fn parent_beacon_block_root(&self) -> [u8; 32] {
        self.parent_beacon_block_root
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: Digest,
        height: u64,
        timestamp: u64,
        epoch: u64,
        view: u64,
        payload_hash: Digest,
        execution_request_hash: Digest,
        checkpoint_hash: Digest,
        prev_epoch_header_hash: Digest,
        added_validators: Vec<AddedValidator>,
        removed_validators: Vec<PublicKey>,
        parent_beacon_block_root: [u8; 32],
    ) -> Self {
        Self {
            parent: parent.into(),
            height,
            timestamp,
            epoch,
            view,
            payload_hash: payload_hash.into(),
            execution_request_hash: execution_request_hash.into(),
            checkpoint_hash: checkpoint_hash.into(),
            prev_epoch_header_hash: prev_epoch_header_hash.into(),
            added_validators,
            removed_validators: removed_validators.into_iter().map(|x| x.into()).collect(),
            parent_beacon_block_root,
            digest: OnceLock::new(),
        }
    }

    /// Builds a header with an externally-supplied digest instead of deriving it
    /// from the canonical encoding. This is intentionally `pub(crate)` and exists
    /// only for `Block::genesis`, which uses the eth genesis hash as the block
    /// identity rather than `SHA256(ssz(header))`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_digest(
        parent: Digest,
        height: u64,
        timestamp: u64,
        epoch: u64,
        view: u64,
        payload_hash: Digest,
        execution_request_hash: Digest,
        checkpoint_hash: Digest,
        prev_epoch_header_hash: Digest,
        added_validators: Vec<AddedValidator>,
        removed_validators: Vec<PublicKey>,
        parent_beacon_block_root: [u8; 32],
        digest: Digest,
    ) -> Self {
        Self {
            parent: parent.into(),
            height,
            timestamp,
            epoch,
            view,
            payload_hash: payload_hash.into(),
            execution_request_hash: execution_request_hash.into(),
            checkpoint_hash: checkpoint_hash.into(),
            prev_epoch_header_hash: prev_epoch_header_hash.into(),
            added_validators,
            removed_validators: removed_validators.into_iter().map(|x| x.into()).collect(),
            parent_beacon_block_root,
            digest: OnceLock::from(digest),
        }
    }

    /// Returns the (cached) digest of this header.
    ///
    /// The value is memoized in `self.digest`, and may have been *seeded* via
    /// [`Header::new_with_digest`] (genesis seeds it with the genesis hash,
    /// which is intentionally not the hash of the fields). This is correct for
    /// block identity, but it means the cached value cannot be trusted to
    /// reflect the current fields. Trust boundaries that authenticate a header
    /// against a signed payload must use [`Header::computed_digest`] instead.
    pub fn get_digest(&self) -> Digest {
        *self.digest.get_or_init(|| self.computed_digest())
    }

    /// Recomputes the digest directly from the header's current fields,
    /// ignoring any cached or seeded value.
    ///
    /// Use this (not [`Header::get_digest`]) when authenticating a header
    /// against a signed certificate payload: it answers whether these fields
    /// actually hash to the signed digest, and cannot be defeated by a header
    /// constructed with a mismatched seed via [`Header::new_with_digest`].
    pub fn computed_digest(&self) -> Digest {
        let bytes = self.encode();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        // Hardfork exception: the migration boundary header keeps its pre-fork
        // identity so its original finalization certificate stays bound to it.
        // See [`FORK_BOUNDARY_NEW_FORMULA_DIGEST`].
        if digest == FORK_BOUNDARY_NEW_FORMULA_DIGEST {
            return FORK_BOUNDARY_OLD_DIGEST;
        }
        digest
    }
}

// `digest` is a memoized value fully determined by the other fields, and may be
// warm or cold depending on whether `get_digest` has been called (a decoded
// header starts cold). It must not affect equality, so compare every field
// except the cache. This cannot be `#[derive]`d because the derive would
// include the `OnceLock` cache state.
impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
            && self.epoch == other.epoch
            && self.view == other.view
            && self.payload_hash == other.payload_hash
            && self.execution_request_hash == other.execution_request_hash
            && self.checkpoint_hash == other.checkpoint_hash
            && self.prev_epoch_header_hash == other.prev_epoch_header_hash
            && self.added_validators == other.added_validators
            && self.removed_validators == other.removed_validators
            && self.parent_beacon_block_root == other.parent_beacon_block_root
    }
}

impl Eq for Header {}

// Size of AddedValidator in SSZ: 32 bytes (node_key) + 48 bytes (BLS consensus_key) = 80 bytes
const ADDED_VALIDATOR_SSZ_SIZE: usize = 32 + 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SszDigest {
    inner: Digest,
}

impl ssz::Encode for SszDigest {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        Digest::SIZE
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.inner.0);
    }

    fn ssz_bytes_len(&self) -> usize {
        Digest::SIZE
    }
}

impl ssz::Decode for SszDigest {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        Digest::SIZE
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() != Digest::SIZE {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: Digest::SIZE,
            });
        }
        let digest: [u8; Digest::SIZE] = bytes[0..Digest::SIZE]
            .try_into()
            .expect("size is checked above");
        Ok(Self {
            inner: Digest(digest),
        })
    }
}

impl From<Digest> for SszDigest {
    fn from(value: Digest) -> Self {
        SszDigest { inner: value }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SszPublicKey {
    inner: PublicKey,
}

impl ssz::Encode for SszPublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        PublicKey::SIZE
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.inner.as_ref());
    }

    fn ssz_bytes_len(&self) -> usize {
        PublicKey::SIZE
    }
}

impl ssz::Decode for SszPublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        PublicKey::SIZE
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() != PublicKey::SIZE {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: PublicKey::SIZE,
            });
        }
        use commonware_codec::DecodeExt as _;
        let inner = PublicKey::decode(bytes)
            .map_err(|_| ssz::DecodeError::BytesInvalid("invalid PublicKey bytes".to_string()))?;
        Ok(Self { inner })
    }
}

impl From<PublicKey> for SszPublicKey {
    fn from(value: PublicKey) -> Self {
        SszPublicKey { inner: value }
    }
}

impl From<SszPublicKey> for PublicKey {
    fn from(value: SszPublicKey) -> Self {
        value.inner
    }
}

impl ssz::Encode for AddedValidator {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        ADDED_VALIDATOR_SSZ_SIZE
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.node_key.as_ref());
        buf.extend_from_slice(self.consensus_key.as_ref());
    }

    fn ssz_bytes_len(&self) -> usize {
        ADDED_VALIDATOR_SSZ_SIZE
    }
}

impl ssz::Decode for AddedValidator {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        ADDED_VALIDATOR_SSZ_SIZE
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() != ADDED_VALIDATOR_SSZ_SIZE {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: ADDED_VALIDATOR_SSZ_SIZE,
            });
        }
        use commonware_codec::DecodeExt as _;
        let node_key = PublicKey::decode(&bytes[..PublicKey::SIZE])
            .map_err(|_| ssz::DecodeError::BytesInvalid("invalid node_key bytes".to_string()))?;
        let consensus_key =
            bls12381::PublicKey::decode(&bytes[PublicKey::SIZE..]).map_err(|_| {
                ssz::DecodeError::BytesInvalid("invalid consensus_key bytes".to_string())
            })?;
        Ok(AddedValidator {
            node_key,
            consensus_key,
        })
    }
}

impl EncodeSize for Header {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET
    }
}

impl Write for Header {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

impl Read for Header {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len: u32 = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)?;
        if len as usize > buf.remaining() {
            return Err(Error::Invalid("Header", "improper encoded length"));
        }

        let mut payload = vec![0u8; len as usize];
        buf.try_copy_to_slice(&mut payload)
            .map_err(|_| Error::EndOfBuffer)?;
        ssz::Decode::from_ssz_bytes(&payload)
            .map_err(|_| Error::Invalid("Header", "Unable to decode bytes for header"))
    }
}

/// Error constructing a [`FinalizedHeader`] via [`FinalizedHeader::new`].
#[derive(Debug, PartialEq, Eq)]
pub enum FinalizedHeaderError {
    /// The finalization certificate's signed payload does not equal the digest
    /// recomputed from the header's fields. The header is not bound to the
    /// certificate.
    PayloadDigestMismatch,
}

impl fmt::Display for FinalizedHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadDigestMismatch => {
                write!(f, "finalization payload does not match the header digest")
            }
        }
    }
}

impl std::error::Error for FinalizedHeaderError {}

/// Upper bound on the participant count read from a raw finalized header before
/// it is used to size certificate (signer-bitmap) decoding. The count is
/// unauthenticated at decode time (it arrives via checkpoint bundles and other
/// raw-header import paths), and the certificate decoder allocates a bitmap of
/// up to `participant_count` bits before validating the encoded bytes, so an
/// unbounded count is a memory-pressure vector. This ceiling sits far above any
/// realistic committee size while capping the worst-case allocation to a few KB.
pub const MAX_FINALIZED_HEADER_PARTICIPANTS: usize = 100_000;

/// A header paired with the finalization certificate that finalized it.
///
/// The fields are private and the only validating constructor
/// ([`FinalizedHeader::new`]) enforces that the certificate's signed payload
/// equals the digest recomputed from the header's fields. This binds the
/// (otherwise free-standing) header fields to the signed certificate, so
/// consumers — e.g. [`crate::checkpoint::verify_checkpoint_chain`] — can trust
/// header fields like `checkpoint_hash` without re-deriving the binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedHeader<S: Scheme> {
    header: Header,
    finalization: Finalization<S, Digest>,
    participant_count: usize,
}

impl<S: Scheme> FinalizedHeader<S> {
    /// Constructs a `FinalizedHeader`, enforcing that the certificate's signed
    /// payload equals the digest recomputed from the header's fields.
    ///
    /// Returns [`FinalizedHeaderError::PayloadDigestMismatch`] if the header is
    /// not bound to the certificate.
    pub fn new(
        header: Header,
        finalization: Finalization<S, Digest>,
        participant_count: usize,
    ) -> Result<Self, FinalizedHeaderError> {
        if finalization.proposal.payload != header.computed_digest() {
            return Err(FinalizedHeaderError::PayloadDigestMismatch);
        }
        Ok(Self::new_unchecked(header, finalization, participant_count))
    }

    /// Constructs a `FinalizedHeader` **without** checking the payload/header
    /// binding.
    ///
    /// Only for callers that have already established the binding through
    /// another path (e.g. the finalizer constructing a header for a block it
    /// just certified). Prefer [`FinalizedHeader::new`] for any header derived
    /// from untrusted input.
    pub fn new_unchecked(
        header: Header,
        finalization: Finalization<S, Digest>,
        participant_count: usize,
    ) -> Self {
        Self {
            header,
            finalization,
            participant_count,
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn finalization(&self) -> &Finalization<S, Digest> {
        &self.finalization
    }

    pub fn participant_count(&self) -> usize {
        self.participant_count
    }

    /// Consumes the header, returning the owned finalization certificate.
    pub fn into_finalization(self) -> Finalization<S, Digest> {
        self.finalization
    }
}

impl<S: Scheme> ssz::Encode for FinalizedHeader<S> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Encode header, participant count, and finalization
        let header_bytes = self.header.as_ssz_bytes();
        let mut finalized_bytes = Vec::new();
        self.finalization.write(&mut finalized_bytes);

        let offset = 8 + 4; // Two 4-byte offsets (for variable fields) + 4 bytes for u32
        let mut encoder = ssz::SszEncoder::container(buf, offset);
        encoder.append(&header_bytes);
        encoder.append(&(self.participant_count as u32));
        encoder.append(&finalized_bytes);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let header_bytes = self.header.as_ssz_bytes();
        let mut finalized_bytes = Vec::new();
        self.finalization.write(&mut finalized_bytes);

        12 + header_bytes.len() + finalized_bytes.len() // Fixed part: 2 offsets + u32 = 12 bytes
    }
}

impl<S: Scheme> ssz::Decode for FinalizedHeader<S>
where
    <S::Certificate as Read>::Cfg: From<usize>,
{
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<u8>>()?; // header bytes
        builder.register_type::<u32>()?; // participant count
        builder.register_type::<Vec<u8>>()?; // finalized bytes

        let mut decoder = builder.build()?;
        let header_bytes: Vec<u8> = decoder.decode_next()?;
        let participant_count: u32 = decoder.decode_next()?;
        let finalized_bytes: Vec<u8> = decoder.decode_next()?;

        // The participant count is unauthenticated here and is used below to size
        // certificate (signer-bitmap) decoding, which allocates before the encoded
        // bytes are validated. Reject an oversized count up front so a malformed
        // raw header cannot drive a large allocation.
        if participant_count as usize > MAX_FINALIZED_HEADER_PARTICIPANTS {
            return Err(ssz::DecodeError::BytesInvalid(format!(
                "participant_count {participant_count} exceeds maximum {MAX_FINALIZED_HEADER_PARTICIPANTS}"
            )));
        }

        let header = Header::from_ssz_bytes(&header_bytes)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{e:?}")))?;

        // Decode the finalization using the stored participant count
        let mut finalized_buf = finalized_bytes.as_slice();
        let cfg = <S::Certificate as Read>::Cfg::from(participant_count as usize);
        let finalization = Finalization::<S, Digest>::read_cfg(&mut finalized_buf, &cfg)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{e:?}")))?;

        // Ensure the finalization is bound to the header (recompute from fields).
        Self::new(header, finalization, participant_count as usize)
            .map_err(|e| ssz::DecodeError::BytesInvalid(e.to_string()))
    }
}

impl<S: Scheme> EncodeSize for FinalizedHeader<S> {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET
    }
}

impl<S: Scheme> Write for FinalizedHeader<S> {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

impl<S: Scheme> Read for FinalizedHeader<S>
where
    <S::Certificate as Read>::Cfg: From<usize>,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len: u32 = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)?;
        if len as usize > buf.remaining() {
            return Err(Error::Invalid("FinalizedHeader", "improper encoded length"));
        }

        let mut payload = vec![0u8; len as usize];
        buf.try_copy_to_slice(&mut payload)
            .map_err(|_| Error::EndOfBuffer)?;
        ssz::Decode::from_ssz_bytes(&payload).map_err(|_| {
            Error::Invalid(
                "FinalizedHeader",
                "Unable to decode bytes for finalized header",
            )
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::hex;
    use commonware_codec::DecodeExt as _;
    use commonware_consensus::simplex::scheme::bls12381_multisig;
    use commonware_consensus::types::{Epoch, View};
    use commonware_consensus::{
        simplex::types::{Finalization, Proposal},
        types::Round,
    };
    use commonware_cryptography::{
        Signer,
        bls12381::{
            certificate::multisig::Certificate,
            primitives::{
                group::Private,
                ops::{aggregate::Signature, sign_message},
                variant::MinPk,
            },
        },
        certificate::Signers,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::Participant;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use ssz::Decode;

    fn create_test_public_key(seed: u8) -> PublicKey {
        let test_keys = [
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            hex!("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
            hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
        ];

        let key_bytes = test_keys[seed as usize % test_keys.len()];
        PublicKey::decode(&key_bytes[..]).expect("Valid test key from known vectors")
    }

    #[test]
    fn test_header_read_truncated_input_returns_err() {
        use commonware_codec::ReadExt;

        for n in 0..4 {
            let data = vec![0xFFu8; n];
            assert!(matches!(
                Header::read(&mut data.as_ref()),
                Err(Error::EndOfBuffer)
            ));
            assert!(matches!(
                FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::read(
                    &mut data.as_ref()
                ),
                Err(Error::EndOfBuffer)
            ));
        }

        let mut huge = Vec::new();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Header::read(&mut huge.as_ref()),
            Err(Error::Invalid("Header", _))
        ));
        assert!(matches!(
            FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::read(
                &mut huge.as_ref()
            ),
            Err(Error::Invalid("FinalizedHeader", _))
        ));
    }

    fn create_test_validators() -> (Vec<AddedValidator>, Vec<PublicKey>) {
        let added = vec![
            AddedValidator {
                node_key: create_test_public_key(1),
                consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
            },
            AddedValidator {
                node_key: create_test_public_key(2),
                consensus_key: bls12381::PrivateKey::from_seed(2).public_key(),
            },
            AddedValidator {
                node_key: create_test_public_key(3),
                consensus_key: bls12381::PrivateKey::from_seed(3).public_key(),
            },
        ];
        let removed = vec![create_test_public_key(10), create_test_public_key(11)];
        (added, removed)
    }

    fn create_dummy_signature() -> Signature<MinPk> {
        // Create a deterministic private key and sign a dummy message to get a valid G2 point
        let mut rng = StdRng::seed_from_u64(42);
        let private = Private::random(&mut rng);
        let g2_signature = sign_message::<MinPk>(&private, b"", b"test message");

        // Encode the G2 signature and decode it as Signature<MinPk>
        use commonware_codec::{DecodeExt as _, Encode as _};
        let encoded = g2_signature.encode();
        Signature::<MinPk>::decode(encoded).expect("valid signature")
    }

    #[test]
    fn test_ssz_digest_roundtrip() {
        let value: SszDigest = Digest([7u8; Digest::SIZE]).into();

        let bytes = value.as_ssz_bytes();
        assert_eq!(bytes.len(), Digest::SIZE);
        assert_eq!(value.ssz_bytes_len(), Digest::SIZE);
        assert_eq!(<SszDigest as ssz::Encode>::ssz_fixed_len(), Digest::SIZE);
        assert_eq!(<SszDigest as ssz::Decode>::ssz_fixed_len(), Digest::SIZE);

        let decoded = SszDigest::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, value);

        for bad_len in [Digest::SIZE - 1, Digest::SIZE + 1] {
            assert!(matches!(
                SszDigest::from_ssz_bytes(&vec![0u8; bad_len]),
                Err(ssz::DecodeError::InvalidByteLength { .. })
            ));
        }
    }

    #[test]
    fn test_ssz_public_key_roundtrip() {
        let value: SszPublicKey = create_test_public_key(1).into();

        let bytes = value.as_ssz_bytes();
        assert_eq!(bytes.len(), PublicKey::SIZE);
        assert_eq!(value.ssz_bytes_len(), PublicKey::SIZE);
        assert_eq!(
            <SszPublicKey as ssz::Encode>::ssz_fixed_len(),
            PublicKey::SIZE
        );
        assert_eq!(
            <SszPublicKey as ssz::Decode>::ssz_fixed_len(),
            PublicKey::SIZE
        );

        let decoded = SszPublicKey::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, value);

        for bad_len in [PublicKey::SIZE - 1, PublicKey::SIZE + 1] {
            assert!(matches!(
                SszPublicKey::from_ssz_bytes(&vec![0u8; bad_len]),
                Err(ssz::DecodeError::InvalidByteLength { .. })
            ));
        }
    }

    #[test]
    fn test_added_validator_roundtrip() {
        let value = AddedValidator {
            node_key: create_test_public_key(1),
            consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
        };

        let bytes = value.as_ssz_bytes();
        assert_eq!(bytes.len(), ADDED_VALIDATOR_SSZ_SIZE);
        assert_eq!(value.ssz_bytes_len(), ADDED_VALIDATOR_SSZ_SIZE);
        assert_eq!(
            <AddedValidator as ssz::Encode>::ssz_fixed_len(),
            ADDED_VALIDATOR_SSZ_SIZE
        );
        assert_eq!(
            <AddedValidator as ssz::Decode>::ssz_fixed_len(),
            ADDED_VALIDATOR_SSZ_SIZE
        );

        let decoded = AddedValidator::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, value);

        for bad_len in [ADDED_VALIDATOR_SSZ_SIZE - 1, ADDED_VALIDATOR_SSZ_SIZE + 1] {
            assert!(matches!(
                AddedValidator::from_ssz_bytes(&vec![0u8; bad_len]),
                Err(ssz::DecodeError::InvalidByteLength { .. })
            ));
        }
    }

    #[test]
    fn test_header_encode_decode() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        let encoded = header.encode();
        let decoded = Header::decode(encoded).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_finalized_header_encode_decode() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        let proposal = Proposal {
            round: Round::new(Epoch::new(0), View::new(header.view())),
            parent: View::new(header.height()),
            payload: header.get_digest(),
        };

        // Use BLS certificate
        let finalized = Finalization {
            proposal,
            certificate: Certificate::<MinPk> {
                signers: Signers::from(3, [0, 1, 2].map(Participant::new)),
                signature: create_dummy_signature().into(),
            },
        };

        let finalized_header = FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::new(
            header.clone(),
            finalized,
            3,
        )
        .expect("payload matches header digest");

        let encoded = finalized_header.encode();
        let decoded =
            FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::decode(encoded)
                .unwrap();

        assert_eq!(finalized_header.finalization(), decoded.finalization());
        assert_eq!(finalized_header.header(), decoded.header());
        assert_eq!(
            finalized_header.participant_count(),
            decoded.participant_count()
        );

        assert_eq!(finalized_header.header(), &header);
    }

    /// A raw finalized header that claims an oversized participant count must be
    /// rejected before the certificate (signer-bitmap) decode, which would
    /// otherwise size its allocation from that unauthenticated count.
    #[test]
    fn from_ssz_bytes_rejects_oversized_participant_count() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        let proposal = Proposal {
            round: Round::new(Epoch::new(0), View::new(header.view)),
            parent: View::new(header.height),
            payload: header.get_digest(),
        };
        let finalized = Finalization {
            proposal,
            certificate: Certificate::<MinPk> {
                signers: Signers::from(3, [0, 1, 2].map(Participant::new)),
                signature: create_dummy_signature().into(),
            },
        };
        let finalized_header = FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::new(
            header, finalized, 3,
        )
        .expect("payload is bound to the header digest");

        let ssz = finalized_header.as_ssz_bytes();
        // Sanity: the well-formed header (participant_count = 3) decodes.
        assert!(
            FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::from_ssz_bytes(&ssz)
                .is_ok()
        );

        // participant_count is the u32 in the container's fixed region, after the
        // first variable-field offset (bytes 4..8), little-endian.
        let mut tampered = ssz.clone();
        assert_eq!(
            u32::from_le_bytes(tampered[4..8].try_into().unwrap()),
            3,
            "expected participant_count at bytes 4..8"
        );
        tampered[4..8].copy_from_slice(&u32::MAX.to_le_bytes());

        let result = FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::from_ssz_bytes(
            &tampered,
        );
        assert!(
            matches!(result, Err(ssz::DecodeError::BytesInvalid(ref msg)) if msg.contains("participant_count")),
            "oversized participant_count must be rejected before certificate decode, got: {result:?}"
        );
    }

    #[test]
    fn test_finalized_header_validation() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        // Create a finalization with wrong payload
        let dummy_digest = [99u8; 32];
        let wrong_proposal = Proposal {
            round: Round::new(Epoch::new(0), View::new(header.view())),
            parent: View::new(header.height()),
            payload: dummy_digest.into(), // Wrong digest
        };

        // Use BLS certificate with wrong payload
        let wrong_finalized = Finalization {
            proposal: wrong_proposal,
            certificate: Certificate::<MinPk> {
                signers: Signers::from(5, [0, 2, 4].map(Participant::new)),
                signature: create_dummy_signature().into(),
            },
        };

        // Build an unbound pairing via `new_unchecked` (the safe `new` would
        // reject it), then confirm decode re-derives and rejects the mismatch.
        let finalized_header: FinalizedHeader<bls12381_multisig::Scheme<PublicKey, MinPk>> =
            FinalizedHeader::new_unchecked(header, wrong_finalized, 5);

        let encoded = finalized_header.as_ssz_bytes();
        let result = FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::from_ssz_bytes(
            &encoded,
        );

        assert!(result.is_err());
        println!("{:?}", result);
        assert!(
            matches!(result.unwrap_err(), ssz::DecodeError::BytesInvalid(msg) if msg.contains("does not match the header digest"))
        );
    }

    #[test]
    fn test_finalized_header_encode_size() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        let proposal = Proposal {
            round: Round::new(Epoch::new(0), View::new(header.view())),
            parent: View::new(header.height()),
            payload: header.get_digest(),
        };

        // Use BLS certificate
        let finalized = Finalization {
            proposal,
            certificate: Certificate::<MinPk> {
                signers: Signers::from(4, [0, 1, 2, 3].map(Participant::new)),
                signature: create_dummy_signature().into(),
            },
        };

        let finalized_header = FinalizedHeader::<bls12381_multisig::Scheme<PublicKey, MinPk>>::new(
            header, finalized, 4,
        )
        .expect("payload matches header digest");

        let ssz_len = finalized_header.ssz_bytes_len();
        let encode_len = finalized_header.encode_size();
        let actual_encoded = finalized_header.encode();

        let pure_ssz = finalized_header.as_ssz_bytes();

        assert_eq!(
            pure_ssz.len(),
            ssz_len,
            "SSZ calculation should match actual SSZ encoding"
        );
        // The Write implementation adds a 4-byte length prefix
        assert_eq!(actual_encoded.len(), pure_ssz.len() + 4);
        assert_eq!(actual_encoded.len(), encode_len);
    }

    /// Builds a header identical in every fixed field, varying only the
    /// validator-transition vectors, so any digest difference is attributable
    /// solely to the added/removed partition.
    fn header_with(added: Vec<AddedValidator>, removed: Vec<PublicKey>) -> Header {
        Header::new(
            [27u8; 32].into(),
            27,
            2727,
            42,
            1,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            added,
            removed,
            [0u8; 32],
        )
    }

    /// Regression test for the header-digest validator-partition ambiguity.
    ///
    /// The previous hand-rolled digest concatenated `added_validators` and
    /// `removed_validators` as raw byte streams with no length, count, or boundary,
    /// so the digest did not commit to where the added list ended and the removed
    /// list began. The SSZ container the digest is now computed over places an
    /// explicit offset for each variable-length field, so the boundary (and each
    /// list's count) is bound by the digest: distinct partitions cannot alias.
    #[test]
    fn test_header_digest_commits_to_validator_partition() {
        let a1 = AddedValidator {
            node_key: create_test_public_key(0),
            consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
        };
        // a2's node identity is the same key that appears as a *removed* key in h_a.
        let a2 = AddedValidator {
            node_key: create_test_public_key(1),
            consensus_key: bls12381::PrivateKey::from_seed(2).public_key(),
        };

        // Same set of identities, partitioned differently across the boundary:
        //   h_a: pk(1) is a removed validator.
        //   h_b: pk(1) is instead the node identity of an added validator (a2).
        let h_a = header_with(
            vec![a1.clone()],
            vec![create_test_public_key(1), create_test_public_key(2)],
        );
        let h_b = header_with(vec![a1.clone(), a2], vec![create_test_public_key(2)]);
        assert_ne!(
            h_a.get_digest(),
            h_b.get_digest(),
            "moving an identity across the added/removed boundary must change the digest"
        );

        // Changing only the count of one list must change the digest too.
        let h_one_removed = header_with(vec![a1.clone()], vec![create_test_public_key(2)]);
        let h_two_removed = header_with(
            vec![a1],
            vec![create_test_public_key(2), create_test_public_key(3)],
        );
        assert_ne!(
            h_one_removed.get_digest(),
            h_two_removed.get_digest(),
            "the removed-validator count must be committed by the digest"
        );
    }

    /// Regression test that the SSZ encoding the digest is computed over is
    /// canonical: the boundary between the added and removed lists is committed by
    /// offsets, so extra heap bytes cannot be silently absorbed into the removed
    /// list to forge a second header that decodes to a different partition yet
    /// shares the digest.
    #[test]
    fn test_header_decode_rejects_misaligned_validator_bytes() {
        let a1 = AddedValidator {
            node_key: create_test_public_key(0),
            consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
        };
        let h = header_with(vec![a1], vec![create_test_public_key(1)]);

        // The encoding round-trips deterministically.
        let ssz = h.as_ssz_bytes();
        let decoded = Header::from_ssz_bytes(&ssz).expect("valid header must decode");
        assert_eq!(
            decoded.as_ssz_bytes(),
            ssz,
            "encoding must be canonical (re-encode matches)"
        );

        // Appending a stray byte makes the trailing removed-validator region
        // (one 32-byte key) no longer a clean multiple of the element size, so
        // decode must reject it rather than absorb the byte into the list.
        let mut padded = ssz.clone();
        padded.push(0u8);
        assert!(
            Header::from_ssz_bytes(&padded).is_err(),
            "trailing bytes must not be absorbed into the removed-validator list"
        );
    }
}
