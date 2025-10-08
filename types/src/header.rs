use std::ops::Deref as _;

use crate::{PublicKey, Signature};
use alloy_primitives::U256;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use ssz::Encode as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub parent: Digest,
    pub height: u64,
    pub timestamp: u64,
    pub view: u64,
    pub payload_hash: Digest,
    pub execution_request_hash: Digest,
    pub checkpoint_hash: Digest,
    pub prev_epoch_header_hash: Digest,
    pub block_value: U256,
    pub added_validators: Vec<PublicKey>,
    pub removed_validators: Vec<PublicKey>,
    // precomputed digest of this header
    pub digest: Digest,
}

impl Header {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_digest(
        parent: Digest,
        height: u64,
        timestamp: u64,
        view: u64,
        payload_hash: Digest,
        execution_request_hash: Digest,
        checkpoint_hash: Digest,
        prev_epoch_header_hash: Digest,
        block_value: U256,
        added_validators: Vec<PublicKey>,
        removed_validators: Vec<PublicKey>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&parent);
        hasher.update(&height.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&payload_hash);
        hasher.update(&execution_request_hash);
        hasher.update(&checkpoint_hash);
        hasher.update(&prev_epoch_header_hash);
        hasher.update(&block_value.as_ssz_bytes());
        // Hash the validator lists by converting to bytes
        let added_validators_bytes: Vec<[u8; 32]> = added_validators
            .iter()
            .map(|pk| pk.as_ref().try_into().expect("PublicKey is 32 bytes"))
            .collect();
        let removed_validators_bytes: Vec<[u8; 32]> = removed_validators
            .iter()
            .map(|pk| pk.as_ref().try_into().expect("PublicKey is 32 bytes"))
            .collect();
        hasher.update(&added_validators_bytes.as_ssz_bytes());
        hasher.update(&removed_validators_bytes.as_ssz_bytes());
        hasher.update(&view.to_be_bytes());
        let digest = hasher.finalize();

        Self {
            parent,
            height,
            timestamp,
            view,
            payload_hash,
            execution_request_hash,
            checkpoint_hash,
            prev_epoch_header_hash,
            block_value,
            added_validators,
            removed_validators,
            digest,
        }
    }
}

impl ssz::Encode for Header {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <[u8; 32] as ssz::Encode>::ssz_fixed_len() * 5 // parent, payload_hash, execution_request_hash, checkpoint_hash, prev_epoch_header_hash
            + <u64 as ssz::Encode>::ssz_fixed_len() * 3 // height, timestamp, view
            + <U256 as ssz::Encode>::ssz_fixed_len() // block_value
            + <Vec<[u8; 32]> as ssz::Encode>::ssz_fixed_len() * 2; // added_validators, removed_validators offsets

        let mut encoder = ssz::SszEncoder::container(buf, offset);

        let parent: [u8; 32] = self.parent.deref().try_into().expect("Digest is 32 bytes");
        let payload_hash: [u8; 32] = self
            .payload_hash
            .deref()
            .try_into()
            .expect("Digest is 32 bytes");
        let execution_request_hash: [u8; 32] = self
            .execution_request_hash
            .deref()
            .try_into()
            .expect("Digest is 32 bytes");
        let checkpoint_hash: [u8; 32] = self
            .checkpoint_hash
            .deref()
            .try_into()
            .expect("Digest is 32 bytes");
        let prev_epoch_header_hash: [u8; 32] = self
            .prev_epoch_header_hash
            .deref()
            .try_into()
            .expect("Digest is 32 bytes");

        // Convert PublicKey vectors to byte arrays for SSZ
        let added_validators: Vec<[u8; 32]> = self
            .added_validators
            .iter()
            .map(|pk| pk.as_ref().try_into().expect("PublicKey is 32 bytes"))
            .collect();
        let removed_validators: Vec<[u8; 32]> = self
            .removed_validators
            .iter()
            .map(|pk| pk.as_ref().try_into().expect("PublicKey is 32 bytes"))
            .collect();

        encoder.append(&parent);
        encoder.append(&self.height);
        encoder.append(&self.timestamp);
        encoder.append(&self.view);
        encoder.append(&payload_hash);
        encoder.append(&execution_request_hash);
        encoder.append(&checkpoint_hash);
        encoder.append(&prev_epoch_header_hash);
        encoder.append(&self.block_value);
        encoder.append(&added_validators);
        encoder.append(&removed_validators);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let fixed_size = <[u8; 32] as ssz::Encode>::ssz_fixed_len() * 5 // parent, payload_hash, execution_request_hash, checkpoint_hash, prev_epoch_header_hash
            + <u64 as ssz::Encode>::ssz_fixed_len() * 3 // height, timestamp, view
            + <U256 as ssz::Encode>::ssz_fixed_len(); // block_value

        // Calculate length as if they were Vec<[u8; 32]>
        let added_validators_len = self.added_validators.len() * 32;
        let removed_validators_len = self.removed_validators.len() * 32;

        fixed_size
            + ssz::BYTES_PER_LENGTH_OFFSET * 2  // 2 variable-length fields need 2 offsets
            + added_validators_len
            + removed_validators_len
    }
}

impl ssz::Decode for Header {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<[u8; 32]>()?; // parent
        builder.register_type::<u64>()?; // height
        builder.register_type::<u64>()?; // timestamp
        builder.register_type::<u64>()?; // view
        builder.register_type::<[u8; 32]>()?; // payload_hash
        builder.register_type::<[u8; 32]>()?; // execution_request_hash
        builder.register_type::<[u8; 32]>()?; // checkpoint_hash
        builder.register_type::<[u8; 32]>()?; // prev_epoch_header_hash
        builder.register_type::<U256>()?; // block_value
        builder.register_type::<Vec<[u8; 32]>>()?; // added_validators
        builder.register_type::<Vec<[u8; 32]>>()?; // removed_validators

        let mut decoder = builder.build()?;

        let parent: [u8; 32] = decoder.decode_next()?;
        let height: u64 = decoder.decode_next()?;
        let timestamp: u64 = decoder.decode_next()?;
        let view: u64 = decoder.decode_next()?;
        let payload_hash: [u8; 32] = decoder.decode_next()?;
        let execution_request_hash: [u8; 32] = decoder.decode_next()?;
        let checkpoint_hash: [u8; 32] = decoder.decode_next()?;
        let prev_epoch_header_hash: [u8; 32] = decoder.decode_next()?;
        let block_value: U256 = decoder.decode_next()?;
        let added_validators_bytes: Vec<[u8; 32]> = decoder.decode_next()?;
        let removed_validators_bytes: Vec<[u8; 32]> = decoder.decode_next()?;

        // Convert byte arrays back to PublicKeys
        use commonware_codec::DecodeExt as _;
        let added_validators: Vec<PublicKey> = added_validators_bytes
            .into_iter()
            .map(|bytes| {
                PublicKey::decode(&bytes[..]).map_err(|_| {
                    ssz::DecodeError::BytesInvalid("Invalid PublicKey bytes".to_string())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let removed_validators: Vec<PublicKey> = removed_validators_bytes
            .into_iter()
            .map(|bytes| {
                PublicKey::decode(&bytes[..]).map_err(|_| {
                    ssz::DecodeError::BytesInvalid("Invalid PublicKey bytes".to_string())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::compute_digest(
            parent.into(),
            height,
            timestamp,
            view,
            payload_hash.into(),
            execution_request_hash.into(),
            checkpoint_hash.into(),
            prev_epoch_header_hash.into(),
            block_value,
            added_validators,
            removed_validators,
        ))
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
        let len: u32 = buf.get_u32();
        if len > buf.remaining() as u32 {
            return Err(Error::Invalid("Header", "improper encoded length"));
        }

        ssz::Decode::from_ssz_bytes(buf.copy_to_bytes(len as usize).chunk())
            .map_err(|_| Error::Invalid("Header", "Unable to decode bytes for header"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedHeader {
    pub header: Header,
    pub finalized: Finalization<Signature, Digest>,
}

impl FinalizedHeader {
    pub fn new(header: Header, finalized: Finalization<Signature, Digest>) -> Self {
        Self { header, finalized }
    }
}

impl ssz::Encode for FinalizedHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // For simplicity, encode header first, then finalized proof using commonware encoding
        let header_bytes = self.header.as_ssz_bytes();
        let mut finalized_bytes = Vec::new();
        self.finalized.write(&mut finalized_bytes);

        let offset = 8; // Two 4-byte length prefixes
        let mut encoder = ssz::SszEncoder::container(buf, offset);
        encoder.append(&header_bytes);
        encoder.append(&finalized_bytes);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let header_bytes = self.header.as_ssz_bytes();
        let mut finalized_bytes = Vec::new();
        self.finalized.write(&mut finalized_bytes);

        header_bytes.len() + finalized_bytes.len() + 8 // Two 4-byte length prefixes
    }
}

impl ssz::Decode for FinalizedHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<u8>>()?; // header bytes
        builder.register_type::<Vec<u8>>()?; // finalized bytes

        let mut decoder = builder.build()?;
        let header_bytes: Vec<u8> = decoder.decode_next()?;
        let finalized_bytes: Vec<u8> = decoder.decode_next()?;

        let header = Header::from_ssz_bytes(&header_bytes)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{e:?}")))?;

        let mut finalized_buf = finalized_bytes.as_slice();
        let finalized = Finalization::read_cfg(&mut finalized_buf, &finalized_bytes.len())
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{e:?}")))?;

        // Ensure the finalization is for the header
        if finalized.proposal.payload != header.digest {
            return Err(ssz::DecodeError::BytesInvalid(
                "Finalization payload does not match header digest".to_string(),
            ));
        }

        Ok(Self { header, finalized })
    }
}

impl EncodeSize for FinalizedHeader {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET
    }
}

impl Write for FinalizedHeader {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

impl Read for FinalizedHeader {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len: u32 = buf.get_u32();
        if len > buf.remaining() as u32 {
            return Err(Error::Invalid("FinalizedHeader", "improper encoded length"));
        }

        ssz::Decode::from_ssz_bytes(buf.copy_to_bytes(len as usize).chunk()).map_err(|_| {
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
    use alloy_primitives::{U256, hex};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_consensus::simplex::types::{Finalization, Proposal};
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

    fn create_test_validators() -> (Vec<PublicKey>, Vec<PublicKey>) {
        let added = vec![
            create_test_public_key(1),
            create_test_public_key(2),
            create_test_public_key(3),
        ];
        let removed = vec![create_test_public_key(10), create_test_public_key(11)];
        (added, removed)
    }

    #[test]
    fn test_header_encode_decode() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            42,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            U256::ZERO,
            added_validators,
            removed_validators,
        );

        let encoded = header.encode();
        let decoded = Header::decode(encoded).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_finalized_header_encode_decode() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            42,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            U256::ZERO,
            added_validators,
            removed_validators,
        );

        let proposal = Proposal {
            view: header.view,
            parent: header.height,
            payload: header.digest,
        };

        let finalized = Finalization {
            proposal,
            signatures: Vec::new(),
        };

        let finalized_header = FinalizedHeader::new(header.clone(), finalized);

        let encoded = finalized_header.encode();
        let decoded = FinalizedHeader::decode(encoded).unwrap();

        assert_eq!(finalized_header, decoded);
        assert_eq!(finalized_header.header, header);
    }

    #[test]
    fn test_finalized_header_validation() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            42,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            U256::ZERO,
            added_validators,
            removed_validators,
        );

        // Create a finalization with wrong payload
        let wrong_proposal = Proposal {
            view: header.view,
            parent: header.height,
            payload: [99u8; 32].into(), // Wrong digest
        };

        let wrong_finalized = Finalization {
            proposal: wrong_proposal,
            signatures: Vec::new(),
        };

        let finalized_header = FinalizedHeader {
            header,
            finalized: wrong_finalized,
        };

        let encoded = finalized_header.as_ssz_bytes();
        let result = FinalizedHeader::from_ssz_bytes(&encoded);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ssz::DecodeError::BytesInvalid(msg) if msg.contains("Finalization payload does not match header digest"))
        );
    }

    #[test]
    fn test_finalized_header_encode_size() {
        let (added_validators, removed_validators) = create_test_validators();
        let header = Header::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            42,
            [1u8; 32].into(),
            [2u8; 32].into(),
            [3u8; 32].into(),
            [4u8; 32].into(),
            U256::ZERO,
            added_validators,
            removed_validators,
        );

        let proposal = Proposal {
            view: header.view,
            parent: header.height,
            payload: header.digest,
        };

        let finalized = Finalization {
            proposal,
            signatures: Vec::new(),
        };

        let finalized_header = FinalizedHeader::new(header, finalized);

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
}
