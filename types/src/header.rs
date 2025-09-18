use std::ops::Deref as _;

use crate::Signature;
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
    // precomputed digest of this header
    pub digest: Digest,
}

pub const HEADER_BYTES_LEN: usize = 32 + 8 + 8 + 8 + 32 + 32 + 32 + 32 + 32; // 216

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
            digest,
        }
    }
}

impl ssz::Encode for Header {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // todo: safe unwrap unless we change digest size. Reason for this is because Digest.0 is private in commonware and it only derefs into [u8] instead of the [u8; DIGEST_LENGTH] that we want
        let parent: [u8; 32] = self
            .parent
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");
        let payload_hash: [u8; 32] = self
            .payload_hash
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");
        let execution_request_hash: [u8; 32] = self
            .execution_request_hash
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");
        let checkpoint_hash: [u8; 32] = self
            .checkpoint_hash
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");
        let prev_epoch_header_hash: [u8; 32] = self
            .prev_epoch_header_hash
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");

        buf.extend_from_slice(&parent);
        buf.extend_from_slice(&self.height.as_ssz_bytes());
        buf.extend_from_slice(&self.timestamp.as_ssz_bytes());
        buf.extend_from_slice(&self.view.as_ssz_bytes());
        buf.extend_from_slice(&payload_hash);
        buf.extend_from_slice(&execution_request_hash);
        buf.extend_from_slice(&checkpoint_hash);
        buf.extend_from_slice(&prev_epoch_header_hash);
        buf.extend_from_slice(&self.block_value.as_ssz_bytes());
    }

    fn ssz_fixed_len() -> usize {
        HEADER_BYTES_LEN
    }

    fn ssz_bytes_len(&self) -> usize {
        HEADER_BYTES_LEN
    }
}

impl ssz::Decode for Header {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if bytes.len() != HEADER_BYTES_LEN {
            return Err(ssz::DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: HEADER_BYTES_LEN,
            });
        }

        let mut offset = 0;

        let parent = <[u8; 32]>::from_ssz_bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let height = u64::from_ssz_bytes(&bytes[offset..offset + 8])?;
        offset += 8;

        let timestamp = u64::from_ssz_bytes(&bytes[offset..offset + 8])?;
        offset += 8;

        let view = u64::from_ssz_bytes(&bytes[offset..offset + 8])?;
        offset += 8;

        let payload_hash = <[u8; 32]>::from_ssz_bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let execution_request_hash = <[u8; 32]>::from_ssz_bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let checkpoint_hash = <[u8; 32]>::from_ssz_bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let prev_epoch_header_hash = <[u8; 32]>::from_ssz_bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let block_value = U256::from_ssz_bytes(&bytes[offset..offset + 32])?;

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
        ))
    }

    fn ssz_fixed_len() -> usize {
        HEADER_BYTES_LEN
    }
}

impl EncodeSize for Header {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len()
    }
}

impl Write for Header {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        buf.put(ssz_bytes);
    }
}

impl Read for Header {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len = HEADER_BYTES_LEN;
        if len > buf.remaining() {
            return Err(Error::Invalid("Header", "missing bytes"));
        }
        ssz::Decode::from_ssz_bytes(buf.copy_to_bytes(len).chunk())
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
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{:?}", e)))?;

        let mut finalized_buf = finalized_bytes.as_slice();
        let finalized = Finalization::read_cfg(&mut finalized_buf, &finalized_bytes.len())
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{:?}", e)))?;

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
    use alloy_primitives::U256;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_consensus::simplex::types::{Finalization, Proposal};
    use ssz::Decode;

    #[test]
    fn test_header_encode_decode() {
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
        );

        let encoded = header.encode();
        let decoded = Header::decode(encoded).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_finalized_header_encode_decode() {
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
