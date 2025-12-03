use crate::{Header, PublicKey};
use alloy_consensus::{Block as AlloyBlock, TxEnvelope};
use alloy_primitives::{Bytes as AlloyBytes, U256};
use alloy_rpc_types_engine::ExecutionPayloadV3;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_consensus::Block as ConsensusBlock;
use commonware_consensus::types::View;
use commonware_consensus::{
    Viewable,
    simplex::{
        signing_scheme::bls12381_multisig::Scheme,
        types::{Finalization, Notarization},
    },
};
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::{
    Committable, Digestible, Hasher, Sha256, Signer, ed25519, sha256::Digest,
};
use ssz::Encode as _;
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<C: Signer = ed25519::PrivateKey, V: Variant = MinPk> {
    pub header: Header,
    pub payload: ExecutionPayloadV3,
    pub execution_requests: Vec<AlloyBytes>,
    pub _signer_marker: PhantomData<C>,
    pub _variant_marker: PhantomData<V>,
}

impl<C: Signer, V: Variant> Block<C, V> {
    pub fn eth_block_hash(&self) -> [u8; 32] {
        // if genesis return your own digest
        if self.header.height == 0 {
            self.header.digest.as_ref().try_into().unwrap()
        } else {
            self.payload.payload_inner.payload_inner.block_hash.into()
        }
    }

    pub fn eth_parent_hash(&self) -> [u8; 32] {
        self.payload.payload_inner.payload_inner.parent_hash.into()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_digest(
        parent: Digest,
        height: u64,
        timestamp: u64,
        payload: ExecutionPayloadV3,
        execution_requests: Vec<AlloyBytes>,
        block_value: U256,
        epoch: u64,
        view: u64,
        checkpoint_hash: Option<Digest>,
        prev_epoch_header_hash: Digest,
        added_validators: Vec<PublicKey>,
        removed_validators: Vec<PublicKey>,
    ) -> Self {
        let payload_ssz = payload.as_ssz_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&payload_ssz);
        let payload_hash = hasher.finalize();

        let execution_request_hash = if !execution_requests.is_empty() {
            let execution_requests_ssz = execution_requests.as_ssz_bytes();
            let mut hasher = Sha256::new();
            hasher.update(&execution_requests_ssz);
            hasher.finalize()
        } else {
            [0; 32].into()
        };

        let checkpoint_hash = if let Some(checkpoint_hash) = checkpoint_hash {
            checkpoint_hash
        } else {
            [0; 32].into()
        };

        let header = Header::compute_digest(
            parent,
            height,
            timestamp,
            epoch,
            view,
            payload_hash,
            execution_request_hash,
            checkpoint_hash,
            prev_epoch_header_hash,
            block_value,
            added_validators,
            removed_validators,
        );

        Self {
            header,
            payload,
            execution_requests,
            _signer_marker: PhantomData,
            _variant_marker: PhantomData,
        }
    }

    pub fn new_with_verify(
        header: Header,
        payload: ExecutionPayloadV3,
        execution_requests: Vec<AlloyBytes>,
    ) -> Result<Self> {
        let payload_ssz = payload.as_ssz_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&payload_ssz);
        let payload_hash = hasher.finalize();

        let execution_request_hash = if !execution_requests.is_empty() {
            let execution_requests_ssz = execution_requests.as_ssz_bytes();
            let mut hasher = Sha256::new();
            hasher.update(&execution_requests_ssz);
            hasher.finalize()
        } else {
            [0; 32].into()
        };

        if payload_hash != header.payload_hash {
            return Err(anyhow!("Payload hash mismatch"));
        }
        if execution_request_hash != header.execution_request_hash {
            return Err(anyhow!("Execution request hash mismatch"));
        }
        Ok(Self {
            header,
            payload,
            execution_requests,
            _signer_marker: PhantomData,
            _variant_marker: PhantomData,
        })
    }

    pub fn genesis(genesis_hash: [u8; 32]) -> Self {
        let payload = ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default());
        let payload_ssz = payload.as_ssz_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&payload_ssz);
        let payload_hash = hasher.finalize();

        let header = Header {
            parent: genesis_hash.into(),
            height: 0,
            timestamp: 0,
            epoch: 0,
            view: 1,
            payload_hash,
            execution_request_hash: [0; 32].into(),
            checkpoint_hash: [0; 32].into(),
            prev_epoch_header_hash: [0; 32].into(),
            block_value: U256::ZERO,
            added_validators: Vec::new(),
            removed_validators: Vec::new(),
            digest: genesis_hash.into(),
        };
        Self {
            header,
            payload: ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default()),
            execution_requests: Default::default(),
            _signer_marker: PhantomData,
            _variant_marker: PhantomData,
        }
    }

    pub fn parent(&self) -> Digest {
        self.header.parent
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    pub fn digest(&self) -> Digest {
        self.header.digest
    }

    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    pub fn view(&self) -> u64 {
        self.header.view
    }

    pub fn epoch(&self) -> u64 {
        self.header.epoch
    }
}

impl<C: Signer, V: Variant> ConsensusBlock for Block<C, V> {
    fn height(&self) -> u64 {
        self.header.height
    }

    fn parent(&self) -> Self::Commitment {
        self.header.parent
    }
}

impl<C: Signer, V: Variant> Viewable for Block<C, V> {
    fn view(&self) -> View {
        View::new(self.header.view)
    }
}

impl<C: Signer, V: Variant> ssz::Encode for Block<C, V> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // All three fields are variable-length, so we only need offsets
        let offset = ssz::BYTES_PER_LENGTH_OFFSET * 3; // 3 variable-length fields

        let mut encoder = ssz::SszEncoder::container(buf, offset);

        encoder.append(&self.header);
        encoder.append(&self.payload);
        encoder.append(&self.execution_requests);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.header.ssz_bytes_len()
            + self.payload.ssz_bytes_len()
            + self.execution_requests.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET * 3 // 3 variable-length fields need 3 offsets
    }
}

impl<C: Signer, V: Variant> ssz::Decode for Block<C, V> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Header>()?;
        builder.register_type::<ExecutionPayloadV3>()?;
        builder.register_type::<Vec<AlloyBytes>>()?;

        let mut decoder = builder.build()?;

        let header: Header = decoder.decode_next()?;
        let payload = decoder.decode_next()?;
        let execution_requests = decoder.decode_next()?;

        Self::new_with_verify(header, payload, execution_requests)
            .map_err(|e| ssz::DecodeError::BytesInvalid(e.to_string()))
    }
}

impl<C: Signer, V: Variant> EncodeSize for Block<C, V> {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET
    }
}

impl<C: Signer, V: Variant> Write for Block<C, V> {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

impl<C: Signer, V: Variant> Read for Block<C, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len: u32 = buf.get_u32();
        if len > buf.remaining() as u32 {
            return Err(Error::Invalid("Block", "improper encoded length"));
        }

        ssz::Decode::from_ssz_bytes(buf.copy_to_bytes(len as usize).chunk())
            .map_err(|_| Error::Invalid("Block", "Unable to decode bytes for block"))
    }
}

impl<C: Signer, V: Variant> Digestible for Block<C, V> {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.header.digest
    }
}

impl<C: Signer, V: Variant> Committable for Block<C, V> {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.header.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized<C: Signer, V: Variant> {
    pub proof: Notarization<Scheme<C::PublicKey, V>, Digest>,
    pub block: Block<C, V>,
}

impl<C: Signer, V: Variant> Notarized<C, V> {
    pub fn new(proof: Notarization<Scheme<C::PublicKey, V>, Digest>, block: Block<C, V>) -> Self {
        Self { proof, block }
    }
}

impl<C: Signer, V: Variant> Write for Notarized<C, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<C: Signer, V: Variant> Read for Notarized<C, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof =
            Notarization::<Scheme<C::PublicKey, V>, Digest>::read_cfg(buf, &buf.remaining())?; // todo: get a test on this to make sure buf.remaining is safe
        let block = Block::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Notarized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<C: Signer, V: Variant> EncodeSize for Notarized<C, V> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized<C: Signer, V: Variant> {
    pub proof: Finalization<Scheme<C::PublicKey, V>, Digest>,
    pub block: Block<C, V>,
}

impl<C: Signer, V: Variant> Finalized<C, V> {
    pub fn new(proof: Finalization<Scheme<C::PublicKey, V>, Digest>, block: Block<C, V>) -> Self {
        Self { proof, block }
    }
}

impl<C: Signer, V: Variant> Write for Finalized<C, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl<C: Signer, V: Variant> Read for Finalized<C, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof =
            Finalization::<Scheme<C::PublicKey, V>, Digest>::read_cfg(buf, &buf.remaining())?;
        let block = Block::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Finalized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl<C: Signer, V: Variant> EncodeSize for Finalized<C, V> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockWithFinalization<C: Signer, V: Variant> {
    pub block: Block<C, V>,
    pub finalized: Option<Finalization<Scheme<C::PublicKey, V>, Digest>>,
}

impl<C: Signer, V: Variant> Digestible for BlockWithFinalization<C, V> {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.block.header.digest
    }
}

impl<C: Signer, V: Variant> Committable for BlockWithFinalization<C, V> {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.block.header.digest
    }
}

impl<C: Signer, V: Variant> ConsensusBlock for BlockWithFinalization<C, V> {
    fn height(&self) -> u64 {
        self.block.header.height
    }

    fn parent(&self) -> Self::Commitment {
        self.block.header.parent
    }
}

impl<C: Signer, V: Variant> Read for BlockWithFinalization<C, V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let block = Block::<C, V>::read(buf)?;
        let has_finalized = buf.get_u8();
        let finalized = if has_finalized == 1 {
            Some(Finalization::<Scheme<C::PublicKey, V>, Digest>::read_cfg(
                buf,
                &buf.remaining(),
            )?)
        } else {
            None
        };
        Ok(Self { block, finalized })
    }
}

impl<C: Signer, V: Variant> Write for BlockWithFinalization<C, V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.block.write(buf);
        if let Some(ref finalized) = self.finalized {
            buf.put_u8(1u8);
            finalized.write(buf);
        } else {
            buf.put_u8(0u8);
        }
    }
}

impl<C: Signer, V: Variant> EncodeSize for BlockWithFinalization<C, V> {
    fn encode_size(&self) -> usize {
        let mut size = self.block.encode_size() + 1; // +1 for the has_finalized flag
        if let Some(ref finalized) = self.finalized {
            size += finalized.encode_size();
        }
        size
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::{Bytes as AlloyBytes, U256, hex};
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_cryptography::ed25519;

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
        let added = vec![create_test_public_key(20), create_test_public_key(21)];
        let removed = vec![create_test_public_key(30)];
        (added, removed)
    }
    #[test]
    fn test_block_encode_decode() {
        let first_transaction_raw = AlloyBytes::from_static(
            &hex!(
                "b9017e02f9017a8501a1f0ff438211cc85012a05f2008512a05f2000830249f094d5409474fd5a725eab2ac9a8b26ca6fb51af37ef80b901040cc7326300000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000001bdd2ed4b616c800000000000000000000000000001e9ee781dd4b97bdef92e5d1785f73a1f931daa20000000000000000000000007a40026a3b9a41754a95eec8c92c6b99886f440c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000009ae80eb647dd09968488fa1d7e412bf8558a0b7a0000000000000000000000000f9815537d361cb02befd9918c95c97d4d8a4a2bc001a0ba8f1928bb0efc3fcd01524a2039a9a2588fa567cd9a7cc18217e05c615e9d69a0544bfd11425ac7748e76b3795b57a5563e2b0eff47b5428744c62ff19ccfc305"
            )[..],
        );
        let second_transaction_raw = AlloyBytes::from_static(
            &hex!(
                "b9013c03f901388501a1f0ff430c843b9aca00843b9aca0082520894e7249813d8ccf6fa95a2203f46a64166073d58878080c005f8c6a00195f6dff17753fc89b60eac6477026a805116962c9e412de8015c0484e661c1a001aae314061d4f5bbf158f15d9417a238f9589783f58762cd39d05966b3ba2fba0013f5be9b12e7da06f0dd11a7bdc4e0db8ef33832acc23b183bd0a2c1408a757a0019d9ac55ea1a615d92965e04d960cb3be7bff121a381424f1f22865bd582e09a001def04412e76df26fefe7b0ed5e10580918ae4f355b074c0cfe5d0259157869a0011c11a415db57e43db07aef0de9280b591d65ca0cce36c7002507f8191e5d4a80a0c89b59970b119187d97ad70539f1624bbede92648e2dc007890f9658a88756c5a06fb2e3d4ce2c438c0856c2de34948b7032b1aadc4642a9666228ea8cdc7786b7"
            )[..],
        );
        let payload = ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas:  U256::from(7u64),
                    block_number: 0xa946u64,
                    block_hash: hex!("a5ddd3f286f429458a39cafc13ffe89295a7efa8eb363cf89a1a4887dbcf272b").into(),
                    logs_bloom: hex!("00200004000000000000000080000000000200000000000000000000000000000000200000000000000000000000000000000000800000000200000000000000000000000000000000000008000000200000000000000000000001000000000000000000000000000000800000000000000000000100000000000030000000000000000040000000000000000000000000000000000800080080404000000000000008000000000008200000000000200000000000000000000000000000000000000002000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000100000000000000000000").into(),
                    extra_data: hex!("d883010d03846765746888676f312e32312e31856c696e7578").into(),
                    gas_limit: 0x1c9c380,
                    gas_used: 0x1f4a9,
                    timestamp: 0x651f35b8,
                    fee_recipient: hex!("f97e180c050e5ab072211ad2c213eb5aee4df134").into(),
                    parent_hash: hex!("d829192799c73ef28a7332313b3c03af1f2d5da2c36f8ecfafe7a83a3bfb8d1e").into(),
                    prev_randao: hex!("753888cc4adfbeb9e24e01c84233f9d204f4a9e1273f0e29b43c4c148b2b8b7e").into(),
                    receipts_root: hex!("4cbc48e87389399a0ea0b382b1c46962c4b8e398014bf0cc610f9c672bee3155").into(),
                    state_root: hex!("017d7fa2b5adb480f5e05b2c95cb4186e12062eed893fc8822798eed134329d1").into(),
                    transactions: vec![first_transaction_raw, second_transaction_raw],
                },
                withdrawals: vec![],
            },
            blob_gas_used: 0xc0000,
            excess_blob_gas: 0x580000,
        };

        let (added_validators, removed_validators) = create_test_validators();
        let block = Block::<ed25519::PrivateKey, MinPk>::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            payload,
            vec![Default::default()],
            U256::ZERO,
            42,
            1,
            Some([0u8; 32].into()),
            [0u8; 32].into(),
            added_validators,
            removed_validators,
        );

        let encoded = block.encode();

        let decoded = Block::decode(encoded).unwrap();

        assert_eq!(block, decoded);
    }

    #[test]
    fn test_empty_tx_encode_decode() {
        let payload = ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas:  U256::ZERO,
                    block_number: 0,
                    block_hash: hex!("a5ddd3f286f429458a39cafc13ffe89295a7efa8eb363cf89a1a4887dbcf272b").into(),
                    logs_bloom: hex!("00200004000000000000000080000000000200000000000000000000000000000000200000000000000000000000000000000000800000000200000000000000000000000000000000000008000000200000000000000000000001000000000000000000000000000000800000000000000000000100000000000030000000000000000040000000000000000000000000000000000800080080404000000000000008000000000008200000000000200000000000000000000000000000000000000002000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000100000000000000000000").into(),
                    extra_data: hex!("d883010d03846765746888676f312e32312e31856c696e7578").into(),
                    gas_limit: 0,
                    gas_used: 0,
                    timestamp: 0,
                    fee_recipient: hex!("f97e180c050e5ab072211ad2c213eb5aee4df134").into(),
                    parent_hash: hex!("d829192799c73ef28a7332313b3c03af1f2d5da2c36f8ecfafe7a83a3bfb8d1e").into(),
                    prev_randao: hex!("753888cc4adfbeb9e24e01c84233f9d204f4a9e1273f0e29b43c4c148b2b8b7e").into(),
                    receipts_root: hex!("4cbc48e87389399a0ea0b382b1c46962c4b8e398014bf0cc610f9c672bee3155").into(),
                    state_root: hex!("017d7fa2b5adb480f5e05b2c95cb4186e12062eed893fc8822798eed134329d1").into(),
                    transactions: Vec::new(),
                },
                withdrawals: vec![],
            },
            blob_gas_used: 0xc0000,
            excess_blob_gas: 0x580000,
        };

        let (added_validators, removed_validators) = create_test_validators();
        let block = Block::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            payload,
            Vec::new(),
            U256::ZERO,
            42,
            1,
            Some([0u8; 32].into()),
            [0u8; 32].into(),
            added_validators,
            removed_validators,
        );

        let encoded = block.encode();

        let decoded = Block::<ed25519::PrivateKey, MinPk>::decode(encoded).unwrap();

        assert_eq!(block, decoded);
    }

    #[test]
    fn test_serialization() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);

        let bytes = block.encode();

        Block::<ed25519::PrivateKey, MinPk>::decode(bytes).unwrap();
    }

    #[test]
    fn test_block_encode_size() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);

        let ssz_len = block.ssz_bytes_len();
        let encode_len = block.encode_size();
        let actual_encoded = block.encode();

        // Also check pure SSZ encoding
        let pure_ssz = block.as_ssz_bytes();

        assert_eq!(
            pure_ssz.len(),
            ssz_len,
            "SSZ calculation should match actual SSZ encoding"
        );
        // The Write implementation adds a 4-byte length prefix
        assert_eq!(actual_encoded.len(), pure_ssz.len() + 4);
        assert_eq!(actual_encoded.len(), encode_len);
    }

    #[test]
    fn test_block_envelope_without_finalization() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);
        let envelope = BlockWithFinalization {
            block: block.clone(),
            finalized: None,
        };

        // Test encoding and decoding
        let encoded = envelope.encode();
        let decoded =
            BlockWithFinalization::<ed25519::PrivateKey, MinPk>::decode(encoded.clone()).unwrap();

        // Verify round-trip: encode the decoded value and compare bytes
        let re_encoded = decoded.encode();
        assert_eq!(
            encoded, re_encoded,
            "Round-trip encoding should be identical"
        );

        // Verify structure
        assert!(decoded.finalized.is_none());
        assert_eq!(envelope.block.header.height, decoded.block.header.height);
        assert_eq!(
            envelope.block.header.timestamp,
            decoded.block.header.timestamp
        );
    }

    #[test]
    fn test_block_envelope_encode_size_without_finalization() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);
        let envelope = BlockWithFinalization {
            block: block.clone(),
            finalized: None,
        };

        let encode_size = envelope.encode_size();
        let actual_encoded = envelope.encode();

        // Size should be block size + 1 byte for the flag
        assert_eq!(actual_encoded.len(), encode_size);
        assert_eq!(encode_size, block.encode_size() + 1);
    }

    #[test]
    fn test_block_envelope_digestible() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);
        let envelope = BlockWithFinalization {
            block: block.clone(),
            finalized: None,
        };

        // BlockEnvelope digest should match the underlying block digest
        assert_eq!(envelope.digest(), block.digest());
        assert_eq!(envelope.commitment(), block.commitment());
    }

    #[test]
    fn test_block_envelope_consensus_block() {
        let block = Block::<ed25519::PrivateKey, MinPk>::genesis([0; 32]);
        let envelope = BlockWithFinalization {
            block: block.clone(),
            finalized: None,
        };

        // BlockEnvelope should expose the same ConsensusBlock properties as the underlying block
        assert_eq!(envelope.height(), block.height());
        assert_eq!(envelope.parent(), block.parent());
    }
}
