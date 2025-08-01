use std::ops::Deref as _;

use alloy_consensus::{Block as AlloyBlock, TxEnvelope};
use alloy_primitives::{Bytes as AlloyBytes, U256};
use alloy_rpc_types_engine::ExecutionPayloadV3;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize as _, Read, ReadExt as _, Write};
use commonware_consensus::Block as Bl;
use commonware_consensus::{
    Viewable,
    threshold_simplex::types::{Finalization, Notarization},
};
use commonware_cryptography::{
    Committable, Digestible, Hasher, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest,
};
use ssz::Encode as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent: Digest,

    pub height: u64,

    pub timestamp: u64,

    pub payload: ExecutionPayloadV3,

    pub execution_requests: Vec<AlloyBytes>,
    pub block_value: U256,

    // precomputed digest of this block
    pub digest: Digest,
}

impl Block {
    pub fn eth_block_hash(&self) -> [u8; 32] {
        // if genesis return your own digest
        if self.height == 0 {
            self.digest.as_ref().try_into().unwrap()
        } else {
            self.payload.payload_inner.payload_inner.block_hash.into()
        }
    }

    pub fn eth_parent_hash(&self) -> [u8; 32] {
        self.payload.payload_inner.payload_inner.parent_hash.into()
    }

    pub fn compute_digest(
        parent: Digest,
        height: u64,
        timestamp: u64,
        payload: ExecutionPayloadV3,
        execution_requests: Vec<AlloyBytes>,
        block_value: U256,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&parent);
        hasher.update(&height.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&payload.as_ssz_bytes());
        hasher.update(&execution_requests.as_ssz_bytes());
        hasher.update(&block_value.as_ssz_bytes());
        let digest = hasher.finalize();

        Self {
            parent,
            height,
            timestamp,
            payload,
            execution_requests,
            block_value,
            digest,
        }
    }

    pub fn genesis(genesis_hash: [u8; 32]) -> Self {
        Self {
            execution_requests: Default::default(),
            digest: genesis_hash.into(),
            parent: genesis_hash.into(),
            height: 0,
            timestamp: 0,
            payload: ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default()),
            block_value: U256::ZERO,
        }
    }
}

impl Bl for Block {
    fn height(&self) -> u64 {
        self.height
    }

    fn parent(&self) -> Self::Commitment {
        self.parent
    }
}

impl Viewable for Block {
    type View = u64;

    fn view(&self) -> commonware_consensus::simplex::types::View {
        self.height
    }
}

impl ssz::Encode for Block {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = <[u8; 32] as ssz::Encode>::ssz_fixed_len()
            + <u64 as ssz::Encode>::ssz_fixed_len() * 2
            + <ExecutionPayloadV3 as ssz::Encode>::ssz_fixed_len()
            + <Vec<AlloyBytes> as ssz::Encode>::ssz_fixed_len()
            + <U256 as ssz::Encode>::ssz_fixed_len();

        let mut encoder = ssz::SszEncoder::container(buf, offset);

        // todo: safe unwrap unless we change digest size. Reason for this is because Digest.0 is private in commonware and it only derefs into [u8] instead of the [u8; DIGEST_LENGTH] that we want
        let fixed_sized_digest: [u8; 32] = self
            .parent
            .deref()
            .try_into()
            .expect("Safe unwrap unless we change digest size");

        encoder.append(&fixed_sized_digest);
        encoder.append(&self.height);
        encoder.append(&self.timestamp);
        encoder.append(&self.payload);
        encoder.append(&self.execution_requests);
        encoder.append(&self.block_value);

        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        Digest::SIZE
            + self.height.ssz_bytes_len()
            + self.timestamp.ssz_bytes_len()
            + self.payload.ssz_bytes_len()
            + self.execution_requests.ssz_bytes_len()
            + ssz::BYTES_PER_LENGTH_OFFSET
            + self.block_value.ssz_bytes_len()
    }
}

impl ssz::Decode for Block {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<[u8; 32]>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<u64>()?;
        builder.register_type::<ExecutionPayloadV3>()?;
        builder.register_type::<Vec<AlloyBytes>>()?;
        builder.register_type::<U256>()?;

        let mut decoder = builder.build()?;

        let parent: [u8; 32] = decoder.decode_next()?;
        let height = decoder.decode_next()?;
        let timestamp = decoder.decode_next()?;
        let payload = decoder.decode_next()?;
        let execution_requests = decoder.decode_next()?;
        let block_value = decoder.decode_next()?;

        let block = Self::compute_digest(
            parent.into(),
            height,
            timestamp,
            payload,
            execution_requests,
            block_value,
        );
        Ok(block)
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + ssz::BYTES_PER_LENGTH_OFFSET * 2
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;
        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(&*self.as_ssz_bytes());
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let len = buf.get_u32();

        ssz::Decode::from_ssz_bytes(buf.copy_to_bytes(len as usize).chunk()).map_err(|_| {
            commonware_codec::Error::Invalid("Block", "Unable to decode bytes for block")
        })
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Committable for Block {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized {
    pub proof: Notarization<MinPk, Digest>,
    pub block: Block,
}

impl Notarized {
    pub fn new(proof: Notarization<MinPk, Digest>, block: Block) -> Self {
        Self { proof, block }
    }
}

impl Write for Notarized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Notarized {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::<MinPk, Digest>::read_cfg(buf, &())?; // todo: get a test on this to make sure buf.remaining is safe
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

impl EncodeSize for Notarized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub proof: Finalization<MinPk, Digest>,
    pub block: Block,
}

impl Finalized {
    pub fn new(proof: Finalization<MinPk, Digest>, block: Block) -> Self {
        Self { proof, block }
    }
}

impl Write for Finalized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Finalized {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::<MinPk, Digest>::read_cfg(buf, &())?;
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

impl EncodeSize for Finalized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_consensus::{Blob, Block as AlloyBlock, Bytes48, TxEnvelope};
    use alloy_primitives::{Bytes as AlloyBytes, FixedBytes, U256, fixed_bytes, hex};
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};
    use commonware_codec::{DecodeExt as _, Encode as _};
    #[test]
    fn test_encode_decode() {
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

        let block = Block::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            payload,
            vec![Default::default()],
            U256::ZERO,
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

        let block =
            Block::compute_digest([27u8; 32].into(), 27, 2727, payload, Vec::new(), U256::ZERO);

        let encoded = block.encode();

        let decoded = Block::decode(encoded).unwrap();

        assert_eq!(block, decoded);
    }

    #[test]
    fn test_serialization() {
        let block = Block::genesis([0; 32]);

        let bytes = block.encode();

        Block::decode(bytes).unwrap();
    }
}
