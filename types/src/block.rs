use crate::{AddedValidator, Header, PublicKey};
use alloy_consensus::{Block as AlloyBlock, TxEnvelope};
use alloy_primitives::Bytes as AlloyBytes;
use alloy_rpc_types_engine::ExecutionPayloadV3;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::Viewable;
use commonware_consensus::types::{Epoch, Height, View};
use commonware_consensus::{Block as ConsensusBlock, Epochable, Heightable};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};
use ssz::Encode as _;
use ssz_derive::Encode;

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct Block {
    pub header: Header,
    pub payload: ExecutionPayloadV3,
    pub execution_requests: Vec<AlloyBytes>,
}

impl Block {
    pub fn eth_block_hash(&self) -> [u8; 32] {
        // if genesis return your own digest
        if self.header.height() == 0 {
            self.header.get_digest().as_ref().try_into().unwrap()
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
        epoch: u64,
        view: u64,
        checkpoint_hash: Option<Digest>,
        prev_epoch_header_hash: Digest,
        added_validators: Vec<AddedValidator>,
        removed_validators: Vec<PublicKey>,
        parent_beacon_block_root: [u8; 32],
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

        let header = Header::new(
            parent,
            height,
            timestamp,
            epoch,
            view,
            payload_hash,
            execution_request_hash,
            checkpoint_hash,
            prev_epoch_header_hash,
            added_validators,
            removed_validators,
            parent_beacon_block_root,
        );

        Self {
            header,
            payload,
            execution_requests,
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

        if payload_hash != header.payload_hash() {
            return Err(anyhow!("Payload hash mismatch"));
        }
        if execution_request_hash != header.execution_request_hash() {
            return Err(anyhow!("Execution request hash mismatch"));
        }
        Ok(Self {
            header,
            payload,
            execution_requests,
        })
    }

    pub fn genesis(genesis_hash: [u8; 32]) -> Self {
        let payload = ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default());
        let payload_ssz = payload.as_ssz_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&payload_ssz);
        let payload_hash = hasher.finalize();

        let header = Header::new_with_digest(
            genesis_hash.into(),
            0,
            0,
            0,
            1,
            payload_hash,
            [0; 32].into(),
            [0; 32].into(),
            [0; 32].into(),
            Vec::new(),
            Vec::new(),
            [0; 32],
            genesis_hash.into(),
        );
        Self {
            header,
            payload: ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default()),
            execution_requests: Default::default(),
        }
    }

    pub fn parent(&self) -> Digest {
        self.header.parent()
    }

    pub fn height(&self) -> u64 {
        self.header.height()
    }

    pub fn digest(&self) -> Digest {
        self.header.get_digest()
    }

    pub fn timestamp(&self) -> u64 {
        self.header.timestamp()
    }

    pub fn view(&self) -> u64 {
        self.header.view()
    }

    pub fn epoch(&self) -> u64 {
        self.header.epoch()
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        Height::new(self.header.height())
    }
}

impl Epochable for Block {
    fn epoch(&self) -> Epoch {
        Epoch::new(self.header.epoch())
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Self::Digest {
        self.header.parent()
    }
}

impl Viewable for Block {
    fn view(&self) -> View {
        View::new(self.header.view())
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.ssz_bytes_len() + 4 // We additionally write the ssz len as u32(bytes)
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        let ssz_bytes = &*self.as_ssz_bytes();
        let bytes_len = ssz_bytes.len() as u32;

        buf.put(&bytes_len.to_be_bytes()[..]);
        buf.put(ssz_bytes);
    }
}

// NOTE: `Decode` is implemented manually (rather than via `ssz_derive`) so that
// decoding re-derives the body commitments and verifies them against the header
// via `new_with_verify`. Without this, SSZ decode could produce a block whose
// `payload`/`execution_requests` do not match the `payload_hash`/
// `execution_request_hash` committed in the (signed) header. The block digest is
// computed solely from the header, so a mismatched body would otherwise share the
// same digest and pass certificate verification.
impl ssz::Decode for Block {
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

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        if len > buf.remaining() {
            return Err(Error::Invalid("Block", "improper encoded length"));
        }

        // Decode SSZ directly from the buffer's contiguous chunk to avoid
        // copying the (up to message-size) payload into a temporary Vec first.
        // `chunk()` returns the whole remaining slice for the contiguous buffers
        // used on the decode paths (`&[u8]`/`Bytes`); for a non-contiguous
        // buffer it may be shorter than `len`, in which case we fall back to a
        // single contiguous copy.
        if buf.chunk().len() >= len {
            let block = ssz::Decode::from_ssz_bytes(&buf.chunk()[..len])
                .map_err(|_| Error::Invalid("Block", "Unable to decode bytes for block"))?;
            buf.advance(len);
            Ok(block)
        } else {
            let mut payload = vec![0u8; len];
            buf.try_copy_to_slice(&mut payload)
                .map_err(|_| Error::EndOfBuffer)?;
            ssz::Decode::from_ssz_bytes(&payload)
                .map_err(|_| Error::Invalid("Block", "Unable to decode bytes for block"))
        }
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.header.get_digest()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::{Bytes as AlloyBytes, U256, hex};
    use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2};
    use commonware_codec::{DecodeExt as _, Encode as _, ReadExt};
    use commonware_cryptography::{Signer, bls12381};

    #[test]
    fn test_read_truncated_input_returns_err() {
        // No bytes / fewer than 4 length-prefix bytes must never panic.
        for n in 0..4 {
            let data = vec![0xFFu8; n];
            assert!(matches!(
                Block::read(&mut data.as_ref()),
                Err(Error::EndOfBuffer)
            ));
        }

        // Oversized length prefix is rejected as Invalid (no allocation attempt).
        let mut huge = Vec::new();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Block::read(&mut huge.as_ref()),
            Err(Error::Invalid("Block", _))
        ));
    }

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

    fn create_test_validators() -> (Vec<AddedValidator>, Vec<PublicKey>) {
        let added = vec![
            AddedValidator {
                node_key: create_test_public_key(20),
                consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
            },
            AddedValidator {
                node_key: create_test_public_key(21),
                consensus_key: bls12381::PrivateKey::from_seed(21).public_key(),
            },
        ];
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
        let block = Block::compute_digest(
            [27u8; 32].into(),
            27,
            2727,
            payload,
            vec![Default::default()],
            42,
            1,
            Some([0u8; 32].into()),
            [0u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
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
            42,
            1,
            Some([0u8; 32].into()),
            [0u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

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

    #[test]
    fn test_decode_rejects_body_header_commitment_mismatch() {
        let payload = ExecutionPayloadV3::from_block_slow(&AlloyBlock::<TxEnvelope>::default());
        let (added_validators, removed_validators) = create_test_validators();

        // Same header inputs, but different execution_requests -> different
        // execution_request_hash committed in the header.
        let block_full = Block::compute_digest(
            [1u8; 32].into(),
            1,
            1,
            payload.clone(),
            vec![AlloyBytes::from_static(&[1, 2, 3])],
            0,
            1,
            None,
            [0u8; 32].into(),
            added_validators.clone(),
            removed_validators.clone(),
            [0u8; 32],
        );
        let block_empty = Block::compute_digest(
            [1u8; 32].into(),
            1,
            1,
            payload,
            Vec::new(),
            0,
            1,
            None,
            [0u8; 32].into(),
            added_validators,
            removed_validators,
            [0u8; 32],
        );

        // Sanity: each block decodes back to itself.
        assert_eq!(
            block_full,
            Block::decode(block_full.encode()).expect("valid block decodes")
        );

        // Splice block_full's header (commits to a non-empty execution request)
        // onto block_empty's body (no execution requests). The SSZ bytes are
        // structurally valid but the header commitment no longer matches the body.
        let mut spliced = Vec::new();
        let mut encoder =
            ssz::SszEncoder::container(&mut spliced, ssz::BYTES_PER_LENGTH_OFFSET * 3);
        encoder.append(&block_full.header);
        encoder.append(&block_empty.payload);
        encoder.append(&block_empty.execution_requests);
        encoder.finalize();

        // Decode must reject the tampered block rather than silently accept a
        // body that disagrees with the signed header commitments.
        assert!(<Block as ssz::Decode>::from_ssz_bytes(&spliced).is_err());
    }

    #[test]
    fn test_block_encode_size() {
        let block = Block::genesis([0; 32]);

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

    /// Build a block whose encoded size is dominated by `extra_data`, so its
    /// total size can be tuned close to a target budget.
    fn block_with_extra_data(extra_len: usize) -> Block {
        let payload = ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas: U256::ZERO,
                    block_number: 1,
                    block_hash: [0u8; 32].into(),
                    logs_bloom: Default::default(),
                    extra_data: AlloyBytes::from(vec![0x11u8; extra_len]),
                    gas_limit: 0,
                    gas_used: 0,
                    timestamp: 1,
                    fee_recipient: Default::default(),
                    parent_hash: [0u8; 32].into(),
                    prev_randao: [0u8; 32].into(),
                    receipts_root: [0u8; 32].into(),
                    state_root: [0u8; 32].into(),
                    transactions: Vec::new(),
                },
                withdrawals: vec![],
            },
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        Block::compute_digest(
            [0u8; 32].into(),
            1,
            1,
            payload,
            Vec::new(),
            0,
            1,
            None,
            [0u8; 32].into(),
            Vec::new(),
            Vec::new(),
            [0u8; 32],
        )
    }

    /// #252 invariant, checked against the ACTUAL encoded resolver response.
    ///
    /// Finalized/notarized backfill is served as a single P2P message:
    /// `(Finalization, Block).encode()`. Proposed/verified/certified blocks are
    /// bounded to `max_message_size_bytes / 2` (application::max_block_size_bytes),
    /// so the other half must always cover the certificate + proposal framing.
    /// A Simplex certificate is one aggregate BLS signature plus an N-bit signer
    /// bitmap (~ceil(N/8)), so this holds with wide margin for realistic N.
    ///
    /// This pins that as a checked invariant rather than a static size proof: a
    /// max-budget block paired with a real certificate for a large validator set
    /// must still fit the cap. It fails loudly if certificate encoding/aggregation
    /// changes (e.g. per-signer signatures) or N grows past the reserved half.
    #[test]
    fn certificate_block_backfill_response_fits_message_cap() {
        use crate::protocol_params::MAX_MESSAGE_SIZE_BYTES_MIN;
        use commonware_consensus::simplex::scheme::bls12381_multisig;
        use commonware_consensus::simplex::types::{Finalization, Proposal};
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::bls12381::certificate::multisig::Certificate;
        use commonware_cryptography::bls12381::primitives::{
            group::Private,
            ops::{aggregate::Signature, sign_message},
            variant::MinPk,
        };
        use commonware_cryptography::certificate::Signers;
        use commonware_math::algebra::Random;
        use commonware_utils::Participant;
        use rand::{SeedableRng as _, rngs::StdRng};

        // Tightest configured cap (genesis floor); the block budget mirrors
        // application's max_block_size_bytes = max_message_size_bytes / 2.
        let cap = MAX_MESSAGE_SIZE_BYTES_MIN as usize;
        let block_budget = cap / 2;

        // A generous, realistic validator set: the signer bitmap is ceil(N/8).
        let n_validators = 10_000usize;

        // Build a valid block just under the block budget (small margin for SSZ
        // offset overhead), the largest block a proposer could legitimately emit.
        let base = block_with_extra_data(0).encode_size();
        let block = block_with_extra_data(block_budget - base - 64);
        assert!(
            block.encode_size() < block_budget,
            "test block ({}) must be a valid sub-budget block (< {block_budget})",
            block.encode_size()
        );

        let signature = {
            let mut rng = StdRng::seed_from_u64(42);
            let private = Private::random(&mut rng);
            let g2 = sign_message::<MinPk>(&private, b"", b"backfill-size-test");
            Signature::<MinPk>::decode(g2.encode()).expect("valid signature")
        };
        let proposal = Proposal {
            round: Round::new(Epoch::new(block.epoch()), View::new(block.view())),
            parent: View::new(block.height().saturating_sub(1)),
            payload: block.digest(),
        };
        let finalization: Finalization<bls12381_multisig::Scheme<PublicKey, MinPk>, Digest> =
            Finalization {
                proposal,
                certificate: Certificate::<MinPk> {
                    signers: Signers::from(n_validators, [0, 1, 2].map(Participant::new)),
                    signature: signature.into(),
                },
            };

        // The actual single-message finalized-backfill response the syncer serves.
        let response_size = (finalization, block).encode_size();
        assert!(
            response_size <= cap,
            "(certificate, block) backfill response ({response_size} bytes) must fit the P2P \
             message cap ({cap} bytes) for {n_validators} validators",
        );
    }
}
