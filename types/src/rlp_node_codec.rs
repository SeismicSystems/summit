//! Ethereum-compatible RLP [`NodeCodec`] for [`trie_db`].
//!
//! Ported from [hyperbridge/ethereum-triedb](https://github.com/polytope-labs/hyperbridge/blob/main/modules/trees/ethereum/src/node_codec.rs)
//! (originally from OpenEthereum, GPL-3.0). Adapted to use `[u8; 32]` instead of
//! `primitive_types::H256`.

use std::borrow::Borrow;

use rlp::{Prototype, Rlp, RlpStream};
use trie_db::{
    ChildReference, NodeCodec, TrieConfiguration, TrieLayout,
    node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
};

type KeccakHasher = keccak_hasher::KeccakHasher;

/// Ethereum empty trie root: `keccak256([0x80])`.
const HASHED_NULL_NODE: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Error type for RLP node codec operations.
#[derive(Debug)]
pub enum Error {
    /// RLP decoding error.
    Decode(rlp::DecoderError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Decode(e) => write!(f, "RLP decode error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rlp::DecoderError> for Error {
    fn from(e: rlp::DecoderError) -> Self {
        Error::Decode(e)
    }
}

/// Apply Ethereum hex-prefix encoding to a partial key from trie-db's `right_iter()`.
///
/// `right_iter()` yields raw packed nibbles: if odd, the first byte has the nibble in the
/// low 4 bits (via `pad_right`, i.e. `& 0x0F`). Hex-prefix prepends a flag nibble:
/// - Extension even: `0x00`, Extension odd: `0x1N`
/// - Leaf even: `0x20`, Leaf odd: `0x3N`
fn hex_prefix_encode(partial: &[u8], number_nibble: usize, is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2u8 } else { 0u8 };
    let odd = !number_nibble.is_multiple_of(2);
    let mut result = Vec::with_capacity(partial.len() + 1);
    if odd {
        // First byte from right_iter() has the first nibble in the low 4 bits
        // (upper 4 bits zeroed by pad_right). Combine flag with first nibble.
        let first_nibble = partial[0] & 0x0f;
        result.push((flag + 1) << 4 | first_nibble);
        result.extend_from_slice(&partial[1..]);
    } else {
        result.push(flag << 4);
        result.extend_from_slice(partial);
    }
    result
}

/// RLP-based [`NodeCodec`] producing Ethereum-compatible trie nodes.
#[derive(Default, Clone)]
pub struct RlpNodeCodec;

impl NodeCodec for RlpNodeCodec {
    type Error = Error;
    type HashOut = [u8; 32];

    fn hashed_null_node() -> Self::HashOut {
        HASHED_NULL_NODE
    }

    fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
        if data == HASHED_NULL_NODE {
            return Ok(NodePlan::Empty);
        }

        let r = Rlp::new(data);
        match r.prototype()? {
            // 2-item list: leaf or extension
            Prototype::List(2) => {
                let (rlp, offset) = r.at_with_offset(0)?;
                let (path_data, info) = (rlp.data()?, rlp.payload_info()?);

                let odd = path_data[0] & 16 == 16;
                let partial = if odd {
                    // Odd hex-prefix: flag nibble + first path nibble share byte.
                    // Include the flag byte, skip 1 nibble (the flag).
                    NibbleSlicePlan::new(
                        (offset + info.header_len)..(offset + info.header_len + info.value_len),
                        1,
                    )
                } else {
                    // Even hex-prefix: flag byte is standalone.
                    // Skip the flag byte entirely, offset 0.
                    NibbleSlicePlan::new(
                        (offset + info.header_len + 1)..(offset + info.header_len + info.value_len),
                        0,
                    )
                };
                let is_leaf = path_data[0] & 32 == 32;

                if is_leaf {
                    Ok(NodePlan::Leaf {
                        partial,
                        value: {
                            let (item, offset) = r.at_with_offset(1)?;
                            let i = item.payload_info()?;
                            ValuePlan::Inline(
                                (offset + i.header_len)..(offset + i.header_len + i.value_len),
                            )
                        },
                    })
                } else {
                    Ok(NodePlan::Extension {
                        partial,
                        child: {
                            let (item, offset) = r.at_with_offset(1)?;
                            let i = item.payload_info()?;
                            if i.value_len == 32 {
                                NodeHandlePlan::Hash(
                                    (offset + i.header_len)..(offset + i.header_len + i.value_len),
                                )
                            } else {
                                // Inline child: full RLP item
                                NodeHandlePlan::Inline(
                                    offset..(offset + i.header_len + i.value_len),
                                )
                            }
                        },
                    })
                }
            }
            // 17-item list: branch
            Prototype::List(17) => {
                let mut children: [Option<NodeHandlePlan>; 16] = std::array::from_fn(|_| None);

                for (index, child) in children.iter_mut().enumerate() {
                    let (item, offset) = r.at_with_offset(index)?;
                    let i = item.payload_info()?;
                    if !item.is_empty() {
                        if i.value_len == 32 {
                            // 32-byte hash reference
                            *child = Some(NodeHandlePlan::Hash(
                                (offset + i.header_len)..(offset + i.header_len + i.value_len),
                            ));
                        } else {
                            // Inline child: include the full RLP item (header + payload)
                            *child = Some(NodeHandlePlan::Inline(
                                offset..(offset + i.header_len + i.value_len),
                            ));
                        }
                    }
                }

                Ok(NodePlan::Branch {
                    children,
                    value: {
                        let (item, offset) = r.at_with_offset(16)?;
                        let i = item.payload_info()?;
                        if item.is_empty() {
                            None
                        } else {
                            Some(ValuePlan::Inline(
                                (offset + i.header_len)..(offset + i.header_len + i.value_len),
                            ))
                        }
                    },
                })
            }
            // Empty data
            Prototype::Data(0) => Ok(NodePlan::Empty),
            // Invalid
            _ => Err(rlp::DecoderError::Custom("RLP is not valid"))?,
        }
    }

    fn is_empty_node(data: &[u8]) -> bool {
        Rlp::new(data).is_empty()
    }

    fn empty_node() -> &'static [u8] {
        &[0x80]
    }

    fn leaf_node(partial: impl Iterator<Item = u8>, number_nibble: usize, value: Value) -> Vec<u8> {
        let partial: Vec<u8> = partial.collect();
        let hp = hex_prefix_encode(&partial, number_nibble, true);
        let mut stream = RlpStream::new_list(2);
        stream.append(&hp);
        let value = match value {
            Value::Node(bytes) | Value::Inline(bytes) => bytes,
        };
        stream.append(&value);
        stream.out().to_vec()
    }

    fn extension_node(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        child_ref: ChildReference<Self::HashOut>,
    ) -> Vec<u8> {
        let partial: Vec<u8> = partial.collect();
        let hp = hex_prefix_encode(&partial, number_nibble, false);
        let mut stream = RlpStream::new_list(2);
        stream.append(&hp);
        match child_ref {
            ChildReference::Hash(h) => stream.append(&h.as_ref()),
            ChildReference::Inline(inline_data, len) => {
                let bytes = &AsRef::<[u8]>::as_ref(&inline_data)[..len];
                if bytes.is_empty() {
                    stream.append_empty_data()
                } else {
                    stream.append_raw(bytes, 1)
                }
            }
        };
        stream.out().to_vec()
    }

    fn branch_node(
        children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        value: Option<Value>,
    ) -> Vec<u8> {
        let mut stream = RlpStream::new_list(17);
        for child_ref in children {
            match child_ref.borrow() {
                Some(c) => match c {
                    ChildReference::Hash(h) => stream.append(&h.as_ref()),
                    ChildReference::Inline(inline_data, len) => {
                        let bytes = &inline_data[..*len];
                        if bytes.is_empty() {
                            // Omitted child in compact proofs
                            stream.append_empty_data()
                        } else {
                            stream.append_raw(bytes, 1)
                        }
                    }
                },
                None => stream.append_empty_data(),
            };
        }
        if let Some(value) = value {
            let v = match value {
                Value::Node(bytes) | Value::Inline(bytes) => bytes,
            };
            stream.append(&v);
        } else {
            stream.append_empty_data();
        }
        stream.out().to_vec()
    }

    fn branch_node_nibbled(
        _partial: impl Iterator<Item = u8>,
        _number_nibble: usize,
        _children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
        _value: Option<Value>,
    ) -> Vec<u8> {
        unimplemented!("Ethereum branch nodes do not have partial keys")
    }
}

/// EIP-1186 compatible trie layout for Ethereum MPT.
#[derive(Default, Clone)]
pub struct EthLayout;

impl TrieLayout for EthLayout {
    const USE_EXTENSION: bool = true;
    const ALLOW_EMPTY: bool = false;
    const MAX_INLINE_VALUE: Option<u32> = None;
    type Hash = KeccakHasher;
    type Codec = RlpNodeCodec;
}

impl TrieConfiguration for EthLayout {}
