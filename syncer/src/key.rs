use bytes::{Buf, BufMut};
use commonware_codec::{Error, FixedSize, Read, ReadExt, Write};
use commonware_utils::Array;
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use summit_types::Digest;

const SIZE: usize = u8::SIZE + Digest::SIZE;

pub enum Value {
    Notarized(u64),
    Finalized(u64),
    Digest(Digest),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct MultiIndex([u8; SIZE]);

impl MultiIndex {
    pub fn new(value: Value) -> Self {
        let mut bytes = [0; SIZE];
        match value {
            Value::Notarized(value) => {
                bytes[0] = 0;
                bytes[1..9].copy_from_slice(&value.to_be_bytes());
            }
            Value::Finalized(value) => {
                bytes[0] = 1;
                bytes[1..9].copy_from_slice(&value.to_be_bytes());
            }
            Value::Digest(digest) => {
                bytes[0] = 2;
                bytes[1..].copy_from_slice(&digest);
            }
        }
        Self(bytes)
    }

    pub fn to_value(&self) -> Value {
        match self.0[0] {
            0 => {
                let bytes: [u8; u64::SIZE] = self.0[1..9].try_into().unwrap();
                let value = u64::from_be_bytes(bytes);
                Value::Notarized(value)
            }
            1 => {
                let bytes: [u8; u64::SIZE] = self.0[1..9].try_into().unwrap();
                let value = u64::from_be_bytes(bytes);
                Value::Finalized(value)
            }
            2 => {
                let bytes: [u8; Digest::SIZE] = self.0[1..].try_into().unwrap();
                let digest = Digest::from(bytes);
                Value::Digest(digest)
            }
            _ => unreachable!(),
        }
    }
}

impl Array for MultiIndex {}

impl Write for MultiIndex {
    fn write(&self, writer: &mut impl BufMut) {
        writer.put_slice(&self.0);
    }
}

impl Read for MultiIndex {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let bytes = <[u8; SIZE]>::read(reader)?;
        Ok(Self(bytes))
    }
}

impl FixedSize for MultiIndex {
    const SIZE: usize = SIZE;
}

impl Debug for MultiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0[0] {
            0 => {
                let bytes: [u8; u64::SIZE] = self.0[1..9].try_into().unwrap();
                write!(f, "notarized({})", u64::from_be_bytes(bytes))
            }
            1 => {
                let bytes: [u8; u64::SIZE] = self.0[1..9].try_into().unwrap();
                write!(f, "finalized({})", u64::from_be_bytes(bytes))
            }
            2 => {
                let bytes: [u8; Digest::SIZE] = self.0[1..].try_into().unwrap();
                write!(f, "digest({})", Digest::from(bytes))
            }
            _ => unreachable!(),
        }
    }
}

impl Display for MultiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl AsRef<[u8]> for MultiIndex {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for MultiIndex {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Encode, DecodeExt};

    #[test]
    fn test_multi_index_value_serialization_consistency() {
        // Test that different value types serialize to different byte patterns
        let notarized = MultiIndex::new(Value::Notarized(42));
        let finalized = MultiIndex::new(Value::Finalized(42));
        let digest = MultiIndex::new(Value::Digest([42u8; 32].into()));
        
        // They should all be different despite similar inputs
        assert_ne!(notarized.as_ref(), finalized.as_ref());
        assert_ne!(notarized.as_ref(), digest.as_ref());
        assert_ne!(finalized.as_ref(), digest.as_ref());
        
        // Prefix bytes should be different
        assert_eq!(notarized.as_ref()[0], 0);
        assert_eq!(finalized.as_ref()[0], 1);
        assert_eq!(digest.as_ref()[0], 2);
    }

    #[test]
    fn test_multi_index_wire_format_stability() {
        // Test that the wire format is stable across serialization/deserialization
        let test_cases = vec![
            (Value::Notarized(u64::MAX), "notarized max value"),
            (Value::Finalized(0), "finalized zero"),
            (Value::Digest([0u8; 32].into()), "zero digest"),
            (Value::Digest([255u8; 32].into()), "max digest"),
        ];

        for (value, description) in test_cases {
            let original = MultiIndex::new(value);
            let encoded = original.encode();
            let decoded = MultiIndex::decode(encoded).unwrap();
            
            assert_eq!(original, decoded, "Failed wire format stability for {}", description);
        }
    }

    #[test]
    fn test_multi_index_ordering_semantics() {
        // Test that ordering follows consensus semantics: Notarized < Finalized < Digest
        let notarized_low = MultiIndex::new(Value::Notarized(1));
        let notarized_high = MultiIndex::new(Value::Notarized(1000));
        let finalized_low = MultiIndex::new(Value::Finalized(1));
        let digest_zero = MultiIndex::new(Value::Digest([0u8; 32].into()));
        let digest_max = MultiIndex::new(Value::Digest([255u8; 32].into()));
        
        // Type ordering should override value ordering
        assert!(notarized_high < finalized_low, "High notarized should come before low finalized");
        assert!(finalized_low < digest_zero, "Finalized should come before digest regardless of value");
        
        // Within same type, value ordering should apply
        assert!(notarized_low < notarized_high, "Lower notarized height should come first");
        assert!(digest_zero < digest_max, "Digest ordering should work lexicographically");
    }

    #[test]
    fn test_multi_index_big_endian_height_encoding() {
        // Test that heights are encoded in big-endian for proper lexicographic ordering
        let height_1 = MultiIndex::new(Value::Notarized(1));
        let height_256 = MultiIndex::new(Value::Notarized(256));
        let height_max = MultiIndex::new(Value::Notarized(u64::MAX));
        
        // Check that byte representation follows big-endian ordering
        assert!(height_1 < height_256, "Height 1 should be less than 256");
        assert!(height_256 < height_max, "Height 256 should be less than max");
        
        // Verify the actual byte encoding for height 256 (0x0100 in big-endian)
        let height_256_bytes = height_256.as_ref();
        assert_eq!(height_256_bytes[0], 0x00); // Type discriminator for Notarized
        assert_eq!(height_256_bytes[1], 0x00); // MSB of u64
        assert_eq!(height_256_bytes[7], 0x01); // Second to last byte (256 = 0x0100)
        assert_eq!(height_256_bytes[8], 0x00); // LSB of u64
    }
}
