use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use bytes::{Buf, BufMut};
use commonware_codec::{Error, FixedSize, Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct PendingWithdrawal {
    pub inner: Withdrawal,
    pub withdrawal_height: u64,
    pub pubkey: [u8; 32],
}

impl TryFrom<&[u8]> for PendingWithdrawal {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // PendingWithdrawal data is exactly 100 bytes
        // Format: index(8) + validator_index(8) + address(20) + amount(8) + withdrawal_height(8) + bls_pubkey(32) = 84 bytes

        if bytes.len() != 84 {
            return Err("PendingWithdrawal must be exactly 84 bytes");
        }

        // Extract index (8 bytes, little-endian u64)
        let index_bytes: [u8; 8] = bytes[0..8]
            .try_into()
            .map_err(|_| "Failed to parse index")?;
        let index = u64::from_le_bytes(index_bytes);

        // Extract validator_index (8 bytes, little-endian u64)
        let validator_index_bytes: [u8; 8] = bytes[8..16]
            .try_into()
            .map_err(|_| "Failed to parse validator_index")?;
        let validator_index = u64::from_le_bytes(validator_index_bytes);

        // Extract address (20 bytes)
        let address_bytes: [u8; 20] = bytes[16..36]
            .try_into()
            .map_err(|_| "Failed to parse address")?;
        let address = Address::from(address_bytes);

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[36..44]
            .try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract withdrawal_height (8 bytes, little-endian u64)
        let withdrawal_height_bytes: [u8; 8] = bytes[44..52]
            .try_into()
            .map_err(|_| "Failed to parse withdrawal_height")?;
        let withdrawal_height = u64::from_le_bytes(withdrawal_height_bytes);

        // Extract bls_pubkey (48 bytes)
        let pubkey: [u8; 32] = bytes[52..84]
            .try_into()
            .map_err(|_| "Failed to parse bls_pubkey")?;

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            withdrawal_height,
            pubkey,
        })
    }
}

impl Write for PendingWithdrawal {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put(&self.inner.index.to_le_bytes()[..]);
        buf.put(&self.inner.validator_index.to_le_bytes()[..]);
        buf.put(&self.inner.address.0[..]);
        buf.put(&self.inner.amount.to_le_bytes()[..]);
        buf.put(&self.withdrawal_height.to_le_bytes()[..]);
        buf.put(&self.pubkey[..]);
    }
}

impl FixedSize for PendingWithdrawal {
    const SIZE: usize = 84; // 8 + 8 + 20 + 8 + 8 + 32 (added ed key)
}

impl Read for PendingWithdrawal {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 84 {
            return Err(Error::Invalid("PendingWithdrawal", "Insufficient bytes"));
        }

        let mut index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut index_bytes);
        let index = u64::from_le_bytes(index_bytes);

        let mut validator_index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut validator_index_bytes);
        let validator_index = u64::from_le_bytes(validator_index_bytes);

        let mut address_bytes = [0u8; 20];
        buf.copy_to_slice(&mut address_bytes);
        let address = Address::from(address_bytes);

        let mut amount_bytes = [0u8; 8];
        buf.copy_to_slice(&mut amount_bytes);
        let amount = u64::from_le_bytes(amount_bytes);

        let mut withdrawal_height_bytes = [0u8; 8];
        buf.copy_to_slice(&mut withdrawal_height_bytes);
        let withdrawal_height = u64::from_le_bytes(withdrawal_height_bytes);

        let mut pubkey = [0u8; 32];
        buf.copy_to_slice(&mut pubkey);

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            withdrawal_height,
            pubkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{ReadExt, Write};

    #[test]
    fn test_pending_withdrawal_codec() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 42u64,
                validator_index: 1337u64,
                address: Address::from([1u8; 20]),
                amount: 16000000000u64, // 16 ETH in gwei
            },
            withdrawal_height: 100,
            pubkey: [42u8; 32],
        };

        // Test Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), 84); // 8 + 8 + 20 + 8 + 8 + 32

        // Test Read
        let decoded = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    #[test]
    fn test_pending_withdrawal_try_from() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 123u64,
                validator_index: 456u64,
                address: Address::from([2u8; 20]),
                amount: 32000000000u64, // 32 ETH in gwei
            },
            withdrawal_height: 200,
            pubkey: [2u8; 32],
        };

        // Encode with Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        // Test TryFrom
        let decoded = PendingWithdrawal::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    #[test]
    fn test_pending_withdrawal_insufficient_bytes() {
        let mut buf = BytesMut::new();
        buf.put(&[0u8; 83][..]); // One byte short

        let result = PendingWithdrawal::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "PendingWithdrawal");
            assert_eq!(msg, "Insufficient bytes");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_pending_withdrawal_try_from_insufficient_bytes() {
        let buf = [0u8; 99]; // One byte short
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 84 bytes"
        );
    }

    #[test]
    fn test_pending_withdrawal_try_from_too_many_bytes() {
        let buf = [0u8; 101]; // One byte too many
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 84 bytes"
        );
    }

    #[test]
    fn test_pending_withdrawal_roundtrip_compatibility() {
        // Test that our Codec implementation is compatible with TryFrom<&[u8]>
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 999u64,
                validator_index: 777u64,
                address: Address::from([3u8; 20]),
                amount: 64000000000u64, // 64 ETH in gwei
            },
            withdrawal_height: 300,
            pubkey: [3u8; 32],
        };

        // Encode with Codec
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        // Decode with TryFrom
        let decoded_try_from = PendingWithdrawal::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded_try_from, withdrawal);

        // Decode with Codec
        let decoded_codec = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded_codec, withdrawal);
        assert_eq!(decoded_try_from, decoded_codec);
    }

    #[test]
    fn test_pending_withdrawal_fixed_size() {
        assert_eq!(PendingWithdrawal::SIZE, 84);

        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::ZERO,
                amount: 0,
            },
            withdrawal_height: 0,
            pubkey: [0u8; 32],
        };

        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), PendingWithdrawal::SIZE);
    }

    #[test]
    fn test_pending_withdrawal_field_ordering() {
        // Test that fields are encoded/decoded in the correct order
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0x0123456789abcdefu64,
                validator_index: 0xfedcba9876543210u64,
                address: Address::from([
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                    0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
                ]),
                amount: 0xa1b2c3d4e5f60708u64,
            },
            withdrawal_height: 500,
            pubkey: [5u8; 32],
        };

        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        let bytes = buf.as_ref();

        // Check index (first 8 bytes, little-endian)
        assert_eq!(&bytes[0..8], &0x0123456789abcdefu64.to_le_bytes());

        // Check validator_index (next 8 bytes, little-endian)
        assert_eq!(&bytes[8..16], &0xfedcba9876543210u64.to_le_bytes());

        // Check address (next 20 bytes)
        assert_eq!(
            &bytes[16..36],
            &[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x01, 0x02, 0x03, 0x04
            ]
        );

        // Check amount (next 8 bytes, little-endian)
        assert_eq!(&bytes[36..44], &0xa1b2c3d4e5f60708u64.to_le_bytes());

        // Check withdrawal_height (next 8 bytes, little-endian)
        assert_eq!(&bytes[44..52], &500u64.to_le_bytes());

        // Check bls_pubkey (last 48 bytes)
        assert_eq!(&bytes[52..84], &[5u8; 32]);

        // Verify roundtrip
        let decoded = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }
}
