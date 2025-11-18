use alloy_primitives::Address;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, Error, FixedSize, Read, Write};
use commonware_cryptography::bls12381;

#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    SubmittedExitRequest,
}

impl ValidatorStatus {
    fn to_u8(&self) -> u8 {
        match self {
            ValidatorStatus::Active => 0,
            ValidatorStatus::Inactive => 1,
            ValidatorStatus::SubmittedExitRequest => 2,
        }
    }

    fn from_u8(value: u8) -> Result<Self, &'static str> {
        match value {
            0 => Ok(ValidatorStatus::Active),
            1 => Ok(ValidatorStatus::Inactive),
            2 => Ok(ValidatorStatus::SubmittedExitRequest),
            _ => Err("Invalid ValidatorStatus value"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorAccount {
    pub consensus_public_key: bls12381::PublicKey, // BLS public key for consensus
    pub withdrawal_credentials: Address,           // Ethereum address
    pub balance: u64,                              // Balance in gwei
    pub pending_withdrawal_amount: u64,            // Sum of pending withdrawals in gwei
    pub status: ValidatorStatus,
    pub last_deposit_index: u64, // Last deposit request index
}

impl TryFrom<&[u8]> for ValidatorAccount {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // ValidatorAccount data is exactly 93 bytes
        // Format: consensus_public_key(48) + withdrawal_credentials(20) + balance(8) + pending_withdrawal_amount(8) + status(1) + last_deposit_index(8) = 93 bytes

        if bytes.len() != 93 {
            return Err("ValidatorAccount must be exactly 93 bytes");
        }

        // Extract consensus_public_key (48 bytes)
        let consensus_key_bytes: [u8; 48] = bytes[0..48]
            .try_into()
            .map_err(|_| "Failed to parse consensus_public_key")?;
        let consensus_public_key = bls12381::PublicKey::decode(&consensus_key_bytes[..])
            .map_err(|_| "Failed to decode consensus_public_key")?;

        // Extract withdrawal_credentials (20 bytes)
        let withdrawal_credentials_bytes: [u8; 20] = bytes[48..68]
            .try_into()
            .map_err(|_| "Failed to parse withdrawal_credentials")?;
        let withdrawal_credentials = Address::from(withdrawal_credentials_bytes);

        // Extract balance (8 bytes, little-endian u64)
        let balance_bytes: [u8; 8] = bytes[68..76]
            .try_into()
            .map_err(|_| "Failed to parse balance")?;
        let balance = u64::from_le_bytes(balance_bytes);

        // Extract pending_withdrawal_amount (8 bytes, little-endian u64)
        let pending_withdrawal_amount_bytes: [u8; 8] = bytes[76..84]
            .try_into()
            .map_err(|_| "Failed to parse pending_withdrawal_amount")?;
        let pending_withdrawal_amount = u64::from_le_bytes(pending_withdrawal_amount_bytes);

        // Extract status (1 byte)
        let status = ValidatorStatus::from_u8(bytes[84])?;

        // Extract last_deposit_index (8 bytes, little-endian u64)
        let last_deposit_index_bytes: [u8; 8] = bytes[85..93]
            .try_into()
            .map_err(|_| "Failed to parse last_deposit_index")?;
        let last_deposit_index = u64::from_le_bytes(last_deposit_index_bytes);

        Ok(ValidatorAccount {
            consensus_public_key,
            withdrawal_credentials,
            balance,
            pending_withdrawal_amount,
            status,
            last_deposit_index,
        })
    }
}

impl Write for ValidatorAccount {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put(&self.consensus_public_key.encode()[..]);
        buf.put(&self.withdrawal_credentials.0[..]);
        buf.put(&self.balance.to_le_bytes()[..]);
        buf.put(&self.pending_withdrawal_amount.to_le_bytes()[..]);
        buf.put_u8(self.status.to_u8());
        buf.put(&self.last_deposit_index.to_le_bytes()[..]);
    }
}

impl FixedSize for ValidatorAccount {
    const SIZE: usize = 93; // 48 + 20 + 8 + 8 + 1 + 8
}

impl Read for ValidatorAccount {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 93 {
            return Err(Error::Invalid("ValidatorAccount", "Insufficient bytes"));
        }

        let mut consensus_key_bytes = [0u8; 48];
        buf.copy_to_slice(&mut consensus_key_bytes);
        let consensus_public_key = bls12381::PublicKey::decode(&consensus_key_bytes[..])
            .map_err(|_| Error::Invalid("ValidatorAccount", "Invalid consensus public key"))?;

        let mut withdrawal_credentials_bytes = [0u8; 20];
        buf.copy_to_slice(&mut withdrawal_credentials_bytes);
        let withdrawal_credentials = Address::from(withdrawal_credentials_bytes);

        let mut balance_bytes = [0u8; 8];
        buf.copy_to_slice(&mut balance_bytes);
        let balance = u64::from_le_bytes(balance_bytes);

        let mut pending_withdrawal_amount_bytes = [0u8; 8];
        buf.copy_to_slice(&mut pending_withdrawal_amount_bytes);
        let pending_withdrawal_amount = u64::from_le_bytes(pending_withdrawal_amount_bytes);

        let status_byte = buf.get_u8();
        let status = ValidatorStatus::from_u8(status_byte)
            .map_err(|_| Error::Invalid("ValidatorAccount", "Invalid status value"))?;

        let mut last_deposit_index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut last_deposit_index_bytes);
        let last_deposit_index = u64::from_le_bytes(last_deposit_index_bytes);

        Ok(ValidatorAccount {
            consensus_public_key,
            withdrawal_credentials,
            balance,
            pending_withdrawal_amount,
            status,
            last_deposit_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{ReadExt, Write};
    use commonware_cryptography::{PrivateKeyExt, Signer};

    #[test]
    fn test_validator_account_codec() {
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        let account = ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([2u8; 20]),
            balance: 32000000000u64,                  // 32 ETH in gwei
            pending_withdrawal_amount: 1000000000u64, // 1 ETH in gwei
            status: ValidatorStatus::Active,
            last_deposit_index: 42u64,
        };

        // Test Write
        let mut buf = BytesMut::new();
        account.write(&mut buf);
        assert_eq!(buf.len(), ValidatorAccount::SIZE); // 48 + 20 + 8 + 8 + 1 + 8

        // Test Read
        let decoded = ValidatorAccount::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, account);
    }

    #[test]
    fn test_validator_account_try_from() {
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        let account = ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([4u8; 20]),
            balance: 64000000000u64,                  // 64 ETH in gwei
            pending_withdrawal_amount: 2000000000u64, // 2 ETH in gwei
            status: ValidatorStatus::Inactive,
            last_deposit_index: 100u64,
        };

        // Encode with Write
        let mut buf = BytesMut::new();
        account.write(&mut buf);

        // Test TryFrom
        let decoded = ValidatorAccount::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded, account);
    }

    #[test]
    fn test_validator_account_insufficient_bytes() {
        let mut buf = BytesMut::new();
        buf.put(&[0u8; 92][..]); // One byte short

        let result = ValidatorAccount::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "ValidatorAccount");
            assert_eq!(msg, "Insufficient bytes");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_validator_account_try_from_insufficient_bytes() {
        let buf = [0u8; 92]; // One byte short
        let result = ValidatorAccount::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "ValidatorAccount must be exactly 93 bytes"
        );
    }

    #[test]
    fn test_validator_account_try_from_too_many_bytes() {
        let buf = [0u8; 94]; // One byte too many
        let result = ValidatorAccount::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "ValidatorAccount must be exactly 93 bytes"
        );
    }

    #[test]
    fn test_validator_account_roundtrip_compatibility() {
        // Test that our Codec implementation is compatible with TryFrom<&[u8]>
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        let account = ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([6u8; 20]),
            balance: 128000000000u64,                 // 128 ETH in gwei
            pending_withdrawal_amount: 4000000000u64, // 4 ETH in gwei
            status: ValidatorStatus::SubmittedExitRequest,
            last_deposit_index: 500u64,
        };

        // Encode with Codec
        let mut buf = BytesMut::new();
        account.write(&mut buf);

        // Decode with TryFrom
        let decoded_try_from = ValidatorAccount::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded_try_from, account);

        // Decode with Codec
        let decoded_codec = ValidatorAccount::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded_codec, account);
        assert_eq!(decoded_try_from, decoded_codec);
    }

    #[test]
    fn test_validator_account_fixed_size() {
        assert_eq!(ValidatorAccount::SIZE, 93);

        let consensus_key = bls12381::PrivateKey::from_seed(1);
        let account = ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::ZERO,
            balance: 0,
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            last_deposit_index: 0,
        };

        let mut buf = BytesMut::new();
        account.write(&mut buf);
        assert_eq!(buf.len(), ValidatorAccount::SIZE);
    }

    #[test]
    fn test_validator_account_field_ordering() {
        // Test that fields are encoded/decoded in the correct order
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        let consensus_public_key = consensus_key.public_key();
        let account = ValidatorAccount {
            consensus_public_key: consensus_public_key.clone(),
            withdrawal_credentials: Address::from([
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            ]),
            balance: 0x0123456789abcdefu64,
            pending_withdrawal_amount: 0xfedcba9876543210u64,
            status: ValidatorStatus::SubmittedExitRequest,
            last_deposit_index: 0xa1b2c3d4e5f60708u64,
        };

        let mut buf = BytesMut::new();
        account.write(&mut buf);

        let bytes = buf.as_ref();

        // Check consensus_public_key (first 48 bytes)
        assert_eq!(&bytes[0..48], &consensus_public_key.encode());

        // Check withdrawal_credentials (next 20 bytes)
        assert_eq!(
            &bytes[48..68],
            &[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x01, 0x02, 0x03, 0x04
            ]
        );

        // Check balance (next 8 bytes, little-endian)
        assert_eq!(&bytes[68..76], &0x0123456789abcdefu64.to_le_bytes());

        // Check pending_withdrawal_amount (next 8 bytes, little-endian)
        assert_eq!(&bytes[76..84], &0xfedcba9876543210u64.to_le_bytes());

        // Check status (next 1 byte)
        assert_eq!(bytes[84], 2); // SubmittedExitRequest = 2

        // Check last_deposit_index (last 8 bytes, little-endian)
        assert_eq!(&bytes[85..93], &0xa1b2c3d4e5f60708u64.to_le_bytes());

        // Verify roundtrip
        let decoded = ValidatorAccount::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, account);
    }

    #[test]
    fn test_validator_status_conversion() {
        // Test status enum conversion
        assert_eq!(ValidatorStatus::Active.to_u8(), 0);
        assert_eq!(ValidatorStatus::Inactive.to_u8(), 1);
        assert_eq!(ValidatorStatus::SubmittedExitRequest.to_u8(), 2);

        assert_eq!(
            ValidatorStatus::from_u8(0).unwrap(),
            ValidatorStatus::Active
        );
        assert_eq!(
            ValidatorStatus::from_u8(1).unwrap(),
            ValidatorStatus::Inactive
        );
        assert_eq!(
            ValidatorStatus::from_u8(2).unwrap(),
            ValidatorStatus::SubmittedExitRequest
        );

        // Test invalid status
        assert!(ValidatorStatus::from_u8(3).is_err());
        assert!(ValidatorStatus::from_u8(255).is_err());
    }

    #[test]
    fn test_validator_account_invalid_status() {
        let mut buf = BytesMut::new();

        // Create a buffer with valid data except for an invalid status byte
        let consensus_key = bls12381::PrivateKey::from_seed(1);
        buf.put(&consensus_key.public_key().encode()[..]); // consensus_public_key
        buf.put(&[2u8; 20][..]); // withdrawal_credentials
        buf.put(&1000u64.to_le_bytes()[..]); // balance
        buf.put(&100u64.to_le_bytes()[..]); // pending_withdrawal_amount
        buf.put_u8(99); // invalid status
        buf.put(&42u64.to_le_bytes()[..]); // last_deposit_index

        let result = ValidatorAccount::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "ValidatorAccount");
            assert_eq!(msg, "Invalid status value");
        } else {
            panic!("Expected Invalid error for invalid status");
        }
    }
}
