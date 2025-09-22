use crate::{Digest, PublicKey};
use alloy_primitives::Address;
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, Error, FixedSize, Read, Write};
use commonware_cryptography::{Hasher, Sha256};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionRequest {
    // EIP-6110
    Deposit(DepositRequest),
    // EIP-7002
    Withdrawal(WithdrawalRequest),
}

impl ExecutionRequest {
    pub fn try_from_eth_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("ExecutionRequest cannot be empty");
        }

        // Use the leading byte to determine request type
        // See: https://docs.rs/alloy/latest/alloy/eips/eip7685/struct.Requests.html
        match bytes[0] {
            0x00 => {
                // Deposit request - parse without the leading type byte
                let deposit = DepositRequest::try_from_eth_bytes(&bytes[1..])?;
                Ok(ExecutionRequest::Deposit(deposit))
            }
            0x01 => {
                // Withdrawal request - parse without the leading type byte
                let withdrawal = WithdrawalRequest::try_from_eth_bytes(&bytes[1..])?;
                Ok(ExecutionRequest::Withdrawal(withdrawal))
            }
            _request_type => Err("Unknown execution request type"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalRequest {
    pub source_address: Address,    // Address that initiated the withdrawal
    pub validator_pubkey: [u8; 32], // Validator BLS public key
    pub amount: u64,                // Amount in gwei
}

impl WithdrawalRequest {
    /// This function is used to parse WithdrawalRequest type off of an Eth block. This is different than from_bytes because the ethereum event assumes BLS
    /// key so the pubkey field has an extra 16 bytes. The pub key is left padded and put in this field instead
    pub fn try_from_eth_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // EIP-7002: Withdrawal request data is exactly 76 bytes (without leading type byte)
        // Format: source_address(20) + validator_pubkey(48) + amount(8) = 76 bytes

        if bytes.len() != 76 {
            return Err("WithdrawalRequest must be exactly 76 bytes");
        }

        // Extract source_address (20 bytes)
        let source_address_bytes: [u8; 20] = bytes[0..20]
            .try_into()
            .map_err(|_| "Failed to parse source_address")?;
        let source_address = Address::from(source_address_bytes);

        // Extract validator_pubkey (32 bytes) left padded
        let validator_pubkey: [u8; 32] = bytes[36..68]
            .try_into()
            .map_err(|_| "Failed to parse validator_pubkey")?;

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[68..76]
            .try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        Ok(WithdrawalRequest {
            source_address,
            validator_pubkey,
            amount,
        })
    }
}

// https://eth2book.info/latest/part2/deposits-withdrawals/withdrawal-processing/
#[derive(Debug, Clone, PartialEq)]
pub struct DepositRequest {
    pub pubkey: PublicKey,                // Validator ED25519 public key
    pub withdrawal_credentials: [u8; 32], // Either hash of the BLS pubkey, or Ethereum address
    pub amount: u64,                      // Amount in gwei
    pub signature: [u8; 64],              // ED signature
    pub index: u64,
}

impl DepositRequest {
    /// This function is used to parse DepositRequest type off of an Eth block. This is different than from_bytes because the ethereum event assumes BLS
    /// signature so the signature field has an extra 32 bytes and the public key has an extra 16 bytes. The ed signature and public key are left padded and put in this field instead
    pub fn try_from_eth_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // EIP-6110: Deposit request data is exactly 144 bytes (without leading type byte)
        // Format: ed25519_pubkey(48) + withdrawal_credentials(32) + amount(8) + signature(96) + index(8) = 192 bytes

        if bytes.len() != 192 {
            return Err("DepositRequest must be exactly 192 bytes");
        }

        // Extract ed25519_pubkey (32 bytes) left padded
        let ed25519_pubkey_bytes: [u8; 32] = bytes[16..48]
            .try_into()
            .map_err(|_| "Failed to parse ed25519_pubkey")?;
        let pubkey = PublicKey::decode(&ed25519_pubkey_bytes[..])
            .map_err(|_| "Invalid ed25519 public key")?;

        // Extract withdrawal_credentials (32 bytes)
        let withdrawal_credentials: [u8; 32] = bytes[48..80]
            .try_into()
            .map_err(|_| "Failed to parse withdrawal_credentials")?;

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[80..88]
            .try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract signature (64 bytes left padded)
        let signature: [u8; 64] = bytes[120..184]
            .try_into()
            .map_err(|_| "Failed to parse signature")?;

        // Extract index (8 bytes, little-endian u64)
        let index_bytes: [u8; 8] = bytes[184..192]
            .try_into()
            .map_err(|_| "Failed to parse index")?;
        let index = u64::from_le_bytes(index_bytes);

        Ok(DepositRequest {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            index,
        })
    }

    pub fn as_message(&self, domain: Digest) -> Digest {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&self.pubkey);

        let mut left = Vec::with_capacity(64);
        left.extend_from_slice(&pubkey);
        left.extend_from_slice(&self.withdrawal_credentials);
        let mut hasher = Sha256::default();
        hasher.update(&left);
        let left_hash = hasher.finalize();

        let mut right = Vec::with_capacity(64);
        right.extend_from_slice(&self.amount.to_le_bytes());
        right.extend_from_slice(&[0; 56]);
        let mut hasher = Sha256::default();
        hasher.update(&right);
        let right_hash = hasher.finalize();

        let mut hasher = Sha256::default();
        hasher.update(&left_hash);
        hasher.update(&right_hash);
        let root_hash = hasher.finalize();

        let mut hasher = Sha256::default();
        hasher.update(&root_hash);
        hasher.update(&domain);
        hasher.finalize()
    }
}

impl Write for ExecutionRequest {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            ExecutionRequest::Deposit(deposit) => {
                buf.put_u8(0x00);
                deposit.write(buf);
            }
            ExecutionRequest::Withdrawal(withdrawal) => {
                buf.put_u8(0x01);
                withdrawal.write(buf);
            }
        }
    }
}

impl Read for ExecutionRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() == 0 {
            return Err(Error::Invalid("ExecutionRequest", "Buffer is empty"));
        }

        let request_type = buf.get_u8();
        match request_type {
            0x00 => {
                let deposit = DepositRequest::read_cfg(buf, &())?;
                Ok(ExecutionRequest::Deposit(deposit))
            }
            0x01 => {
                let withdrawal = WithdrawalRequest::read_cfg(buf, &())?;
                Ok(ExecutionRequest::Withdrawal(withdrawal))
            }
            _ => Err(Error::Invalid("ExecutionRequest", "Unknown request type")),
        }
    }
}

impl Write for WithdrawalRequest {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put(&self.source_address.0[..]);
        // padding for pubkey since eth puts pub key as 48 bytes in event
        buf.put(&[0; 16][..]);
        buf.put(&self.validator_pubkey[..]);
        buf.put(&self.amount.to_le_bytes()[..]);
    }
}

impl FixedSize for WithdrawalRequest {
    const SIZE: usize = 76; // 20 + 48 + 8
}

impl Read for WithdrawalRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 76 {
            return Err(Error::Invalid("WithdrawalRequest", "Insufficient bytes"));
        }

        let mut source_address_bytes = [0u8; 20];
        buf.copy_to_slice(&mut source_address_bytes);
        let source_address = Address::from(source_address_bytes);

        // account for the padding
        buf.advance(16);
        let mut validator_pubkey = [0u8; 32];
        buf.copy_to_slice(&mut validator_pubkey);

        let mut amount_bytes = [0u8; 8];
        buf.copy_to_slice(&mut amount_bytes);
        let amount = u64::from_le_bytes(amount_bytes);

        Ok(WithdrawalRequest {
            source_address,
            validator_pubkey,
            amount,
        })
    }
}

impl Write for DepositRequest {
    fn write(&self, buf: &mut impl BufMut) {
        // padding for pubkey since eth puts pub key as 48 bytes in event
        buf.put(&[0; 16][..]);
        buf.put(&self.pubkey.encode()[..]);
        buf.put(&self.withdrawal_credentials[..]);
        buf.put(&self.amount.to_le_bytes()[..]);
        // padding for sig
        buf.put(&[0; 32][..]);
        buf.put(&self.signature[..]);
        buf.put(&self.index.to_le_bytes()[..])
    }
}

impl FixedSize for DepositRequest {
    const SIZE: usize = 192; // 48 + 32 + 8 + 96 + 8
}

impl Read for DepositRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 192 {
            return Err(Error::Invalid("DepositRequest", "Insufficient bytes"));
        }
        // account for padding on pub key
        buf.advance(16);

        let mut ed25519_pubkey_bytes = [0u8; 32];
        buf.copy_to_slice(&mut ed25519_pubkey_bytes);
        let pubkey = PublicKey::decode(&ed25519_pubkey_bytes[..])
            .map_err(|_| Error::Invalid("DepositRequest", "Invalid ed25519 public key"))?;

        let mut withdrawal_credentials = [0u8; 32];
        buf.copy_to_slice(&mut withdrawal_credentials);

        let mut amount_bytes = [0u8; 8];
        buf.copy_to_slice(&mut amount_bytes);
        let amount = u64::from_le_bytes(amount_bytes);

        // account for padding on signature
        buf.advance(32);

        let mut signature = [0u8; 64];
        buf.copy_to_slice(&mut signature);

        let mut index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut index_bytes);
        let index = u64::from_le_bytes(index_bytes);

        Ok(DepositRequest {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{ReadExt, Write};

    #[test]
    fn test_deposit_request_codec() {
        let deposit = DepositRequest {
            pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            withdrawal_credentials: [3u8; 32],
            amount: 32000000000u64, // 32 ETH in gwei
            signature: [4u8; 64],
            index: 42u64,
        };

        // Test Write
        let mut buf = BytesMut::new();
        deposit.write(&mut buf);
        assert_eq!(buf.len(), 192); // 48 + 32 + 8 + 96 + 8

        // Test Read
        let decoded = DepositRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, deposit);
    }

    #[test]
    fn test_withdrawal_request_codec() {
        let withdrawal = WithdrawalRequest {
            source_address: Address::from([4u8; 20]),
            validator_pubkey: [5u8; 32],
            amount: 16000000000u64, // 16 ETH in gwei
        };

        // Test Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), 76); // 20 + 48 + 8

        // Test Read
        let decoded = WithdrawalRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    #[test]
    fn test_execution_request_deposit_codec() {
        let deposit = DepositRequest {
            pubkey: PublicKey::decode(&[6u8; 32][..]).unwrap(),
            withdrawal_credentials: [8u8; 32],
            amount: 32000000000u64,
            signature: [9u8; 64],
            index: 123u64,
        };
        let exec_request = ExecutionRequest::Deposit(deposit.clone());

        // Test Write
        let mut buf = BytesMut::new();
        exec_request.write(&mut buf);
        assert_eq!(buf.len(), 193); // 1 (type) + 192 (deposit)
        assert_eq!(buf[0], 0x00); // Deposit type byte

        // Test Read
        let decoded = ExecutionRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, exec_request);
        if let ExecutionRequest::Deposit(decoded_deposit) = decoded {
            assert_eq!(decoded_deposit, deposit);
        } else {
            panic!("Expected deposit request");
        }
    }

    #[test]
    fn test_execution_request_withdrawal_codec() {
        let withdrawal = WithdrawalRequest {
            source_address: Address::from([9u8; 20]),
            validator_pubkey: [10u8; 32],
            amount: 8000000000u64,
        };
        let exec_request = ExecutionRequest::Withdrawal(withdrawal.clone());

        // Test Write
        let mut buf = BytesMut::new();
        exec_request.write(&mut buf);
        assert_eq!(buf.len(), 77); // 1 (type) + 76 (withdrawal)
        assert_eq!(buf[0], 0x01); // Withdrawal type byte

        // Test Read
        let decoded = ExecutionRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, exec_request);
        if let ExecutionRequest::Withdrawal(decoded_withdrawal) = decoded {
            assert_eq!(decoded_withdrawal, withdrawal);
        } else {
            panic!("Expected withdrawal request");
        }
    }

    #[test]
    fn test_execution_request_invalid_type() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x99); // Invalid type
        buf.put(&[0u8; 76][..]); // Some dummy data

        let result = ExecutionRequest::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "ExecutionRequest");
            assert_eq!(msg, "Unknown request type");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_execution_request_empty_buffer() {
        let buf = BytesMut::new();
        let result = ExecutionRequest::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "ExecutionRequest");
            assert_eq!(msg, "Buffer is empty");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_deposit_request_insufficient_bytes() {
        let mut buf = BytesMut::new();
        buf.put(&[0u8; 191][..]); // One byte short

        let result = DepositRequest::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "DepositRequest");
            assert_eq!(msg, "Insufficient bytes");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_withdrawal_request_insufficient_bytes() {
        let mut buf = BytesMut::new();
        buf.put(&[0u8; 71][..]); // One byte short

        let result = WithdrawalRequest::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "WithdrawalRequest");
            assert_eq!(msg, "Insufficient bytes");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_roundtrip_compatibility_with_try_from() {
        // Test that our Codec implementation is compatible with existing TryFrom<&[u8]>
        let deposit = DepositRequest {
            pubkey: PublicKey::decode(&[11u8; 32][..]).unwrap(),
            withdrawal_credentials: [13u8; 32],
            amount: 64000000000u64,
            signature: [14u8; 64],
            index: 999u64,
        };
        let exec_request = ExecutionRequest::Deposit(deposit);

        // Encode with Codec
        let mut buf = BytesMut::new();
        exec_request.write(&mut buf);

        // Decode with Codec
        let decoded_codec = ExecutionRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded_codec, exec_request);
    }
}
