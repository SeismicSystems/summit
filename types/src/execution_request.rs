use crate::{Digest, PublicKey};
use alloy_primitives::{Address, U256};
use bytes::{Buf, BufMut};
use commonware_codec::{DecodeExt, Encode, Error, FixedSize, Read, Write};
use commonware_cryptography::{Hasher, Sha256, bls12381};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionRequest {
    // EIP-6110
    Deposit(DepositRequest),
    // EIP-7002
    Withdrawal(WithdrawalRequest),
    // Seismic execution request
    ProtocolParam(ProtocolParamRequest),
}

/// Refund metadata extracted from a 288-byte deposit chunk whose Ed25519 or
/// BLS key fields could not be decoded. Withdrawal credentials, amount, and
/// index live at fixed offsets and are recoverable from the raw chunk even
/// when key decoding fails.
#[derive(Debug, Clone, PartialEq)]
pub struct MalformedDepositRequest {
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub index: u64,
    pub reason: &'static str,
}

/// Per-chunk outcome of parsing a grouped EIP-7685 entry.
/// `MalformedDeposit` is parse-time only and never round-trips through the
/// Summit-internal codec — it exists so the finalizer can route a single
/// bad chunk through the refund branch instead of dropping every chunk in
/// the entry.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedExecutionRequest {
    Valid(ExecutionRequest),
    MalformedDeposit(MalformedDepositRequest),
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
            0xFF => {
                // Protocol param request - parse without the leading type byte
                let protocol_param = ProtocolParamRequest::try_from_eth_bytes(&bytes[1..])?;
                Ok(ExecutionRequest::ProtocolParam(protocol_param))
            }
            _request_type => Err("Unknown execution request type"),
        }
    }

    /// Parse a grouped EIP-7685 entry chunk-by-chunk. The outer `Err`
    /// captures entry-level structural failures (empty buffer, unknown type
    /// byte, length not a multiple of the per-chunk size). Within a `0x00`
    /// (deposit) entry, individual chunks whose Ed25519 / BLS keys cannot
    /// be decoded surface as `MalformedDeposit` carrying the refund
    /// metadata so the caller can isolate them from chunks that decoded
    /// cleanly.
    ///
    /// Reth's EIP-6110 extraction concatenates same-block deposit logs into
    /// one type-0x00 entry, so a single contract-accepted but
    /// parser-invalid deposit would otherwise poison every legitimate
    /// deposit alongside it.
    pub fn parse_eth_entry(bytes: &[u8]) -> Result<Vec<ParsedExecutionRequest>, &'static str> {
        if bytes.is_empty() {
            return Err("ExecutionRequest cannot be empty");
        }

        match bytes[0] {
            0x00 => {
                let body = &bytes[1..];
                if !body
                    .len()
                    .is_multiple_of(<DepositRequest as FixedSize>::SIZE)
                {
                    return Err("DepositRequest payload length must be a multiple of 288 bytes");
                }
                Ok(body
                    .chunks_exact(<DepositRequest as FixedSize>::SIZE)
                    .map(parse_deposit_chunk)
                    .collect())
            }
            0x01 => Ok(WithdrawalRequest::try_from_eth_entry_bytes(&bytes[1..])?
                .into_iter()
                .map(|w| ParsedExecutionRequest::Valid(ExecutionRequest::Withdrawal(w)))
                .collect()),
            0xFF => Ok(ProtocolParamRequest::try_from_eth_entry_bytes(&bytes[1..])?
                .into_iter()
                .map(|p| ParsedExecutionRequest::Valid(ExecutionRequest::ProtocolParam(p)))
                .collect()),
            _request_type => Err("Unknown execution request type"),
        }
    }
}

fn parse_deposit_chunk(chunk: &[u8]) -> ParsedExecutionRequest {
    match DepositRequest::try_from_eth_bytes(chunk) {
        Ok(deposit) => ParsedExecutionRequest::Valid(ExecutionRequest::Deposit(deposit)),
        Err(reason) => {
            // try_from_eth_bytes only fails for key-decode errors on a
            // 288-byte chunk, so these byte slices are guaranteed to be
            // extractable.
            let withdrawal_credentials: [u8; 32] =
                chunk[80..112].try_into().expect("288-byte deposit chunk");
            let amount =
                u64::from_le_bytes(chunk[112..120].try_into().expect("288-byte deposit chunk"));
            let index =
                u64::from_le_bytes(chunk[280..288].try_into().expect("288-byte deposit chunk"));
            ParsedExecutionRequest::MalformedDeposit(MalformedDepositRequest {
                withdrawal_credentials,
                amount,
                index,
                reason,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalRequest {
    pub source_address: Address,    // Address that initiated the withdrawal
    pub validator_pubkey: [u8; 32], // Validator ed25519 public key
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

    pub fn try_from_eth_entry_bytes(bytes: &[u8]) -> Result<Vec<Self>, &'static str> {
        if !bytes.len().is_multiple_of(<Self as FixedSize>::SIZE) {
            return Err("WithdrawalRequest payload length must be a multiple of 76 bytes");
        }

        bytes
            .chunks_exact(<Self as FixedSize>::SIZE)
            .map(Self::try_from_eth_bytes)
            .collect()
    }
}

// https://eth2book.info/latest/part2/deposits-withdrawals/withdrawal-processing/
#[derive(Debug, Clone, PartialEq)]
pub struct DepositRequest {
    pub node_pubkey: PublicKey,                // Node ED25519 public key
    pub consensus_pubkey: bls12381::PublicKey, // Consensus BLS public key
    pub withdrawal_credentials: [u8; 32],      // Either hash of the BLS pubkey, or Ethereum address
    pub amount: u64,                           // Amount in gwei
    pub node_signature: [u8; 64],              // ED25519 signature
    pub consensus_signature: [u8; 96],         // BLS signature
    pub index: u64,
}

impl DepositRequest {
    /// This function is used to parse the DepositRequest event from the execution layer.
    pub fn try_from_eth_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // EIP-6110 (modified): Deposit request data is exactly 288 bytes (without leading type byte)
        // Format: node_pubkey(32) + consensus_pubkey(48) + withdrawal_credentials(32) + amount(8) + node_signature(64) + consensus_signature(96) + index(8) = 288 bytes

        if bytes.len() != 288 {
            return Err("DepositRequest must be exactly 288 bytes");
        }

        // Extract node_pubkey (32 bytes ed25519)
        let node_pubkey_bytes: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| "Failed to parse node_pubkey")?;
        let node_pubkey =
            PublicKey::decode(&node_pubkey_bytes[..]).map_err(|_| "Invalid ed25519 public key")?;

        // Extract consensus_pubkey (48 bytes BLS)
        let consensus_pubkey_bytes: [u8; 48] = bytes[32..80]
            .try_into()
            .map_err(|_| "Failed to parse consensus_pubkey")?;
        let consensus_pubkey = bls12381::PublicKey::decode(&consensus_pubkey_bytes[..])
            .map_err(|_| "Invalid BLS public key")?;

        // Extract withdrawal_credentials (32 bytes)
        let withdrawal_credentials: [u8; 32] = bytes[80..112]
            .try_into()
            .map_err(|_| "Failed to parse withdrawal_credentials")?;

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[112..120]
            .try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract node_signature (64 bytes ed25519)
        let node_signature: [u8; 64] = bytes[120..184]
            .try_into()
            .map_err(|_| "Failed to parse node_signature")?;

        // Extract consensus_signature (96 bytes BLS)
        let consensus_signature: [u8; 96] = bytes[184..280]
            .try_into()
            .map_err(|_| "Failed to parse consensus_signature")?;

        // Extract index (8 bytes, little-endian u64)
        let index_bytes: [u8; 8] = bytes[280..288]
            .try_into()
            .map_err(|_| "Failed to parse index")?;
        let index = u64::from_le_bytes(index_bytes);

        Ok(DepositRequest {
            node_pubkey,
            consensus_pubkey,
            withdrawal_credentials,
            amount,
            node_signature,
            consensus_signature,
            index,
        })
    }

    pub fn try_from_eth_entry_bytes(bytes: &[u8]) -> Result<Vec<Self>, &'static str> {
        if !bytes.len().is_multiple_of(<Self as FixedSize>::SIZE) {
            return Err("DepositRequest payload length must be a multiple of 288 bytes");
        }

        bytes
            .chunks_exact(<Self as FixedSize>::SIZE)
            .map(Self::try_from_eth_bytes)
            .collect()
    }

    pub fn as_message(&self, domain: Digest) -> Digest {
        let mut node_pubkey_bytes = [0u8; 32];
        node_pubkey_bytes.copy_from_slice(&self.node_pubkey.encode());

        // Hash node_pubkey and consensus_pubkey together
        let mut left = Vec::with_capacity(80);
        left.extend_from_slice(&node_pubkey_bytes);
        left.extend_from_slice(&self.consensus_pubkey.encode());
        let mut hasher = Sha256::default();
        hasher.update(&left);
        let pubkeys_hash = hasher.finalize();

        // Hash pubkeys_hash with withdrawal_credentials
        let mut left = Vec::with_capacity(64);
        left.extend_from_slice(&pubkeys_hash);
        left.extend_from_slice(&self.withdrawal_credentials);
        let mut hasher = Sha256::default();
        hasher.update(&left);
        let left_hash = hasher.finalize();

        // Hash amount with padding
        let mut right = Vec::with_capacity(64);
        right.extend_from_slice(&self.amount.to_le_bytes());
        right.extend_from_slice(&[0; 56]);
        let mut hasher = Sha256::default();
        hasher.update(&right);
        let right_hash = hasher.finalize();

        // Combine left and right
        let mut hasher = Sha256::default();
        hasher.update(&left_hash);
        hasher.update(&right_hash);
        let root_hash = hasher.finalize();

        // Final hash with domain
        let mut hasher = Sha256::default();
        hasher.update(&root_hash);
        hasher.update(&domain);
        hasher.finalize()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolParamRequest {
    pub param_id: u8,   // The protocol param id
    pub param: Vec<u8>, // The protocol param value
}

impl ProtocolParamRequest {
    pub fn try_from_eth_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        // Format: param_id(1) + length(1) + param(variable)
        if bytes.len() < 2 {
            return Err("ProtocolParamRequest must be at least 2 bytes");
        }

        let param_id = bytes[0];
        let param_len = bytes[1] as usize;

        if bytes.len() != 2 + param_len {
            return Err("ProtocolParamRequest length mismatch");
        }

        let param = bytes[2..2 + param_len].to_vec();

        Ok(ProtocolParamRequest { param_id, param })
    }

    pub fn try_from_eth_entry_bytes(bytes: &[u8]) -> Result<Vec<Self>, &'static str> {
        let mut buf = bytes;
        let mut requests = Vec::new();

        while !buf.is_empty() {
            let request = Self::read_cfg(&mut buf, &())
                .map_err(|_| "Failed to parse grouped protocol param request payload")?;
            requests.push(request);
        }

        Ok(requests)
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
            ExecutionRequest::ProtocolParam(protocol_param) => {
                buf.put_u8(0xFF);
                protocol_param.write(buf);
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

        let request_type = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
        match request_type {
            0x00 => {
                let deposit = DepositRequest::read_cfg(buf, &())?;
                Ok(ExecutionRequest::Deposit(deposit))
            }
            0x01 => {
                let withdrawal = WithdrawalRequest::read_cfg(buf, &())?;
                Ok(ExecutionRequest::Withdrawal(withdrawal))
            }
            0xFF => {
                let protocol_param = ProtocolParamRequest::read_cfg(buf, &())?;
                Ok(ExecutionRequest::ProtocolParam(protocol_param))
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
        buf.try_copy_to_slice(&mut source_address_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let source_address = Address::from(source_address_bytes);

        // account for the padding
        if buf.remaining() < 16 {
            return Err(Error::EndOfBuffer);
        }
        buf.advance(16);
        let mut validator_pubkey = [0u8; 32];
        buf.try_copy_to_slice(&mut validator_pubkey)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut amount_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut amount_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
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
        buf.put(&self.node_pubkey.encode()[..]);
        buf.put(&self.consensus_pubkey.encode()[..]);
        buf.put(&self.withdrawal_credentials[..]);
        buf.put(&self.amount.to_le_bytes()[..]);
        buf.put(&self.node_signature[..]);
        buf.put(&self.consensus_signature[..]);
        buf.put(&self.index.to_le_bytes()[..])
    }
}

impl FixedSize for DepositRequest {
    const SIZE: usize = 288; // 32 + 48 + 32 + 8 + 64 + 96 + 8
}

impl Read for DepositRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 288 {
            return Err(Error::Invalid("DepositRequest", "Insufficient bytes"));
        }

        let mut node_pubkey_bytes = [0u8; 32];
        buf.try_copy_to_slice(&mut node_pubkey_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let node_pubkey = PublicKey::decode(&node_pubkey_bytes[..])
            .map_err(|_| Error::Invalid("DepositRequest", "Invalid ed25519 public key"))?;

        let mut consensus_pubkey_bytes = [0u8; 48];
        buf.try_copy_to_slice(&mut consensus_pubkey_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let consensus_pubkey = bls12381::PublicKey::decode(&consensus_pubkey_bytes[..])
            .map_err(|_| Error::Invalid("DepositRequest", "Invalid BLS public key"))?;

        let mut withdrawal_credentials = [0u8; 32];
        buf.try_copy_to_slice(&mut withdrawal_credentials)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut amount_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut amount_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let amount = u64::from_le_bytes(amount_bytes);

        let mut node_signature = [0u8; 64];
        buf.try_copy_to_slice(&mut node_signature)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut consensus_signature = [0u8; 96];
        buf.try_copy_to_slice(&mut consensus_signature)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut index_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut index_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let index = u64::from_le_bytes(index_bytes);

        Ok(DepositRequest {
            node_pubkey,
            consensus_pubkey,
            withdrawal_credentials,
            amount,
            node_signature,
            consensus_signature,
            index,
        })
    }
}

impl Write for ProtocolParamRequest {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.param_id);
        buf.put_u8(self.param.len() as u8);
        buf.put(&self.param[..]);
    }
}

impl Read for ProtocolParamRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Invalid(
                "ProtocolParamRequest",
                "Insufficient bytes for header",
            ));
        }

        let param_id = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
        let param_len = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)? as usize;

        if buf.remaining() < param_len {
            return Err(Error::Invalid(
                "ProtocolParamRequest",
                "Insufficient bytes for param data",
            ));
        }

        let mut param = vec![0u8; param_len];
        buf.try_copy_to_slice(&mut param)
            .map_err(|_| Error::EndOfBuffer)?;

        Ok(ProtocolParamRequest { param_id, param })
    }
}

pub fn compute_deposit_data_root(
    node_pubkey: &[u8; 32],
    consensus_pubkey: &[u8; 48],
    withdrawal_credentials: &[u8; 32],
    amount: U256,
    node_signature: &[u8; 64],
    consensus_signature: &[u8; 96],
) -> [u8; 32] {
    /*
    Solidity computation:
    bytes32 consensus_pubkey_hash = sha256(abi.encodePacked(consensus_pubkey, bytes16(0)));
    bytes32 pubkey_root = sha256(abi.encodePacked(node_pubkey, consensus_pubkey_hash));
    bytes32 node_signature_hash = sha256(node_signature);
    bytes32 consensus_signature_hash = sha256(abi.encodePacked(
        sha256(abi.encodePacked(consensus_signature[:64])),
        sha256(abi.encodePacked(consensus_signature[64:], bytes32(0)))
    ));
    bytes32 signature_root = sha256(abi.encodePacked(node_signature_hash, consensus_signature_hash));
    bytes32 node = sha256(abi.encodePacked(
        sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
        sha256(abi.encodePacked(amount, bytes24(0), signature_root))
    ));
    */

    // 1. consensus_pubkey_hash = sha256(consensus_pubkey || bytes16(0))
    let mut hasher = Sha256::new();
    hasher.update(consensus_pubkey);
    hasher.update(&[0u8; 16]); // bytes16(0)
    let consensus_pubkey_hash = hasher.finalize();

    // 2. pubkey_root = sha256(node_pubkey || consensus_pubkey_hash)
    let mut hasher = Sha256::new();
    hasher.update(node_pubkey);
    hasher.update(&consensus_pubkey_hash);
    let pubkey_root = hasher.finalize();

    // 3. node_signature_hash = sha256(node_signature)
    let mut hasher = Sha256::new();
    hasher.update(node_signature);
    let node_signature_hash = hasher.finalize();

    // 4. consensus_signature_hash = sha256(sha256(consensus_signature[0:64]) || sha256(consensus_signature[64:96] || bytes32(0)))
    let mut hasher = Sha256::new();
    hasher.update(&consensus_signature[0..64]);
    let consensus_sig_part1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&consensus_signature[64..96]);
    hasher.update(&[0u8; 32]); // bytes32(0)
    let consensus_sig_part2 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&consensus_sig_part1);
    hasher.update(&consensus_sig_part2);
    let consensus_signature_hash = hasher.finalize();

    // 5. signature_root = sha256(node_signature_hash || consensus_signature_hash)
    let mut hasher = Sha256::new();
    hasher.update(&node_signature_hash);
    hasher.update(&consensus_signature_hash);
    let signature_root = hasher.finalize();

    // 3. Convert amount to 8-byte little-endian (gwei)
    let amount_gwei = amount / U256::from(10).pow(U256::from(9)); // Convert wei to gwei
    let amount_u64 = amount_gwei.to::<u64>(); // Convert to u64 (should fit for reasonable amounts)
    let amount_bytes = amount_u64.to_le_bytes(); // 8 bytes little-endian

    // 4. node = sha256(sha256(pubkey_root || withdrawal_credentials) || sha256(amount || bytes24(0) || signature_root))
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_root);
    hasher.update(withdrawal_credentials);
    let left_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&amount_bytes);
    hasher.update(&[0u8; 24]); // bytes24(0)
    hasher.update(&signature_root);
    let right_node = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&left_node);
    hasher.update(&right_node);
    let deposit_data_root = hasher.finalize();

    let digest_bytes: &[u8] = deposit_data_root.as_ref();
    digest_bytes
        .try_into()
        .expect("SHA-256 digest is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{ReadExt, Write};
    use commonware_cryptography::Signer;

    #[test]
    fn test_deposit_request_codec() {
        let consensus_private_key = bls12381::PrivateKey::from_seed(1);
        let deposit = DepositRequest {
            node_pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            consensus_pubkey: consensus_private_key.public_key(),
            withdrawal_credentials: [3u8; 32],
            amount: 32000000000u64, // 32 ETH in gwei
            node_signature: [4u8; 64],
            consensus_signature: [5u8; 96],
            index: 42u64,
        };

        // Test Write
        let mut buf = BytesMut::new();
        deposit.write(&mut buf);
        assert_eq!(buf.len(), 288); // 32 + 48 + 32 + 8 + 64 + 96 + 8

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
    fn test_protocol_param_request_codec() {
        let protocol_param = ProtocolParamRequest {
            param_id: 1,
            param: b"test_parameter_value".to_vec(),
        };

        // Test Write
        let mut buf = BytesMut::new();
        protocol_param.write(&mut buf);
        assert_eq!(buf.len(), 22); // 1 (param_id) + 1 (length) + 20 (data)

        // Test Read
        let decoded = ProtocolParamRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, protocol_param);
        assert_eq!(decoded.param_id, 1);
        assert_eq!(decoded.param, b"test_parameter_value".to_vec());
    }

    #[test]
    fn test_execution_request_deposit_codec() {
        let consensus_private_key = bls12381::PrivateKey::from_seed(2);
        let deposit = DepositRequest {
            node_pubkey: PublicKey::decode(&[6u8; 32][..]).unwrap(),
            consensus_pubkey: consensus_private_key.public_key(),
            withdrawal_credentials: [8u8; 32],
            amount: 32000000000u64,
            node_signature: [9u8; 64],
            consensus_signature: [10u8; 96],
            index: 123u64,
        };
        let exec_request = ExecutionRequest::Deposit(deposit.clone());

        // Test Write
        let mut buf = BytesMut::new();
        exec_request.write(&mut buf);
        assert_eq!(buf.len(), 289); // 1 (type) + 288 (deposit)
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
    fn test_execution_request_protocol_param_codec() {
        let protocol_param = ProtocolParamRequest {
            param_id: 42,
            param: vec![1, 2, 3, 4, 5],
        };
        let exec_request = ExecutionRequest::ProtocolParam(protocol_param.clone());

        // Test Write
        let mut buf = BytesMut::new();
        exec_request.write(&mut buf);
        assert_eq!(buf.len(), 8); // 1 (type) + 1 (param_id) + 1 (length) + 5 (data)
        assert_eq!(buf[0], 0xFF); // ProtocolParam type byte

        // Test Read
        let decoded = ExecutionRequest::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, exec_request);
        if let ExecutionRequest::ProtocolParam(decoded_protocol_param) = decoded {
            assert_eq!(decoded_protocol_param, protocol_param);
        } else {
            panic!("Expected protocol param request");
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
        buf.put(&[0u8; 287][..]); // One byte short

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

    /// Build a valid 288-byte deposit chunk by serializing a real
    /// `DepositRequest` whose keys decode cleanly.
    fn valid_deposit_chunk(
        seed: u64,
        withdrawal_credentials: [u8; 32],
        amount: u64,
        index: u64,
    ) -> ([u8; 288], DepositRequest) {
        let node_private_key = commonware_cryptography::ed25519::PrivateKey::from_seed(seed);
        let consensus_private_key = bls12381::PrivateKey::from_seed(seed);
        let deposit = DepositRequest {
            node_pubkey: node_private_key.public_key(),
            consensus_pubkey: consensus_private_key.public_key(),
            withdrawal_credentials,
            amount,
            node_signature: [seed as u8; 64],
            consensus_signature: [seed as u8; 96],
            index,
        };
        let mut buf = BytesMut::new();
        deposit.write(&mut buf);
        let chunk: [u8; 288] = buf.as_ref().try_into().unwrap();
        (chunk, deposit)
    }

    /// Build a 288-byte chunk that the public deposit contract would accept
    /// (length / withdrawal-credentials shape look fine) but whose BLS
    /// consensus pubkey field bytes cannot be decoded as a G1 point. Returns
    /// the chunk together with the embedded refund metadata so the test can
    /// pin what the per-chunk parser should surface.
    fn parser_invalid_deposit_chunk(
        withdrawal_credentials: [u8; 32],
        amount: u64,
        index: u64,
    ) -> [u8; 288] {
        let mut chunk = [0u8; 288];
        // node_pubkey: 32 bytes that pass Ed25519 decoding (any byte pattern
        // works here — Ed25519 decode does not reject curve points up front).
        chunk[0..32].copy_from_slice(&[0x01u8; 32]);
        // consensus_pubkey: 48 bytes that fail BLS12-381 G1 decoding.
        // Compressed-form flag bits set but x coordinate = 2^381 - 1, which
        // is far above the field modulus p, so decode must reject.
        chunk[32] = 0x9F;
        for b in chunk.iter_mut().take(80).skip(33) {
            *b = 0xFF;
        }
        // withdrawal_credentials (32 bytes): copied verbatim by the parser.
        chunk[80..112].copy_from_slice(&withdrawal_credentials);
        // amount (8 bytes, little-endian).
        chunk[112..120].copy_from_slice(&amount.to_le_bytes());
        // node_signature (64 bytes) + consensus_signature (96 bytes): not
        // decoded at parse time; leave as zero.
        // index (8 bytes, little-endian).
        chunk[280..288].copy_from_slice(&index.to_le_bytes());
        chunk
    }

    /// Regression test for the grouped-deposit poisoning attack. Reth's
    /// EIP-6110 deposit extraction concatenates every same-block deposit
    /// log into a single type-0x00 EIP-7685 entry. Summit's per-chunk
    /// parser must surface the valid chunk as `Valid(Deposit(_))` and the
    /// contract-accepted-but-parser-invalid chunk as `MalformedDeposit(_)`
    /// carrying the refund metadata — without dropping either.
    #[test]
    fn parse_eth_entry_isolates_malformed_chunk_in_grouped_deposit_entry() {
        let valid_creds = [0x01u8; 32];
        let valid_amount = 32_000_000_000u64; // 32 ETH in gwei
        let valid_index = 7u64;
        let (valid_chunk, valid_deposit) =
            valid_deposit_chunk(11, valid_creds, valid_amount, valid_index);

        let bad_creds = [0x01u8; 32];
        let bad_amount = 1_000_000_000u64; // 1 ETH minimum
        let bad_index = 8u64;
        let bad_chunk = parser_invalid_deposit_chunk(bad_creds, bad_amount, bad_index);

        // Sanity: each chunk on its own behaves as we expect, so the
        // grouped-entry test below is exercising the poisoning path and
        // nothing else.
        assert!(
            DepositRequest::try_from_eth_bytes(&bad_chunk).is_err(),
            "test setup: parser_invalid_deposit_chunk did not fail decoding"
        );
        assert!(
            DepositRequest::try_from_eth_bytes(&valid_chunk).is_ok(),
            "test setup: valid_deposit_chunk did not parse on its own"
        );

        // Build the 0x00 entry the way Reth/EIP-6110 would: one type byte
        // followed by concatenated 288-byte chunks.
        let mut entry = vec![0x00];
        entry.extend_from_slice(&valid_chunk);
        entry.extend_from_slice(&bad_chunk);

        let parsed = ExecutionRequest::parse_eth_entry(&entry)
            .expect("entry-level structure is valid (length is a multiple of 288)");
        assert_eq!(parsed.len(), 2);

        match &parsed[0] {
            ParsedExecutionRequest::Valid(ExecutionRequest::Deposit(d)) => {
                assert_eq!(d, &valid_deposit)
            }
            other => panic!("valid chunk was not surfaced as Valid(Deposit): {other:?}"),
        }
        match &parsed[1] {
            ParsedExecutionRequest::MalformedDeposit(m) => {
                assert_eq!(m.withdrawal_credentials, bad_creds);
                assert_eq!(m.amount, bad_amount);
                assert_eq!(m.index, bad_index);
            }
            other => panic!("parser-invalid chunk was not surfaced as MalformedDeposit: {other:?}"),
        }
    }

    #[test]
    fn parse_eth_entry_rejects_deposit_entry_with_truncated_length() {
        // 1 (type byte) + 287 bytes is not a valid deposit entry — the body
        // must be a multiple of 288. This is an entry-level structural
        // failure that cannot be recovered per-chunk.
        let mut entry = vec![0x00];
        entry.extend_from_slice(&[0u8; 287]);
        let err = ExecutionRequest::parse_eth_entry(&entry).unwrap_err();
        assert!(err.contains("multiple of 288"), "unexpected error: {err}");
    }

    #[test]
    fn test_roundtrip_compatibility_with_try_from() {
        // Test that our Codec implementation is compatible with existing TryFrom<&[u8]>
        let consensus_private_key = bls12381::PrivateKey::from_seed(3);
        let deposit = DepositRequest {
            node_pubkey: PublicKey::decode(&[11u8; 32][..]).unwrap(),
            consensus_pubkey: consensus_private_key.public_key(),
            withdrawal_credentials: [13u8; 32],
            amount: 64000000000u64,
            node_signature: [14u8; 64],
            consensus_signature: [15u8; 96],
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
