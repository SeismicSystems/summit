use crate::execution_request::ProtocolParamRequest;
use alloy_primitives::Address;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};

pub const MIN_EPOCH_LENGTH: u64 = 10;
pub const MAX_EPOCH_LENGTH: u64 = 1_814_400;
pub const MIN_ALLOWED_TIMESTAMP_FUTURE_MS: u64 = 1_000;
pub const MAX_ALLOWED_TIMESTAMP_FUTURE_MS: u64 = 600_000;
pub const MIN_MAX_DEPOSITS_PER_EPOCH: u64 = 0;
pub const MAX_MAX_DEPOSITS_PER_EPOCH: u64 = 256;
pub const MAX_WITHDRAWALS_PER_EPOCH_MIN: u64 = 1;
pub const MAX_WITHDRAWALS_PER_EPOCH_MAX: u64 = 256;
pub const MIN_OBSERVERS_PER_VALIDATOR: u64 = 0;
pub const MAX_OBSERVERS_PER_VALIDATOR: u64 = 256;
pub const MIN_MINIMUM_VALIDATOR_COUNT: u64 = 1;
pub const DEFAULT_MINIMUM_VALIDATOR_COUNT: u64 = 3;
// Bounds on the genesis `max_message_size_bytes`. The floor must be large enough
// to carry the largest legitimate P2P message (full blocks dominate; checkpoints
// scale with validator count); below it, large-block sync stalls. The ceiling
// bounds per-message allocation (anti-DoS) and stays well under `u32::MAX`, which
// is the hard limit imposed by the `as u32` conversion at the p2p config boundary.
pub const MAX_MESSAGE_SIZE_BYTES_MIN: u64 = 1 << 20; // 1 MiB
pub const MAX_MESSAGE_SIZE_BYTES_MAX: u64 = 1 << 30; // 1 GiB
pub const MIN_INVALID_DEPOSIT_TAX: u64 = 0;
pub const MAX_INVALID_DEPOSIT_TAX: u64 = 100;

#[derive(Clone, Debug)]
pub enum ProtocolParam {
    MinimumStake(u64),
    EpochLength(u64),
    AllowedTimestampFuture(u64),
    TreasuryAddress(Address),
    MaxDepositsPerEpoch(u64),
    MaxWithdrawalsPerEpoch(u64),
    ObserversPerValidator(u64),
    MinimumValidatorCount(u64),
    InvalidDepositTax(u64),
}

/// A protocol-parameter value that fell outside its allowed bounds.
///
/// This is the single source of truth for per-parameter value bounds, shared by
/// every site that validates a [`ProtocolParam`]: the execution-request parse path
/// ([`TryFrom<ProtocolParamRequest>`](ProtocolParam), the codec decode path
/// ([`Read`]), and genesis validation. Each caller maps it into its own error
/// type — [`reason`](Self::reason) yields the `&'static str` the codec layer
/// requires, while [`Display`](std::fmt::Display) carries the offending value for
/// the human-facing (anyhow / genesis) paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamBoundsError {
    EpochLength(u64),
    AllowedTimestampFuture(u64),
    MaxDepositsPerEpoch(u64),
    MaxWithdrawalsPerEpoch(u64),
    ObserversPerValidator(u64),
}

impl ParamBoundsError {
    /// Stable, value-free reason string. Required by [`commonware_codec::Error::Invalid`],
    /// which only accepts `&'static str` and so cannot carry the offending value.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::EpochLength(_) => "epoch length out of bounds",
            Self::AllowedTimestampFuture(_) => "allowed timestamp future out of bounds",
            Self::MaxDepositsPerEpoch(_) => "max deposits per epoch out of bounds",
            Self::MaxWithdrawalsPerEpoch(_) => "max withdrawals per epoch out of bounds",
            Self::ObserversPerValidator(_) => "observers per validator out of bounds",
        }
    }
}

impl std::fmt::Display for ParamBoundsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EpochLength(v) => write!(
                f,
                "epoch length {v} must be between {MIN_EPOCH_LENGTH} and {MAX_EPOCH_LENGTH}"
            ),
            Self::AllowedTimestampFuture(v) => write!(
                f,
                "allowed timestamp future {v}ms must be between {MIN_ALLOWED_TIMESTAMP_FUTURE_MS} and {MAX_ALLOWED_TIMESTAMP_FUTURE_MS}"
            ),
            Self::MaxDepositsPerEpoch(v) => write!(
                f,
                "max deposits per epoch {v} must not exceed {MAX_MAX_DEPOSITS_PER_EPOCH}"
            ),
            Self::MaxWithdrawalsPerEpoch(v) => write!(
                f,
                "max withdrawals per epoch {v} must be between {MAX_WITHDRAWALS_PER_EPOCH_MIN} and {MAX_WITHDRAWALS_PER_EPOCH_MAX}"
            ),
            Self::ObserversPerValidator(v) => write!(
                f,
                "observers per validator {v} must not exceed {MAX_OBSERVERS_PER_VALIDATOR}"
            ),
        }
    }
}

impl std::error::Error for ParamBoundsError {}

impl ProtocolParam {
    /// Validate this parameter's value against its protocol bounds.
    ///
    /// The authoritative per-parameter bounds check. Every construction site
    /// ([`TryFrom<ProtocolParamRequest>`](ProtocolParam), [`Read`], genesis) calls
    /// this so the numeric bounds live in exactly one place. Variants without a
    /// scalar bound ([`MinimumStake`](Self::MinimumStake),
    /// [`TreasuryAddress`](Self::TreasuryAddress)) always pass.
    pub fn validate(&self) -> Result<(), ParamBoundsError> {
        match *self {
            ProtocolParam::EpochLength(v)
                if !(MIN_EPOCH_LENGTH..=MAX_EPOCH_LENGTH).contains(&v) =>
            {
                Err(ParamBoundsError::EpochLength(v))
            }
            ProtocolParam::AllowedTimestampFuture(v)
                if !(MIN_ALLOWED_TIMESTAMP_FUTURE_MS..=MAX_ALLOWED_TIMESTAMP_FUTURE_MS)
                    .contains(&v) =>
            {
                Err(ParamBoundsError::AllowedTimestampFuture(v))
            }
            ProtocolParam::MaxDepositsPerEpoch(v) if v > MAX_MAX_DEPOSITS_PER_EPOCH => {
                Err(ParamBoundsError::MaxDepositsPerEpoch(v))
            }
            ProtocolParam::MaxWithdrawalsPerEpoch(v)
                if !(MAX_WITHDRAWALS_PER_EPOCH_MIN..=MAX_WITHDRAWALS_PER_EPOCH_MAX)
                    .contains(&v) =>
            {
                Err(ParamBoundsError::MaxWithdrawalsPerEpoch(v))
            }
            ProtocolParam::ObserversPerValidator(v) if v > MAX_OBSERVERS_PER_VALIDATOR => {
                Err(ParamBoundsError::ObserversPerValidator(v))
            }
            _ => Ok(()),
        }
    }
}

impl TryFrom<ProtocolParamRequest> for ProtocolParam {
    type Error = anyhow::Error;

    fn try_from(request: ProtocolParamRequest) -> anyhow::Result<Self> {
        match request.param_id {
            0x00 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse minimum stake protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let minimum_stake = u64::from_le_bytes(bytes);
                Ok(ProtocolParam::MinimumStake(minimum_stake))
            }

            0x01 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse epoch length protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let param = ProtocolParam::EpochLength(u64::from_le_bytes(bytes));
                param.validate().map_err(|e| anyhow!("{e}"))?;
                Ok(param)
            }
            0x02 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse allowed timestamp future protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let param = ProtocolParam::AllowedTimestampFuture(u64::from_le_bytes(bytes));
                param.validate().map_err(|e| anyhow!("{e}"))?;
                Ok(param)
            }
            0x03 => {
                if request.param.len() != 20 {
                    return Err(anyhow!(
                        "Failed to parse treasury address protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 20] = request.param.as_slice().try_into()?;
                Ok(ProtocolParam::TreasuryAddress(Address::from(bytes)))
            }
            0x04 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse max deposits per epoch protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let param = ProtocolParam::MaxDepositsPerEpoch(u64::from_le_bytes(bytes));
                param.validate().map_err(|e| anyhow!("{e}"))?;
                Ok(param)
            }
            0x05 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse max withdrawals per epoch protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let param = ProtocolParam::MaxWithdrawalsPerEpoch(u64::from_le_bytes(bytes));
                param.validate().map_err(|e| anyhow!("{e}"))?;
                Ok(param)
            }
            0x06 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse observers per validator protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let param = ProtocolParam::ObserversPerValidator(u64::from_le_bytes(bytes));
                param.validate().map_err(|e| anyhow!("{e}"))?;
                Ok(param)
            }
            0x07 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse minimum validator count protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let minimum_validator_count = u64::from_le_bytes(bytes);
                if minimum_validator_count < MIN_MINIMUM_VALIDATOR_COUNT {
                    return Err(anyhow!(
                        "Minimum validator count {minimum_validator_count} is below minimum {MIN_MINIMUM_VALIDATOR_COUNT}"
                    ));
                }
                Ok(ProtocolParam::MinimumValidatorCount(
                    minimum_validator_count,
                ))
            }
            0x08 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse invalid deposit tax protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let invalid_deposit_tax = u64::from_le_bytes(bytes);
                if invalid_deposit_tax > MAX_INVALID_DEPOSIT_TAX {
                    return Err(anyhow!(
                        "Invalid deposit tax {invalid_deposit_tax} exceeds maximum {MAX_INVALID_DEPOSIT_TAX}"
                    ));
                }
                Ok(ProtocolParam::InvalidDepositTax(invalid_deposit_tax))
            }
            _ => Err(anyhow!(
                "Failed to parse protocol param request - unknown param_id: {request:?}"
            )),
        }
    }
}

impl EncodeSize for ProtocolParam {
    fn encode_size(&self) -> usize {
        match self {
            ProtocolParam::MinimumStake(_)
            | ProtocolParam::EpochLength(_)
            | ProtocolParam::AllowedTimestampFuture(_)
            | ProtocolParam::MaxDepositsPerEpoch(_)
            | ProtocolParam::MaxWithdrawalsPerEpoch(_)
            | ProtocolParam::ObserversPerValidator(_)
            | ProtocolParam::MinimumValidatorCount(_)
            | ProtocolParam::InvalidDepositTax(_) => 1 + 8, // 1 byte tag + 8 byte value
            ProtocolParam::TreasuryAddress(_) => 1 + 20, // 1 byte tag + 20 byte address
        }
    }
}

impl Write for ProtocolParam {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            ProtocolParam::MinimumStake(value) => {
                buf.put_u8(0x00);
                buf.put_u64(*value);
            }
            ProtocolParam::EpochLength(value) => {
                buf.put_u8(0x01);
                buf.put_u64(*value);
            }
            ProtocolParam::AllowedTimestampFuture(value) => {
                buf.put_u8(0x02);
                buf.put_u64(*value);
            }
            ProtocolParam::TreasuryAddress(address) => {
                buf.put_u8(0x03);
                buf.put_slice(address.as_slice());
            }
            ProtocolParam::MaxDepositsPerEpoch(value) => {
                buf.put_u8(0x04);
                buf.put_u64(*value);
            }
            ProtocolParam::MaxWithdrawalsPerEpoch(value) => {
                buf.put_u8(0x05);
                buf.put_u64(*value);
            }
            ProtocolParam::ObserversPerValidator(value) => {
                buf.put_u8(0x06);
                buf.put_u64(*value);
            }
            ProtocolParam::MinimumValidatorCount(value) => {
                buf.put_u8(0x07);
                buf.put_u64(*value);
            }
            ProtocolParam::InvalidDepositTax(value) => {
                buf.put_u8(0x08);
                buf.put_u64(*value);
            }
        }
    }
}

impl Read for ProtocolParam {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
        match tag {
            0x00 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                Ok(ProtocolParam::MinimumStake(value))
            }
            0x01 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let param = ProtocolParam::EpochLength(value);
                param
                    .validate()
                    .map_err(|e| Error::Invalid("ProtocolParam", e.reason()))?;
                Ok(param)
            }
            0x02 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let param = ProtocolParam::AllowedTimestampFuture(value);
                param
                    .validate()
                    .map_err(|e| Error::Invalid("ProtocolParam", e.reason()))?;
                Ok(param)
            }
            0x03 => {
                let mut bytes = [0u8; 20];
                buf.try_copy_to_slice(&mut bytes)
                    .map_err(|_| Error::EndOfBuffer)?;
                Ok(ProtocolParam::TreasuryAddress(Address::from(bytes)))
            }
            0x04 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let param = ProtocolParam::MaxDepositsPerEpoch(value);
                param
                    .validate()
                    .map_err(|e| Error::Invalid("ProtocolParam", e.reason()))?;
                Ok(param)
            }
            0x05 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let param = ProtocolParam::MaxWithdrawalsPerEpoch(value);
                param
                    .validate()
                    .map_err(|e| Error::Invalid("ProtocolParam", e.reason()))?;
                Ok(param)
            }
            0x06 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                let param = ProtocolParam::ObserversPerValidator(value);
                param
                    .validate()
                    .map_err(|e| Error::Invalid("ProtocolParam", e.reason()))?;
                Ok(param)
            }
            0x07 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                if value < MIN_MINIMUM_VALIDATOR_COUNT {
                    return Err(Error::Invalid(
                        "ProtocolParam",
                        "minimum validator count out of bounds",
                    ));
                }
                Ok(ProtocolParam::MinimumValidatorCount(value))
            }
            0x08 => {
                let value = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
                if !(MIN_INVALID_DEPOSIT_TAX..=MAX_INVALID_DEPOSIT_TAX).contains(&value) {
                    return Err(Error::Invalid(
                        "ProtocolParam",
                        "invalid deposit tax out of bounds",
                    ));
                }
                Ok(ProtocolParam::InvalidDepositTax(value))
            }
            _ => Err(Error::Invalid("ProtocolParam", "unknown tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::ReadExt;

    #[test]
    fn test_minimum_stake_encode_decode() {
        let param = ProtocolParam::MinimumStake(32_000_000_000);

        // Test encoding
        let mut buf = BytesMut::new();
        param.write(&mut buf);

        // Verify encode_size matches actual size
        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9); // 1 byte tag + 8 byte value

        // Verify tag
        assert_eq!(buf[0], 0x00);

        // Test decoding
        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::MinimumStake(value) => assert_eq!(value, 32_000_000_000),
            _ => panic!("Expected MinimumStake variant"),
        }
    }

    #[test]
    fn test_encode_decode_zero_value() {
        let param = ProtocolParam::MinimumStake(0);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::MinimumStake(value) => assert_eq!(value, 0),
            _ => panic!("Expected MinimumStake variant"),
        }
    }

    #[test]
    fn test_encode_decode_max_value() {
        let param = ProtocolParam::MinimumStake(u64::MAX);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::MinimumStake(value) => assert_eq!(value, u64::MAX),
            _ => panic!("Expected MinimumStake variant"),
        }
    }

    #[test]
    fn test_invalid_tag() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF); // Invalid tag
        buf.put_u64(12345);

        let result = ProtocolParam::read(&mut buf.as_ref());
        assert!(result.is_err());

        match result {
            Err(Error::Invalid(entity, message)) => {
                assert_eq!(entity, "ProtocolParam");
                assert_eq!(message, "unknown tag");
            }
            _ => panic!("Expected Invalid error"),
        }
    }

    #[test]
    fn test_try_from_protocol_param_request_minimum_stake() {
        let request = ProtocolParamRequest {
            param_id: 0x00,
            param: 32_000_000_000u64.to_le_bytes().to_vec(),
        };

        let param = ProtocolParam::try_from(request).unwrap();

        match param {
            ProtocolParam::MinimumStake(value) => assert_eq!(value, 32_000_000_000),
            _ => panic!("Expected MinimumStake variant"),
        }
    }

    #[test]
    fn test_try_from_protocol_param_request_invalid_param_id() {
        let request = ProtocolParamRequest {
            param_id: 0xFF,
            param: 12345u64.to_le_bytes().to_vec(),
        };

        let result = ProtocolParam::try_from(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_protocol_param_request_invalid_length() {
        let request = ProtocolParamRequest {
            param_id: 0x00,
            param: vec![0x01, 0x02, 0x03], // Only 3 bytes instead of 8
        };

        let result = ProtocolParam::try_from(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_size_consistency() {
        let params = vec![
            ProtocolParam::MinimumStake(100),
            ProtocolParam::MinimumStake(0),
            ProtocolParam::MinimumValidatorCount(3),
        ];

        for param in params {
            let mut buf = BytesMut::new();
            param.write(&mut buf);
            assert_eq!(buf.len(), param.encode_size());
        }
    }

    #[test]
    fn test_multiple_params_sequential_encoding() {
        let params = vec![
            ProtocolParam::MinimumStake(32_000_000_000),
            ProtocolParam::MinimumValidatorCount(5),
        ];

        let mut buf = BytesMut::new();
        for param in &params {
            param.write(&mut buf);
        }

        // Decode them back
        let mut read_buf = buf.as_ref();
        let decoded1 = ProtocolParam::read(&mut read_buf).unwrap();
        let decoded2 = ProtocolParam::read(&mut read_buf).unwrap();

        match decoded1 {
            ProtocolParam::MinimumStake(value) => assert_eq!(value, 32_000_000_000),
            _ => panic!("Expected MinimumStake variant"),
        }

        match decoded2 {
            ProtocolParam::MinimumValidatorCount(value) => assert_eq!(value, 5),
            _ => panic!("Expected MinimumValidatorCount variant"),
        }
    }

    #[test]
    fn test_epoch_length_encode_decode() {
        let param = ProtocolParam::EpochLength(500);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x01);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::EpochLength(value) => assert_eq!(value, 500),
            _ => panic!("Expected EpochLength variant"),
        }
    }

    #[test]
    fn test_try_from_protocol_param_request_epoch_length() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: 100u64.to_le_bytes().to_vec(),
        };

        let param = ProtocolParam::try_from(request).unwrap();

        match param {
            ProtocolParam::EpochLength(value) => assert_eq!(value, 100),
            _ => panic!("Expected EpochLength variant"),
        }
    }

    #[test]
    fn test_try_from_protocol_param_request_epoch_length_zero() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: 0u64.to_le_bytes().to_vec(),
        };

        let result = ProtocolParam::try_from(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_epoch_length_below_minimum() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: (MIN_EPOCH_LENGTH - 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_try_from_epoch_length_at_minimum() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: MIN_EPOCH_LENGTH.to_le_bytes().to_vec(),
        };
        let param = ProtocolParam::try_from(request).unwrap();
        match param {
            ProtocolParam::EpochLength(v) => assert_eq!(v, MIN_EPOCH_LENGTH),
            _ => panic!("Expected EpochLength"),
        }
    }

    #[test]
    fn test_try_from_epoch_length_above_maximum() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: (MAX_EPOCH_LENGTH + 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_try_from_epoch_length_at_maximum() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: MAX_EPOCH_LENGTH.to_le_bytes().to_vec(),
        };
        let param = ProtocolParam::try_from(request).unwrap();
        match param {
            ProtocolParam::EpochLength(v) => assert_eq!(v, MAX_EPOCH_LENGTH),
            _ => panic!("Expected EpochLength"),
        }
    }

    #[test]
    fn test_decode_epoch_length_out_of_bounds() {
        // Below minimum
        let mut buf = BytesMut::new();
        buf.put_u8(0x01);
        buf.put_u64(1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());

        // Above maximum
        let mut buf = BytesMut::new();
        buf.put_u8(0x01);
        buf.put_u64(MAX_EPOCH_LENGTH + 1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
    }

    #[test]
    fn test_decode_epoch_length_within_bounds() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01);
        buf.put_u64(500);
        let param = ProtocolParam::read(&mut buf.as_ref()).unwrap();
        match param {
            ProtocolParam::EpochLength(v) => assert_eq!(v, 500),
            _ => panic!("Expected EpochLength"),
        }
    }

    /// All three construction paths share `ProtocolParam::validate`, so an
    /// out-of-bounds value must be rejected identically by the validator itself,
    /// the execution-request parse path, and the codec decode path. This guards
    /// against the centralized validator silently loosening any one path.
    #[test]
    fn all_entry_points_reject_same_out_of_bounds_value() {
        let below_min = MIN_EPOCH_LENGTH - 1;
        let above_max = MAX_EPOCH_LENGTH + 1;

        for bad in [below_min, above_max] {
            // 1. The param validator directly.
            assert!(ProtocolParam::EpochLength(bad).validate().is_err());

            // 2. The execution-request parse path.
            let request = ProtocolParamRequest {
                param_id: 0x01,
                param: bad.to_le_bytes().to_vec(),
            };
            assert!(ProtocolParam::try_from(request).is_err());

            // 3. The codec decode path.
            let mut buf = BytesMut::new();
            buf.put_u8(0x01);
            buf.put_u64(bad);
            assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
        }

        // A within-bounds value passes all three.
        let good = MIN_EPOCH_LENGTH;
        assert!(ProtocolParam::EpochLength(good).validate().is_ok());
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: good.to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_ok());
        let mut buf = BytesMut::new();
        buf.put_u8(0x01);
        buf.put_u64(good);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_ok());
    }

    #[test]
    fn test_observers_per_validator_encode_decode() {
        let param = ProtocolParam::ObserversPerValidator(7);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x06);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();
        match decoded {
            ProtocolParam::ObserversPerValidator(v) => assert_eq!(v, 7),
            _ => panic!("Expected ObserversPerValidator variant"),
        }
    }

    #[test]
    fn test_try_from_observers_per_validator() {
        let request = ProtocolParamRequest {
            param_id: 0x06,
            param: 5u64.to_le_bytes().to_vec(),
        };
        let param = ProtocolParam::try_from(request).unwrap();
        match param {
            ProtocolParam::ObserversPerValidator(v) => assert_eq!(v, 5),
            _ => panic!("Expected ObserversPerValidator variant"),
        }
    }

    #[test]
    fn test_try_from_observers_per_validator_above_maximum() {
        let request = ProtocolParamRequest {
            param_id: 0x06,
            param: (MAX_OBSERVERS_PER_VALIDATOR + 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_decode_observers_per_validator_out_of_bounds() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x06);
        buf.put_u64(MAX_OBSERVERS_PER_VALIDATOR + 1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
    }

    #[test]
    fn test_minimum_validator_count_encode_decode() {
        let param = ProtocolParam::MinimumValidatorCount(3);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x07);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();
        match decoded {
            ProtocolParam::MinimumValidatorCount(v) => assert_eq!(v, 3),
            _ => panic!("Expected MinimumValidatorCount variant"),
        }
    }

    #[test]
    fn test_try_from_minimum_validator_count() {
        let request = ProtocolParamRequest {
            param_id: 0x07,
            param: 5u64.to_le_bytes().to_vec(),
        };
        let param = ProtocolParam::try_from(request).unwrap();
        match param {
            ProtocolParam::MinimumValidatorCount(v) => assert_eq!(v, 5),
            _ => panic!("Expected MinimumValidatorCount variant"),
        }
    }

    #[test]
    fn test_minimum_validator_count_rejects_zero() {
        let request = ProtocolParamRequest {
            param_id: 0x07,
            param: 0u64.to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());

        let mut buf = BytesMut::new();
        buf.put_u8(0x07);
        buf.put_u64(0);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
    }

    #[test]
    fn test_invalid_deposit_tax_encode_decode() {
        let param = ProtocolParam::InvalidDepositTax(25);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x08);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();
        match decoded {
            ProtocolParam::InvalidDepositTax(v) => assert_eq!(v, 25),
            _ => panic!("Expected InvalidDepositTax variant"),
        }
    }

    #[test]
    fn test_try_from_invalid_deposit_tax_bounds() {
        for tax in [MIN_INVALID_DEPOSIT_TAX, 25, MAX_INVALID_DEPOSIT_TAX] {
            let request = ProtocolParamRequest {
                param_id: 0x08,
                param: tax.to_le_bytes().to_vec(),
            };
            let param = ProtocolParam::try_from(request).unwrap();
            match param {
                ProtocolParam::InvalidDepositTax(v) => assert_eq!(v, tax),
                _ => panic!("Expected InvalidDepositTax variant"),
            }
        }
    }

    #[test]
    fn test_try_from_invalid_deposit_tax_above_maximum() {
        let request = ProtocolParamRequest {
            param_id: 0x08,
            param: (MAX_INVALID_DEPOSIT_TAX + 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_decode_invalid_deposit_tax_out_of_bounds() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x08);
        buf.put_u64(MAX_INVALID_DEPOSIT_TAX + 1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
    }

    #[test]
    fn test_decode_truncated_input_returns_err() {
        // Empty buffer — must not panic.
        let empty: &[u8] = &[];
        assert!(matches!(
            ProtocolParam::read(&mut empty.as_ref()),
            Err(Error::EndOfBuffer)
        ));

        // Tag only, no payload.
        for tag in 0x00u8..=0x08 {
            let mut buf = BytesMut::new();
            buf.put_u8(tag);
            assert!(
                matches!(
                    ProtocolParam::read(&mut buf.as_ref()),
                    Err(Error::EndOfBuffer)
                ),
                "tag {tag:#x} must return EndOfBuffer on truncated payload"
            );
        }

        // Tag + partial u64 (7 bytes instead of 8).
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        buf.put_slice(&[0u8; 7]);
        assert!(matches!(
            ProtocolParam::read(&mut buf.as_ref()),
            Err(Error::EndOfBuffer)
        ));

        // Treasury address tag + truncated 20-byte payload.
        let mut buf = BytesMut::new();
        buf.put_u8(0x03);
        buf.put_slice(&[0u8; 19]);
        assert!(matches!(
            ProtocolParam::read(&mut buf.as_ref()),
            Err(Error::EndOfBuffer)
        ));
    }
}
