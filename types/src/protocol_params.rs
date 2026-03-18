use crate::execution_request::ProtocolParamRequest;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};

pub const MIN_EPOCH_LENGTH: u64 = 10;
pub const MAX_EPOCH_LENGTH: u64 = 1_814_400;
pub const MIN_ALLOWED_TIMESTAMP_FUTURE_MS: u64 = 1_000;
pub const MAX_ALLOWED_TIMESTAMP_FUTURE_MS: u64 = 600_000;

#[derive(Clone, Debug)]
pub enum ProtocolParam {
    MinimumStake(u64),
    MaximumStake(u64),
    EpochLength(u64),
    AllowedTimestampFuture(u64),
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
                        "Failed to parse maximum stake protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let maximum_stake = u64::from_le_bytes(bytes);
                Ok(ProtocolParam::MaximumStake(maximum_stake))
            }
            0x02 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse epoch length protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let epoch_length = u64::from_le_bytes(bytes);
                if epoch_length < MIN_EPOCH_LENGTH {
                    return Err(anyhow!(
                        "Epoch length {epoch_length} is below minimum {MIN_EPOCH_LENGTH}"
                    ));
                }
                if epoch_length > MAX_EPOCH_LENGTH {
                    return Err(anyhow!(
                        "Epoch length {epoch_length} exceeds maximum {MAX_EPOCH_LENGTH}"
                    ));
                }
                Ok(ProtocolParam::EpochLength(epoch_length))
            }
            0x03 => {
                if request.param.len() != 8 {
                    return Err(anyhow!(
                        "Failed to parse allowed timestamp future protocol param, invalid length {}",
                        request.param.len()
                    ));
                }
                let bytes: [u8; 8] = request.param.as_slice().try_into()?;
                let allowed_timestamp_future = u64::from_le_bytes(bytes);
                if allowed_timestamp_future < MIN_ALLOWED_TIMESTAMP_FUTURE_MS {
                    return Err(anyhow!(
                        "Allowed timestamp future {allowed_timestamp_future}ms is below minimum {MIN_ALLOWED_TIMESTAMP_FUTURE_MS}ms"
                    ));
                }
                if allowed_timestamp_future > MAX_ALLOWED_TIMESTAMP_FUTURE_MS {
                    return Err(anyhow!(
                        "Allowed timestamp future {allowed_timestamp_future}ms exceeds maximum {MAX_ALLOWED_TIMESTAMP_FUTURE_MS}ms"
                    ));
                }
                Ok(ProtocolParam::AllowedTimestampFuture(
                    allowed_timestamp_future,
                ))
            }
            _ => Err(anyhow!(
                "Failed to parse protocol param request - unknown param_id: {request:?}"
            )),
        }
    }
}

impl EncodeSize for ProtocolParam {
    fn encode_size(&self) -> usize {
        1 + 8 // 1 byte tag + 8 byte value for all current variants
    }
}

impl Write for ProtocolParam {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            ProtocolParam::MinimumStake(value) => {
                buf.put_u8(0x00);
                buf.put_u64(*value);
            }
            ProtocolParam::MaximumStake(value) => {
                buf.put_u8(0x01);
                buf.put_u64(*value);
            }
            ProtocolParam::EpochLength(value) => {
                buf.put_u8(0x02);
                buf.put_u64(*value);
            }
            ProtocolParam::AllowedTimestampFuture(value) => {
                buf.put_u8(0x03);
                buf.put_u64(*value);
            }
        }
    }
}

impl Read for ProtocolParam {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = buf.get_u8();
        let value = buf.get_u64();
        match tag {
            0x00 => Ok(ProtocolParam::MinimumStake(value)),
            0x01 => Ok(ProtocolParam::MaximumStake(value)),
            0x02 => {
                if !(MIN_EPOCH_LENGTH..=MAX_EPOCH_LENGTH).contains(&value) {
                    return Err(Error::Invalid(
                        "ProtocolParam",
                        "epoch length out of bounds",
                    ));
                }
                Ok(ProtocolParam::EpochLength(value))
            }
            0x03 => {
                if !(MIN_ALLOWED_TIMESTAMP_FUTURE_MS..=MAX_ALLOWED_TIMESTAMP_FUTURE_MS)
                    .contains(&value)
                {
                    return Err(Error::Invalid(
                        "ProtocolParam",
                        "allowed timestamp future out of bounds",
                    ));
                }
                Ok(ProtocolParam::AllowedTimestampFuture(value))
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
    fn test_maximum_stake_encode_decode() {
        let param = ProtocolParam::MaximumStake(64_000_000_000);

        // Test encoding
        let mut buf = BytesMut::new();
        param.write(&mut buf);

        // Verify encode_size matches actual size
        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9); // 1 byte tag + 8 byte value

        // Verify tag
        assert_eq!(buf[0], 0x01);

        // Test decoding
        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::MaximumStake(value) => assert_eq!(value, 64_000_000_000),
            _ => panic!("Expected MaximumStake variant"),
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
        let param = ProtocolParam::MaximumStake(u64::MAX);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::MaximumStake(value) => assert_eq!(value, u64::MAX),
            _ => panic!("Expected MaximumStake variant"),
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
    fn test_try_from_protocol_param_request_maximum_stake() {
        let request = ProtocolParamRequest {
            param_id: 0x01,
            param: 64_000_000_000u64.to_le_bytes().to_vec(),
        };

        let param = ProtocolParam::try_from(request).unwrap();

        match param {
            ProtocolParam::MaximumStake(value) => assert_eq!(value, 64_000_000_000),
            _ => panic!("Expected MaximumStake variant"),
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
            ProtocolParam::MaximumStake(200),
            ProtocolParam::MinimumStake(0),
            ProtocolParam::MaximumStake(u64::MAX),
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
            ProtocolParam::MaximumStake(64_000_000_000),
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
            ProtocolParam::MaximumStake(value) => assert_eq!(value, 64_000_000_000),
            _ => panic!("Expected MaximumStake variant"),
        }
    }

    #[test]
    fn test_epoch_length_encode_decode() {
        let param = ProtocolParam::EpochLength(500);

        let mut buf = BytesMut::new();
        param.write(&mut buf);

        assert_eq!(buf.len(), param.encode_size());
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0x02);

        let decoded = ProtocolParam::read(&mut buf.as_ref()).unwrap();

        match decoded {
            ProtocolParam::EpochLength(value) => assert_eq!(value, 500),
            _ => panic!("Expected EpochLength variant"),
        }
    }

    #[test]
    fn test_try_from_protocol_param_request_epoch_length() {
        let request = ProtocolParamRequest {
            param_id: 0x02,
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
            param_id: 0x02,
            param: 0u64.to_le_bytes().to_vec(),
        };

        let result = ProtocolParam::try_from(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_epoch_length_below_minimum() {
        let request = ProtocolParamRequest {
            param_id: 0x02,
            param: (MIN_EPOCH_LENGTH - 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_try_from_epoch_length_at_minimum() {
        let request = ProtocolParamRequest {
            param_id: 0x02,
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
            param_id: 0x02,
            param: (MAX_EPOCH_LENGTH + 1).to_le_bytes().to_vec(),
        };
        assert!(ProtocolParam::try_from(request).is_err());
    }

    #[test]
    fn test_try_from_epoch_length_at_maximum() {
        let request = ProtocolParamRequest {
            param_id: 0x02,
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
        buf.put_u8(0x02);
        buf.put_u64(1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());

        // Above maximum
        let mut buf = BytesMut::new();
        buf.put_u8(0x02);
        buf.put_u64(MAX_EPOCH_LENGTH + 1);
        assert!(ProtocolParam::read(&mut buf.as_ref()).is_err());
    }

    #[test]
    fn test_decode_epoch_length_within_bounds() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x02);
        buf.put_u64(500);
        let param = ProtocolParam::read(&mut buf.as_ref()).unwrap();
        match param {
            ProtocolParam::EpochLength(v) => assert_eq!(v, 500),
            _ => panic!("Expected EpochLength"),
        }
    }
}
