use crate::execution_request::ProtocolParamRequest;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};

#[derive(Clone, Debug)]
pub enum ProtocolParam {
    MinimumStake(u64),
    MaximumStake(u64),
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
}
