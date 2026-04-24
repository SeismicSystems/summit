#![no_main]

//! Fuzz target for `ProtocolParam::read`.
//!
//! Goals:
//!   1. Parsing arbitrary bytes must never panic — only return `Result`.
//!   2. When parsing succeeds, re-encoding must roundtrip to identical bytes
//!      (canonical encoding).

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::protocol_params::ProtocolParam;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(param) = ProtocolParam::read(&mut buf) else {
        return;
    };

    let encoded = param.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = ProtocolParam::read(&mut rebuf)
        .expect("encoded ProtocolParam must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "ProtocolParam encode is not idempotent across a roundtrip",
    );
});
