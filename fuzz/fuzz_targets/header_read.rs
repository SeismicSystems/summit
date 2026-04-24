#![no_main]

//! Fuzz target for `Header::read_cfg`.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::header::Header;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = Header::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded =
        Header::read(&mut rebuf).expect("encoded Header must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "Header encode is not idempotent across a roundtrip",
    );
});
