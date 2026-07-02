#![no_main]

//! Fuzz target for `Block::read_cfg`.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::Block;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = Block::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = Block::read(&mut rebuf).expect("encoded Block must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "Block encode is not idempotent across a roundtrip",
    );
});
