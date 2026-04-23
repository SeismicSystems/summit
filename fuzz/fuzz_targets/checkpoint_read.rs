#![no_main]

//! Fuzz target for `Checkpoint::read_cfg` — entry point for on-disk checkpoints.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::checkpoint::Checkpoint;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = Checkpoint::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded =
        Checkpoint::read(&mut rebuf).expect("encoded Checkpoint must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "Checkpoint encode is not idempotent across a roundtrip",
    );
});
