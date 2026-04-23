#![no_main]

//! Fuzz target for `DynamicEpocher::read_cfg`.
//!
//! Exercises the segments loop, including the zero-length segment rejection
//! and `checked_mul` / `checked_add` overflow checks in `bounds`.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::dynamic_epocher::DynamicEpocher;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = DynamicEpocher::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = DynamicEpocher::read(&mut rebuf)
        .expect("encoded DynamicEpocher must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "DynamicEpocher encode is not idempotent across a roundtrip",
    );
});
