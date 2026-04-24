#![no_main]

//! Fuzz target for `ValidatorAccount::read_cfg`.
//!
//! Though it is reachable through `ConsensusState::read_cfg`, a direct target
//! converges on the 95-byte fixed-size layout much faster than sifting through
//! ConsensusState's prefix fields.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::account::ValidatorAccount;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = ValidatorAccount::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = ValidatorAccount::read(&mut rebuf)
        .expect("encoded ValidatorAccount must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "ValidatorAccount encode is not idempotent across a roundtrip",
    );
});
