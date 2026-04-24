#![no_main]

//! Fuzz target for `ConsensusState::read_cfg`.
//!
//! Goals:
//!   1. Parsing arbitrary bytes must never panic — only return `Result`.
//!   2. When parsing succeeds, re-encoding the decoded value and decoding
//!      again must produce byte-identical output (canonical encoding).

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::consensus_state::ConsensusState;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(state) = ConsensusState::read(&mut buf) else {
        return;
    };

    let encoded = state.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = ConsensusState::read(&mut rebuf)
        .expect("encoded ConsensusState must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "ConsensusState encode is not idempotent across a roundtrip",
    );
});
