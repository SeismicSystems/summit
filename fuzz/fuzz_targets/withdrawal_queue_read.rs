#![no_main]

//! Fuzz target for `WithdrawalQueue::read_cfg`.
//!
//! Exercises the three-level structure (queue → per-epoch → per-item) and
//! `PendingWithdrawal::read_cfg` via nested dispatch.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::withdrawal::WithdrawalQueue;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = WithdrawalQueue::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = WithdrawalQueue::read(&mut rebuf)
        .expect("encoded WithdrawalQueue must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "WithdrawalQueue encode is not idempotent across a roundtrip",
    );
});
