#![no_main]

//! Fuzz target for `ExecutionRequest::read_cfg`.
//!
//! Covers Deposit / Withdrawal / ProtocolParamRequest variants via the tag dispatch.
//! `ExecutionRequest` does not implement `EncodeSize`, so we only check that
//! parsing arbitrary bytes never panics (`Result::is_err()` is fine).

use commonware_codec::ReadExt as _;
use libfuzzer_sys::fuzz_target;
use summit_types::execution_request::ExecutionRequest;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = ExecutionRequest::read(&mut buf);
});
