#![no_main]

//! Fuzz target for `ssz_tree_key::parse_key`.
//!
//! `parse_key` consumes a string from RPC input. Goal: it must always return
//! `Ok` or `Err`, never panic.

use libfuzzer_sys::fuzz_target;
use summit_types::ssz_tree_key::parse_key;

fuzz_target!(|s: &str| {
    let _ = parse_key(s);
});
