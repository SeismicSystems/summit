#![no_main]

//! Fuzz target for `derive_child_public`.
//!
//! The function calls `CompressedEdwardsY::decompress().expect(...)` on the
//! master pubkey bytes. If `PublicKey::decode` ever lets through a non-canonical
//! 32-byte point, this panics. Fuzzing with arbitrary 32-byte slices confirms
//! the validation path catches those before they reach derivation.

use arbitrary::Arbitrary;
use commonware_codec::DecodeExt;
use libfuzzer_sys::fuzz_target;
use summit_types::PublicKey;
use summit_types::ext_private_key::derive_child_public;

#[derive(Arbitrary, Debug)]
struct Input {
    master_pubkey_bytes: [u8; 32],
    namespace: Vec<u8>,
    index: u32,
}

fuzz_target!(|input: Input| {
    // Path 1: through the canonical decoder — expected to reject invalid points.
    if let Ok(pk) = PublicKey::decode(&input.master_pubkey_bytes[..]) {
        let _ = derive_child_public(pk, &input.namespace, input.index);
    }
});
