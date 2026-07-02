#![no_main]

//! Property-based fuzz target for `ExtPrivateKey` sign / verify.
//!
//! Invariants:
//!   - `ExtPrivateKey::derive_child_signer(master, ns, idx).public_key()` equals
//!     `derive_child_public(master.public_key(), ns, idx)` for any
//!     `(master, ns, idx)`.
//!   - A signature produced by the child signer verifies under both the child's
//!     own public key and the public-only derivation.

use arbitrary::Arbitrary;
use commonware_cryptography::{Signer as _, Verifier, ed25519::PrivateKey};
use libfuzzer_sys::fuzz_target;
use summit_types::ext_private_key::{ExtPrivateKey, derive_child_public};

#[derive(Arbitrary, Debug)]
struct Input {
    master_seed: u64,
    index: u32,
    namespace: Vec<u8>,
    msg: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let master = PrivateKey::from_seed(input.master_seed);
    let master_pub = master.public_key();

    let child = ExtPrivateKey::derive_child_signer(&master, &input.namespace, input.index);
    let child_pub = child.public_key();
    let derived_pub = derive_child_public(master_pub, &input.namespace, input.index);

    assert_eq!(
        child_pub, derived_pub,
        "signer-derived pubkey must match public-only derivation",
    );

    let sig = child.sign(&input.namespace, &input.msg);

    assert!(
        child_pub.verify(&input.namespace, &input.msg, &sig),
        "signature must verify under child's own pubkey",
    );
    assert!(
        derived_pub.verify(&input.namespace, &input.msg, &sig),
        "signature must verify under public-only derivation",
    );
});
