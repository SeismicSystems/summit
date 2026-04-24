#![no_main]

//! Fuzz target for `SszProof::verify`.
//!
//! Given an adversarial `(gindex, leaf, branch, state_root)`, `verify` must
//! return a `bool` and never panic. The underlying `verify_proof_gindex` loops
//! `gindex /= 2` until the root is reached — overflow-edge gindex values and
//! mismatched branch lengths are the usual culprits.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use summit_types::ssz_state_tree::SszProof;

#[derive(Arbitrary, Debug)]
struct Input {
    gindex: u64,
    leaf: [u8; 32],
    branch: Vec<[u8; 32]>,
    state_root: [u8; 32],
}

fuzz_target!(|input: Input| {
    let proof = SszProof {
        gindex: input.gindex,
        leaf: input.leaf,
        branch: input.branch,
    };
    let _ = proof.verify(&input.state_root);
});
