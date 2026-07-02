#![no_main]

//! Property-based fuzz target: any proof generated from a captured state tree
//! must verify against that state's captured root.
//!
//! Generate-side coverage — complements `ssz_proof_verify`, which fuzzes
//! `SszProof::verify` with adversarial inputs. Here, we fuzz the generate
//! step across every supported proof kind (top-level scalars, validators,
//! deposits, withdrawals, protocol params, added / removed validators) and
//! assert the generate→verify roundtrip holds.

use commonware_codec::ReadExt as _;
use libfuzzer_sys::fuzz_target;
use summit_types::{consensus_state::ConsensusState, ssz_state_tree};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(mut state) = ConsensusState::read(&mut buf) else {
        return;
    };

    // Freeze proof_tree, state_root and proof_validator_keys so the
    // frozen snapshot matches the root proofs are verified against.
    state.capture_state_root(0);
    let root = state.get_state_root();
    let validator_keys: Vec<[u8; 32]> = state.proof_validator_keys().to_vec();
    let tree = state.proof_tree();

    // Top-level scalar proofs: must verify for every leaf index.
    for leaf in 0..ssz_state_tree::NUM_TOP_LEAVES {
        let proof = tree.generate_scalar_proof(leaf);
        assert!(
            proof.verify(&root),
            "scalar proof for leaf {leaf} failed to verify",
        );
    }

    // Validator proofs: one per frozen validator key.
    for pk in &validator_keys {
        let proof = tree
            .generate_validator_proof(pk, &validator_keys)
            .expect("validator in keys must produce a proof");
        assert!(proof.verify(&root), "validator proof failed to verify");
    }

    // Deposit proofs: iterate until None (past the count).
    for i in 0..64 {
        match tree.generate_deposit_proof(i) {
            Some(proof) => assert!(
                proof.verify(&root),
                "deposit proof at index {i} failed to verify",
            ),
            None => break,
        }
    }

    // Protocol param proofs.
    for i in 0..64 {
        match tree.generate_protocol_param_proof(i) {
            Some(proof) => assert!(
                proof.verify(&root),
                "protocol param proof at index {i} failed to verify",
            ),
            None => break,
        }
    }

    // Added / removed validator proofs.
    for i in 0..64 {
        match tree.generate_added_validator_proof(i) {
            Some(proof) => assert!(
                proof.verify(&root),
                "added validator proof at index {i} failed to verify",
            ),
            None => break,
        }
    }
    for i in 0..64 {
        match tree.generate_removed_validator_proof(i) {
            Some(proof) => assert!(
                proof.verify(&root),
                "removed validator proof at index {i} failed to verify",
            ),
            None => break,
        }
    }

    // Withdrawal proofs: the queue is a flat combined collection, so iterate by
    // positional index until None (past the count), like the deposit proofs.
    for i in 0..64 {
        match tree.generate_withdrawal_proof(i) {
            Some(proof) => assert!(
                proof.verify(&root),
                "withdrawal proof at index {i} failed to verify",
            ),
            None => break,
        }
    }
});
