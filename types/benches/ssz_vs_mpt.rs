//! Benchmark: SSZ binary Merkle tree performance.
//!
//! Measures key operations:
//! - Full rebuild from scratch (N validators)
//! - Incremental single-validator update (balance change)
//! - Root read
//! - Proof generation (validator + scalar)
//! - Proof verification
//! - Clone (for capturing proof snapshots)
//!
//! Run with:
//! ```
//! cargo bench --package summit-types --bench ssz_vs_mpt --features bench
//! ```

use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};
use std::collections::BTreeMap;
use std::time::Instant;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::ssz_state_tree::SszStateTree;
use summit_types::withdrawal::WithdrawalQueue;

fn create_validator_account(seed: u64) -> ValidatorAccount {
    let consensus_key = bls12381::PrivateKey::from_seed(seed);
    ValidatorAccount {
        consensus_public_key: consensus_key.public_key(),
        withdrawal_credentials: Address::from([seed as u8; 20]),
        balance: 32_000_000_000,
        status: ValidatorStatus::Active,
        has_pending_deposit: false,
        has_pending_withdrawal: false,
        joining_epoch: 0,
        last_deposit_index: seed,
    }
}

fn create_pubkey_bytes(seed: u64) -> [u8; 32] {
    let pk = ed25519::PrivateKey::from_seed(seed).public_key();
    pk.as_ref().try_into().unwrap()
}

/// Build SSZ state tree with scalar fields + all validators.
fn ssz_full_rebuild(validators: &BTreeMap<[u8; 32], ValidatorAccount>) -> SszStateTree {
    let mut tree = SszStateTree::new();
    tree.rebuild(
        42,
        100,
        1000,
        &[0xAA; 32],
        &[0xBB; 32],
        32_000_000_000,
        64_000_000_000,
        5,
        &[0xCC; 32],
        &[0xDD; 32],
        &[0xEE; 32],
        validators,
        &std::collections::VecDeque::new(),
        &WithdrawalQueue::default(),
        &[],
        &BTreeMap::new(),
        &[],
    );
    tree
}

struct BenchResult {
    label: String,
    us: f64,
}

impl BenchResult {
    fn print(&self) {
        println!("  {:<40} {:>10.1} µs", self.label, self.us);
    }
}

fn bench_iterations<F: FnMut()>(mut f: F, iterations: usize) -> f64 {
    // Warmup
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    elapsed.as_micros() as f64 / iterations as f64
}

fn main() {
    let validator_counts = [10, 50, 100, 500];

    for &num_validators in &validator_counts {
        println!("\n=== {} validators ===\n", num_validators);

        // Pre-generate validator data
        let mut validators = BTreeMap::new();
        let mut pubkeys = Vec::new();
        for i in 0..num_validators {
            let pubkey = create_pubkey_bytes(i as u64);
            let account = create_validator_account(i as u64);
            validators.insert(pubkey, account);
            pubkeys.push(pubkey);
        }

        let iterations = if num_validators <= 100 { 50 } else { 10 };

        // --- Full rebuild ---
        let ssz_rebuild = bench_iterations(
            || {
                std::hint::black_box(ssz_full_rebuild(&validators));
            },
            iterations,
        );

        BenchResult {
            label: "Full rebuild".to_string(),
            us: ssz_rebuild,
        }
        .print();

        // --- Build baseline tree for incremental benchmarks ---
        let mut ssz_tree = ssz_full_rebuild(&validators);

        // --- Incremental: update one validator's balance ---
        let target_pk = &pubkeys[0];
        let mut updated_account = validators[target_pk].clone();
        updated_account.balance = 64_000_000_000;

        let mut updated_validators = validators.clone();
        updated_validators.insert(*target_pk, updated_account.clone());
        let ssz_update = bench_iterations(
            || {
                ssz_tree.rebuild_validators(&updated_validators);
                std::hint::black_box(ssz_tree.root());
            },
            iterations * 10,
        );

        BenchResult {
            label: "Incremental update (1 validator)".to_string(),
            us: ssz_update,
        }
        .print();

        // --- Root read ---
        let ssz_root = bench_iterations(
            || {
                std::hint::black_box(ssz_tree.root());
            },
            10000,
        );

        BenchResult {
            label: "Root read".to_string(),
            us: ssz_root,
        }
        .print();

        // --- Proof generation (single validator) ---
        let ssz_proof_gen = bench_iterations(
            || {
                std::hint::black_box(ssz_tree.generate_validator_proof(target_pk, &pubkeys));
            },
            iterations * 5,
        );

        BenchResult {
            label: "Proof generation (1 validator)".to_string(),
            us: ssz_proof_gen,
        }
        .print();

        // --- Proof verification ---
        let ssz_proof = ssz_tree
            .generate_validator_proof(target_pk, &pubkeys)
            .unwrap();
        let ssz_root_val = ssz_tree.root();

        let ssz_verify = bench_iterations(
            || {
                std::hint::black_box(ssz_proof.verify(&ssz_root_val));
            },
            iterations * 10,
        );

        BenchResult {
            label: "Proof verification".to_string(),
            us: ssz_verify,
        }
        .print();

        // --- Clone (snapshot for proof trie) ---
        let ssz_clone = bench_iterations(
            || {
                std::hint::black_box(ssz_tree.clone());
            },
            iterations * 5,
        );

        BenchResult {
            label: "Clone (proof snapshot)".to_string(),
            us: ssz_clone,
        }
        .print();

        // --- Scalar proof (epoch) ---
        let ssz_scalar_proof = bench_iterations(
            || {
                std::hint::black_box(
                    ssz_tree.generate_scalar_proof(summit_types::ssz_state_tree::EPOCH),
                );
            },
            iterations * 5,
        );

        BenchResult {
            label: "Scalar proof (epoch)".to_string(),
            us: ssz_scalar_proof,
        }
        .print();
    }

    println!("\nDone.");
}
