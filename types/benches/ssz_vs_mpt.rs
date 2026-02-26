//! Benchmark: SSZ binary Merkle proof sizes and timing.
//!
//! Measures proof sizes for various multi-key scenarios, showing how
//! branch nodes are shared (deduplicated) when proving multiple keys.
//! Also measures proof generation and verification time.
//!
//! Run with:
//! ```
//! cargo bench --package summit-types --bench ssz_vs_mpt --features bench
//! ```

use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};
use std::collections::{BTreeMap, HashSet};
use std::time::Instant;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::ssz_state_tree::*;
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

fn build_tree(validators: &BTreeMap<[u8; 32], ValidatorAccount>) -> SszStateTree {
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

fn multiproof_nodes(proofs: &[SszProof]) -> usize {
    let mut sibling_gindices = HashSet::new();
    for proof in proofs {
        let mut idx = proof.gindex;
        for _ in &proof.branch {
            sibling_gindices.insert(idx ^ 1);
            idx >>= 1;
        }
    }
    sibling_gindices.len()
}

fn multiproof_size(proofs: &[SszProof]) -> usize {
    let num_nodes = multiproof_nodes(proofs);
    proofs.len() * (8 + 32) + num_nodes * 32
}

fn bench_us<F: FnMut()>(mut f: F, iterations: usize) -> f64 {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    start.elapsed().as_nanos() as f64 / iterations as f64 / 1000.0
}

fn format_bytes(n: usize) -> String {
    if n >= 1000 {
        let whole = n / 1000;
        let frac = (n % 1000) / 100;
        if frac > 0 {
            format!("{},{:03} bytes", whole, n % 1000)
        } else {
            format!("{},000 bytes", whole)
        }
    } else {
        format!("{} bytes", n)
    }
}

fn format_time(us: f64) -> String {
    if us >= 1000.0 {
        format!("{:.1} ms", us / 1000.0)
    } else if us >= 1.0 {
        format!("{:.0} µs", us)
    } else {
        format!("{:.1} µs", us)
    }
}

struct Row {
    label: String,
    validators: usize,
    keys: usize,
    nodes: usize,
    proof_size: usize,
    time_us: f64,
}

fn print_table(rows: &[Row]) {
    // Column widths
    let w_label = 32;
    let w_val = 12;
    let w_keys = 6;
    let w_nodes = 7;
    let w_proof = 14;
    let w_time = 8;

    let sep = format!(
        "├{:─<w_label$}┼{:─<w_val$}┼{:─<w_keys$}┼{:─<w_nodes$}┼{:─<w_proof$}┼{:─<w_time$}┤",
        "", "", "", "", "", "",
    );
    // Top border
    println!(
        "┌{:─<w_label$}┬{:─<w_val$}┬{:─<w_keys$}┬{:─<w_nodes$}┬{:─<w_proof$}┬{:─<w_time$}┐",
        "", "", "", "", "", "",
    );

    // Header
    println!(
        "│{:^w_label$}│{:^w_val$}│{:^w_keys$}│{:^w_nodes$}│{:^w_proof$}│{:^w_time$}│",
        "Query pattern", "Validators", "Keys", "Nodes", "Proof size", "Time",
    );

    // Header separator
    println!("{}", sep);

    for (i, row) in rows.iter().enumerate() {
        println!(
            "│ {:<w$}│ {:<wv$}│ {:<wk$}│ {:<wn$}│ {:<wp$}│ {:<wt$}│",
            row.label,
            row.validators,
            row.keys,
            row.nodes,
            format_bytes(row.proof_size),
            format_time(row.time_us),
            w = w_label - 1,
            wv = w_val - 1,
            wk = w_keys - 1,
            wn = w_nodes - 1,
            wp = w_proof - 1,
            wt = w_time - 1,
        );

        if i + 1 < rows.len() {
            println!("{}", sep);
        }
    }

    // Bottom border
    println!(
        "└{:─<w_label$}┴{:─<w_val$}┴{:─<w_keys$}┴{:─<w_nodes$}┴{:─<w_proof$}┴{:─<w_time$}┘",
        "", "", "", "", "", "",
    );
}

fn main() {
    let highlight_counts = [10, 100, 1000];
    let scalar_indices: Vec<usize> = (EPOCH..=FORKCHOICE_FINALIZED_BLOCK_HASH).collect();

    let mut rows = Vec::new();

    for &num_validators in &highlight_counts {
        let mut validators = BTreeMap::new();
        let mut pubkeys = Vec::new();
        for i in 0..num_validators {
            let pubkey = create_pubkey_bytes(i as u64);
            let account = create_validator_account(i as u64);
            validators.insert(pubkey, account);
            pubkeys.push(pubkey);
        }

        let tree = build_tree(&validators);
        let root = tree.root();
        let target_pk = &pubkeys[0];
        let iterations = if num_validators <= 100 { 500 } else { 100 };

        // Helper to generate + verify timing
        let mut measure = |label: &str, make_proofs: &dyn Fn() -> Vec<SszProof>| {
            let gen_us = bench_us(
                || {
                    std::hint::black_box(make_proofs());
                },
                iterations,
            );
            let proofs = make_proofs();
            let verify_us = bench_us(
                || {
                    for p in &proofs {
                        std::hint::black_box(p.verify(&root));
                    }
                },
                iterations,
            );
            rows.push(Row {
                label: label.to_string(),
                validators: num_validators,
                keys: proofs.len(),
                nodes: multiproof_nodes(&proofs),
                proof_size: multiproof_size(&proofs),
                time_us: gen_us + verify_us,
            });
        };

        // 1. Single scalar (epoch)
        measure("Single scalar (epoch)", &|| {
            vec![tree.generate_scalar_proof(EPOCH)]
        });

        // 2. Single validator balance
        measure("Single validator balance", &|| {
            vec![
                tree.generate_validator_field_proof(target_pk, VALIDATOR_FIELD_BALANCE, &pubkeys)
                    .unwrap(),
            ]
        });

        // 3. All scalars + forkchoice (11 keys)
        measure("All scalars + forkchoice", &|| {
            scalar_indices
                .iter()
                .map(|&idx| tree.generate_scalar_proof(idx))
                .collect()
        });

        // 4. All fields for 1 validator (8 keys)
        measure("All fields for 1 validator", &|| {
            (0..VALIDATOR_FIELDS_PER_ACCOUNT)
                .map(|f| {
                    tree.generate_validator_field_proof(target_pk, f, &pubkeys)
                        .unwrap()
                })
                .collect()
        });

        // 5. Mixed (2 scalars + 1 validator field)
        measure("Mixed (2 scalars + 1 field)", &|| {
            vec![
                tree.generate_scalar_proof(EPOCH),
                tree.generate_scalar_proof(LATEST_HEIGHT),
                tree.generate_validator_field_proof(target_pk, VALIDATOR_FIELD_BALANCE, &pubkeys)
                    .unwrap(),
            ]
        });

        // 6. All scalars + 1 full validator
        measure("All scalars + 1 full validator", &|| {
            let mut proofs: Vec<SszProof> = scalar_indices
                .iter()
                .map(|&idx| tree.generate_scalar_proof(idx))
                .collect();
            for f in 0..VALIDATOR_FIELDS_PER_ACCOUNT {
                proofs.push(
                    tree.generate_validator_field_proof(target_pk, f, &pubkeys)
                        .unwrap(),
                );
            }
            proofs
        });

        // 7. 10 validator balances
        {
            let count = num_validators.min(10);
            measure(&format!("{} validator balances", count), &|| {
                pubkeys
                    .iter()
                    .take(count)
                    .map(|pk| {
                        tree.generate_validator_field_proof(pk, VALIDATOR_FIELD_BALANCE, &pubkeys)
                            .unwrap()
                    })
                    .collect()
            });
        }
    }

    println!();
    print_table(&rows);

    // --- Update timing ---
    println!();
    println!("┌────────────────────────────────────────────────────┬────────────┬────────────┐");
    println!("│{:^52}│{:^12}│{:^12}│", "Operation", "Validators", "Time");
    println!("├────────────────────────────────────────────────────┼────────────┼────────────┤");

    let update_counts = [50, 100, 200, 500, 1000];
    let update_iterations_for = |n: usize| if n <= 200 { 50 } else { 10 };

    for (i, &num_validators) in update_counts.iter().enumerate() {
        let mut validators = BTreeMap::new();
        let mut pubkeys = Vec::new();
        for j in 0..num_validators {
            let pubkey = create_pubkey_bytes(j as u64);
            let account = create_validator_account(j as u64);
            validators.insert(pubkey, account);
            pubkeys.push(pubkey);
        }

        let mut tree = build_tree(&validators);
        let target_pk = pubkeys[0];
        let mut updated_account = validators[&target_pk].clone();
        updated_account.balance = 64_000_000_000;
        let mut updated_validators = validators.clone();
        updated_validators.insert(target_pk, updated_account.clone());
        let target_slot = pubkeys.iter().position(|k| k == &target_pk).unwrap();
        let iters = update_iterations_for(num_validators);

        let full_us = bench_us(
            || {
                std::hint::black_box(build_tree(&validators));
            },
            iters,
        );
        let subtree_us = bench_us(
            || {
                tree.rebuild_validators(&updated_validators);
                std::hint::black_box(tree.root());
            },
            iters * 10,
        );
        let incremental_us = bench_us(
            || {
                tree.update_validator_at_slot(target_slot, &updated_account);
                std::hint::black_box(tree.root());
            },
            iters * 10,
        );
        let root_us = bench_us(
            || {
                std::hint::black_box(tree.root());
            },
            10000,
        );
        let clone_us = bench_us(
            || {
                std::hint::black_box(tree.clone());
            },
            iters * 5,
        );

        // Insert a new validator at the middle position
        let mid_slot = num_validators / 2;
        let new_pk = create_pubkey_bytes(num_validators as u64 + 1000);
        let new_account = create_validator_account(num_validators as u64 + 1000);
        // Prepare a tree with the validator already inserted for removal benchmark
        let mut tree_with_extra = tree.clone();
        tree_with_extra.insert_validator_at_slot(mid_slot, &new_account);

        let insert_us = bench_us(
            || {
                let mut t = tree.clone();
                t.insert_validator_at_slot(mid_slot, &new_account);
                std::hint::black_box(t.root());
            },
            iters * 5,
        );
        let remove_us = bench_us(
            || {
                let mut t = tree_with_extra.clone();
                t.remove_validator_at_slot(mid_slot);
                std::hint::black_box(t.root());
            },
            iters * 5,
        );
        let _ = (new_pk, new_account);

        let ops: Vec<(&str, f64)> = vec![
            ("Full state rebuild", full_us),
            ("Validator subtree rebuild (1 balance change)", subtree_us),
            ("Incremental update (1 balance change)", incremental_us),
            ("Insert validator (middle)", insert_us),
            ("Remove validator (middle)", remove_us),
            ("Root read", root_us),
            ("Clone (proof snapshot)", clone_us),
        ];

        for (label, us) in &ops {
            println!(
                "│ {:<51}│ {:<11}│ {:>10} │",
                label,
                num_validators,
                format_time(*us),
            );
        }

        if i + 1 < update_counts.len() {
            println!(
                "├────────────────────────────────────────────────────┼────────────┼────────────┤"
            );
        }
    }

    println!("└────────────────────────────────────────────────────┴────────────┴────────────┘");
    println!();
}
