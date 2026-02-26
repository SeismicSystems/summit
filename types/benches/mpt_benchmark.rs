use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};
use std::time::Instant;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::consensus_state::ConsensusState;
use summit_types::state_trie::StateTrie;
use summit_types::state_trie_key;

fn create_validator_account(index: u64, balance: u64) -> ValidatorAccount {
    let consensus_key = bls12381::PrivateKey::from_seed(index);
    ValidatorAccount {
        consensus_public_key: consensus_key.public_key(),
        withdrawal_credentials: Address::from([index as u8; 20]),
        balance,
        status: ValidatorStatus::Active,
        has_pending_deposit: false,
        has_pending_withdrawal: false,
        joining_epoch: 0,
        last_deposit_index: index,
    }
}

fn create_populated_state(num_validators: usize) -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_epoch(100);
    state.set_view(500);
    state.set_latest_height(500);
    state.set_next_withdrawal_index(42);
    state.set_epoch_genesis_hash([0xABu8; 32]);

    for i in 0..num_validators {
        let pubkey = ed25519::PrivateKey::from_seed(i as u64).public_key();
        let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
        let account = create_validator_account(i as u64, 32_000_000_000);
        state.set_account(pubkey_bytes, account);
    }

    state
}

fn bench_root_computation(state: &ConsensusState, num_validators: usize, iterations: u32) -> u128 {
    // Force a fresh root computation each iteration by cloning the trie
    let trie = state.state_trie();
    let mut total = 0u128;
    for _ in 0..iterations {
        let mut cloned = trie.clone();
        // Invalidate cache by inserting and reverting
        cloned.insert_raw(b"__bench_nonce__", &[0]);
        cloned.remove_raw(b"__bench_nonce__");
        let start = Instant::now();
        let _root = cloned.root();
        total += start.elapsed().as_nanos();
    }
    total / iterations as u128
}

fn bench_incremental_update(state: &mut ConsensusState, _num_validators: usize) -> u128 {
    // Measure time to update a single validator balance + recompute root
    // (simulates what happens each block)
    let pubkey = ed25519::PrivateKey::from_seed(0).public_key();
    let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
    let iterations = 100u32;
    let mut total = 0u128;

    for i in 0..iterations {
        let account = create_validator_account(0, 32_000_000_000 + i as u64);
        let start = Instant::now();
        state.set_account(pubkey_bytes, account);
        let _root = state.state_trie().root();
        total += start.elapsed().as_nanos();
    }
    total / iterations as u128
}

fn bench_capture_state_root(state: &mut ConsensusState, _num_validators: usize) -> u128 {
    let iterations = 50u32;
    let mut total = 0u128;

    for i in 0..iterations {
        // Simulate a block: update a validator, then capture
        let pubkey = ed25519::PrivateKey::from_seed(0).public_key();
        let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
        let account = create_validator_account(0, 32_000_000_000 + i as u64);
        state.set_account(pubkey_bytes, account);

        let start = Instant::now();
        state.capture_state_root(i as u64);
        total += start.elapsed().as_nanos();
    }
    total / iterations as u128
}

fn bench_proof_generation(
    state: &ConsensusState,
    num_keys: usize,
) -> (u128, Vec<usize>) {
    let trie = state.state_trie();
    let iterations = 50u32;

    // Build list of keys to prove
    let mut logical_keys: Vec<Vec<u8>> = vec![
        state_trie_key::EPOCH.to_vec(),
        state_trie_key::LATEST_HEIGHT.to_vec(),
        state_trie_key::VIEW.to_vec(),
    ];
    // Add some validator balance keys
    for i in 0..num_keys.saturating_sub(3) {
        let pubkey = ed25519::PrivateKey::from_seed(i as u64).public_key();
        let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
        logical_keys.push(state_trie_key::validator_account_balance(&pubkey_bytes));
    }
    logical_keys.truncate(num_keys);

    let key_refs: Vec<&[u8]> = logical_keys.iter().map(|k| k.as_slice()).collect();

    let mut total = 0u128;
    let mut proof_sizes = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();
        let proofs = trie.generate_proof(&key_refs);
        total += start.elapsed().as_nanos();

        // Measure proof sizes (only on first iteration)
        if proof_sizes.is_empty() {
            for proof in &proofs {
                let size: usize = proof.iter().map(|node| node.len()).sum();
                proof_sizes.push(size);
            }
        }
    }

    (total / iterations as u128, proof_sizes)
}

fn bench_proof_verification(state: &ConsensusState) -> u128 {
    let trie = state.state_trie();
    let root = trie.root();

    let key = state_trie_key::EPOCH;
    let key_refs: Vec<&[u8]> = vec![key];
    let proofs = trie.generate_proof(&key_refs);
    let value = trie.get_raw(key).unwrap();

    let iterations = 1000u32;
    let mut total = 0u128;
    for _ in 0..iterations {
        let start = Instant::now();
        let result = StateTrie::verify_proof(&root, &proofs[0], key, Some(&value));
        total += start.elapsed().as_nanos();
        assert!(result);
    }
    total / iterations as u128
}

fn main() {
    let validator_counts = [50, 100, 200, 500, 1000];

    println!("MPT Benchmark (alloy-trie)");
    println!("==========================\n");

    // Header
    println!(
        "{:>12} {:>14} {:>14} {:>14} {:>14} {:>14}",
        "Validators", "Root (µs)", "Update+Root", "Capture (µs)", "Proof Gen", "Verify (µs)"
    );
    println!(
        "{:>12} {:>14} {:>14} {:>14} {:>14} {:>14}",
        "", "", "(µs)", "", "(1 key, µs)", ""
    );
    println!("{}", "-".repeat(90));

    for &n in &validator_counts {
        let mut state = create_populated_state(n);

        let root_ns = bench_root_computation(&state, n, 100);
        let update_ns = bench_incremental_update(&mut state, n);

        // Recreate because incremental_update mutates
        let mut state = create_populated_state(n);
        let capture_ns = bench_capture_state_root(&mut state, n);

        let state = create_populated_state(n);
        let (proof_gen_ns, _) = bench_proof_generation(&state, 1);
        let verify_ns = bench_proof_verification(&state);

        println!(
            "{:>12} {:>13.1} {:>13.1} {:>13.1} {:>13.1} {:>13.1}",
            n,
            root_ns as f64 / 1000.0,
            update_ns as f64 / 1000.0,
            capture_ns as f64 / 1000.0,
            proof_gen_ns as f64 / 1000.0,
            verify_ns as f64 / 1000.0,
        );
    }

    // Proof size measurements
    println!("\n\nProof Size Measurements");
    println!("=======================\n");

    let proof_key_counts = [1, 3, 5, 10];

    // Print header
    print!("{:>12}", "Validators");
    for &k in &proof_key_counts {
        print!(" {:>20}", format!("{} key(s) (bytes)", k));
    }
    println!();
    println!("{}", "-".repeat(12 + proof_key_counts.len() * 21));

    for &n in &validator_counts {
        let state = create_populated_state(n);
        print!("{:>12}", n);

        for &num_keys in &proof_key_counts {
            let (_, proof_sizes) = bench_proof_generation(&state, num_keys);
            let total_size: usize = proof_sizes.iter().sum();
            let avg_size = if proof_sizes.is_empty() {
                0
            } else {
                total_size / proof_sizes.len()
            };
            print!(" {:>10} (avg {:>5})", total_size, avg_size);
        }
        println!();
    }

    // Detailed proof breakdown for one config
    println!("\n\nDetailed Proof Breakdown (100 validators, 3 keys)");
    println!("=================================================\n");

    let state = create_populated_state(100);
    let trie = state.state_trie();

    let keys: Vec<Vec<u8>> = vec![
        state_trie_key::EPOCH.to_vec(),
        state_trie_key::LATEST_HEIGHT.to_vec(),
        state_trie_key::validator_account_balance(
            &ed25519::PrivateKey::from_seed(0)
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
        ),
    ];
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
    let proofs = trie.generate_proof(&key_refs);

    let key_names = ["epoch", "latest_height", "validator_balance[0]"];
    for (proof, name) in proofs.iter().zip(key_names.iter()) {
        let total_bytes: usize = proof.iter().map(|n| n.len()).sum();
        println!(
            "  Key: {:30} nodes: {:2}  total bytes: {:5}",
            name,
            proof.len(),
            total_bytes
        );
        for (j, node) in proof.iter().enumerate() {
            println!("    node[{}]: {} bytes", j, node.len());
        }
    }

    // Trie entry count
    println!("\n\nTrie Entry Counts");
    println!("=================\n");
    for &n in &validator_counts {
        let state = create_populated_state(n);
        let trie = state.state_trie();
        // Each validator has 7 trie entries + 11 scalar fields
        let expected_entries = 11 + n * 7;
        println!(
            "  {:>4} validators: ~{} trie entries, root = 0x{}",
            n,
            expected_entries,
            alloy_primitives::hex::encode(&trie.root()[..8])
        );
    }
}
