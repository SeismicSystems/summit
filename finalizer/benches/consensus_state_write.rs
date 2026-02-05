use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{Runner as _, tokio::Runner};
use commonware_storage::translator::EightCap;
use commonware_utils::{NZU64, NZUsize};
use std::time::Instant;
use summit_finalizer::db::{Config, FinalizerState};
use summit_types::Block;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;

use commonware_cryptography::bls12381::primitives::variant::MinPk;

fn create_validator_account(index: u64, balance: u64) -> ValidatorAccount {
    let consensus_key = bls12381::PrivateKey::from_seed(index);
    ValidatorAccount {
        consensus_public_key: consensus_key.public_key(),
        withdrawal_credentials: Address::from([index as u8; 20]),
        balance,
        pending_withdrawal_amount: 0,
        status: ValidatorStatus::Active,
        has_pending_deposit: false,
        has_pending_withdrawal: false,
        joining_epoch: 0,
        last_deposit_index: index,
    }
}

fn create_populated_state(num_validators: usize, epoch: u64, height: u64) -> ConsensusState {
    let mut state = ConsensusState::default();

    state.epoch = epoch;
    state.view = height;
    state.set_latest_height(height);
    state.next_withdrawal_index = epoch * 10;
    state.epoch_genesis_hash = [42u8; 32];

    // Add validators
    for i in 0..num_validators {
        let pubkey = ed25519::PrivateKey::from_seed(i as u64).public_key();
        let pubkey_bytes: [u8; 32] = pubkey.as_ref().try_into().unwrap();
        let account = create_validator_account(i as u64, 32_000_000_000);
        state.set_account(pubkey_bytes, account);
    }

    state
}

/// Benchmark for measuring consensus state and checkpoint write performance over time.
///
/// This benchmark writes consensus state and checkpoint data for many epochs to detect
/// performance degradation as the database grows. It was created to identify and verify
/// fixes for O(n) write performance caused by hash collisions in the QMDB translator.
///
/// The benchmark measures:
/// - `store_consensus_state` + `commit` time for each epoch
/// - `store_finalized_checkpoint` + `commit` time for each epoch
///
/// Run with:
/// ```
/// cargo bench --package summit-finalizer --bench consensus_state_write
/// ```
fn main() {
    let num_validators = 100;
    let num_epochs = 1000;
    let blocks_per_epoch = 100;

    println!(
        "Benchmarking consensus state write performance over {} epochs",
        num_epochs
    );
    println!(
        "Validators: {}, Blocks per epoch: {}",
        num_validators, blocks_per_epoch
    );
    println!();

    // Use tokio runtime with disk storage
    let storage_dir = std::env::temp_dir().join(format!("summit_bench_{}", std::process::id()));
    let cfg = commonware_runtime::tokio::Config::default().with_storage_directory(&storage_dir);
    let executor = Runner::new(cfg);

    executor.start(|context| async move {
        let config = Config {
            log_partition: "bench-log".to_string(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: (),
            log_items_per_section: NZU64!(4),
            translator: EightCap,
            page_cache: CacheRef::new(std::num::NonZero::new(77u16).unwrap(), NZUsize!(9)),
        };

        let mut db = FinalizerState::<_, MinPk>::new(context, config).await;

        let mut write_times: Vec<(u64, u128)> = Vec::new();
        let mut checkpoint_times: Vec<(u64, u128)> = Vec::new();

        for epoch in 0..num_epochs {
            let height = epoch * blocks_per_epoch + blocks_per_epoch - 1;
            let state = create_populated_state(num_validators, epoch, height);

            // Measure store_consensus_state + commit
            let start = Instant::now();
            db.store_consensus_state(height, &state).await;
            db.commit().await;
            let duration = start.elapsed().as_micros();
            write_times.push((epoch, duration));

            // Store checkpoint
            let checkpoint = Checkpoint::new(&state);
            let checkpoint_start = Instant::now();
            db.store_finalized_checkpoint(epoch, &checkpoint, Block::genesis([0; 32]))
                .await;
            db.commit().await;
            let checkpoint_duration = checkpoint_start.elapsed().as_micros();
            checkpoint_times.push((epoch, checkpoint_duration));

            if epoch % 50 == 0 {
                println!(
                    "Epoch {:3}: state write = {:6} µs, checkpoint write = {:6} µs",
                    epoch, duration, checkpoint_duration
                );
            }
        }

        println!();
        println!("Summary:");
        println!("=========");

        // Calculate statistics for state writes
        let state_times: Vec<u128> = write_times.iter().map(|(_, t)| *t).collect();
        let state_avg = state_times.iter().sum::<u128>() / state_times.len() as u128;
        let state_min = *state_times.iter().min().unwrap();
        let state_max = *state_times.iter().max().unwrap();

        println!("Consensus state writes:");
        println!("  Average: {} µs", state_avg);
        println!("  Min:     {} µs", state_min);
        println!("  Max:     {} µs", state_max);

        // Compare different ranges (skip first 50 for warm-up)
        let range_50_60: u128 = write_times
            .iter()
            .skip(50)
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        let range_450_460: u128 = write_times
            .iter()
            .skip(450)
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        let last_10_avg: u128 = write_times
            .iter()
            .rev()
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        println!("  Epochs 50-60 avg:    {} µs", range_50_60);
        println!("  Epochs 450-460 avg:  {} µs", range_450_460);
        println!("  Last 10 epochs avg:  {} µs", last_10_avg);
        let change_pct = ((last_10_avg as f64 - range_50_60 as f64) / range_50_60 as f64) * 100.0;
        println!("  Change (50-60 vs last 10): {:.1}%", change_pct);

        println!();

        // Calculate statistics for checkpoint writes
        let checkpoint_times_vec: Vec<u128> = checkpoint_times.iter().map(|(_, t)| *t).collect();
        let checkpoint_avg =
            checkpoint_times_vec.iter().sum::<u128>() / checkpoint_times_vec.len() as u128;
        let checkpoint_min = *checkpoint_times_vec.iter().min().unwrap();
        let checkpoint_max = *checkpoint_times_vec.iter().max().unwrap();

        println!("Checkpoint writes:");
        println!("  Average: {} µs", checkpoint_avg);
        println!("  Min:     {} µs", checkpoint_min);
        println!("  Max:     {} µs", checkpoint_max);

        // Compare different ranges (skip first 50 for warm-up)
        let cp_range_50_60: u128 = checkpoint_times
            .iter()
            .skip(50)
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        let cp_range_450_460: u128 = checkpoint_times
            .iter()
            .skip(450)
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        let last_10_checkpoint_avg: u128 = checkpoint_times
            .iter()
            .rev()
            .take(10)
            .map(|(_, t)| *t)
            .sum::<u128>()
            / 10;
        println!("  Epochs 50-60 avg:    {} µs", cp_range_50_60);
        println!("  Epochs 450-460 avg:  {} µs", cp_range_450_460);
        println!("  Last 10 epochs avg:  {} µs", last_10_checkpoint_avg);
        let checkpoint_change_pct = ((last_10_checkpoint_avg as f64 - cp_range_50_60 as f64)
            / cp_range_50_60 as f64)
            * 100.0;
        println!("  Change (50-60 vs last 10): {:.1}%", checkpoint_change_pct);
    });

    // Cleanup temp directory
    let _ = std::fs::remove_dir_all(&storage_dir);
}
