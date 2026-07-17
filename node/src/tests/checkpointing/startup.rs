use crate::args::{
    CheckpointStartupDecision, check_last_block_binding, classify_checkpoint_startup,
    read_checkpoint,
};
use alloy_primitives::Address;
use ssz::Encode as _;
use std::num::NonZeroU64;
use summit_types::Digest;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::scheme::MultisigScheme;

#[test]
fn no_checkpoint_starts_from_genesis() {
    assert_eq!(
        classify_checkpoint_startup(false, false, false),
        CheckpointStartupDecision::NoCheckpoint
    );
    // Headers/unsafe flags are irrelevant when no checkpoint is supplied.
    assert_eq!(
        classify_checkpoint_startup(false, true, true),
        CheckpointStartupDecision::NoCheckpoint
    );
}

#[test]
fn checkpoint_with_headers_chain_is_verified() {
    assert_eq!(
        classify_checkpoint_startup(true, true, false),
        CheckpointStartupDecision::Verify
    );
    // The unsafe flag must not downgrade the verified path when a chain is
    // present — verification still runs.
    assert_eq!(
        classify_checkpoint_startup(true, true, true),
        CheckpointStartupDecision::Verify
    );
}

#[test]
fn standalone_checkpoint_is_refused_by_default() {
    // Regression for #214: a checkpoint with no finalized-headers chain must
    // be refused rather than silently imported unverified.
    assert_eq!(
        classify_checkpoint_startup(true, false, false),
        CheckpointStartupDecision::RefuseUnverified
    );
}

#[test]
fn standalone_checkpoint_allowed_only_with_unsafe_flag() {
    assert_eq!(
        classify_checkpoint_startup(true, false, true),
        CheckpointStartupDecision::SkipUnsafe
    );
}

#[test]
fn last_block_binding_accepts_matching_or_absent() {
    let committed: Digest = [7u8; 32].into();
    // No last_block supplied: nothing to bind.
    assert!(check_last_block_binding(None, committed).is_ok());
    // last_block matches the verified terminal's finalized block.
    assert!(check_last_block_binding(Some(committed), committed).is_ok());
}

#[test]
fn last_block_binding_rejects_mismatch() {
    // A directory pairing a verified checkpoint with an unrelated last_block
    // must be rejected.
    let committed: Digest = [7u8; 32].into();
    let unrelated: Digest = [9u8; 32].into();
    assert!(check_last_block_binding(Some(unrelated), committed).is_err());
}

// #214 single-file path: a standalone checkpoint file decodes to a
// self-consistent state but can never carry a finalized-header chain, so
// startup must refuse it by default and only import it under the explicit
// unsafe flag. Exercises the real on-disk read_checkpoint path.
#[test]
fn single_file_import_has_no_chain_and_is_refused() {
    let state = ConsensusState::new(
        Default::default(),
        32_000_000_000,
        NonZeroU64::new(10).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        1,
        0,
        3,
    );
    let checkpoint = Checkpoint::new(&state);

    let path = std::env::temp_dir().join(format!(
        "summit_single_file_checkpoint_{}.ssz",
        std::process::id()
    ));
    std::fs::write(&path, checkpoint.as_ssz_bytes()).unwrap();
    let path_str = path.to_str().unwrap().to_string();

    let loaded = read_checkpoint::<MultisigScheme>(&path_str, false);
    let _ = std::fs::remove_file(&path);

    // A single-file import yields a checkpoint with no chain to verify against.
    assert!(loaded.raw_checkpoint.is_some());
    assert!(
        loaded.finalized_headers_chain.is_none(),
        "a single-file import cannot carry a finalized-header chain"
    );

    // So startup refuses it by default, and only imports it when the operator
    // explicitly waives verification.
    assert_eq!(
        classify_checkpoint_startup(
            loaded.raw_checkpoint.is_some(),
            loaded.finalized_headers_chain.is_some(),
            false,
        ),
        CheckpointStartupDecision::RefuseUnverified
    );
    assert_eq!(
        classify_checkpoint_startup(
            loaded.raw_checkpoint.is_some(),
            loaded.finalized_headers_chain.is_some(),
            true,
        ),
        CheckpointStartupDecision::SkipUnsafe
    );
}

// Checkpoints are created at the penultimate block of an epoch and cannot nest
// a pending checkpoint (ConsensusState::try_from rejects it), so a state
// restored from a checkpoint always starts with pending_checkpoint unset. Live
// peers at that point have it set, and their captured state root includes its
// digest leaf; the epoch terminal block commits that root as
// parent_beacon_block_root and its aux data requires the pending checkpoint.
// read_checkpoint must therefore repopulate the field from the checkpoint it
// just loaded and re-capture the root, or the restored node cannot
// propose/verify/certify the terminal block and its state root diverges from
// its peers until the epoch boundary.
#[test]
fn read_checkpoint_repopulates_pending_checkpoint() {
    // A live peer at the penultimate block (finalizer flow: create the
    // checkpoint, set it as pending, capture the root).
    let mut live = ConsensusState::new(
        Default::default(),
        32_000_000_000,
        NonZeroU64::new(10).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        1,
        0,
        3,
    );
    let checkpoint = Checkpoint::new(&live);
    live.set_pending_checkpoint(Some(checkpoint.clone()));
    live.capture_state_root(live.get_latest_height());

    let assert_restored = |restored: &ConsensusState, branch: &str| {
        assert_eq!(
            restored.get_pending_checkpoint().map(|cp| cp.digest),
            Some(checkpoint.digest),
            "{branch}: restore must repopulate pending_checkpoint from the loaded checkpoint"
        );
        assert_eq!(
            restored.get_state_root(),
            live.get_state_root(),
            "{branch}: restored state root must match the live penultimate root"
        );
    };

    // Single-file branch.
    let file_path = std::env::temp_dir().join(format!(
        "summit_repopulate_checkpoint_{}.ssz",
        std::process::id()
    ));
    std::fs::write(&file_path, checkpoint.as_ssz_bytes()).unwrap();
    let loaded = read_checkpoint::<MultisigScheme>(&file_path.to_str().unwrap().to_string(), false);
    let _ = std::fs::remove_file(&file_path);
    assert_restored(
        &loaded.consensus_state.expect("checkpoint state must load"),
        "file",
    );

    // Directory branch.
    let dir_path = std::env::temp_dir().join(format!(
        "summit_repopulate_checkpoint_dir_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir_path).unwrap();
    std::fs::write(dir_path.join("checkpoint"), checkpoint.as_ssz_bytes()).unwrap();
    let loaded = read_checkpoint::<MultisigScheme>(&dir_path.to_str().unwrap().to_string(), false);
    let _ = std::fs::remove_dir_all(&dir_path);
    assert_restored(
        &loaded.consensus_state.expect("checkpoint state must load"),
        "directory",
    );
}
