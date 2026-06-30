use super::super::*;
use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::ssz_state_tree;

use alloy_primitives::Address;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Signer, bls12381, ed25519};

use super::common::*;

#[test]
fn pending_execution_requests_bind_into_captured_state_root() {
    let mut state = ConsensusState::default();
    state.rebuild_ssz_tree();
    state.capture_state_root(0);
    let before = state.get_state_root();

    // Buffering a deferred request via the production mutator must change the
    // captured state root (the mutator keeps the SSZ subtree in sync).
    state.push_pending_execution_request(alloy_primitives::Bytes::from(vec![0xAAu8; 40]));
    state.capture_state_root(0);
    let after = state.get_state_root();
    assert_ne!(
        before, after,
        "pushing a pending execution request must change the captured state root"
    );

    // Draining them restores the prior (empty-collection) root.
    let taken = state.take_pending_execution_requests();
    assert_eq!(taken.len(), 1);
    state.capture_state_root(0);
    assert_eq!(
        state.get_state_root(),
        before,
        "draining pending requests must restore the prior state root"
    );
}

#[test]
fn pending_checkpoint_binds_into_captured_state_root() {
    let mut state = ConsensusState::default();
    state.rebuild_ssz_tree();
    state.capture_state_root(0);
    let before = state.get_state_root();

    // Setting the pending checkpoint via the production mutator binds its digest
    // into the captured state root.
    let checkpoint = Checkpoint::new(&state);
    state.set_pending_checkpoint(Some(checkpoint));
    state.capture_state_root(0);
    let after = state.get_state_root();
    assert_ne!(
        before, after,
        "setting a pending checkpoint must change the captured state root"
    );

    // Taking it restores the prior (no-checkpoint) root.
    let taken = state.take_pending_checkpoint();
    assert!(taken.is_some());
    state.capture_state_root(0);
    assert_eq!(
        state.get_state_root(),
        before,
        "taking the pending checkpoint must restore the prior state root"
    );
}

#[test]
fn dynamic_epoch_schedule_binds_into_captured_state_root() {
    use std::num::NonZeroU64;

    let mut state = ConsensusState::default();
    state.rebuild_ssz_tree();
    state.capture_state_root(0);
    let before = state.get_state_root();

    // Mutate the epoch schedule through interior mutability — no `&mut
    // ConsensusState` setter is involved — and confirm the captured root still
    // changes, via the refresh in `capture_state_root`.
    state
        .get_epocher()
        .update_length(NonZeroU64::new(20).unwrap())
        .expect("update_length should succeed");
    state.capture_state_root(0);

    assert_ne!(
        before,
        state.get_state_root(),
        "an epoch-schedule change must change the captured state root"
    );
}

/// Changing only a validator-account map key (the node
/// pubkey) must change the SSZ state root. The tree commits account values
/// positionally without the key, so two states with the same account value
/// under different keys must not share a root.
#[test]
fn validator_account_key_binds_into_state_root() {
    let account = ValidatorAccount {
        consensus_public_key: bls12381::PrivateKey::from_seed(1).public_key(),
        withdrawal_credentials: Address::from([7u8; 20]),
        balance: 32_000_000_000,
        status: ValidatorStatus::Active,
        has_pending_deposit: false,
        has_pending_withdrawal: false,
        joining_epoch: 0,
        last_deposit_index: 0,
    };

    let root_for_key = |key: [u8; 32]| {
        let mut state = ConsensusState::default();
        state.validator_accounts.insert(key, account.clone());
        state.rebuild_ssz_tree();
        state.capture_state_root(0);
        state.get_state_root()
    };

    assert_ne!(
        root_for_key([1u8; 32]),
        root_for_key([2u8; 32]),
        "changing only the validator-account map key must change the state root"
    );
}

/// Changing only the scheduled-activation epoch key must
/// change the SSZ state root. added_validators is flattened to its values, so
/// the same activation under a different epoch must not share a root.
#[test]
fn added_validator_epoch_key_binds_into_state_root() {
    let av = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(1).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(1).public_key(),
    };

    let root_for_epoch = |epoch: u64| {
        let mut state = ConsensusState::default();
        state.add_validator(epoch, av.clone());
        state.rebuild_ssz_tree();
        state.capture_state_root(0);
        state.get_state_root()
    };

    assert_ne!(
        root_for_epoch(5),
        root_for_epoch(6),
        "changing only the added-validator epoch key must change the state root"
    );
}

// ---- SSZ state tree integration tests ----

#[test]
fn test_ssz_scalar_setters_update_root() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    state.set_epoch(10);
    assert_ne!(state.ssz_tree().root(), root_before);

    let r1 = state.ssz_tree().root();
    state.set_view(99);
    assert_ne!(state.ssz_tree().root(), r1);

    let r2 = state.ssz_tree().root();
    state.set_latest_height(500);
    assert_ne!(state.ssz_tree().root(), r2);

    let r3 = state.ssz_tree().root();
    state.set_head_digest(sha256::Digest([0xAB; 32]));
    assert_ne!(state.ssz_tree().root(), r3);

    let r4 = state.ssz_tree().root();
    state.set_epoch_genesis_hash([0xCD; 32]);
    assert_ne!(state.ssz_tree().root(), r4);

    let r5 = state.ssz_tree().root();
    state.set_minimum_stake(16_000_000_000);
    assert_ne!(state.ssz_tree().root(), r5);

    let r6 = state.ssz_tree().root();
    state.set_maximum_stake(64_000_000_000);
    assert_ne!(state.ssz_tree().root(), r6);

    let r7 = state.ssz_tree().root();
    state.set_next_withdrawal_index(42);
    assert_ne!(state.ssz_tree().root(), r7);
}

#[test]
fn test_ssz_scalar_proof_verifies() {
    let mut state = ConsensusState::default();
    state.set_epoch(10);
    state.set_view(99);

    let tree = state.ssz_tree();
    let root = tree.root();
    let proof = tree.generate_scalar_proof(ssz_state_tree::EPOCH);
    assert!(proof.verify(&root));

    let proof_view = tree.generate_scalar_proof(ssz_state_tree::VIEW);
    assert!(proof_view.verify(&root));
}

#[test]
fn test_ssz_forkchoice_updates() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    let fcs = ForkchoiceState {
        head_block_hash: [0x11; 32].into(),
        safe_block_hash: [0x22; 32].into(),
        finalized_block_hash: [0x33; 32].into(),
    };
    state.set_forkchoice(fcs);
    assert_ne!(state.ssz_tree().root(), root_before);

    let r1 = state.ssz_tree().root();

    // Partial setters
    state.set_forkchoice_head([0xAA; 32].into());
    assert_ne!(state.ssz_tree().root(), r1);

    let r2 = state.ssz_tree().root();
    state.set_forkchoice_safe_and_finalized([0xBB; 32].into());
    assert_ne!(state.ssz_tree().root(), r2);
}

#[test]
fn test_ssz_validator_account_lifecycle() {
    let mut state = ConsensusState::default();
    let pubkey = [1u8; 32];
    let account = create_test_validator_account(1, 32_000_000_000);

    let root_before = state.ssz_tree().root();

    // Insert
    state.set_account(pubkey, account.clone());
    assert_ne!(state.ssz_tree().root(), root_before);

    // Verify proof
    let tree = state.ssz_tree();
    let root = tree.root();
    let keys = [pubkey];
    let proof = tree.generate_validator_proof(&pubkey, &keys).unwrap();
    assert!(proof.verify(&root));

    // Update balance
    let mut updated = account.clone();
    updated.balance = 48_000_000_000;
    state.set_account(pubkey, updated);
    assert_ne!(state.ssz_tree().root(), root);

    // Remove
    let root_with_account = state.ssz_tree().root();
    state.remove_account(&pubkey);
    assert_ne!(state.ssz_tree().root(), root_with_account);

    // Validator proof should return None for removed pubkey
    assert!(
        state
            .ssz_tree()
            .generate_validator_proof(&pubkey, &[])
            .is_none()
    );
}

#[test]
fn test_ssz_deposit_queue_operations() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    let deposit = create_test_deposit_request(1, 32_000_000_000);
    state.push_deposit(deposit.clone());
    assert_ne!(state.ssz_tree().root(), root_before);

    let root_with_deposit = state.ssz_tree().root();

    // Pop deposit changes root
    let popped = state.pop_deposit().unwrap();
    assert_eq!(popped.amount, 32_000_000_000);
    assert_ne!(state.ssz_tree().root(), root_with_deposit);
}

#[test]
fn test_ssz_withdrawal_queue_operations() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    let withdrawal = create_test_withdrawal(1, 16_000_000_000, 5);
    state.push_withdrawal(withdrawal);
    assert_ne!(state.ssz_tree().root(), root_before);

    let root_with_withdrawal = state.ssz_tree().root();

    // Pop withdrawal changes root
    let popped = state.pop_withdrawal(5).unwrap();
    assert_eq!(popped.inner.amount, 16_000_000_000);
    assert_ne!(state.ssz_tree().root(), root_with_withdrawal);
}

#[test]
fn test_ssz_added_removed_validators() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    let validator = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(10).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
    };

    // add_validator changes root
    state.add_validator(5, validator.clone());
    assert_ne!(state.ssz_tree().root(), root_before);

    let root_with_added = state.ssz_tree().root();

    // remove_added_validators_for_epoch changes root
    state.remove_added_validators_for_epoch(5);
    assert_ne!(state.ssz_tree().root(), root_with_added);

    // push_removed_validator / clear_removed_validators
    let removed_pk = ed25519::PrivateKey::from_seed(20).public_key();
    let r1 = state.ssz_tree().root();
    state.push_removed_validator(removed_pk);
    assert_ne!(state.ssz_tree().root(), r1);

    let r2 = state.ssz_tree().root();
    state.clear_removed_validators();
    assert_ne!(state.ssz_tree().root(), r2);
}

#[test]
fn test_ssz_protocol_param_changes() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();

    state.push_protocol_param_change(ProtocolParam::MinimumStake(40_000_000_000));
    assert_ne!(state.ssz_tree().root(), root_before);

    let r1 = state.ssz_tree().root();
    state.push_protocol_param_change(ProtocolParam::MaximumStake(80_000_000_000));
    assert_ne!(state.ssz_tree().root(), r1);

    // apply_protocol_parameter_changes consumes them
    let changed = state.apply_protocol_parameter_changes().unwrap();
    assert!(changed);
    assert_eq!(state.get_minimum_stake(), 40_000_000_000);
    assert_eq!(state.get_maximum_stake(), 80_000_000_000);

    let root_before_tax = state.ssz_tree().root();
    state.push_protocol_param_change(ProtocolParam::InvalidDepositTax(25));
    assert_ne!(state.ssz_tree().root(), root_before_tax);
    let changed = state.apply_protocol_parameter_changes().unwrap();
    assert!(!changed);
    assert_eq!(state.get_invalid_deposit_tax(), 25);

    state.push_protocol_param_change(ProtocolParam::InvalidDepositTax(101));
    let changed = state.apply_protocol_parameter_changes().unwrap();
    assert!(!changed);
    assert_eq!(state.get_invalid_deposit_tax(), 25);
}

#[test]
fn test_ssz_rebuild_matches_incremental() {
    let mut state = ConsensusState::default();

    // Build up state incrementally through setters
    state.set_epoch(7);
    state.set_view(42);
    state.set_latest_height(100);
    state.set_head_digest(sha256::Digest([0xAB; 32]));
    state.set_epoch_genesis_hash([0xCD; 32]);
    state.set_minimum_stake(16_000_000_000);
    state.set_maximum_stake(64_000_000_000);
    state.set_next_withdrawal_index(5);
    state.set_forkchoice(ForkchoiceState {
        head_block_hash: [0x11; 32].into(),
        safe_block_hash: [0x22; 32].into(),
        finalized_block_hash: [0x33; 32].into(),
    });

    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 32_000_000_000));

    let deposit = create_test_deposit_request(1, 32_000_000_000);
    state.push_deposit(deposit);

    let withdrawal = create_test_withdrawal(1, 16_000_000_000, 5);
    state.push_withdrawal(withdrawal);

    let incremental_root = state.ssz_tree().root();

    // Rebuild from scratch
    state.rebuild_ssz_tree();
    let rebuilt_root = state.ssz_tree().root();

    assert_eq!(incremental_root, rebuilt_root);
}

#[test]
fn test_ssz_root_survives_serialization_roundtrip() {
    let mut state = ConsensusState::default();

    state.set_epoch(5);
    state.set_view(99);
    state.set_latest_height(200);
    state.set_next_withdrawal_index(10);
    state.set_epoch_genesis_hash([0xFF; 32]);
    state.set_forkchoice(ForkchoiceState {
        head_block_hash: [0xAA; 32].into(),
        safe_block_hash: [0xBB; 32].into(),
        finalized_block_hash: [0xCC; 32].into(),
    });

    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 32_000_000_000));

    let deposit = create_test_deposit_request(1, 32_000_000_000);
    state.push_deposit(deposit);

    let withdrawal = create_test_withdrawal(1, 16_000_000_000, 7);
    state.push_withdrawal(withdrawal);

    let original_root = state.ssz_tree().root();

    // Round-trip through serialization
    let mut encoded = state.encode();
    let decoded = ConsensusState::decode(&mut encoded).unwrap();

    assert_eq!(decoded.ssz_tree().root(), original_root);
}

#[test]
fn test_ssz_set_validator_accounts_rebuilds() {
    let mut state = ConsensusState::default();
    state.set_epoch(3);
    state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

    let root_before = state.ssz_tree().root();

    // Bulk replace validator accounts
    let mut new_accounts = BTreeMap::new();
    new_accounts.insert([2u8; 32], create_test_validator_account(2, 64_000_000_000));
    new_accounts.insert([3u8; 32], create_test_validator_account(3, 48_000_000_000));
    state.set_validator_accounts(new_accounts);

    assert_ne!(state.ssz_tree().root(), root_before);

    // New validators have proofs
    let tree = state.ssz_tree();
    let root = tree.root();
    let keys = [[2u8; 32], [3u8; 32]];
    let proof = tree.generate_validator_proof(&[2u8; 32], &keys).unwrap();
    assert!(proof.verify(&root));

    // Old validator is gone
    assert!(tree.generate_validator_proof(&[1u8; 32], &keys).is_none());
}

#[test]
fn test_ssz_clone_independence() {
    let mut state = ConsensusState::default();
    state.set_epoch(5);
    state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

    let cloned = state.clone();
    let root_before = cloned.ssz_tree().root();

    // Mutate original
    state.set_epoch(99);
    state.set_account([2u8; 32], create_test_validator_account(2, 64_000_000_000));

    // Clone is unaffected
    assert_eq!(cloned.ssz_tree().root(), root_before);
}

#[test]
fn test_ssz_capture_and_proof_tree() {
    let mut state = ConsensusState::default();
    state.set_epoch(5);
    state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

    // Capture state root
    state.capture_state_root(100);
    let captured_root = state.get_state_root();
    assert_eq!(captured_root, state.proof_tree().root());
    assert_eq!(state.get_proof_el_block_number(), 100);

    // Mutate the live tree
    state.set_epoch(99);
    assert_ne!(state.ssz_tree().root(), captured_root);

    // Proof tree is still frozen at the captured state
    assert_eq!(state.proof_tree().root(), captured_root);

    // Proof still verifies against captured root
    let proof = state
        .proof_tree()
        .generate_validator_proof(&[1u8; 32], state.proof_validator_keys())
        .unwrap();
    assert!(proof.verify(&captured_root));
}

/// A restart between `capture_state_root` and the next block must preserve
/// the captured snapshot: `state_root`, `proof_tree`, `proof_validator_keys`,
/// and `proof_el_block_number`. The finalizer captures the root inside
/// `execute_block` and only persists ConsensusState *after* the
/// epoch-transition mutations run, so the live SSZ tree at persistence
/// time differs from the captured one. If `Read` rebuilds the snapshot
/// from the post-mutation live fields, restarted validators end up with
/// a different aux-data `state_root` than uninterrupted peers — they
/// reject each other's proposals on `parent_beacon_block_root`.
#[test]
fn test_serialization_preserves_captured_proof_snapshot() {
    // Build state with one validator and capture a snapshot.
    let mut state = ConsensusState::default();
    state.set_epoch(5);
    state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));
    state.capture_state_root(100);

    let captured_root = state.get_state_root();
    let captured_proof_root = state.proof_tree().root();
    let captured_validator_keys = state.proof_validator_keys().to_vec();
    let captured_el_block = state.get_proof_el_block_number();

    // Mutate the live fields the same way an epoch-boundary apply does:
    // bump epoch, swap a validator account out. Any live-tree mutation is
    // sufficient — these specific ones ensure the post-mutation live root
    // is provably different from the captured one.
    state.set_epoch(99);
    state.set_account([2u8; 32], create_test_validator_account(2, 32_000_000_000));
    assert_ne!(
        state.ssz_tree().root(),
        captured_root,
        "live tree mutations must produce a different root; the captured \
             snapshot must NOT track them — this is the property the audit \
             worries restart breaks"
    );
    // The frozen snapshot is unaffected by the live mutations: this is
    // the invariant `capture_state_root` exists to provide, and it's the
    // invariant the encode/decode roundtrip below must preserve.
    assert_eq!(
        state.get_state_root(),
        captured_root,
        "post-capture mutations must not touch the frozen state_root"
    );

    // Persist and restore.
    let mut encoded = state.encode();
    let restored = ConsensusState::decode(&mut encoded).expect("decode");

    // Property 1: cross-validator block-validity agreement. A restarted
    // validator and an uninterrupted peer both need to derive the same
    // `parent_beacon_block_root` expectation; this is the field they use.
    assert_eq!(
        restored.get_state_root(),
        captured_root,
        "state_root must equal the pre-mutation captured root after restart, \
             not the post-mutation live root"
    );

    // Property 2: proof generation. A restarted validator must be able to
    // produce proofs that verify against the same on-chain root.
    assert_eq!(
        restored.proof_tree().root(),
        captured_proof_root,
        "proof_tree must reflect the captured snapshot, not the post-mutation tree"
    );
    assert_eq!(
        restored.proof_validator_keys(),
        captured_validator_keys.as_slice(),
        "proof_validator_keys must be the captured snapshot"
    );
    assert_eq!(
        restored.get_proof_el_block_number(),
        captured_el_block,
        "proof_el_block_number must be the captured value"
    );

    // End-to-end: a proof generated by the restored state must verify
    // against the captured root.
    let restored_proof = restored
        .proof_tree()
        .generate_validator_proof(&[1u8; 32], restored.proof_validator_keys())
        .unwrap();
    assert!(
        restored_proof.verify(&captured_root),
        "proof generated post-restart must verify against the captured root"
    );
}

#[test]
fn test_ssz_push_withdrawal_request_keeps_next_index_in_sync() {
    use crate::execution_request::WithdrawalRequest;

    let mut state = ConsensusState::default();
    state.set_epoch(1);
    state.set_account([1u8; 32], create_test_validator_account(1, 32_000_000_000));

    // push_withdrawal_request internally calls WithdrawalQueue::push_request
    // which increments next_index. The SSZ tree's NEXT_WITHDRAWAL_INDEX leaf
    // must stay in sync.
    let request = WithdrawalRequest {
        source_address: alloy_primitives::Address::from([0xAA; 20]),
        validator_pubkey: [1u8; 32],
        amount: 16_000_000_000,
    };
    state.push_withdrawal_request(request, 5, 16_000_000_000);

    let incremental_root = state.ssz_tree().root();

    // Rebuild must produce the same root
    state.rebuild_ssz_tree();
    let rebuilt_root = state.ssz_tree().root();

    assert_eq!(
        incremental_root, rebuilt_root,
        "push_withdrawal_request must keep NEXT_WITHDRAWAL_INDEX in sync with rebuild"
    );
}

/// Simulate the full block execution lifecycle and check that
/// incremental SSZ tree matches rebuild at every step.
#[test]
fn test_ssz_full_block_lifecycle_matches_rebuild() {
    use crate::execution_request::WithdrawalRequest;
    use crate::header::AddedValidator;
    use crate::protocol_params::ProtocolParam;
    use commonware_cryptography::Signer;

    // Derive valid Ed25519 pubkeys from seeds
    let ed_keys: Vec<ed25519::PrivateKey> = (1..=5u64)
        .map(|i| ed25519::PrivateKey::from_seed(i))
        .collect();
    let pubkeys: Vec<[u8; 32]> = ed_keys
        .iter()
        .map(|k| k.public_key().as_ref().try_into().unwrap())
        .collect();

    // --- Genesis setup (mimics get_initial_state in args.rs) ---
    let forkchoice = ForkchoiceState {
        head_block_hash: [0xAA; 32].into(),
        safe_block_hash: [0xAA; 32].into(),
        finalized_block_hash: [0xAA; 32].into(),
    };
    let mut state = ConsensusState::new(
        forkchoice,
        32_000_000_000,
        32_000_000_000,
        NonZeroU64::new(10).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        DEFAULT_MINIMUM_VALIDATOR_COUNT,
        0,
    );

    // Add 4 genesis validators (like the testnet)
    for i in 0..4 {
        state.set_account(
            pubkeys[i],
            create_test_validator_account(i as u64 + 1, 32_000_000_000),
        );
    }

    // Check: after genesis setup, incremental matches rebuild
    let genesis_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        genesis_root,
        state.ssz_tree().root(),
        "genesis: incremental != rebuild"
    );

    // --- Simulate execute_block for height 1 ---
    state.set_forkchoice_head([0xBB; 32].into());
    state.set_latest_height(1);
    state.set_view(1);
    state.set_head_digest([0xCC; 32].into());
    state.capture_state_root(100);

    let block1_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        block1_root,
        state.ssz_tree().root(),
        "block 1: incremental != rebuild"
    );

    // --- Simulate finalization (forkchoice update after capture) ---
    state.set_forkchoice_safe_and_finalized([0xBB; 32].into());

    let post_finalization_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        post_finalization_root,
        state.ssz_tree().root(),
        "post-finalization: incremental != rebuild"
    );

    // --- Simulate execute_block for height 2 (with a deposit) ---
    state.set_forkchoice_head([0xDD; 32].into());

    // Push a deposit request
    let deposit = create_test_deposit_request(1, 32_000_000_000);
    state.push_deposit(deposit);

    state.set_latest_height(2);
    state.set_view(2);
    state.set_head_digest([0xEE; 32].into());
    state.capture_state_root(101);

    let block2_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        block2_root,
        state.ssz_tree().root(),
        "block 2: incremental != rebuild"
    );

    // --- Simulate execute_block for height 3 (pop deposit, push withdrawal) ---
    state.set_forkchoice_head([0xFF; 32].into());

    // Pop the deposit
    let _ = state.pop_deposit();

    // Process the deposit: create a new validator
    let new_pubkey = pubkeys[4];
    let mut new_account = create_test_validator_account(5, 32_000_000_000);
    new_account.status = ValidatorStatus::Joining;
    new_account.joining_epoch = 2;
    state.set_account(new_pubkey, new_account);

    // Add to added_validators
    let node_key = ed_keys[4].public_key();
    let consensus_key = bls12381::PrivateKey::from_seed(5).public_key();
    state.add_validator(
        2,
        AddedValidator {
            node_key,
            consensus_key,
        },
    );

    state.set_latest_height(3);
    state.set_view(3);
    state.set_head_digest([0x11; 32].into());
    state.capture_state_root(102);

    let block3_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        block3_root,
        state.ssz_tree().root(),
        "block 3: incremental != rebuild"
    );

    // --- Simulate epoch transition ---
    // Apply protocol param changes (none in this case)
    state.apply_protocol_parameter_changes().unwrap();

    // Activate the joining validator
    let mut account = state.get_account(&new_pubkey).unwrap().clone();
    account.status = ValidatorStatus::Active;
    state.set_account(new_pubkey, account);

    // Clear added/removed validators
    state.remove_added_validators_for_epoch(2);
    state.clear_removed_validators();

    // Increment epoch
    state.set_epoch(2);
    state.set_epoch_genesis_hash([0x22; 32]);

    let epoch_transition_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        epoch_transition_root,
        state.ssz_tree().root(),
        "epoch transition: incremental != rebuild"
    );

    // --- Simulate withdrawal request ---
    let wr = WithdrawalRequest {
        source_address: alloy_primitives::Address::from([0xAA; 20]),
        validator_pubkey: pubkeys[0],
        amount: 32_000_000_000,
    };
    state.push_withdrawal_request(wr, 4, 32_000_000_000);

    // Mark validator as exiting
    let mut account = state.get_account(&pubkeys[0]).unwrap().clone();
    account.balance = 0;
    account.has_pending_withdrawal = true;
    account.status = ValidatorStatus::Inactive;
    state.set_account(pubkeys[0], account);

    state.push_removed_validator(ed_keys[0].public_key());

    let withdrawal_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        withdrawal_root,
        state.ssz_tree().root(),
        "withdrawal: incremental != rebuild"
    );

    // --- Simulate protocol param change ---
    state.push_protocol_param_change(ProtocolParam::MinimumStake(16_000_000_000));
    state.apply_protocol_parameter_changes().unwrap();

    let param_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        param_root,
        state.ssz_tree().root(),
        "protocol param: incremental != rebuild"
    );

    // --- Remove validator account ---
    state.remove_account(&pubkeys[0]);

    let remove_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        remove_root,
        state.ssz_tree().root(),
        "remove validator: incremental != rebuild"
    );
}

#[test]
fn test_withdrawal_requests_keep_ssz_tree_in_sync() {
    let mut state = ConsensusState::default();

    let req = |tag: u8, amount: u64| WithdrawalRequest {
        source_address: Address::from([tag; 20]),
        validator_pubkey: [tag; 32],
        amount,
    };

    // Interleave validator withdrawals and deposit refunds. Pushing a validator
    // withdrawal while a refund is already queued exercises the rebuild branch in
    // `push_withdrawal_request_with_kind`; the rest are incremental appends.
    state.push_withdrawal_request(req(1, 100), 5, 100);
    state.push_refund_withdrawal_request(req(2, 200), 5, 0);
    state.push_withdrawal_request(req(3, 300), 6, 300); // validator after a refund → rebuild
    state.push_refund_withdrawal_request(req(4, 400), 7, 0);

    // The incrementally maintained root must equal a full rebuild from the queue.
    let incremental_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        incremental_root,
        state.ssz_tree().root(),
        "incrementally maintained withdrawal SSZ root must match a full rebuild"
    );
}

// Genesis startup builds ConsensusState::new (which
// freezes the proof snapshot over an empty validator set), then inserts the
// genesis committee via set_account, which only touches the live tree. A
// rebuild_ssz_tree after materialization must re-freeze so the exposed
// state_root, proof_tree, and proof_validator_keys all commit to the
// installed committee, rather than staying stale until the first capture.
#[test]
fn test_genesis_materialization_refreshes_proof_snapshot() {
    let mut state = ConsensusState::new(
        ForkchoiceState::default(),
        0,
        0,
        NonZeroU64::new(10).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        0,
        0,
    );

    // mirror node/src/args.rs genesis materialization.
    let mut keys: Vec<[u8; 32]> = Vec::new();
    for i in 0..4u64 {
        let mut pubkey = [0u8; 32];
        pubkey[0] = i as u8 + 1;
        state.set_account(pubkey, create_test_validator_account(i, 32_000_000_000));
        keys.push(pubkey);
    }
    keys.sort();

    // before re freezing, the frozen snapshot still reflects the empty set
    // that new() captured, so it diverges from the live tree.
    assert_ne!(
        state.get_state_root(),
        state.ssz_tree().root(),
        "frozen root should be stale before the post genesis rebuild"
    );

    // the fix: re-freeze after the committee is installed.
    state.rebuild_ssz_tree();

    assert_eq!(
        state.get_state_root(),
        state.ssz_tree().root(),
        "state_root should commit to the live tree after rebuild"
    );
    assert_eq!(
        state.proof_tree().root(),
        state.ssz_tree().root(),
        "proof_tree should commit to the live tree after rebuild"
    );
    assert_eq!(
        state.proof_validator_keys(),
        keys.as_slice(),
        "proof_validator_keys should list the genesis committee after rebuild"
    );
}
