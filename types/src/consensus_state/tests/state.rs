use super::super::*;
use crate::account::ValidatorStatus;

use alloy_primitives::Address;
use commonware_consensus::types::{Epoch, Epocher};

use super::common::*;

#[test]
fn active_exit_counter_preserves_minimum_validator_count() {
    let mut state = ConsensusState::default();
    state.set_minimum_validator_count(3);

    for i in 0..4 {
        state.set_account(
            [i as u8 + 1; 32],
            create_test_validator_account(i as u64 + 1, 32_000_000_000),
        );
    }

    assert!(state.can_accept_active_validator_exit());
    state.increment_pending_active_validator_exits();
    assert!(!state.can_accept_active_validator_exit());

    let mut exiting_account = state.get_account(&[1u8; 32]).unwrap().clone();
    exiting_account.status = ValidatorStatus::SubmittedExitRequest;
    state.set_account([1u8; 32], exiting_account);
    assert_eq!(state.current_epoch_active_validator_count(), 4);
    assert!(!state.can_accept_active_validator_exit());

    let refund = create_test_withdrawal(99, 1, 0);
    state.push_withdrawal(refund);
    assert_eq!(state.get_withdrawal_count_for_epoch(0), 1);
    assert!(!state.can_accept_active_validator_exit());

    state.reset_pending_active_validator_exits();
    assert!(state.can_accept_active_validator_exit());
}

#[test]
fn exit_floor_honors_queued_minimum_validator_count_raise() {
    // Removals staged this epoch take effect next epoch, at the same boundary
    // a queued MinimumValidatorCount change applies — so the floor check must
    // use the prospective value, not the current one.
    let mut state = ConsensusState::default();
    state.set_minimum_validator_count(2);
    for i in 0..3u8 {
        state.set_account(
            [i + 1; 32],
            create_test_validator_account(i as u64 + 1, 32_000_000_000),
        );
    }

    // 3 active, floor 2: one exit is acceptable (3 - 1 >= 2).
    assert!(state.can_accept_active_validator_exit());

    // Queue a raise to floor 3. The prospective floor now governs: 3 - 1 = 2 < 3.
    state.push_protocol_param_change(ProtocolParam::MinimumValidatorCount(3));
    assert_eq!(state.prospective_minimum_validator_count(), 3);
    assert!(!state.can_accept_active_validator_exit());

    // A queued lowering is likewise honored before it is applied.
    state.protocol_param_changes.clear();
    state.push_protocol_param_change(ProtocolParam::MinimumValidatorCount(1));
    assert_eq!(state.prospective_minimum_validator_count(), 1);
    assert!(state.can_accept_active_validator_exit());
}

#[test]
fn test_clone_preserves_epoch_schedule_snapshot() {
    let state = ConsensusState::new(
        ForkchoiceState::default(),
        0,
        NonZeroU64::new(10).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        0,
        0,
        3,
    );
    state.get_epocher().advance_epoch(Epoch::new(0));

    let cloned = state.clone();
    let cloned_epoch_two_bounds_before = (
        cloned.get_epocher().first(Epoch::new(2)),
        cloned.get_epocher().last(Epoch::new(2)),
    );

    state
        .get_epocher()
        .update_length(NonZeroU64::new(20).unwrap())
        .unwrap();
    state.get_epocher().advance_epoch(Epoch::new(2));

    assert_eq!(
        (
            cloned.get_epocher().first(Epoch::new(2)),
            cloned.get_epocher().last(Epoch::new(2)),
        ),
        cloned_epoch_two_bounds_before,
        "cloned consensus state must retain the epoch schedule captured at clone time",
    );
}

#[test]
fn test_account_operations() {
    let mut state = ConsensusState::default();
    let pubkey = [1u8; 32];
    let account = create_test_validator_account(1, 32000000000);

    // Test that account doesn't exist initially
    assert!(state.get_account(&pubkey).is_none());

    // Test setting account
    state.set_account(pubkey, account.clone());
    let retrieved_account = state.get_account(&pubkey);
    assert!(retrieved_account.is_some());
    assert_eq!(retrieved_account.unwrap().balance, account.balance);

    // Test removing account
    let removed_account = state.remove_account(&pubkey);
    assert!(removed_account.is_some());
    assert_eq!(removed_account.unwrap().balance, account.balance);

    // Test that account no longer exists
    assert!(state.get_account(&pubkey).is_none());

    // Test removing non-existent account
    let non_existent = state.remove_account(&pubkey);
    assert!(non_existent.is_none());
}

#[test]
fn test_try_from_checkpoint() {
    // Create a populated ConsensusState
    let mut original_state = ConsensusState::default();
    original_state.set_epoch(5);
    original_state.set_view(789);
    original_state.set_latest_height(100);
    original_state.set_next_withdrawal_index(42);
    original_state.set_epoch_genesis_hash([99u8; 32]);

    // Add some data
    let deposit = create_test_deposit_request(1, 32000000000);
    original_state.push_deposit(deposit);

    let withdrawal = create_test_withdrawal(1, 16000000000, 7);
    original_state.push_withdrawal(withdrawal);

    let pubkey = [1u8; 32];
    let account = create_test_validator_account(1, 32000000000);
    original_state.set_account(pubkey, account);

    // Convert to checkpoint
    let checkpoint = Checkpoint::new(&original_state);

    // Convert back to ConsensusState
    let restored_state: ConsensusState = checkpoint
        .try_into()
        .expect("Failed to convert checkpoint back to ConsensusState");

    // Verify the data matches
    assert_eq!(restored_state.epoch, original_state.epoch);
    assert_eq!(restored_state.view, original_state.view);
    assert_eq!(restored_state.latest_height, original_state.latest_height);
    assert_eq!(
        restored_state.get_next_withdrawal_index(),
        original_state.get_next_withdrawal_index()
    );
    assert_eq!(
        restored_state.epoch_genesis_hash,
        original_state.epoch_genesis_hash
    );
    assert_eq!(
        restored_state.deposit_queue.len(),
        original_state.deposit_queue.len()
    );
    assert_eq!(
        restored_state.withdrawal_queue,
        original_state.withdrawal_queue
    );
    assert_eq!(
        restored_state.validator_accounts.len(),
        original_state.validator_accounts.len()
    );

    // Check specific values
    assert_eq!(restored_state.deposit_queue[0].amount, 32000000000);
    let epoch7_withdrawals = restored_state.get_withdrawals_for_epoch(7);
    assert_eq!(epoch7_withdrawals[0].inner.amount, 16000000000);

    let restored_account = restored_state.get_account(&pubkey).unwrap();
    assert_eq!(restored_account.balance, 32000000000);
    assert_eq!(restored_account.last_deposit_index, 1);
}
