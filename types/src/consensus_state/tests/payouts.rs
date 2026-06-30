use super::super::*;
use super::common::*;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use alloy_primitives::Address;

const MIN: u64 = 32;

fn payout_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_withdrawals_per_epoch(10);
    state
}

fn push_partial(state: &mut ConsensusState, pubkey: [u8; 32], amount: u64, epoch: u64) {
    state.push_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([pubkey[0]; 20]),
            validator_pubkey: pubkey,
            amount,
        },
        epoch,
        amount,
    );
}

fn push_full_exit(state: &mut ConsensusState, pubkey: [u8; 32], epoch: u64) {
    state.push_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([pubkey[0]; 20]),
            validator_pubkey: pubkey,
            amount: 0,
        },
        epoch,
        0,
    );
}

fn amounts(payouts: &[alloy_eips::eip4895::Withdrawal]) -> Vec<u64> {
    payouts.iter().map(|w| w.amount).collect()
}

// emit: two partials due in the same epoch for one validator clamp sequentially,
// so the remainder stays at the minimum (not double counted against 100).
#[test]
fn emit_sequential_clamp_across_partials() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    push_partial(&mut state, pubkey, 50, 0);
    push_partial(&mut state, pubkey, 50, 0);

    // 100 - 32 = 68 headroom: first pays 50, second pays min(50, 50-32)=18.
    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![50, 18]);
    // emit is read only: the balance is untouched until apply.
    assert_eq!(state.get_account(&pubkey).unwrap().balance, 100);
}

// emit: the running balance is per validator, so two validators clamp
// independently rather than against a shared total.
#[test]
fn emit_running_balance_is_per_validator() {
    let mut state = payout_state();
    let a = [1u8; 32];
    let b = [2u8; 32];
    state.set_account(a, create_test_validator_account(1, 100));
    state.set_account(b, create_test_validator_account(2, 100));
    push_partial(&mut state, a, 50, 0);
    push_partial(&mut state, b, 50, 0);

    // Each is min(50, 100-32)=50; b is not reduced by a's withdrawal.
    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![50, 50]);
}

// emit: a full exit (marker amount 0) pays the entire balance.
#[test]
fn emit_full_exit_pays_whole_balance() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    push_full_exit(&mut state, pubkey, 0);

    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![100]);
}

// emit: an active partial is floored so the remaining balance stays at the
// minimum.
#[test]
fn emit_partial_floored_at_min() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 50));
    push_partial(&mut state, pubkey, 50, 0);

    // min(50, 50-32) = 18.
    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![18]);
}

// emit: a partial that clamps to zero (balance already at the minimum) is
// dropped from the emitted list.
#[test]
fn emit_drops_not_filled_partial() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, MIN));
    push_partial(&mut state, pubkey, 50, 0);

    assert!(state.emit_withdrawal_payouts(0).is_empty());
}

// emit: an inactive validator has no minimum floor, so a partial can draw the
// balance down to zero.
#[test]
fn emit_inactive_has_no_floor() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    let mut account = create_test_validator_account(1, 40);
    account.status = ValidatorStatus::Inactive;
    state.set_account(pubkey, account);
    push_partial(&mut state, pubkey, 40, 0);

    // No floor: min(40, 40) = 40.
    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![40]);
}

// emit: a deposit refund pays its fixed amount regardless of balance, and needs
// no validator account.
#[test]
fn emit_refund_pays_fixed_amount() {
    let mut state = payout_state();
    state.push_refund_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([9u8; 20]),
            validator_pubkey: [0u8; 32],
            amount: 7,
        },
        0,
        0,
    );

    assert_eq!(amounts(&state.emit_withdrawal_payouts(0)), vec![7]);
}

// apply: debits the balance by the paid amounts, keeps the account, and consumes
// the entries.
#[test]
fn apply_debits_and_keeps_account() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    push_partial(&mut state, pubkey, 50, 0);
    push_partial(&mut state, pubkey, 50, 0);

    let block = state.emit_withdrawal_payouts(0);
    state.apply_withdrawal_payouts(0, &block);

    assert_eq!(state.get_account(&pubkey).unwrap().balance, MIN);
    assert!(state.get_withdrawals_for_epoch(0).is_empty());
}

// apply: a full exit drains the balance and removes the account.
#[test]
fn apply_full_exit_removes_account() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    push_full_exit(&mut state, pubkey, 0);

    let block = state.emit_withdrawal_payouts(0);
    state.apply_withdrawal_payouts(0, &block);

    assert!(state.get_account(&pubkey).is_none());
    assert!(state.get_withdrawals_for_epoch(0).is_empty());
}

// apply: a partial that clamps to zero is consumed (removed from the queue) but
// the balance is left unchanged.
#[test]
fn apply_consumes_dropped_not_filled() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, MIN));
    push_partial(&mut state, pubkey, 50, 0);

    // emit is empty (nothing fills), so the block carries no withdrawals.
    let block = state.emit_withdrawal_payouts(0);
    assert!(block.is_empty());
    state.apply_withdrawal_payouts(0, &block);

    assert_eq!(state.get_account(&pubkey).unwrap().balance, MIN);
    assert!(state.get_withdrawals_for_epoch(0).is_empty());
}

// apply: a refund touches no validator balance.
#[test]
fn apply_refund_leaves_balance_unchanged() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    state.push_refund_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([9u8; 20]),
            validator_pubkey: [0u8; 32],
            amount: 7,
        },
        0,
        0,
    );

    let block = state.emit_withdrawal_payouts(0);
    state.apply_withdrawal_payouts(0, &block);

    assert_eq!(state.get_account(&pubkey).unwrap().balance, 100);
    assert!(state.get_withdrawals_for_epoch(0).is_empty());
}

// apply: the equality assert halts the node if the block's withdrawals do not
// match what consensus state would emit.
#[test]
#[should_panic(expected = "block withdrawals must match")]
fn apply_panics_on_block_mismatch() {
    let mut state = payout_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    push_full_exit(&mut state, pubkey, 0);

    // emit would be [100]; pass an empty list to force the mismatch.
    state.apply_withdrawal_payouts(0, &[]);
}

// emit/apply honor the per-epoch total cap: only `max_withdrawals_per_epoch`
// are paid, and the overflow rolls to a later sweep.
#[test]
fn emit_and_apply_honor_cap_and_defer_overflow() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_withdrawals_per_epoch(1);
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    state.set_account(k1, create_test_validator_account(1, 100));
    state.set_account(k2, create_test_validator_account(2, 100));
    push_full_exit(&mut state, k1, 0);
    push_full_exit(&mut state, k2, 0);

    // Only one fits under the cap (FIFO: k1).
    let block = state.emit_withdrawal_payouts(0);
    assert_eq!(block.len(), 1);
    state.apply_withdrawal_payouts(0, &block);
    assert!(state.get_account(&k1).is_none());
    assert!(state.get_account(&k2).is_some());

    // The deferred exit is paid in the next sweep.
    let block2 = state.emit_withdrawal_payouts(0);
    assert_eq!(block2.len(), 1);
    state.apply_withdrawal_payouts(0, &block2);
    assert!(state.get_account(&k2).is_none());
}

// Under the cap, validator exits take strict priority over deposit refunds even
// when a refund was enqueued first (#226 starvation guard).
#[test]
fn emit_prioritizes_validator_exits_over_refunds_under_cap() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_withdrawals_per_epoch(1);
    let k1 = [1u8; 32];
    state.set_account(k1, create_test_validator_account(1, 100));
    state.push_refund_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([9u8; 20]),
            validator_pubkey: [0u8; 32],
            amount: 7,
        },
        0,
        0,
    );
    push_full_exit(&mut state, k1, 0);

    // Cap 1: the validator exit wins despite the refund being enqueued first.
    let block = state.emit_withdrawal_payouts(0);
    assert_eq!(block.len(), 1);
    assert_eq!(block[0].amount, 100);
}
