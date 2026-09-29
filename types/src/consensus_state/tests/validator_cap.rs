//! Admission-cap regressions through the buffered request path used by the
//! finalizer at the penultimate block. Committee changes/payouts are applied
//! separately, as they are at finalized epoch boundaries.
use super::common::{create_test_validator_account, eth1_credentials, make_signed_deposit};
use crate::account::ValidatorStatus;
use crate::checkpoint::Checkpoint;
use crate::consensus_state::ConsensusState;
use crate::execution_request::{DepositRequest, ProtocolParamRequest, WithdrawalRequest};
use crate::protocol_params::ProtocolParam;
use crate::{Digest, PublicKey, deposit_signature_domain};
use alloy_primitives::{Address, Bytes};
use commonware_codec::{DecodeExt, Encode, Write};
use commonware_cryptography::{Signer, bls12381, ed25519};

const MIN: u64 = 32;
const WARM_UP: u64 = 2;
const PAYOUT_DELAY: u64 = 2;

fn domain() -> Digest {
    deposit_signature_domain([9; 32], b"_TEST")
}

fn key(seed: u64) -> PublicKey {
    ed25519::PrivateKey::from_seed(seed).public_key()
}

fn account_key(seed: u64) -> [u8; 32] {
    key(seed).as_ref().try_into().unwrap()
}

fn deposit(seed: u64, amount: u64, index: u64) -> DepositRequest {
    make_signed_deposit(
        &ed25519::PrivateKey::from_seed(seed),
        &bls12381::PrivateKey::from_seed(seed),
        eth1_credentials(1),
        amount,
        index,
        domain(),
    )
}

fn deposit_entry(seed: u64, amount: u64, index: u64) -> Bytes {
    let mut bytes = vec![0x00];
    deposit(seed, amount, index).write(&mut bytes);
    bytes.into()
}

fn withdrawal_entry(seed: u64, amount: u64, authorized: bool) -> Bytes {
    let mut bytes = vec![0x01];
    WithdrawalRequest {
        validator_pubkey: account_key(seed),
        source_address: Address::from([if authorized { 1 } else { 9 }; 20]),
        amount,
    }
    .write(&mut bytes);
    bytes.into()
}

fn param_entry(id: u8, value: u64) -> Bytes {
    let mut bytes = vec![0xff];
    ProtocolParamRequest {
        param_id: id,
        param: value.to_le_bytes().to_vec(),
    }
    .write(&mut bytes);
    bytes.into()
}

fn state(cap: u64) -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_validator_count(1);
    state.set_max_validator_count(cap);
    state.set_minimum_stake(MIN);
    state.set_max_deposits_per_epoch(16);
    state.set_max_withdrawals_per_epoch(16);
    state
}

fn seed_active(state: &mut ConsensusState, seed: u64) {
    let mut account = create_test_validator_account(1, MIN + 10);
    account.consensus_public_key = bls12381::PrivateKey::from_seed(seed).public_key();
    state.set_account(account_key(seed), account);
}

fn process(state: &mut ConsensusState, entries: &[Bytes]) {
    state.buffer_execution_requests(entries);
    state.process_buffered_requests(domain(), WARM_UP, PAYOUT_DELAY);
}

// Boundary ordering mirrors the finalizer: apply params, transition committee,
// advance epoch, then retire consumed deltas. Payout tests apply terminal-block
// payouts explicitly before calling this helper.
fn advance_epoch(state: &mut ConsensusState) {
    state.apply_protocol_parameter_changes().unwrap();
    state.apply_committee_transition(&key(99_999));
    let next = state.get_epoch() + 1;
    state.set_epoch(next);
    state.remove_added_validators_for_epoch(next);
    state.clear_removed_validators();
    assert_tree_consistent(state);
}

fn status(state: &ConsensusState, seed: u64) -> ValidatorStatus {
    state
        .get_account(&account_key(seed))
        .unwrap()
        .status
        .clone()
}

fn assert_tree_consistent(state: &ConsensusState) {
    let root = state.ssz_tree().root();
    let mut rebuilt = state.clone();
    rebuilt.rebuild_ssz_tree();
    assert_eq!(root, rebuilt.ssz_tree().root());
}

#[test]
fn conflicting_pair_is_discarded_before_deposit_and_exit_decisions() {
    // Neither the rejected raise nor the rejected lowering may influence
    // admission/exit decisions, even though params occur after other requests.
    for (minimum, maximum) in [(4, 3), (2, 1)] {
        let mut state = state(2);
        seed_active(&mut state, 1);
        seed_active(&mut state, 2);
        process(
            &mut state,
            &[
                deposit_entry(3, MIN, 0),
                deposit_entry(4, MIN, 1),
                withdrawal_entry(1, 0, true),
                param_entry(0x07, minimum),
                param_entry(0x0a, maximum),
                param_entry(0x06, 8),
            ],
        );
        assert_eq!(status(&state, 1), ValidatorStatus::SubmittedExitRequest);
        assert_eq!(status(&state, 3), ValidatorStatus::Joining);
        assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
        assert_eq!(state.prospective_minimum_validator_count(), 1);
        assert_eq!(state.prospective_max_validator_count(), 2);
        assert_tree_consistent(&state);
        state.apply_protocol_parameter_changes().unwrap();
        assert_eq!(state.get_minimum_validator_count(), 1);
        assert_eq!(state.get_max_validator_count(), 2);
        assert_eq!(state.get_observers_per_validator(), 8);
        assert_tree_consistent(&state);
    }
}

#[test]
fn conflicting_single_updates_are_discarded_at_boundary_too() {
    for params in [
        vec![ProtocolParam::MinimumValidatorCount(3)],
        vec![ProtocolParam::MaxValidatorCount(1)],
        vec![
            ProtocolParam::MinimumValidatorCount(4),
            ProtocolParam::MaxValidatorCount(3),
        ],
    ] {
        let mut state = state(2);
        state.set_minimum_validator_count(2);
        state.push_protocol_param_changes(params);
        state.push_protocol_param_change(ProtocolParam::ObserversPerValidator(8));
        // A checkpoint may carry pending updates; current scalar values are valid.
        let mut restored = ConsensusState::try_from(&Checkpoint::new(&state)).unwrap();
        restored.apply_protocol_parameter_changes().unwrap();
        assert_eq!(restored.get_minimum_validator_count(), 2);
        assert_eq!(restored.get_max_validator_count(), 2);
        assert_eq!(restored.get_observers_per_validator(), 8);
        assert_tree_consistent(&restored);
    }
}

#[test]
fn valid_paired_updates_are_order_independent_and_last_values_win() {
    for (old_min, old_max, new_min, new_max) in [(1, 2, 3, 4), (3, 4, 1, 2)] {
        for reverse in [false, true] {
            let mut state = state(old_max);
            state.set_minimum_validator_count(old_min);
            let mut entries = vec![param_entry(0x07, new_min), param_entry(0x0a, new_max)];
            if reverse {
                entries.reverse();
            }
            process(&mut state, &entries);
            state.apply_protocol_parameter_changes().unwrap();
            assert_eq!(state.get_minimum_validator_count(), new_min);
            assert_eq!(state.get_max_validator_count(), new_max);
        }
    }
    for final_cap in [1, 2] {
        let mut state = state(1);
        seed_active(&mut state, 1);
        process(
            &mut state,
            &[
                deposit_entry(2, MIN, 0),
                param_entry(0x07, 3), // Temporarily inconsistent pair is repaired below.
                param_entry(0x0a, 3),
                param_entry(0x07, 1),
                param_entry(0x0a, final_cap),
            ],
        );
        assert_eq!(
            status(&state, 2),
            if final_cap == 2 {
                ValidatorStatus::Joining
            } else {
                ValidatorStatus::Inactive
            }
        );
        state.apply_protocol_parameter_changes().unwrap();
        assert_eq!(state.get_max_validator_count(), final_cap);
        assert_tree_consistent(&state);
    }
}

#[test]
fn deposits_compete_in_queue_order_and_raising_cap_requires_another_deposit() {
    let mut state = state(1);
    process(
        &mut state,
        &[deposit_entry(1, MIN, 0), deposit_entry(2, MIN, 1)],
    );
    assert_eq!(status(&state, 1), ValidatorStatus::Joining);
    assert_eq!(status(&state, 2), ValidatorStatus::Inactive);
    assert_eq!(state.get_account(&account_key(2)).unwrap().balance, MIN);
    assert_eq!(state.get_added_validators(WARM_UP).unwrap().len(), 1);
    process(&mut state, &[param_entry(0x0a, 2)]);
    state.apply_protocol_parameter_changes().unwrap();
    process(&mut state, &[]);
    assert_eq!(status(&state, 2), ValidatorStatus::Inactive);
    process(&mut state, &[deposit_entry(2, 1, 2)]);
    assert_eq!(status(&state, 2), ValidatorStatus::Joining);
    assert_eq!(state.active_or_joining_validator_count(), 2);
    assert_tree_consistent(&state);
}

#[test]
fn only_accepted_full_active_exit_frees_a_slot() {
    // accepted, wrong address, exit floor, withdrawal queue full, partial
    for case in 0..5 {
        let mut state = state(2);
        seed_active(&mut state, 1);
        seed_active(&mut state, 2);
        if case == 2 {
            state.set_minimum_validator_count(2);
        }
        if case == 3 {
            state.set_max_pending_withdrawals_per_validator(1);
            process(&mut state, &[withdrawal_entry(1, 1, true)]);
        }
        process(
            &mut state,
            &[
                deposit_entry(3, MIN, 0),
                withdrawal_entry(1, if case == 4 { 1 } else { 0 }, case != 1),
                withdrawal_entry(1, 0, case == 0), // Duplicate cannot free another slot.
                deposit_entry(4, MIN, 1),
            ],
        );
        assert_eq!(
            status(&state, 3),
            if case == 0 {
                ValidatorStatus::Joining
            } else {
                ValidatorStatus::Inactive
            }
        );
        assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
        assert_eq!(state.get_removed_validators().len(), usize::from(case == 0));
        state.apply_committee_transition(&key(2));
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_tree_consistent(&state);
    }
}

#[test]
fn joining_withdrawal_cancels_reservation_only_when_accepted() {
    // full, partial, wrong address, full pending-withdrawal queue
    for case in 0..4 {
        let mut state = state(1);
        process(&mut state, &[deposit_entry(1, MIN, 0)]);
        if case == 3 {
            // Model an already occupied queue without invoking cancellation.
            state.set_max_pending_withdrawals_per_validator(1);
            state.push_withdrawal_request(
                WithdrawalRequest {
                    validator_pubkey: account_key(1),
                    source_address: Address::from([1; 20]),
                    amount: 1,
                },
                PAYOUT_DELAY,
            );
        }
        process(
            &mut state,
            &[
                deposit_entry(2, MIN, 1),
                withdrawal_entry(1, if case == 1 { 1 } else { 0 }, case != 2),
            ],
        );
        let additions = state.get_added_validators(WARM_UP).unwrap();
        assert_eq!(additions.len(), 1);
        assert_eq!(additions[0].node_key, key(if case < 2 { 2 } else { 1 }));
        assert_eq!(
            status(&state, 2),
            if case < 2 {
                ValidatorStatus::Joining
            } else {
                ValidatorStatus::Inactive
            }
        );
        assert_eq!(state.active_or_joining_validator_count(), 1);
        assert_tree_consistent(&state);
    }
}

#[test]
fn cap_blocked_account_can_withdraw_and_pending_payout_prevents_reactivation() {
    for full in [false, true] {
        let mut state = state(1);
        seed_active(&mut state, 1);
        process(&mut state, &[deposit_entry(2, MIN, 0)]);
        assert_eq!(status(&state, 2), ValidatorStatus::Inactive);
        process(
            &mut state,
            &[
                deposit_entry(2, 5, 1),
                withdrawal_entry(2, if full { 0 } else { 1 }, true),
                param_entry(0x0a, 2),
            ],
        );
        assert_eq!(
            status(&state, 2),
            if full {
                ValidatorStatus::FullPayoutPending
            } else {
                ValidatorStatus::Inactive
            }
        );
        assert_eq!(state.get_account(&account_key(2)).unwrap().balance, MIN + 5);
        assert!(!state.has_added_validators(WARM_UP));
        state.apply_protocol_parameter_changes().unwrap();
        let payouts = state.emit_withdrawal_payouts(PAYOUT_DELAY);
        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0].amount, if full { MIN + 5 } else { 1 });
        state.apply_withdrawal_payouts(PAYOUT_DELAY, &payouts);
        if full {
            assert!(state.get_account(&account_key(2)).is_none());
        } else {
            assert_eq!(status(&state, 2), ValidatorStatus::Inactive);
            process(&mut state, &[deposit_entry(2, 1, 2)]);
            assert_eq!(status(&state, 2), ValidatorStatus::Joining);
        }
        assert_tree_consistent(&state);
    }
}

#[test]
fn first_deposit_and_same_batch_withdrawal_do_not_cancel_each_other() {
    let mut state = state(1);
    seed_active(&mut state, 1);
    process(
        &mut state,
        &[deposit_entry(2, MIN, 0), withdrawal_entry(2, 0, true)],
    );
    // Withdrawal precedes account creation despite deposit appearing first.
    assert_eq!(status(&state, 2), ValidatorStatus::Inactive);
    assert_eq!(state.get_withdrawal_count_for_epoch(PAYOUT_DELAY), 0);
    process(&mut state, &[withdrawal_entry(2, 0, true)]);
    assert_eq!(status(&state, 2), ValidatorStatus::FullPayoutPending);
    assert_eq!(state.get_withdrawal_count_for_epoch(PAYOUT_DELAY), 1);
}

#[test]
fn cap_below_reserved_membership_is_rejected_across_codec_and_checkpoint_restore() {
    let mut state = state(2);
    process(
        &mut state,
        &[deposit_entry(1, MIN, 0), deposit_entry(2, MIN, 1)],
    );
    // Restore a queued update that has not yet passed batch validation. The
    // boundary fallback must also reject a cap below existing reservations.
    state.push_protocol_param_change(ProtocolParam::MaxValidatorCount(1));
    state.capture_state_root(0);
    for mut restored in [
        ConsensusState::decode(state.encode()).unwrap(),
        ConsensusState::try_from(&Checkpoint::new(&state)).unwrap(),
    ] {
        restored.apply_protocol_parameter_changes().unwrap();
        assert_eq!(restored.get_max_validator_count(), 2);
        assert_eq!(restored.active_or_joining_validator_count(), 2);
        assert_eq!(restored.get_added_validators(WARM_UP).unwrap().len(), 2);
        assert_eq!(restored.get_state_root(), state.get_state_root());
        process(&mut restored, &[deposit_entry(3, MIN, 2)]);
        assert_eq!(status(&restored, 3), ValidatorStatus::Inactive);
        restored.set_epoch(WARM_UP - 1);
        restored.apply_committee_transition(&key(1));
        assert_eq!(restored.get_active_validators().len(), 2);
        assert_tree_consistent(&restored);
    }
}

#[test]
fn prospective_raise_and_funded_inactive_accounts_survive_restore() {
    let mut state = state(1);
    seed_active(&mut state, 1);
    process(
        &mut state,
        &[
            deposit_entry(2, MIN, 0),
            deposit_entry(3, MIN, 1),
            param_entry(0x0a, 2),
        ],
    );
    // More reservations than the stored cap is legitimate before boundary application.
    assert_eq!(state.get_max_validator_count(), 1);
    for mut restored in [
        ConsensusState::decode(state.encode()).unwrap(),
        ConsensusState::try_from(&Checkpoint::new(&state)).unwrap(),
    ] {
        assert_eq!(restored.prospective_max_validator_count(), 2);
        assert_eq!(status(&restored, 2), ValidatorStatus::Joining);
        assert_eq!(status(&restored, 3), ValidatorStatus::Inactive);
        assert_eq!(restored.get_account(&account_key(3)).unwrap().balance, MIN);
        restored.apply_protocol_parameter_changes().unwrap();
        process(&mut restored, &[deposit_entry(4, MIN, 2)]);
        assert_eq!(status(&restored, 4), ValidatorStatus::Inactive);
        assert_eq!(restored.active_or_joining_validator_count(), 2);
        assert_tree_consistent(&restored);
    }
}

#[test]
fn deposit_backlog_uses_processing_epoch_cap_and_preserves_fifo() {
    for (old_cap, new_cap) in [(1, 2), (3, 2)] {
        let mut state = state(old_cap);
        state.set_max_deposits_per_epoch(1);
        seed_active(&mut state, 1);
        process(
            &mut state,
            &[deposit_entry(2, MIN, 0), deposit_entry(3, MIN, 1)],
        );
        assert_eq!(state.deposit_count(), 1);
        assert!(state.get_account(&account_key(3)).is_none());
        assert_eq!(
            status(&state, 2),
            if old_cap == 1 {
                ValidatorStatus::Inactive
            } else {
                ValidatorStatus::Joining
            }
        );
        advance_epoch(&mut state);

        // The older, still-uncredited deposit competes under the new cap, ahead
        // of the newly submitted deposit. The first deposit is never retried.
        process(
            &mut state,
            &[deposit_entry(4, MIN, 2), param_entry(0x0a, new_cap)],
        );
        assert_eq!(
            status(&state, 3),
            if old_cap == 1 {
                ValidatorStatus::Joining
            } else {
                ValidatorStatus::Inactive
            }
        );
        assert!(state.get_account(&account_key(4)).is_none());
        assert_eq!(state.deposit_count(), 1);
        assert_eq!(state.get_deposit(0).unwrap().index, 2);
        assert_eq!(state.get_account(&account_key(2)).unwrap().balance, MIN);
        advance_epoch(&mut state);
        process(&mut state, &[]);
        assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
        assert_eq!(state.deposit_count(), 0);
        advance_epoch(&mut state);
        process(&mut state, &[]);
        for seed in [2, 3, 4] {
            assert_eq!(state.get_account(&account_key(seed)).unwrap().balance, MIN);
        }
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_tree_consistent(&state);
    }
}

#[test]
fn terminal_block_cap_update_is_deferred_and_precedes_next_epoch_updates() {
    for final_cap in [2, 3] {
        let mut state = state(2);
        seed_active(&mut state, 1);
        seed_active(&mut state, 2);
        process(&mut state, &[deposit_entry(3, MIN, 0)]); // Epoch 0 penultimate.
        assert_eq!(status(&state, 3), ValidatorStatus::Inactive);
        // These arrive on epoch 0's terminal block: buffer, but do not process.
        state.buffer_execution_requests(&[
            param_entry(0x07, 3),
            param_entry(0x0a, 3),
            withdrawal_entry(1, 0, true),
            deposit_entry(4, MIN, 1),
        ]);
        advance_epoch(&mut state);
        assert_eq!(state.get_max_validator_count(), 2);
        assert_eq!(state.get_minimum_validator_count(), 1);
        assert_eq!(status(&state, 1), ValidatorStatus::Active);
        assert_eq!(status(&state, 3), ValidatorStatus::Inactive);
        assert!(state.get_account(&account_key(4)).is_none());

        let entries = if final_cap == 2 {
            vec![
                param_entry(0x07, 1),
                param_entry(0x0a, 2),
                deposit_entry(5, MIN, 2),
            ]
        } else {
            vec![deposit_entry(5, MIN, 2)]
        };
        process(&mut state, &entries); // Epoch 1 penultimate.
        // Without an override, minimum=3 rejects the exit; with the later pair,
        // minimum=1 permits it. Exactly one deposit gets a slot in either case.
        assert_eq!(
            status(&state, 1),
            if final_cap == 2 {
                ValidatorStatus::SubmittedExitRequest
            } else {
                ValidatorStatus::Active
            }
        );
        assert_eq!(status(&state, 4), ValidatorStatus::Joining);
        assert_eq!(
            state.get_account(&account_key(4)).unwrap().joining_epoch,
            1 + WARM_UP
        );
        assert_eq!(status(&state, 5), ValidatorStatus::Inactive);
        assert_eq!(state.get_withdrawal_count_for_epoch(PAYOUT_DELAY), 0);
        assert_eq!(
            state.get_withdrawal_count_for_epoch(1 + PAYOUT_DELAY),
            usize::from(final_cap == 2)
        );
        advance_epoch(&mut state);
        assert_eq!(state.get_max_validator_count(), final_cap);
        assert_eq!(
            state.get_minimum_validator_count(),
            if final_cap == 2 { 1 } else { 3 }
        );
    }
}

#[test]
fn stake_enforcement_after_admission_does_not_retry_cap_blocked_deposits() {
    for joining in [false, true] {
        for accepted in [false, true] {
            let mut state = state(3);
            seed_active(&mut state, 1);
            seed_active(&mut state, 2);
            if joining {
                process(&mut state, &[deposit_entry(3, MIN, 0)]);
            } else {
                seed_active(&mut state, 3);
                let mut account = state.get_account(&account_key(3)).unwrap().clone();
                account.balance = MIN;
                state.set_account(account_key(3), account);
            }
            advance_epoch(&mut state);
            process(
                &mut state,
                &[
                    deposit_entry(4, MIN + 10, 1),
                    param_entry(0x07, if accepted { 2 } else { 3 }),
                    param_entry(0x00, MIN + 1),
                ],
            );
            assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
            state.enforce_minimum_stake(); // Production ordering: after deposits.
            if joining {
                assert_eq!(state.has_added_validators(WARM_UP), !accepted);
            } else {
                assert_eq!(state.get_removed_validators().contains(&key(3)), accepted);
            }
            assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
            advance_epoch(&mut state);
            assert_eq!(
                state.get_minimum_stake(),
                if accepted { MIN + 1 } else { MIN }
            );
            assert_eq!(
                status(&state, 3),
                if accepted {
                    ValidatorStatus::Inactive
                } else {
                    ValidatorStatus::Active
                }
            );
            assert_eq!(
                state.active_or_joining_validator_count(),
                if accepted { 2 } else { 3 }
            );
            process(&mut state, &[deposit_entry(4, 1, 2)]);
            assert_eq!(
                status(&state, 4),
                if accepted {
                    ValidatorStatus::Joining
                } else {
                    ValidatorStatus::Inactive
                }
            );
            assert_tree_consistent(&state);
        }
    }
}

#[test]
fn same_batch_exit_cannot_validate_reduction_but_later_update_can() {
    // Both a voluntary active exit and a joining cancellation occur too late
    // to make the same batch's reduction valid.
    for joining in [false, true] {
        let mut state = state(3);
        seed_active(&mut state, 1);
        seed_active(&mut state, 2);
        if joining {
            process(&mut state, &[deposit_entry(3, MIN, 0)]);
        } else {
            seed_active(&mut state, 3);
        }
        process(
            &mut state,
            &[withdrawal_entry(3, 0, true), param_entry(0x0a, 2)],
        );
        assert_eq!(state.prospective_max_validator_count(), 3);
        assert_eq!(state.active_or_joining_validator_count(), 2);
        advance_epoch(&mut state);
        assert_eq!(state.get_max_validator_count(), 3);

        // A later reduction to the now-current count is valid. Deposits see
        // the accepted smaller cap and cannot take the old spare slot.
        process(
            &mut state,
            &[param_entry(0x0a, 2), deposit_entry(4, MIN, 1)],
        );
        assert_eq!(state.prospective_max_validator_count(), 2);
        assert_eq!(status(&state, 4), ValidatorStatus::Inactive);
        advance_epoch(&mut state);
        assert_eq!(state.get_max_validator_count(), 2);
        process(
            &mut state,
            &[withdrawal_entry(2, 0, true), deposit_entry(4, 1, 2)],
        );
        assert_eq!(status(&state, 4), ValidatorStatus::Joining);
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_tree_consistent(&state);
    }
}

#[test]
fn cap_reduction_counts_active_and_joining_but_not_inactive_accounts() {
    for joining_count in 0..=2 {
        let mut state = state(4);
        state.set_minimum_validator_count(2);
        for seed in 1..=2 - joining_count {
            seed_active(&mut state, seed);
        }
        for seed in 3 - joining_count..=2 {
            process(&mut state, &[deposit_entry(seed, MIN, seed)]);
        }
        process(
            &mut state,
            &[deposit_entry(3, MIN - 1, 3), param_entry(0x0a, 2)],
        );
        assert_eq!(state.prospective_max_validator_count(), 2);
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_eq!(status(&state, 3), ValidatorStatus::Inactive);
        state.apply_protocol_parameter_changes().unwrap();
        assert_eq!(state.get_max_validator_count(), 2);
        process(
            &mut state,
            &[
                param_entry(0x07, 1),
                param_entry(0x0a, 1),
                param_entry(0x06, 8),
            ],
        );
        assert_eq!(state.prospective_max_validator_count(), 2);
        assert_tree_consistent(&state);
        state.apply_protocol_parameter_changes().unwrap();
        assert_eq!(state.get_max_validator_count(), 2);
        assert_eq!(state.get_minimum_validator_count(), 1);
        assert_eq!(state.get_observers_per_validator(), 8);
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_tree_consistent(&state);
    }
}

#[test]
fn last_valid_cap_decides_reduction_without_falling_back_to_earlier_update() {
    for last_cap in [1, 2] {
        let mut state = state(3);
        seed_active(&mut state, 1);
        seed_active(&mut state, 2);
        process(
            &mut state,
            &[
                param_entry(0x0a, if last_cap == 1 { 2 } else { 1 }),
                param_entry(0x0a, last_cap),
                deposit_entry(3, MIN, 0),
            ],
        );
        let accepted_cap = if last_cap == 1 { 3 } else { 2 };
        assert_eq!(state.prospective_max_validator_count(), accepted_cap);
        assert_eq!(
            status(&state, 3),
            if last_cap == 1 {
                ValidatorStatus::Joining
            } else {
                ValidatorStatus::Inactive
            }
        );
        advance_epoch(&mut state);
        assert_eq!(state.get_max_validator_count(), accepted_cap);
    }
}

#[test]
fn delayed_exit_payout_topup_and_redeposit_do_not_reclaim_replacement_slot() {
    let mut state = state(2);
    state.set_max_withdrawals_per_epoch(1);
    seed_active(&mut state, 1); // A: exits.
    seed_active(&mut state, 2); // Remains active and supplies the earlier payout.
    process(
        &mut state,
        &[
            withdrawal_entry(2, 1, true),
            withdrawal_entry(1, 0, true),
            deposit_entry(3, MIN, 0), // B: replacement reserves A's slot.
        ],
    );
    assert_eq!(status(&state, 1), ValidatorStatus::SubmittedExitRequest);
    assert_eq!(status(&state, 3), ValidatorStatus::Joining);
    advance_epoch(&mut state);
    assert_eq!(status(&state, 1), ValidatorStatus::FullPayoutPending);
    advance_epoch(&mut state);
    assert_eq!(status(&state, 3), ValidatorStatus::Active);

    let first = state.emit_withdrawal_payouts(PAYOUT_DELAY);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].amount, 1);
    state.apply_withdrawal_payouts(PAYOUT_DELAY, &first);
    assert_eq!(state.get_account(&account_key(2)).unwrap().balance, MIN + 9);
    assert_eq!(
        state.get_account(&account_key(1)).unwrap().balance,
        MIN + 10
    );
    assert_eq!(state.get_withdrawal_count_for_epoch(PAYOUT_DELAY), 1);
    advance_epoch(&mut state);

    // A's payout was deferred by the payout cap; next epoch's deposit is still
    // only a top-up to that exit balance, not a new admission.
    process(&mut state, &[deposit_entry(1, 5, 1)]);
    assert_eq!(status(&state, 1), ValidatorStatus::FullPayoutPending);
    assert_eq!(state.active_or_joining_validator_count(), 2);
    assert!(!state.has_added_validators(state.get_epoch() + WARM_UP));
    let second = state.emit_withdrawal_payouts(state.get_epoch());
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].amount, MIN + 15);
    state.apply_withdrawal_payouts(state.get_epoch(), &second);
    assert!(state.get_account(&account_key(1)).is_none());
    assert_eq!(state.get_withdrawal_count_for_epoch(PAYOUT_DELAY), 0);
    advance_epoch(&mut state);

    process(&mut state, &[deposit_entry(1, MIN, 2)]);
    assert_eq!(status(&state, 1), ValidatorStatus::Inactive);
    assert_eq!(state.get_account(&account_key(1)).unwrap().balance, MIN);
    assert_eq!(status(&state, 3), ValidatorStatus::Active);
    assert_eq!(state.active_or_joining_validator_count(), 2);
    assert!(state.emit_withdrawal_payouts(state.get_epoch()).is_empty());
    assert_tree_consistent(&state);
}

#[test]
fn rejected_deposits_do_not_consume_final_slot() {
    for key_mismatch in [false, true] {
        let mut state = state(2);
        seed_active(&mut state, 1);
        let mut rejected = if key_mismatch {
            make_signed_deposit(
                &ed25519::PrivateKey::from_seed(2),
                &bls12381::PrivateKey::from_seed(1),
                eth1_credentials(1),
                MIN,
                0,
                domain(),
            )
        } else {
            deposit(2, MIN, 0)
        };
        if !key_mismatch {
            rejected.node_signature[0] ^= 1;
        }
        let mut bytes = vec![0x00];
        rejected.write(&mut bytes);
        process(&mut state, &[bytes.into(), deposit_entry(3, MIN, 1)]);
        assert!(state.get_account(&account_key(2)).is_none());
        assert_eq!(status(&state, 3), ValidatorStatus::Joining);
        assert_eq!(state.active_or_joining_validator_count(), 2);
        assert_eq!(state.get_added_validators(WARM_UP).unwrap().len(), 1);
        let refunds = state.get_withdrawals_for_epoch(PAYOUT_DELAY);
        assert!(!refunds.is_empty());
        assert_eq!(refunds.iter().map(|w| w.inner.amount).sum::<u64>(), MIN);
        assert_tree_consistent(&state);
    }
}

#[test]
fn repeated_joining_topups_at_capacity_preserve_single_original_reservation() {
    let mut state = state(2);
    seed_active(&mut state, 1);
    process(&mut state, &[deposit_entry(2, MIN, 0)]);
    advance_epoch(&mut state);
    process(
        &mut state,
        &[
            deposit_entry(2, 1, 1),
            deposit_entry(2, 2, 2),
            deposit_entry(3, MIN, 3),
        ],
    );
    assert_eq!(state.get_account(&account_key(2)).unwrap().balance, MIN + 3);
    assert_eq!(
        state.get_account(&account_key(2)).unwrap().joining_epoch,
        WARM_UP
    );
    assert_eq!(state.get_added_validators(WARM_UP).unwrap().len(), 1);
    assert!(!state.has_added_validators(1 + WARM_UP));
    assert_eq!(status(&state, 3), ValidatorStatus::Inactive);
    advance_epoch(&mut state);
    assert_eq!(status(&state, 2), ValidatorStatus::Active);
    assert_eq!(state.active_or_joining_validator_count(), 2);
}

#[test]
fn invalid_cap_update_does_not_override_last_valid_pair() {
    let mut malformed = vec![0xff];
    ProtocolParamRequest {
        param_id: 0x0a,
        param: vec![2; 7],
    }
    .write(&mut malformed);
    for invalid in [
        param_entry(0x0a, 0),
        param_entry(0x0a, 4097),
        malformed.into(),
    ] {
        let mut state = state(1);
        seed_active(&mut state, 1);
        process(
            &mut state,
            &[
                deposit_entry(2, MIN, 0),
                param_entry(0x07, 2),
                param_entry(0x0a, 2),
                invalid,
            ],
        );
        assert_eq!(status(&state, 2), ValidatorStatus::Joining);
        advance_epoch(&mut state);
        assert_eq!(state.get_minimum_validator_count(), 2);
        assert_eq!(state.get_max_validator_count(), 2);
    }
}
