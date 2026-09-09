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
fn lower_cap_grandfathers_reservations_across_codec_and_checkpoint_restore() {
    let mut state = state(2);
    process(
        &mut state,
        &[deposit_entry(1, MIN, 0), deposit_entry(2, MIN, 1)],
    );
    process(&mut state, &[param_entry(0x0a, 1)]);
    state.apply_protocol_parameter_changes().unwrap();
    state.capture_state_root(0);
    for mut restored in [
        ConsensusState::decode(state.encode()).unwrap(),
        ConsensusState::try_from(&Checkpoint::new(&state)).unwrap(),
    ] {
        assert_eq!(restored.get_max_validator_count(), 1);
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
