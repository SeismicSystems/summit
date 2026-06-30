use super::super::*;
use super::common::*;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::protocol_params::ProtocolParam;
use crate::{Digest, deposit_signature_domain};
use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};

const MIN: u64 = 32;
const WARM_UP: u64 = 2;
const WITHDRAWAL_EPOCHS: u64 = 2;

fn domain() -> Digest {
    deposit_signature_domain([9u8; 32], b"_TEST")
}

fn node_bytes(node_priv: &ed25519::PrivateKey) -> [u8; 32] {
    node_priv.public_key().as_ref().try_into().unwrap()
}

fn lifecycle_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_minimum_validator_count(0);
    state.set_max_deposits_per_epoch(16);
    state.set_max_withdrawals_per_epoch(16);
    state
}

// Active account keyed by a real ed25519 key (so committee routing can decode
// it), with a matching consensus key for the given seed.
fn active_validator(state: &mut ConsensusState, seed: u64, balance: u64) -> [u8; 32] {
    let key = node_bytes(&ed25519::PrivateKey::from_seed(seed));
    let mut account = create_test_validator_account(1, balance);
    account.consensus_public_key = bls12381::PrivateKey::from_seed(seed).public_key();
    state.set_account(key, account);
    key
}

// Drive the epoch boundary the way the finalizer does (minus the DB/orchestrator
// side effects): apply pending protocol params, apply the committee transition,
// advance the epoch counter, and clear the consumed deltas.
fn advance_epoch(state: &mut ConsensusState) {
    let _ = state.apply_protocol_parameter_changes();
    let outside_key = ed25519::PrivateKey::from_seed(99_999).public_key();
    state.apply_committee_transition(&outside_key);
    let next = state.get_epoch() + 1;
    state.set_epoch(next);
    state.remove_added_validators_for_epoch(next);
    if state.has_removed_validators() {
        state.clear_removed_validators();
    }
    state.reset_pending_active_validator_exits();
}

// A deposit at or above the minimum schedules activation and the validator
// joins the committee at its warm-up epoch, not before.
#[test]
fn deposit_joins_committee_after_warmup() {
    let mut state = lifecycle_state();
    let node = ed25519::PrivateKey::from_seed(1);
    let bls = bls12381::PrivateKey::from_seed(1);
    let key = node_bytes(&node);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        100,
        0,
        domain(),
    ));
    state.process_deposits(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    // Warming up, scheduled for epoch WARM_UP, not yet in the committee.
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.joining_epoch, WARM_UP);
    assert_eq!(state.current_epoch_active_validator_count(), 0);

    // Still warming up one epoch in.
    advance_epoch(&mut state);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Joining
    );

    // Activates at the warm-up epoch boundary.
    advance_epoch(&mut state);
    assert_eq!(state.get_epoch(), WARM_UP);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Active
    );
    assert_eq!(state.current_epoch_active_validator_count(), 1);
}

// A full exit removes the validator from the committee at the next boundary, and
// the balance is paid out (account removed) at the scheduled payout epoch.
#[test]
fn full_exit_removes_from_committee_then_pays_out() {
    let mut state = lifecycle_state();
    let key = active_validator(&mut state, 2, 100);

    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount: 0,
        },
        WITHDRAWAL_EPOCHS,
    );
    // Still serving this epoch, counted as active.
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert_eq!(state.current_epoch_active_validator_count(), 1);

    // Boundary: leaves the committee, awaiting payout.
    advance_epoch(&mut state);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    assert_eq!(state.current_epoch_active_validator_count(), 0);

    // Reach the payout epoch and pay out the full balance.
    advance_epoch(&mut state);
    assert_eq!(state.get_epoch(), WITHDRAWAL_EPOCHS);
    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![100]
    );
    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert!(state.get_account(&key).is_none());
}

// A below-minimum initial deposit creates an inactive account; a later top-up to
// the minimum schedules activation, and the validator joins after the warm up.
#[test]
fn below_min_deposit_then_topup_joins() {
    let mut state = lifecycle_state();
    let node = ed25519::PrivateKey::from_seed(3);
    let bls = bls12381::PrivateKey::from_seed(3);
    let key = node_bytes(&node);

    // Below-minimum initial deposit: inactive, balance kept.
    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        20,
        0,
        domain(),
    ));
    state.process_deposits(domain(), WARM_UP, WITHDRAWAL_EPOCHS);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert_eq!(state.get_account(&key).unwrap().balance, 20);

    // Top up over the minimum: schedules activation.
    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        20,
        1,
        domain(),
    ));
    state.process_deposits(domain(), WARM_UP, WITHDRAWAL_EPOCHS);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.balance, 40);
    let activation_epoch = account.joining_epoch;

    // Joins at the scheduled epoch.
    while state.get_epoch() < activation_epoch {
        advance_epoch(&mut state);
    }
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Active
    );
}

// A minimum stake increase removes a below-minimum validator from the committee
// at the boundary; it keeps its balance and can withdraw it later.
#[test]
fn stake_increase_removes_low_stake_validator() {
    let mut state = lifecycle_state();
    state.set_minimum_validator_count(1);
    let high = active_validator(&mut state, 1, 100);
    let low = active_validator(&mut state, 2, 50);

    // Raise the minimum above the low validator's balance, then enforce it.
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);
    state.enforce_minimum_stake();

    advance_epoch(&mut state);

    // The low validator is out of the committee but keeps its balance; the high
    // validator stays active.
    let low_account = state.get_account(&low).unwrap();
    assert_eq!(low_account.status, ValidatorStatus::Inactive);
    assert_eq!(low_account.balance, 50);
    assert_eq!(
        state.get_account(&high).unwrap().status,
        ValidatorStatus::Active
    );
    assert_eq!(state.get_minimum_stake(), 80);
}

// apply_committee_transition reports whether THIS node was removed, so the
// finalizer can coordinate its own shutdown. A bystander sees no self-exit.
#[test]
fn committee_transition_reports_self_exit() {
    let mut state = lifecycle_state();
    let node = ed25519::PrivateKey::from_seed(7);
    let key = node_bytes(&node);
    let mut account = create_test_validator_account(1, 100);
    account.consensus_public_key = bls12381::PrivateKey::from_seed(7).public_key();
    state.set_account(key, account);

    // Full exit stages this validator for removal.
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount: 0,
        },
        WITHDRAWAL_EPOCHS,
    );

    // A bystander node's transition reports no self-exit.
    let bystander = ed25519::PrivateKey::from_seed(8).public_key();
    assert!(!state.clone().apply_committee_transition(&bystander));

    // The exiting node's own transition reports the exit.
    assert!(state.apply_committee_transition(&node.public_key()));
}
