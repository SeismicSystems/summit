use super::super::*;
use super::common::*;
use crate::PublicKey;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::header::AddedValidator;
use alloy_primitives::Address;
use commonware_codec::DecodeExt;

const MIN: u64 = 32;
const WITHDRAWAL_EPOCHS: u64 = 2;

fn withdrawal_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_withdrawals_per_epoch(10);
    // Allow voluntary exits without tripping the minimum validator count guard;
    // that guard has its own coverage in guards.rs.
    state.set_minimum_validator_count(0);
    state
}

fn creds(index: u8) -> Address {
    Address::from([index; 20])
}

fn request(pubkey: [u8; 32], source: Address, amount: u64) -> WithdrawalRequest {
    WithdrawalRequest {
        source_address: source,
        validator_pubkey: pubkey,
        amount,
    }
}

fn is_removed(state: &ConsensusState, pubkey: [u8; 32]) -> bool {
    let pk = PublicKey::decode(&pubkey[..]).unwrap();
    state.get_removed_validators().contains(&pk)
}

fn due(state: &ConsensusState) -> Vec<u64> {
    state
        .get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS)
        .iter()
        .map(|w| w.inner.amount)
        .collect()
}

fn set_joining(state: &mut ConsensusState, pubkey: [u8; 32], balance: u64, activation_epoch: u64) {
    let mut account = create_test_validator_account(pubkey[0] as u64, balance);
    account.status = ValidatorStatus::Joining;
    account.joining_epoch = activation_epoch;
    let consensus_key = account.consensus_public_key.clone();
    state.set_account(pubkey, account);
    state.add_validator(
        activation_epoch,
        AddedValidator {
            node_key: PublicKey::decode(&pubkey[..]).unwrap(),
            consensus_key,
        },
    );
}

// Active full exit: stage committee removal, mark SubmittedExitRequest, enqueue
// the marker, leave the balance untouched (reduced only at payout).
#[test]
fn active_full_exit() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));

    state.apply_withdrawal_request(request(pubkey, creds(1), 0), WITHDRAWAL_EPOCHS);

    let account = state.get_account(&pubkey).unwrap();
    assert_eq!(account.status, ValidatorStatus::SubmittedExitRequest);
    assert_eq!(account.balance, 100);
    assert!(is_removed(&state, pubkey));
    assert_eq!(due(&state), vec![0]); // full exit marker
}

// Active partial: clamp so the remainder stays at MIN, stay Active and in the
// committee, balance unchanged at request time.
#[test]
fn active_partial_clamped_to_min() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));

    state.apply_withdrawal_request(request(pubkey, creds(1), 50), WITHDRAWAL_EPOCHS);

    let account = state.get_account(&pubkey).unwrap();
    assert_eq!(account.status, ValidatorStatus::Active);
    assert_eq!(account.balance, 100);
    assert!(!is_removed(&state, pubkey));
    assert_eq!(due(&state), vec![50]); // min(50, 100-32)
}

// Active partial that would leave the validator below MIN enqueues nothing.
#[test]
fn active_partial_at_floor_is_dropped() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, MIN));

    state.apply_withdrawal_request(request(pubkey, creds(1), 50), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::Active
    );
    assert!(due(&state).is_empty());
}

// Inactive full exit: become FullPayoutPending, no committee removal delta.
#[test]
fn inactive_full_exit() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    let mut account = create_test_validator_account(1, 40);
    account.status = ValidatorStatus::Inactive;
    state.set_account(pubkey, account);

    state.apply_withdrawal_request(request(pubkey, creds(1), 0), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    assert!(!is_removed(&state, pubkey));
    assert_eq!(due(&state), vec![0]);
}

// Inactive partial: no minimum floor, stays Inactive.
#[test]
fn inactive_partial_no_floor() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    let mut account = create_test_validator_account(1, 40);
    account.status = ValidatorStatus::Inactive;
    state.set_account(pubkey, account);

    state.apply_withdrawal_request(request(pubkey, creds(1), 40), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert_eq!(due(&state), vec![40]); // min(40, 40), no floor
}

// Joining full exit: cancel the pending activation, then treat as a full exit.
#[test]
fn joining_full_exit_cancels_activation() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    set_joining(&mut state, pubkey, 100, 5);
    assert!(state.has_added_validators(5));

    state.apply_withdrawal_request(request(pubkey, creds(1), 0), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    assert!(!state.has_added_validators(5)); // activation cancelled, epoch key pruned
    assert!(!is_removed(&state, pubkey)); // never entered the committee
    assert_eq!(due(&state), vec![0]);
}

// Joining partial: cancel activation, become Inactive, no-floor partial.
#[test]
fn joining_partial_cancels_activation() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    set_joining(&mut state, pubkey, 100, 5);

    state.apply_withdrawal_request(request(pubkey, creds(1), 40), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert!(!state.has_added_validators(5));
    assert_eq!(due(&state), vec![40]);
}

// A validator already mid full exit ignores further requests.
#[test]
fn submitted_exit_request_skips() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    let mut account = create_test_validator_account(1, 100);
    account.status = ValidatorStatus::SubmittedExitRequest;
    state.set_account(pubkey, account);

    state.apply_withdrawal_request(request(pubkey, creds(1), 0), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert!(due(&state).is_empty());
}

// A validator already awaiting its full payout ignores further requests.
#[test]
fn full_payout_pending_skips() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    let mut account = create_test_validator_account(1, 100);
    account.status = ValidatorStatus::FullPayoutPending;
    state.set_account(pubkey, account);

    state.apply_withdrawal_request(request(pubkey, creds(1), 50), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    assert!(due(&state).is_empty());
}

// A request for a validator with no account is dropped.
#[test]
fn no_account_dropped() {
    let mut state = withdrawal_state();
    state.apply_withdrawal_request(request([1u8; 32], creds(1), 0), WITHDRAWAL_EPOCHS);
    assert!(due(&state).is_empty());
}

// A request whose source address does not match the withdrawal credentials is
// dropped.
#[test]
fn source_address_mismatch_dropped() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));

    // Account credentials are address [1; 20]; request claims [2; 20].
    state.apply_withdrawal_request(request(pubkey, creds(2), 0), WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&pubkey).unwrap().status,
        ValidatorStatus::Active
    );
    assert!(!is_removed(&state, pubkey));
    assert!(due(&state).is_empty());
}
