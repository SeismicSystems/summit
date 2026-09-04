use super::super::*;
use super::common::*;
use crate::PublicKey;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::header::AddedValidator;
use alloy_primitives::Address;
use commonware_codec::{DecodeExt, Encode};

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

// Applying a batch of withdrawal requests through the deferred path plus one
// rebuild_withdrawal_tree must land in the exact same ssz root as applying the
// same requests one at a time, where every mid sequence push rebuilt the
// subtree immediately. A queued refund forces every validator push to land mid
// sequence, so this exercises the deferred (stale tree) branch.
#[test]
fn deferred_withdrawal_push_matches_per_push() {
    let refund = || WithdrawalRequest {
        source_address: creds(9),
        validator_pubkey: [0u8; 32],
        amount: 7,
    };
    let seed = |state: &mut ConsensusState| {
        for i in 1u8..=3 {
            state.set_account([i; 32], create_test_validator_account(i as u64, 100));
        }
        state.push_refund_withdrawal_request(refund(), WITHDRAWAL_EPOCHS);
    };

    let mut per_push = withdrawal_state();
    let mut deferred = withdrawal_state();
    seed(&mut per_push);
    seed(&mut deferred);

    for i in 1u8..=3 {
        per_push.apply_withdrawal_request(request([i; 32], creds(i), 40), WITHDRAWAL_EPOCHS);
        assert!(
            deferred.apply_withdrawal_request_deferred(
                request([i; 32], creds(i), 40),
                WITHDRAWAL_EPOCHS
            ),
            "push {i} lands mid sequence, so its rebuild must be deferred"
        );
    }

    // The deferred pushes left the subtree stale until the batch rebuild.
    assert_ne!(deferred.ssz_tree().root(), per_push.ssz_tree().root());
    deferred.rebuild_withdrawal_tree();
    assert_eq!(deferred.ssz_tree().root(), per_push.ssz_tree().root());
    assert_eq!(due(&deferred), due(&per_push));
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

// The per-validator cap drops a request once the validator already has
// max_pending_withdrawals_per_validator entries outstanding.
#[test]
fn requests_beyond_cap_dropped() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    assert_eq!(state.get_max_pending_withdrawals_per_validator(), 3);

    for _ in 0..3 {
        state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    }
    assert_eq!(due(&state), vec![5, 5, 5]);

    state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    assert_eq!(due(&state), vec![5, 5, 5]);
}

// A capped full-exit request is dropped wholesale: no status flip, no staged
// committee removal, no marker enqueued.
#[test]
fn capped_exit_request_leaves_state_untouched() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));

    for _ in 0..3 {
        state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    }
    state.apply_withdrawal_request(request(pubkey, creds(1), 0), WITHDRAWAL_EPOCHS);

    let account = state.get_account(&pubkey).unwrap();
    assert_eq!(account.status, ValidatorStatus::Active);
    assert!(!is_removed(&state, pubkey));
    assert_eq!(due(&state), vec![5, 5, 5]);
}

// Cap slots free up as the payout sweep drains the validator's entries.
#[test]
fn cap_slot_frees_after_drain() {
    let mut state = withdrawal_state();
    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));

    for _ in 0..3 {
        state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    }
    state.pop_withdrawal(WITHDRAWAL_EPOCHS).unwrap();

    state.apply_withdrawal_request(request(pubkey, creds(1), 7), WITHDRAWAL_EPOCHS);
    assert_eq!(due(&state), vec![5, 5, 7]);
}

// The cap is per validator: one validator at cap does not block another.
#[test]
fn cap_is_per_validator() {
    let mut state = withdrawal_state();
    let full = [1u8; 32];
    let other = [2u8; 32];
    state.set_account(full, create_test_validator_account(1, 100));
    state.set_account(other, create_test_validator_account(2, 100));

    for _ in 0..3 {
        state.apply_withdrawal_request(request(full, creds(1), 5), WITHDRAWAL_EPOCHS);
    }
    state.apply_withdrawal_request(request(other, creds(2), 7), WITHDRAWAL_EPOCHS);

    assert_eq!(due(&state), vec![5, 5, 5, 7]);
}

// The cap is a protocol parameter: a queued change applies at the boundary and
// governs subsequent intake.
#[test]
fn cap_param_change_applies() {
    use crate::protocol_params::ProtocolParam;

    let mut state = withdrawal_state();
    state.push_protocol_param_change(ProtocolParam::MaxPendingWithdrawalsPerValidator(1));
    state.apply_protocol_parameter_changes().unwrap();
    assert_eq!(state.get_max_pending_withdrawals_per_validator(), 1);

    let pubkey = [1u8; 32];
    state.set_account(pubkey, create_test_validator_account(1, 100));
    state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    assert_eq!(due(&state), vec![5]);
}

/// A serializable state with one validator holding partial withdrawals at the
/// cap. Unlike [`withdrawal_state`] this keeps the default (nonzero) minimum
/// validator count, which decode requires, and uses partials only so no exit
/// machinery is involved.
fn serializable_state_at_cap(pubkey: [u8; 32]) -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_withdrawals_per_epoch(10);
    state.set_account(pubkey, create_test_validator_account(1, 100));
    for _ in 0..3 {
        state.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    }
    assert_eq!(due(&state), vec![5, 5, 5]);
    state
}

/// After restoring, the rebuilt transient counts must both hold the validator
/// at cap and free a slot when an entry drains.
fn assert_cap_live_after_restore(restored: &mut ConsensusState, pubkey: [u8; 32]) {
    restored.apply_withdrawal_request(request(pubkey, creds(1), 5), WITHDRAWAL_EPOCHS);
    assert_eq!(due(restored), vec![5, 5, 5]);

    restored.pop_withdrawal(WITHDRAWAL_EPOCHS).unwrap();
    restored.apply_withdrawal_request(request(pubkey, creds(1), 7), WITHDRAWAL_EPOCHS);
    assert_eq!(due(restored), vec![5, 5, 7]);
}

// The per pubkey pending counts are transient and never serialized, so every
// state reconstruction path must rebuild them from the decoded queue. This
// covers the codec round trip, which is also the finalizer disk load path.
#[test]
fn cap_enforced_after_codec_round_trip() {
    let pubkey = [1u8; 32];
    let state = serializable_state_at_cap(pubkey);

    let mut encoded = state.encode();
    let mut restored = ConsensusState::decode(&mut encoded).unwrap();
    assert_cap_live_after_restore(&mut restored, pubkey);
}

// Checkpoint restore decodes the state from the checkpoint data blob; the
// rebuilt counts must keep enforcing the cap.
#[test]
fn cap_enforced_after_checkpoint_restore() {
    use crate::checkpoint::Checkpoint;

    let pubkey = [1u8; 32];
    let state = serializable_state_at_cap(pubkey);

    let checkpoint = Checkpoint::new(&state);
    let mut restored = ConsensusState::try_from(&checkpoint).unwrap();
    assert_cap_live_after_restore(&mut restored, pubkey);
}
