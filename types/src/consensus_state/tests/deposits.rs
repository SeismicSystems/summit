use super::super::*;
use crate::account::ValidatorStatus;
use crate::withdrawal::WithdrawalKind;
use crate::{Digest, deposit_signature_domain};

use commonware_cryptography::{Signer, bls12381, ed25519};

use super::common::*;

// Draining a capped batch of deposits through
// pop_deposit_deferred + a single rebuild_deposit_tree must land in the
// exact same state (queue length and ssz root) as draining the same count
// one pop at a time, where every pop rebuilt the whole remaining subtree.
#[test]
fn test_deferred_deposit_drain_matches_per_pop() {
    // backlog larger than the cap so the drain is partial and the remaining
    // subtree is non trivial.
    let backlog = 64usize;
    let cap = 16usize;

    let mut per_pop = ConsensusState::default();
    let mut deferred = ConsensusState::default();
    for i in 0..backlog as u64 {
        let deposit = create_test_deposit_request(i, 32_000_000_000 + i);
        per_pop.push_deposit(deposit.clone());
        deferred.push_deposit(deposit);
    }
    assert_eq!(
        per_pop.ssz_tree().root(),
        deferred.ssz_tree().root(),
        "states should start identical"
    );

    // per pop path: rebuild on every pop (the original behaviour).
    for _ in 0..cap {
        per_pop.pop_deposit();
    }

    // deferred path: pop without rebuilding, then rebuild exactly once.
    for _ in 0..cap {
        deferred.pop_deposit_deferred();
    }
    deferred.rebuild_deposit_tree();

    assert_eq!(
        deferred.deposit_count(),
        per_pop.deposit_count(),
        "both paths should drain the same number of deposits"
    );
    assert_eq!(deferred.deposit_count(), backlog - cap);
    assert_eq!(
        deferred.ssz_tree().root(),
        per_pop.ssz_tree().root(),
        "deferred single rebuild root should match per pop root"
    );

    // and the deferred root must equal a fresh full rebuild from the queue.
    deferred.rebuild_ssz_tree();
    assert_eq!(
        deferred.ssz_tree().root(),
        per_pop.ssz_tree().root(),
        "deferred root should match a full rebuild"
    );
}

// draining a backlog smaller than the cap must fully empty the queue and
// leave a root identical to per pop draining (mirrors the finalizer break
// on empty queue).
#[test]
fn test_deferred_deposit_drain_empties_small_backlog() {
    let backlog = 5usize;
    let cap = 16usize;

    let mut per_pop = ConsensusState::default();
    let mut deferred = ConsensusState::default();
    for i in 0..backlog as u64 {
        let deposit = create_test_deposit_request(i, 32_000_000_000 + i);
        per_pop.push_deposit(deposit.clone());
        deferred.push_deposit(deposit);
    }

    let mut drained_any = false;
    for _ in 0..cap {
        if per_pop.pop_deposit().is_none() {
            break;
        }
    }
    for _ in 0..cap {
        if deferred.pop_deposit_deferred().is_some() {
            drained_any = true;
        } else {
            break;
        }
    }
    if drained_any {
        deferred.rebuild_deposit_tree();
    }

    assert_eq!(deferred.deposit_count(), 0);
    assert_eq!(per_pop.deposit_count(), 0);
    assert_eq!(
        deferred.ssz_tree().root(),
        per_pop.ssz_tree().root(),
        "empty queue roots should match"
    );
}

// ---- deposit processing by validator status ----

const MIN: u64 = 32;
const WARM_UP: u64 = 2;
const WITHDRAWAL_EPOCHS: u64 = 2;

fn test_domain() -> Digest {
    deposit_signature_domain([9u8; 32], b"_TEST")
}

fn deposit_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_deposits_per_epoch(16);
    state
}

fn node_bytes(node_priv: &ed25519::PrivateKey) -> [u8; 32] {
    node_priv.public_key().as_ref().try_into().unwrap()
}

// Seed an account keyed by the node's public key, carrying `bls_priv`'s
// consensus key so a matching deposit verifies. Returns the account key.
fn seed_account(
    state: &mut ConsensusState,
    node_priv: &ed25519::PrivateKey,
    bls_priv: &bls12381::PrivateKey,
    status: ValidatorStatus,
    balance: u64,
) -> [u8; 32] {
    let key = node_bytes(node_priv);
    let mut account = create_test_validator_account(1, balance);
    account.status = status;
    account.consensus_public_key = bls_priv.public_key();
    state.set_account(key, account);
    key
}

fn has_refund(state: &ConsensusState) -> bool {
    state
        .get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS)
        .iter()
        .any(|w| w.kind == WithdrawalKind::DepositRefund)
}

// A deposit for a new validator below the minimum stake creates an inactive
// account that keeps the balance (no refund).
#[test]
fn new_account_below_min_stays_inactive() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(10);
    let bls = bls12381::PrivateKey::from_seed(10);
    let key = node_bytes(&node);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        20,
        0,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Inactive);
    assert_eq!(account.balance, 20);
}

// A deposit for a new validator at or above the minimum stake creates the
// account and schedules activation after the warm up.
#[test]
fn new_account_at_min_activates() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(11);
    let bls = bls12381::PrivateKey::from_seed(11);
    let key = node_bytes(&node);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        100,
        0,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.balance, 100);
    assert_eq!(account.joining_epoch, WARM_UP);
    assert!(state.has_added_validators(WARM_UP));
}

// A top up that lifts an inactive validator to the minimum stake rejoins it.
#[test]
fn inactive_topup_to_min_rejoins() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(12);
    let bls = bls12381::PrivateKey::from_seed(12);
    let key = seed_account(&mut state, &node, &bls, ValidatorStatus::Inactive, 20);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        20,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.balance, 40);
    assert!(state.has_added_validators(WARM_UP));
}

// A top up that leaves an inactive validator below the minimum keeps it
// inactive with the credited balance.
#[test]
fn inactive_topup_below_min_stays_inactive() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(13);
    let bls = bls12381::PrivateKey::from_seed(13);
    let key = seed_account(&mut state, &node, &bls, ValidatorStatus::Inactive, 10);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        5,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Inactive);
    assert_eq!(account.balance, 15);
    assert!(!state.has_added_validators(WARM_UP));
}

// A top up to an active validator credits the balance, status unchanged.
#[test]
fn active_topup_credits_balance() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(14);
    let bls = bls12381::PrivateKey::from_seed(14);
    let key = seed_account(&mut state, &node, &bls, ValidatorStatus::Active, 100);

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        50,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Active);
    assert_eq!(account.balance, 150);
}

// A deposit to a validator mid full exit (still serving) is credited only and
// does not re activate it.
#[test]
fn submitted_exit_deposit_credits_only() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(15);
    let bls = bls12381::PrivateKey::from_seed(15);
    let key = seed_account(
        &mut state,
        &node,
        &bls,
        ValidatorStatus::SubmittedExitRequest,
        100,
    );

    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        50,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::SubmittedExitRequest);
    assert_eq!(account.balance, 150);
    assert!(!state.has_added_validators(WARM_UP));
}

// A deposit to a validator awaiting its full payout folds into the balance but
// must NOT rejoin it (the FullPayoutPending anti rejoin guard).
#[test]
fn full_payout_pending_deposit_does_not_rejoin() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(16);
    let bls = bls12381::PrivateKey::from_seed(16);
    let key = seed_account(
        &mut state,
        &node,
        &bls,
        ValidatorStatus::FullPayoutPending,
        20,
    );

    // Lift well past the minimum: a plain inactive validator would rejoin here.
    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        100,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::FullPayoutPending); // not rejoined
    assert_eq!(account.balance, 120); // folds into the pending payout
    assert!(!state.has_added_validators(WARM_UP));
}

// A deposit with an invalid signature is refunded and never credited.
#[test]
fn invalid_signature_is_refunded() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(17);
    let bls = bls12381::PrivateKey::from_seed(17);
    let key = node_bytes(&node);

    let mut deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, test_domain());
    deposit.node_signature[0] ^= 0xFF; // corrupt the node signature
    state.push_deposit(deposit);
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    assert!(state.get_account(&key).is_none()); // never credited
    assert!(has_refund(&state));
}

// A deposit whose consensus key does not match the existing account is refunded
// and the account balance is unchanged.
#[test]
fn consensus_key_mismatch_is_refunded() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(18);
    let account_bls = bls12381::PrivateKey::from_seed(18);
    let key = seed_account(&mut state, &node, &account_bls, ValidatorStatus::Active, 50);

    // Validly signed, but with a different consensus key than the account holds.
    let wrong_bls = bls12381::PrivateKey::from_seed(99);
    state.push_deposit(make_signed_deposit(
        &node,
        &wrong_bls,
        eth1_credentials(1),
        100,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 50); // not credited
    assert!(has_refund(&state));
}

// verify_deposit_request accepts a correctly signed deposit.
#[test]
fn verify_accepts_valid_signatures() {
    let state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(50);
    let bls = bls12381::PrivateKey::from_seed(50);
    let deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, test_domain());
    assert_eq!(
        state.verify_deposit_request(&deposit, test_domain()),
        Ok(())
    );
}

// A bad node (Ed25519) signature is reported as InvalidNodeSignature.
#[test]
fn verify_rejects_invalid_node_signature() {
    let state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(51);
    let bls = bls12381::PrivateKey::from_seed(51);
    let mut deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, test_domain());
    deposit.node_signature[0] ^= 0xFF;
    assert_eq!(
        state.verify_deposit_request(&deposit, test_domain()),
        Err(DepositRejectionReason::InvalidNodeSignature)
    );
}

// A valid node signature but bad consensus (BLS) signature is reported as
// InvalidConsensusSignature.
#[test]
fn verify_rejects_invalid_consensus_signature() {
    let state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(52);
    let bls = bls12381::PrivateKey::from_seed(52);
    let mut deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, test_domain());
    deposit.consensus_signature[0] ^= 0xFF; // node signature stays valid
    assert_eq!(
        state.verify_deposit_request(&deposit, test_domain()),
        Err(DepositRejectionReason::InvalidConsensusSignature)
    );
}

// The node signature is checked before the consensus signature: a deposit with
// both invalid reports the node failure (and the BLS verify is skipped).
#[test]
fn verify_checks_node_signature_before_consensus() {
    let state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(53);
    let bls = bls12381::PrivateKey::from_seed(53);
    let mut deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, test_domain());
    deposit.node_signature[0] ^= 0xFF;
    deposit.consensus_signature[0] ^= 0xFF;
    assert_eq!(
        state.verify_deposit_request(&deposit, test_domain()),
        Err(DepositRejectionReason::InvalidNodeSignature)
    );
}

// A top-up for a validator that is already Joining (activation pending) credits
// the balance without disturbing the scheduled activation: the status stays
// Joining, the original joining_epoch is preserved (not pushed later by the new
// deposit's later epoch), and the activation is not duplicated. The second
// deposit lands in a later epoch to prove joining_epoch is not re-derived from
// the current epoch.
#[test]
fn joining_topup_credits_without_rescheduling_activation() {
    let mut state = deposit_state();
    let node = ed25519::PrivateKey::from_seed(15);
    let bls = bls12381::PrivateKey::from_seed(15);
    let key = node_bytes(&node);

    // First deposit in epoch 0 creates the account and schedules activation for
    // epoch WARM_UP.
    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        100,
        0,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.joining_epoch, WARM_UP);
    assert!(state.has_added_validators(WARM_UP));

    // A top-up in a later epoch (1) with a higher deposit index.
    state.set_epoch(1);
    state.push_deposit(make_signed_deposit(
        &node,
        &bls,
        eth1_credentials(1),
        50,
        1,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 150, "top-up must be credited");
    assert_eq!(
        account.status,
        ValidatorStatus::Joining,
        "an already-joining validator stays Joining after a top-up"
    );
    assert_eq!(
        account.joining_epoch, WARM_UP,
        "the top-up must not push the activation to a later epoch"
    );
    assert!(
        state.has_added_validators(WARM_UP),
        "the original scheduled activation must remain"
    );
    assert!(
        !state.has_added_validators(1 + WARM_UP),
        "the top-up must not create a second, later activation"
    );
}
