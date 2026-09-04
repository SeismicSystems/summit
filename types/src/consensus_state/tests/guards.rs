use super::super::*;
use super::common::*;
use crate::PublicKey;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use alloy_primitives::Address;
use commonware_codec::DecodeExt;
use commonware_cryptography::{Signer, bls12381, ed25519};

// Add an active validator keyed by a real ed25519 public key (arbitrary [n; 32]
// byte patterns are not all valid curve points). Returns the account key.
fn add_active(state: &mut ConsensusState, seed: u64, balance: u64) -> [u8; 32] {
    let key: [u8; 32] = ed25519::PrivateKey::from_seed(seed)
        .public_key()
        .as_ref()
        .try_into()
        .unwrap();
    state.set_account(key, create_test_validator_account(1, balance));
    key
}

// Add a joining validator (status Joining, activation scheduled for
// `joining_epoch`) keyed by a real ed25519 public key. Returns the account key.
fn add_joining(
    state: &mut ConsensusState,
    seed: u64,
    balance: u64,
    joining_epoch: u64,
) -> [u8; 32] {
    let node_key = ed25519::PrivateKey::from_seed(seed).public_key();
    let consensus_key = bls12381::PrivateKey::from_seed(seed).public_key();
    let key: [u8; 32] = node_key.as_ref().try_into().unwrap();
    let mut account = create_test_validator_account(seed, balance);
    account.status = ValidatorStatus::Joining;
    account.joining_epoch = joining_epoch;
    account.consensus_public_key = consensus_key.clone();
    state.set_account(key, account);
    state.add_validator(
        joining_epoch,
        AddedValidator {
            node_key,
            consensus_key,
        },
    );
    key
}

fn removed(state: &ConsensusState, key: [u8; 32]) -> bool {
    let pk = PublicKey::decode(&key[..]).unwrap();
    state.get_removed_validators().contains(&pk)
}

fn removed_count(state: &ConsensusState, key: [u8; 32]) -> usize {
    let pk = PublicKey::decode(&key[..]).unwrap();
    state
        .get_removed_validators()
        .iter()
        .filter(|k| **k == pk)
        .count()
}

// A full exit is refused when it would drop the active set below the minimum
// validator count: the validator stays Active and nothing is enqueued.
#[test]
fn exit_floor_blocks_full_exit() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(2);
    state.set_max_withdrawals_per_epoch(10);
    let key = add_active(&mut state, 1, 100);
    add_active(&mut state, 2, 100);

    // Active count is 2; accepting an exit would leave 1 < the floor of 2.
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount: 0,
        },
        2,
    );

    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Active
    );
    assert!(!removed(&state, key));
    assert!(state.get_withdrawals_for_epoch(2).is_empty());
}

// A pending minimum stake increase is rejected when too few validators would
// remain: the change is dropped and no one is removed.
#[test]
fn enforce_minimum_stake_rejects_when_too_few_retained() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(2);
    // Both validators are below the proposed new minimum of 100.
    add_active(&mut state, 1, 50);
    add_active(&mut state, 2, 50);
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(100)]);
    assert_eq!(state.prospective_minimum_stake(), 100);

    state.enforce_minimum_stake();

    // Retained at >= 100 is 0 < the floor of 2: reject the change, remove no one.
    assert_eq!(state.prospective_minimum_stake(), 32);
    assert!(state.get_removed_validators().is_empty());
}

// A pending minimum stake increase is applied when enough validators remain:
// the change stands and below-minimum validators are staged for removal.
#[test]
fn enforce_minimum_stake_applies_when_enough_retained() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    let key1 = add_active(&mut state, 1, 100);
    let key2 = add_active(&mut state, 2, 100);
    let below = add_active(&mut state, 3, 50);
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);

    state.enforce_minimum_stake();

    // Retained at >= 80 is 2 >= the floor of 1: keep the change, remove only the
    // below-minimum validator.
    assert_eq!(state.prospective_minimum_stake(), 80);
    assert!(removed(&state, below));
    assert!(!removed(&state, key1));
    assert!(!removed(&state, key2));
}

// A joining validator below the raised minimum has its pending activation
// cancelled and reverts to Inactive. It must not be left stuck as Joining (which
// would never re-activate, since its scheduled activation was removed), and it is
// not committee-removed (it never entered the committee).
#[test]
fn enforce_minimum_stake_cancels_joining_validator_to_inactive() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    // Two active validators stay above the new minimum so the change is applied.
    add_active(&mut state, 1, 100);
    add_active(&mut state, 2, 100);
    // A joining validator (activation scheduled for epoch 2) sits below it.
    let joining = add_joining(&mut state, 3, 50, 2);
    assert!(state.has_added_validators(2));
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);

    state.enforce_minimum_stake();

    // Activation cancelled, account reverted to Inactive, and not committee-removed.
    assert_eq!(
        state.get_account(&joining).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert!(!state.has_added_validators(2));
    assert!(!removed(&state, joining));
}

// Regression for #204: a voluntary full exit and a minimum-stake increase that
// takes effect in the same epoch must not collide. The voluntarily-exiting
// validator (already SubmittedExitRequest and in removed_validators) is excluded
// from the stake-bound removal candidates, so it is neither reverted nor listed
// twice, and its single full-exit payout is untouched. The separately
// below-minimum validator is removed with no forced payout.
#[test]
fn enforce_minimum_stake_preserves_concurrent_voluntary_exit() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    state.set_max_withdrawals_per_epoch(10);
    let stays = add_active(&mut state, 1, 100);
    let exiting = add_active(&mut state, 2, 100);
    let below = add_active(&mut state, 3, 50);

    // The exiting validator submits a voluntary full exit first: staged for
    // committee removal with a full-exit payout enqueued for epoch 2.
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: exiting,
            amount: 0,
        },
        2,
    );
    assert_eq!(
        state.get_account(&exiting).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );

    // A minimum-stake increase to 80 is enforced the same epoch. `stays` (100)
    // retains the committee above the floor, so the change applies.
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);
    state.enforce_minimum_stake();

    assert_eq!(state.prospective_minimum_stake(), 80);

    // The voluntary exit is preserved exactly: status unchanged, listed for
    // removal once (not duplicated by enforcement), and its single full-exit
    // payout still queued.
    assert_eq!(
        state.get_account(&exiting).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert_eq!(removed_count(&state, exiting), 1);
    let queued = state.get_withdrawals_for_epoch(2);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].pubkey, exiting);

    // The below-minimum validator is removed by the stake bound, but keeps its
    // balance and gets no forced payout (removed validators withdraw later).
    assert!(removed(&state, below));
    assert_eq!(state.get_account(&below).unwrap().balance, 50);
    assert!(!removed(&state, stays));
}

// Regression for #374: when the minimum stake is raised, a validator whose
// same-epoch top-up did not reach the new minimum is removed from the committee
// but keeps its full (topped-up) balance. The rework never force-withdraws on
// stake-bound removal, so the balance is retained (withdrawable later), not
// dropped.
#[test]
fn enforce_minimum_stake_removal_retains_topped_up_balance() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    state.set_max_withdrawals_per_epoch(10);
    let key1 = add_active(&mut state, 1, 100);
    let key2 = add_active(&mut state, 2, 100);
    // Balance 60 reflects an original 50 plus a same-epoch top-up of 10 that
    // still falls short of the raised minimum of 80.
    let below = add_active(&mut state, 3, 60);

    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);
    state.enforce_minimum_stake();

    // Removed from the committee, but the account and its full balance are kept:
    // the balance is not dropped and nothing is force-withdrawn.
    assert!(removed(&state, below));
    let account = state.get_account(&below).unwrap();
    assert_eq!(account.balance, 60);
    assert_eq!(account.status, ValidatorStatus::Active);
    assert!(state.get_withdrawals_for_epoch(2).is_empty());
    assert!(!removed(&state, key1));
    assert!(!removed(&state, key2));
}

// enforce_minimum_stake only considers Active and Joining validators as removal
// candidates. Validators already out of the committee — Inactive (kept balance,
// may rejoin) and FullPayoutPending (awaiting a full-exit payout) — must be left
// untouched even when their balance is below a raised minimum: status unchanged,
// not (re-)added to removed_validators, balance preserved. Completes the
// status-variant matrix for stake-bound enforcement.
#[test]
fn enforce_minimum_stake_ignores_out_of_committee_validators() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    state.set_max_withdrawals_per_epoch(10);

    // Two active validators keep the committee above the floor so the change applies.
    let stays_a = add_active(&mut state, 1, 100);
    let stays_b = add_active(&mut state, 2, 100);

    // Out-of-committee validators sitting below the raised minimum of 80.
    let inactive = add_active(&mut state, 3, 50);
    let mut acc = state.get_account(&inactive).unwrap().clone();
    acc.status = ValidatorStatus::Inactive;
    state.set_account(inactive, acc);

    let payout_pending = add_active(&mut state, 4, 50);
    let mut acc = state.get_account(&payout_pending).unwrap().clone();
    acc.status = ValidatorStatus::FullPayoutPending;
    state.set_account(payout_pending, acc);

    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);
    state.enforce_minimum_stake();

    assert_eq!(state.prospective_minimum_stake(), 80);

    // Neither out-of-committee validator is touched: not removed, balance kept.
    assert!(!removed(&state, inactive));
    assert!(!removed(&state, payout_pending));
    assert_eq!(state.get_account(&inactive).unwrap().balance, 50);
    assert_eq!(state.get_account(&payout_pending).unwrap().balance, 50);
    assert_eq!(
        state.get_account(&inactive).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert_eq!(
        state.get_account(&payout_pending).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    // The retained active validators are untouched too.
    assert!(!removed(&state, stays_a));
    assert!(!removed(&state, stays_b));
}

// Regression for the terminal payout ordering finding (F2): payouts run on the
// terminal block, after enforce_minimum_stake retained the committee against a
// pending raise (penultimate block) and before the boundary applies it. A
// partial due on the terminal block must clamp against the prospective
// minimum, not the outgoing one. Clamping against the old minimum lets the
// payout drain a retained validator below the raise, leaving it stranded
// Active under the new minimum with no later re enforcement.
#[test]
fn terminal_payout_clamps_against_prospective_minimum() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    state.set_max_withdrawals_per_epoch(10);
    // A well funded validator keeps the committee above the retention floor.
    let stays = add_active(&mut state, 1, 100);
    // The target validator sits above the pending raise before payouts.
    let clipped = add_active(&mut state, 2, 45);

    // A partial withdrawal of 10 is requested at epoch 0 and falls due at
    // epoch 2, the epoch whose terminal block pays it out.
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: clipped,
            amount: 10,
        },
        2,
    );

    // Penultimate block of the payout epoch: a raise to 40 lands and is
    // enforced against pre payout balances. 45 >= 40, so the validator is
    // retained rather than removed.
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(40)]);
    state.enforce_minimum_stake();
    assert_eq!(state.prospective_minimum_stake(), 40);
    assert!(!removed(&state, clipped));

    // Terminal block: the payout must keep the retained validator viable under
    // the incoming minimum, paying min(10, 45 - 40) = 5 rather than the full 10.
    let block = state.emit_withdrawal_payouts(2);
    assert_eq!(block.iter().map(|w| w.amount).collect::<Vec<_>>(), vec![5]);
    state.apply_withdrawal_payouts(2, &block);

    // Boundary: the raise is applied after the payouts.
    state.apply_protocol_parameter_changes().unwrap();
    assert_eq!(state.get_minimum_stake(), 40);

    // The validator ends the boundary Active at exactly the new minimum.
    let account = state.get_account(&clipped).unwrap();
    assert_eq!(account.status, ValidatorStatus::Active);
    assert_eq!(account.balance, 40);
    assert!(!removed(&state, stays));
}

// Companion in the lowering direction: a pending minimum stake decrease also
// takes effect for terminal block payouts. The second of two same epoch
// partials clamps against the incoming lower minimum and gains the headroom
// the decrease opens up, instead of being clamped to zero by the outgoing
// minimum and dropped.
#[test]
fn terminal_payout_uses_incoming_lowered_minimum() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(40);
    state.set_minimum_validator_count(1);
    state.set_max_withdrawals_per_epoch(10);
    let key = add_active(&mut state, 1, 100);

    // Two partials of 60 due at epoch 2, pushed raw as in the payouts tests:
    // request time clamping is not under test here.
    for _ in 0..2 {
        state.push_withdrawal_request(
            WithdrawalRequest {
                source_address: Address::from([1u8; 20]),
                validator_pubkey: key,
                amount: 60,
            },
            2,
        );
    }

    // Penultimate block: a decrease to 32 lands; nobody is below it, so
    // enforcement retains everyone and keeps the change pending.
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(32)]);
    state.enforce_minimum_stake();
    assert_eq!(state.prospective_minimum_stake(), 32);

    // Terminal block: the sequential clamp runs against the incoming minimum.
    // The first pays min(60, 100 - 32) = 60, the second min(60, 40 - 32) = 8.
    let block = state.emit_withdrawal_payouts(2);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![60, 8]
    );
    state.apply_withdrawal_payouts(2, &block);

    // Boundary: the decrease is applied after the payouts; the validator ends
    // Active at exactly the new minimum.
    state.apply_protocol_parameter_changes().unwrap();
    assert_eq!(state.get_minimum_stake(), 32);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Active);
    assert_eq!(account.balance, 32);
}
