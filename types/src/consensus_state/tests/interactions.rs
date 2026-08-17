use super::super::*;
use super::common::*;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::{Digest, deposit_signature_domain};
use alloy_primitives::Address;
use commonware_cryptography::{Signer, bls12381, ed25519};

const MIN: u64 = 32;
const WARM_UP: u64 = 2;
const WITHDRAWAL_EPOCHS: u64 = 2;

fn test_domain() -> Digest {
    deposit_signature_domain([9u8; 32], b"_TEST")
}

fn node_bytes(node_priv: &ed25519::PrivateKey) -> [u8; 32] {
    node_priv.public_key().as_ref().try_into().unwrap()
}

fn interaction_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_max_deposits_per_epoch(16);
    state.set_max_withdrawals_per_epoch(16);
    state.set_minimum_validator_count(0);
    state
}

// Seed an account keyed by the node key with a matching consensus key.
fn seed(
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

fn full_exit(state: &mut ConsensusState, key: [u8; 32]) {
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount: 0,
        },
        WITHDRAWAL_EPOCHS,
    );
}

fn partial_withdrawal(state: &mut ConsensusState, key: [u8; 32], amount: u64) {
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount,
        },
        WITHDRAWAL_EPOCHS,
    );
}

fn land_deposit(
    state: &mut ConsensusState,
    node_priv: &ed25519::PrivateKey,
    bls_priv: &bls12381::PrivateKey,
    amount: u64,
) {
    state.push_deposit(make_signed_deposit(
        node_priv,
        bls_priv,
        eth1_credentials(1),
        amount,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);
}

// An active validator's full exit, then a deposit before payout: the deposit is
// credited (no re activation, B6) and the payout pays the larger balance,
// folding the deposit into the exit. The account is removed at payout.
#[test]
fn active_full_exit_then_deposit_folds_into_payout() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(30);
    let bls = bls12381::PrivateKey::from_seed(30);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Active, 100);

    full_exit(&mut state, key);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );

    land_deposit(&mut state, &node, &bls, 50);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 150);
    assert_eq!(account.status, ValidatorStatus::SubmittedExitRequest);

    // Payout pays the live balance including the folded in deposit.
    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![150]
    );
    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert!(state.get_account(&key).is_none());
}

// An inactive validator's full exit (FullPayoutPending), then a deposit large
// enough to otherwise rejoin: it stays FullPayoutPending, the deposit folds into
// the payout, and the account is removed.
#[test]
fn inactive_full_exit_then_deposit_folds_and_removed() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(31);
    let bls = bls12381::PrivateKey::from_seed(31);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Inactive, 40);

    full_exit(&mut state, key);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );

    land_deposit(&mut state, &node, &bls, 100);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 140);
    assert_eq!(account.status, ValidatorStatus::FullPayoutPending); // not rejoined

    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![140]
    );
    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert!(state.get_account(&key).is_none());
}

// Independent validators processed together do not interfere: one rejoins via a
// deposit while another fully exits in the same epoch.
#[test]
fn deposit_rejoin_and_exit_are_independent() {
    let mut state = interaction_state();

    // Validator A: inactive below min, a deposit rejoins it.
    let node_a = ed25519::PrivateKey::from_seed(32);
    let bls_a = bls12381::PrivateKey::from_seed(32);
    let key_a = seed(&mut state, &node_a, &bls_a, ValidatorStatus::Inactive, 20);

    // Validator B: active, fully exits.
    let node_b = ed25519::PrivateKey::from_seed(33);
    let bls_b = bls12381::PrivateKey::from_seed(33);
    let key_b = seed(&mut state, &node_b, &bls_b, ValidatorStatus::Active, 100);

    full_exit(&mut state, key_b);
    land_deposit(&mut state, &node_a, &bls_a, 20); // 20 + 20 = 40 >= MIN

    assert_eq!(
        state.get_account(&key_a).unwrap().status,
        ValidatorStatus::Joining
    );
    assert_eq!(state.get_account(&key_a).unwrap().balance, 40);
    assert_eq!(
        state.get_account(&key_b).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
}

// Regression for #211 (Critical): a deposit refund and a validator full-exit that
// target the SAME node pubkey and are scheduled for the SAME payout epoch must stay
// separate queue entries. The old code keyed refunds by the depositor's node pubkey
// and merged same-pubkey withdrawals, so a same-pubkey withdrawal could mutate an
// already-snapshotted refund and trip the emit-equals-block assertion in
// apply_withdrawal_payouts, panicking finalization. The rework makes this impossible:
// refunds carry a zero pubkey, are a distinct kind, and are never merged (append-only).
#[test]
fn refund_and_same_pubkey_exit_do_not_merge_and_payout_is_stable() {
    let mut state = interaction_state();

    // An active validator fully exits: a Validator-kind payout of its live balance
    // (100) scheduled for epoch WITHDRAWAL_EPOCHS.
    let node = ed25519::PrivateKey::from_seed(40);
    let bls = bls12381::PrivateKey::from_seed(40);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Active, 100);
    full_exit(&mut state, key);

    // A deposit for the SAME node pubkey but carrying a different consensus key is
    // rejected at processing time and refunded (a DepositRefund-kind payout with a
    // zero pubkey, scheduled for the same epoch WITHDRAWAL_EPOCHS). This is exactly
    // the same-pubkey collision that used to merge into the exit.
    let wrong_bls = bls12381::PrivateKey::from_seed(41);
    state.push_deposit(make_signed_deposit(
        &node,
        &wrong_bls,
        eth1_credentials(1),
        50,
        5,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    // The exit (100) and the refund (50) are two independent payouts, not a single
    // merged 150 entry. A merge would surface as one payout here and then panic in
    // apply_withdrawal_payouts.
    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(block.len(), 2);
    let mut amounts: Vec<u64> = block.iter().map(|w| w.amount).collect();
    amounts.sort_unstable();
    assert_eq!(amounts, vec![50, 100]);

    // Emit equals the applied payouts, so the reconciliation assertion does not fire.
    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert!(state.get_account(&key).is_none());
}

// Regression for #339: a queued deposit for a node pubkey whose consensus (BLS)
// key does not match the account currently registered for that pubkey (a stale
// top-up landing after the original validator exited and a replacement account
// was created under the same node pubkey) is refunded to the deposit's own
// withdrawal credentials. It must not be credited to the replacement account or
// overwrite its metadata.
#[test]
fn stale_topup_with_mismatched_consensus_key_is_refunded_not_rebound() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(50);
    let replacement_bls = bls12381::PrivateKey::from_seed(50);
    // The account currently registered for this node pubkey (the replacement).
    let key = seed(
        &mut state,
        &node,
        &replacement_bls,
        ValidatorStatus::Active,
        100,
    );

    // A stale deposit for the same node pubkey but carrying a different consensus
    // key (the pre-exit identity). Signatures are valid; the key mismatches.
    let stale_bls = bls12381::PrivateKey::from_seed(51);
    let refund_creds = eth1_credentials(9);
    state.push_deposit(make_signed_deposit(
        &node,
        &stale_bls,
        refund_creds,
        40,
        7,
        test_domain(),
    ));
    state.process_deposits(test_domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    // The replacement account is untouched: balance not credited, key preserved.
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 100);
    assert_eq!(account.consensus_public_key, replacement_bls.public_key());

    // The stale deposit was refunded to its own withdrawal address (in full,
    // since the invalid deposit tax defaults to zero), not rebound to the
    // replacement account.
    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(block.len(), 1);
    assert_eq!(block[0].amount, 40);
    assert_eq!(block[0].address, Address::from([9u8; 20]));
}

// A partial withdrawal followed by a full exit for the same active validator,
// both scheduled for the same payout epoch, must pay out the balance exactly
// once across the two entries: the partial pays its requested amount and the
// full-exit marker pays only the remaining balance (not the whole balance
// again), so the sum equals the original balance and the account is removed.
// This guards against a double-pay where the full-exit marker would ignore the
// partial already draining part of the balance.
#[test]
fn partial_then_full_exit_pays_balance_once_and_removes_account() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(60);
    let bls = bls12381::PrivateKey::from_seed(60);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Active, 100);

    // Partial first: withdrawable is 100 - MIN(32) = 68, so 40 is enqueued in
    // full. The validator stays Active with its balance unchanged (debited at
    // payout).
    partial_withdrawal(&mut state, key, 40);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Active
    );

    // Then a full exit: stages committee removal and enqueues a full-exit marker
    // (amount 0) behind the partial for the same epoch.
    full_exit(&mut state, key);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert_eq!(state.get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS).len(), 2);

    // Payout: the partial pays 40 (running balance 100 -> 60), then the full-exit
    // marker pays the remaining 60 (running balance 60 -> 0). Total 100, the
    // original balance, with no double-pay.
    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![40, 60]
    );
    assert_eq!(block.iter().map(|w| w.amount).sum::<u64>(), 100);

    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert!(state.get_account(&key).is_none());
}

// Partial withdrawals queued while a validator is active, then a full exit
// requested before those partials pay out, must keep the minimum-stake floor on
// the partials until the validator has actually left the committee. The partials
// may not drain the retained stake; only the full-exit payout may empty the
// account after the exit.
#[test]
fn partials_keep_minimum_floor_for_staged_exit() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(63);
    let bls = bls12381::PrivateKey::from_seed(63);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Active, 2 * MIN);

    // Two partials queued while active, due two epochs later.
    state.set_epoch(1);
    partial_withdrawal(&mut state, key, MIN);
    partial_withdrawal(&mut state, key, MIN);
    assert_eq!(state.get_withdrawals_for_epoch(3).len(), 2);

    // The full exit is requested in the epoch the partials become due.
    state.set_epoch(3);
    full_exit(&mut state, key);
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );

    // The partials are still floored: only one fills, leaving the minimum stake.
    let block = state.emit_withdrawal_payouts(3);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![MIN]
    );
    state.apply_withdrawal_payouts(3, &block);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, MIN);
    assert_eq!(account.status, ValidatorStatus::SubmittedExitRequest);

    // After the validator leaves the committee, the full-exit payout drains the
    // retained stake and removes the account.
    assert!(state.apply_committee_transition(&node.public_key()));
    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::FullPayoutPending
    );
    state.set_epoch(5);
    let block = state.emit_withdrawal_payouts(5);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![MIN]
    );
    state.apply_withdrawal_payouts(5, &block);
    assert!(state.get_account(&key).is_none());
}

// Regression: two withdrawals from an inactive validator are independently
// valid against its unchanged balance. A later deposit credits the balance
// but does not schedule activation while the withdrawal queue still has
// pending entries for this validator, preventing a stale activation that
// would otherwise be drained before it takes effect.
#[test]
fn inactive_withdrawals_then_rejoin_do_not_leave_stale_activation() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(61);
    let bls = bls12381::PrivateKey::from_seed(61);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Inactive, MIN - 1);

    // Epoch 1: both requests are valid against the unchanged 31 ETH balance and
    // are scheduled for epoch 3.
    state.set_epoch(1);
    partial_withdrawal(&mut state, key, MIN - 1);
    partial_withdrawal(&mut state, key, MIN - 1);
    assert_eq!(state.get_withdrawals_for_epoch(3).len(), 2);

    // Epoch 2: a 1 ETH top-up reaches the minimum but pending withdrawals
    // block activation — the validator stays Inactive.
    state.set_epoch(2);
    land_deposit(&mut state, &node, &bls, 1);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, MIN);
    assert_eq!(account.status, ValidatorStatus::Inactive);
    assert!(!state.has_added_validators(4));

    // Epoch 3: the payouts drain the account to zero without leaving a stale
    // activation behind.
    state.set_epoch(3);
    let block = state.emit_withdrawal_payouts(3);
    assert_eq!(
        block
            .iter()
            .map(|withdrawal| withdrawal.amount)
            .collect::<Vec<_>>(),
        vec![MIN - 1, 1]
    );
    state.apply_withdrawal_payouts(3, &block);
    assert!(state.get_account(&key).is_none());
    assert!(!state.has_added_validators(4));

    // No panic — no stale activation was queued.
    state.apply_committee_transition(&node.public_key());
}

// Regression: a pending partial withdrawal prevents a Joining validator from
// being scheduled in the first place. A deposit that reaches the minimum stake
// does not activate while withdrawals are pending, avoiding a scenario where
// the withdrawal subsequently drains the validator below the minimum before
// activation.
#[test]
fn joining_validator_drained_below_minimum_is_not_activated() {
    let mut state = interaction_state();
    let node = ed25519::PrivateKey::from_seed(62);
    let bls = bls12381::PrivateKey::from_seed(62);
    let key = seed(&mut state, &node, &bls, ValidatorStatus::Inactive, MIN - 1);

    // Epoch 1: schedule one 31 ETH withdrawal for epoch 3.
    state.set_epoch(1);
    partial_withdrawal(&mut state, key, MIN - 1);
    assert_eq!(state.get_withdrawals_for_epoch(3).len(), 1);

    // Epoch 2: a 1 ETH deposit reaches the minimum but pending withdrawals
    // block activation — the validator stays Inactive.
    state.set_epoch(2);
    land_deposit(&mut state, &node, &bls, 1);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, MIN);
    assert_eq!(account.status, ValidatorStatus::Inactive);

    // Epoch 3: the pending withdrawal is paid, leaving 1 ETH. Balance stays
    // below minimum, no activation was ever scheduled.
    state.set_epoch(3);
    let block = state.emit_withdrawal_payouts(3);
    assert_eq!(
        block
            .iter()
            .map(|withdrawal| withdrawal.amount)
            .collect::<Vec<_>>(),
        vec![MIN - 1]
    );
    state.apply_withdrawal_payouts(3, &block);
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.balance, 1);
    assert_eq!(account.status, ValidatorStatus::Inactive);

    // No stale activation to cancel — the committee transition is a no-op.
    state.apply_committee_transition(&node.public_key());
}
