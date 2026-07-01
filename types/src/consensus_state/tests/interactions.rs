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
