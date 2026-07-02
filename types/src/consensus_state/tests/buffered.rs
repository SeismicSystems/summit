use super::super::*;
use super::common::*;
use crate::account::ValidatorStatus;
use crate::execution_request::{DepositRequest, WithdrawalRequest};
use crate::withdrawal::WithdrawalKind;
use crate::{Digest, PublicKey, deposit_signature_domain};
use alloy_primitives::{Address, Bytes};
use commonware_codec::{DecodeExt, Write};
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

fn buffered_state() -> ConsensusState {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN);
    state.set_minimum_validator_count(0);
    state.set_max_deposits_per_epoch(16);
    state.set_max_withdrawals_per_epoch(16);
    state
}

// Raw EIP-7685 entry: [type byte] ++ inner.write(), matching how Reth groups
// requests (see node test_harness execution_requests_to_requests).
fn deposit_entry(deposit: &DepositRequest) -> Bytes {
    let mut payload = vec![0x00u8];
    deposit.write(&mut payload);
    Bytes::from(payload)
}

fn withdrawal_entry(request: &WithdrawalRequest) -> Bytes {
    let mut payload = vec![0x01u8];
    request.write(&mut payload);
    Bytes::from(payload)
}

// A 288-byte deposit chunk whose node/consensus key region (offsets 0..80) is
// corrupted so the key decode fails, while the withdrawal credentials (80..112)
// stay valid so the malformed-deposit refund can be paid.
fn malformed_deposit_entry(deposit: &DepositRequest) -> Bytes {
    let mut payload = vec![0x00u8];
    deposit.write(&mut payload);
    for byte in payload[1..1 + 80].iter_mut() {
        *byte = 0xFF;
    }
    Bytes::from(payload)
}

fn has_refund(state: &ConsensusState) -> bool {
    state
        .get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS)
        .iter()
        .any(|w| w.kind == WithdrawalKind::DepositRefund)
}

fn removed(state: &ConsensusState, key: [u8; 32]) -> bool {
    let pk = PublicKey::decode(&key[..]).unwrap();
    state.get_removed_validators().contains(&pk)
}

// A buffered deposit entry is decoded, queued, processed, and (at or above the
// minimum) schedules activation.
#[test]
fn buffered_deposit_creates_and_schedules_activation() {
    let mut state = buffered_state();
    let node = ed25519::PrivateKey::from_seed(40);
    let bls = bls12381::PrivateKey::from_seed(40);
    let key = node_bytes(&node);
    let deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, domain());

    state.buffer_execution_requests(&[deposit_entry(&deposit)]);
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.balance, 100);
}

// A buffered withdrawal entry is routed to the withdrawal handler and enqueues a
// payout.
#[test]
fn buffered_withdrawal_enqueues_payout() {
    let mut state = buffered_state();
    let node = ed25519::PrivateKey::from_seed(41);
    let key = node_bytes(&node);
    let mut account = create_test_validator_account(1, 100);
    account.consensus_public_key = bls12381::PrivateKey::from_seed(41).public_key();
    state.set_account(key, account);

    let request = WithdrawalRequest {
        source_address: Address::from([1u8; 20]),
        validator_pubkey: key,
        amount: 0,
    };
    state.buffer_execution_requests(&[withdrawal_entry(&request)]);
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert_eq!(state.get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS).len(), 1);
}

// A buffered malformed deposit chunk is refunded, not credited.
#[test]
fn buffered_malformed_deposit_is_refunded() {
    let mut state = buffered_state();
    let node = ed25519::PrivateKey::from_seed(42);
    let bls = bls12381::PrivateKey::from_seed(42);
    let key = node_bytes(&node);
    let deposit = make_signed_deposit(&node, &bls, eth1_credentials(1), 100, 0, domain());

    state.buffer_execution_requests(&[malformed_deposit_entry(&deposit)]);
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    assert!(state.get_account(&key).is_none());
    assert!(has_refund(&state));
}

// Buffering accumulates across calls and a single processing pass consumes the
// whole buffer (a second pass is a no-op).
#[test]
fn buffer_accumulates_then_processing_consumes_it() {
    let mut state = buffered_state();
    let node_a = ed25519::PrivateKey::from_seed(43);
    let bls_a = bls12381::PrivateKey::from_seed(43);
    let key_a = node_bytes(&node_a);
    let node_b = ed25519::PrivateKey::from_seed(44);
    let bls_b = bls12381::PrivateKey::from_seed(44);
    let key_b = node_bytes(&node_b);

    // Two separate buffer calls accumulate.
    state.buffer_execution_requests(&[deposit_entry(&make_signed_deposit(
        &node_a,
        &bls_a,
        eth1_credentials(1),
        100,
        0,
        domain(),
    ))]);
    state.buffer_execution_requests(&[deposit_entry(&make_signed_deposit(
        &node_b,
        &bls_b,
        eth1_credentials(2),
        100,
        1,
        domain(),
    ))]);

    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);
    assert_eq!(state.get_account(&key_a).unwrap().balance, 100);
    assert_eq!(state.get_account(&key_b).unwrap().balance, 100);

    // A second pass has nothing buffered to process, so balances are unchanged.
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);
    assert_eq!(state.get_account(&key_a).unwrap().balance, 100);
    assert_eq!(state.get_account(&key_b).unwrap().balance, 100);
}

// Regression for #248: a full exit and a deposit (top-up) for the SAME validator
// buffered for the same block must both take effect. Withdrawals are applied
// inline as the buffer is parsed and deposits are drained afterward, so the
// deposit can never drop the exit. The old mutual-exclusion (a pending-deposit
// flag that suppressed the withdrawal) would have silently discarded the exit.
#[test]
fn buffered_exit_and_topup_same_validator_both_apply() {
    let mut state = buffered_state();
    let node = ed25519::PrivateKey::from_seed(45);
    let bls = bls12381::PrivateKey::from_seed(45);
    let key = node_bytes(&node);
    let mut account = create_test_validator_account(1, 100);
    account.consensus_public_key = bls.public_key();
    state.set_account(key, account);

    // Deposit entry (type 0x00) groups before the withdrawal entry (type 0x01),
    // mirroring EIP-7685 type ordering. The withdrawal still wins: it is applied
    // during the parse loop, before the deposit queue is drained.
    let topup = make_signed_deposit(&node, &bls, eth1_credentials(1), 50, 0, domain());
    let exit = WithdrawalRequest {
        source_address: Address::from([1u8; 20]),
        validator_pubkey: key,
        amount: 0,
    };
    state.buffer_execution_requests(&[deposit_entry(&topup), withdrawal_entry(&exit)]);
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    // The exit took effect: the validator is exiting and staged for committee
    // removal, with a single full-exit payout queued.
    let account = state.get_account(&key).unwrap();
    assert_eq!(account.status, ValidatorStatus::SubmittedExitRequest);
    assert!(removed(&state, key));
    assert_eq!(state.get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS).len(), 1);

    // The deposit was still credited (folded into the pending exit balance), not
    // dropped: 100 + 50 = 150.
    assert_eq!(account.balance, 150);
}

// Multiple buffered partial withdrawals for the same validator are accepted as
// distinct queue entries, then re-clamped sequentially at payout time. This
// covers the production parsing path (buffer -> process_buffered_requests), not
// just direct queue insertion.
#[test]
fn buffered_multiple_partials_same_validator_reclamp_at_payout() {
    let mut state = buffered_state();
    let node = ed25519::PrivateKey::from_seed(46);
    let key = node_bytes(&node);
    state.set_account(key, create_test_validator_account(1, 100));

    let first = WithdrawalRequest {
        source_address: Address::from([1u8; 20]),
        validator_pubkey: key,
        amount: 50,
    };
    let second = first.clone();

    state.buffer_execution_requests(&[withdrawal_entry(&first), withdrawal_entry(&second)]);
    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    assert_eq!(state.get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS).len(), 2);

    let block = state.emit_withdrawal_payouts(WITHDRAWAL_EPOCHS);
    assert_eq!(
        block.iter().map(|w| w.amount).collect::<Vec<_>>(),
        vec![50, 18]
    );

    state.apply_withdrawal_payouts(WITHDRAWAL_EPOCHS, &block);
    assert_eq!(state.get_account(&key).unwrap().balance, MIN);
    assert!(
        state
            .get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS)
            .is_empty()
    );
}

// Requests buffered after the epoch's processing point (i.e. the last block)
// survive the epoch transition, stay ahead of later next-epoch requests, and are
// scheduled from the next epoch when the buffer is processed.
#[test]
fn deferred_last_block_request_keeps_order_and_next_epoch_schedule() {
    let mut state = buffered_state();
    let node_a = ed25519::PrivateKey::from_seed(47);
    let node_b = ed25519::PrivateKey::from_seed(48);
    let key_a = node_bytes(&node_a);
    let key_b = node_bytes(&node_b);
    state.set_account(key_a, create_test_validator_account(1, 100));
    state.set_account(key_b, create_test_validator_account(2, 100));

    let exit_a = WithdrawalRequest {
        source_address: Address::from([1u8; 20]),
        validator_pubkey: key_a,
        amount: 0,
    };
    let exit_b = WithdrawalRequest {
        source_address: Address::from([2u8; 20]),
        validator_pubkey: key_b,
        amount: 0,
    };

    // Simulate a request that arrived after epoch 0 processing already ran.
    state.buffer_execution_requests(&[withdrawal_entry(&exit_a)]);
    state.set_epoch(1);
    // Then a normal request from epoch 1 arrives behind it.
    state.buffer_execution_requests(&[withdrawal_entry(&exit_b)]);

    state.process_buffered_requests(domain(), WARM_UP, WITHDRAWAL_EPOCHS);

    assert!(
        state
            .get_withdrawals_for_epoch(WITHDRAWAL_EPOCHS)
            .is_empty(),
        "deferred last-block request must not keep the previous epoch's payout schedule"
    );

    let payout_epoch = 1 + WITHDRAWAL_EPOCHS;
    let queued = state.get_withdrawals_for_epoch(payout_epoch);
    assert_eq!(queued.len(), 2);
    assert_eq!(queued[0].pubkey, key_a);
    assert_eq!(queued[1].pubkey, key_b);
    assert_eq!(
        state.get_account(&key_a).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
    assert_eq!(
        state.get_account(&key_b).unwrap().status,
        ValidatorStatus::SubmittedExitRequest
    );
}
