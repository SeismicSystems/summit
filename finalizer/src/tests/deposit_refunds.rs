//! Deposit-refund queue behavior.
//!
//! The per-epoch withdrawal cap bounds only how many withdrawals are
//! emitted in a block, not the size of the ready backlog the finalizer must
//! inspect and roll over at every epoch boundary. Refunds for rejected deposits
//! are keyed by `(reason, withdrawal_address)` (not by deposit index) so that
//! many rejected deposits to the same address collapse onto a single pending
//! entry, bounding the backlog by distinct addresses rather than by deposits.

use crate::actor::{DepositRejectionReason, queue_deposit_refund};
use crate::config::ProtocolConsts;
use summit_types::consensus_state::ConsensusState;

const CONSTS: ProtocolConsts = ProtocolConsts {
    validator_num_warm_up_epochs: 2,
    validator_withdrawal_num_epochs: 2,
};

/// Build valid Eth1 withdrawal credentials (0x01 + 11 zero bytes + 20-byte
/// address) so `parse_withdrawal_credentials` succeeds.
fn credentials(addr_byte: u8) -> [u8; 32] {
    let mut creds = [0u8; 32];
    creds[0] = 0x01;
    creds[12..32].copy_from_slice(&[addr_byte; 20]);
    creds
}

/// Many rejected deposits to the same withdrawal address must collapse onto a
/// single pending refund entry (amounts summed), so the ready backlog is bounded
/// by distinct addresses rather than by the number of deposits.
#[test]
fn many_invalid_deposits_to_one_address_collapse_to_one_entry() {
    let mut state = ConsensusState::default();
    let refund_epoch = state.get_epoch() + CONSTS.validator_withdrawal_num_epochs;

    // 50 distinct deposit indices, same address, same rejection reason.
    const N: u64 = 50;
    const AMOUNT: u64 = 1_000;
    for deposit_index in 0..N {
        queue_deposit_refund(
            &mut state,
            credentials(0xAB),
            AMOUNT,
            deposit_index,
            DepositRejectionReason::InvalidSignature,
            &CONSTS,
        );
    }

    let refunds = state.get_withdrawals_for_epoch(refund_epoch);
    assert_eq!(
        refunds.len(),
        1,
        "all same-address refunds should collapse to a single entry"
    );
    assert_eq!(
        refunds[0].inner.amount,
        AMOUNT * N,
        "the collapsed entry should owe the summed amount"
    );
    assert_eq!(
        state.get_withdrawal_count_for_epoch(refund_epoch),
        1,
        "the ready backlog is bounded by distinct addresses, not deposits"
    );
    // Only one withdrawal index is consumed despite N deposits.
    assert_eq!(state.get_next_withdrawal_index(), 1);

    // The incremental in-place merge must leave the SSZ tree identical to a full
    // rebuild from the queue.
    let incremental_root = state.ssz_tree().root();
    state.rebuild_ssz_tree();
    assert_eq!(
        incremental_root,
        state.ssz_tree().root(),
        "incremental merge root should match a full rebuild"
    );
}

/// Distinct addresses (and distinct rejection reasons) remain separate entries —
/// collapse must not over-merge unrelated obligations.
#[test]
fn distinct_addresses_and_reasons_stay_separate() {
    let mut state = ConsensusState::default();
    let refund_epoch = state.get_epoch() + CONSTS.validator_withdrawal_num_epochs;

    // Two distinct addresses.
    queue_deposit_refund(
        &mut state,
        credentials(0x01),
        500,
        0,
        DepositRejectionReason::InvalidSignature,
        &CONSTS,
    );
    queue_deposit_refund(
        &mut state,
        credentials(0x02),
        500,
        1,
        DepositRejectionReason::InvalidSignature,
        &CONSTS,
    );
    // Same address as the first, but a different rejection reason → different
    // domain tag → separate entry.
    queue_deposit_refund(
        &mut state,
        credentials(0x01),
        500,
        2,
        DepositRejectionReason::Refund,
        &CONSTS,
    );

    assert_eq!(
        state.get_withdrawal_count_for_epoch(refund_epoch),
        3,
        "distinct (address, reason) pairs must not merge"
    );
}
