#![no_main]

//! Property-based fuzz target for `WithdrawalQueue` operations.
//!
//! Runs an arbitrary sequence of push/pop/reschedule ops and asserts:
//!   - No panic.
//!   - `len()` == number of withdrawals actually stored.
//!   - Sum of `count_for_epoch(e)` over all `e` equals `len()`.
//!   - `next_index()` is non-decreasing across the whole sequence.
//!   - Encode → Decode → Encode produces byte-identical output (canonicalisation).

use arbitrary::Arbitrary;
use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::execution_request::WithdrawalRequest;
use summit_types::withdrawal::WithdrawalQueue;

/// Single clamp for every fuzz-driven u64 (amounts, balance deductions,
/// next_index).
///
/// `WithdrawalQueue::push_request` uses unchecked `+=` on `amount`,
/// `balance_deduction`, and `next_index`. In production these values are
/// bounded by validator balance and chain activity, so overflow is
/// unreachable — the fuzz target doesn't model those upstream bounds, so
/// we clamp the inputs here to reflect realistic decoded state.
///
/// 2^48 gwei is far above any realistic validator balance; 2^16 bits of
/// headroom is more ops than libFuzzer's default input size can encode.
const FUZZ_VALUE_MAX: u64 = (1u64 << 48) - 1;

#[derive(Arbitrary, Debug)]
enum Op {
    PushRequest {
        source_address: [u8; 20],
        validator_pubkey: [u8; 32],
        amount: u64,
        epoch: u64,
        balance_deduction: u64,
    },
    Pop {
        epoch: u64,
    },
    Reschedule {
        from_epoch: u64,
        to_epoch: u64,
    },
    SetNextIndex(u64),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut queue = WithdrawalQueue::default();
    let mut prev_next_index = queue.next_index();

    for op in ops {
        match op {
            Op::PushRequest {
                source_address,
                validator_pubkey,
                amount,
                epoch,
                balance_deduction,
            } => {
                let req = WithdrawalRequest {
                    source_address: source_address.into(),
                    validator_pubkey,
                    amount: amount & FUZZ_VALUE_MAX,
                };
                queue.push_request(req, epoch, balance_deduction & FUZZ_VALUE_MAX);
            }
            Op::Pop { epoch } => {
                let _ = queue.pop(epoch);
            }
            Op::Reschedule {
                from_epoch,
                to_epoch,
            } => {
                queue.reschedule_epoch(from_epoch, to_epoch);
            }
            Op::SetNextIndex(idx) => {
                let idx = idx & FUZZ_VALUE_MAX;
                queue.set_next_index(idx);
                // set_next_index may decrease; reset baseline so the monotonicity
                // invariant tracks organic growth from push_request.
                prev_next_index = idx;
                continue;
            }
        }

        // next_index must be non-decreasing across push/pop/reschedule.
        let cur = queue.next_index();
        assert!(
            cur >= prev_next_index,
            "next_index regressed from {prev_next_index} to {cur}",
        );
        prev_next_index = cur;
    }

    // len() matches the number of actual withdrawal entries.
    let via_iter = queue.withdrawals_iter().count();
    assert_eq!(
        queue.len(),
        via_iter,
        "len() ({}) mismatches withdrawals_iter().count() ({})",
        queue.len(),
        via_iter,
    );

    // Sum of per-epoch counts equals total length.
    let per_epoch_sum: usize = queue
        .epochs_with_withdrawals()
        .iter()
        .map(|e| queue.count_for_epoch(*e))
        .sum();
    assert_eq!(
        per_epoch_sum,
        queue.len(),
        "sum(count_for_epoch) ({}) mismatches len() ({})",
        per_epoch_sum,
        queue.len(),
    );

    // Canonical encoding roundtrip.
    let encoded = queue.encode();
    let mut buf: &[u8] = encoded.as_ref();
    let decoded = WithdrawalQueue::read(&mut buf)
        .expect("encoded WithdrawalQueue must decode back successfully");
    let re_encoded = decoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "WithdrawalQueue encode is not idempotent across a roundtrip",
    );
});
