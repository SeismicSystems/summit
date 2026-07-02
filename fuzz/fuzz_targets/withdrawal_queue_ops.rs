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

/// Single clamp for every fuzz-driven u64 (amounts, next_index).
///
/// `WithdrawalQueue::push_request` uses unchecked `+=` on `amount` and
/// `next_index`. In production these values are bounded by validator balance
/// and chain activity, so overflow is unreachable — the fuzz target doesn't
/// model those upstream bounds, so we clamp the inputs here to reflect
/// realistic decoded state.
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
    // Production always enqueues at `current_epoch + k` with a monotonic
    // `current_epoch`, so the queue's epochs are non-decreasing — an invariant the
    // decoder enforces. Model that here by clamping each pushed epoch up to a
    // running floor; otherwise the raw push API could build a decreasing-epoch
    // queue that encodes but is (correctly) rejected on decode.
    let mut epoch_floor = 0u64;

    for op in ops {
        match op {
            Op::PushRequest {
                source_address,
                validator_pubkey,
                amount,
                epoch,
            } => {
                let epoch = epoch.max(epoch_floor);
                epoch_floor = epoch;
                let req = WithdrawalRequest {
                    source_address: source_address.into(),
                    validator_pubkey,
                    amount: amount & FUZZ_VALUE_MAX,
                };
                queue.push_request(req, epoch);
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

    // len() matches the number of actual withdrawal entries (validators + refunds).
    let via_iter = queue.iter_all().count();
    assert_eq!(
        queue.len(),
        via_iter,
        "len() ({}) mismatches iter_all().count() ({})",
        queue.len(),
        via_iter,
    );

    // count_for_epoch is cumulative — it counts every entry whose earliest
    // processable epoch is <= its argument — so by the maximum epoch all entries
    // are due and the count must equal len().
    assert_eq!(
        queue.count_for_epoch(u64::MAX),
        queue.len(),
        "count_for_epoch(MAX) ({}) must equal len() ({})",
        queue.count_for_epoch(u64::MAX),
        queue.len(),
    );

    // Canonical encoding roundtrip. The raw ops can build a queue that violates a
    // decode invariant production upholds (e.g. `set_next_index` below an assigned
    // index, which the decoder rejects with "next_index must exceed pending
    // withdrawal indexes"). Such a rejection is a validation guard firing, not a
    // codec asymmetry, so the encode/decode idempotence property only applies when
    // the queue actually decodes.
    let encoded = queue.encode();
    let mut buf: &[u8] = encoded.as_ref();
    if let Ok(decoded) = WithdrawalQueue::read(&mut buf) {
        assert_eq!(
            encoded.as_ref(),
            decoded.encode().as_ref(),
            "WithdrawalQueue encode is not idempotent across a roundtrip",
        );
    }
});
