use crate::execution_request::WithdrawalRequest;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, Write};
use std::collections::{BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalKind {
    Validator,
    DepositRefund,
}

impl WithdrawalKind {
    pub fn as_u8(self) -> u8 {
        match self {
            WithdrawalKind::Validator => 0,
            WithdrawalKind::DepositRefund => 1,
        }
    }
}

impl TryFrom<u8> for WithdrawalKind {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(WithdrawalKind::Validator),
            1 => Ok(WithdrawalKind::DepositRefund),
            _ => Err("invalid withdrawal kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalKindMismatch {
    pub existing: WithdrawalKind,
    pub requested: WithdrawalKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingWithdrawal {
    pub inner: Withdrawal,
    pub pubkey: [u8; 32],
    /// The epoch in which this withdrawal is scheduled to be processed.
    pub epoch: u64,
    pub kind: WithdrawalKind,
}

impl TryFrom<&[u8]> for PendingWithdrawal {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // PendingWithdrawal data is exactly 85 bytes
        // Format: index(8) + validator_index(8) + address(20) + amount(8) + pubkey(32) + epoch(8) + kind(1) = 85 bytes

        if bytes.len() != 85 {
            return Err("PendingWithdrawal must be exactly 85 bytes");
        }

        // Extract index (8 bytes, little-endian u64)
        let index_bytes: [u8; 8] = bytes[0..8]
            .try_into()
            .map_err(|_| "Failed to parse index")?;
        let index = u64::from_le_bytes(index_bytes);

        // Extract validator_index (8 bytes, little-endian u64)
        let validator_index_bytes: [u8; 8] = bytes[8..16]
            .try_into()
            .map_err(|_| "Failed to parse validator_index")?;
        let validator_index = u64::from_le_bytes(validator_index_bytes);

        // Extract address (20 bytes)
        let address_bytes: [u8; 20] = bytes[16..36]
            .try_into()
            .map_err(|_| "Failed to parse address")?;
        let address = Address::from(address_bytes);

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[36..44]
            .try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract pubkey (32 bytes)
        let pubkey: [u8; 32] = bytes[44..76]
            .try_into()
            .map_err(|_| "Failed to parse pubkey")?;

        // Extract epoch (8 bytes, little-endian u64)
        let epoch_bytes: [u8; 8] = bytes[76..84]
            .try_into()
            .map_err(|_| "Failed to parse epoch")?;
        let epoch = u64::from_le_bytes(epoch_bytes);
        let kind = WithdrawalKind::try_from(bytes[84]).map_err(|_| "Failed to parse kind")?;

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            pubkey,
            epoch,
            kind,
        })
    }
}

impl Write for PendingWithdrawal {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put(&self.inner.index.to_le_bytes()[..]);
        buf.put(&self.inner.validator_index.to_le_bytes()[..]);
        buf.put(&self.inner.address.0[..]);
        buf.put(&self.inner.amount.to_le_bytes()[..]);
        buf.put(&self.pubkey[..]);
        buf.put(&self.epoch.to_le_bytes()[..]);
        buf.put_u8(self.kind.as_u8());
    }
}

impl FixedSize for PendingWithdrawal {
    const SIZE: usize = 85; // 8 + 8 + 20 + 8 + 32 + 8 + 1
}

impl Read for PendingWithdrawal {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 85 {
            return Err(Error::Invalid("PendingWithdrawal", "Insufficient bytes"));
        }

        let mut index_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut index_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let index = u64::from_le_bytes(index_bytes);

        let mut validator_index_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut validator_index_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let validator_index = u64::from_le_bytes(validator_index_bytes);

        let mut address_bytes = [0u8; 20];
        buf.try_copy_to_slice(&mut address_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let address = Address::from(address_bytes);

        let mut amount_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut amount_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let amount = u64::from_le_bytes(amount_bytes);

        let mut pubkey = [0u8; 32];
        buf.try_copy_to_slice(&mut pubkey)
            .map_err(|_| Error::EndOfBuffer)?;

        let mut epoch_bytes = [0u8; 8];
        buf.try_copy_to_slice(&mut epoch_bytes)
            .map_err(|_| Error::EndOfBuffer)?;
        let epoch = u64::from_le_bytes(epoch_bytes);
        let kind = WithdrawalKind::try_from(buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?)
            .map_err(|_| Error::Invalid("PendingWithdrawal", "Invalid withdrawal kind"))?;

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            pubkey,
            epoch,
            kind,
        })
    }
}

/// Encapsulates withdrawal data and scheduling.
///
/// Two flat queues in processing order: validator-initiated/stake-bound
/// withdrawals and deposit refunds. Each `PendingWithdrawal` carries its own
/// earliest-processable `epoch`; the per-epoch cap drains from the front, so the
/// queues are expected to stay ordered by that epoch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WithdrawalQueue {
    /// Validator-initiated / stake-bound withdrawals, in processing order.
    withdrawals: VecDeque<PendingWithdrawal>,
    /// Deposit refunds, in processing order.
    refunds: VecDeque<PendingWithdrawal>,
    /// The next withdrawal index to assign.
    next_index: u64,
}

impl WithdrawalQueue {
    pub fn push_withdrawal(&mut self, epoch: u64, request: WithdrawalRequest) {
        let index = self.next_index;
        self.next_index += 1;
        let pending = PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: 0,
                address: request.source_address,
                amount: request.amount,
            },
            pubkey: request.validator_pubkey,
            epoch,
            kind: WithdrawalKind::Validator,
        };
        self.withdrawals.push_back(pending);
    }

    /// Peek at the next validator withdrawal without removing it, returning it only
    /// if it is due (its earliest-processable `epoch <= current_epoch`). Since the
    /// queue is epoch-ordered, a not-due front means nothing is due.
    pub fn peek_withdrawal(&self, current_epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawals
            .front()
            .filter(|w| w.epoch <= current_epoch)
    }

    fn deque(&self, kind: WithdrawalKind) -> &VecDeque<PendingWithdrawal> {
        match kind {
            WithdrawalKind::Validator => &self.withdrawals,
            WithdrawalKind::DepositRefund => &self.refunds,
        }
    }

    fn deque_mut(&mut self, kind: WithdrawalKind) -> &mut VecDeque<PendingWithdrawal> {
        match kind {
            WithdrawalKind::Validator => &mut self.withdrawals,
            WithdrawalKind::DepositRefund => &mut self.refunds,
        }
    }

    /// Append a validator withdrawal request to the end of the queue.
    pub fn push_request(&mut self, request: WithdrawalRequest, epoch: u64) {
        self.push_request_with_kind(request, epoch, WithdrawalKind::Validator)
            .expect("validator withdrawal kind must match queue");
    }

    /// Append a withdrawal request of the given kind to the end of the corresponding
    /// queue. Entries are never merged — each request is a distinct queue entry.
    ///
    /// Returns `Ok(false)` (the historical "merged?" flag, now always false). The
    /// `Result` is retained for call-site compatibility.
    pub fn push_request_with_kind(
        &mut self,
        request: WithdrawalRequest,
        epoch: u64,
        kind: WithdrawalKind,
    ) -> Result<bool, WithdrawalKindMismatch> {
        let index = self.next_index;
        self.next_index += 1;
        let pending = PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: 0,
                address: request.source_address,
                amount: request.amount,
            },
            pubkey: request.validator_pubkey,
            epoch,
            kind,
        };
        self.deque_mut(kind).push_back(pending);
        Ok(false)
    }

    /// Push a pre-built withdrawal directly (for test setup and deserialization).
    pub fn push(&mut self, withdrawal: PendingWithdrawal) {
        self.deque_mut(withdrawal.kind).push_back(withdrawal);
    }

    /// The most recently appended entry of the given kind, if any.
    pub fn back(&self, kind: WithdrawalKind) -> Option<&PendingWithdrawal> {
        self.deque(kind).back()
    }

    /// Iterate the full combined sequence `[validator withdrawals ++ deposit
    /// refunds]` in queue order. This is the order committed to the SSZ tree.
    pub fn iter_all(&self) -> impl Iterator<Item = &PendingWithdrawal> {
        self.withdrawals.iter().chain(self.refunds.iter())
    }

    fn pop_kind(&mut self, epoch: u64, kind: WithdrawalKind) -> Option<PendingWithdrawal> {
        // Pop the front only if it is due (its earliest-processable epoch has arrived).
        if self.deque(kind).front().is_some_and(|w| w.epoch <= epoch) {
            self.deque_mut(kind).pop_front()
        } else {
            None
        }
    }

    /// Pop the next due withdrawal for the given epoch, prioritizing validator withdrawals.
    pub fn pop(&mut self, epoch: u64) -> Option<PendingWithdrawal> {
        self.pop_kind(epoch, WithdrawalKind::Validator)
            .or_else(|| self.pop_kind(epoch, WithdrawalKind::DepositRefund))
    }

    /// Remove and return the withdrawal with the given index, which must be at the
    /// front of one of the two queues (validator queue first).
    ///
    /// This is the commit-time reconciliation path: the EL block replays the
    /// withdrawals it was given in emission order, and emission only ever takes a
    /// front-prefix of each queue (pushes go to the back, the only removals are
    /// these front pops). So the matched entry is always a current front entry —
    /// no scan is needed, and `index` doubles as an integrity check.
    pub fn pop_by_index(&mut self, _epoch: u64, index: u64) -> Option<PendingWithdrawal> {
        if self
            .withdrawals
            .front()
            .is_some_and(|w| w.inner.index == index)
        {
            return self.withdrawals.pop_front();
        }
        if self.refunds.front().is_some_and(|w| w.inner.index == index) {
            return self.refunds.pop_front();
        }
        None
    }

    /// Peek at the next due withdrawal for the given epoch (validator priority).
    pub fn peek(&self, epoch: u64) -> Option<&PendingWithdrawal> {
        self.withdrawals
            .front()
            .filter(|w| w.epoch <= epoch)
            .or_else(|| self.refunds.front().filter(|w| w.epoch <= epoch))
    }

    /// All due withdrawals of the given kind for `epoch` (earliest-epoch `<= epoch`),
    /// in queue order.
    pub fn get_for_epoch_by_kind(
        &self,
        epoch: u64,
        kind: WithdrawalKind,
    ) -> Vec<&PendingWithdrawal> {
        self.deque(kind)
            .iter()
            .filter(|w| w.epoch <= epoch)
            .collect()
    }

    /// Get all pending withdrawals for a specific epoch.
    pub fn get_for_epoch(&self, epoch: u64) -> Vec<&PendingWithdrawal> {
        let mut withdrawals = self.get_for_epoch_by_kind(epoch, WithdrawalKind::Validator);
        withdrawals.extend(self.get_for_epoch_by_kind(epoch, WithdrawalKind::DepositRefund));
        withdrawals
    }

    /// Select up to `max_total` withdrawals for the epoch under a single total
    /// cap, with validator exits taking strict priority over deposit refunds:
    /// validator exits fill the budget first, then refunds use only the
    /// remaining capacity. This keeps one per-epoch terminal-block bound while
    /// guaranteeing refunds can never displace validator exits (the #226
    /// starvation guard). Refunds that do not fit roll to a later epoch.
    pub fn get_for_epoch_with_total_cap(
        &self,
        epoch: u64,
        max_total: usize,
    ) -> Vec<&PendingWithdrawal> {
        // The deques are epoch-ordered (non-decreasing), so the due entries
        // (`epoch <= epoch`) form a contiguous front prefix. `take_while` stops at
        // the first not-due entry instead of scanning the whole deque, and `take`
        // caps the result — so the work stays bounded by min(cap, due-prefix) even
        // when a far larger future backlog is queued behind it (#362).
        let mut withdrawals: Vec<_> = self
            .withdrawals
            .iter()
            .take_while(|w| w.epoch <= epoch)
            .take(max_total)
            .collect();
        let remaining = max_total - withdrawals.len();
        withdrawals.extend(
            self.refunds
                .iter()
                .take_while(|w| w.epoch <= epoch)
                .take(remaining),
        );
        withdrawals
    }

    /// Number of due withdrawals for `epoch` (earliest-epoch `<= epoch`).
    pub fn count_for_epoch(&self, epoch: u64) -> usize {
        self.withdrawals.iter().filter(|w| w.epoch <= epoch).count()
            + self.refunds.iter().filter(|w| w.epoch <= epoch).count()
    }

    /// Get all epochs that have pending withdrawals.
    pub fn epochs_with_withdrawals(&self) -> Vec<u64> {
        self.withdrawals
            .iter()
            .chain(self.refunds.iter())
            .map(|w| w.epoch)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Get the next withdrawal index.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Set the next withdrawal index.
    pub fn set_next_index(&mut self, index: u64) {
        self.next_index = index;
    }

    /// Total number of pending withdrawals (validator exits + refunds).
    pub fn len(&self) -> usize {
        self.withdrawals.len() + self.refunds.len()
    }

    /// Whether there are any pending withdrawals.
    pub fn is_empty(&self) -> bool {
        self.withdrawals.is_empty() && self.refunds.is_empty()
    }

    /// Number of epochs with scheduled withdrawals.
    pub fn num_epochs(&self) -> usize {
        self.epochs_with_withdrawals().len()
    }

    /// Get the first pending withdrawal for a validator pubkey, validator queue
    /// first. Entries are not deduplicated by pubkey, so a pubkey may have several
    /// pending entries; this returns the earliest-queued one.
    pub fn get_withdrawal(&self, pubkey: &[u8; 32]) -> Option<&PendingWithdrawal> {
        self.withdrawals
            .iter()
            .chain(self.refunds.iter())
            .find(|w| &w.pubkey == pubkey)
    }
}

/// Serialized size of one flat withdrawal deque.
fn flat_encode_size(deque: &VecDeque<PendingWithdrawal>) -> usize {
    4 // count
    + deque.len() * PendingWithdrawal::SIZE
}

/// Write one flat deque: count, then each full withdrawal in queue order.
fn write_flat(deque: &VecDeque<PendingWithdrawal>, buf: &mut impl BufMut) {
    buf.put_u32(deque.len() as u32);
    for withdrawal in deque {
        withdrawal.write(buf);
    }
}

/// Read one flat deque written by [`write_flat`], validating that every item's
/// `kind` matches the queue and that indexes are globally unique and below
/// `next_index` (shared `indexes` set across both deques).
fn read_flat(
    buf: &mut impl Buf,
    kind: WithdrawalKind,
    next_index: u64,
    indexes: &mut BTreeSet<u64>,
) -> Result<VecDeque<PendingWithdrawal>, Error> {
    let count = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
    // Bound preallocation by the bytes actually remaining so a crafted count
    // cannot force a huge upfront allocation.
    let mut deque =
        VecDeque::with_capacity(count.min(buf.remaining() / PendingWithdrawal::SIZE + 1));
    let mut prev_epoch = 0u64;
    for _ in 0..count {
        let withdrawal = PendingWithdrawal::read_cfg(buf, &())?;
        if withdrawal.kind != kind {
            return Err(Error::Invalid(
                "WithdrawalQueue",
                "withdrawal kind does not match queue",
            ));
        }
        if withdrawal.inner.index >= next_index {
            return Err(Error::Invalid(
                "WithdrawalQueue",
                "next_index must exceed pending withdrawal indexes",
            ));
        }
        if !indexes.insert(withdrawal.inner.index) {
            return Err(Error::Invalid(
                "WithdrawalQueue",
                "duplicate withdrawal index",
            ));
        }
        // The queue is drained from the front under the per-epoch cap, so it must
        // stay ordered by earliest-processable `epoch`. Every runtime enqueue uses
        // `current_epoch + validator_withdrawal_num_epochs` (a fixed genesis
        // constant, not a runtime-changeable param) with a monotonic
        // `current_epoch`, so a legitimately serialized deque is non-decreasing by
        // `epoch`; an out-of-order one is a tampered/corrupt artifact and is
        // rejected here.
        if withdrawal.epoch < prev_epoch {
            return Err(Error::Invalid(
                "WithdrawalQueue",
                "withdrawal epochs must be non-decreasing",
            ));
        }
        prev_epoch = withdrawal.epoch;
        deque.push_back(withdrawal);
    }
    Ok(deque)
}

impl EncodeSize for WithdrawalQueue {
    fn encode_size(&self) -> usize {
        8 // next_index
        + flat_encode_size(&self.withdrawals)
        + flat_encode_size(&self.refunds)
    }
}

impl Write for WithdrawalQueue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.next_index);
        write_flat(&self.withdrawals, buf);
        write_flat(&self.refunds, buf);
    }
}

impl Read for WithdrawalQueue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let next_index = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
        // Reject an already-exhausted counter so a subsequent push_request
        // cannot wrap next_index.
        if next_index == u64::MAX {
            return Err(Error::Invalid(
                "WithdrawalQueue",
                "next_index exhausted u64 space",
            ));
        }

        // Indexes are unique across the whole queue (validator + refund), so the
        // set is shared between both deques.
        let mut indexes = BTreeSet::new();
        let withdrawals = read_flat(buf, WithdrawalKind::Validator, next_index, &mut indexes)?;
        let refunds = read_flat(buf, WithdrawalKind::DepositRefund, next_index, &mut indexes)?;

        Ok(Self {
            withdrawals,
            refunds,
            next_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{ReadExt, Write};

    #[test]
    fn test_pending_withdrawal_codec() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 42u64,
                validator_index: 1337u64,
                address: Address::from([1u8; 20]),
                amount: 16000000000u64, // 16 ETH in gwei
            },
            pubkey: [42u8; 32],
            epoch: 5,
            kind: WithdrawalKind::Validator,
        };

        // Test Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), 85); // 8 + 8 + 20 + 8 + 32 + 8 + 1

        // Test Read
        let decoded = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    fn pw(tag: u8, epoch: u64, index: u64, kind: WithdrawalKind) -> PendingWithdrawal {
        PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index: 0,
                address: Address::from([tag; 20]),
                amount: 1,
            },
            pubkey: [tag; 32],
            epoch,
            kind,
        }
    }

    /// Encode the flat wire format directly from explicit deques, for decode tests
    /// that need to construct malformed input.
    fn encode_flat(
        next_index: u64,
        validators: &[PendingWithdrawal],
        refunds: &[PendingWithdrawal],
    ) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u64(next_index);
        buf.put_u32(validators.len() as u32);
        for w in validators {
            w.write(&mut buf);
        }
        buf.put_u32(refunds.len() as u32);
        for w in refunds {
            w.write(&mut buf);
        }
        buf
    }

    #[test]
    fn test_pending_withdrawal_try_from() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 123u64,
                validator_index: 456u64,
                address: Address::from([2u8; 20]),
                amount: 32000000000u64, // 32 ETH in gwei
            },
            pubkey: [2u8; 32],
            epoch: 10,
            kind: WithdrawalKind::DepositRefund,
        };

        // Encode with Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        // Test TryFrom
        let decoded = PendingWithdrawal::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    #[test]
    fn test_pending_withdrawal_insufficient_bytes() {
        let mut buf = BytesMut::new();
        buf.put(&[0u8; 84][..]); // One byte short

        let result = PendingWithdrawal::read(&mut buf.as_ref());
        assert!(result.is_err());
        if let Err(Error::Invalid(type_name, msg)) = result {
            assert_eq!(type_name, "PendingWithdrawal");
            assert_eq!(msg, "Insufficient bytes");
        } else {
            panic!("Expected Invalid error");
        }
    }

    #[test]
    fn test_pending_withdrawal_try_from_insufficient_bytes() {
        let buf = [0u8; 84]; // One byte short
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 85 bytes"
        );
    }

    #[test]
    fn test_pending_withdrawal_try_from_too_many_bytes() {
        let buf = [0u8; 86]; // One byte too many
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 85 bytes"
        );
    }

    #[test]
    fn test_pending_withdrawal_roundtrip_compatibility() {
        // Test that our Codec implementation is compatible with TryFrom<&[u8]>
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 999u64,
                validator_index: 777u64,
                address: Address::from([3u8; 20]),
                amount: 64000000000u64, // 64 ETH in gwei
            },
            pubkey: [3u8; 32],
            epoch: 42,
            kind: WithdrawalKind::Validator,
        };

        // Encode with Codec
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        // Decode with TryFrom
        let decoded_try_from = PendingWithdrawal::try_from(buf.as_ref()).unwrap();
        assert_eq!(decoded_try_from, withdrawal);

        // Decode with Codec
        let decoded_codec = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded_codec, withdrawal);
        assert_eq!(decoded_try_from, decoded_codec);
    }

    #[test]
    fn test_pending_withdrawal_fixed_size() {
        assert_eq!(PendingWithdrawal::SIZE, 85);

        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::ZERO,
                amount: 0,
            },
            pubkey: [0u8; 32],
            epoch: 0,
            kind: WithdrawalKind::Validator,
        };

        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), PendingWithdrawal::SIZE);
    }

    #[test]
    fn test_pending_withdrawal_field_ordering() {
        // Test that fields are encoded/decoded in the correct order
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0x0123456789abcdefu64,
                validator_index: 0xfedcba9876543210u64,
                address: Address::from([
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                    0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
                ]),
                amount: 0xa1b2c3d4e5f60708u64,
            },
            pubkey: [5u8; 32],
            epoch: 0x1122334455667788u64,
            kind: WithdrawalKind::DepositRefund,
        };

        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);

        let bytes = buf.as_ref();

        // Check index (first 8 bytes, little-endian)
        assert_eq!(&bytes[0..8], &0x0123456789abcdefu64.to_le_bytes());

        // Check validator_index (next 8 bytes, little-endian)
        assert_eq!(&bytes[8..16], &0xfedcba9876543210u64.to_le_bytes());

        // Check address (next 20 bytes)
        assert_eq!(
            &bytes[16..36],
            &[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x01, 0x02, 0x03, 0x04
            ]
        );

        // Check amount (next 8 bytes, little-endian)
        assert_eq!(&bytes[36..44], &0xa1b2c3d4e5f60708u64.to_le_bytes());

        // Check pubkey (next 32 bytes)
        assert_eq!(&bytes[44..76], &[5u8; 32]);

        // Check epoch (next 8 bytes, little-endian)
        assert_eq!(&bytes[76..84], &0x1122334455667788u64.to_le_bytes());

        // Check kind (last byte)
        assert_eq!(bytes[84], WithdrawalKind::DepositRefund.as_u8());

        // Verify roundtrip
        let decoded = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
    }

    fn make_request(pubkey: [u8; 32], amount: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: pubkey,
            amount,
        }
    }

    #[test]
    fn test_queue_push_pop_basic() {
        let mut queue = WithdrawalQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        let req = make_request([1u8; 32], 100);
        queue.push_request(req, 5);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.num_epochs(), 1);
        assert_eq!(queue.next_index(), 1);

        let w = queue.pop(5).unwrap();
        assert_eq!(w.inner.amount, 100);
        assert_eq!(w.inner.index, 0);
        assert_eq!(w.pubkey, [1u8; 32]);
        assert_eq!(w.epoch, 5);

        assert!(queue.is_empty());
        assert_eq!(queue.num_epochs(), 0);
    }

    #[test]
    fn test_queue_peek() {
        let mut queue = WithdrawalQueue::default();
        assert!(queue.peek(5).is_none());

        let req = make_request([1u8; 32], 100);
        queue.push_request(req, 5);

        let w = queue.peek(5).unwrap();
        assert_eq!(w.inner.amount, 100);
        // peek doesn't remove
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_pop_respects_due_epoch() {
        let mut queue = WithdrawalQueue::default();
        let req = make_request([1u8; 32], 100);
        queue.push_request(req, 5);

        // Not due before the scheduled (earliest) epoch.
        assert!(queue.pop(4).is_none());
        assert_eq!(queue.len(), 1);
        // Due once the current epoch reaches/passes the scheduled epoch.
        assert!(queue.pop(6).is_some());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_multiple_validators_same_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5);
        queue.push_request(make_request([2u8; 32], 200), 5);
        queue.push_request(make_request([3u8; 32], 300), 5);

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.count_for_epoch(5), 3);
        assert_eq!(queue.num_epochs(), 1);

        // Pop in FIFO order
        assert_eq!(queue.pop(5).unwrap().inner.amount, 100);
        assert_eq!(queue.pop(5).unwrap().inner.amount, 200);
        assert_eq!(queue.pop(5).unwrap().inner.amount, 300);
        assert!(queue.pop(5).is_none());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_multiple_epochs() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5);
        queue.push_request(make_request([2u8; 32], 200), 7);

        assert_eq!(queue.num_epochs(), 2);
        let mut epochs = queue.epochs_with_withdrawals();
        epochs.sort();
        assert_eq!(epochs, vec![5, 7]);

        // count_for_epoch(e) counts entries DUE at e (earliest epoch <= e).
        assert_eq!(queue.count_for_epoch(5), 1); // only the epoch-5 entry is due
        assert_eq!(queue.count_for_epoch(7), 2); // both are due by epoch 7
        assert_eq!(queue.count_for_epoch(4), 0); // nothing due before epoch 5
    }

    #[test]
    fn test_queue_get_for_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5);
        queue.push_request(make_request([2u8; 32], 200), 5);
        queue.push_request(make_request([3u8; 32], 300), 7);

        // get_for_epoch(e) returns entries DUE at e (earliest epoch <= e), in order.
        let due5 = queue.get_for_epoch(5);
        assert_eq!(due5.len(), 2);
        assert_eq!(due5[0].inner.amount, 100);
        assert_eq!(due5[1].inner.amount, 200);

        // By epoch 7 all three are due, in queue order.
        let due7 = queue.get_for_epoch(7);
        assert_eq!(due7.len(), 3);
        assert_eq!(due7[2].inner.amount, 300);

        // Nothing is due before epoch 5.
        assert!(queue.get_for_epoch(4).is_empty());
    }

    #[test]
    fn test_queue_uses_separate_schedules_with_validator_priority() {
        let mut queue = WithdrawalQueue::default();

        queue
            .push_request_with_kind(
                make_request([0xFE; 32], 10),
                5,
                WithdrawalKind::DepositRefund,
            )
            .unwrap();
        queue.push_request(make_request([1u8; 32], 50), 5);

        let epoch5 = queue.get_for_epoch(5);
        assert_eq!(epoch5.len(), 2);
        assert_eq!(epoch5[0].kind, WithdrawalKind::Validator);
        assert_eq!(epoch5[0].pubkey, [1u8; 32]);
        assert_eq!(epoch5[1].kind, WithdrawalKind::DepositRefund);
        assert_eq!(epoch5[1].pubkey, [0xFE; 32]);

        // Total cap with validator priority: a cap of 1, with both a validator
        // exit and a refund pending, must yield the validator exit only — the
        // refund is displaced, not given its own slot.
        let capped = queue.get_for_epoch_with_total_cap(5, 1);
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].kind, WithdrawalKind::Validator);

        // A cap of 0 yields nothing.
        assert!(queue.get_for_epoch_with_total_cap(5, 0).is_empty());

        // A cap that admits both keeps validator-first ordering.
        let both = queue.get_for_epoch_with_total_cap(5, 2);
        assert_eq!(both.len(), 2);
        assert_eq!(both[0].kind, WithdrawalKind::Validator);
        assert_eq!(both[1].kind, WithdrawalKind::DepositRefund);
    }

    #[test]
    fn test_queue_next_index_increments() {
        let mut queue = WithdrawalQueue::default();
        assert_eq!(queue.next_index(), 0);

        queue.push_request(make_request([1u8; 32], 100), 5);
        assert_eq!(queue.next_index(), 1);

        queue.push_request(make_request([2u8; 32], 200), 5);
        assert_eq!(queue.next_index(), 2);

        // Every request is a distinct entry (no merge), so each increments the index —
        // even a repeat of the same pubkey.
        queue.push_request(make_request([1u8; 32], 50), 5);
        assert_eq!(queue.next_index(), 3);
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_queue_set_next_index() {
        let mut queue = WithdrawalQueue::default();
        queue.set_next_index(42);
        assert_eq!(queue.next_index(), 42);

        queue.push_request(make_request([1u8; 32], 100), 5);
        assert_eq!(queue.next_index(), 43);
    }

    #[test]
    fn test_read_rejects_exhausted_next_index() {
        // A decoded state with next_index == u64::MAX would overflow on the
        // first push_request. Reject it at the parse boundary.
        let mut buf = BytesMut::new();
        buf.put_u64(u64::MAX); // next_index
        buf.put_u32(0); // withdrawals_len
        buf.put_u32(0); // schedule_len
        let err = WithdrawalQueue::read(&mut buf.as_ref())
            .expect_err("read must reject next_index == u64::MAX");
        assert!(matches!(err, Error::Invalid("WithdrawalQueue", _)));
    }

    #[test]
    fn test_read_rejects_wrong_kind_in_queue() {
        // A DepositRefund-kind entry in the validator queue must be rejected.
        let buf = encode_flat(1, &[pw(1, 5, 0, WithdrawalKind::DepositRefund)], &[]);
        let err = WithdrawalQueue::read(&mut buf.as_ref())
            .expect_err("read must reject a withdrawal whose kind does not match its queue");
        assert!(matches!(err, Error::Invalid("WithdrawalQueue", _)));
    }

    #[test]
    fn test_read_rejects_duplicate_index_across_queues() {
        // Index 0 reused across the validator and refund queues.
        let buf = encode_flat(
            1,
            &[pw(1, 5, 0, WithdrawalKind::Validator)],
            &[pw(2, 5, 0, WithdrawalKind::DepositRefund)],
        );
        let err = WithdrawalQueue::read(&mut buf.as_ref())
            .expect_err("read must reject duplicate withdrawal indexes");
        assert!(matches!(err, Error::Invalid("WithdrawalQueue", _)));
    }

    #[test]
    fn test_read_rejects_index_at_or_above_next_index() {
        // index == next_index is out of range (next_index must exceed all indexes).
        let buf = encode_flat(1, &[pw(1, 5, 1, WithdrawalKind::Validator)], &[]);
        let err = WithdrawalQueue::read(&mut buf.as_ref())
            .expect_err("read must reject an index >= next_index");
        assert!(matches!(err, Error::Invalid("WithdrawalQueue", _)));
    }

    #[test]
    fn test_read_rejects_decreasing_epoch() {
        // The deque is drained from the front under the per-epoch cap, so it must
        // stay ordered by earliest-processable epoch. A later entry with a smaller
        // epoch is a tampered/corrupt artifact and must be rejected at decode.
        let buf = encode_flat(
            2,
            &[
                pw(1, 5, 0, WithdrawalKind::Validator),
                pw(2, 3, 1, WithdrawalKind::Validator),
            ],
            &[],
        );
        let err = WithdrawalQueue::read(&mut buf.as_ref())
            .expect_err("read must reject a queue whose epochs decrease");
        assert!(matches!(err, Error::Invalid("WithdrawalQueue", _)));
    }

    #[test]
    fn test_read_accepts_non_decreasing_epoch() {
        // Equal and increasing epochs are the legitimate order every runtime
        // enqueue produces (current_epoch + a fixed delay), so they must decode.
        let buf = encode_flat(
            3,
            &[
                pw(1, 3, 0, WithdrawalKind::Validator),
                pw(2, 3, 1, WithdrawalKind::Validator),
                pw(3, 7, 2, WithdrawalKind::Validator),
            ],
            &[],
        );
        WithdrawalQueue::read(&mut buf.as_ref()).expect("non-decreasing epochs must decode");
    }

    #[test]
    fn test_read_accepts_valid_flat_queue_with_refunds() {
        // A consistent queue with both kinds round-trips and preserves order.
        let buf = encode_flat(
            3,
            &[
                pw(1, 5, 0, WithdrawalKind::Validator),
                pw(2, 6, 1, WithdrawalKind::Validator),
            ],
            &[pw(3, 5, 2, WithdrawalKind::DepositRefund)],
        );
        let decoded = WithdrawalQueue::read(&mut buf.as_ref()).expect("valid queue must decode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(
            decoded.back(WithdrawalKind::Validator).unwrap().pubkey,
            [2u8; 32]
        );
        assert_eq!(
            decoded.back(WithdrawalKind::DepositRefund).unwrap().pubkey,
            [3u8; 32]
        );
    }

    #[test]
    fn test_queue_serialization_roundtrip_empty() {
        let queue = WithdrawalQueue::default();

        let mut buf = BytesMut::new();
        queue.write(&mut buf);
        assert_eq!(buf.len(), queue.encode_size());

        let decoded = WithdrawalQueue::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, queue);
    }

    #[test]
    fn test_queue_serialization_roundtrip_populated() {
        let mut queue = WithdrawalQueue::default();
        queue.set_next_index(10);
        queue.push_request(make_request([1u8; 32], 100), 5);
        queue.push_request(make_request([2u8; 32], 200), 5);
        queue.push_request(make_request([3u8; 32], 300), 7);

        let mut buf = BytesMut::new();
        queue.write(&mut buf);
        assert_eq!(buf.len(), queue.encode_size());

        let decoded = WithdrawalQueue::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, queue);
        assert_eq!(decoded.next_index(), 13);
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.num_epochs(), 2);
    }

    #[test]
    fn test_queue_push_raw() {
        let mut queue = WithdrawalQueue::default();

        let pending = PendingWithdrawal {
            inner: Withdrawal {
                index: 42,
                validator_index: 0,
                address: Address::from([1u8; 20]),
                amount: 100,
            },
            pubkey: [1u8; 32],
            epoch: 5,
            kind: WithdrawalKind::Validator,
        };
        queue.push(pending.clone());

        assert_eq!(queue.len(), 1);
        let w = queue.pop(5).unwrap();
        assert_eq!(w, pending);
    }

    #[test]
    fn test_queue_pop_cleans_up_empty_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5);

        assert_eq!(queue.num_epochs(), 1);
        queue.pop(5);
        assert_eq!(queue.num_epochs(), 0);
        assert!(queue.epochs_with_withdrawals().is_empty());
    }
}
