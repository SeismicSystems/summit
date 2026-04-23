use crate::execution_request::WithdrawalRequest;
use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::Address;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, Write};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq)]
pub struct PendingWithdrawal {
    pub inner: Withdrawal,
    pub pubkey: [u8; 32],
    /// Amount to subtract from the validator's `pending_withdrawal_amount` when processed.
    /// For validator-initiated withdrawals and stake bounds enforcement, this equals the
    /// withdrawal amount. For deposit refunds (where funds were never credited to the
    /// account), this is 0.
    pub balance_deduction: u64,
    /// The epoch in which this withdrawal is scheduled to be processed.
    pub epoch: u64,
}

impl TryFrom<&[u8]> for PendingWithdrawal {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // PendingWithdrawal data is exactly 92 bytes
        // Format: index(8) + validator_index(8) + address(20) + amount(8) + pubkey(32) + balance_deduction(8) + epoch(8) = 92 bytes

        if bytes.len() != 92 {
            return Err("PendingWithdrawal must be exactly 92 bytes");
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

        // Extract balance_deduction (8 bytes, little-endian u64)
        let balance_deduction_bytes: [u8; 8] = bytes[76..84]
            .try_into()
            .map_err(|_| "Failed to parse balance_deduction")?;
        let balance_deduction = u64::from_le_bytes(balance_deduction_bytes);

        // Extract epoch (8 bytes, little-endian u64)
        let epoch_bytes: [u8; 8] = bytes[84..92]
            .try_into()
            .map_err(|_| "Failed to parse epoch")?;
        let epoch = u64::from_le_bytes(epoch_bytes);

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            pubkey,
            balance_deduction,
            epoch,
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
        buf.put(&self.balance_deduction.to_le_bytes()[..]);
        buf.put(&self.epoch.to_le_bytes()[..]);
    }
}

impl FixedSize for PendingWithdrawal {
    const SIZE: usize = 92; // 8 + 8 + 20 + 8 + 32 + 8 + 8
}

impl Read for PendingWithdrawal {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        if buf.remaining() < 92 {
            return Err(Error::Invalid("PendingWithdrawal", "Insufficient bytes"));
        }

        let mut index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut index_bytes);
        let index = u64::from_le_bytes(index_bytes);

        let mut validator_index_bytes = [0u8; 8];
        buf.copy_to_slice(&mut validator_index_bytes);
        let validator_index = u64::from_le_bytes(validator_index_bytes);

        let mut address_bytes = [0u8; 20];
        buf.copy_to_slice(&mut address_bytes);
        let address = Address::from(address_bytes);

        let mut amount_bytes = [0u8; 8];
        buf.copy_to_slice(&mut amount_bytes);
        let amount = u64::from_le_bytes(amount_bytes);

        let mut pubkey = [0u8; 32];
        buf.copy_to_slice(&mut pubkey);

        let mut balance_deduction_bytes = [0u8; 8];
        buf.copy_to_slice(&mut balance_deduction_bytes);
        let balance_deduction = u64::from_le_bytes(balance_deduction_bytes);

        let mut epoch_bytes = [0u8; 8];
        buf.copy_to_slice(&mut epoch_bytes);
        let epoch = u64::from_le_bytes(epoch_bytes);

        Ok(PendingWithdrawal {
            inner: Withdrawal {
                index,
                validator_index,
                address,
                amount,
            },
            pubkey,
            balance_deduction,
            epoch,
        })
    }
}

/// Encapsulates withdrawal data and scheduling.
///
/// Stores at most one withdrawal per validator (keyed by pubkey). If a withdrawal
/// is pushed for a pubkey that already has one pending, amounts and balance
/// deductions are merged and the original scheduled epoch is kept.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WithdrawalQueue {
    /// Map from validator pubkey to their pending withdrawal data.
    withdrawals: BTreeMap<[u8; 32], PendingWithdrawal>,
    /// Withdrawals ordered by epoch. Each epoch maps to an ordered list of
    /// validator pubkeys whose withdrawals should be processed in that epoch.
    schedule: BTreeMap<u64, VecDeque<[u8; 32]>>,
    /// The next withdrawal index to assign.
    next_index: u64,
}

impl WithdrawalQueue {
    /// Add a withdrawal request. If the pubkey already has a pending withdrawal,
    /// merges amounts and balance deductions into the existing entry (keeping the
    /// original scheduled epoch).
    pub fn push_request(&mut self, request: WithdrawalRequest, epoch: u64, balance_deduction: u64) {
        let pubkey = request.validator_pubkey;

        if let Some(existing) = self.withdrawals.get_mut(&pubkey) {
            existing.inner.amount += request.amount;
            existing.balance_deduction += balance_deduction;
        } else {
            let index = self.next_index;
            self.next_index += 1;

            let pending = PendingWithdrawal {
                inner: Withdrawal {
                    index,
                    validator_index: 0,
                    address: request.source_address,
                    amount: request.amount,
                },
                pubkey,
                balance_deduction,
                epoch,
            };

            self.withdrawals.insert(pubkey, pending);
            self.schedule.entry(epoch).or_default().push_back(pubkey);
        }
    }

    /// Push a pre-built withdrawal directly (for test setup and deserialization).
    pub fn push(&mut self, withdrawal: PendingWithdrawal) {
        let pubkey = withdrawal.pubkey;
        let epoch = withdrawal.epoch;
        self.withdrawals.insert(pubkey, withdrawal);
        self.schedule.entry(epoch).or_default().push_back(pubkey);
    }

    /// Pop the next withdrawal for the given epoch.
    pub fn pop(&mut self, epoch: u64) -> Option<PendingWithdrawal> {
        if let Some(queue) = self.schedule.get_mut(&epoch)
            && let Some(pubkey) = queue.pop_front()
        {
            if queue.is_empty() {
                self.schedule.remove(&epoch);
            }
            return self.withdrawals.remove(&pubkey);
        }
        None
    }

    /// Peek at the next withdrawal for the given epoch without removing it.
    pub fn peek(&self, epoch: u64) -> Option<&PendingWithdrawal> {
        self.schedule
            .get(&epoch)
            .and_then(|queue| queue.front())
            .and_then(|pubkey| self.withdrawals.get(pubkey))
    }

    /// Get all pending withdrawals for a specific epoch.
    pub fn get_for_epoch(&self, epoch: u64) -> Vec<&PendingWithdrawal> {
        self.schedule
            .get(&epoch)
            .map(|queue| {
                queue
                    .iter()
                    .filter_map(|pk| self.withdrawals.get(pk))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Move all remaining withdrawals from one epoch to another.
    /// Used to reschedule overflow withdrawals that exceeded the per-epoch cap.
    /// Rescheduled withdrawals are placed at the front of the target epoch's queue
    /// since they were scheduled earlier and should have priority.
    pub fn reschedule_epoch(&mut self, from_epoch: u64, to_epoch: u64) {
        if let Some(mut pubkeys) = self.schedule.remove(&from_epoch) {
            if pubkeys.is_empty() {
                return;
            }
            // Update the epoch on each withdrawal entry
            for pk in &pubkeys {
                if let Some(w) = self.withdrawals.get_mut(pk) {
                    w.epoch = to_epoch;
                }
            }
            // Prepend to the target epoch's schedule (rescheduled withdrawals get priority)
            if let Some(existing) = self.schedule.get_mut(&to_epoch) {
                pubkeys.extend(existing.iter().copied());
                *existing = pubkeys;
            } else {
                self.schedule.insert(to_epoch, pubkeys);
            }
        }
    }

    /// Get the number of pending withdrawals for a specific epoch.
    pub fn count_for_epoch(&self, epoch: u64) -> usize {
        self.schedule.get(&epoch).map(|q| q.len()).unwrap_or(0)
    }

    /// Get all epochs that have pending withdrawals.
    pub fn epochs_with_withdrawals(&self) -> Vec<u64> {
        self.schedule.keys().copied().collect()
    }

    /// Get the next withdrawal index.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Set the next withdrawal index.
    pub fn set_next_index(&mut self, index: u64) {
        self.next_index = index;
    }

    /// Number of unique validators with pending withdrawals.
    pub fn len(&self) -> usize {
        self.withdrawals.len()
    }

    /// Whether there are any pending withdrawals.
    pub fn is_empty(&self) -> bool {
        self.withdrawals.is_empty()
    }

    /// Number of epochs with scheduled withdrawals.
    pub fn num_epochs(&self) -> usize {
        self.schedule.len()
    }

    /// Get the `balance_deduction` for a specific validator, or 0 if not in the queue.
    pub fn balance_deduction_for(&self, pubkey: &[u8; 32]) -> u64 {
        self.withdrawals
            .get(pubkey)
            .map(|w| w.balance_deduction)
            .unwrap_or(0)
    }

    /// Get a pending withdrawal by validator pubkey.
    pub fn get_withdrawal(&self, pubkey: &[u8; 32]) -> Option<&PendingWithdrawal> {
        self.withdrawals.get(pubkey)
    }

    /// Iterate over all pending withdrawals as (pubkey, withdrawal) pairs.
    pub fn withdrawals_iter(&self) -> impl Iterator<Item = (&[u8; 32], &PendingWithdrawal)> {
        self.withdrawals.iter()
    }
}

impl EncodeSize for WithdrawalQueue {
    fn encode_size(&self) -> usize {
        8 // next_index
        + 4 // withdrawals count
        + self.withdrawals.len() * (32 + PendingWithdrawal::SIZE)
        + 4 // schedule epoch count
        + self.schedule.values().map(|pubkeys| {
            8 // epoch
            + 4 // pubkey count
            + pubkeys.len() * 32
        }).sum::<usize>()
    }
}

impl Write for WithdrawalQueue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.next_index);

        // Write withdrawals map
        buf.put_u32(self.withdrawals.len() as u32);
        for (pubkey, withdrawal) in &self.withdrawals {
            buf.put_slice(pubkey);
            withdrawal.write(buf);
        }

        // Write schedule
        buf.put_u32(self.schedule.len() as u32);
        for (epoch, pubkeys) in &self.schedule {
            buf.put_u64(*epoch);
            buf.put_u32(pubkeys.len() as u32);
            for pubkey in pubkeys {
                buf.put_slice(pubkey);
            }
        }
    }
}

impl Read for WithdrawalQueue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let next_index = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;

        let withdrawals_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut withdrawals = BTreeMap::new();
        for _ in 0..withdrawals_len {
            let mut pubkey = [0u8; 32];
            buf.try_copy_to_slice(&mut pubkey)
                .map_err(|_| Error::EndOfBuffer)?;
            let withdrawal = PendingWithdrawal::read_cfg(buf, &())?;
            withdrawals.insert(pubkey, withdrawal);
        }

        let schedule_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
        let mut schedule = BTreeMap::new();
        for _ in 0..schedule_len {
            let epoch = buf.try_get_u64().map_err(|_| Error::EndOfBuffer)?;
            let pubkeys_len = buf.try_get_u32().map_err(|_| Error::EndOfBuffer)? as usize;
            let mut pubkeys = VecDeque::with_capacity(pubkeys_len.min(buf.remaining()));
            for _ in 0..pubkeys_len {
                let mut pubkey = [0u8; 32];
                buf.try_copy_to_slice(&mut pubkey)
                    .map_err(|_| Error::EndOfBuffer)?;
                pubkeys.push_back(pubkey);
            }
            schedule.insert(epoch, pubkeys);
        }

        Ok(Self {
            withdrawals,
            schedule,
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
            balance_deduction: 16000000000u64,
            epoch: 5,
        };

        // Test Write
        let mut buf = BytesMut::new();
        withdrawal.write(&mut buf);
        assert_eq!(buf.len(), 92); // 8 + 8 + 20 + 8 + 32 + 8 + 8

        // Test Read
        let decoded = PendingWithdrawal::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, withdrawal);
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
            balance_deduction: 0,
            epoch: 10,
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
        buf.put(&[0u8; 91][..]); // One byte short

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
        let buf = [0u8; 91]; // One byte short
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 92 bytes"
        );
    }

    #[test]
    fn test_pending_withdrawal_try_from_too_many_bytes() {
        let buf = [0u8; 93]; // One byte too many
        let result = PendingWithdrawal::try_from(buf.as_ref());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "PendingWithdrawal must be exactly 92 bytes"
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
            balance_deduction: 64000000000u64,
            epoch: 42,
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
        assert_eq!(PendingWithdrawal::SIZE, 92);

        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::ZERO,
                amount: 0,
            },
            pubkey: [0u8; 32],
            balance_deduction: 0,
            epoch: 0,
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
            balance_deduction: 0xa1b2c3d4e5f60708u64,
            epoch: 0x1122334455667788u64,
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

        // Check balance_deduction (next 8 bytes, little-endian)
        assert_eq!(&bytes[76..84], &0xa1b2c3d4e5f60708u64.to_le_bytes());

        // Check epoch (last 8 bytes, little-endian)
        assert_eq!(&bytes[84..92], &0x1122334455667788u64.to_le_bytes());

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
        queue.push_request(req, 5, 100);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.num_epochs(), 1);
        assert_eq!(queue.next_index(), 1);

        let w = queue.pop(5).unwrap();
        assert_eq!(w.inner.amount, 100);
        assert_eq!(w.inner.index, 0);
        assert_eq!(w.balance_deduction, 100);
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
        queue.push_request(req, 5, 100);

        let w = queue.peek(5).unwrap();
        assert_eq!(w.inner.amount, 100);
        // peek doesn't remove
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_pop_wrong_epoch() {
        let mut queue = WithdrawalQueue::default();
        let req = make_request([1u8; 32], 100);
        queue.push_request(req, 5, 100);

        assert!(queue.pop(4).is_none());
        assert!(queue.pop(6).is_none());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_queue_multiple_validators_same_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 5, 200);
        queue.push_request(make_request([3u8; 32], 300), 5, 300);

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
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 7, 200);

        assert_eq!(queue.num_epochs(), 2);
        let mut epochs = queue.epochs_with_withdrawals();
        epochs.sort();
        assert_eq!(epochs, vec![5, 7]);

        assert_eq!(queue.count_for_epoch(5), 1);
        assert_eq!(queue.count_for_epoch(7), 1);
        assert_eq!(queue.count_for_epoch(6), 0);
    }

    #[test]
    fn test_queue_get_for_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 5, 200);
        queue.push_request(make_request([3u8; 32], 300), 7, 300);

        let epoch5 = queue.get_for_epoch(5);
        assert_eq!(epoch5.len(), 2);
        assert_eq!(epoch5[0].inner.amount, 100);
        assert_eq!(epoch5[1].inner.amount, 200);

        let epoch7 = queue.get_for_epoch(7);
        assert_eq!(epoch7.len(), 1);
        assert_eq!(epoch7[0].inner.amount, 300);

        assert!(queue.get_for_epoch(6).is_empty());
    }

    #[test]
    fn test_queue_merge_same_pubkey() {
        let mut queue = WithdrawalQueue::default();

        // First withdrawal: user-initiated, 50 ETH
        queue.push_request(make_request([1u8; 32], 50), 5, 50);
        assert_eq!(queue.next_index(), 1);

        // Second withdrawal for same pubkey: deposit refund, 10 ETH, balance_deduction=0
        queue.push_request(make_request([1u8; 32], 10), 7, 0);

        // Should still be one entry, no new index assigned
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.next_index(), 1);

        // Amounts merged, original epoch preserved
        let w = queue.peek(5).unwrap();
        assert_eq!(w.inner.amount, 60); // 50 + 10
        assert_eq!(w.balance_deduction, 50); // 50 + 0
        assert_eq!(w.inner.index, 0);
        assert_eq!(w.epoch, 5); // original epoch, not 7

        // Nothing at the second epoch (merged into first)
        assert!(queue.peek(7).is_none());
        assert_eq!(queue.num_epochs(), 1);
    }

    #[test]
    fn test_queue_merge_accumulates_balance_deduction() {
        let mut queue = WithdrawalQueue::default();

        // First: user withdrawal, 50 ETH
        queue.push_request(make_request([1u8; 32], 50), 5, 50);

        // Second: stake bounds enforcement adds 10 ETH
        queue.push_request(make_request([1u8; 32], 10), 6, 10);

        let w = queue.peek(5).unwrap();
        assert_eq!(w.inner.amount, 60);
        assert_eq!(w.balance_deduction, 60); // 50 + 10
    }

    #[test]
    fn test_queue_merge_does_not_affect_other_validators() {
        let mut queue = WithdrawalQueue::default();

        queue.push_request(make_request([1u8; 32], 50), 5, 50);
        queue.push_request(make_request([2u8; 32], 30), 5, 30);

        // Merge into validator 1 only
        queue.push_request(make_request([1u8; 32], 10), 5, 0);

        assert_eq!(queue.len(), 2);

        let epoch5 = queue.get_for_epoch(5);
        assert_eq!(epoch5.len(), 2);
        // Validator 1: merged
        assert_eq!(epoch5[0].inner.amount, 60);
        assert_eq!(epoch5[0].balance_deduction, 50);
        // Validator 2: unchanged
        assert_eq!(epoch5[1].inner.amount, 30);
        assert_eq!(epoch5[1].balance_deduction, 30);
    }

    #[test]
    fn test_queue_next_index_increments() {
        let mut queue = WithdrawalQueue::default();
        assert_eq!(queue.next_index(), 0);

        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        assert_eq!(queue.next_index(), 1);

        queue.push_request(make_request([2u8; 32], 200), 5, 200);
        assert_eq!(queue.next_index(), 2);

        // Merge doesn't increment
        queue.push_request(make_request([1u8; 32], 50), 5, 0);
        assert_eq!(queue.next_index(), 2);
    }

    #[test]
    fn test_queue_set_next_index() {
        let mut queue = WithdrawalQueue::default();
        queue.set_next_index(42);
        assert_eq!(queue.next_index(), 42);

        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        assert_eq!(queue.next_index(), 43);
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
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 5, 200);
        queue.push_request(make_request([3u8; 32], 300), 7, 300);

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
    fn test_queue_serialization_roundtrip_after_merge() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 50), 5, 50);
        queue.push_request(make_request([1u8; 32], 10), 7, 0); // merged

        let mut buf = BytesMut::new();
        queue.write(&mut buf);
        assert_eq!(buf.len(), queue.encode_size());

        let decoded = WithdrawalQueue::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded, queue);
        assert_eq!(decoded.len(), 1);

        let w = decoded.peek(5).unwrap();
        assert_eq!(w.inner.amount, 60);
        assert_eq!(w.balance_deduction, 50);
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
            balance_deduction: 100,
            epoch: 5,
        };
        queue.push(pending.clone());

        assert_eq!(queue.len(), 1);
        let w = queue.pop(5).unwrap();
        assert_eq!(w, pending);
    }

    #[test]
    fn test_queue_pop_cleans_up_empty_epoch() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5, 100);

        assert_eq!(queue.num_epochs(), 1);
        queue.pop(5);
        assert_eq!(queue.num_epochs(), 0);
        assert!(queue.epochs_with_withdrawals().is_empty());
    }

    #[test]
    fn test_reschedule_epoch_moves_all_withdrawals() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 5, 200);

        assert_eq!(queue.count_for_epoch(5), 2);
        assert_eq!(queue.count_for_epoch(6), 0);

        queue.reschedule_epoch(5, 6);

        assert_eq!(queue.count_for_epoch(5), 0);
        assert_eq!(queue.count_for_epoch(6), 2);
        // Epochs on the withdrawal entries should be updated
        assert_eq!(queue.get_for_epoch(6)[0].epoch, 6);
        assert_eq!(queue.get_for_epoch(6)[1].epoch, 6);
    }

    #[test]
    fn test_reschedule_epoch_prepends_to_existing() {
        let mut queue = WithdrawalQueue::default();
        // Two withdrawals in epoch 5 (will be rescheduled)
        queue.push_request(make_request([1u8; 32], 100), 5, 100);
        queue.push_request(make_request([2u8; 32], 200), 5, 200);
        // One withdrawal already in epoch 6
        queue.push_request(make_request([3u8; 32], 300), 6, 300);

        queue.reschedule_epoch(5, 6);

        assert_eq!(queue.count_for_epoch(5), 0);
        assert_eq!(queue.count_for_epoch(6), 3);

        // Rescheduled withdrawals should be at the front
        let epoch6 = queue.get_for_epoch(6);
        assert_eq!(epoch6[0].pubkey, [1u8; 32]);
        assert_eq!(epoch6[1].pubkey, [2u8; 32]);
        assert_eq!(epoch6[2].pubkey, [3u8; 32]);
    }

    #[test]
    fn test_reschedule_epoch_noop_when_empty() {
        let mut queue = WithdrawalQueue::default();
        queue.push_request(make_request([1u8; 32], 100), 6, 100);

        queue.reschedule_epoch(5, 6);

        // Nothing should change
        assert_eq!(queue.count_for_epoch(6), 1);
        assert_eq!(queue.get_for_epoch(6)[0].pubkey, [1u8; 32]);
    }
}
