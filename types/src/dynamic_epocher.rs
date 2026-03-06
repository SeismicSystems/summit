use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_consensus::types::{Epoch, EpochInfo, Epocher, Height};
use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
struct Segment {
    start_epoch: Epoch,
    start_height: Height,
    length: u64,
}

#[derive(Debug)]
struct DynamicEpocherInner {
    segments: Vec<Segment>,
    current_epoch: Epoch,
}

/// An [`Epocher`] that supports dynamic epoch length changes.
///
/// Epoch length changes are registered via [`update_length`](Self::update_length)
/// and take effect two epochs after the current epoch (to avoid changing
/// boundaries that are already queryable).
///
/// Queries for epochs beyond `current_epoch + 1` return `None`.
#[derive(Debug, Clone)]
pub struct DynamicEpocher {
    inner: Arc<RwLock<DynamicEpocherInner>>,
}

impl DynamicEpocher {
    /// Creates a new `DynamicEpocher` with the given genesis epoch length.
    pub fn new(genesis_length: NonZeroU64) -> Self {
        let segment = Segment {
            start_epoch: Epoch::new(0),
            start_height: Height::new(0),
            length: genesis_length.get(),
        };
        Self {
            inner: Arc::new(RwLock::new(DynamicEpocherInner {
                segments: vec![segment],
                current_epoch: Epoch::new(0),
            })),
        }
    }

    /// Returns the epoch length for the current epoch.
    pub fn current_length(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        let epoch = inner.current_epoch;
        for seg in inner.segments.iter().rev() {
            if seg.start_epoch.get() <= epoch.get() {
                return seg.length;
            }
        }
        unreachable!("segments is never empty")
    }

    /// Advances the current epoch. Called by the finalizer at each epoch
    /// boundary and at startup from persisted state.
    pub fn advance_epoch(&self, epoch: Epoch) {
        let mut inner = self.inner.write().unwrap();
        inner.current_epoch = epoch;
    }

    /// Registers a new epoch length, taking effect at `current_epoch + 2`.
    ///
    /// Returns an error if the target epoch is before the latest registered
    /// segment's start epoch, or if bounds computation overflows.
    pub fn update_length(&self, new_length: NonZeroU64) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        let target_epoch = Epoch::new(
            inner
                .current_epoch
                .get()
                .checked_add(2)
                .ok_or_else(|| anyhow!("epoch overflow"))?,
        );

        let last_segment = inner
            .segments
            .last()
            .ok_or_else(|| anyhow!("no segments"))?;
        if target_epoch.get() < last_segment.start_epoch.get() {
            return Err(anyhow!(
                "target epoch {} is before latest segment epoch {}",
                target_epoch.get(),
                last_segment.start_epoch.get()
            ));
        }

        let (start_height, _) = Self::bounds(&inner.segments, target_epoch)
            .ok_or_else(|| anyhow!("failed to compute bounds for epoch {}", target_epoch))?;

        // If the last segment starts at the same epoch, overwrite it.
        if last_segment.start_epoch == target_epoch {
            let seg = inner.segments.last_mut().unwrap();
            seg.length = new_length.get();
        } else {
            inner.segments.push(Segment {
                start_epoch: target_epoch,
                start_height,
                length: new_length.get(),
            });
        }
        Ok(())
    }

    /// Computes the bounds (first, last) of a given epoch.
    /// The theoretical runtime of this function is O(n).
    /// It could be optimized to O(log n) by using binary search, since the segments are sorted by
    /// both start_epoch and start_height.
    /// However, in practice, calls for first(epoch) and last(epoch) will always be for the current
    /// or recent epochs.
    /// Therefore, the loop will stop after a single iteration, since we only need the last segment.
    /// Thus, the best case runtime is O(1) and we hit the best case almost every time.
    fn bounds(segments: &[Segment], epoch: Epoch) -> Option<(Height, Height)> {
        for seg in segments.iter().rev() {
            if seg.start_epoch.get() <= epoch.get() {
                let relative_epoch = epoch.get() - seg.start_epoch.get();
                let relative_start = relative_epoch.checked_mul(seg.length)?;
                let first = seg.start_height.get().checked_add(relative_start)?;
                let last = first.checked_add(seg.length - 1)?;
                return Some((Height::new(first), Height::new(last)));
            }
        }
        None
    }
}

impl Epocher for DynamicEpocher {
    /// Computes the bounds (first, last) of a given epoch.
    /// The theoretical runtime of this function is O(n).
    /// It could be optimized to O(log n) by using binary search, since the segments are sorted by
    /// both start_epoch and start_height.
    /// However, in practice, calls for containing(height) will always be for recent heights.
    /// Therefore, the loop will stop after a single iteration, since we only need the last segment.
    /// Thus, the best case runtime is O(1) and we hit the best case almost every time.
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        let inner = self.inner.read().unwrap();
        for seg in inner.segments.iter().rev() {
            if seg.start_height.get() <= height.get() {
                let relative_height = height.get() - seg.start_height.get();
                let relative_epoch = relative_height / seg.length;
                let epoch = Epoch::new(seg.start_epoch.get().checked_add(relative_epoch)?);

                if epoch.get() > inner.current_epoch.get() + 1 {
                    return None;
                }

                let (first, last) = Self::bounds(&inner.segments, epoch)?;
                return Some(EpochInfo::new(epoch, height, first, last));
            }
        }
        None
    }

    fn first(&self, epoch: Epoch) -> Option<Height> {
        let inner = self.inner.read().unwrap();
        if epoch.get() > inner.current_epoch.get() + 1 {
            return None;
        }
        Self::bounds(&inner.segments, epoch).map(|(first, _)| first)
    }

    fn last(&self, epoch: Epoch) -> Option<Height> {
        let inner = self.inner.read().unwrap();
        if epoch.get() > inner.current_epoch.get() + 1 {
            return None;
        }
        Self::bounds(&inner.segments, epoch).map(|(_, last)| last)
    }
}

impl EncodeSize for DynamicEpocher {
    fn encode_size(&self) -> usize {
        let inner = self.inner.read().unwrap();
        8 // current_epoch
        + 4 // segments length
        + inner.segments.len() * (8 + 8 + 8) // start_epoch + start_height + length per segment
    }
}

impl Write for DynamicEpocher {
    fn write(&self, buf: &mut impl BufMut) {
        let inner = self.inner.read().unwrap();
        buf.put_u64(inner.current_epoch.get());
        buf.put_u32(inner.segments.len() as u32);
        for seg in &inner.segments {
            buf.put_u64(seg.start_epoch.get());
            buf.put_u64(seg.start_height.get());
            buf.put_u64(seg.length);
        }
    }
}

impl Read for DynamicEpocher {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> core::result::Result<Self, Error> {
        let current_epoch = Epoch::new(buf.get_u64());
        let segments_len = buf.get_u32() as usize;
        if segments_len == 0 {
            return Err(Error::Invalid("DynamicEpocher", "no segments"));
        }
        let mut segments = Vec::with_capacity(segments_len);
        for _ in 0..segments_len {
            let start_epoch = Epoch::new(buf.get_u64());
            let start_height = Height::new(buf.get_u64());
            let length = buf.get_u64();
            if length == 0 {
                return Err(Error::Invalid("DynamicEpocher", "zero-length segment"));
            }
            segments.push(Segment {
                start_epoch,
                start_height,
                length,
            });
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(DynamicEpocherInner {
                segments,
                current_epoch,
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::ReadExt;

    fn setup() -> DynamicEpocher {
        // epoch 0-1: length 100 (heights 0-199)
        // epoch 2-3: length 250 (heights 200-699)
        // epoch 4-6: length 87  (heights 700-960)
        // epoch 7+:  length 205 (heights 961+)
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());

        // current_epoch=0, targets epoch 2
        epocher
            .update_length(NonZeroU64::new(250).unwrap())
            .unwrap();

        // current_epoch=2, targets epoch 4
        epocher.advance_epoch(Epoch::new(2));
        epocher.update_length(NonZeroU64::new(87).unwrap()).unwrap();

        // current_epoch=5, targets epoch 7
        epocher.advance_epoch(Epoch::new(5));
        epocher
            .update_length(NonZeroU64::new(205).unwrap())
            .unwrap();

        // Advance so all epochs are queryable.
        epocher.advance_epoch(Epoch::new(8));

        epocher
    }

    #[test]
    fn test_containing() {
        let epocher = setup();

        assert_eq!(
            epocher.containing(Height::new(0)).unwrap().epoch(),
            Epoch::new(0)
        );
        assert_eq!(
            epocher.containing(Height::new(50)).unwrap().epoch(),
            Epoch::new(0)
        );
        assert_eq!(
            epocher.containing(Height::new(99)).unwrap().epoch(),
            Epoch::new(0)
        );

        assert_eq!(
            epocher.containing(Height::new(100)).unwrap().epoch(),
            Epoch::new(1)
        );
        assert_eq!(
            epocher.containing(Height::new(187)).unwrap().epoch(),
            Epoch::new(1)
        );
        assert_eq!(
            epocher.containing(Height::new(199)).unwrap().epoch(),
            Epoch::new(1)
        );

        assert_eq!(
            epocher.containing(Height::new(200)).unwrap().epoch(),
            Epoch::new(2)
        );
        assert_eq!(
            epocher.containing(Height::new(280)).unwrap().epoch(),
            Epoch::new(2)
        );
        assert_eq!(
            epocher.containing(Height::new(449)).unwrap().epoch(),
            Epoch::new(2)
        );

        assert_eq!(
            epocher.containing(Height::new(450)).unwrap().epoch(),
            Epoch::new(3)
        );
        assert_eq!(
            epocher.containing(Height::new(500)).unwrap().epoch(),
            Epoch::new(3)
        );
        assert_eq!(
            epocher.containing(Height::new(699)).unwrap().epoch(),
            Epoch::new(3)
        );

        assert_eq!(
            epocher.containing(Height::new(700)).unwrap().epoch(),
            Epoch::new(4)
        );
        assert_eq!(
            epocher.containing(Height::new(730)).unwrap().epoch(),
            Epoch::new(4)
        );
        assert_eq!(
            epocher.containing(Height::new(786)).unwrap().epoch(),
            Epoch::new(4)
        );

        assert_eq!(
            epocher.containing(Height::new(787)).unwrap().epoch(),
            Epoch::new(5)
        );
        assert_eq!(
            epocher.containing(Height::new(800)).unwrap().epoch(),
            Epoch::new(5)
        );
        assert_eq!(
            epocher.containing(Height::new(873)).unwrap().epoch(),
            Epoch::new(5)
        );

        assert_eq!(
            epocher.containing(Height::new(874)).unwrap().epoch(),
            Epoch::new(6)
        );
        assert_eq!(
            epocher.containing(Height::new(901)).unwrap().epoch(),
            Epoch::new(6)
        );
        assert_eq!(
            epocher.containing(Height::new(960)).unwrap().epoch(),
            Epoch::new(6)
        );

        assert_eq!(
            epocher.containing(Height::new(961)).unwrap().epoch(),
            Epoch::new(7)
        );
        assert_eq!(
            epocher.containing(Height::new(989)).unwrap().epoch(),
            Epoch::new(7)
        );
        assert_eq!(
            epocher.containing(Height::new(1165)).unwrap().epoch(),
            Epoch::new(7)
        );

        assert_eq!(
            epocher.containing(Height::new(1170)).unwrap().epoch(),
            Epoch::new(8)
        );
    }

    #[test]
    fn test_first_and_last() {
        let epocher = setup();

        assert_eq!(epocher.first(Epoch::new(0)), Some(Height::new(0)));
        assert_eq!(epocher.last(Epoch::new(0)), Some(Height::new(99)));

        assert_eq!(epocher.first(Epoch::new(1)), Some(Height::new(100)));
        assert_eq!(epocher.last(Epoch::new(1)), Some(Height::new(199)));

        assert_eq!(epocher.first(Epoch::new(2)), Some(Height::new(200)));
        assert_eq!(epocher.last(Epoch::new(2)), Some(Height::new(449)));

        assert_eq!(epocher.first(Epoch::new(3)), Some(Height::new(450)));
        assert_eq!(epocher.last(Epoch::new(3)), Some(Height::new(699)));

        assert_eq!(epocher.first(Epoch::new(4)), Some(Height::new(700)));
        assert_eq!(epocher.last(Epoch::new(4)), Some(Height::new(786)));

        assert_eq!(epocher.first(Epoch::new(5)), Some(Height::new(787)));
        assert_eq!(epocher.last(Epoch::new(5)), Some(Height::new(873)));

        assert_eq!(epocher.first(Epoch::new(6)), Some(Height::new(874)));
        assert_eq!(epocher.last(Epoch::new(6)), Some(Height::new(960)));

        assert_eq!(epocher.first(Epoch::new(7)), Some(Height::new(961)));
        assert_eq!(epocher.last(Epoch::new(7)), Some(Height::new(1165)));
    }

    #[test]
    fn test_future_epoch_returns_none() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        assert!(epocher.first(Epoch::new(0)).is_some());
        assert!(epocher.first(Epoch::new(1)).is_some());
        assert!(epocher.first(Epoch::new(2)).is_none());
        assert!(epocher.first(Epoch::new(100)).is_none());
    }

    #[test]
    fn test_advance_expands_queryable_range() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        assert!(epocher.first(Epoch::new(5)).is_none());

        epocher.advance_epoch(Epoch::new(5));
        assert!(epocher.first(Epoch::new(5)).is_some());
        assert!(epocher.first(Epoch::new(6)).is_some());
        assert!(epocher.first(Epoch::new(7)).is_none());
    }

    #[test]
    fn test_update_overwrites_same_epoch() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        epocher
            .update_length(NonZeroU64::new(250).unwrap())
            .unwrap();
        // Same current_epoch, so targets epoch 2 again — should overwrite.
        epocher
            .update_length(NonZeroU64::new(300).unwrap())
            .unwrap();

        epocher.advance_epoch(Epoch::new(2));
        assert_eq!(epocher.first(Epoch::new(2)), Some(Height::new(200)));
        assert_eq!(epocher.last(Epoch::new(2)), Some(Height::new(499)));
    }

    #[test]
    fn test_single_segment_matches_fixed() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(10).unwrap());
        epocher.advance_epoch(Epoch::new(100));

        for e in 0..=101 {
            let epoch = Epoch::new(e);
            assert_eq!(epocher.first(epoch), Some(Height::new(e * 10)));
            assert_eq!(epocher.last(epoch), Some(Height::new(e * 10 + 9)));
        }

        for h in 0..1010 {
            let height = Height::new(h);
            let info = epocher.containing(height).unwrap();
            assert_eq!(info.epoch(), Epoch::new(h / 10));
            assert_eq!(info.first(), Height::new((h / 10) * 10));
            assert_eq!(info.last(), Height::new((h / 10) * 10 + 9));
        }
    }

    #[test]
    fn test_containing_returns_correct_epoch_info() {
        let epocher = setup();

        let info = epocher.containing(Height::new(500)).unwrap();
        assert_eq!(info.epoch(), Epoch::new(3));
        assert_eq!(info.height(), Height::new(500));
        assert_eq!(info.first(), Height::new(450));
        assert_eq!(info.last(), Height::new(699));
    }

    #[test]
    fn test_containing_future_height_returns_none() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        // current_epoch = 0, so epochs 0 and 1 are queryable (heights 0-199).
        assert!(epocher.containing(Height::new(0)).is_some());
        assert!(epocher.containing(Height::new(199)).is_some());
        // Height 200 maps to epoch 2, which is beyond current_epoch + 1.
        assert!(epocher.containing(Height::new(200)).is_none());
        assert!(epocher.containing(Height::new(1000)).is_none());
    }

    #[test]
    fn test_last_future_epoch_returns_none() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        assert!(epocher.last(Epoch::new(0)).is_some());
        assert!(epocher.last(Epoch::new(1)).is_some());
        assert!(epocher.last(Epoch::new(2)).is_none());
        assert!(epocher.last(Epoch::new(100)).is_none());
    }

    #[test]
    fn test_update_rejects_past_epoch() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        // Register at epoch 2 (current=0, target=2).
        epocher
            .update_length(NonZeroU64::new(250).unwrap())
            .unwrap();
        // Advance to epoch 3, register at epoch 5 (current=3, target=5).
        epocher.advance_epoch(Epoch::new(3));
        epocher.update_length(NonZeroU64::new(50).unwrap()).unwrap();
        // Go back to epoch 1 — target would be epoch 3, which is before
        // the latest segment at epoch 5.
        epocher.advance_epoch(Epoch::new(1));
        assert!(epocher.update_length(NonZeroU64::new(80).unwrap()).is_err());
    }

    #[test]
    fn test_segment_boundary_transitions() {
        let epocher = setup();

        // Last height of epoch 1 (segment 0) and first height of epoch 2 (segment 1).
        assert_eq!(
            epocher.containing(Height::new(199)).unwrap().epoch(),
            Epoch::new(1)
        );
        assert_eq!(
            epocher.containing(Height::new(200)).unwrap().epoch(),
            Epoch::new(2)
        );

        // Last height of epoch 3 (segment 1) and first height of epoch 4 (segment 2).
        assert_eq!(
            epocher.containing(Height::new(699)).unwrap().epoch(),
            Epoch::new(3)
        );
        assert_eq!(
            epocher.containing(Height::new(700)).unwrap().epoch(),
            Epoch::new(4)
        );

        // Last height of epoch 6 (segment 2) and first height of epoch 7 (segment 3).
        assert_eq!(
            epocher.containing(Height::new(960)).unwrap().epoch(),
            Epoch::new(6)
        );
        assert_eq!(
            epocher.containing(Height::new(961)).unwrap().epoch(),
            Epoch::new(7)
        );

        // Verify full EpochInfo at boundaries.
        let info = epocher.containing(Height::new(199)).unwrap();
        assert_eq!(info.first(), Height::new(100));
        assert_eq!(info.last(), Height::new(199));

        let info = epocher.containing(Height::new(200)).unwrap();
        assert_eq!(info.first(), Height::new(200));
        assert_eq!(info.last(), Height::new(449));
    }

    #[test]
    fn test_overwrite_preserves_subsequent_epochs() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        epocher
            .update_length(NonZeroU64::new(250).unwrap())
            .unwrap();
        // Overwrite with different length.
        epocher
            .update_length(NonZeroU64::new(300).unwrap())
            .unwrap();

        epocher.advance_epoch(Epoch::new(5));

        // Epoch 0-1: length 100 (heights 0-199)
        // Epoch 2+: length 300 (heights 200-499, 500-799, ...)
        assert_eq!(epocher.first(Epoch::new(2)), Some(Height::new(200)));
        assert_eq!(epocher.last(Epoch::new(2)), Some(Height::new(499)));
        assert_eq!(epocher.first(Epoch::new(3)), Some(Height::new(500)));
        assert_eq!(epocher.last(Epoch::new(3)), Some(Height::new(799)));
        assert_eq!(epocher.first(Epoch::new(4)), Some(Height::new(800)));
        assert_eq!(epocher.last(Epoch::new(4)), Some(Height::new(1099)));
    }

    #[test]
    fn test_encode_decode_genesis_only() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(10).unwrap());
        epocher.advance_epoch(Epoch::new(3));

        let mut buf = BytesMut::new();
        epocher.write(&mut buf);
        assert_eq!(buf.len(), epocher.encode_size());

        let decoded = DynamicEpocher::read(&mut buf.as_ref()).unwrap();
        assert_eq!(decoded.current_length(), 10);
        assert_eq!(decoded.first(Epoch::new(0)), Some(Height::new(0)));
        assert_eq!(decoded.last(Epoch::new(3)), Some(Height::new(39)));
    }

    #[test]
    fn test_encode_decode_multiple_segments() {
        let epocher = DynamicEpocher::new(NonZeroU64::new(100).unwrap());
        epocher.advance_epoch(Epoch::new(0));
        epocher
            .update_length(NonZeroU64::new(200).unwrap())
            .unwrap();
        epocher.advance_epoch(Epoch::new(3));

        let mut buf = BytesMut::new();
        epocher.write(&mut buf);
        assert_eq!(buf.len(), epocher.encode_size());

        let decoded = DynamicEpocher::read(&mut buf.as_ref()).unwrap();
        // Epoch 0-1: length 100, epoch 2+: length 200
        assert_eq!(decoded.first(Epoch::new(0)), Some(Height::new(0)));
        assert_eq!(decoded.last(Epoch::new(1)), Some(Height::new(199)));
        assert_eq!(decoded.first(Epoch::new(2)), Some(Height::new(200)));
        assert_eq!(decoded.last(Epoch::new(2)), Some(Height::new(399)));
    }

    #[test]
    fn test_decode_empty_segments_fails() {
        let mut buf = BytesMut::new();
        buf.put_u64(0); // current_epoch
        buf.put_u32(0); // zero segments

        let result = DynamicEpocher::read(&mut buf.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_zero_length_segment_fails() {
        let mut buf = BytesMut::new();
        buf.put_u64(0); // current_epoch
        buf.put_u32(1); // one segment
        buf.put_u64(0); // start_epoch
        buf.put_u64(0); // start_height
        buf.put_u64(0); // length = 0 (invalid)

        let result = DynamicEpocher::read(&mut buf.as_ref());
        assert!(result.is_err());
    }
}
