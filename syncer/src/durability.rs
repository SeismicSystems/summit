//! Helpers for observing deferred storage syncs and gating finalized dispatch.

use commonware_consensus::types::{Height, Round};
use commonware_runtime::{Error, Handle};
use std::{collections::BTreeMap, future::Future};
use tracing::debug;

/// Applies the syncer's fatal policy when awaiting a durable-sync handle.
pub(crate) trait Durable {
    /// Resolves once the sync is durable. Storage failures are fatal; `false`
    /// only indicates runtime shutdown before completion.
    fn durable(self, round: Round, name: &'static str) -> impl Future<Output = bool> + Send;
}

impl Durable for Handle<()> {
    async fn durable(self, round: Round, name: &'static str) -> bool {
        match self.await {
            Ok(()) => true,
            Err(Error::Closed | Error::Aborted) => {
                debug!(name, "runtime shutdown before sync completed");
                false
            }
            Err(e) => panic!("failed to sync {name} at {round}: {e}"),
        }
    }
}

/// Defers finalized-block dispatch until a sync covering each buffered write completes.
#[derive(Default)]
pub(crate) struct DispatchGate {
    unsynced: Option<Height>,
    inflight: BTreeMap<u64, Height>,
    next_seq: u64,
}

impl DispatchGate {
    pub(crate) fn defer(&mut self, height: Height) {
        self.unsynced = Some(self.unsynced.map_or(height, |lowest| lowest.min(height)));
    }

    pub(crate) fn adopt(&mut self) -> Option<u64> {
        let lowest = self.unsynced.take()?;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.inflight.insert(seq, lowest);
        Some(seq)
    }

    pub(crate) fn release(&mut self, seq: u64) {
        self.inflight = self.inflight.split_off(&(seq + 1));
    }

    pub(crate) fn clear(&mut self) {
        self.unsynced = None;
        self.inflight.clear();
    }

    pub(crate) fn barrier(&self) -> Option<Height> {
        self.inflight.values().copied().chain(self.unsynced).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn durable_resolves_true_on_success() {
        deterministic::Runner::default().start(|_| async move {
            assert!(Handle::ready(Ok(())).durable(Round::zero(), "test").await);
        });
    }

    #[test]
    fn durable_reports_shutdown_as_not_durable() {
        deterministic::Runner::default().start(|_| async move {
            assert!(
                !Handle::ready(Err(Error::Closed))
                    .durable(Round::zero(), "test")
                    .await
            );
            assert!(
                !Handle::ready(Err(Error::Aborted))
                    .durable(Round::zero(), "test")
                    .await
            );
        });
    }

    #[test]
    #[should_panic(expected = "failed to sync test")]
    fn durable_panics_on_sync_failure() {
        deterministic::Runner::default().start(|_| async move {
            let _ = Handle::<()>::ready(Err(Error::WriteFailed))
                .durable(Round::zero(), "test")
                .await;
        });
    }

    #[test]
    fn gate_defer_keeps_lowest_write() {
        let mut gate = DispatchGate::default();
        gate.defer(Height::new(5));
        gate.defer(Height::new(3));
        gate.defer(Height::new(7));
        assert_eq!(gate.barrier(), Some(Height::new(3)));
    }

    #[test]
    fn gate_adopt_moves_writes_to_one_batch() {
        let mut gate = DispatchGate::default();
        assert_eq!(gate.adopt(), None);
        gate.defer(Height::new(5));
        let seq = gate.adopt().expect("deferred write must adopt");
        assert_eq!(gate.adopt(), None);
        gate.release(seq);
        assert_eq!(gate.barrier(), None);
    }

    #[test]
    fn gate_release_covers_earlier_batches_only() {
        let mut gate = DispatchGate::default();
        gate.defer(Height::new(5));
        let first = gate.adopt().expect("first batch");
        gate.defer(Height::new(8));
        let second = gate.adopt().expect("second batch");
        gate.release(first);
        assert_eq!(gate.barrier(), Some(Height::new(8)));
        gate.release(second);
        assert_eq!(gate.barrier(), None);

        let mut out_of_order = DispatchGate::default();
        out_of_order.defer(Height::new(5));
        out_of_order.adopt().expect("first batch");
        out_of_order.defer(Height::new(8));
        let newest = out_of_order.adopt().expect("second batch");
        out_of_order.release(newest);
        assert_eq!(out_of_order.barrier(), None);
    }

    #[test]
    fn gate_clear_does_not_release_later_batches() {
        let mut gate = DispatchGate::default();
        gate.defer(Height::new(5));
        let stale = gate.adopt().expect("first batch");
        gate.clear();
        gate.defer(Height::new(9));
        gate.adopt().expect("post-clear batch");
        gate.release(stale);
        assert_eq!(gate.barrier(), Some(Height::new(9)));
    }
}
