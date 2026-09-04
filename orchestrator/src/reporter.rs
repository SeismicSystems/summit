use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    simplex::{scheme::Scheme, types::Activity},
};
use commonware_cryptography::Digest;
use std::marker::PhantomData;

/// Filters Simplex activity down to the reports consumed by the syncer.
///
/// The syncer mailbox also filters activities in its [`Reporter`] implementation.
/// This outer filter is intentionally redundant: it runs before Commonware's
/// `AttributableReporter` so ignored individual votes are not synchronously
/// verified only to be discarded by the syncer mailbox.
#[derive(Clone)]
pub(crate) struct SyncerActivityFilter<S, D, R> {
    inner: R,
    _activity: PhantomData<fn() -> (S, D)>,
}

impl<S, D, R> SyncerActivityFilter<S, D, R> {
    pub(crate) const fn new(inner: R) -> Self {
        Self {
            inner,
            _activity: PhantomData,
        }
    }
}

impl<S, D, R> Reporter for SyncerActivityFilter<S, D, R>
where
    S: Scheme<D>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if matches!(
            &activity,
            Activity::Notarization(_)
                | Activity::Finalization(_)
                | Activity::ConflictingNotarize(_)
                | Activity::ConflictingFinalize(_)
                | Activity::NullifyFinalize(_)
        ) {
            self.inner.report(activity)
        } else {
            Feedback::Ok
        }
    }
}
