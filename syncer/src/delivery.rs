use commonware_consensus::{
    Block,
    simplex::scheme::Scheme,
    simplex::types::{Finalization, Notarization},
};
use commonware_utils::channel::oneshot;

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
pub(crate) enum PendingVerification<S: Scheme<B::Digest>, B: Block> {
    Notarized {
        notarization: Notarization<S, B::Digest>,
        block: B,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        finalization: Finalization<S, B::Digest>,
        block: B,
        response: oneshot::Sender<bool>,
    },
}

impl<S: Scheme<B::Digest>, B: Block> PendingVerification<S, B> {
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { response, .. } | Self::Finalized { response, .. } => {
                response.is_closed()
            }
        }
    }
}
