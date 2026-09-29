use commonware_consensus::{
    Block,
    simplex::scheme::Scheme,
    simplex::types::{Finalization, Notarization},
};
use commonware_utils::channel::oneshot;

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
pub(crate) enum PendingVerification<S: Scheme<B::Digest>, B: Block> {
    Notarized {
        scoped: commonware_cryptography::certificate::Scoped<S>,
        notarization: Notarization<S, B::Digest>,
        block: B,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        scoped: commonware_cryptography::certificate::Scoped<S>,
        finalization: Finalization<S, B::Digest>,
        block: B,
        response: oneshot::Sender<bool>,
    },
}

impl<S: Scheme<B::Digest>, B: Block> PendingVerification<S, B> {
    pub(crate) fn scoped(&self) -> &commonware_cryptography::certificate::Scoped<S> {
        match self {
            Self::Notarized { scoped, .. } | Self::Finalized { scoped, .. } => scoped,
        }
    }

    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { response, .. } | Self::Finalized { response, .. } => {
                response.is_closed()
            }
        }
    }
}
