use crate::Block;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_consensus::simplex::types::Finalization;
use futures::{
    SinkExt,
    channel::{mpsc, oneshot},
};
use tracing::error;

/// Messages sent from the finalizer task to the main actor loop.
///
/// We break this into a separate enum to establish a separate priority for
/// finalizer messages over consensus messages.
pub enum Orchestration<S: Scheme, B: Block> {
    /// A request to get the next finalized block.
    Get {
        /// The height of the block to get.
        height: u64,
        /// A channel to send the block, if found.
        result: oneshot::Sender<Option<B>>,
    },
    /// A request to get the next finalized block together with the finalization.
    GetWithFinalization {
        height: u64,
        #[allow(clippy::type_complexity)]
        result: oneshot::Sender<(Option<B>, Option<Finalization<S, B::Commitment>>)>,
    },
    /// A notification that a block has been processed by the application.
    Processed {
        /// The height of the processed block.
        height: u64,
        /// The digest of the processed block.
        digest: B::Commitment,
    },
    /// A request to repair a gap in the finalized block sequence.
    Repair {
        /// The height at which to start repairing.
        height: u64,
    },
}

/// A handle for the finalizer to communicate with the main actor loop.
#[derive(Clone)]
pub struct Orchestrator<S: Scheme, B: Block> {
    sender: mpsc::Sender<Orchestration<S, B>>,
}

impl<S: Scheme, B: Block> Orchestrator<S, B> {
    /// Creates a new orchestrator.
    pub fn new(sender: mpsc::Sender<Orchestration<S, B>>) -> Self {
        Self { sender }
    }

    /// Gets the finalized block at the given height.
    pub async fn get(&mut self, height: u64) -> Option<B> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Orchestration::Get {
                height,
                result: response,
            })
            .await
            .is_err()
        {
            error!("failed to send get message to actor: receiver dropped");
            return None;
        }
        receiver.await.unwrap_or(None)
    }

    /// Gets the finalized block at the given height together with the finalization.
    pub async fn get_with_finalization(
        &mut self,
        height: u64,
    ) -> (Option<B>, Option<Finalization<S, B::Commitment>>) {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Orchestration::GetWithFinalization {
                height,
                result: response,
            })
            .await
            .is_err()
        {
            error!("failed to send get_with_finalization message to actor: receiver dropped");
            return (None, None);
        }
        receiver.await.unwrap_or((None, None))
    }

    /// Notifies the actor that a block has been processed.
    pub async fn processed(&mut self, height: u64, digest: B::Commitment) {
        if self
            .sender
            .send(Orchestration::Processed { height, digest })
            .await
            .is_err()
        {
            error!("failed to send processed message to actor: receiver dropped");
        }
    }

    /// Attempts to repair a gap in the block sequence.
    pub async fn repair(&mut self, height: u64) {
        if self
            .sender
            .send(Orchestration::Repair { height })
            .await
            .is_err()
        {
            error!("failed to send repair message to actor: receiver dropped");
        }
    }
}
