use commonware_consensus::{
    Reporter,
    simplex::types::{Finalization, Notarization},
};
use commonware_cryptography::sha256::Digest;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use summit_types::{Activity, Block, Signature};
use tracing::debug;

pub enum Message {
    Get {
        view: Option<u64>,
        payload: Digest,
        response: oneshot::Sender<Block>,
    },

    Broadcast {
        payload: Block,
    },

    StoreVerified {
        view: u64,
        payload: Block,
    },

    Finalize {
        finalization: Finalization<Signature, Digest>,
    },

    Notarize {
        notarization: Notarization<Signature, Digest>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn get(&mut self, view: Option<u64>, payload: Digest) -> oneshot::Receiver<Block> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                view,
                payload,
                response,
            })
            .await
            .expect("Failed to send get");
        receiver
    }

    pub async fn broadcast(&mut self, payload: Block) {
        self.sender
            .send(Message::Broadcast { payload })
            .await
            .expect("Failed to send broadcast");
    }

    pub async fn store_verified(&mut self, view: u64, payload: Block) {
        self.sender
            .send(Message::StoreVerified { view, payload })
            .await
            .expect("Failed to send lock");
    }
}

impl Reporter for Mailbox {
    type Activity = Activity;

    async fn report(&mut self, activity: Self::Activity) {
        // leaving all possible activity branches just for now. I think the only one we need to care about is finalization
        // we possibly might need to care about notarization but I will need to look into simplex a bit more to know for sure
        match activity {
            Activity::Notarize(notarize) => {
                // When a single node notarizes a proposal
                debug!("Notarize Activity for view {}", notarize.proposal.view);
            }
            Activity::Notarization(notarization) => {
                // when a quorum of nodes nortarized a proposal
                debug!(
                    "Notarization Activity for view {}",
                    notarization.proposal.view
                );

                let _ = self.sender.send(Message::Notarize { notarization }).await;
            }
            Activity::Nullify(nullify) => {
                // single node votes to skip a view
                debug!("Nullify Activity for view {}", nullify.view);
            }
            Activity::Nullification(nullification) => {
                // a quorum of nodes vote to skip a view
                debug!("Nullification Activity for view {}", nullification.view);
            }
            Activity::Finalize(finalize) => {
                // a single validator finalizes a proposal
                debug!("Finalize Activity for view {}", finalize.proposal.view);
            }
            Activity::Finalization(finalization) => {
                // a quorum of validators finalize a proposal
                debug!(
                    "Finalization Activity for view {}",
                    finalization.proposal.view
                );

                // Simplex checks the signature before here so we shouldnt have to
                let _ = self.sender.send(Message::Finalize { finalization }).await;
            }
            Activity::ConflictingNotarize(conflicting_notarize) => {
                // Evidence byzantine behavior
                debug!(
                    "Conflicting Notarize Activity for view {}",
                    conflicting_notarize.view
                );
            }
            Activity::ConflictingFinalize(conflicting_finalize) => {
                // evidence of byzantine behavior
                debug!(
                    "Conflicting Finalize Activity for view {}",
                    conflicting_finalize.view
                );
            }
            Activity::NullifyFinalize(nullify_finalize) => {
                // evidence of byzantine behavior
                debug!(
                    "Nullify Finalize Activity for view {}",
                    nullify_finalize.proposal.view
                );
            }
        }
    }
}

/// Enum representing the different types of messages that the `Finalizer` loop
/// can send to the inner actor loop.
///
/// We break this into a separate enum to establish a separate priority for consensus messages.
pub enum Orchestration {
    Get {
        next: u64,
        result: oneshot::Sender<Option<Block>>,
    },
    Processed {
        next: u64,
        digest: Digest,
    },
    Repair {
        next: u64,
        result: oneshot::Sender<bool>,
    },
}

#[derive(Clone)]
pub struct Orchestrator {
    sender: mpsc::Sender<Orchestration>,
}

impl Orchestrator {
    pub fn new(sender: mpsc::Sender<Orchestration>) -> Self {
        Self { sender }
    }

    pub async fn get(&mut self, next: u64) -> Option<Block> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Orchestration::Get {
                next,
                result: response,
            })
            .await
            .expect("Failed to send get");
        receiver.await.unwrap()
    }

    pub async fn processed(&mut self, next: u64, digest: Digest) {
        self.sender
            .send(Orchestration::Processed { next, digest })
            .await
            .expect("Failed to send processed");
    }

    pub async fn repair(&mut self, next: u64) -> bool {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Orchestration::Repair {
                next,
                result: response,
            })
            .await
            .expect("Failed to send repair");
        receiver.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::mpsc;
    use summit_types::Block;

    fn create_test_block() -> Block {
        Block::genesis([42u8; 32])
    }

    #[test]
    fn test_mailbox_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let mailbox = Mailbox::new(tx);
        // Test passes if we can create a mailbox without panicking
        drop(mailbox);
    }

    #[test]
    fn test_orchestrator_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let orchestrator = Orchestrator::new(tx);
        // Test passes if we can create an orchestrator without panicking
        drop(orchestrator);
    }

    #[test]
    fn test_digest_type_compatibility() {
        let block = create_test_block();
        let digest = block.digest;
        // Verify digest type is compatible with our Digest type alias
        let _: Digest = digest;
    }
}
