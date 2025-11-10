//! Inbound communication channel for epoch transitions.

use commonware_consensus::{Reporter, types::Epoch};
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use futures::{SinkExt, channel::mpsc};
use summit_types::scheme::EpochTransition;

/// Messages that can be sent to the orchestrator.
pub enum Message<V: Variant, P: PublicKey> {
    Enter(EpochTransition),
    Exit(Epoch),
    _Phantom(std::marker::PhantomData<V>, std::marker::PhantomData<P>),
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, P: PublicKey> {
    sender: mpsc::Sender<Message<V, P>>,
}

impl<V: Variant, P: PublicKey> Mailbox<V, P> {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::Sender<Message<V, P>>) -> Self {
        Self { sender }
    }
}

impl<V: Variant, P: PublicKey> Reporter for Mailbox<V, P> {
    type Activity = Message<V, P>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
