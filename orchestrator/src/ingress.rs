//! Inbound communication channel for epoch transitions.

use commonware_consensus::{Reporter, types::Epoch};
use futures::{SinkExt, channel::mpsc};
use summit_types::scheme::EpochTransition;

/// Messages that can be sent to the orchestrator.
pub enum Message {
    Enter(EpochTransition),
    Exit(Epoch),
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = Message;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
