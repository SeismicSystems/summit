//! Inbound communication channel for epoch transitions.

use commonware_actor::Feedback;
use commonware_consensus::{Reporter, types::Epoch};
use futures::channel::mpsc;
use summit_types::scheme::EpochTransition;

/// Messages that can be sent to the orchestrator.
pub enum Message {
    Enter(EpochTransition),
    Exit(Epoch),
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox {
    sender: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::UnboundedSender<Message>) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = Message;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.sender
            .unbounded_send(activity)
            .expect("failed to send epoch transition");
        Feedback::Ok
    }
}
