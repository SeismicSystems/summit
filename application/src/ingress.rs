use commonware_consensus::{Automaton, Relay, simplex::types::Context, types::View, Epochable};
use commonware_consensus::types::{Epoch, Round};
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::Signer;
use futures::{
    SinkExt,
    channel::{mpsc, oneshot},
};

pub enum Message {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<Digest>,
    },
    Propose {
        round: Round,
        parent: (View, Digest),
        response: oneshot::Sender<Digest>,
    },
    Broadcast {
        payload: Digest,
    },
    Verify {
        round: Round,
        parent: (View, Digest),
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
}

#[derive(Clone)]
pub struct Mailbox<C: Signer> {
    sender: mpsc::Sender<Message>,
}

impl<C: Signer> Mailbox<C> {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl<C: Signer> Automaton for Mailbox<C> {
    type Context = Context<Self::Digest, C>;
    type Digest = Digest;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response, epoch })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context<Self::Digest, C>) -> oneshot::Receiver<Self::Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose {
                round: context.round,
                parent: context.parent,
                response,
            })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest, C>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
                round: context.round,
                parent: context.parent,
                payload,
                response,
            })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl<C: Signer> Relay for Mailbox<C> {
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        self.sender
            .send(Message::Broadcast { payload: digest })
            .await
            .expect("Failed to send broadcast");
    }
}
