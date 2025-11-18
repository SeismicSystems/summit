use commonware_consensus::types::{Epoch, Round};
use commonware_consensus::{Automaton, Relay, simplex::types::Context, types::View};
use commonware_cryptography::PublicKey;
use commonware_cryptography::sha256::Digest;
use futures::{
    SinkExt,
    channel::{mpsc, oneshot},
};
use std::marker::PhantomData;

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
pub struct Mailbox<P: PublicKey> {
    sender: mpsc::Sender<Message>,
    _signer_marker: PhantomData<P>,
}

impl<P: PublicKey> Mailbox<P> {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self {
            sender,
            _signer_marker: PhantomData,
        }
    }
}

impl<P: PublicKey> Automaton for Mailbox<P> {
    type Context = Context<Self::Digest, P>;
    type Digest = Digest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response, epoch })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(
        &mut self,
        context: Context<Self::Digest, P>,
    ) -> oneshot::Receiver<Self::Digest> {
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
        context: Context<Self::Digest, P>,
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

impl<P: PublicKey> Relay for Mailbox<P> {
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        self.sender
            .send(Message::Broadcast { payload: digest })
            .await
            .expect("Failed to send broadcast");
    }
}
