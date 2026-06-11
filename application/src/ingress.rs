use commonware_consensus::types::{Epoch, Round};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay,
    simplex::{Plan, types::Context},
    types::View,
};
use commonware_cryptography::PublicKey;
use commonware_cryptography::sha256::Digest;
use commonware_utils::channel::{mpsc, oneshot};

pub enum Message<P: PublicKey> {
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
        plan: Plan<P>,
    },
    Verify {
        round: Round,
        parent: (View, Digest),
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
    Certify {
        round: Round,
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
}

#[derive(Clone)]
pub struct Mailbox<P: PublicKey> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: PublicKey> Mailbox<P> {
    pub fn new(sender: mpsc::Sender<Message<P>>) -> Self {
        Self { sender }
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

impl<P: PublicKey> CertifiableAutomaton for Mailbox<P> {
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Certify {
                round,
                payload,
                response,
            })
            .await
            .expect("Failed to send certify");
        receiver
    }
}

impl<P: PublicKey> Relay for Mailbox<P> {
    type Digest = Digest;
    type PublicKey = P;
    type Plan = commonware_consensus::simplex::Plan<P>;

    async fn broadcast(&mut self, digest: Self::Digest, plan: Self::Plan) {
        self.sender
            .send(Message::Broadcast {
                payload: digest,
                plan,
            })
            .await
            .expect("Failed to send broadcast");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{Hasher as _, Signer as _, ed25519, sha256::Sha256};

    fn test_public_key(seed: u8) -> ed25519::PublicKey {
        ed25519::PrivateKey::decode([seed; 32].as_ref())
            .unwrap()
            .public_key()
    }

    /// Regression test for the relay dropping Commonware's broadcast identity:
    /// the requested digest and the full `Plan` (including `Plan::Forward`'s
    /// round and peer targets) must survive into `Message::Broadcast` so the
    /// actor can serve targeted forwarding to silent voters.
    #[test]
    fn test_broadcast_preserves_digest_and_plan() {
        futures::executor::block_on(async {
            let (tx, mut rx) = mpsc::channel(4);
            let mut mailbox = Mailbox::<ed25519::PublicKey>::new(tx);

            let digest = Sha256::hash(b"proposal");
            let round = Round::new(Epoch::new(3), View::new(7));
            let peers = vec![test_public_key(1), test_public_key(2)];

            mailbox
                .broadcast(
                    digest,
                    Plan::Forward {
                        round,
                        peers: peers.clone(),
                    },
                )
                .await;
            let Some(Message::Broadcast { payload, plan }) = rx.recv().await else {
                panic!("expected a Broadcast message");
            };
            assert_eq!(payload, digest);
            match plan {
                Plan::Forward {
                    round: got_round,
                    peers: got_peers,
                } => {
                    assert_eq!(got_round, round);
                    assert_eq!(got_peers, peers);
                }
                Plan::Propose => panic!("Plan::Forward was lost in the relay"),
            }

            mailbox.broadcast(digest, Plan::Propose).await;
            let Some(Message::Broadcast { payload, plan }) = rx.recv().await else {
                panic!("expected a Broadcast message");
            };
            assert_eq!(payload, digest);
            assert!(matches!(plan, Plan::Propose));
        });
    }
}
