use commonware_resolver::p2p;
use commonware_utils::Array;

#[derive(Clone)]
pub struct Coordinator<P: Array> {
    participants: Vec<P>,
}

impl<P: commonware_cryptography::PublicKey> Coordinator<P> {
    pub fn new(participants: Vec<P>) -> Self {
        Self { participants }
    }
}

impl<P: commonware_cryptography::PublicKey> p2p::Coordinator for Coordinator<P> {
    type PublicKey = P;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        &self.participants
    }

    fn peer_set_id(&self) -> u64 {
        0
    }
}
