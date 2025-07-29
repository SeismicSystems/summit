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

#[cfg(test)]
mod tests {
    use crate::coordinator::Coordinator;
    use commonware_resolver::p2p::Coordinator as P2PCoordinator;
    use summit_types::PublicKey;

    #[test]
    fn test_coordinator_basic_functionality() {
        // Create some basic coordinators with empty participant lists for testing
        let participants1: Vec<PublicKey> = vec![];
        let participants2: Vec<PublicKey> = vec![];
        
        let coord1 = Coordinator::new(participants1.clone());
        let coord2 = Coordinator::new(participants2);
        
        // Test that it properly implements the p2p::Coordinator trait
        assert_eq!(coord1.peers(), &participants1);
        assert_eq!(coord1.peer_set_id(), 0);
        assert_eq!(coord2.peer_set_id(), 0);
    }
}
