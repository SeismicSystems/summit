use commonware_actor::Feedback;
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    Blocker, Manager, PeerSetSubscription, Provider, TrackedPeers, authenticated::discovery::Oracle,
};
use commonware_utils::ordered::Set as OrderedSet;
use std::future::Future;

pub trait NetworkOracle<C: PublicKey>: Send + Sync + 'static {
    fn track(
        &mut self,
        index: u64,
        primary: Vec<C>,
        secondary: Vec<C>,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug)]
pub struct DiscoveryOracle<C: PublicKey> {
    oracle: Oracle<C>,
    local: C,
    capacity: std::num::NonZeroUsize,
}

impl<C: PublicKey> DiscoveryOracle<C> {
    pub fn new(oracle: Oracle<C>, local: C, capacity: std::num::NonZeroUsize) -> Self {
        Self {
            oracle,
            local,
            capacity,
        }
    }

    fn check_capacity<'a>(
        local: &'a C,
        capacity: std::num::NonZeroUsize,
        primary: impl Iterator<Item = &'a C>,
        secondary: impl Iterator<Item = &'a C>,
    ) {
        let identities: std::collections::BTreeSet<_> = primary
            .chain(secondary)
            .chain(std::iter::once(local))
            .collect();
        assert!(
            identities.len() <= capacity.get(),
            "peer set requires {} identities but startup capacity is {}; capacity-exceeding updates are unsupported in this deployment",
            identities.len(),
            capacity
        );
    }
}

impl<C: PublicKey> NetworkOracle<C> for DiscoveryOracle<C> {
    async fn track(&mut self, index: u64, primary: Vec<C>, secondary: Vec<C>) {
        Self::check_capacity(&self.local, self.capacity, primary.iter(), secondary.iter());
        let primary = OrderedSet::from_iter_dedup(primary);
        let secondary = OrderedSet::from_iter_dedup(secondary);
        let _ = self
            .oracle
            .track(index, TrackedPeers::new(primary, secondary));
    }
}

impl<C: PublicKey> Blocker for DiscoveryOracle<C> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        self.oracle.block(public_key)
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        self.oracle.blocked()
    }
}

impl<C: PublicKey> Provider for DiscoveryOracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        self.oracle.subscribe().await
    }
}

impl<C: PublicKey> Manager for DiscoveryOracle<C> {
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<Self::PublicKey>> + Send,
    {
        let peers = peers.into();
        Self::check_capacity(
            &self.local,
            self.capacity,
            peers.primary.iter(),
            peers.secondary.iter(),
        );
        self.oracle.track(id, peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_utils::NZUsize;

    fn keys() -> [ed25519::PublicKey; 3] {
        std::array::from_fn(|seed| ed25519::PrivateKey::from_seed(seed as u64).public_key())
    }

    #[test]
    fn capacity_deduplicates_primary_secondary_and_local_identity() {
        let [local, primary, observer] = keys();
        DiscoveryOracle::check_capacity(
            &local,
            NZUsize!(3),
            [&local, &primary].into_iter(),
            [&primary, &observer].into_iter(),
        );
        // The local node can be outside both sets (e.g. a joining validator).
        DiscoveryOracle::check_capacity(
            &local,
            NZUsize!(3),
            [&primary].into_iter(),
            [&observer].into_iter(),
        );
    }

    #[test]
    #[should_panic(expected = "peer set requires 3 identities but startup capacity is 2")]
    fn capacity_counts_offline_authorized_observers_and_unlisted_local_identity() {
        let [local, primary, offline_observer] = keys();
        DiscoveryOracle::check_capacity(
            &local,
            NZUsize!(2),
            [&primary].into_iter(),
            [&offline_observer].into_iter(),
        );
    }
}
