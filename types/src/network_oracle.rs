use commonware_cryptography::PublicKey;
use commonware_p2p::{
    Blocker, Manager, PeerSetUpdate, Provider, TrackedPeers, authenticated::discovery::Oracle,
};
use commonware_utils::ordered::Set as OrderedSet;
use std::future::Future;
use tokio::sync::mpsc::UnboundedReceiver;

pub trait NetworkOracle<C: PublicKey>: Send + Sync + 'static {
    fn track(&mut self, index: u64, peers: Vec<C>) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Debug)]
pub struct DiscoveryOracle<C: PublicKey> {
    oracle: Oracle<C>,
}

impl<C: PublicKey> DiscoveryOracle<C> {
    pub fn new(oracle: Oracle<C>) -> Self {
        Self { oracle }
    }
}

impl<C: PublicKey> NetworkOracle<C> for DiscoveryOracle<C> {
    async fn track(&mut self, index: u64, peers: Vec<C>) {
        let primary = OrderedSet::from_iter_dedup(peers);
        let secondary = OrderedSet::default();
        self.oracle
            .track(index, TrackedPeers::new(primary, secondary))
            .await;
    }
}

impl<C: PublicKey> Blocker for DiscoveryOracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        self.oracle.block(public_key).await
    }
}

impl<C: PublicKey> Provider for DiscoveryOracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<PeerSetUpdate<Self::PublicKey>> {
        self.oracle.subscribe().await
    }
}

impl<C: PublicKey> Manager for DiscoveryOracle<C> {
    async fn track<R>(&mut self, id: u64, peers: R)
    where
        R: Into<TrackedPeers<Self::PublicKey>> + Send,
    {
        self.oracle.track(id, peers).await
    }
}
