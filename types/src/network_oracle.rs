use commonware_cryptography::PublicKey;
use commonware_p2p::{Blocker, Manager, authenticated::discovery::Oracle};
use commonware_utils::set::Ordered;
use std::future::Future;

pub trait NetworkOracle<C: PublicKey>: Send + Sync + 'static {
    fn register(&mut self, index: u64, peers: Vec<C>) -> impl Future<Output = ()> + Send;
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
    async fn register(&mut self, index: u64, peers: Vec<C>) {
        self.oracle.update(index, Ordered::from(peers)).await;
    }
}

impl<C: PublicKey> Blocker for DiscoveryOracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        self.oracle.block(public_key).await
    }
}

impl<C: PublicKey> Manager for DiscoveryOracle<C> {
    type PublicKey = C;
    type Peers = Ordered<C>;

    fn update(&mut self, id: u64, peers: Self::Peers) -> impl Future<Output = ()> + Send {
        self.oracle.update(id, peers)
    }

    async fn peer_set(&mut self, id: u64) -> Option<Ordered<Self::PublicKey>> {
        self.oracle.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> futures::channel::mpsc::UnboundedReceiver<(
        u64,
        Ordered<Self::PublicKey>,
        Ordered<Self::PublicKey>,
    )> {
        self.oracle.subscribe().await
    }
}
