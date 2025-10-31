use commonware_cryptography::PublicKey;
use commonware_p2p::{Manager, authenticated::discovery::Oracle};
use commonware_utils::set::Ordered;

pub trait NetworkOracle<C: PublicKey>: Send + Sync + 'static {
    fn register(&mut self, index: u64, peers: Vec<C>) -> impl Future<Output = ()> + Send;
}

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
