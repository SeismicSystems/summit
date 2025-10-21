use commonware_cryptography::PublicKey;
use commonware_p2p::authenticated::discovery::Oracle;
use commonware_runtime::{Metrics, Spawner};

pub trait NetworkOracle<C: PublicKey>: Send + Sync + 'static {
    fn register(&mut self, index: u64, peers: Vec<C>) -> impl Future<Output = ()> + Send;
}

pub struct DiscoveryOracle<E: Spawner + Metrics, C: PublicKey> {
    oracle: Oracle<E, C>,
}

impl<E: Spawner + Metrics, C: PublicKey> DiscoveryOracle<E, C> {
    pub fn new(oracle: Oracle<E, C>) -> Self {
        Self { oracle }
    }
}

impl<E: Spawner + Metrics, C: PublicKey> NetworkOracle<C> for DiscoveryOracle<E, C> {
    async fn register(&mut self, index: u64, peers: Vec<C>) {
        self.oracle.register(index, peers).await;
    }
}
