//! A network that never delivers, for actors a follower runs without P2P.
//!
//! TODO(#481): once the syncer can start without a broadcast buffer, the
//! null channel goes away and [`NullOracle`] shrinks to a no-op `track`.

use commonware_actor::{Feedback, Unreliable};
use commonware_p2p::{
    BlockedSubscription, Blocker, CheckedSender, LimitedSender, PeerSetSubscription, Provider,
    Receiver, Recipients, TrackedPeers,
};
use commonware_runtime::{IoBuf, IoBufs};
use commonware_utils::{
    NZUsize,
    channel::{mpsc, ring},
};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::SystemTime,
};
use summit_types::PublicKey;
use summit_types::network_oracle::NetworkOracle;

/// An oracle with no peers: tracking and blocking do nothing, and no peer set
/// ever arrives.
#[derive(Clone, Debug, Default)]
pub struct NullOracle {
    /// Senders for every peer-set subscription, held so the subscriptions
    /// stay open: commonware's buffered broadcast engine stops when its
    /// subscription closes.
    subscriptions: Arc<Mutex<Vec<mpsc::UnboundedSender<commonware_p2p::PeerSetUpdate<PublicKey>>>>>,
}

impl NetworkOracle<PublicKey> for NullOracle {
    async fn track(&mut self, _: u64, _: Vec<PublicKey>, _: Vec<PublicKey>) {}
}

impl Blocker for NullOracle {
    type PublicKey = PublicKey;

    fn block(&mut self, _: PublicKey) -> Feedback {
        Feedback::Ok
    }

    fn blocked(&mut self) -> BlockedSubscription<PublicKey> {
        ring::channel(NZUsize!(1)).1
    }
}

impl Provider for NullOracle {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, _: u64) -> Option<TrackedPeers<PublicKey>> {
        None
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<PublicKey> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.subscriptions
            .lock()
            .expect("subscriptions lock poisoned")
            .push(sender);
        receiver
    }
}

/// A channel that accepts every message and delivers none.
pub fn channel() -> (NullSender, NullReceiver) {
    (NullSender, NullReceiver)
}

#[derive(Clone, Debug)]
pub struct NullSender;

#[derive(Debug)]
pub struct NullCheckedSender;

#[derive(Debug)]
pub struct NullReceiver;

impl LimitedSender for NullSender {
    type PublicKey = PublicKey;
    type Checked<'a> = NullCheckedSender;

    fn check(&mut self, _: Recipients<PublicKey>) -> Result<NullCheckedSender, SystemTime> {
        Ok(NullCheckedSender)
    }
}

impl CheckedSender for NullCheckedSender {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<PublicKey> {
        Vec::new()
    }

    fn send(self, _: impl Into<IoBufs> + Send, _: bool) -> Unreliable<Feedback> {
        Unreliable::new(Feedback::Ok)
    }
}

impl Receiver for NullReceiver {
    type Error = Infallible;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<(PublicKey, IoBuf), Infallible> {
        futures::future::pending().await
    }
}
