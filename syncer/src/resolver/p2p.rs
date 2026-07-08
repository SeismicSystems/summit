//! P2P resolver initialization and config.

use crate::ingress::handler::{self, Annotation, Key, Receiver as HandlerReceiver};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, PublicKey};
use commonware_p2p::{Blocker, Provider, Receiver as P2pReceiver, Sender};
use commonware_resolver::p2p;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the P2P [Resolver](commonware_resolver::Resolver).
pub struct Config<P: PublicKey, C: Provider<PublicKey = P>, B: Blocker<PublicKey = P>> {
    /// The public key to identify this node.
    pub public_key: P,

    /// The provider of peers that can be consulted for fetching data.
    pub provider: C,

    /// The blocker that will be used to block peers that send invalid responses.
    pub blocker: B,

    /// The size of the request mailbox backlog.
    pub mailbox_size: NonZeroUsize,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,

    /// Retry timeout for the fetcher.
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}

/// Mailbox for issuing syncer backfill requests.
pub type Mailbox<D, P> = p2p::Mailbox<Key<D>, P, Annotation>;

/// Initialize a P2P resolver.
pub fn init<E, C, Bl, D, S, R, P>(
    context: E,
    config: Config<P, C, Bl>,
    backfill: (S, R),
) -> (HandlerReceiver<D>, Mailbox<D, P>)
where
    E: BufferPooler + Rng + Spawner + Clock + GClock + Metrics,
    C: Provider<PublicKey = P>,
    Bl: Blocker<PublicKey = P>,
    D: Digest,
    S: Sender<PublicKey = P>,
    R: P2pReceiver<PublicKey = P>,
    P: PublicKey,
{
    let (sender, receiver) = mailbox::new(context.child("handler"), config.mailbox_size);
    let handler = handler::Handler::new(sender);
    let (resolver_engine, resolver) = p2p::Engine::new(
        context.child("resolver"),
        p2p::Config {
            peer_provider: config.provider,
            blocker: config.blocker,
            consumer: handler.clone(),
            producer: handler,
            mailbox_size: config.mailbox_size,
            me: Some(config.public_key),
            initial: config.initial,
            timeout: config.timeout,
            fetch_retry_timeout: config.fetch_retry_timeout,
            priority_requests: config.priority_requests,
            priority_responses: config.priority_responses,
        },
    );
    resolver_engine.start(backfill);
    (HandlerReceiver::new(receiver), resolver)
}
