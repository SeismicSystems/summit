//! Opaque resolver: backfills syncer data from untrusted sources instead of p2p peers.
//!
//! As [`super::p2p`] wraps commonware's p2p resolver, this module wraps
//! commonware's [`opaque`] resolver, which fetches through an application
//! provided fetcher instead of the p2p network.
//!
//! A follower that is not in any summit peer set cannot use
//! [`super::p2p`], because commonware's authenticated p2p only admits keys in a
//! tracked peer set. This resolver carries the same requests over any
//! request/response transport (an HTTP or JSON-RPC endpoint on a node, or a
//! cache in front of one) behind the [`Source`] trait.
//!
//! The contract is the p2p resolver's, unchanged: the request is a [`Key`]
//! and the response is whatever the serving node's
//! [`Producer`](commonware_resolver::p2p::Producer) returns for it. For
//! `Key::Finalized { height }` that is `(Finalization, Block)`. Sources are
//! untrusted: every response goes through the syncer's handler, which checks
//! the finalization against the epoch's validator set exactly as it does for a
//! p2p peer's reply.
//!
//! Coalescing, retries, retain, and delivery bookkeeping are commonware's
//! [`opaque`] resolver. This module only picks a source for each attempt and
//! bounds how long that source may take.
//!
//! Each attempt goes to a source picked at random. The fetcher can't tell a
//! retry from a first attempt, so it can't rotate per key, and rotating
//! through one counter shared by every key lets concurrent fetches line up so
//! that a key's retries keep landing on the same source. A random pick reaches
//! an honest source within a few attempts whatever else is in flight.

use crate::ingress::handler::{Annotation, Handler, Key};
use bytes::Bytes;
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_resolver::opaque::{self, Fetcher};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::vec::NonEmptyVec;
use rand::{Rng, RngExt as _, SeedableRng as _, rngs::StdRng};
use std::{
    future::Future,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::debug;

/// An untrusted place to fetch resolver values from.
pub trait Source<D: Digest>: Clone + Send + Sync + 'static {
    /// Fetch the encoded value for a resolver key, or `None` if the source
    /// doesn't have it or can't be reached. The resolver gives up on a call
    /// after [`Config::timeout`], so implementations needn't bound it.
    fn get(&self, key: Key<D>) -> impl Future<Output = Option<Bytes>> + Send;
}

/// Configuration for the opaque resolver.
pub struct Config<S> {
    /// Sources, one picked at random for every attempt.
    pub sources: NonEmptyVec<S>,
    /// How long one source may take to answer before the attempt fails.
    pub timeout: Duration,
    /// Wait before retrying a key whose attempt failed or was rejected.
    pub fetch_retry_timeout: Duration,
    /// The size of the request mailbox backlog.
    pub mailbox_size: NonZeroUsize,
}

/// Mailbox for issuing syncer backfill requests, in place of [`super::p2p::Mailbox`].
pub type Mailbox<D, P> = opaque::Resolver<Key<D>, Annotation, P>;

/// Initialize an opaque resolver that delivers through `handler`.
///
/// As with [`super::p2p::init`], the handler comes from
/// [`crate::ingress::handler::init`], whose receiver goes to the syncer.
pub fn init<E, S, D, P>(mut context: E, config: Config<S>, handler: Handler<D>) -> Mailbox<D, P>
where
    E: Spawner + Clock + Metrics + Rng,
    S: Source<D>,
    D: Digest,
    P: PublicKey,
{
    let fetcher = Sources {
        inner: Arc::new(Inner {
            clock: context.child("fetcher"),
            sources: config.sources,
            rng: Mutex::new(StdRng::from_rng(&mut context)),
            timeout: config.timeout,
        }),
        _digest: PhantomData,
    };
    opaque::init(
        context.child("resolver"),
        fetcher,
        handler,
        config.mailbox_size,
        config.fetch_retry_timeout,
    )
}

struct Inner<E, S> {
    clock: E,
    sources: NonEmptyVec<S>,
    /// Picks the source for each attempt.
    rng: Mutex<StdRng>,
    timeout: Duration,
}

/// The [`Fetcher`] handed to the opaque resolver, cloned for every attempt.
struct Sources<E, S, D> {
    inner: Arc<Inner<E, S>>,
    _digest: PhantomData<fn() -> D>,
}

impl<E, S, D> Clone for Sources<E, S, D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _digest: PhantomData,
        }
    }
}

impl<E: Clock, S: Source<D>, D: Digest> Fetcher for Sources<E, S, D> {
    type Key = Key<D>;
    type Value = Bytes;

    fn fetch(&self, key: Key<D>) -> impl Future<Output = Option<Bytes>> + Send {
        // The fetcher never learns which replies the syncer rejected, so it
        // picks a source at random on every attempt: a retry after a forged,
        // missing, or late reply has the same chance as any attempt of
        // reaching an honest source.
        let index = self
            .inner
            .rng
            .lock()
            .expect("source rng lock poisoned")
            .random_range(0..self.inner.sources.len().get());
        let source = self.inner.sources[index].clone();
        let deadline = self.inner.clock.sleep(self.inner.timeout);
        async move {
            select! {
                value = source.get(key) => {
                    if value.is_none() {
                        debug!(%key, source = index, "source had no value");
                    }
                    value
                },
                _ = deadline => {
                    debug!(%key, source = index, "source timed out");
                    None
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::handler::{self, Finalized, Message};
    use commonware_actor::Feedback;
    use commonware_consensus::types::Height;
    use commonware_cryptography::{ed25519, sha256::Digest as Sha256Digest};
    use commonware_resolver::{Fetch, Resolver as _, TargetedResolver};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, non_empty_vec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    type D = Sha256Digest;

    const VALID: &[u8] = b"finalization+block";

    /// The syncer's own bound on its resolver, from `Actor::start`. If this
    /// compiles, the opaque mailbox drops in where the p2p mailbox goes.
    fn accepted_by_syncer<
        R: TargetedResolver<Key = Key<D>, Subscriber = Annotation, PublicKey = ed25519::PublicKey>,
    >() {
    }

    #[test]
    fn opaque_mailbox_satisfies_the_syncer_bound() {
        accepted_by_syncer::<Mailbox<D, ed25519::PublicKey>>();
    }

    /// A source that answers every request with the same bytes, or never
    /// answers when `reply` is `None`, and counts requests.
    #[derive(Clone)]
    struct Fixed {
        reply: Option<Bytes>,
        calls: Arc<AtomicUsize>,
    }

    impl Fixed {
        fn new(reply: Option<&'static [u8]>) -> Self {
            Self {
                reply: reply.map(Bytes::from_static),
                calls: Arc::default(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl<D: Digest> Source<D> for Fixed {
        async fn get(&self, _key: Key<D>) -> Option<Bytes> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.reply {
                Some(reply) => Some(reply.clone()),
                None => futures::future::pending().await,
            }
        }
    }

    /// Seeds each test sweeps, so random source picks cover both orders.
    const SEEDS: u64 = 16;

    /// Fetch finalized heights `0..keys` at once through an opaque resolver
    /// over `sources`, standing in for the syncer: reject every reply but
    /// [`VALID`]. Returns each key's verdicts in delivery order, once every
    /// key has had one accepted.
    fn fetch_until_valid(seed: u64, sources: NonEmptyVec<Fixed>, keys: u64) -> Vec<Vec<bool>> {
        let config = deterministic::Config::default().with_seed(seed);
        deterministic::Runner::from(config).start(|context| async move {
            let (mut receiver, handler) = handler::init(context.child("handler"), NZUsize!(16));
            let mut mailbox = init::<_, _, D, ed25519::PublicKey>(
                context.child("opaque"),
                Config {
                    sources,
                    timeout: Duration::from_secs(1),
                    fetch_retry_timeout: Duration::from_secs(1),
                    mailbox_size: NZUsize!(16),
                },
                handler,
            );

            // One message, so every key is in flight at once.
            let fetches = (0..keys)
                .map(|height| Fetch {
                    key: Key::<D>::Finalized { height },
                    subscriber: Annotation::Finalized(Finalized::ByHeight {
                        height: Height::new(height),
                    }),
                    span: tracing::Span::none(),
                })
                .collect();
            assert_eq!(mailbox.fetch_all(fetches), Feedback::Ok);

            let mut verdicts = vec![Vec::new(); keys as usize];
            while verdicts.iter().any(|key| key.last() != Some(&true)) {
                let Some(Message::Deliver {
                    delivery,
                    value,
                    response,
                }) = receiver.recv().await
                else {
                    panic!("expected a delivery");
                };
                let Key::Finalized { height } = delivery.key else {
                    panic!("expected a finalized key");
                };
                assert_eq!(
                    delivery.subscribers.first().0,
                    Annotation::Finalized(Finalized::ByHeight {
                        height: Height::new(height),
                    })
                );
                let valid = value.as_ref() == VALID;
                let _ = response.send(valid);
                verdicts[height as usize].push(valid);
            }
            verdicts
        })
    }

    #[test]
    fn invalid_reply_moves_the_key_on_until_an_honest_source_answers() {
        let mut forged = 0;
        for seed in 0..SEEDS {
            let bad = Fixed::new(Some(b"forged"));
            let good = Fixed::new(Some(VALID));

            let [verdicts] = <[_; 1]>::try_from(fetch_until_valid(
                seed,
                non_empty_vec![bad.clone(), good.clone()],
                1,
            ))
            .unwrap();

            // Every forged reply is rejected, and the first honest one ends it.
            let (accepted, rejected) = verdicts.split_last().unwrap();
            assert!(*accepted, "seed {seed}");
            assert!(rejected.iter().all(|valid| !valid), "seed {seed}");
            assert_eq!(bad.calls(), rejected.len(), "seed {seed}");
            assert_eq!(good.calls(), 1, "seed {seed}");
            forged += bad.calls();
        }
        assert!(forged > 0, "no seed asked the forging source");
    }

    #[test]
    fn hanging_source_times_out_and_the_key_moves_on() {
        let mut timed_out = 0;
        for seed in 0..SEEDS {
            let hanging = Fixed::new(None);
            let good = Fixed::new(Some(VALID));

            let verdicts =
                fetch_until_valid(seed, non_empty_vec![hanging.clone(), good.clone()], 1);

            // A timeout delivers nothing; the key retries until good answers.
            assert_eq!(verdicts, vec![vec![true]], "seed {seed}");
            assert_eq!(good.calls(), 1, "seed {seed}");
            timed_out += hanging.calls();
        }
        assert!(timed_out > 0, "no seed asked the hanging source");
    }

    #[test]
    fn every_key_reaches_the_honest_source_while_others_are_in_flight() {
        // Many keys retrying together share the source picks: each must still
        // reach the honest source, whatever the others draw.
        let keys = 64;
        let bad = Fixed::new(Some(b"forged"));
        let good = Fixed::new(Some(VALID));

        let verdicts = fetch_until_valid(0, non_empty_vec![bad.clone(), good.clone()], keys);

        assert!(verdicts.iter().all(|key| key.last() == Some(&true)));
        assert_eq!(good.calls(), keys as usize);
        assert!(bad.calls() > 0);
    }
}
