//! Follow mode: a node with no P2P identity follows the chain from validators'
//! RPC, through the opaque resolver and the follow driver.

use crate::engine::Engine;
use crate::follow::{FollowSource, NullOracle};
use crate::test_harness::common::{
    self, DEFAULT_BLOCKS_PER_EPOCH, SimulatedOracle, get_default_engine_config, get_initial_state,
};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use bytes::Bytes;
use commonware_cryptography::{Signer, bls12381};
use commonware_formatting::from_hex;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::deterministic::{self, Runner};
use commonware_runtime::{Clock, Runner as _, Supervisor as _};
use commonware_utils::{NZUsize, non_empty_vec};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use summit_rpc::{FollowerRpcServer, SummitFollowerApiServer};
use summit_syncer::ingress::handler::Key;
use summit_syncer::resolver::opaque::Source;
use summit_types::{Digest, PrivateKey, keystore::KeyStore};

/// A validator's follower listener, called in process instead of over HTTP.
#[derive(Clone)]
struct InProcess {
    server: FollowerRpcServer,
}

impl Source<Digest> for InProcess {
    async fn get(&self, key: Key<Digest>) -> Option<Bytes> {
        let value = self.server.get_resolver_value(key.into()).await.ok()??;
        Some(value.0)
    }
}

impl FollowSource for InProcess {
    async fn latest_height(&self) -> Option<u64> {
        self.server.get_latest_height().await.ok()
    }
}

/// A source that lies: it answers every finalized height with the genuine
/// reply for the next height, and claims a tip far ahead of the chain.
#[derive(Clone)]
struct Forger {
    inner: InProcess,
    forged: Arc<AtomicUsize>,
}

impl Source<Digest> for Forger {
    async fn get(&self, key: Key<Digest>) -> Option<Bytes> {
        let Key::Finalized { height } = key else {
            return None;
        };
        let reply = self
            .inner
            .get(Key::Finalized { height: height + 1 })
            .await?;
        self.forged.fetch_add(1, Ordering::SeqCst);
        Some(reply)
    }
}

impl FollowSource for Forger {
    async fn latest_height(&self) -> Option<u64> {
        Some(self.inner.latest_height().await? + 1_000)
    }
}

/// Any kind of source, so one follower can mix them. `Silent` has no blocks
/// and never answers for its tip, like a source behind a firewall that drops
/// packets.
#[derive(Clone)]
enum TestSource {
    Honest(InProcess),
    Forger(Forger),
    Silent,
}

impl Source<Digest> for TestSource {
    async fn get(&self, key: Key<Digest>) -> Option<Bytes> {
        match self {
            Self::Honest(source) => source.get(key).await,
            Self::Forger(source) => source.get(key).await,
            Self::Silent => None,
        }
    }
}

impl FollowSource for TestSource {
    async fn latest_height(&self) -> Option<u64> {
        match self {
            Self::Honest(source) => source.latest_height().await,
            Self::Forger(source) => source.latest_height().await,
            Self::Silent => futures::future::pending().await,
        }
    }
}

#[test_traced("INFO")]
fn test_follower_catches_up_from_remote_sources() {
    // Four validators reach the middle of epoch 1. A follower then starts with
    // no P2P registration at all, fetching only from one validator's RPC, a
    // source forging every reply, and a source that never reports its tip. It
    // must execute up to the same tip as the validators, across an epoch
    // boundary, with the same state root.
    let n_validators: u32 = 4;
    let join_height = DEFAULT_BLOCKS_PER_EPOCH + DEFAULT_BLOCKS_PER_EPOCH / 2;
    let stop_height = 3 * DEFAULT_BLOCKS_PER_EPOCH;

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: commonware_utils::probability!(1.0),
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_peers_per_set: NZUsize!(2177),
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(n_validators as usize * 10),
            },
        );
        network.start();

        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n_validators {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            validators.push((node_key.public_key(), consensus_key.public_key()));
            key_stores.push(KeyStore {
                node_key,
                consensus_key,
            });
        }
        validators.sort_by(|a, b| a.0.cmp(&b.0));
        key_stores.sort_by_key(|key_store| key_store.node_key.public_key());
        let validator_pubkeys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();

        let mut registrations = common::register_validators(&oracle, &validator_pubkeys).await;
        common::link_validators(&mut oracle, &validator_pubkeys, link, None).await;

        let genesis_hash: [u8; 32] = from_hex(common::GENESIS_HASH)
            .expect("genesis hash hex")
            .try_into()
            .expect("genesis hash len");
        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        let mut servers = Vec::new();
        let mut finalizers = Vec::new();
        for key_store in key_stores {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            let config = get_default_engine_config(
                engine_client_network.create_client(uid.clone()),
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                String::from("_SUMMIT"),
                key_store,
                validators.clone(),
                initial_state.clone(),
            );
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            servers.push(FollowerRpcServer::new(
                engine.resolver_handler(),
                engine.finalizer_state_query.clone(),
            ));
            finalizers.push(engine.finalizer_mailbox.clone());
            let (pending, recovered, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();
            engine.start(pending, recovered, resolver, broadcast, backfill);
        }

        while finalizers[0].get_latest_height().await < join_height {
            context.sleep(Duration::from_millis(100)).await;
        }

        // The follower: no P2P registration, throwaway keys, verifier only.
        let forged = Arc::new(AtomicUsize::new(0));
        let sources = non_empty_vec![
            TestSource::Forger(Forger {
                inner: InProcess {
                    server: servers[1].clone(),
                },
                forged: forged.clone(),
            }),
            TestSource::Honest(InProcess {
                server: servers[0].clone(),
            }),
            TestSource::Silent,
        ];
        let uid = String::from("follower");
        let mut config = get_default_engine_config(
            engine_client_network.create_client(uid.clone()),
            NullOracle::default(),
            uid.clone(),
            genesis_hash,
            String::from("_SUMMIT"),
            KeyStore {
                node_key: PrivateKey::random(&mut context),
                consensus_key: bls12381::PrivateKey::random(&mut context),
            },
            validators.clone(),
            initial_state.clone(),
        );
        config.force_verifier_only = true;
        let follower =
            Engine::new(context.child("follower").with_attribute("uid", uid), config).await;
        let follower_finalizer = follower.finalizer_mailbox.clone();
        follower.start_follow(sources);

        while follower_finalizer.get_latest_height().await < stop_height {
            context.sleep(Duration::from_millis(100)).await;
        }

        assert!(
            forged.load(Ordering::SeqCst) > 0,
            "the forger was never asked"
        );
        let (follower_root, follower_block) = follower_finalizer.get_state_root().await;
        for finalizer in &finalizers {
            while finalizer.get_latest_height().await < stop_height {
                context.sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(
                finalizer.get_state_root().await,
                (follower_root, follower_block)
            );
        }
    });
}
