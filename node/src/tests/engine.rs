//! Engine-level configuration and supervision tests.

use crate::engine::Engine;
use crate::test_harness::common::{
    GENESIS_HASH, SimulatedOracle, get_default_engine_config, get_initial_state,
    register_validators,
};
use crate::test_harness::mock_engine_client::MockEngineNetwork;
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::{Signer, bls12381};
use commonware_formatting::from_hex;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::{
    CheckedSender, LimitedSender, Message, Receiver, Recipients,
    simulated::{self, Network},
};
use commonware_runtime::Supervisor as _;
use commonware_runtime::{
    Clock, IoBufs, Runner as _,
    deterministic::{self, Runner},
};
use commonware_utils::NZUsize;
use futures::FutureExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::{Duration, SystemTime};
use summit_types::keystore::KeyStore;
use summit_types::{PrivateKey, PublicKey};

/// Regression test: the backfill resolver must inherit
/// [`EngineConfig::fetch_timeout`](crate::config::EngineConfig::fetch_timeout) instead of
/// hard-coding its active-request timeout. Commonware's resolver drops in-flight requests
/// when the timeout fires and discards responses that arrive afterwards, so a hard-coded
/// timeout shorter than the configured one prevents catching up from valid finalized
/// history under slow storage/network conditions.
#[test_traced("INFO")]
fn test_backfill_resolver_inherits_fetch_timeout() {
    let executor = Runner::from(deterministic::Config::default());
    executor.start(|context| async move {
        let (network, oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(10),
            },
        );
        network.start();

        let mut rng = StdRng::seed_from_u64(0);
        let node_key = PrivateKey::random(&mut rng);
        let consensus_key = bls12381::PrivateKey::random(&mut rng);
        let validators = vec![(node_key.public_key(), consensus_key.public_key())];
        let key_store = KeyStore {
            node_key,
            consensus_key,
        };

        let genesis_hash: [u8; 32] = from_hex(GENESIS_HASH)
            .expect("failed to decode genesis hash")
            .try_into()
            .expect("failed to convert genesis hash");
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        let engine_client =
            MockEngineNetwork::new(genesis_hash, None).create_client("engine_config_test".into());

        let mut config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle),
            "engine_config_test".into(),
            genesis_hash,
            "_SUMMIT".into(),
            key_store,
            validators,
            initial_state,
        );
        let fetch_timeout = Duration::from_secs(7);
        config.fetch_timeout = fetch_timeout;

        let engine = Engine::new(context.child("engine"), config).await;
        let resolver_config = engine.backfill_resolver_config();
        assert_eq!(resolver_config.timeout, fetch_timeout);
    });
}

/// A backfill sender whose sends silently reach nobody.
#[derive(Clone, Debug)]
struct DeadBackfillSender;

struct DeadBackfillCheckedSender;

impl CheckedSender for DeadBackfillCheckedSender {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<PublicKey> {
        Vec::new()
    }

    fn send(self, _message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        Unreliable::Outcome(Feedback::Ok)
    }
}

impl LimitedSender for DeadBackfillSender {
    type PublicKey = PublicKey;
    type Checked<'a> = DeadBackfillCheckedSender;

    fn check(
        &mut self,
        _recipients: Recipients<PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(DeadBackfillCheckedSender)
    }
}

/// A backfill receiver that fails on the first `recv`, killing the resolver engine.
#[derive(Debug)]
struct ClosedBackfillReceiver;

impl Receiver for ClosedBackfillReceiver {
    type Error = std::io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<PublicKey>, Self::Error> {
        Err(std::io::Error::other("backfill network closed"))
    }
}

/// A single tracked actor exiting cleanly while its siblings keep running must
/// surface as an engine failure.
///
/// The failing backfill receiver makes the (untracked) commonware resolver engine exit
/// ("receiver closed"), which drops the handler channel into the syncer, so the syncer
/// clean-returns ("handler closed, shutting down") — one of five tracked actors dead
/// while application, buffer, finalizer, and orchestrator keep running. `try_join_all`
/// only resolves early on `Err` (panic/abort), so the engine handle stays pending and
/// the node lingers half-alive instead of coming down for restart.
#[test_traced("INFO")]
fn test_engine_detects_single_actor_clean_exit() {
    let executor = Runner::from(deterministic::Config::default());
    executor.start(|context| async move {
        let (network, oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(10),
            },
        );
        network.start();

        let mut rng = StdRng::seed_from_u64(0);
        let node_key = PrivateKey::random(&mut rng);
        let node_public_key = node_key.public_key();
        let consensus_key = bls12381::PrivateKey::random(&mut rng);
        let validators = vec![(node_public_key.clone(), consensus_key.public_key())];
        let key_store = KeyStore {
            node_key,
            consensus_key,
        };

        let mut registrations =
            register_validators(&oracle, std::slice::from_ref(&node_public_key)).await;
        let (pending, recovered, resolver, broadcast, _backfill) =
            registrations.remove(&node_public_key).unwrap();

        let genesis_hash: [u8; 32] = from_hex(GENESIS_HASH)
            .expect("failed to decode genesis hash")
            .try_into()
            .expect("failed to convert genesis hash");
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        let engine_client =
            MockEngineNetwork::new(genesis_hash, None).create_client("single_actor_exit".into());

        let config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle),
            "single_actor_exit".into(),
            genesis_hash,
            "_SUMMIT".into(),
            key_store,
            validators,
            initial_state,
        );

        let engine = Engine::new(context.child("engine"), config).await;
        let engine_handle = engine.start(
            pending,
            recovered,
            resolver,
            broadcast,
            (DeadBackfillSender, ClosedBackfillReceiver),
        );

        let engine_fut = engine_handle.fuse();
        let timeout = context.sleep(Duration::from_secs(120)).fuse();
        futures::pin_mut!(engine_fut, timeout);
        futures::select! {
            outcome = engine_fut => {
                let result = outcome.expect("engine task must not panic");
                assert!(
                    result.is_err(),
                    "an uncoordinated actor exit must surface as an engine error, got {result:?}"
                );
            }
            _ = timeout => panic!(
                "engine ignored the dead syncer for 120s and stayed half-alive (#360)"
            ),
        }
    });
}
