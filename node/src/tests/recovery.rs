//! Real finalizer + syncer recovery, using the production immutable archives.
use crate::engine::Engine;
use crate::test_harness::common::{
    GENESIS_HASH, SimulatedOracle, get_default_engine_config, get_initial_state, link_validators,
    register_validators,
};
use crate::test_harness::mock_engine_client::{MockEngineClient, MockEngineNetwork};
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, types::Height};
use commonware_cryptography::Signer;
use commonware_formatting::from_hex;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{self, Link, Network, Oracle};
use commonware_runtime::{Clock, Runner as _, Supervisor as _, deterministic};
use commonware_utils::NZUsize;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use summit_finalizer::FinalizerMailbox;
use summit_types::{
    Block, PrivateKey, PublicKey, consensus_state::ConsensusState, keystore::KeyStore,
    scheme::MultisigScheme,
};

const STOP: u64 = 24;

struct Fixture {
    key: KeyStore<PrivateKey>,
    validators: Vec<(PublicKey, commonware_cryptography::bls12381::PublicKey)>,
    genesis: [u8; 32],
    initial: ConsensusState,
    client: MockEngineClient,
    expected_root: ([u8; 32], u64),
}

fn network(context: deterministic::Context) -> Oracle<PublicKey, deterministic::Context> {
    let (network, oracle) = Network::new(
        context,
        simulated::Config {
            max_peers_per_set: NZUsize!(2177),
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(40),
        },
    );
    network.start();
    oracle
}

/// Forward actual blocks/acks to the real finalizer, but hold the replay tail
/// when modelling a second crash. Keeping the updates alive also holds their
/// acknowledgements, rather than accidentally shutting the syncer down.
#[derive(Clone)]
struct ReplayReporter {
    finalizer: FinalizerMailbox<MultisigScheme, Block>,
    through: u64,
    delivered: Arc<Mutex<Vec<u64>>>,
    held: Vec<summit_syncer::Update<Block, MultisigScheme>>,
}

impl Reporter for ReplayReporter {
    type Activity = summit_syncer::Update<Block, MultisigScheme>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let summit_syncer::Update::FinalizedBlock((block, _), _) = &update {
            self.delivered.lock().unwrap().push(block.height());
            if block.height() > self.through {
                self.held.push(update);
                return Feedback::Ok;
            }
        }
        self.finalizer.report(update)
    }
}

#[test_traced("WARN")]
fn mid_epoch_restart_replays_from_finalizer_and_survives_another_crash() {
    let (fixture, recovered) = deterministic::Runner::timed(Duration::from_secs(300))
        .start_and_recover(|context| async move {
            let mut oracle = network(context.child("network"));
            let mut keys: Vec<_> = (0..4)
                .map(|seed| {
                    let mut rng = StdRng::seed_from_u64(seed);
                    KeyStore {
                        node_key: PrivateKey::random(&mut rng),
                        consensus_key: commonware_cryptography::bls12381::PrivateKey::random(
                            &mut rng,
                        ),
                    }
                })
                .collect();
            keys.sort_by_key(|key| key.node_key.public_key());
            let validators: Vec<_> = keys
                .iter()
                .map(|key| (key.node_key.public_key(), key.consensus_key.public_key()))
                .collect();
            let public_keys: Vec<_> = validators.iter().map(|(key, _)| key.clone()).collect();
            let mut registrations = register_validators(&oracle, &public_keys).await;
            link_validators(
                &mut oracle,
                &public_keys,
                Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: commonware_utils::probability!(1.0),
                },
                None,
            )
            .await;
            let genesis: [u8; 32] = from_hex(GENESIS_HASH).unwrap().try_into().unwrap();
            let initial = get_initial_state(genesis, &validators, None, None, 32_000_000_000);
            let clients = MockEngineNetwork::new(genesis, Some(STOP));
            let key = KeyStore {
                node_key: keys[0].node_key.clone(),
                consensus_key: keys[0].consensus_key.clone(),
            };
            let mut primary = None;
            for (index, key) in keys.into_iter().enumerate() {
                let public_key = key.node_key.public_key();
                let uid = format!("recovery_{index}");
                let client = clients.create_client(uid.clone());
                let config = get_default_engine_config(
                    client.clone(),
                    SimulatedOracle::new(oracle.clone()),
                    uid.clone(),
                    genesis,
                    "_SUMMIT".into(),
                    key,
                    validators.clone(),
                    initial.clone(),
                );
                let engine =
                    Engine::new(context.child("engine").with_attribute("uid", uid), config).await;
                assert_eq!(engine.sync_start.height, 0);
                if index == 0 {
                    primary = Some((
                        client,
                        engine.finalizer_mailbox.clone(),
                        engine.syncer_mailbox.clone(),
                    ));
                }
                let (pending, recovered, resolver, broadcast, backfill) =
                    registrations.remove(&public_key).unwrap();
                engine.start(pending, recovered, resolver, broadcast, backfill);
            }
            let (client, finalizer, mut syncer) = primary.unwrap();
            while syncer.get_processed_height().await != Some(Height::new(STOP)) {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(finalizer.get_latest_height().await, STOP);
            assert!(
                syncer.get_block(1u64).await.is_some(),
                "genesis startup must deliver height 1 onward"
            );
            Fixture {
                key,
                validators,
                genesis,
                initial,
                client,
                expected_root: finalizer.get_state_root().await,
            }
        });

    // Runtime recovery drops all actors and reopens only durable storage. The
    // finalizer restores the epoch boundary at 19, behind live acknowledgements
    // at 24. Interrupt this first replay at 22 (still short of a durable boundary).
    let (fixture, recovered) =
        deterministic::Runner::from(recovered).start_and_recover(|context| async move {
            replay(&context, &fixture, 22).await;
            fixture
        });
    deterministic::Runner::from(recovered).start(|context| async move {
        replay(&context, &fixture, STOP).await;
    });
}

async fn replay(context: &deterministic::Context, fixture: &Fixture, through: u64) {
    let oracle = network(context.child("network"));
    let public_key = fixture.key.node_key.public_key();
    let mut registrations = register_validators(&oracle, std::slice::from_ref(&public_key)).await;
    let config = get_default_engine_config(
        fixture.client.clone(),
        SimulatedOracle::new(oracle),
        "recovery_0".into(),
        fixture.genesis,
        "_SUMMIT".into(),
        KeyStore {
            node_key: fixture.key.node_key.clone(),
            consensus_key: fixture.key.consensus_key.clone(),
        },
        fixture.validators.clone(),
        fixture.initial.clone(),
    );
    let engine = Engine::new(context.child("engine"), config).await;
    // This asserts real database recovery, rather than supplying an invented
    // SyncStart to a mock application. Live progress must not override it.
    assert_eq!(engine.sync_start.height, 19);
    let finalizer = engine.finalizer_mailbox.clone();
    let syncer = engine.syncer_mailbox.clone();
    let (_, _, _, broadcast, backfill) = registrations.remove(&public_key).unwrap();
    let resolver_config = engine.backfill_resolver_config();
    let resolver =
        summit_syncer::resolver::p2p::init(context.child("backfill"), resolver_config, backfill);
    engine.buffer.start(broadcast);
    engine.finalizer.start(engine.orchestrator_mailbox);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    engine.syncer.start(
        ReplayReporter {
            finalizer: engine.finalizer_mailbox,
            through,
            delivered: delivered.clone(),
            held: Vec::new(),
        },
        engine.buffer_mailbox,
        resolver,
        engine.sync_start,
        engine.checkpoint,
    );
    while syncer.get_processed_height().await != Some(Height::new(through)) {
        context.sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(finalizer.get_latest_height().await, through);
    assert_eq!(delivered.lock().unwrap()[0], 20);
    if through == STOP {
        assert_eq!(*delivered.lock().unwrap(), (20..=STOP).collect::<Vec<_>>());
        assert_eq!(finalizer.get_state_root().await, fixture.expected_root);
    }
}
