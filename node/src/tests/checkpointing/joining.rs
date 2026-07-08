use crate::engine::Engine;
use crate::test_harness::common;
use crate::test_harness::common::DEFAULT_BLOCKS_PER_EPOCH;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381;
use commonware_formatting::from_hex;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::Supervisor as _;
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::NZUsize;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::PrivateKey;
use summit_types::consensus_state::ConsensusState;
use summit_types::keystore::KeyStore;

#[test_traced("INFO")]
fn test_single_engine_with_checkpoint() {
    // Test that an Engine instance can be initialized with a pre-created checkpoint
    // and properly load the consensus state from it
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };
    // Create context
    let cfg = deterministic::Config::default().with_seed(42);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(10),
            },
        );
        // Start network
        network.start();

        // Create a single validator
        let mut rng = StdRng::seed_from_u64(100);
        let node_key = PrivateKey::random(&mut rng);
        let node_public_key = node_key.public_key();
        let consensus_key = bls12381::PrivateKey::random(&mut rng);
        let consensus_public_key = consensus_key.public_key();
        let key_store = KeyStore {
            node_key,
            consensus_key,
        };

        // Create a second set of keys to stop the single engine from producing blocks.
        let mut rng2 = StdRng::seed_from_u64(101);
        let node_key2 = PrivateKey::random(&mut rng2);
        let node_public_key2 = node_key2.public_key();
        let consensus_key2 = bls12381::PrivateKey::random(&mut rng2);
        let consensus_public_key2 = consensus_key2.public_key();

        let validators = vec![
            (node_public_key.clone(), consensus_public_key),
            (node_public_key2, consensus_public_key2),
        ];
        let node_public_keys = vec![node_public_key.clone()];
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        // Link validator
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create and populate a consensus state
        let mut consensus_state =
            common::get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        consensus_state.set_latest_height(50); // Set a specific height

        // Configure engine with the checkpoint
        let public_key = key_store.node_key.public_key();
        let uid = format!("validator_{public_key}");
        let namespace = String::from("_SUMMIT");
        let engine_client = engine_client_network.create_client(uid.clone());

        let latest_height = consensus_state.get_latest_height();

        let config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle.clone()),
            uid.clone(),
            genesis_hash,
            namespace,
            key_store,
            validators.clone(),
            consensus_state,
        );

        let engine = Engine::new(
            context.child("engine").with_attribute("uid", uid.clone()),
            config,
        )
        .await;
        let finalizer_mailbox = engine.finalizer_mailbox.clone();
        // Get networking
        let (pending, recovered, resolver, orchestrator, broadcast) =
            registrations.remove(&public_key).unwrap();

        // Start engine
        engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // Wait a bit for initialization
        context.sleep(Duration::from_millis(500)).await;

        // Verify the consensus state was initialized from the checkpoint (height 50)
        let current_height = finalizer_mailbox.get_latest_height().await;

        // The finalizer should have been initialized with our checkpoint at height 50
        // Since consensus is running, the height might be >= 50
        assert!(
            current_height >= latest_height,
            "Expected height >= {}, got {}",
            latest_height,
            current_height
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_node_joins_later_with_checkpoint() {
    // Creates a network of 5 nodes, and starts only 4 of them.
    // The last node starts after the first checkpoint was created, and
    // it uses that checkpoint to initialize the consensus DB
    let n = 5;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };
    // Create context
    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        let stop_height = 3 * DEFAULT_BLOCKS_PER_EPOCH;
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            let consensus_public_key = consensus_key.public_key();
            let key_store = KeyStore {
                node_key,
                consensus_key,
            };
            key_stores.push(key_store);
            validators.push((node_public_key, consensus_public_key));
        }
        validators.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        key_stores.sort_by_key(|ks| ks.node_key.public_key());

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();

        // Separate initial validators from late joiner
        let initial_node_public_keys = &node_public_keys[..node_public_keys.len() - 1];

        // Register and link only initial validators
        let mut registrations =
            common::register_validators(&mut oracle, initial_node_public_keys).await;
        common::link_validators(&mut oracle, initial_node_public_keys, link.clone(), None).await;
        // Create the engine clients
        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();

        // Start all the engines, except for one
        let key_store_joining_later = key_stores.pop().unwrap();

        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace,
                key_store,
                validators.clone(),
                initial_state.clone(),
            );
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for the validators to checkpoint
        let consensus_state_query = consensus_state_queries.get(&0).unwrap();
        let (checkpoint, _) = loop {
            if let Some(checkpoint) = consensus_state_query
                .clone()
                .get_latest_checkpoint()
                .await
                .0
            {
                break checkpoint;
            }
            context.sleep(Duration::from_secs(1)).await;
        };

        loop {
            if consensus_state_query.get_latest_height().await >= 20 {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Now register and join the final validator to the network
        let public_key = key_store_joining_later.node_key.public_key();

        // Register the late joining validator
        let late_registrations =
            common::register_validators(&mut oracle, &[public_key.clone()]).await;

        // Join the validator to the network
        common::join_validator(&mut oracle, &public_key, initial_node_public_keys, link).await;

        // Allow p2p connections to establish before starting engine
        context.sleep(Duration::from_millis(100)).await;

        public_keys.insert(public_key.clone());

        // Configure engine
        let uid = format!("validator_{public_key}");
        let namespace = String::from("_SUMMIT");

        let engine_client = engine_client_network.create_client(uid.clone());

        // This corresponds to snapshotting Reth
        let consensus_state = ConsensusState::try_from(&checkpoint).unwrap();
        let from_block = consensus_state.get_latest_height() + 1;
        let eth_hash = consensus_state.get_forkchoice().head_block_hash.into();

        engine_client.load_checkpoint(consensus_state.get_latest_height(), eth_hash);

        let config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle.clone()),
            uid.clone(),
            genesis_hash,
            namespace,
            key_store_joining_later,
            validators.clone(),
            consensus_state,
        );
        let engine = Engine::new(
            context.child("engine").with_attribute("uid", uid.clone()),
            config,
        )
        .await;

        // Get networking from late registrations
        let (pending, recovered, resolver, orchestrator, broadcast) =
            late_registrations.into_iter().next().unwrap().1;

        // Start engine
        engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // Poll metrics
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                // If ends with peers_blocked, ensure it is zero
                if sample.name.ends_with("_peers_blocked") {
                    let value = sample.value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if sample.name.ends_with("finalizer_height") {
                    let value = sample.value.parse::<u64>().unwrap();
                    if value >= stop_height {
                        nodes_finished.insert(sample.uid.clone());
                        if nodes_finished.len() as u32 == n {
                            success = true;
                            break;
                        }
                    }
                }

                if nodes_finished.len() as u32 >= n {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            // Still waiting for all validators to complete
            context.sleep(Duration::from_secs(1)).await;
        }

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(Some(from_block), Some(stop_height))
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    });
}

/// A node joining from a checkpoint that carries the `last_block` +
/// `finalized_header` artifacts (a `SyncCheckpoint`) must seed the checkpoint
/// epoch's finalized header into finalizer storage at startup, via the syncer's
/// pre-consensus replay of the terminal block — NOT via live block delivery.
///
/// Boundary aux-data derives `prev_epoch_header_hash` from
/// `get_most_recent_finalized_header()`, falling back to the genesis hash when
/// the finalized-header DB is empty. If the checkpoint header is never seeded, a
/// checkpoint-joined node's first boundary header would link to genesis instead
/// of the checkpoint epoch's header. The pre-consensus replay is what prevents
/// that, yet every other checkpoint test exercises only the state-only /
/// live-sync path (`checkpoint_last_block: None`), so the replay-seeding path is
/// otherwise uncovered.
///
/// To prove the header is seeded by the replay and not by network sync, the
/// joiner is registered but deliberately left UNLINKED: it can receive no blocks
/// from peers, so a populated `get_finalized_header(E)` can only be the result of
/// the startup replay.
#[test_traced("INFO")]
fn test_checkpoint_join_replays_and_seeds_finalized_header() {
    let n = 5;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };
    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(n as usize * 10),
            },
        );
        network.start();

        // Register participants.
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            let consensus_public_key = consensus_key.public_key();
            key_stores.push(KeyStore {
                node_key,
                consensus_key,
            });
            validators.push((node_public_key, consensus_public_key));
        }
        validators.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        key_stores.sort_by_key(|ks| ks.node_key.public_key());

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let initial_node_public_keys = &node_public_keys[..node_public_keys.len() - 1];

        let mut registrations =
            common::register_validators(&oracle, initial_node_public_keys).await;
        common::link_validators(&mut oracle, initial_node_public_keys, link.clone(), None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        // Start the initial validators.
        let key_store_joining_later = key_stores.pop().unwrap();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");
            let engine_client = engine_client_network.create_client(uid.clone());
            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace,
                key_store,
                validators.clone(),
                initial_state.clone(),
            );
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());
            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for a checkpoint, then capture the full checkpoint artifacts:
        // the checkpoint bytes, the epoch-terminal `last_block`, and the
        // certified finalized header for that epoch.
        let source_query = consensus_state_queries.get(&0).unwrap();
        let (checkpoint, last_block) = loop {
            if let Some(pair) = source_query.clone().get_latest_checkpoint().await.0 {
                break pair;
            }
            context.sleep(Duration::from_secs(1)).await;
        };

        // Let the network advance well past the checkpoint epoch's terminal so
        // the source node has durably stored that epoch's finalized header.
        loop {
            if source_query.get_latest_height().await >= 20 {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // The checkpoint state is captured at the penultimate block, so its epoch
        // is the checkpoint epoch E; `last_block` is E's terminal.
        let checkpoint_state = ConsensusState::try_from(&checkpoint).unwrap();
        let checkpoint_epoch = checkpoint_state.get_epoch();
        let source_header = source_query
            .clone()
            .get_finalized_header(checkpoint_epoch)
            .await
            .expect("source node must have stored the checkpoint epoch's finalized header");
        // Sanity: the finalized header certifies exactly the terminal `last_block`.
        assert_eq!(
            source_header.finalization().proposal.payload,
            last_block.digest(),
            "finalized header must certify the checkpoint's last_block"
        );

        // Register the joining validator but do NOT link it: with no peers it
        // cannot receive any block over the network, so anything the finalizer
        // stores can only have come from the checkpoint replay.
        let public_key = key_store_joining_later.node_key.public_key();
        let mut late_registrations =
            common::register_validators(&oracle, &[public_key.clone()]).await;

        let uid = format!("validator_{public_key}");
        let namespace = String::from("_SUMMIT");
        let engine_client = engine_client_network.create_client(uid.clone());
        // Prime the joiner's execution client at the checkpoint (penultimate)
        // height so replaying the terminal block executes as the next block.
        let eth_hash = checkpoint_state.get_forkchoice().head_block_hash.into();
        engine_client.load_checkpoint(checkpoint_state.get_latest_height(), eth_hash);

        let mut config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle.clone()),
            uid.clone(),
            genesis_hash,
            namespace,
            key_store_joining_later,
            validators.clone(),
            checkpoint_state.clone(),
        );
        // The artifacts that make this a `SyncCheckpoint` join rather than a
        // state-only join. This is exactly what the other checkpoint tests omit.
        config.checkpoint_last_block = Some(last_block.clone());
        config.checkpoint_finalized_header = Some(source_header.clone());

        let engine = Engine::new(
            context.child("engine").with_attribute("uid", uid.clone()),
            config,
        )
        .await;
        let joiner_query = engine.finalizer_mailbox.clone();
        let (pending, recovered, resolver, orchestrator, broadcast) =
            late_registrations.remove(&public_key).unwrap();
        engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // The replay runs in the syncer's `run()` before the consensus loop.
        // Poll until the finalizer has processed it (bounded); an unlinked node
        // has no other way to obtain the terminal block.
        let mut seeded = None;
        for _ in 0..30 {
            if let Some(header) = joiner_query
                .clone()
                .get_finalized_header(checkpoint_epoch)
                .await
            {
                seeded = Some(header);
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        let seeded = seeded.expect(
            "checkpoint-joined finalizer must seed the checkpoint epoch's finalized header \
             from the startup replay (get_most_recent_finalized_header would otherwise fall \
             back to genesis at the next boundary)",
        );
        assert_eq!(
            seeded.header().get_digest(),
            source_header.header().get_digest(),
            "seeded finalized header must match the checkpoint epoch's terminal header"
        );
        // The terminal was executed and the finalizer advanced past the
        // penultimate checkpoint height, confirming the replay ran end to end.
        assert!(
            joiner_query.get_latest_height().await > checkpoint_state.get_latest_height(),
            "finalizer must have advanced past the checkpoint (penultimate) height via replay"
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_node_joins_later_with_checkpoint_not_in_genesis() {
    // Creates a network of 5 nodes, and starts only 4 of them.
    // The last node starts after the first checkpoint was created, and
    // it uses that checkpoint to initialize the consensus DB
    // In this test the joining node is not included in the list of peers that is passed to the engine.
    let n = 5;
    let end_epoch = 4;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };
    // Create context
    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        let stop_height = end_epoch * DEFAULT_BLOCKS_PER_EPOCH;
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            let consensus_public_key = consensus_key.public_key();
            let key_store = KeyStore {
                node_key,
                consensus_key,
            };
            key_stores.push(key_store);
            validators.push((node_public_key, consensus_public_key));
        }
        validators.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        key_stores.sort_by_key(|ks| ks.node_key.public_key());

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();

        // Separate initial validators from late joiner
        let initial_validators = validators[..validators.len() - 1].to_vec();
        let initial_node_public_keys = &node_public_keys[..node_public_keys.len() - 1];

        // Register and link only initial validators
        let mut registrations =
            common::register_validators(&mut oracle, initial_node_public_keys).await;
        common::link_validators(&mut oracle, initial_node_public_keys, link.clone(), None).await;
        // Create the engine clients
        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();

        // Start all the engines, except for one
        let key_store_joining_later = key_stores.pop().unwrap();

        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace,
                key_store,
                initial_validators.clone(),
                initial_state.clone(),
            );
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for the validators to checkpoint
        let consensus_state_query = consensus_state_queries.get(&0).clone().unwrap();
        let (checkpoint, _) = loop {
            if let Some(checkpoint) = consensus_state_query
                .clone()
                .get_latest_checkpoint()
                .await
                .0
            {
                break checkpoint;
            }
            context.sleep(Duration::from_secs(1)).await;
        };

        loop {
            if consensus_state_query.get_latest_height().await >= 20 {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Now register and join the final validator to the network
        let public_key = key_store_joining_later.node_key.public_key();

        // Register the late joining validator
        let late_registrations =
            common::register_validators(&mut oracle, &[public_key.clone()]).await;

        // Join the validator to the network
        common::join_validator(&mut oracle, &public_key, initial_node_public_keys, link).await;

        // Allow p2p connections to establish before starting engine
        context.sleep(Duration::from_millis(100)).await;

        public_keys.insert(public_key.clone());

        // Configure engine
        let uid = format!("validator_{public_key}");
        let namespace = String::from("_SUMMIT");

        let engine_client = engine_client_network.create_client(uid.clone());

        // This corresponds to snapshotting Reth
        let consensus_state = ConsensusState::try_from(&checkpoint).unwrap();
        let from_block = consensus_state.get_latest_height() + 1;
        let eth_hash = consensus_state.get_forkchoice().head_block_hash.into();

        engine_client.load_checkpoint(consensus_state.get_latest_height(), eth_hash);

        let config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle.clone()),
            uid.clone(),
            genesis_hash,
            namespace,
            key_store_joining_later,
            initial_validators,
            consensus_state,
        );
        let engine = Engine::new(
            context.child("engine").with_attribute("uid", uid.clone()),
            config,
        )
        .await;

        // Get networking from late registrations
        let (pending, recovered, resolver, orchestrator, broadcast) =
            late_registrations.into_iter().next().unwrap().1;

        consensus_state_queries.insert(n - 1, engine.finalizer_mailbox.clone());

        // Start engine
        engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // Poll metrics
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                // If ends with peers_blocked, ensure it is zero
                if sample.name.ends_with("_peers_blocked") {
                    let value = sample.value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if sample.name.ends_with("finalizer_height") {
                    let value = sample.value.parse::<u64>().unwrap();
                    if value >= stop_height {
                        nodes_finished.insert(sample.uid.clone());
                        if nodes_finished.len() == n as usize {
                            success = true;
                            break;
                        }
                    }
                }

                if nodes_finished.len() >= n as usize {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            // Still waiting for all validators to complete
            context.sleep(Duration::from_secs(1)).await;
        }

        // Check that all validators (including the joining validator) stored the same checkpoints
        let mut reference_mailbox = consensus_state_queries.get(&0).unwrap().clone();
        let mut reference_digests = Vec::with_capacity(end_epoch as usize);
        for epoch in 0..end_epoch {
            let (ckpt, _) = reference_mailbox.get_checkpoint(epoch).await.unwrap();
            reference_digests.push(ckpt.digest);
        }
        for i in 1..n {
            let mut mailbox = consensus_state_queries.get(&i).unwrap().clone();
            // Only check starting from epoch 1 because the joining node won't have
            // a checkpoint for epoch 0
            for j in 1..end_epoch {
                let (ckpt, _) = mailbox.get_checkpoint(j).await.unwrap();
                assert_eq!(ckpt.digest, reference_digests[j as usize]);
            }
        }

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(Some(from_block), Some(stop_height))
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    });
}
