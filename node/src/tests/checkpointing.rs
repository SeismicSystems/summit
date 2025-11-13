use crate::engine::{BLOCKS_PER_EPOCH, Engine, VALIDATOR_MINIMUM_STAKE};
use crate::test_harness::common;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::bls12381;
use commonware_cryptography::{PrivateKeyExt, Signer};
use commonware_macros::test_traced;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::from_hex_formatted;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::consensus_state::ConsensusState;
use summit_types::keystore::KeyStore;
use summit_types::{PrivateKey, utils};

#[test_traced("INFO")]
fn test_checkpoint_created() {
    // Makes sure that the validators come to consensus on a checkpoint
    // and store it to disk
    let n = 10;
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
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let node_key = PrivateKey::from_seed(i as u64);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(i as u64);
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
        let mut registrations = common::register_validators(&mut oracle, &node_public_keys).await;

        // Link all validators
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;
        // Create the engine clients
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let stop_height = BLOCKS_PER_EPOCH;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

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
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                orchestrator,
                broadcast,
                backfill,
            );
        }
        // Poll metrics
        let mut state_stored = HashSet::new();
        let mut header_stored = HashSet::new();
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                // Ensure it is a metrics line
                if !line.starts_with("validator-") {
                    continue;
                }

                // Split metric and value
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // If ends with peers_blocked, ensure it is zero
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("consensus_state_stored") {
                    let height = value.parse::<u64>().unwrap();
                    assert_eq!(height, BLOCKS_PER_EPOCH - 1);
                    state_stored.insert(metric.to_string());
                }

                if metric.ends_with("finalizer_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("finalized_header_stored") {
                    let height = value.parse::<u64>().unwrap();
                    assert_eq!(height, BLOCKS_PER_EPOCH - 1);
                    header_stored.insert(metric.to_string());
                }
                if header_stored.len() as u32 >= n
                    && state_stored.len() as u32 == n
                    && height_reached.len() as u32 >= n
                {
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

        let consensus_state_query = consensus_state_queries.get(&0).unwrap();
        let checkpoint = consensus_state_query
            .clone()
            .get_latest_checkpoint()
            .await
            .expect("failed to query checkpoint");
        let _consensus_state =
            ConsensusState::try_from(&checkpoint).expect("failed to parse consensus state");

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_previous_header_hash_matches() {
    // The finalized header that is stored at the end of an epoch points to the finalized
    // header that was stored at the previous epoch.
    // This test verifies that these hashes match.
    let n = 10;
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
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let node_key = PrivateKey::from_seed(i as u64);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(i as u64);
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
        let mut registrations = common::register_validators(&mut oracle, &node_public_keys).await;

        // Link all validators
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;
        // Create the engine clients
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let stop_height = BLOCKS_PER_EPOCH + 1;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

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
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                orchestrator,
                broadcast,
                backfill,
            );
        }
        // Poll metrics
        let mut first_header_stored = HashMap::new();
        let mut second_header_stored = HashSet::new();
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                // Ensure it is a metrics line
                if !line.starts_with("validator-") {
                    continue;
                }

                // Split metric and value
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // If ends with peers_blocked, ensure it is zero
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("finalizer_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("finalized_header_stored") {
                    let height = value.parse::<u64>().unwrap();
                    let header =
                        common::parse_metric_substring(metric, "header").expect("header missing");
                    let prev_header = common::parse_metric_substring(metric, "prev_header")
                        .expect("prev_header missing");
                    let validator_id =
                        common::extract_validator_id(metric).expect("failed to parse validator id");

                    if utils::is_last_block_of_epoch(BLOCKS_PER_EPOCH, height)
                        && height <= BLOCKS_PER_EPOCH
                    {
                        // This is the first time the finalized header is written to disk
                        first_header_stored.insert(validator_id, header);
                    } else if utils::is_last_block_of_epoch(BLOCKS_PER_EPOCH, height) {
                        // This is the second time the finalized header is written to disk
                        if let Some(header_from_prev_epoch) = first_header_stored.get(&validator_id)
                        {
                            // Assert that the finalized header in epoch 2 points to the finalized header of epoch 1
                            assert_eq!(header_from_prev_epoch, &prev_header);
                            second_header_stored.insert(validator_id);
                        }
                    } else {
                        assert!(utils::is_last_block_of_epoch(BLOCKS_PER_EPOCH, height));
                    }
                }
                // There is an edge case where not all validators write a finalized header to disk.
                // That's why we only enforce n - 1 validators to reach this checkpoint to avoid a flaky test.
                if second_header_stored.len() as u32 == n - 1 && height_reached.len() as u32 >= n {
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

        let consensus_state_query = consensus_state_queries.get(&0).unwrap();
        let checkpoint = consensus_state_query
            .clone()
            .get_latest_checkpoint()
            .await
            .expect("failed to query checkpoint");
        let _consensus_state =
            ConsensusState::try_from(&checkpoint).expect("failed to parse consensus state");

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

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
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(10),
            },
        );
        // Start network
        network.start();

        // Create a single validator
        let node_key = PrivateKey::from_seed(100);
        let node_public_key = node_key.public_key();
        let consensus_key = bls12381::PrivateKey::from_seed(100);
        let consensus_public_key = consensus_key.public_key();
        let key_store = KeyStore {
            node_key,
            consensus_key,
        };

        // Create a second set of keys to stop the single engine from producing blocks.
        let node_key2 = PrivateKey::from_seed(101);
        let node_public_key2 = node_key2.public_key();
        let consensus_key2 = bls12381::PrivateKey::from_seed(101);
        let consensus_public_key2 = consensus_key2.public_key();

        let validators = vec![
            (node_public_key.clone(), consensus_public_key),
            (node_public_key2, consensus_public_key2),
        ];
        let node_public_keys = vec![node_public_key.clone()];
        let mut registrations = common::register_validators(&mut oracle, &node_public_keys).await;

        // Link validator
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create and populate a consensus state
        let mut consensus_state = common::get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );
        consensus_state.set_latest_height(50); // Set a specific height

        // Configure engine with the checkpoint
        let public_key = key_store.node_key.public_key();
        let uid = format!("validator-{public_key}");
        let namespace = String::from("_SEISMIC_BFT");
        let engine_client = engine_client_network.create_client(uid.clone());

        let latest_height = consensus_state.latest_height;

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

        let engine = Engine::new(context.with_label(&uid), config).await;
        let finalizer_mailbox = engine.finalizer_mailbox.clone();
        // Get networking
        let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
            registrations.remove(&public_key).unwrap();

        // Start engine
        engine.start(
            pending,
            recovered,
            resolver,
            orchestrator,
            broadcast,
            backfill,
        );

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
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let node_key = PrivateKey::from_seed(i as u64);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(i as u64);
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
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );

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
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

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
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                orchestrator,
                broadcast,
                backfill,
            );
        }

        // Wait for the validators to checkpoint
        let consensus_state_query = consensus_state_queries.get(&0).unwrap();
        let checkpoint = loop {
            if let Some(checkpoint) = consensus_state_query.clone().get_latest_checkpoint().await {
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
        let uid = format!("validator-{public_key}");
        let namespace = String::from("_SEISMIC_BFT");

        let engine_client = engine_client_network.create_client(uid.clone());

        // This corresponds to snapshotting Reth
        let consensus_state = ConsensusState::try_from(&checkpoint).unwrap();
        let from_block = consensus_state.latest_height + 1;
        let eth_hash = consensus_state.forkchoice.head_block_hash.into();

        engine_client.load_checkpoint(consensus_state.latest_height, eth_hash);

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
        let engine = Engine::new(context.with_label(&uid), config).await;

        // Get networking from late registrations
        let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
            late_registrations.into_iter().next().unwrap().1;

        // Start engine
        engine.start(
            pending,
            recovered,
            resolver,
            orchestrator,
            broadcast,
            backfill,
        );

        // Poll metrics
        let stop_height = 3 * BLOCKS_PER_EPOCH;
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                // Ensure it is a metrics line
                if !line.starts_with("validator-") {
                    continue;
                }

                // Split metric and value
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // If ends with peers_blocked, ensure it is zero
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("finalizer_height") {
                    let value = value.parse::<u64>().unwrap();
                    if value == stop_height {
                        nodes_finished.insert(metric.to_string());
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
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10), // Each engine may subscribe multiple times
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let node_key = PrivateKey::from_seed(i as u64);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(i as u64);
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
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );

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
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

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
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                orchestrator,
                broadcast,
                backfill,
            );
        }

        // Wait for the validators to checkpoint
        let consensus_state_query = consensus_state_queries.get(&0).unwrap();
        let checkpoint = loop {
            if let Some(checkpoint) = consensus_state_query.clone().get_latest_checkpoint().await {
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
        let uid = format!("validator-{public_key}");
        let namespace = String::from("_SEISMIC_BFT");

        let engine_client = engine_client_network.create_client(uid.clone());

        // This corresponds to snapshotting Reth
        let consensus_state = ConsensusState::try_from(&checkpoint).unwrap();
        let from_block = consensus_state.latest_height + 1;
        let eth_hash = consensus_state.forkchoice.head_block_hash.into();

        engine_client.load_checkpoint(consensus_state.latest_height, eth_hash);

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
        let engine = Engine::new(context.with_label(&uid), config).await;

        // Get networking from late registrations
        let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
            late_registrations.into_iter().next().unwrap().1;

        // Start engine
        engine.start(
            pending,
            recovered,
            resolver,
            orchestrator,
            broadcast,
            backfill,
        );

        // Poll metrics
        let stop_height = 3 * BLOCKS_PER_EPOCH;
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                // Ensure it is a metrics line
                if !line.starts_with("validator-") {
                    continue;
                }

                // Split metric and value
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // If ends with peers_blocked, ensure it is zero
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("finalizer_height") {
                    let value = value.parse::<u64>().unwrap();
                    if value == stop_height {
                        nodes_finished.insert(metric.to_string());
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

        context.auditor().state()
    });
}
