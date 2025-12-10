use crate::engine::{BLOCKS_PER_EPOCH, Engine, VALIDATOR_MINIMUM_STAKE};
use crate::test_harness::common;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::{PrivateKeyExt, Signer, bls12381};
use commonware_macros::test_traced;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::from_hex_formatted;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::{PrivateKey, keystore::KeyStore};

#[test_traced("INFO")]
fn test_node_joins_later_no_checkpoint_in_genesis() {
    // Creates a network of 5 nodes, and starts only 4 of them.
    // The last node starts after 10 blocks, to ensure that the block backfilling
    // in the syncer_old works.
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
        key_stores.sort_by(|lhs, rhs| lhs.node_key.public_key().cmp(&rhs.node_key.public_key()));

        // Separate initial validators from late joiner
        let initial_validators = &validators[..validators.len() - 1];
        let initial_node_public_keys: Vec<_> = initial_validators
            .iter()
            .map(|(pk, _)| pk.clone())
            .collect();

        // Register and link only initial validators
        let mut registrations =
            common::register_validators(&oracle, &initial_node_public_keys).await;
        common::link_validators(&mut oracle, &initial_node_public_keys, link.clone(), None).await;
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
        let _checkpoint = loop {
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

        // Now register and join the final validator to the network
        let public_key = key_store_joining_later.node_key.public_key();

        // Register the late joining validator
        let late_registrations =
            common::register_validators(&mut oracle, &[public_key.clone()]).await;

        // Join the validator to the network
        common::join_validator(&mut oracle, &public_key, &initial_node_public_keys, link).await;

        // Allow p2p connections to establish before starting engine
        context.sleep(Duration::from_millis(100)).await;

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
            key_store_joining_later,
            validators.clone(),
            initial_state, // pass initial state (start from genesis)
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
        let stop_height = 2 * BLOCKS_PER_EPOCH;
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
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_node_joins_later_no_checkpoint_not_in_genesis() {
    // Creates a network of 5 nodes, and starts only 4 of them.
    // The last node starts after 10 blocks, to ensure that the block backfilling
    // in the syncer_old works.
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
        key_stores.sort_by(|lhs, rhs| lhs.node_key.public_key().cmp(&rhs.node_key.public_key()));

        // Separate initial validators from late joiner
        let initial_validators = &validators[..validators.len() - 1];
        let initial_node_public_keys: Vec<_> = initial_validators
            .iter()
            .map(|(pk, _)| pk.clone())
            .collect();

        // Register and link only initial validators
        let mut registrations =
            common::register_validators(&oracle, &initial_node_public_keys).await;
        common::link_validators(&mut oracle, &initial_node_public_keys, link.clone(), None).await;
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
                initial_validators.to_vec(),
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
        let _checkpoint = loop {
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

        // Now register and join the final validator to the network
        let public_key = key_store_joining_later.node_key.public_key();

        // Register the late joining validator
        let late_registrations =
            common::register_validators(&mut oracle, &[public_key.clone()]).await;

        // Join the validator to the network
        common::join_validator(&mut oracle, &public_key, &initial_node_public_keys, link).await;

        // Allow p2p connections to establish before starting engine
        context.sleep(Duration::from_millis(100)).await;

        public_keys.insert(public_key.clone());

        // Configure engine
        let uid = format!("validator-{public_key}");
        let namespace = String::from("_SEISMIC_BFT");

        let engine_client = engine_client_network.create_client(uid.clone());

        // Joining node uses initial_validators for syncer_old verification
        // since historical blocks were finalized by only those 4 validators
        let config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle.clone()),
            uid.clone(),
            genesis_hash,
            namespace,
            key_store_joining_later,
            initial_validators.to_vec(),
            initial_state, // pass initial state (start from genesis)
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
        let stop_height = 2 * BLOCKS_PER_EPOCH;
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
                    println!("{} -> {}", metric, value);
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
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}
