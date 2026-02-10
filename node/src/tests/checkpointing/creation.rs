use crate::engine::{BLOCKS_PER_EPOCH, Engine};
use crate::test_harness::common;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::from_hex_formatted;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::consensus_state::ConsensusState;
use summit_types::keystore::KeyStore;
use summit_types::{PrivateKey, utils};

#[test_traced("INFO")]
fn test_checkpoint_created() {
    // Makes sure that the validators come to consensus on a checkpoint
    // and store it to disk
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
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

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
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator_{public_key}");
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
            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
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
                if !line.starts_with("validator_") {
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
                    // Height should be the last block of an epoch
                    if height > 0 {
                        assert_eq!((height + 1) % BLOCKS_PER_EPOCH, 0);
                    }
                    state_stored.insert(metric.to_string());
                }

                if metric.ends_with("finalizer_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("finalized_header_stored") {
                    let height = value.parse::<u64>().unwrap();
                    // Height should be the last block of an epoch
                    assert_eq!((height + 1) % BLOCKS_PER_EPOCH, 0);
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

        let mut consensus_state_query = consensus_state_queries.get(&0).unwrap().clone();
        let (checkpoint, _) = consensus_state_query
            .clone()
            .get_latest_checkpoint()
            .await
            .0
            .expect("failed to query checkpoint");
        let _consensus_state =
            ConsensusState::try_from(&checkpoint).expect("failed to parse consensus state");

        // Verify the finalized header's checkpoint_hash matches the checkpoint digest
        let finalized_header = consensus_state_query
            .get_finalized_header(0)
            .await
            .expect("failed to get finalized header");
        assert_eq!(
            finalized_header.header.checkpoint_hash.as_ref(),
            checkpoint.digest.as_ref(),
            "checkpoint_hash in header should match checkpoint digest"
        );

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
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

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
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator_{public_key}");
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
            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
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
                if !line.starts_with("validator_") {
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
                    if height >= stop_height {
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
        let (checkpoint, _) = consensus_state_query
            .clone()
            .get_latest_checkpoint()
            .await
            .0
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
