use crate::engine::{EPOCH_NUM_BLOCKS, Engine};
use crate::test_harness::common;
use crate::test_harness::common::get_default_engine_config;
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::{PrivateKeyExt, Signer};
use commonware_macros::test_traced;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::from_hex_formatted;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::PrivateKey;
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;

#[test_traced("INFO")]
fn test_checkpoint_created() {
    // Makes sure that the validators come to consensus on a checkpoint
    // and store it to disk
    let n = 10;
    let link = Link {
        latency: 80.0,
        jitter: 10.0,
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
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let signer = PrivateKey::from_seed(i as u64);
            let pk = signer.public_key();
            signers.push(signer);
            validators.push(pk);
        }
        validators.sort();
        signers.sort_by_key(|s| s.public_key());
        let mut registrations = common::register_validators(&mut oracle, &validators).await;

        // Link all validators
        common::link_validators(&mut oracle, &validators, link, None).await;
        // Create the engine clients
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let stop_height = EPOCH_NUM_BLOCKS + 1;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, signer) in signers.into_iter().enumerate() {
            // Create signer context
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                uid.clone(),
                genesis_hash,
                namespace,
                signer,
                validators.clone(),
                None,
            );
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, resolver, broadcast, backfill);
        }
        // Poll metrics
        let mut state_stored = HashSet::new();
        let mut header_stored = HashSet::new();
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
                    assert_eq!(height, EPOCH_NUM_BLOCKS);
                    state_stored.insert(metric.to_string());
                }

                if metric.ends_with("finalized_header_stored") {
                    let height = value.parse::<u64>().unwrap();
                    assert_eq!(height, EPOCH_NUM_BLOCKS);
                    header_stored.insert(metric.to_string());
                }
                if header_stored.len() as u32 >= n && state_stored.len() as u32 == n {
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
        latency: 80.0,
        jitter: 10.0,
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
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let signer = PrivateKey::from_seed(i as u64);
            let pk = signer.public_key();
            signers.push(signer);
            validators.push(pk);
        }
        validators.sort();
        signers.sort_by_key(|s| s.public_key());
        let mut registrations = common::register_validators(&mut oracle, &validators).await;

        // Link all validators
        common::link_validators(&mut oracle, &validators, link, None).await;
        // Create the engine clients
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let stop_height = EPOCH_NUM_BLOCKS + 1;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, signer) in signers.into_iter().enumerate() {
            // Create signer context
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                uid.clone(),
                genesis_hash,
                namespace,
                signer,
                validators.clone(),
                None,
            );
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, resolver, broadcast, backfill);
        }
        // Poll metrics
        let mut first_header_stored = HashMap::new();
        let mut second_header_stored = HashSet::new();
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

                if metric.ends_with("finalized_header_stored") {
                    let height = value.parse::<u64>().unwrap();
                    let header =
                        common::parse_metric_substring(metric, "header").expect("header missing");
                    let prev_header = common::parse_metric_substring(metric, "prev_header")
                        .expect("prev_header missing");
                    let validator_id =
                        common::extract_validator_id(metric).expect("failed to parse validator id");

                    if height == EPOCH_NUM_BLOCKS {
                        // This is the first time the finalized header is written to disk
                        first_header_stored.insert(validator_id, header);
                    } else if height == 2 * EPOCH_NUM_BLOCKS {
                        // This is the second time the finalized header is written to disk
                        if let Some(header_from_prev_epoch) = first_header_stored.get(&validator_id)
                        {
                            // Assert that the finalized header in epoch 2 points to the finalized header of epoch 1
                            assert_eq!(header_from_prev_epoch, &prev_header);
                            second_header_stored.insert(validator_id);
                        }
                    } else {
                        assert_eq!(height % EPOCH_NUM_BLOCKS, 0);
                    }
                }
                // There is an edge case where not all validators write a finalized header to disk.
                // That's why we only enforce n - 1 validators to reach this checkpoint to avoid a flaky test.
                if second_header_stored.len() as u32 == n - 1 {
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
        latency: 80.0,
        jitter: 10.0,
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
            },
        );
        // Start network
        network.start();

        // Create a single validator
        let signer = PrivateKey::from_seed(100);
        let validators = vec![signer.public_key()];
        let mut registrations = common::register_validators(&mut oracle, &validators).await;

        // Link validator
        common::link_validators(&mut oracle, &validators, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create and populate a consensus state
        let mut consensus_state = ConsensusState::default();
        consensus_state.set_latest_height(50); // Set a specific height

        // Create a checkpoint from the consensus state
        let checkpoint = Checkpoint::new(&consensus_state);

        // Configure engine with the checkpoint
        let public_key = signer.public_key();
        let uid = format!("validator-{public_key}");
        let namespace = String::from("_SEISMIC_BFT");
        let engine_client = engine_client_network.create_client(uid.clone());

        let config = get_default_engine_config(
            engine_client,
            uid.clone(),
            genesis_hash,
            namespace,
            signer,
            validators.clone(),
            Some(checkpoint.clone()),
        );

        let engine = Engine::new(context.with_label(&uid), config).await;
        let finalizer_mailbox = engine.finalizer_mailbox.clone();
        // Get networking
        let (pending, resolver, broadcast, backfill) = registrations.remove(&public_key).unwrap();

        // Start engine
        engine.start(pending, resolver, broadcast, backfill);

        // Wait a bit for initialization
        context.sleep(Duration::from_millis(500)).await;

        // Verify the consensus state was initialized from the checkpoint (height 50)
        let current_height = finalizer_mailbox.get_latest_height().await;

        // The finalizer should have been initialized with our checkpoint at height 50
        // Since consensus is running, the height might be >= 50
        assert!(
            current_height >= consensus_state.latest_height,
            "Expected height >= {}, got {}",
            consensus_state.latest_height,
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
        latency: 80.0,
        jitter: 10.0,
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
            },
        );
        // Start network
        network.start();
        // Register participants
        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let signer = PrivateKey::from_seed(i as u64);
            let pk = signer.public_key();
            signers.push(signer);
            validators.push(pk);
        }
        validators.sort();
        signers.sort_by_key(|s| s.public_key());

        // Separate initial validators from late joiner
        let initial_validators = &validators[..validators.len() - 1];

        // Register and link only initial validators
        let mut registrations = common::register_validators(&mut oracle, initial_validators).await;
        common::link_validators(&mut oracle, initial_validators, link.clone(), None).await;
        // Create the engine clients
        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash).build();

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();

        // Start all the engines, except for one
        let signer_joining_later = signers.pop().unwrap();

        for (idx, signer) in signers.into_iter().enumerate() {
            // Create signer context
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                uid.clone(),
                genesis_hash,
                namespace,
                signer,
                validators.clone(),
                None,
            );
            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, resolver, broadcast, backfill);
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
        let public_key = signer_joining_later.public_key();

        // Register the late joining validator
        let late_registrations =
            common::register_validators(&mut oracle, &[public_key.clone()]).await;

        // Join the validator to the network
        common::join_validator(&mut oracle, &public_key, initial_validators, link).await;

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
            uid.clone(),
            genesis_hash,
            namespace,
            signer_joining_later,
            validators.clone(),
            Some(checkpoint),
        );
        let engine = Engine::new(context.with_label(&uid), config).await;

        // Get networking from late registrations
        let (pending, resolver, broadcast, backfill) =
            late_registrations.into_iter().next().unwrap().1;

        // Start engine
        engine.start(pending, resolver, broadcast, backfill);

        // Poll metrics
        let stop_height = 3 * EPOCH_NUM_BLOCKS;
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
