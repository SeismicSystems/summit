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
        for signer in signers.into_iter() {
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
            );
            let engine = Engine::new(context.with_label(&uid), config).await;

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

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(Some(stop_height))
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
        for signer in signers.into_iter() {
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
            );
            let engine = Engine::new(context.with_label(&uid), config).await;

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

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}
