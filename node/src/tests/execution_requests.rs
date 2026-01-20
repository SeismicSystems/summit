use crate::engine::{BLOCKS_PER_EPOCH, Engine};
use crate::test_harness::common;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use alloy_primitives::{Address, hex};
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
use summit_types::account::ValidatorStatus;
use summit_types::execution_request::ExecutionRequest;
use summit_types::keystore::KeyStore;
use summit_types::{PrivateKey, utils};

use crate::engine::VALIDATOR_WITHDRAWAL_NUM_EPOCHS;

#[test_traced("INFO")]
fn test_deposit_request_single() {
    // Adds a deposit request to the block at height 5, and then checks
    // the internal validator state to make sure that the validator balance, public keys,
    // and withdrawal credentials were added correctly.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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
                disconnect_on_block: true,
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

        // Create a single deposit request using the helper
        let (test_deposit, _, _) =
            common::create_deposit_request(10, min_stake, common::get_domain(), None, None);

        // Convert to ExecutionRequest and then to Requests
        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let stop_height = BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("validator_balance") {
                    let value = value.parse::<u64>().unwrap();
                    //println!("*********************************");
                    //println!("{metric}: size: {}", processed_requests.len());
                    // Parse the pubkey from the metric name using helper function
                    let pubkey_hex =
                        common::parse_metric_substring(metric, "pubkey").expect("pubkey missing");
                    let creds =
                        common::parse_metric_substring(metric, "creds").expect("creds missing");
                    assert_eq!(creds, hex::encode(test_deposit.withdrawal_credentials));
                    assert_eq!(pubkey_hex, test_deposit.node_pubkey.to_string());
                    assert_eq!(value, test_deposit.amount);
                    processed_requests.insert(metric.to_string());
                }
                if processed_requests.len() as u32 >= n && height_reached.len() as u32 == n {
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
fn test_deposit_request_top_up() {
    // Adds three deposit requests to blocks at different heights, and makes sure that only
    // the first two request are processed because the last request would put the validator
    // over the maximum stake.
    let n = 10;
    let minimum_stake = 32_000_000_000;
    let maximum_stake = 40_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create a single deposit request using the helper
        let (test_deposit1, private_key, _) =
            common::create_deposit_request(10, minimum_stake, common::get_domain(), None, None);
        let (test_deposit2, _, _) = common::create_deposit_request(
            10,
            8_000_000_000,
            common::get_domain(),
            Some(private_key.clone()),
            Some(test_deposit1.withdrawal_credentials),
        );
        let (test_deposit3, _, _) = common::create_deposit_request(
            10,
            1_000_000_000,
            common::get_domain(),
            Some(private_key),
            Some(test_deposit1.withdrawal_credentials),
        );

        let validator_node_key = test_deposit1.node_pubkey.clone();

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![
            ExecutionRequest::Deposit(test_deposit1.clone()),
            ExecutionRequest::Deposit(test_deposit2.clone()),
        ];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests3 = vec![ExecutionRequest::Deposit(test_deposit3.clone())];
        let requests3 = common::execution_requests_to_requests(execution_requests3);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height1 = 5;
        let deposit_block_height2 = 5;
        let deposit_block_height3 = 10;

        let deposit_process_height2 =
            utils::last_block_in_epoch(BLOCKS_PER_EPOCH, deposit_block_height2 / BLOCKS_PER_EPOCH);
        let _withdrawal_height2 =
            deposit_process_height2 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * BLOCKS_PER_EPOCH;

        // Because we already check in `parse_execution_requests` if the deposit will
        // make the validator balance invalid.
        let deposit_process_height3 = deposit_block_height3;
        let withdrawal_height3 =
            deposit_process_height3 + (VALIDATOR_WITHDRAWAL_NUM_EPOCHS + 1) * BLOCKS_PER_EPOCH - 1;

        let stop_height = withdrawal_height3 + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height1, requests1);
        execution_requests_map.insert(deposit_block_height3, requests3);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        // Set the validator balance to 0, min stake to 10 ETH, max stake to 50 ETH
        let mut initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        initial_state.validator_minimum_stake = minimum_stake; // 32 ETH in gwei
        initial_state.validator_maximum_stake = maximum_stake; // 40 ETH in gwei

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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if height_reached.len() as u32 == n {
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

        // Assert that the validator account data is consistent with the request
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validator_node_key)
            .await
            .unwrap();
        assert_eq!(
            account.withdrawal_credentials,
            utils::parse_withdrawal_credentials(test_deposit1.withdrawal_credentials).unwrap()
        );
        assert_eq!(account.consensus_public_key, test_deposit1.consensus_pubkey);
        assert_eq!(account.balance, test_deposit1.amount + test_deposit2.amount);

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        // check test_deposit3
        let epoch_withdrawals = withdrawals.get(&withdrawal_height3).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, test_deposit3.amount);

        let address =
            utils::parse_withdrawal_credentials(test_deposit3.withdrawal_credentials).unwrap();
        assert_eq!(epoch_withdrawals[0].address, address);

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_deposit_and_withdrawal_request_single() {
    // Adds a deposit request to the block at height 5, and then adds a withdrawal request
    // to the block at height 7.
    // It is verified that the validator balance is correctly decremented after the withdrawal,
    // and that the withdrawal request that is sent to the execution layer matches the
    // withdrawal request (execution request) that was initially added to block 7.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create a single deposit request using the helper
        let (test_deposit, _, _) = common::create_deposit_request(
            n as u64, // use a private key seed that doesn't exist on the consensus state
            min_stake,
            common::get_domain(),
            None,
            None,
        );

        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.node_pubkey.as_ref().try_into().unwrap(),
            test_deposit.amount,
        );

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(test_withdrawal.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Create execution requests map (add deposit to block 5)
        // The deposit request will be processed after 10 blocks because `BLOCKS_PER_EPOCH`
        // is set to 10 in debug mode.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("withdrawal_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_withdrawal.source_address));
                        assert_eq!(ed_pubkey_hex, test_deposit.node_pubkey.to_string());
                        assert_eq!(balance, test_deposit.amount - test_withdrawal.amount);
                        processed_requests.insert(metric.to_string());
                    } else {
                        println!("{}: {} (failed to parse pubkey)", metric, value);
                    }
                }
                if processed_requests.len() as u32 >= n && height_reached.len() as u32 == n {
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

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let withdrawals = withdrawals
            .get(&(withdrawal_height))
            .expect("missing withdrawal");
        assert_eq!(withdrawals[0].amount, test_withdrawal.amount);
        assert_eq!(withdrawals[0].address, test_withdrawal.source_address);

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_partial_withdrawal_balance_below_minimum_stake() {
    // Adds a deposit request to the block at height 5, and then adds a withdrawal request
    // to the block at height 7.
    // The withdrawal request will take the validator below the minimum stake, which means that
    // the entire remaining balance should be withdrawn.
    // We also add another withdraw request at height 8, which should be ignored, since there
    // is no balance left.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };
    // Create context
    let cfg = deterministic::Config::default().with_seed(3);
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

        // Create a single deposit request using the helper
        let (test_deposit, _, _) =
            common::create_deposit_request(n as u64, min_stake, common::get_domain(), None, None);

        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal1 = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.node_pubkey.as_ref().try_into().unwrap(),
            test_deposit.amount / 2,
        );
        let mut test_withdrawal2 = test_withdrawal1.clone();
        test_withdrawal2.amount -= test_withdrawal1.amount / 2;

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(test_withdrawal1.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        let execution_requests3 = vec![ExecutionRequest::Withdrawal(test_withdrawal1.clone())];
        let requests3 = common::execution_requests_to_requests(execution_requests3);

        // Create execution requests map (add deposit to block 5)
        // The deposit request will processed after 10 blocks because `BLOCKS_PER_EPOCH`
        // is set to 10 in debug mode.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);
        execution_requests_map.insert(withdrawal_block_height + 1, requests3);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("withdrawal_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_withdrawal1.source_address));
                        assert_eq!(ed_pubkey_hex, test_deposit.node_pubkey.to_string());
                        assert_eq!(balance, 0);
                        processed_requests.insert(metric.to_string());
                    } else {
                        println!("{}: {} (failed to parse pubkey)", metric, value);
                    }
                }
                if processed_requests.len() as u32 >= n && height_reached.len() as u32 == n {
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

        let withdrawals = engine_client_network.get_withdrawals();
        // Make sure that test_withdrawal2 was ignored, only test_withdraw1 should be submitted
        // to the execution layer.
        assert_eq!(withdrawals.len(), 1);
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing withdrawal");
        // Even though the first withdrawal was only 50% of the deposited amount,
        // since it put the validator under the minimum stake limit, the entire balance was withdrawn.
        assert_eq!(withdrawals[0].amount, test_deposit.amount);
        assert_eq!(withdrawals[0].address, test_withdrawal1.source_address);

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_deposit_less_than_min_stake_rejected() {
    // Adds a deposit request to the block at height 5.
    // The deposit request should be skipped and a withdrawal request for the same amount
    // should be initiated.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create a single deposit request using the helper
        let (test_deposit, _, _) = common::create_deposit_request(
            n as u64,
            min_stake / 2,
            common::get_domain(),
            None,
            None,
        );

        let validator_node_key = test_deposit.node_pubkey.clone();

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;

        let deposit_process_height =
            utils::last_block_in_epoch(BLOCKS_PER_EPOCH, deposit_block_height / BLOCKS_PER_EPOCH);
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * BLOCKS_PER_EPOCH;

        let stop_height = withdrawal_height + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        // Set the validator balance to 0
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if height_reached.len() as u32 == n {
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

        let state_query = consensus_state_queries.get(&0).unwrap();
        let balance = state_query.get_validator_balance(validator_node_key).await;
        // Assert that no validator account was created
        assert!(balance.is_none());

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, test_deposit.amount);

        let address =
            utils::parse_withdrawal_credentials(test_deposit.withdrawal_credentials).unwrap();
        assert_eq!(epoch_withdrawals[0].address, address);

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_deposit_and_withdrawal_request_multiple() {
    // This test is very similar to `test_deposit_and_withdrawal_request`, but instead
    // of a single deposit and withdrawal request, it has 5 deposit and withdrawal requests
    // (from different public keys).
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create deposit and matching withdrawal requests
        let mut deposit_reqs = HashMap::new();
        let mut withdrawal_reqs = HashMap::new();
        for i in 0..deposit_reqs.len() {
            let (test_deposit, _, _) = common::create_deposit_request(
                i as u64,
                min_stake,
                common::get_domain(),
                None,
                None,
            );

            let withdrawal_address =
                Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
            let test_withdrawal = common::create_withdrawal_request(
                withdrawal_address,
                test_deposit.node_pubkey.as_ref().try_into().unwrap(),
                test_deposit.amount,
            );
            deposit_reqs.insert(hex::encode(test_deposit.node_pubkey.clone()), test_deposit);
            withdrawal_reqs.insert(
                hex::encode(test_withdrawal.validator_pubkey),
                test_withdrawal,
            );
        }

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1: Vec<ExecutionRequest> = deposit_reqs
            .values()
            .map(|d| ExecutionRequest::Deposit(d.clone()))
            .collect();
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2: Vec<ExecutionRequest> = withdrawal_reqs
            .values()
            .map(|w| ExecutionRequest::Withdrawal(w.clone()))
            .collect();
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        // Set the validator balance to 0
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("deposit_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    let ed_pubkey_hex =
                        common::parse_metric_substring(metric, "pubkey").expect("pubkey missing");

                    let deposit_req = deposit_reqs.get(&ed_pubkey_hex).unwrap();

                    let creds =
                        common::parse_metric_substring(metric, "creds").expect("creds missing");
                    assert_eq!(creds, hex::encode(deposit_req.withdrawal_credentials));
                    assert_eq!(ed_pubkey_hex, deposit_req.node_pubkey.to_string());
                    assert_eq!(balance, deposit_req.amount);
                }

                if metric.ends_with("withdrawal_validator_balance") {
                    let bls_key_hex =
                        common::parse_metric_substring(metric, "bls_key").expect("bls key missing");
                    let withdrawal_req = withdrawal_reqs.get(&bls_key_hex).unwrap();
                    let deposit_req = deposit_reqs.get(&bls_key_hex).unwrap();
                    let ed_pubkey_hex =
                        common::parse_metric_substring(metric, "ed_key").expect("ed key missing");
                    let creds =
                        common::parse_metric_substring(metric, "creds").expect("creds missing");

                    let balance = value.parse::<u64>().unwrap();
                    assert_eq!(creds, hex::encode(withdrawal_req.source_address));
                    assert_eq!(ed_pubkey_hex, deposit_req.node_pubkey.to_string());
                    assert_eq!(balance, deposit_req.amount - withdrawal_req.amount);
                }
                if height_reached.len() as u32 >= n {
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

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), withdrawal_reqs.len());

        let expected_withdrawals: HashMap<Address, _> = withdrawal_reqs
            .into_iter()
            .map(|(_, withdrawal)| (withdrawal.source_address, withdrawal))
            .collect();

        for (_height, withdrawals) in withdrawals {
            for withdrawal in withdrawals {
                let expected_withdrawal = expected_withdrawals.get(&withdrawal.address).unwrap();
                assert_eq!(withdrawal.amount, expected_withdrawal.amount);
                assert_eq!(withdrawal.address, expected_withdrawal.source_address);
            }
        }

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_deposit_request_invalid_signature() {
    // Adds a deposit request with an invalid signature to the block at height 5, and then
    // verifies that the request is rejected and a withdrawal request is submitted for the same amount.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create a single deposit request using the helper
        let (mut test_deposit, _, _) =
            common::create_deposit_request(n, min_stake, common::get_domain(), None, None);

        let (test_deposit2, _, _) =
            common::create_deposit_request(2, min_stake, common::get_domain(), None, None);
        // Use signatures from another private key (to make it invalid)
        test_deposit.node_signature = test_deposit2.node_signature;
        test_deposit.consensus_signature = test_deposit2.consensus_signature;

        let validator_node_key = test_deposit.node_pubkey.clone();

        // Convert to ExecutionRequest and then to Requests
        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let deposit_process_height =
            utils::last_block_in_epoch(BLOCKS_PER_EPOCH, deposit_block_height / BLOCKS_PER_EPOCH);
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * BLOCKS_PER_EPOCH;
        let stop_height = withdrawal_height + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        // Set the validator balance to 0
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
        let mut processed_requests = HashSet::new();
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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if metric.ends_with("deposit_request_invalid_node_sig") {
                    let value = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let validator_id = common::extract_validator_id(metric)
                            .expect("failed to parse validator id");
                        assert_eq!(pubkey_hex, test_deposit.node_pubkey.to_string());
                        processed_requests.insert(validator_id);
                    } else {
                        println!("{}: {} (failed to parse pubkey)", metric, value);
                    }
                }

                if processed_requests.len() as u64 >= n && height_reached.len() as u64 >= n {
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

        let state_query = consensus_state_queries.get(&0).unwrap();
        let balance = state_query.get_validator_balance(validator_node_key).await;
        // Assert that no validator account was created
        assert!(balance.is_none());

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, test_deposit.amount);

        let address =
            utils::parse_withdrawal_credentials(test_deposit.withdrawal_credentials).unwrap();
        assert_eq!(epoch_withdrawals[0].address, address);

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
fn test_protocol_param_max_stake() {
    // Adds a protocol param request for maximum stake to the block at height 5
    // and verifies that the maximum stake is changed at the end of the epoch.
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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

        // Create a single protocol_param request for minimum stake
        let new_max_stake = 64_000_000_000;
        let test_protocol_param1 = common::create_protocol_param_request(0x01, new_max_stake);

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::ProtocolParam(
            test_protocol_param1.clone(),
        )];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Create execution requests map (add deposit to block 5)
        // The protocol param request will be processed after 10 blocks because `BLOCKS_PER_EPOCH`
        // is set to 10 in debug mode.
        let protocol_param_block_height1 = 5;
        let stop_height = BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height1, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if height_reached.len() as u32 == n {
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

        // Check that the minimum stake was updated
        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(state_query.get_maximum_stake().await, new_max_stake);

        // Check that all nodes have the same canonical chain
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_protocol_param_stake_update_committee() {
    // Tests that when min/max stake protocol parameters change:
    // - Validators with balance < new min_stake are kicked and fully withdrawn
    // - Validators with balance > new max_stake have excess withdrawn but remain active
    //
    // Test setup:
    // - Initial protocol params: min_stake = 32 ETH, max_stake = 64 ETH
    // - Genesis validators start with 32 ETH each
    // - Add deposits at block 3:
    //   * Validators 0-7: deposit 8 ETH each → reach 40 ETH
    //   * Validator 8: deposit 32 ETH → reach 64 ETH
    //   * Validator 9: no deposit → stays at 32 ETH
    // - Change min_stake to 40 ETH and max_stake to 40 ETH at blocks 5-6 (epoch 0)
    // - Protocol params applied at block 8 (penultimate block of epoch 0)
    // - Committee updated at block 9 (last block of epoch 0)
    // - Withdrawals occur at block 19 (last block of epoch 1)
    //
    // Expected results at block 19:
    // - Validators 0-7 (40 ETH): Active, no withdrawals (exactly at min/max)
    // - Validator 8 (64 ETH): Active, withdraw 24 ETH excess (64 - 40 = 24)
    // - Validator 9 (32 ETH): Inactive, full withdrawal of 32 ETH
    let n = 10;
    let min_stake = 32_000_000_000; // 32 ETH
    let max_stake = 64_000_000_000; // 64 ETH
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
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
                tracked_peer_sets: Some(n as usize * 10),
            },
        );

        network.start();

        // Register genesis validators
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

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create deposits for genesis validators (all have 32 ETH initially)
        let mut deposit_requests = Vec::new();

        // Validators 0-7: deposit 8 ETH to reach 40 ETH (32 + 8 = 40)
        for i in 0..8 {
            let deposit_amount = 8_000_000_000; // 8 ETH
            let (deposit, _, _) = common::create_deposit_request(
                i,
                deposit_amount,
                common::get_domain(),
                Some(key_stores[i as usize].node_key.clone()),
                None,
            );
            deposit_requests.push(ExecutionRequest::Deposit(deposit));
        }

        // Validator 8: deposit 32 ETH to reach 64 ETH (32 + 32 = 64)
        let deposit_amount_validator8 = 32_000_000_000; // 32 ETH
        let (deposit8, _, _) = common::create_deposit_request(
            8,
            deposit_amount_validator8,
            common::get_domain(),
            Some(key_stores[8].node_key.clone()),
            None,
        );
        deposit_requests.push(ExecutionRequest::Deposit(deposit8));

        // Validator 9: no deposit, stays at 32 ETH - below new min

        let requests_deposits = common::execution_requests_to_requests(deposit_requests);

        // Create protocol param change requests - set both min and max to 40 ETH
        let new_min_stake = 40_000_000_000; // 40 ETH
        let new_max_stake = 40_000_000_000; // 40 ETH
        let test_protocol_param1 = common::create_protocol_param_request(0x00, new_min_stake);
        let test_protocol_param2 = common::create_protocol_param_request(0x01, new_max_stake);

        let execution_requests1 = vec![ExecutionRequest::ProtocolParam(test_protocol_param1)];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::ProtocolParam(test_protocol_param2)];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Add execution requests to specific blocks in epoch 0
        let deposit_block_height = 3;
        let protocol_param_block_height1 = 5;
        let protocol_param_block_height2 = 6;
        let stop_height = BLOCKS_PER_EPOCH * 2 + 1; // Block 21 (need to reach block 19 for withdrawals)

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposits);
        execution_requests_map.insert(protocol_param_block_height1, requests1);
        execution_requests_map.insert(protocol_param_block_height2, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.validator_maximum_stake = max_stake;

        // Store validator public keys for later verification
        let validator8_pubkey = validators[8].0.clone();
        let validator9_pubkey = validators[9].0.clone();

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
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                // One of the validators is kicked due to unsiffient stake,
                // so we only check that n - 1 validators reached the stop height
                if height_reached.len() as u32 == n - 1 {
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

        // Verify protocol parameters were updated
        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);
        assert_eq!(state_query.get_maximum_stake().await, new_max_stake);

        // Verify validator 8 (64 ETH > 40 ETH max): should be Active with balance reduced to 40 ETH
        let account8 = state_query
            .get_validator_account(validator8_pubkey)
            .await
            .unwrap();

        assert_eq!(account8.status, ValidatorStatus::Active);
        assert_eq!(account8.balance, new_max_stake); // Should be 40 ETH

        // Verify validator 9 (32 ETH < 40 ETH min): should be removed after full withdrawal
        let account9 = state_query
            .get_validator_account(validator9_pubkey.clone())
            .await;
        assert!(
            account9.is_none(),
            "Validator 9 should be removed after full withdrawal"
        );

        // Verify withdrawals occurred at block 19 (last block of epoch 1)
        let withdrawal_height = 19;
        let withdrawals = engine_client_network.get_withdrawals();

        let epoch_withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing withdrawals at height 19");

        // Should have 2 withdrawals: validator 9 (32 ETH full), validator 8 (24 ETH excess)
        assert_eq!(epoch_withdrawals.len(), 2);

        // Find the withdrawals by checking amounts
        let withdrawal_32_eth = epoch_withdrawals
            .iter()
            .find(|w| w.amount == 32_000_000_000)
            .expect("missing 32 ETH withdrawal for validator 9");
        let withdrawal_24_eth = epoch_withdrawals
            .iter()
            .find(|w| w.amount == 24_000_000_000)
            .expect("missing 24 ETH excess withdrawal for validator 8");

        // Verify the 32 ETH withdrawal is for validator 9 (full withdrawal)
        assert_eq!(withdrawal_32_eth.amount, min_stake);

        // Verify the 24 ETH excess withdrawal is for validator 8 (64 - 40 = 24)
        let expected_excess = (min_stake + deposit_amount_validator8) - new_max_stake;
        assert_eq!(withdrawal_24_eth.amount, expected_excess);
        assert_eq!(withdrawal_24_eth.amount, 24_000_000_000);

        // Check that all nodes have the same canonical chain, skipping validator 9 which exited
        let validator9_client_id = format!("validator_{}", validator9_pubkey);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&validator9_client_id])
                .is_ok()
        );

        context.auditor().state()
    })
}
