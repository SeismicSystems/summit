use crate::engine::{EPOCH_NUM_BLOCKS, Engine, VALIDATOR_MINIMUM_STAKE};
use crate::test_harness::common;
use crate::test_harness::common::get_default_engine_config;
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use alloy_primitives::{Address, hex};
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
use summit_types::execution_request::ExecutionRequest;

use crate::engine::VALIDATOR_WITHDRAWAL_PERIOD;

#[test_traced("INFO")]
fn test_deposit_request_single() {
    // Adds a deposit request to the block at height 5, and then checks
    // the internal validator state to make sure that the validator balance, public keys,
    // and withdrawal credentials were added correctly.
    let n = 10;
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

        // Create a single deposit request using the helper
        let (test_deposit, _) = common::create_deposit_request(
            1,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );

        // Convert to ExecutionRequest and then to Requests
        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let stop_height = deposit_block_height + 7;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("validator_balance") {
                    let value = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_deposit.withdrawal_credentials));
                        assert_eq!(pubkey_hex, test_deposit.pubkey.to_string());
                        assert_eq!(value, test_deposit.amount);
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
    // Adds two deposit requests to blocks at different heights, and makes sure that the
    // validator balance is the sum of the amounts of both deposit requests.
    let n = 10;
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

        // Create a single deposit request using the helper
        let (test_deposit1, private_key) = common::create_deposit_request(
            1,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );
        let (test_deposit2, _) = common::create_deposit_request(
            2,
            10_000_000_000,
            common::get_domain(),
            Some(private_key),
            Some(test_deposit1.withdrawal_credentials),
        );

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit1.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Deposit(test_deposit2.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let withdrawal_block_height = 10;
        let stop_height = withdrawal_block_height + VALIDATOR_WITHDRAWAL_PERIOD + 5;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    if balance == test_deposit1.amount {
                        continue;
                    }
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_deposit1.withdrawal_credentials));
                        assert_eq!(ed_pubkey_hex, test_deposit1.pubkey.to_string());
                        // The amount from both deposits should be added to the validator balance
                        assert_eq!(balance, test_deposit1.amount + test_deposit2.amount);
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
    // and that the withdrawal request that is send to the execution layer matches the
    // withdrawal request (execution request) that was initially added to block 7.
    let n = 10;
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

        // Create a single deposit request using the helper
        let (test_deposit, _) = common::create_deposit_request(
            1,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );

        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.pubkey.as_ref().try_into().unwrap(),
            test_deposit.amount,
        );

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(test_withdrawal.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Create execution requests map (add deposit to block 5)
        // The deposit request will processed after 10 blocks because `EPOCH_NUM_BLOCKS`
        // is set to 10 in debug mode.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + EPOCH_NUM_BLOCKS + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("withdrawal_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_withdrawal.source_address));
                        assert_eq!(ed_pubkey_hex, test_deposit.pubkey.to_string());
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
            (withdrawal_block_height + VALIDATOR_WITHDRAWAL_PERIOD + EPOCH_NUM_BLOCKS - 1)
                / EPOCH_NUM_BLOCKS;
        let withdrawal_height = withdrawal_epoch * EPOCH_NUM_BLOCKS;
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

        // Create a single deposit request using the helper
        let (test_deposit, _) = common::create_deposit_request(
            1,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );

        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal1 = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.pubkey.as_ref().try_into().unwrap(),
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
        // The deposit request will processed after 10 blocks because `EPOCH_NUM_BLOCKS`
        // is set to 10 in debug mode.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + EPOCH_NUM_BLOCKS + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);
        execution_requests_map.insert(withdrawal_block_height + 1, requests3);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("withdrawal_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_withdrawal1.source_address));
                        assert_eq!(ed_pubkey_hex, test_deposit.pubkey.to_string());
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
            (withdrawal_block_height + VALIDATOR_WITHDRAWAL_PERIOD + EPOCH_NUM_BLOCKS - 1)
                / EPOCH_NUM_BLOCKS;
        let withdrawal_height = withdrawal_epoch * EPOCH_NUM_BLOCKS;
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
fn test_deposit_less_than_min_stake_and_withdrawal() {
    // Adds a deposit request to the block at height 5, and then adds a withdrawal request
    // to the block at height 7.
    // The deposit request is less than the minimum stake, so the validator should not be added
    // to the registry.
    // The balance should still increase and the withdrawal should work as well.
    let n = 10;
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

        // Create a single deposit request using the helper
        let (test_deposit, _) = common::create_deposit_request(
            n as u64,
            VALIDATOR_MINIMUM_STAKE / 2,
            common::get_domain(),
            None,
            None,
        );

        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.pubkey.as_ref().try_into().unwrap(),
            test_deposit.amount,
        );

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(test_withdrawal.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Create execution requests map (add deposit to block 5)
        // The deposit request will processed after 10 blocks because `EPOCH_NUM_BLOCKS`
        // is set to 10 in debug mode.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let stop_height = withdrawal_block_height + EPOCH_NUM_BLOCKS + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("deposit_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    let registry_flag = common::parse_metric_substring(metric, "registry")
                        .expect("registry flag missing");
                    assert_eq!(balance, test_deposit.amount);
                    // Make sure that the validator was not added to the registry
                    assert_eq!(registry_flag, "false");
                }

                if metric.ends_with("withdrawal_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(ed_pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let creds =
                            common::parse_metric_substring(metric, "creds").expect("creds missing");
                        assert_eq!(creds, hex::encode(test_withdrawal.source_address));
                        assert_eq!(ed_pubkey_hex, test_deposit.pubkey.to_string());
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
            (withdrawal_block_height + VALIDATOR_WITHDRAWAL_PERIOD + EPOCH_NUM_BLOCKS - 1)
                / EPOCH_NUM_BLOCKS;
        let withdrawal_height = withdrawal_epoch * EPOCH_NUM_BLOCKS;
        let withdrawals = withdrawals
            .get(&withdrawal_height)
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
fn test_deposit_and_withdrawal_request_multiple() {
    // This test is very similar to `test_deposit_and_withdrawal_request`, but instead
    // of a single deposit and withdrawal request, it has 5 deposit and withdrawal requests
    // (from different public keys).
    let n = 10;
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

        // Create deposit and matching withdrawal requests
        let mut deposit_reqs = HashMap::new();
        let mut withdrawal_reqs = HashMap::new();
        for i in 0..deposit_reqs.len() {
            let (test_deposit, _) = common::create_deposit_request(
                i as u64,
                VALIDATOR_MINIMUM_STAKE,
                common::get_domain(),
                None,
                None,
            );

            let withdrawal_address =
                Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
            let test_withdrawal = common::create_withdrawal_request(
                withdrawal_address,
                test_deposit.pubkey.as_ref().try_into().unwrap(),
                test_deposit.amount,
            );
            deposit_reqs.insert(hex::encode(test_deposit.pubkey.clone()), test_deposit);
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
        let stop_height = withdrawal_block_height + EPOCH_NUM_BLOCKS + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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

                if metric.ends_with("deposit_validator_balance") {
                    let balance = value.parse::<u64>().unwrap();
                    let ed_pubkey_hex =
                        common::parse_metric_substring(metric, "pubkey").expect("pubkey missing");

                    let deposit_req = deposit_reqs.get(&ed_pubkey_hex).unwrap();

                    let creds =
                        common::parse_metric_substring(metric, "creds").expect("creds missing");
                    assert_eq!(creds, hex::encode(deposit_req.withdrawal_credentials));
                    assert_eq!(ed_pubkey_hex, deposit_req.pubkey.to_string());
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
                    assert_eq!(ed_pubkey_hex, deposit_req.pubkey.to_string());
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
    // verifies that the request is rejected.
    let n = 10;
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

        // Create a single deposit request using the helper
        let (mut test_deposit, _) = common::create_deposit_request(
            1,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );

        let (test_deposit2, _) = common::create_deposit_request(
            2,
            VALIDATOR_MINIMUM_STAKE,
            common::get_domain(),
            None,
            None,
        );
        // Use signature from another private key
        test_deposit.signature = test_deposit2.signature;

        // Convert to ExecutionRequest and then to Requests
        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let stop_height = deposit_block_height + EPOCH_NUM_BLOCKS + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

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
        let mut processed_requests = HashSet::new();
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

                if metric.ends_with("deposit_request_invalid_sig") {
                    let value = value.parse::<u64>().unwrap();
                    // Parse the pubkey from the metric name using helper function
                    if let Some(pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let validator_id = common::extract_validator_id(metric)
                            .expect("failed to parse validator id");
                        assert_eq!(pubkey_hex, test_deposit.pubkey.to_string());
                        processed_requests.insert(validator_id);
                    } else {
                        println!("{}: {} (failed to parse pubkey)", metric, value);
                    }
                }
                if processed_requests.len() as u32 >= n {
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
