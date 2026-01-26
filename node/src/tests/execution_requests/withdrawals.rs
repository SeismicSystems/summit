use super::*;
use alloy_primitives::hex;

#[test_traced("INFO")]
fn test_partial_withdrawal_balance_below_minimum_stake() {
    // Adds a deposit request to the block at height 5, and then adds a withdrawal request
    // to the block at height 7.
    // The withdrawal request will take the validator below the minimum stake, which means that
    // the entire remaining balance should be withdrawn.
    // We also add another withdraw request at height 8, which should be ignored, since there
    // is no balance left.
    let n = 5;
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
fn test_duplicate_withdrawal_blocked() {
    // Tests that a second withdrawal request from the same validator is ignored
    // while the first withdrawal is still pending.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Submit two withdrawal requests for the same validator at blocks 3 and 4
    // - Only the first withdrawal should be processed, second should be ignored
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10),
            },
        );

        network.start();

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

        // Create addresses AFTER sorting so they match sorted validators
        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create two withdrawal requests for validator 0
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];

        let withdrawal1 =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);
        let withdrawal2 =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);

        let execution_requests1 = vec![ExecutionRequest::Withdrawal(withdrawal1.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(withdrawal2.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // First withdrawal at block 3, second at block 4
        let withdrawal_block_height1 = 3;
        let withdrawal_block_height2 = 4;
        let withdrawal_epoch =
            (withdrawal_block_height1 / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height1, requests1);
        execution_requests_map.insert(withdrawal_block_height2, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

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

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for n-1 validators (validator 0 exits)
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("finalizer_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height == stop_height {
                        height_reached.insert(metric.to_string());
                    }
                }

                if height_reached.len() as u32 == n - 1 {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Verify only one withdrawal occurred
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), 1);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[0].address, withdrawal_address);

        let validator0_client_id = format!("validator_{}", validators[0].0);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&validator0_client_id])
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_withdrawal_wrong_source_address_rejected() {
    // Tests that a withdrawal request with a source address that doesn't match
    // the validator's withdrawal credentials is rejected.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each, with known withdrawal addresses
    // - Submit a withdrawal request for validator 0 with a WRONG source address
    // - The withdrawal should be rejected, validator balance unchanged
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10),
            },
        );

        network.start();

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

        // Create addresses AFTER sorting so they match sorted validators
        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create a withdrawal request for validator 0 with WRONG source address
        // Validator 0's correct address is addresses[0], but we use addresses[1]
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let wrong_address = addresses[1]; // Wrong address - should be addresses[0]

        let withdrawal =
            common::create_withdrawal_request(wrong_address, validator0_pubkey, min_stake);

        let execution_requests1 = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Submit withdrawal at block 3
        let withdrawal_block_height = 3;
        // Calculate when withdrawal would have been processed if it were valid
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

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

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for all validators to reach stop_height
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

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
            context.sleep(Duration::from_secs(1)).await;
        }

        // Verify no withdrawal occurred (request was rejected due to wrong address)
        let withdrawals = engine_client_network.get_withdrawals();
        assert!(withdrawals.is_empty());

        // Verify validator 0's balance is unchanged
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validators[0].0.clone())
            .await
            .unwrap();

        assert_eq!(account.balance, min_stake);
        assert_eq!(account.status, ValidatorStatus::Active);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_withdrawal_nonexistent_validator_ignored() {
    // Tests that a withdrawal request for a validator that doesn't exist is ignored.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Submit a withdrawal request for a non-existent validator (random pubkey)
    // - The withdrawal should be ignored, no state changes
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10),
            },
        );

        network.start();

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

        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create a withdrawal request for a non-existent validator
        // Use a random pubkey that doesn't belong to any genesis validator
        let nonexistent_pubkey: [u8; 32] = [0xFFu8; 32];
        let some_address = addresses[0];

        let withdrawal =
            common::create_withdrawal_request(some_address, nonexistent_pubkey, min_stake);

        let execution_requests1 = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Submit withdrawal at block 3
        let withdrawal_block_height = 3;
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

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

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for all validators to reach stop_height
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

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
            context.sleep(Duration::from_secs(1)).await;
        }

        // Verify no withdrawal occurred (request was ignored)
        let withdrawals = engine_client_network.get_withdrawals();
        assert!(withdrawals.is_empty());

        // Verify all genesis validators still have their original balance
        let state_query = consensus_state_queries.get(&0).unwrap();
        for validator in &validators {
            let account = state_query
                .get_validator_account(validator.0.clone())
                .await
                .unwrap();
            assert_eq!(account.balance, min_stake);
            assert_eq!(account.status, ValidatorStatus::Active);
        }

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_withdrawal_during_onboarding_aborts() {
    // Tests that a withdrawal request during the onboarding phase aborts the onboarding
    // and processes the withdrawal.
    //
    // Test setup:
    // - Submit deposit at block 5 (epoch 0) for a new validator
    // - Deposit processed at block 8 (penultimate block of epoch 0)
    // - Validator's joining_epoch = 2 (epoch 0 + VALIDATOR_NUM_WARM_UP_EPOCHS)
    // - Submit withdrawal at block 15 (epoch 1) - before joining_epoch
    // - Onboarding should be aborted, withdrawal processed at epoch 3
    let n = 10;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: Some(n as usize * 10),
            },
        );

        network.start();

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

        // Create a deposit request for a new validator
        let (test_deposit, _, _) =
            common::create_deposit_request(n as u64, min_stake, common::get_domain(), None, None);

        let new_validator_pubkey: [u8; 32] = test_deposit.node_pubkey.as_ref().try_into().unwrap();

        // Parse withdrawal credentials to get the address for the withdrawal request
        let withdrawal_address =
            utils::parse_withdrawal_credentials(test_deposit.withdrawal_credentials).unwrap();

        // Create a withdrawal request for the same validator (during onboarding)
        let withdrawal =
            common::create_withdrawal_request(withdrawal_address, new_validator_pubkey, min_stake);

        let execution_requests_deposit = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests_deposit = common::execution_requests_to_requests(execution_requests_deposit);

        let execution_requests_withdrawal = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests_withdrawal =
            common::execution_requests_to_requests(execution_requests_withdrawal);

        // Deposit at block 5 (epoch 0), withdrawal at block 15 (epoch 1)
        // Deposit is processed at block 8, joining_epoch = 2
        // Withdrawal is submitted in epoch 1, before joining_epoch (2)
        let deposit_block_height = 5;
        let withdrawal_block_height = 15; // Epoch 1

        // Withdrawal epoch = epoch when withdrawal is submitted + VALIDATOR_WITHDRAWAL_NUM_EPOCHS
        // = 1 + 2 = 3
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1; // Block 39
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposit);
        execution_requests_map.insert(withdrawal_block_height, requests_withdrawal);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

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

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for all validators to reach stop_height
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

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
            context.sleep(Duration::from_secs(1)).await;
        }

        // Verify the withdrawal occurred (onboarding was aborted, funds returned)
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), 1);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[0].address, withdrawal_address);

        // Verify the new validator account was removed (balance and pending both 0)
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(test_deposit.node_pubkey.clone())
            .await;
        assert!(
            account.is_none(),
            "Validator account should be removed after full withdrawal"
        );

        // Verify the validator never joined the committee (was not added to active validators)
        // All genesis validators should still be active with unchanged balance
        for validator in &validators {
            let account = state_query
                .get_validator_account(validator.0.clone())
                .await
                .unwrap();
            assert_eq!(account.balance, min_stake);
            assert_eq!(account.status, ValidatorStatus::Active);
        }

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}
