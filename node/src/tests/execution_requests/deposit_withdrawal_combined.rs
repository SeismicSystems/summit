use super::*;
use alloy_primitives::hex;

#[test_traced("INFO")]
fn test_deposit_and_withdrawal_request_single() {
    // Adds a deposit request to the block at height 5, and then adds a withdrawal request
    // to the block at height 7.
    // It is verified that the validator balance is correctly decremented after the withdrawal,
    // and that the withdrawal request that is sent to the execution layer matches the
    // withdrawal request (execution request) that was initially added to block 7.
    let n = 5;
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
                    if height >= stop_height {
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
fn test_deposit_and_withdrawal_request_multiple() {
    // This test is very similar to `test_deposit_and_withdrawal_request`, but instead
    // of a single deposit and withdrawal request, it has 5 deposit and withdrawal requests
    // (from different public keys).
    let n = 5;
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
                    if height >= stop_height {
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
fn test_deposit_blocked_by_pending_withdrawal() {
    // Tests that a deposit request is rejected and refunded when the validator has a pending withdrawal.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Submit withdrawal at block 3, then deposit at block 4
    // - Withdrawal should be processed, deposit should be rejected and refunded
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
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
        let mut addresses = Vec::new();
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
            addresses.push(Address::from([i as u8; 20]));
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

        // Create withdrawal then deposit for validator 0
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];

        let withdrawal =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);

        // Create withdrawal credentials matching the address
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;
        withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_ref());

        let deposit_amount = 5_000_000_000; // 5 ETH
        let (deposit, _, _) = common::create_deposit_request(
            0,
            deposit_amount,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            Some(withdrawal_credentials),
        );

        let execution_requests1 = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Deposit(deposit.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Withdrawal at block 3, deposit at block 4
        let withdrawal_block_height = 3;
        let deposit_block_height = 4;
        let withdrawal_epoch =
            (withdrawal_block_height / BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);
        execution_requests_map.insert(deposit_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.validator_maximum_stake = max_stake;

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
                    if height >= stop_height {
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

        // Verify withdrawal occurred and rejected deposit was refunded
        // Two withdrawals expected:
        // 1. Original withdrawal of 32 ETH (min_stake)
        // 2. Refund of rejected deposit of 5 ETH (deposit_amount)
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), 2);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[1].amount, deposit_amount);

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
fn test_withdrawal_blocked_by_pending_deposit() {
    // Tests that a withdrawal request is ignored when the validator has a pending deposit.
    //
    // Test setup:
    // - New validator submits deposit at block 3
    // - Same validator submits withdrawal at block 4 (before deposit is processed)
    // - Deposit should be processed, withdrawal should be ignored
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
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
        let mut addresses = Vec::new();
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
            addresses.push(Address::from([i as u8; 20]));
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

        // Create deposit then withdrawal for validator 0 (existing genesis validator)
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];

        // Create withdrawal credentials matching the address
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;
        withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_ref());

        let deposit_amount = 5_000_000_000; // 5 ETH top-up
        let (deposit, _, _) = common::create_deposit_request(
            0,
            deposit_amount,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            Some(withdrawal_credentials),
        );

        let withdrawal =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);

        let execution_requests1 = vec![ExecutionRequest::Deposit(deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // Deposit at block 3, withdrawal at block 4 (both before deposit processed at block 9)
        let deposit_block_height = 3;
        let withdrawal_block_height = 4;
        let stop_height = BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.validator_maximum_stake = max_stake;

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

        // Wait for all validators to reach stop height
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
                    if height >= stop_height {
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

        // Verify deposit was processed and withdrawal was ignored
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validators[0].0.clone())
            .await
            .unwrap();

        // Balance should be initial (32 ETH) + deposit (5 ETH) = 37 ETH
        // Withdrawal should have been ignored
        assert_eq!(account.balance, min_stake + deposit_amount);
        assert_eq!(account.status, ValidatorStatus::Active);

        // No withdrawals should have occurred
        let withdrawals = engine_client_network.get_withdrawals();
        assert!(withdrawals.is_empty());

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_deposit_and_withdrawal_same_block() {
    // Tests that when a deposit and withdrawal for the same validator are in the same block,
    // the second request is blocked by the first one's pending flag.
    //
    // Test setup:
    // - Genesis validator 0 starts with 32 ETH
    // - Submit both a deposit (5 ETH top-up) and withdrawal in block 5
    // - Deposit is processed first, sets has_pending_deposit = true
    // - Withdrawal sees the flag and is blocked
    // - Result: balance increases by 5 ETH, no withdrawal occurs
    let n = 10;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
    let deposit_amount = 5_000_000_000; // 5 ETH top-up
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

        // Create deposit and withdrawal for validator 0
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];

        // Create withdrawal credentials matching the address
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;
        withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_ref());

        // Create a top-up deposit for validator 0
        let (deposit, _, _) = common::create_deposit_request(
            0,
            deposit_amount,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            Some(withdrawal_credentials),
        );

        // Create a withdrawal request for validator 0
        let withdrawal =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);

        // Put BOTH requests in the same block - deposit first, then withdrawal
        // The deposit will set has_pending_deposit, blocking the withdrawal
        let execution_requests = vec![
            ExecutionRequest::Deposit(deposit.clone()),
            ExecutionRequest::Withdrawal(withdrawal.clone()),
        ];
        let requests = common::execution_requests_to_requests(execution_requests);

        let request_block_height = 5;
        // Deposit will be processed at end of epoch 0 (block 9)
        // We need to wait past that to verify the balance
        let stop_height = 2 * BLOCKS_PER_EPOCH;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(request_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.validator_maximum_stake = max_stake;

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
                    if height >= stop_height {
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

        // Verify NO withdrawal occurred (withdrawal was blocked by pending deposit)
        let withdrawals = engine_client_network.get_withdrawals();
        assert!(withdrawals.is_empty());

        // Verify validator 0's balance increased (deposit was processed)
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validators[0].0.clone())
            .await
            .unwrap();

        // Balance should be initial (32 ETH) + deposit (5 ETH) = 37 ETH
        assert_eq!(account.balance, min_stake + deposit_amount);
        assert_eq!(account.status, ValidatorStatus::Active);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}
