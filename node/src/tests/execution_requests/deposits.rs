use super::*;
use alloy_primitives::hex;

#[test_traced("INFO")]
fn test_deposit_request_single() {
    // Adds a deposit request to the block at height 5, and then checks
    // the internal validator state to make sure that the validator balance, public keys,
    // and withdrawal credentials were added correctly.
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
    let n = 5;
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
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit1.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Deposit(test_deposit2.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        let execution_requests3 = vec![ExecutionRequest::Deposit(test_deposit3.clone())];
        let requests3 = common::execution_requests_to_requests(execution_requests3);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height1 = 5;
        let deposit_block_height2 = 10;
        let deposit_block_height3 = 20;

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
        execution_requests_map.insert(deposit_block_height2, requests2);
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
fn test_deposit_less_than_min_stake_rejected() {
    // Adds a deposit request to the block at height 5.
    // The deposit request should be skipped and a withdrawal request for the same amount
    // should be initiated.
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
fn test_deposit_greater_than_max_stake_rejected() {
    // Adds a deposit request to the block at height 5 with amount exceeding max stake.
    // The deposit request should be rejected and a withdrawal request for the same amount
    // should be initiated to refund the depositor.
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 64_000_000_000;
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

        // Create a deposit request with amount exceeding max stake
        let deposit_amount = max_stake + 10_000_000_000; // 74 ETH, exceeds 64 ETH max
        let (test_deposit, _, _) = common::create_deposit_request(
            n as u64,
            deposit_amount,
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

        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.validator_maximum_stake = max_stake;

        // Create instances
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

        // Poll metrics until all validators reach stop_height
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

            context.sleep(Duration::from_secs(1)).await;
        }

        // Assert that no validator account was created (deposit was rejected)
        let state_query = consensus_state_queries.get(&0).unwrap();
        let balance = state_query.get_validator_balance(validator_node_key).await;
        assert!(balance.is_none());

        // Verify that a refund withdrawal was initiated
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, deposit_amount);

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
fn test_deposit_request_invalid_node_signature() {
    // Adds a deposit request with an invalid node signature (but valid consensus signature)
    // to the block at height 5, and verifies that the request is rejected with a refund.
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

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create deposit request with valid signatures
        let (mut test_deposit, _, _) =
            common::create_deposit_request(n, min_stake, common::get_domain(), None, None);

        // Create another deposit to get a different node signature
        let (test_deposit2, _, _) =
            common::create_deposit_request(2, min_stake, common::get_domain(), None, None);

        // Only invalidate the node signature (keep consensus signature valid)
        test_deposit.node_signature = test_deposit2.node_signature;

        let validator_node_key = test_deposit.node_pubkey.clone();

        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

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

        let mut processed_requests = HashSet::new();
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

                // Check specifically for invalid NODE signature metric
                if metric.ends_with("deposit_request_invalid_node_sig") {
                    if let Some(pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let validator_id = common::extract_validator_id(metric)
                            .expect("failed to parse validator id");
                        assert_eq!(pubkey_hex, test_deposit.node_pubkey.to_string());
                        processed_requests.insert(validator_id);
                    }
                }

                // Ensure NO invalid consensus signature metric is emitted
                // (node sig check should fail first)
                assert!(
                    !metric.ends_with("deposit_request_invalid_consensus_sig"),
                    "Consensus signature should not be checked when node signature is invalid"
                );

                if processed_requests.len() as u64 >= n && height_reached.len() as u64 >= n {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        let state_query = consensus_state_queries.get(&0).unwrap();
        let balance = state_query.get_validator_balance(validator_node_key).await;
        assert!(balance.is_none());

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, test_deposit.amount);

        let address =
            utils::parse_withdrawal_credentials(test_deposit.withdrawal_credentials).unwrap();
        assert_eq!(epoch_withdrawals[0].address, address);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_deposit_request_invalid_consensus_signature() {
    // Adds a deposit request with a valid node signature but invalid consensus signature
    // to the block at height 5, and verifies that the request is rejected with a refund.
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

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create deposit request with valid signatures
        let (mut test_deposit, _, _) =
            common::create_deposit_request(n, min_stake, common::get_domain(), None, None);

        // Create another deposit to get a different consensus signature
        let (test_deposit2, _, _) =
            common::create_deposit_request(2, min_stake, common::get_domain(), None, None);

        // Only invalidate the consensus signature (keep node signature valid)
        test_deposit.consensus_signature = test_deposit2.consensus_signature;

        let validator_node_key = test_deposit.node_pubkey.clone();

        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

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

        let mut processed_requests = HashSet::new();
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

                // Check specifically for invalid CONSENSUS signature metric
                // Note: consensus sig metric uses consensus_pubkey (BLS), not node_pubkey
                if metric.ends_with("deposit_request_invalid_consensus_sig") {
                    if let Some(pubkey_hex) = common::parse_metric_substring(metric, "pubkey") {
                        let validator_id = common::extract_validator_id(metric)
                            .expect("failed to parse validator id");
                        let expected_pubkey = hex::encode(test_deposit.consensus_pubkey.encode());
                        assert_eq!(pubkey_hex, expected_pubkey);
                        processed_requests.insert(validator_id);
                    }
                }

                // Ensure NO invalid node signature metric is emitted
                // (node sig should be valid in this test)
                assert!(
                    !metric.ends_with("deposit_request_invalid_node_sig"),
                    "Node signature should be valid in this test"
                );

                if processed_requests.len() as u64 >= n && height_reached.len() as u64 >= n {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        let state_query = consensus_state_queries.get(&0).unwrap();
        let balance = state_query.get_validator_balance(validator_node_key).await;
        assert!(balance.is_none());

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals[0].amount, test_deposit.amount);

        let address =
            utils::parse_withdrawal_credentials(test_deposit.withdrawal_credentials).unwrap();
        assert_eq!(epoch_withdrawals[0].address, address);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_duplicate_deposit_blocked() {
    // Tests that a second deposit request from the same validator is ignored
    // while the first deposit is still pending.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Submit two top-up deposits for the same validator at blocks 3 and 4
    // - Only the first deposit should be processed, second should be ignored
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

        // Create two top-up deposits for validator 0
        let deposit_amount1 = 5_000_000_000; // 5 ETH
        let deposit_amount2 = 3_000_000_000; // 3 ETH
        let (deposit1, _, _) = common::create_deposit_request(
            0,
            deposit_amount1,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            None,
        );
        let (deposit2, _, _) = common::create_deposit_request(
            0,
            deposit_amount2,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            Some(deposit1.withdrawal_credentials),
        );

        let validator0_pubkey = validators[0].0.clone();

        let execution_requests1 = vec![ExecutionRequest::Deposit(deposit1.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Deposit(deposit2.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // First deposit at block 3, second at block 4 (both before processing at block 9)
        let deposit_block_height1 = 3;
        let deposit_block_height2 = 4;
        let stop_height = BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height1, requests1);
        execution_requests_map.insert(deposit_block_height2, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
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

        // Verify only the first deposit was processed
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validator0_pubkey)
            .await
            .unwrap();

        // Balance should be initial (32 ETH) + first deposit (5 ETH) = 37 ETH
        // Second deposit (3 ETH) should have been ignored
        assert_eq!(account.balance, min_stake + deposit_amount1);

        // No refund withdrawals should have been created (second deposit was just ignored)
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
