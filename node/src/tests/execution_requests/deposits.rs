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
                tracked_peer_sets: NZUsize!(n as usize * 10), // Each engine may subscribe multiple times
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
            common::create_deposit_request(10, min_stake, common::get_domain(), None, None, None);

        // Convert to ExecutionRequest and then to Requests
        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
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
            let namespace = String::from("_SUMMIT");

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
            // Peer-block health is a P2P signal, not consensus state, so it stays
            // a metric check.
            let metrics = context.encode();
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                if metric.ends_with("_peers_blocked") {
                    assert_eq!(value.parse::<u64>().unwrap(), 0);
                }
            }

            // Height and deposit processing both come from each validator's
            // consensus state, queried via the finalizer mailbox.
            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
                if let Some(balance) = query
                    .get_validator_balance(test_deposit.node_pubkey.clone())
                    .await
                    && balance == test_deposit.amount
                {
                    processed_requests.insert(*idx);
                }
            }

            if processed_requests.len() as u32 >= n && height_reached.len() as u32 == n {
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
                tracked_peer_sets: NZUsize!(n as usize * 10), // Each engine may subscribe multiple times
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
        let (test_deposit1, private_key, consensus_key) = common::create_deposit_request(
            10,
            minimum_stake,
            common::get_domain(),
            None,
            None,
            None,
        );
        let (test_deposit2, _, _) = common::create_deposit_request(
            10,
            8_000_000_000,
            common::get_domain(),
            Some(private_key.clone()),
            Some(consensus_key.clone()),
            Some(test_deposit1.withdrawal_credentials),
        );
        let (test_deposit3, _, _) = common::create_deposit_request(
            10,
            1_000_000_000,
            common::get_domain(),
            Some(private_key),
            Some(consensus_key),
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

        let deposit_process_height2 = last_block_in_epoch(
            DEFAULT_BLOCKS_PER_EPOCH,
            deposit_block_height2 / DEFAULT_BLOCKS_PER_EPOCH,
        );
        let _withdrawal_height2 =
            deposit_process_height2 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * DEFAULT_BLOCKS_PER_EPOCH;

        // Because we already check in `parse_execution_requests` if the deposit will
        // make the validator balance invalid.
        let deposit_process_height3 = deposit_block_height3;
        let withdrawal_height3 = deposit_process_height3
            + (VALIDATOR_WITHDRAWAL_NUM_EPOCHS + 1) * DEFAULT_BLOCKS_PER_EPOCH
            - 1;

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
        initial_state.set_minimum_stake(minimum_stake); // 32 ETH in gwei
        initial_state.set_maximum_stake(maximum_stake); // 40 ETH in gwei

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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
                tracked_peer_sets: NZUsize!(n as usize * 10), // Each engine may subscribe multiple times
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
            None,
        );

        let validator_node_key = test_deposit.node_pubkey.clone();

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;

        let deposit_process_height = last_block_in_epoch(
            DEFAULT_BLOCKS_PER_EPOCH,
            deposit_block_height / DEFAULT_BLOCKS_PER_EPOCH,
        );
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * DEFAULT_BLOCKS_PER_EPOCH;

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
            let namespace = String::from("_SUMMIT");

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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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
            None,
        );

        let validator_node_key = test_deposit.node_pubkey.clone();

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Create execution requests map (add deposit to block 5)
        let deposit_block_height = 5;

        let deposit_process_height = last_block_in_epoch(
            DEFAULT_BLOCKS_PER_EPOCH,
            deposit_block_height / DEFAULT_BLOCKS_PER_EPOCH,
        );
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * DEFAULT_BLOCKS_PER_EPOCH;

        let stop_height = withdrawal_height + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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
            common::create_deposit_request(n, min_stake, common::get_domain(), None, None, None);

        // Create another deposit to get a different node signature
        let (test_deposit2, _, _) =
            common::create_deposit_request(2, min_stake, common::get_domain(), None, None, None);

        // Only invalidate the node signature (keep consensus signature valid)
        test_deposit.node_signature = test_deposit2.node_signature;

        let validator_node_key = test_deposit.node_pubkey.clone();

        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        let deposit_block_height = 5;
        let deposit_process_height = last_block_in_epoch(
            DEFAULT_BLOCKS_PER_EPOCH,
            deposit_block_height / DEFAULT_BLOCKS_PER_EPOCH,
        );
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * DEFAULT_BLOCKS_PER_EPOCH;
        let stop_height = withdrawal_height + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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
                    if height >= stop_height {
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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
            common::create_deposit_request(n, min_stake, common::get_domain(), None, None, None);

        // Create another deposit to get a different consensus signature
        let (test_deposit2, _, _) =
            common::create_deposit_request(2, min_stake, common::get_domain(), None, None, None);

        // Only invalidate the consensus signature (keep node signature valid)
        test_deposit.consensus_signature = test_deposit2.consensus_signature;

        let validator_node_key = test_deposit.node_pubkey.clone();

        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        let deposit_block_height = 5;
        let deposit_process_height = last_block_in_epoch(
            DEFAULT_BLOCKS_PER_EPOCH,
            deposit_block_height / DEFAULT_BLOCKS_PER_EPOCH,
        );
        let withdrawal_height =
            deposit_process_height + VALIDATOR_WITHDRAWAL_NUM_EPOCHS * DEFAULT_BLOCKS_PER_EPOCH;
        let stop_height = withdrawal_height + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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
                    if height >= stop_height {
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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
            Some(key_stores[0].consensus_key.clone()),
            None,
        );
        let (deposit2, _, _) = common::create_deposit_request(
            0,
            deposit_amount2,
            common::get_domain(),
            Some(key_stores[0].node_key.clone()),
            Some(key_stores[0].consensus_key.clone()),
            Some(deposit1.withdrawal_credentials),
        );
        println!("{:?}", deposit1);
        println!("");
        println!("{:?}", deposit2);

        let validator0_pubkey = validators[0].0.clone();

        let execution_requests1 = vec![ExecutionRequest::Deposit(deposit1.clone())];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        let execution_requests2 = vec![ExecutionRequest::Deposit(deposit2.clone())];
        let requests2 = common::execution_requests_to_requests(execution_requests2);

        // First deposit at block 3, second at block 4 (both before processing at block 9)
        let deposit_block_height1 = 3;
        let deposit_block_height2 = 4;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height1, requests1);
        execution_requests_map.insert(deposit_block_height2, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();

        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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

/// `verify_deposit_request` must reject a deposit whose `consensus_pubkey`
/// matches an existing validator account's BLS key under a different node
/// public key.
///
/// Validator accounts are stored keyed by ed25519 node pubkey, so a fresh
/// node key + a re-used BLS key currently slips past the per-account
/// duplicate-deposit and signature checks. If that deposit is later
/// processed and activated, the active validator set contains two distinct
/// node identities mapped to the same BLS key. Epoch scheme construction
/// builds a one-to-one `BiMap` from node keys to BLS keys and panics on
/// duplicate BLS values (`types/src/scheme.rs:109`).
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2):
///  - 5 genesis validators @ 32 ETH with distinct BLS keys.
///  - Block 5: a deposit signed by a fresh ed25519 node key + reuses
///    genesis validator 0's BLS private key (i.e. an attacker who controls
///    that BLS key tries to register a second node identity under the same
///    BLS key).
///
/// Assertions (stop at block 10 — past deposit processing at block 8, but
/// before the duplicate would be activated at the epoch 1→2 boundary where
/// scheme construction would panic if the duplicate slipped through):
///  - No validator account exists at the fresh node pubkey. The deposit was
///    rejected and refunded; the duplicate never entered the validator set.
///  - Genesis validator 0 is unaffected.
#[test_traced("INFO")]
fn test_duplicate_bls_consensus_key_rejected() {
    use commonware_codec::Write;
    use summit_types::execution_request::DepositRequest;

    let n = 5;
    let min_stake = 32_000_000_000;
    let new_validator_amount = min_stake;
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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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

        // Build a deposit with a FRESH ed25519 node key but reuse genesis
        // validator 0's BLS private key as the consensus key. This simulates
        // an attacker who controls validator 0's BLS private key and is
        // trying to register a second validator identity under the same BLS
        // key. Both signatures verify, but the deposit must still be
        // rejected because the BLS key is already attached to another
        // validator account.
        let mut rng = StdRng::seed_from_u64(99_999);
        let new_node_priv = PrivateKey::random(&mut rng);
        let new_node_pub = new_node_priv.public_key();
        let dup_bls_priv = key_stores[0].consensus_key.clone();
        let dup_bls_pub = dup_bls_priv.public_key();
        // Sanity: the reused BLS key really is genesis validator 0's.
        assert_eq!(dup_bls_pub, validators[0].1);

        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;
        for j in 0..20 {
            withdrawal_credentials[12 + j] = (j as u8) ^ 0xAA;
        }

        let mut deposit = DepositRequest {
            node_pubkey: new_node_pub.clone(),
            consensus_pubkey: dup_bls_pub,
            withdrawal_credentials,
            amount: new_validator_amount,
            node_signature: [0u8; 64],
            consensus_signature: [0u8; 96],
            index: n as u64,
        };

        let message = deposit.as_message(common::get_domain());

        let node_sig = new_node_priv.sign(&[], &message);
        deposit.node_signature.copy_from_slice(node_sig.as_ref());

        let bls_sig = dup_bls_priv.sign(&[], &message);
        // Encode the BLS signature into the fixed-size signature buffer.
        let mut bls_sig_buf: Vec<u8> = Vec::new();
        bls_sig.write(&mut bls_sig_buf);
        assert_eq!(bls_sig_buf.len(), 96);
        deposit.consensus_signature.copy_from_slice(&bls_sig_buf);

        let deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(deposit)]);

        let deposit_block_height = 5;
        // Stop one block past the end of epoch 0 — deposit processing has
        // already run at block 8 (penultimate of epoch 0). The duplicate
        // would be activated at the epoch 1→2 boundary (end of block 19),
        // at which point scheme construction would panic on the BiMap if
        // the duplicate slipped through; we deliberately stop before that
        // so the test fails on the assertion (with the bug) instead of on
        // a panic in another task.
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, deposit_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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

        let state_query = consensus_state_queries.get(&0).unwrap();

        // The duplicate-BLS deposit must have been rejected at verification
        // time — no validator account should exist at the fresh node pubkey.
        let dup_account = state_query
            .get_validator_account(new_node_pub.clone())
            .await;
        assert!(
            dup_account.is_none(),
            "deposit with duplicate BLS consensus key must be rejected and \
             refunded, otherwise epoch scheme construction will later panic \
             on the duplicate BLS value; found account = {:?}",
            dup_account
        );

        // Genesis validator 0 is unaffected.
        let v0 = state_query
            .get_validator_account(validators[0].0.clone())
            .await
            .expect("genesis validator 0 should exist");
        assert_eq!(v0.status, ValidatorStatus::Active);
        assert_eq!(v0.balance, min_stake);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}

/// A top-up deposit for an existing validator account must carry the BLS
/// `consensus_pubkey` already stored on that account. Today
/// `verify_deposit_request` only checks the deposit's signatures and balance
/// bounds; the deposit's `consensus_pubkey` field is then silently ignored at
/// top-up processing time (`finalizer/src/actor.rs:1814` only touches
/// `balance`), so a top-up signed by the validator's node key but carrying a
/// fresh BLS keypair credits the validator's balance without any binding
/// between the deposit and the validator's actual consensus key.
///
/// This is defense-in-depth: a top-up should be strictly bound to the
/// validator identity it's topping up, otherwise the deposit shape and the
/// account state can drift apart in ways that are hard to reason about
/// (and that bypass the BLS-uniqueness check exercised by
/// `test_duplicate_bls_consensus_key_rejected`).
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10):
///  - 5 genesis validators @ 32 ETH (min_stake = 32 ETH, max_stake = 64 ETH).
///  - Block 5: top-up deposit for validator 0 worth 8 ETH, signed by
///    validator 0's node key BUT carrying a freshly-generated BLS keypair as
///    `consensus_pubkey` (and signed by that fresh BLS key, so the BLS
///    signature still verifies). The fresh BLS key is not in use by any
///    existing account.
///
/// Assertions (stop at block 10 — past deposit processing at block 8):
///  - Validator 0's balance is unchanged at 32 ETH. The mismatched top-up
///    was refunded, not credited.
///  - Validator 0's stored `consensus_public_key` is still the original
///    genesis BLS key (the deposit's fresh key never replaced it).
#[test_traced("INFO")]
fn test_top_up_deposit_with_mismatched_bls_key_rejected() {
    use commonware_codec::Write;
    use summit_types::execution_request::DepositRequest;

    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 64_000_000_000;
    let top_up_amount = 8_000_000_000;
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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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

        // Top-up deposit for validator 0: signed with validator 0's node
        // private key (correct), but carrying a FRESH BLS keypair as
        // consensus_pubkey + consensus_signature. Both signatures verify, but
        // the deposit's BLS key does not match validator 0's stored BLS key.
        let v0_node_priv = key_stores[0].node_key.clone();
        let v0_node_pub = v0_node_priv.public_key();
        let v0_original_bls_pub = validators[0].1.clone();

        let mut rng = StdRng::seed_from_u64(424_242);
        let fresh_bls_priv = bls12381::PrivateKey::random(&mut rng);
        let fresh_bls_pub = fresh_bls_priv.public_key();
        // Sanity: the fresh BLS key isn't already in use, so this deposit
        // doesn't trip a duplicate-BLS-key check; it must fail purely on the
        // "doesn't match the existing account's BLS key" check.
        assert!(validators.iter().all(|(_, bls)| bls != &fresh_bls_pub));

        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01;
        for j in 0..20 {
            withdrawal_credentials[12 + j] = j as u8;
        }

        let mut deposit = DepositRequest {
            node_pubkey: v0_node_pub.clone(),
            consensus_pubkey: fresh_bls_pub,
            withdrawal_credentials,
            amount: top_up_amount,
            node_signature: [0u8; 64],
            consensus_signature: [0u8; 96],
            index: n as u64,
        };

        let message = deposit.as_message(common::get_domain());

        let node_sig = v0_node_priv.sign(&[], &message);
        deposit.node_signature.copy_from_slice(node_sig.as_ref());

        let bls_sig = fresh_bls_priv.sign(&[], &message);
        let mut bls_sig_buf: Vec<u8> = Vec::new();
        bls_sig.write(&mut bls_sig_buf);
        assert_eq!(bls_sig_buf.len(), 96);
        deposit.consensus_signature.copy_from_slice(&bls_sig_buf);

        let deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(deposit)]);

        let deposit_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, deposit_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        // Raise max_stake so that the post-top-up balance (32 + 8 = 40) is
        // within [min, max]; otherwise the bounds check at deposit
        // verification refunds the deposit and we wouldn't actually be
        // exercising the missing "BLS key must match the account's stored
        // BLS key" check.
        initial_state.set_maximum_stake(max_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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

        let state_query = consensus_state_queries.get(&0).unwrap();
        let v0 = state_query
            .get_validator_account(v0_node_pub.clone())
            .await
            .expect("validator 0 account should still exist");

        // The mismatched top-up must have been refunded, not credited.
        // (max_stake is 64 ETH, so 32 + 8 = 40 is within bounds; the bounds
        // check can't be the reason for rejection.)
        assert_eq!(
            v0.balance, min_stake,
            "validator 0's balance must remain at its genesis 32 ETH; the \
             top-up carrying a BLS key that does not match the account's \
             stored BLS key must be refunded, not credited"
        );

        // The stored BLS key on validator 0's account is unchanged — the
        // deposit's fresh BLS key never replaces it.
        assert_eq!(
            v0.consensus_public_key, v0_original_bls_pub,
            "validator 0's stored BLS key must not be overwritten by a \
             top-up deposit carrying a different BLS key"
        );

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    })
}
