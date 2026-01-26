use super::*;

#[test_traced("INFO")]
fn test_protocol_param_max_stake() {
    // Adds a protocol param request for maximum stake to the block at height 5
    // and verifies that the maximum stake is changed at the end of the epoch.
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
