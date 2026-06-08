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
            n as u64, // use a private key seed that doesn't exist on the consensus state
            min_stake,
            common::get_domain(),
            None,
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
        // The deposit request will be processed after 10 blocks because `DEFAULT_BLOCKS_PER_EPOCH`
        // is set to 10.
        // The withdrawal request should be added after block 10, otherwise it will be ignored, because
        // the account doesn't exist yet.
        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 2;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height) // stop after the epoch+1 hold period on withdrawals
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
        let stop_height = withdrawal_block_height + DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
    // - The deposit refund is queued under a refund-only key, so it stays separate from the
    //   validator's real withdrawal even though both pay the same address
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
            Some(key_stores[0].consensus_key.clone()),
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
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);
        execution_requests_map.insert(deposit_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
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

        // Verify withdrawal occurred and rejected deposit was refunded as a separate entry.
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), 2);

        let withdrawal_amounts: Vec<u64> = epoch_withdrawals
            .iter()
            .map(|withdrawal| withdrawal.amount)
            .collect();
        assert!(withdrawal_amounts.contains(&min_stake));
        assert!(withdrawal_amounts.contains(&deposit_amount));
        assert!(
            epoch_withdrawals
                .iter()
                .all(|withdrawal| withdrawal.address == withdrawal_address)
        );

        let validator0_client_id = format!("validator_{}", validators[0].0);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&validator0_client_id])
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[0]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_invalid_deposit_refund_does_not_merge_with_later_withdrawal() {
    // Tests that an invalid deposit refund cannot poison the withdrawal queue for an
    // existing validator.
    //
    // Test setup:
    // - Genesis validator 0 starts with 32 ETH and victim withdrawal credentials
    // - Block 3 includes an invalid deposit request that targets validator 0's pubkey but uses
    //   attacker-controlled withdrawal credentials
    // - Block 4 includes validator 0's legitimate withdrawal request to the victim address
    // - The invalid deposit refund is queued under a synthetic refund key
    // - The later legitimate withdrawal remains keyed by the real validator pubkey
    // - Both withdrawals are processed independently at the same withdrawal height
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
    let deposit_amount = 5_000_000_000; // 5 ETH
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

        let victim_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let victim_address = addresses[0];
        let attacker_address = addresses[1];

        let mut attacker_withdrawal_credentials = [0u8; 32];
        attacker_withdrawal_credentials[0] = 0x01;
        attacker_withdrawal_credentials[12..32].copy_from_slice(attacker_address.as_ref());

        let (mut invalid_deposit, _, _) = common::create_deposit_request(
            99,
            deposit_amount,
            common::get_domain(),
            None,
            None,
            Some(attacker_withdrawal_credentials),
        );
        // Re-target the deposit to the existing validator after signing so signature verification
        // fails but the refund path still keys the withdrawal to the victim validator pubkey.
        invalid_deposit.node_pubkey = validators[0].0.clone();

        let victim_withdrawal =
            common::create_withdrawal_request(victim_address, victim_pubkey, min_stake);

        let invalid_deposit_block_height = 3;
        let legitimate_withdrawal_block_height = 4;
        let withdrawal_epoch = (legitimate_withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH)
            + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let requests1 = common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
            invalid_deposit.clone(),
        )]);
        let requests2 = common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(
            victim_withdrawal.clone(),
        )]);

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(invalid_deposit_block_height, requests1);
        execution_requests_map.insert(legitimate_withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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

        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);

        let epoch_withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing withdrawals");
        assert_eq!(epoch_withdrawals.len(), 2);

        let attacker_withdrawal = epoch_withdrawals
            .iter()
            .find(|withdrawal| withdrawal.address == attacker_address)
            .expect("missing attacker refund");
        assert_eq!(attacker_withdrawal.amount, deposit_amount);

        let victim_withdrawal = epoch_withdrawals
            .iter()
            .find(|withdrawal| withdrawal.address == victim_address)
            .expect("missing victim withdrawal");
        assert_eq!(victim_withdrawal.amount, min_stake);

        let victim_client_id = format!("validator_{}", validators[0].0);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&victim_client_id])
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[0]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_invalid_deposit_refund_applies_invalid_deposit_tax() {
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
    let deposit_amount = 5_000_000_000;
    let invalid_deposit_tax = 25;
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

        let refund_address = addresses[1];
        let treasury_address = Address::from([0xEE; 20]);
        let mut refund_withdrawal_credentials = [0u8; 32];
        refund_withdrawal_credentials[0] = 0x01;
        refund_withdrawal_credentials[12..32].copy_from_slice(refund_address.as_ref());

        let (mut invalid_deposit, _, _) = common::create_deposit_request(
            99,
            deposit_amount,
            common::get_domain(),
            None,
            None,
            Some(refund_withdrawal_credentials),
        );
        invalid_deposit.node_pubkey = validators[0].0.clone();

        let invalid_deposit_block_height = 3;
        let withdrawal_epoch = (invalid_deposit_block_height / DEFAULT_BLOCKS_PER_EPOCH)
            + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let requests = common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
            invalid_deposit.clone(),
        )]);

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(invalid_deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.set_maximum_stake(max_stake);
        initial_state.set_treasury_address(treasury_address);
        initial_state.set_invalid_deposit_tax(invalid_deposit_tax);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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

        let withdrawals = engine_client_network.get_withdrawals();
        let epoch_withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing invalid-deposit withdrawals");
        assert_eq!(epoch_withdrawals.len(), 2);

        let refund_withdrawal = epoch_withdrawals
            .iter()
            .find(|withdrawal| withdrawal.address == refund_address)
            .expect("missing depositor refund");
        assert_eq!(refund_withdrawal.amount, 3_750_000_000);

        let tax_withdrawal = epoch_withdrawals
            .iter()
            .find(|withdrawal| withdrawal.address == treasury_address)
            .expect("missing invalid-deposit tax withdrawal");
        assert_eq!(tax_withdrawal.amount, 1_250_000_000);

        common::assert_state_root_consensus_skip(&consensus_state_queries, &[0]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_process_time_invalid_new_validator_refund_does_not_merge_with_reused_pubkey_withdrawal() {
    // A new-validator deposit can pass parse-time validation, then become invalid at
    // deposit-processing time because stake bounds changed in between. That refund
    // must not poison the queue for a later account that reuses the same node pubkey
    // with different withdrawal credentials.
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 40_000_000_000;
    let lowered_max_stake = 32_000_000_000;
    let stale_deposit_amount = 40_000_000_000;
    let valid_deposit_amount = 32_000_000_000;
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

        let stale_refund_address = Address::from([0xAA; 20]);
        let current_withdrawal_address = Address::from([0xBB; 20]);

        let mut stale_withdrawal_credentials = [0u8; 32];
        stale_withdrawal_credentials[0] = 0x01;
        stale_withdrawal_credentials[12..32].copy_from_slice(stale_refund_address.as_slice());

        let mut current_withdrawal_credentials = [0u8; 32];
        current_withdrawal_credentials[0] = 0x01;
        current_withdrawal_credentials[12..32]
            .copy_from_slice(current_withdrawal_address.as_slice());

        let (stale_deposit, reused_node_key, _) = common::create_deposit_request(
            99,
            stale_deposit_amount,
            common::get_domain(),
            None,
            None,
            Some(stale_withdrawal_credentials),
        );
        let reused_pubkey: [u8; 32] = stale_deposit.node_pubkey.as_ref().try_into().unwrap();

        let (valid_deposit, _, _) = common::create_deposit_request(
            100,
            valid_deposit_amount,
            common::get_domain(),
            Some(reused_node_key),
            None,
            Some(current_withdrawal_credentials),
        );
        assert_eq!(valid_deposit.node_pubkey, stale_deposit.node_pubkey);

        let withdrawal_request = common::create_withdrawal_request(
            current_withdrawal_address,
            reused_pubkey,
            valid_deposit_amount,
        );

        let param_request = common::create_protocol_param_request(0x01, lowered_max_stake);
        let param_block_height = 5;
        let stale_deposit_block_height = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        let valid_deposit_block_height = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 1);
        let withdrawal_block_height = 30;

        let stale_refund_epoch = 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let stale_refund_height = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, stale_refund_epoch);
        let current_withdrawal_epoch = 3 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let current_withdrawal_height =
            last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, current_withdrawal_epoch);
        let stop_height = current_withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(
            param_block_height,
            common::execution_requests_to_requests(vec![ExecutionRequest::ProtocolParam(
                param_request,
            )]),
        );
        execution_requests_map.insert(
            stale_deposit_block_height,
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
                stale_deposit.clone(),
            )]),
        );
        execution_requests_map.insert(
            valid_deposit_block_height,
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
                valid_deposit.clone(),
            )]),
        );
        execution_requests_map.insert(
            withdrawal_block_height,
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(
                withdrawal_request,
            )]),
        );

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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
        assert_eq!(state_query.get_maximum_stake().await, lowered_max_stake);

        let withdrawals = engine_client_network.get_withdrawals();
        let stale_epoch_withdrawals = withdrawals
            .get(&stale_refund_height)
            .expect("missing process-time stale refund withdrawal");
        assert!(
            stale_epoch_withdrawals.iter().any(|withdrawal| {
                withdrawal.address == stale_refund_address
                    && withdrawal.amount == stale_deposit_amount
            }),
            "process-time invalid deposit refund should remain separate; got withdrawals = {stale_epoch_withdrawals:?}"
        );
        assert!(
            !stale_epoch_withdrawals.iter().any(|withdrawal| {
                withdrawal.address == stale_refund_address
                    && withdrawal.amount == stale_deposit_amount + valid_deposit_amount
            }),
            "later valid withdrawal must not merge into stale refund address; got withdrawals = {stale_epoch_withdrawals:?}"
        );

        let current_epoch_withdrawals = withdrawals
            .get(&current_withdrawal_height)
            .expect("missing later valid withdrawal");
        assert!(
            current_epoch_withdrawals.iter().any(|withdrawal| {
                withdrawal.address == current_withdrawal_address
                    && withdrawal.amount == valid_deposit_amount
            }),
            "later valid withdrawal should be paid to current credentials; got withdrawals = {current_epoch_withdrawals:?}"
        );

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_invalid_deposit_refunds_do_not_delay_validator_exit_withdrawal() {
    // Invalid deposits that are rejected before deposit queue admission should not
    // consume the scarce withdrawal slot ahead of a legitimate validator exit.
    let n = 5;
    let min_stake = 32_000_000_000;
    let invalid_deposit_amount = 1;
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

        let (invalid_deposit0, _, _) = common::create_deposit_request(
            50,
            invalid_deposit_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        let (invalid_deposit1, _, _) = common::create_deposit_request(
            51,
            invalid_deposit_amount,
            common::get_domain(),
            None,
            None,
            None,
        );

        let exit_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let exit_withdrawal = common::create_withdrawal_request(Address::ZERO, exit_pubkey, min_stake);

        let refund_requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Deposit(invalid_deposit0),
            ExecutionRequest::Deposit(invalid_deposit1),
        ]);
        let exit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(
                exit_withdrawal,
            )]);

        let invalid_deposit_block_height = 3;
        let exit_block_height = 4;
        let first_withdrawal_epoch =
            (exit_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let first_withdrawal_height =
            last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, first_withdrawal_epoch);
        let stop_height = first_withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(invalid_deposit_block_height, refund_requests);
        execution_requests_map.insert(exit_block_height, exit_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_max_withdrawals_per_epoch(1);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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

        let withdrawals = engine_client_network.get_withdrawals();
        let epoch_withdrawals = withdrawals
            .get(&first_withdrawal_height)
            .expect("missing withdrawals at first eligible withdrawal epoch");
        assert!(
            epoch_withdrawals
                .iter()
                .any(|withdrawal| withdrawal.address == Address::ZERO
                    && withdrawal.amount == min_stake),
            "validator exit should not be delayed by invalid-deposit refunds; got withdrawals = {epoch_withdrawals:?}"
        );

        let exiting_client_id = format!("validator_{}", validators[0].0);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&exiting_client_id])
                .is_ok()
        );

        common::assert_state_root_consensus_skip(&consensus_state_queries, &[0]).await;

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
                tracked_peer_sets: NZUsize!(n as usize * 10),
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
            Some(key_stores[0].consensus_key.clone()),
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
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests1);
        execution_requests_map.insert(withdrawal_block_height, requests2);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_last_block_topup_does_not_drop_staged_removal_balance() {
    // No invalid-deposit tax configured: the full 33 ETH (32 bonded + 1 top-up) is
    // returned to the victim's address.
    run_staged_removal_topup_scenario(0);
}

#[test_traced("INFO")]
fn test_last_block_topup_staged_removal_refund_is_untaxed() {
    // A nonzero invalid_deposit_tax must NOT skim the refunded top-up. The top-up was
    // a valid deposit (valid shape, signature, and resulting balance) refunded only
    // because the independent stake-bound removal wins — the depositor is blameless,
    // the bonded balance is returned untaxed, and the canonical stake-bound exit
    // applies no tax. So with a 25% tax configured the victim must still receive the
    // full 33 ETH and the treasury must receive nothing.
    run_staged_removal_topup_scenario(25);
}

// Shared scenario for the stake-bound staged-removal + last-block top-up balance drop.
//
// Scenario (audit issue):
//   1. A MinimumStake increase (32 -> 33 ETH) is submitted early in epoch 0.
//   2. The victim validator (validators[0], 32 ETH) will fall below the new minimum. The
//      other validators are at 40 ETH, so only the victim is a removal candidate (and the
//      minimum-validator-count floor of 3 still permits staging one of the five).
//   3. At the penultimate block of epoch 0 the victim is staged into removed_validators.
//   4. At the last block of epoch 0 the victim submits a 1 ETH top-up. This sets
//      has_pending_deposit = true and queues the deposit: 32 + 1 = 33 still passes the
//      parse-time bounds check because the raised minimum has not been applied yet.
//   5. At the epoch boundary the staged removal marks the victim Inactive (balance 32 kept),
//      and the stake-bound withdrawal scan SKIPS the victim because has_pending_deposit.
//   6. At the next penultimate block (epoch 1) the queued top-up is processed against the
//      now-Inactive account. The buggy code treats it as a new-validator deposit, uses
//      new_balance = request.amount (1 ETH), refunds only the 1 ETH and removes the account.
//
// Correct behavior (removal wins): the staged removal is honored. When the top-up is processed
// against the Inactive account, the victim's original 32 ETH bonded balance is withdrawn to its
// withdrawal address and the 1 ETH top-up is refunded in full (never credited, never taxed),
// so the full 33 ETH is returned to the victim's address and the account is removed. The
// original bonded balance is never silently dropped, and the treasury never receives a cut of
// the valid top-up regardless of `invalid_deposit_tax`.
fn run_staged_removal_topup_scenario(invalid_deposit_tax: u64) {
    let n = 5;
    let min_stake = 32_000_000_000; // 32 ETH (victim's balance)
    let healthy_balance = 40_000_000_000; // 40 ETH (other validators, above the raised minimum)
    let max_stake = 100_000_000_000; // 100 ETH
    let new_min_stake = 33_000_000_000; // 33 ETH (raised minimum, above the victim's balance)
    let topup_amount = 1_000_000_000; // 1 ETH last-block top-up
    // Distinct from every validator address ([0x00..0x04]) so a taxed cut, if one
    // were (wrongly) taken, would land here and be observable.
    let treasury_address = Address::from([0xEE; 20]);
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

        // Withdrawal credentials per validator, created after sorting so they align.
        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // The victim is validators[0] (smallest pubkey after sorting).
        let victim_idx = 0usize;
        let victim_pubkey = validators[victim_idx].0.clone();
        let victim_address = addresses[victim_idx];

        // The victim's last-block top-up reuses the victim's node + consensus keys so it is
        // recognized as an existing-validator top-up rather than a new validator.
        let mut victim_withdrawal_credentials = [0u8; 32];
        victim_withdrawal_credentials[0] = 0x01;
        victim_withdrawal_credentials[12..32].copy_from_slice(victim_address.as_ref());
        let (topup_deposit, _, _) = common::create_deposit_request(
            50, // deposit index distinct from the genesis validators
            topup_amount,
            common::get_domain(),
            Some(key_stores[victim_idx].node_key.clone()),
            Some(key_stores[victim_idx].consensus_key.clone()),
            Some(victim_withdrawal_credentials),
        );

        // MinimumStake increase (param_id 0x00).
        let min_stake_update = common::create_protocol_param_request(0x00, new_min_stake);

        // Block schedule (DEFAULT_BLOCKS_PER_EPOCH = 10):
        //   - param update early in epoch 0 (pending through the epoch, applied at its last block)
        //   - victim staged at the penultimate block of epoch 0
        //   - victim top-up at the LAST block of epoch 0 (after staging)
        let param_block = 3;
        let topup_block = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        // The queued top-up is processed at the penultimate block of epoch 1, where the resulting
        // refund/withdrawal is scheduled `VALIDATOR_WITHDRAWAL_NUM_EPOCHS` epochs out.
        let resolution_epoch = 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let resolution_height = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, resolution_epoch);
        let stop_height = resolution_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(
            param_block,
            common::execution_requests_to_requests(vec![ExecutionRequest::ProtocolParam(
                min_stake_update,
            )]),
        );
        execution_requests_map.insert(
            topup_block,
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
                topup_deposit.clone(),
            )]),
        );

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        // Genesis: victim at 32 ETH, every other validator at 40 ETH (above the raised minimum),
        // maximum stake raised to 100 ETH so the healthy validators stay in range.
        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.set_maximum_stake(max_stake);
        initial_state.set_treasury_address(treasury_address);
        initial_state.set_invalid_deposit_tax(invalid_deposit_tax);
        for idx in 0..n as usize {
            if idx == victim_idx {
                continue;
            }
            let pk_bytes: [u8; 32] = validators[idx].0.as_ref().try_into().unwrap();
            let mut account = initial_state.get_account(&pk_bytes).unwrap().clone();
            account.balance = healthy_balance;
            initial_state.set_account(pk_bytes, account);
        }

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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

        // The victim exits the validator set, so only n-1 validators keep finalizing.
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

        // Query a surviving validator's view of the canonical state.
        let state_query = consensus_state_queries.get(&1).unwrap();

        // Sanity: the MinimumStake increase was applied.
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);

        // The staged removal is honored: the victim account no longer exists.
        let victim_account = state_query.get_validator_account(victim_pubkey).await;
        assert!(
            victim_account.is_none(),
            "staged-removal validator should be removed once its top-up is resolved, got {victim_account:?}"
        );

        // The victim's original bonded balance is returned to the EL rather than silently dropped:
        // the full 32 ETH is withdrawn and the 1 ETH top-up is refunded in full, so 33 ETH total
        // reaches the victim's withdrawal address regardless of the configured tax.
        let withdrawals = engine_client_network.get_withdrawals();
        let total_withdrawn_to_victim: u64 = withdrawals
            .values()
            .flatten()
            .filter(|withdrawal| withdrawal.address == victim_address)
            .map(|withdrawal| withdrawal.amount)
            .sum();
        assert_eq!(
            total_withdrawn_to_victim,
            min_stake + topup_amount,
            "expected the original bonded balance ({min_stake}) plus the refunded top-up \
             ({topup_amount}) to be returned to the victim's address, got {total_withdrawn_to_victim}"
        );

        // The refunded top-up is a valid deposit returned only because the removal wins, so it
        // must never be taxed: the treasury receives nothing even with a nonzero tax configured.
        let total_to_treasury: u64 = withdrawals
            .values()
            .flatten()
            .filter(|withdrawal| withdrawal.address == treasury_address)
            .map(|withdrawal| withdrawal.amount)
            .sum();
        assert_eq!(
            total_to_treasury, 0,
            "the valid top-up refund must not be taxed (tax = {invalid_deposit_tax}), \
             but the treasury received {total_to_treasury}"
        );

        // The network stays consistent across the validators that remain.
        let victim_client_id = format!("validator_{}", validators[victim_idx].0);
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&victim_client_id])
                .is_ok()
        );
        common::assert_state_root_consensus_skip(&consensus_state_queries, &[victim_idx]).await;

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_pending_topup_does_not_evade_minimum_stake_increase() {
    // A validator must not stay active below the minimum stake by having an insufficient top-up
    // pending across a MinimumStake increase.
    //
    // Stake-bound enforcement is one-shot — it runs only at the boundary where a stake param
    // actually changes (staging is gated by `has_pending_stake_bound_change()`, the scan by
    // `stake_changed`). At that single boundary, #188 skips any account with a pending deposit.
    // So if a top-up is still queued when the increase applies, the validator is skipped and is
    // never re-checked: it remains active below the new minimum.
    //
    // This is reached through the real ingestion path (no state editing) with a zero
    // deposit-processing cap — the "low/zero cap" trigger the finding describes — which keeps the
    // top-up queued across the boundary. The victim's top-up (1 ETH) cannot cover the increase
    // (32 -> 40), so even once processed it could never satisfy the new minimum.
    let n = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 100_000_000_000;
    let new_min_stake = 40_000_000_000;
    let topup_amount = 1_000_000_000; // 1 ETH — far short of the 8 ETH needed to reach the new min
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

        // Victim is validators[0]. Its top-up uses its own keys so it is a valid top-up.
        let victim_idx = 0usize;
        let victim_pubkey = validators[victim_idx].0.clone();
        let victim_address = addresses[victim_idx];
        let mut victim_credentials = [0u8; 32];
        victim_credentials[0] = 0x01;
        victim_credentials[12..32].copy_from_slice(victim_address.as_ref());
        let (topup_deposit, _, _) = common::create_deposit_request(
            50,
            topup_amount,
            common::get_domain(),
            Some(key_stores[victim_idx].node_key.clone()),
            Some(key_stores[victim_idx].consensus_key.clone()),
            Some(victim_credentials),
        );

        // Submit the top-up and the MinimumStake increase early in epoch 0 (param applies at the
        // epoch-0 boundary; the top-up is queued and — with the zero cap — stays queued across it).
        let min_stake_update = common::create_protocol_param_request(0x00, new_min_stake);
        let submit_block = 3;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(
            submit_block,
            common::execution_requests_to_requests(vec![
                ExecutionRequest::Deposit(topup_deposit.clone()),
                ExecutionRequest::ProtocolParam(min_stake_update),
            ]),
        );

        // Run well past the increase and any withdrawal window so a correctly-enforced removal
        // would have completed.
        let stop_height =
            last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, VALIDATOR_WITHDRAWAL_NUM_EPOCHS + 2) + 1;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
        initial_state.set_maximum_stake(max_stake);
        // Zero deposit-processing cap keeps the top-up queued across the MinimumStake boundary.
        initial_state.set_max_deposits_per_epoch(0);
        // Only the victim should fall below the raised minimum. Give every other validator a
        // balance comfortably above it so the increase doesn't force-remove the rest of the
        // committee (which would collapse consensus and confound the test).
        let healthy_balance = 50_000_000_000;
        for idx in 0..n as usize {
            if idx == victim_idx {
                continue;
            }
            let pk_bytes: [u8; 32] = validators[idx].0.as_ref().try_into().unwrap();
            let mut account = initial_state.get_account(&pk_bytes).unwrap().clone();
            account.balance = healthy_balance;
            initial_state.set_account(pk_bytes, account);
        }

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
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

        // The victim should be force-removed, so only n-1 validators keep finalizing once the fix
        // is in place. Without the fix all n keep going, so wait for at least n-1.
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

                if height_reached.len() as u32 >= n - 1 {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Sanity: the MinimumStake increase was applied.
        let state_query = consensus_state_queries.get(&1).unwrap();
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);

        // The victim cannot satisfy the raised minimum, so it must not remain an active
        // below-minimum validator — it should be force-removed (its stake withdrawn).
        let account = state_query.get_validator_account(victim_pubkey).await;
        assert!(
            account
                .as_ref()
                .is_none_or(|account| account.balance >= new_min_stake),
            "validator below the raised minimum must be force-removed, not left active below it: {account:?}"
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
            Some(key_stores[0].consensus_key.clone()),
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
        let stop_height = 2 * DEFAULT_BLOCKS_PER_EPOCH;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(request_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    })
}
