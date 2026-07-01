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

        // Create a single deposit request using the helper. The deposit is twice
        // the minimum stake so the later partial withdrawal leaves the validator
        // at the minimum stake (so its account survives, rather than draining to
        // zero and being removed).
        let (test_deposit, _, _) = common::create_deposit_request(
            n as u64, // use a private key seed that doesn't exist on the consensus state
            2 * min_stake,
            common::get_domain(),
            None,
            None,
            None,
        );

        // Withdraw the minimum stake: a partial withdrawal that leaves the
        // validator at the minimum stake.
        let withdrawal_address = Address::from_slice(&test_deposit.withdrawal_credentials[12..32]);
        let test_withdrawal = common::create_withdrawal_request(
            withdrawal_address,
            test_deposit.node_pubkey.as_ref().try_into().unwrap(),
            min_stake,
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
        // Poll consensus state until the deposit is credited and the partial
        // withdrawal has been paid out (balance reduced by the withdrawal amount).
        let mut height_reached = HashSet::new();
        let mut processed_requests = HashSet::new();
        loop {
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

            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
                if let Some(balance) = query
                    .get_validator_balance(test_deposit.node_pubkey.clone())
                    .await
                    && balance == test_deposit.amount - test_withdrawal.amount
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

        // Create deposit and matching withdrawal requests, one per validator.
        // Each deposit uses a fresh key (seed offset past the genesis validators)
        // for twice the minimum stake; the matching withdrawal is a partial of the
        // minimum stake, leaving each validator at the minimum stake.
        let mut deposit_reqs = HashMap::new();
        let mut withdrawal_reqs = HashMap::new();
        for i in 0..n {
            let (test_deposit, _, _) = common::create_deposit_request(
                (n + i) as u64,
                2 * min_stake,
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
                min_stake,
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
        let withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 2;
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

        // Poll consensus state until all validators reach the stop height. The
        // deposited validators are cancelled while still joining (the withdrawal
        // arrives before they activate), so they never join the committee and the
        // original n validators drive consensus.
        let mut height_reached = HashSet::new();
        loop {
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

            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
            }

            if height_reached.len() as u32 == n {
                break;
            }

            // Still waiting for all validators to complete
            context.sleep(Duration::from_secs(1)).await;
        }

        // Each deposited validator was credited twice the minimum stake and then
        // partially withdrew the minimum stake, leaving it at the minimum stake.
        let state_query = consensus_state_queries.get(&0).unwrap();
        for deposit_req in deposit_reqs.values() {
            let balance = state_query
                .get_validator_balance(deposit_req.node_pubkey.clone())
                .await
                .expect("deposited validator should still exist");
            assert_eq!(balance, deposit_req.amount - min_stake);
        }

        // Every partial withdrawal is paid out at the same scheduled height.
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);
        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), withdrawal_reqs.len());

        let expected_withdrawals: HashMap<Address, _> = withdrawal_reqs
            .into_iter()
            .map(|(_, withdrawal)| (withdrawal.source_address, withdrawal))
            .collect();
        for withdrawal in epoch_withdrawals {
            let expected_withdrawal = expected_withdrawals.get(&withdrawal.address).unwrap();
            assert_eq!(withdrawal.amount, expected_withdrawal.amount);
            assert_eq!(withdrawal.address, expected_withdrawal.source_address);
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

        // A full exit (amount 0): validator 0 leaves and its entire balance
        // (min_stake) is paid out, independent of the attacker's refund.
        let victim_withdrawal = common::create_withdrawal_request(victim_address, victim_pubkey, 0);

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

            for (idx, query) in consensus_state_queries.iter() {
                // Validator 0 fully exits and shuts its node down, so its mailbox
                // is not queried.
                if *idx == 0 {
                    continue;
                }
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
            }

            if height_reached.len() as u32 == n - 1 {
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

            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
            }

            // The invalid deposit is refunded without touching any validator's
            // committee membership, so all validators keep finalizing.
            if height_reached.len() as u32 == n {
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

        // Re-target the node pubkey after signing so the node signature no longer
        // matches: the deposit is rejected at processing time and refunded (a
        // DepositRefund-kind payout), which must not preempt the validator exit.
        let (mut invalid_deposit0, _, _) = common::create_deposit_request(
            50,
            invalid_deposit_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        invalid_deposit0.node_pubkey = validators[1].0.clone();
        let (mut invalid_deposit1, _, _) = common::create_deposit_request(
            51,
            invalid_deposit_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        invalid_deposit1.node_pubkey = validators[2].0.clone();

        // A full exit (amount 0): validator 0 leaves and its whole balance is paid out.
        let exit_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let exit_withdrawal = common::create_withdrawal_request(Address::ZERO, exit_pubkey, 0);

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
