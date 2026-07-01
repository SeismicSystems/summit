use super::*;
use summit_types::execution_request::ProtocolParamRequest;
use summit_types::protocol_params::MAX_MAX_DEPOSITS_PER_EPOCH;

#[test_traced("INFO")]
fn test_grouped_protocol_param_requests_in_single_eip7685_entry() {
    // Adds two protocol param requests in a single grouped type-0xFF EIP-7685 entry
    // and verifies that both values are applied at the end of the epoch.
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

        let new_min_stake = 16_000_000_000u64;
        let new_max_stake = 64_000_000_000u64;
        let min_request = common::create_protocol_param_request(0x00, new_min_stake);
        let max_request = common::create_protocol_param_request(0x01, new_max_stake);

        let requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::ProtocolParam(min_request),
            ExecutionRequest::ProtocolParam(max_request),
        ]);

        let protocol_param_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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

            // Height comes from each validator's consensus state, queried via
            // the finalizer mailbox.
            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
            }

            if height_reached.len() as u32 == n {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);
        assert_eq!(state_query.get_maximum_stake().await, new_max_stake);

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
fn test_protocol_param_allowed_timestamp_future() {
    // Adds a protocol param request for allowed_timestamp_future to the block at height 5
    // and verifies that the value is changed at the end of the epoch.
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

        // Create a protocol param request for allowed_timestamp_future (param_id 0x03)
        let new_allowed_timestamp_future = 30_000u64; // 30 seconds
        let test_protocol_param =
            common::create_protocol_param_request(0x03, new_allowed_timestamp_future);

        let execution_requests = vec![ExecutionRequest::ProtocolParam(test_protocol_param)];
        let requests = common::execution_requests_to_requests(execution_requests);

        let protocol_param_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height, requests);

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

        // Poll metrics
        let mut height_reached = HashSet::new();
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

            // Height comes from each validator's consensus state, queried via
            // the finalizer mailbox.
            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= stop_height {
                    height_reached.insert(*idx);
                }
            }

            if height_reached.len() as u32 == n {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        // Check that allowed_timestamp_future was updated
        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(
            state_query.get_allowed_timestamp_future().await,
            new_allowed_timestamp_future
        );

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

        // Create a single protocol_param request for minimum stake
        let new_max_stake = 64_000_000_000;
        let test_protocol_param1 = common::create_protocol_param_request(0x01, new_max_stake);

        // Convert to ExecutionRequest and then to Requests
        let execution_requests1 = vec![ExecutionRequest::ProtocolParam(
            test_protocol_param1.clone(),
        )];
        let requests1 = common::execution_requests_to_requests(execution_requests1);

        // Create execution requests map (add deposit to block 5)
        // The protocol param request will be processed after 10 blocks because `DEFAULT_BLOCKS_PER_EPOCH`
        // is set to 10.
        let protocol_param_block_height1 = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height1, requests1);

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

            // Height comes from each validator's consensus state, queried via
            // the finalizer mailbox.
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

        // Check that the minimum stake was updated
        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(state_query.get_maximum_stake().await, new_max_stake);

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
fn test_protocol_param_treasury_address() {
    // Tests that the treasury address protocol parameter controls suggested_fee_recipient:
    // - Epoch 0: treasury_address is zero → fee_recipient = proposer's withdrawal credentials
    // - Protocol param request at block 5 sets treasury_address to non-zero
    // - After epoch 0 boundary is finalized: fee_recipient = treasury_address
    let n = 5;
    let min_stake = 32_000_000_000;
    let treasury_address = Address::from([0xAB; 20]);
    let withdrawal_cred = Address::from([0xCC; 20]);
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

        // Create a treasury address protocol param request (param_id 0x04, 20-byte address)
        let test_protocol_param = ProtocolParamRequest {
            param_id: 0x04,
            param: treasury_address.as_slice().to_vec(),
        };

        let execution_requests =
            vec![ExecutionRequest::ProtocolParam(test_protocol_param)];
        let requests = common::execution_requests_to_requests(execution_requests);

        let last_epoch0 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        let first_epoch1 = last_epoch0 + 1;
        let protocol_param_block_height = last_epoch0 / 2; // mid-epoch
        let stop_height = first_epoch1 + 1; // one block into epoch 1
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let withdrawal_creds = vec![withdrawal_cred; n as usize];
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            Some(&withdrawal_creds),
            None,
            min_stake,
        );

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

        // Before the epoch boundary, the treasury address is zero so fee_recipient
        // should be the proposer's withdrawal credentials.
        let fee_recipients = engine_client_network.get_fee_recipients();
        let epoch0_check_height = last_epoch0 / 2;
        let epoch0_recipient = fee_recipients.get(&epoch0_check_height).expect("epoch 0 block should exist");
        assert_eq!(
            *epoch0_recipient, withdrawal_cred,
            "block {epoch0_check_height}: treasury is zero, fee_recipient should be withdrawal credentials"
        );

        // After the epoch boundary, treasury address is set so fee_recipient
        // should be the treasury address.
        let epoch1_recipient = fee_recipients.get(&first_epoch1).expect("epoch 1 block should exist");
        assert_eq!(
            *epoch1_recipient, treasury_address,
            "block {first_epoch1}: treasury was set, fee_recipient should be treasury address"
        );

        // Verify that all nodes agree on the treasury address
        for (_, query) in &consensus_state_queries {
            assert_eq!(query.get_treasury_address().await, treasury_address);
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
fn test_protocol_param_max_deposits_per_epoch() {
    // Submits a protocol param request for max_deposits_per_epoch (param_id 0x05)
    // and verifies that the value is applied at the end of the epoch.
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

        let new_max_joining = 1u64;
        let test_protocol_param = common::create_protocol_param_request(0x05, new_max_joining);

        let execution_requests = vec![ExecutionRequest::ProtocolParam(test_protocol_param)];
        let requests = common::execution_requests_to_requests(execution_requests);

        let protocol_param_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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

        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(
            state_query.get_max_deposits_per_epoch().await,
            new_max_joining
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
fn test_protocol_param_max_deposits_per_epoch_rejected_above_max() {
    // Submits a protocol param request for max_deposits_per_epoch with a value above the
    // maximum bound (256). The request should be rejected and the value should remain
    // at the initial default.
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

        // Value above MAX_MAX_DEPOSITS_PER_EPOCH (256)
        let invalid_value = MAX_MAX_DEPOSITS_PER_EPOCH + 1;
        let test_protocol_param = common::create_protocol_param_request(0x05, invalid_value);

        let execution_requests = vec![ExecutionRequest::ProtocolParam(test_protocol_param)];
        let requests = common::execution_requests_to_requests(execution_requests);

        let protocol_param_block_height = 5;
        let stop_height = DEFAULT_BLOCKS_PER_EPOCH + 1;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(protocol_param_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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

        // Value should remain at the initial default (10, set in test harness)
        let state_query = consensus_state_queries.get(&0).unwrap();
        assert_eq!(state_query.get_max_deposits_per_epoch().await, 10);

        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    })
}

/// Verifies that a validator force-removed by stake-bound enforcement is recorded in the
/// finalized header's `removed_validators` list at the epoch boundary where the removal
/// takes effect.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10):
/// - 5 genesis validators, each at 32 ETH. min_stake = 32 ETH, max_stake = 40 ETH.
/// - Block 3: validators 0..=3 each deposit 8 ETH → 40 ETH (= max_stake). Validator 4
///   does not deposit (stays at 32 ETH).
/// - Block 5: protocol-param request raises min_stake to 40 ETH.
/// - At the epoch 0 boundary (block 9), the new min_stake takes effect and validator 4
///   (still at 32 ETH) must be force-removed.
///
/// Assertion: the finalized header for epoch 0 contains validator 4 in
/// `removed_validators`, so a node joining later (which reconstructs the next epoch's
/// committee from header deltas in `verify_checkpoint_chain`) sees the same validator
/// set as a live node.
#[test_traced("INFO")]
fn test_removed_validators_at_epoch_boundary_stake_bound() {
    let n: u32 = 5;
    let min_stake = 32_000_000_000; // 32 ETH
    let max_stake = 40_000_000_000; // 40 ETH (set from genesis to avoid partial-withdrawal noise)
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

        // Validator at index n-1 stays at 32 ETH — it will fall below the new 40 ETH min
        // stake and must be force-removed at the epoch 0 boundary.
        let kicked_idx = (n - 1) as usize;
        let kicked_pubkey = validators[kicked_idx].0.clone();

        // Validators 0..kicked_idx each deposit 8 ETH (32 + 8 = 40 ETH, exactly at max).
        let mut deposit_requests = Vec::new();
        let deposit_amount = 8_000_000_000u64;
        for i in 0..kicked_idx as u64 {
            let (deposit, _, _) = common::create_deposit_request(
                i,
                deposit_amount,
                common::get_domain(),
                Some(key_stores[i as usize].node_key.clone()),
                Some(key_stores[i as usize].consensus_key.clone()),
                None,
            );
            deposit_requests.push(ExecutionRequest::Deposit(deposit));
        }
        let requests_deposits = common::execution_requests_to_requests(deposit_requests);

        let new_min_stake = 40_000_000_000u64; // 40 ETH
        let min_param = common::create_protocol_param_request(0x00, new_min_stake);
        let requests_param =
            common::execution_requests_to_requests(vec![ExecutionRequest::ProtocolParam(
                min_param,
            )]);

        let deposit_block_height = 3;
        let protocol_param_block_height = 5;
        // Last block of epoch 0 = 9. Stop at 10 so block 9 is finalized.
        let last_block_epoch_0 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        let stop_height = last_block_epoch_0 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposits);
        execution_requests_map.insert(protocol_param_block_height, requests_param);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut public_keys = HashSet::new();
        let mut finalizer_mailboxes = HashMap::new();
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
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // The kicked validator exits at the epoch boundary, so only n-1 validators
        // will reach stop_height.
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

        // Sanity-check that the stake-bound enforcement actually fired: the protocol
        // parameter took effect and the kicked validator was moved out of the active
        // set. Query a still-running validator (index 0) — the kicked validator's
        // finalizer shuts down after exit.
        let state_query = finalizer_mailboxes.get(&0).unwrap();
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);
        let kicked_account = state_query
            .get_validator_account(kicked_pubkey.clone())
            .await;
        assert!(
            kicked_account.is_none()
                || kicked_account.as_ref().unwrap().status == ValidatorStatus::Inactive,
            "kicked validator should be Inactive (or already removed) after epoch 0 boundary"
        );

        // The header for the last block of epoch 0 must include the force-removed
        // validator in `removed_validators` so header-walking verifiers
        // (verify_checkpoint_chain) reconstruct the same committee as live nodes.
        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();
        let finalized_header = mailbox
            .get_finalized_header(0)
            .await
            .expect("failed to get finalized header for last block of epoch 0");

        let removed_validators = finalized_header.header().removed_validators();
        assert!(
            removed_validators.contains(&kicked_pubkey),
            "force-removed validator (stake-bound) should be in removed_validators of \
             epoch 0's finalized header, but removed_validators = {removed_validators:?}"
        );

        context.auditor().state()
    })
}

/// Regression: the finalizer processes the epoch's buffered deposits *before* it
/// enforces a pending minimum-stake increase (both run at the penultimate block).
/// So a same-epoch top-up that lifts an already-active validator back to at least
/// the new minimum is credited first, and enforcement then sees a sufficient
/// balance and does not remove it. The validator stays Active continuously, with
/// no committee churn or warm-up gap.
///
/// This is the inverse of `test_removed_validators_at_epoch_boundary_stake_bound`,
/// where a below-minimum validator with no saving top-up is removed at the boundary.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10):
/// - 5 genesis validators, each at 32 ETH. min_stake = 32 ETH.
/// - Block 3: validators 0..=3 each top up 16 ETH (-> 48 ETH); the "saved" validator
///   (index n-1) tops up 8 ETH (-> 40 ETH, exactly the new minimum).
/// - Block 5: protocol-param request raises min_stake to 40 ETH.
/// - Epoch 0 boundary (block 9): every validator is now at or above 40 ETH, so the
///   change is viable and nobody is removed. The saved validator was at 32 ETH
///   (below the new minimum) before its top-up but is kept by it.
///
/// Assertions (stop one block past epoch 0):
/// - The new min_stake took effect (40 ETH).
/// - The saved validator is still Active at 40 ETH.
/// - Epoch 0's finalized header carries an empty `removed_validators` list.
#[test_traced("INFO")]
fn test_stake_increase_topup_keeps_active_validator() {
    let n: u32 = 5;
    let min_stake = 32_000_000_000; // 32 ETH
    let max_stake = 64_000_000_000; // 64 ETH (well above every top-up target)
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

        // Validator n-1 starts at 32 ETH and would fall below the new 40 ETH minimum,
        // but a same-epoch top-up lifts it to exactly 40 ETH and keeps it in the set.
        let saved_idx = (n - 1) as usize;
        let saved_pubkey = validators[saved_idx].0.clone();

        // Block 3 top-ups keyed to the existing genesis validators: 0..=3 add 16 ETH
        // (-> 48 ETH), the saved validator adds 8 ETH (-> 40 ETH).
        let mut deposit_requests = Vec::new();
        for i in 0..n as usize {
            let amount = if i == saved_idx {
                8_000_000_000u64 // -> 40 ETH (exactly the new minimum)
            } else {
                16_000_000_000u64 // -> 48 ETH (safely above)
            };
            let (deposit, _, _) = common::create_deposit_request(
                i as u64,
                amount,
                common::get_domain(),
                Some(key_stores[i].node_key.clone()),
                Some(key_stores[i].consensus_key.clone()),
                None,
            );
            deposit_requests.push(ExecutionRequest::Deposit(deposit));
        }
        let requests_deposits = common::execution_requests_to_requests(deposit_requests);

        let new_min_stake = 40_000_000_000u64; // 40 ETH
        let min_param = common::create_protocol_param_request(0x00, new_min_stake);
        let requests_param =
            common::execution_requests_to_requests(vec![ExecutionRequest::ProtocolParam(
                min_param,
            )]);

        let deposit_block_height = 3;
        let protocol_param_block_height = 5;
        // Last block of epoch 0 = 9. Stop at 10 so block 9 is finalized.
        let last_block_epoch_0 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        let stop_height = last_block_epoch_0 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposits);
        execution_requests_map.insert(protocol_param_block_height, requests_param);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut public_keys = HashSet::new();
        let mut finalizer_mailboxes = HashMap::new();
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
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Nobody exits, so all n validators reach stop_height.
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

        // The minimum-stake change took effect and the saved validator is still
        // Active at exactly the new minimum: its top-up, credited before enforcement,
        // kept it in the committee.
        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();
        assert_eq!(mailbox.get_minimum_stake().await, new_min_stake);

        let saved_account = mailbox
            .get_validator_account(saved_pubkey.clone())
            .await
            .expect("saved validator should still exist");
        assert_eq!(
            saved_account.status,
            ValidatorStatus::Active,
            "saved validator should stay Active (top-up processed before enforcement)"
        );
        assert_eq!(saved_account.balance, new_min_stake);

        // No validator was removed at the epoch 0 boundary.
        let finalized_header = mailbox
            .get_finalized_header(0)
            .await
            .expect("failed to get finalized header for last block of epoch 0");
        assert!(
            finalized_header.header().removed_validators().is_empty(),
            "no validator should be removed; removed_validators = {:?}",
            finalized_header.header().removed_validators()
        );

        context.auditor().state()
    })
}

/// Verifies that when stake-bound enforcement force-removes a Joining validator
/// (one whose activation is still pending in `added_validators`), the pending
/// activation is cancelled so the finalized header does not carry a stale
/// `added_validators` entry. Without the cancellation, a header-walking verifier
/// (verify_checkpoint_chain) would reconstruct the validator into the committee
/// even though the live node excluded it.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2):
/// - 5 genesis validators, each at 32 ETH. min_stake = 32 ETH, max_stake = 40 ETH.
/// - Block 3: validators 0..=4 each top up 8 ETH → 40 ETH (safely above the new min).
/// - Block 5: a brand-new validator deposits 32 ETH. Processed at penultimate of
///   epoch 0 (block 8): account created with status = Joining, joining_epoch = 0 + 2 = 2.
///   `state.add_validator(2, ...)` is called.
/// - Block 15: protocol-param request raises min_stake to 36 ETH.
/// - Penultimate of epoch 1 (block 18): stake-bound staging detects the Joining
///   validator (balance 32 < prospective_min 36). The correct behavior is to
///   *cancel* the pending activation via `remove_added_validator(2, pk)` so the
///   activation never lands in any header.
/// - Last block of epoch 1 (block 19) is the header that would normally activate
///   the validator (`next_epoch == joining_epoch == 2`).
///
/// Assertion: epoch 1's finalized header does NOT contain the joining validator
/// in `added_validators`.
#[test_traced("INFO")]
fn test_joining_validator_activation_cancelled_on_stake_bound_force_removal() {
    let n: u32 = 5;
    let min_stake = 32_000_000_000; // 32 ETH
    let max_stake = 40_000_000_000; // 40 ETH
    let new_validator_amount = 32_000_000_000u64; // below new min after the raise
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

        // Block 3: top-up deposits for genesis validators so each ends up at exactly
        // 40 ETH (= max), safely above the new min.
        let topup_amount = 8_000_000_000u64;
        let mut topup_deposits = Vec::new();
        for i in 0..n as u64 {
            let (deposit, _, _) = common::create_deposit_request(
                i,
                topup_amount,
                common::get_domain(),
                Some(key_stores[i as usize].node_key.clone()),
                Some(key_stores[i as usize].consensus_key.clone()),
                None,
            );
            topup_deposits.push(ExecutionRequest::Deposit(deposit));
        }
        let topup_requests = common::execution_requests_to_requests(topup_deposits);

        // Block 5: brand-new validator deposit. The index n is unused so far, so its
        // seeded key won't collide with any genesis validator.
        let new_validator_index = n as u64;
        let (new_deposit, new_validator_private_key, _) = common::create_deposit_request(
            new_validator_index,
            new_validator_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        let new_validator_pubkey = new_validator_private_key.public_key();
        let new_deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(new_deposit)]);

        // Block 15 (mid-epoch 1): raise min_stake to 36 ETH.
        let new_min_stake = 36_000_000_000u64;
        let min_param = common::create_protocol_param_request(0x00, new_min_stake);
        let param_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::ProtocolParam(
                min_param,
            )]);

        let topup_block_height = 3;
        let new_deposit_block_height = 5;
        let protocol_param_block_height = 15;
        // Last block of epoch 1 = 19. Stop at 20 so block 19 is finalized.
        let last_block_epoch_1 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 1);
        let stop_height = last_block_epoch_1 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(topup_block_height, topup_requests);
        execution_requests_map.insert(new_deposit_block_height, new_deposit_requests);
        execution_requests_map.insert(protocol_param_block_height, param_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_maximum_stake(max_stake);

        let mut public_keys = HashSet::new();
        let mut finalizer_mailboxes = HashMap::new();
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
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // All 5 genesis validators stay above the new min (40 >= 36) and continue
        // participating, so all of them should reach stop_height.
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

        // Sanity-check: the protocol param took effect and the new validator's
        // pending activation was cancelled. Stake-bound enforcement no longer
        // force-withdraws, so the account keeps its balance; only the scheduled
        // activation is removed (it never re-activates).
        let state_query = finalizer_mailboxes.get(&0).unwrap();
        assert_eq!(state_query.get_minimum_stake().await, new_min_stake);
        let new_account = state_query
            .get_validator_account(new_validator_pubkey.clone())
            .await
            .expect("new validator account should still exist (activation only cancelled)");
        assert_eq!(new_account.balance, new_validator_amount);
        // Cancelling the pending activation reverts the account to Inactive; it is
        // never left stuck as Joining.
        assert_eq!(new_account.status, ValidatorStatus::Inactive);

        // Bug under test: epoch 1's finalized header must NOT list the joining
        // validator in added_validators. The pending activation should have been
        // cancelled at the penultimate block; otherwise a header-walking verifier
        // would reconstruct the validator into the committee for epoch 2 while the
        // live node correctly excludes them.
        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();
        let finalized_header = mailbox
            .get_finalized_header(1)
            .await
            .expect("failed to get finalized header for last block of epoch 1");

        let added = finalized_header.header().added_validators();
        assert!(
            !added.iter().any(|av| av.node_key == new_validator_pubkey),
            "force-removed Joining validator should NOT appear in added_validators of \
             epoch 1's finalized header, but added_validators = {added:?}"
        );

        context.auditor().state()
    })
}

/// A pending-deposit placeholder account (balance=0, has_pending_deposit=true,
/// status=Inactive) is not flagged as an underfunded validator by stake-bound
/// enforcement. After the deposit is later credited at the penultimate block
/// of the next epoch and the validator is activated, the account is fully
/// usable: has_pending_withdrawal is false, so subsequent withdrawal or top-up
/// requests are not silently rejected.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2):
///  - 5 genesis validators @ 32 ETH (min_stake = 32 ETH, max_stake = 64 ETH).
///  - Block 9 (last block of epoch 0): a brand-new validator deposit (32 ETH)
///    and a protocol-param change lowering max_stake to 50 ETH land in the
///    same block. Deposit processing only runs at the penultimate block, so
///    the placeholder is still in the deposit queue with balance=0 when the
///    last-block stake-bound enforcement runs. Lowering max_stake is enough
///    to flip stake_changed = true while keeping every genesis validator
///    inside the new [32, 50] band.
///
/// Timeline:
///  - Block 9 (last of epoch 0): placeholder is created in parse_execution_requests.
///    apply_protocol_parameter_changes lowers max_stake → stake_changed=true.
///    The stake-bound scan must skip the placeholder (it has not been credited
///    yet) instead of force-removing it with a zero-amount withdrawal.
///  - Block 18 (penultimate of epoch 1): deposit processed — balance = 32 ETH,
///    status = Joining, joining_epoch = 3.
///  - Block 29 (last of epoch 2): joining_epoch=3 matches next_epoch — the
///    validator is activated for epoch 3.
///
/// Assertions (stop at block 30 — one block into epoch 3):
///  - Account exists with status = Active and balance = 32 ETH.
///  - has_pending_deposit = false (deposit was processed).
///  - has_pending_withdrawal = false. The last-block stake-bound scan must
///    not flag the placeholder, otherwise the flag remains stuck after deposit
///    processing (the deposit path does not clear it) and after the
///    zero-amount withdrawal completes (the balance_deduction == 0 path skips
///    account updates) — permanently blocking future withdrawal/top-up
///    requests for this validator.
#[test_traced("INFO")]
fn test_stake_bound_skips_pending_deposit_placeholder() {
    let n: u32 = 5;
    let min_stake = 32_000_000_000;
    let max_stake = 64_000_000_000;
    let new_max_stake = 50_000_000_000;
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

        // Brand-new validator deposit, scheduled to land at block 9 (last of
        // epoch 0). Index = n so the seed does not collide with any genesis
        // validator.
        let (new_deposit, new_validator_private_key, _) = common::create_deposit_request(
            n as u64,
            new_validator_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        let new_validator_pubkey = new_validator_private_key.public_key();

        // Lower max_stake to flip stake_changed = true at the end of epoch 0
        // without putting genesis validators (32 ETH each) outside the new band.
        let param_request = common::create_protocol_param_request(0x01, new_max_stake);

        // Bundle the deposit and the protocol-param change into the same
        // block (last block of epoch 0). Deposit processing only runs at the
        // penultimate block, so the placeholder is still uncredited when the
        // last-block stake-bound scan fires.
        let last_block_epoch_0 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 0);
        let block_requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Deposit(new_deposit),
            ExecutionRequest::ProtocolParam(param_request),
        ]);

        // Stop one block past epoch 2's last block so the joining_epoch=3
        // boundary has been processed and the validator is Active.
        let last_block_epoch_2 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 2);
        let stop_height = last_block_epoch_2 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(last_block_epoch_0, block_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
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

        // Protocol-param change landed and stake_changed was true at the
        // epoch 0 boundary.
        assert_eq!(state_query.get_maximum_stake().await, new_max_stake);
        assert_eq!(state_query.get_minimum_stake().await, min_stake);

        // Genesis validators are unaffected — all 5 stay Active at 32 ETH.
        for (pk, _) in &validators {
            let account = state_query
                .get_validator_account(pk.clone())
                .await
                .expect("genesis validator account should exist");
            assert_eq!(account.status, ValidatorStatus::Active);
            assert_eq!(account.balance, min_stake);
            assert!(!account.has_pending_withdrawal);
        }

        // The new validator is activated for epoch 3, and the account is not
        // carrying a stale pending-withdrawal flag from a stake-bound scan
        // against the zero-balance placeholder.
        let new_account = state_query
            .get_validator_account(new_validator_pubkey.clone())
            .await
            .expect("new validator account should exist after activation");
        assert_eq!(new_account.status, ValidatorStatus::Active);
        assert_eq!(new_account.balance, new_validator_amount);
        assert!(
            !new_account.has_pending_deposit,
            "has_pending_deposit must be cleared after deposit processing"
        );
        assert!(
            !new_account.has_pending_withdrawal,
            "has_pending_withdrawal must be false; the placeholder must not be \
             treated as an underfunded validator by the last-block stake-bound \
             scan, otherwise the flag stays stuck (deposit processing does not \
             clear it and the zero-balance_deduction withdrawal completion \
             skips account updates), permanently blocking future withdrawal \
             and top-up requests"
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
