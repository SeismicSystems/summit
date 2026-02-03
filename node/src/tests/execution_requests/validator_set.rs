use super::*;

/// Test that verifies added_validators is correctly populated in block headers at epoch boundaries.
///
/// When a new validator deposits, they are scheduled to join the validator set after a warm-up
/// period. The header at the last block of an epoch must include validators joining in the
/// next epoch so that light clients and syncers can track validator set changes.
///
/// Test setup:
/// - BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2
/// - Submit deposit at block 5 (epoch 0)
/// - Validator's joining_epoch = 0 + 2 = 2
/// - At block 19 (last block of epoch 1), header should contain the validator
///   (because next_epoch = 2, which matches joining_epoch)
#[test_traced("INFO")]
fn test_added_validators_at_epoch_boundary() {
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
                disconnect_on_block: true,
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
            common::create_deposit_request(10, min_stake, common::get_domain(), None, None);

        let new_validator_node_key = test_deposit.node_pubkey.clone();
        let new_validator_consensus_key = test_deposit.consensus_pubkey.clone();

        let execution_requests = vec![ExecutionRequest::Deposit(test_deposit.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Submit deposit at block 5 (epoch 0)
        let deposit_block_height = 5;

        // The validator will join at epoch = deposit_processing_epoch + VALIDATOR_NUM_WARM_UP_EPOCHS
        // Deposit is processed at the end of epoch 0 (block 9)
        // joining_epoch = 0 + 2 = 2
        //
        // With BLOCKS_PER_EPOCH = 10:
        // - Epoch 0: blocks 0-9, last block = 9
        // - Epoch 1: blocks 10-19, last block = 19
        // - Epoch 2: blocks 20-29, last block = 29
        //
        // At the last block of epoch 1 (block 19), the header should include validators
        // joining in epoch 2 (next_epoch).
        //
        // We need to run until block 20 to ensure block 19's header is finalized.
        let last_block_epoch_1 = utils::last_block_in_epoch(BLOCKS_PER_EPOCH, 1); // block 19
        let stop_height = last_block_epoch_1 + 1; // block 20

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut finalizer_mailboxes = HashMap::new();
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
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

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

        // Get the finalized header for the last block of epoch 1 (block 19)
        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();
        let finalized_header = mailbox
            .get_finalized_header(last_block_epoch_1)
            .await
            .expect("Failed to get finalized header for last block of epoch 1");

        // Verify the header contains the new validator in added_validators
        // The new validator's joining_epoch = 2, and at block 19 (last block of epoch 1),
        // the header should include validators joining in epoch 2 (next_epoch).
        let added_validators = &finalized_header.header.added_validators;

        // Assert that added_validators contains the new validator
        assert!(
            !added_validators.is_empty(),
            "added_validators should not be empty at the last block of epoch 1"
        );

        // Find the new validator in the list
        let found = added_validators
            .iter()
            .any(|av| av.node_key == new_validator_node_key);

        assert!(
            found,
            "New validator should be in added_validators at the last block of epoch 1"
        );

        // Also verify the consensus key matches
        let added_validator = added_validators
            .iter()
            .find(|av| av.node_key == new_validator_node_key)
            .expect("Validator should be found");

        assert_eq!(
            added_validator.consensus_key, new_validator_consensus_key,
            "Consensus key should match"
        );

        // Verify consensus
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}

/// Test that verifies removed_validators is correctly populated in block headers at epoch boundaries.
///
/// When an active validator submits a withdrawal request, they are added to the removed_validators
/// list. The header at the last block of an epoch must include validators being removed.
///
/// Test setup:
/// - BLOCKS_PER_EPOCH = 10
/// - Genesis validator submits withdrawal at block 5 (epoch 0)
/// - At block 9 (last block of epoch 0), header should contain the validator in removed_validators
#[test_traced("INFO")]
fn test_removed_validators_at_epoch_boundary() {
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
                disconnect_on_block: true,
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

        // Pick a genesis validator to withdraw (not validator 0 to avoid issues with proposer)
        let withdrawing_validator_idx = 1;
        let withdrawing_validator_pubkey = validators[withdrawing_validator_idx].0.clone();
        let withdrawing_validator_pubkey_bytes: [u8; 32] = withdrawing_validator_pubkey
            .as_ref()
            .try_into()
            .expect("Public key must be 32 bytes");

        // Create withdrawal request for the genesis validator
        // Genesis validators have Address::ZERO as withdrawal credentials by default
        let withdrawal_request = common::create_withdrawal_request(
            Address::ZERO,
            withdrawing_validator_pubkey_bytes,
            min_stake, // Full withdrawal
        );

        let execution_requests = vec![ExecutionRequest::Withdrawal(withdrawal_request)];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Submit withdrawal at block 5 (epoch 0, not last block)
        // The validator will be added to removed_validators immediately
        let withdrawal_block_height = 5;

        // With BLOCKS_PER_EPOCH = 10:
        // - Epoch 0: blocks 0-9, last block = 9
        //
        // At the last block of epoch 0 (block 9), the header should include the
        // withdrawing validator in removed_validators.
        //
        // We need to run until block 10 to ensure block 9's header is finalized.
        let last_block_epoch_0 = utils::last_block_in_epoch(BLOCKS_PER_EPOCH, 0); // block 9
        let stop_height = last_block_epoch_0 + 1; // block 10

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut finalizer_mailboxes = HashMap::new();
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
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

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

        // Get the finalized header for the last block of epoch 0 (block 9)
        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();
        let finalized_header = mailbox
            .get_finalized_header(last_block_epoch_0)
            .await
            .expect("Failed to get finalized header for last block of epoch 0");

        // Verify the header contains the withdrawing validator in removed_validators
        let removed_validators = &finalized_header.header.removed_validators;

        // Assert that removed_validators contains the withdrawing validator
        assert!(
            !removed_validators.is_empty(),
            "removed_validators should not be empty at the last block of epoch 0"
        );

        // Find the withdrawing validator in the list
        let found = removed_validators
            .iter()
            .any(|pk| *pk == withdrawing_validator_pubkey);

        assert!(
            found,
            "Withdrawing validator should be in removed_validators at the last block of epoch 0"
        );

        // Verify consensus
        assert!(
            engine_client_network
                .verify_consensus(None, Some(stop_height))
                .is_ok()
        );

        context.auditor().state()
    });
}
