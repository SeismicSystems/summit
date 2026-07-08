use super::*;
use alloy_eips::eip7685::Requests;
use alloy_primitives::Bytes;
use commonware_codec::Write;
use commonware_runtime::Supervisor as _;

#[test_traced("INFO")]
fn test_grouped_withdrawal_requests_in_single_eip7685_entry() {
    // Adds two deposits so both validators are active, then submits two withdrawal requests
    // packed into a single type-0x01 EIP-7685 entry.
    // Both withdrawals should be decoded from the grouped entry and processed.
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(3);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let (deposit1, _, _) = common::create_deposit_request(
            n as u64,
            min_stake,
            common::get_domain(),
            None,
            None,
            None,
        );
        let (deposit2, _, _) = common::create_deposit_request(
            (n + 1) as u64,
            min_stake,
            common::get_domain(),
            None,
            None,
            None,
        );

        let withdrawal1 = common::create_withdrawal_request(
            Address::from_slice(&deposit1.withdrawal_credentials[12..32]),
            deposit1.node_pubkey.as_ref().try_into().unwrap(),
            min_stake,
        );
        let withdrawal2 = common::create_withdrawal_request(
            Address::from_slice(&deposit2.withdrawal_credentials[12..32]),
            deposit2.node_pubkey.as_ref().try_into().unwrap(),
            min_stake,
        );

        let requests_deposit_1 =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
                deposit1.clone(),
            )]);
        let requests_deposit_2 =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(
                deposit2.clone(),
            )]);

        // Canonical EIP-7685 shape: one top-level withdrawal entry containing multiple
        // SSZ-encoded withdrawal requests of the same type.
        let mut grouped_withdrawals = Vec::new();
        grouped_withdrawals.push(0x01);
        withdrawal1.write(&mut grouped_withdrawals);
        withdrawal2.write(&mut grouped_withdrawals);
        let grouped_withdrawal_requests = Requests::from(vec![Bytes::from(grouped_withdrawals)]);

        let deposit_block_height = 5;
        let withdrawal_block_height = 11;
        let withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 2;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposit_1);
        execution_requests_map.insert(deposit_block_height + 1, requests_deposit_2);
        execution_requests_map.insert(withdrawal_block_height, grouped_withdrawal_requests);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };
                if sample.name.ends_with("_peers_blocked") {
                    assert_eq!(sample.value.parse::<u64>().unwrap(), 0);
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

        let withdrawals = engine_client_network.get_withdrawals();
        let withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing grouped withdrawal entry");

        assert_eq!(
            withdrawals.len(),
            2,
            "both withdrawals packed into the same EIP-7685 entry should be processed"
        );
        assert!(withdrawals.iter().any(|w| {
            w.address == withdrawal1.source_address && w.amount == withdrawal1.amount
        }));
        assert!(withdrawals.iter().any(|w| {
            w.address == withdrawal2.source_address && w.amount == withdrawal2.amount
        }));

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
fn test_full_exit_withdrawal_removes_validator_and_pays_out() {
    // A withdrawal request with amount 0 is a full exit (EIP-7002 style): the
    // validator leaves the committee and its entire balance is paid out once at
    // the scheduled height. This is distinct from a partial withdrawal, which
    // carries a positive amount.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Validator 0 requests a full exit (amount 0) at block 3 (epoch 0)
    // - The payout happens at the last block of epoch VALIDATOR_WITHDRAWAL_NUM_EPOCHS
    // - Validator 0 is removed and the remaining validators keep running
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
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Validator 0 requests a full exit (amount 0).
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];
        let full_exit = common::create_withdrawal_request(withdrawal_address, validator0_pubkey, 0);

        let execution_requests = vec![ExecutionRequest::Withdrawal(full_exit)];
        let requests = common::execution_requests_to_requests(execution_requests);

        let withdrawal_block_height = 3;
        let withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        let mut withdrawn_validator_uid = String::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            if idx == 0 {
                withdrawn_validator_uid = uid.clone();
            }
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Validator 0 exits the committee, so only the remaining n - 1 validators
        // drive consensus to the stop height. Poll those specifically; the exited
        // validator is not expected to reach the stop height.
        let mut height_reached = HashSet::new();
        loop {
            for (idx, query) in consensus_state_queries.iter() {
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

        // Exactly one payout, for the full balance, at the scheduled height.
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);
        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(epoch_withdrawals.len(), 1);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[0].address, withdrawal_address);

        // Validator 0's account is removed once the full exit pays out.
        let state_query = consensus_state_queries.get(&1).unwrap();
        assert!(
            state_query
                .get_validator_account(validators[0].0.clone())
                .await
                .is_none(),
            "fully exited validator account should be removed"
        );

        // The other genesis validators are untouched.
        for validator in validators.iter().skip(1) {
            let account = state_query
                .get_validator_account(validator.0.clone())
                .await
                .unwrap();
            assert_eq!(account.balance, min_stake);
            assert_eq!(account.status, ValidatorStatus::Active);
        }

        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&withdrawn_validator_uid])
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[0]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_multiple_partial_withdrawals_paid_out_clamped_to_minimum() {
    // Two concurrent partial withdrawals (positive amounts) from the same
    // validator are both scheduled and paid out; duplicate/concurrent partials
    // are no longer rejected. Each partial is clamped so the validator stays at
    // or above the minimum stake.
    //
    // Test setup:
    // - Validator 0 is topped up above the minimum stake via a deposit (32 ETH
    //   base + 64 ETH top up = 96 ETH), giving head room for the partials.
    // - Two partials of 32 ETH each are then requested in epoch 1. Together they
    //   draw the balance back down to exactly the minimum (a third would clamp
    //   to zero and be dropped).
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
            context.child("network"),
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

        // Validator 0's keys are needed to sign the top-up deposit; clone them
        // before the key stores are consumed by the engine loop.
        let validator0_node_key = key_stores[0].node_key.clone();
        let validator0_consensus_key = key_stores[0].consensus_key.clone();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Top up validator 0 with 64 ETH (2 x min_stake), carrying its existing
        // node and consensus keys and Eth1 withdrawal credentials for address 0.
        let mut topup_credentials = [0u8; 32];
        topup_credentials[0] = 0x01;
        topup_credentials[12..32].copy_from_slice(addresses[0].as_slice());
        let (topup_deposit, _, _) = common::create_deposit_request(
            0,
            2 * min_stake,
            common::get_domain(),
            Some(validator0_node_key),
            Some(validator0_consensus_key),
            Some(topup_credentials),
        );

        // Two partial withdrawals for validator 0, each of the minimum stake.
        let validator0_pubkey: [u8; 32] = validators[0].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[0];
        let partial1 =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);
        let partial2 =
            common::create_withdrawal_request(withdrawal_address, validator0_pubkey, min_stake);

        // Top up in epoch 0; request both partials in epoch 1, after the top up
        // has been credited so there is head room above the minimum stake.
        let deposit_block_height = 3;
        let withdrawal_block_height1 = 12;
        let withdrawal_block_height2 = 13;
        let withdrawal_epoch =
            (withdrawal_block_height1 / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 2;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(
            deposit_block_height,
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(topup_deposit)]),
        );
        execution_requests_map.insert(
            withdrawal_block_height1,
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(partial1)]),
        );
        execution_requests_map.insert(
            withdrawal_block_height2,
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(partial2)]),
        );

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Validator 0 stays active (partials never remove it), so all validators
        // reach the stop height.
        let mut height_reached = HashSet::new();
        loop {
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

        // Both partials are paid out at the same scheduled height.
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1);
        let epoch_withdrawals = withdrawals.get(&withdrawal_height).unwrap();
        assert_eq!(
            epoch_withdrawals.len(),
            2,
            "both partial withdrawals should be paid out"
        );
        for withdrawal in epoch_withdrawals {
            assert_eq!(withdrawal.amount, min_stake);
            assert_eq!(withdrawal.address, withdrawal_address);
        }

        // Validator 0 remains active, drawn down to exactly the minimum stake.
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
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
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for all validators to reach stop_height
        let mut height_reached = HashSet::new();
        loop {
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
            context.child("network"),
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

        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
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
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests1);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
                    }
                }

                if height_reached.len() as u32 == n {
                    success = true;
                    break;
                }
            }
            // Replaced by query-based loop below.
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

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
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create a deposit request for a new validator
        let (test_deposit, _, _) = common::create_deposit_request(
            n as u64,
            min_stake,
            common::get_domain(),
            None,
            None,
            None,
        );

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
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1; // Block 39
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, requests_deposit);
        execution_requests_map.insert(withdrawal_block_height, requests_withdrawal);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
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

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_minimum_validator_count_blocks_excess_active_validator_exits() {
    // The default minimum validator count is 3. With 4 active genesis validators,
    // two same-block full exits should only admit the first exit.
    let n = 4;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(44);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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

        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8 + 1; 20])).collect();
        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Two full exits (amount 0) submitted in the same block; the minimum
        // validator floor admits only the first.
        let withdrawal_a = common::create_withdrawal_request(
            addresses[0],
            validators[0].0.as_ref().try_into().unwrap(),
            0,
        );
        let withdrawal_b = common::create_withdrawal_request(
            addresses[1],
            validators[1].0.as_ref().try_into().unwrap(),
            0,
        );
        let requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Withdrawal(withdrawal_a.clone()),
            ExecutionRequest::Withdrawal(withdrawal_b.clone()),
        ]);

        let withdrawal_block_height = 3;
        let withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let withdrawal_height = (withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut consensus_state_queries = HashMap::new();
        let mut validator_uids = vec![String::new(); n as usize];
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            validator_uids[idx] = uid.clone();
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("_peers_blocked") {
                    let value = sample.value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
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
        assert_eq!(withdrawals.len(), 1, "only one full exit should be queued");
        let epoch_withdrawals = withdrawals
            .get(&withdrawal_height)
            .expect("missing accepted full-exit withdrawal");
        assert_eq!(epoch_withdrawals.len(), 1);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[0].address, withdrawal_a.source_address);
        assert_ne!(epoch_withdrawals[0].address, withdrawal_b.source_address);

        let state_query = consensus_state_queries
            .get(&1)
            .expect("second validator should still be running");
        let first_account = state_query
            .get_validator_account(validators[0].0.clone())
            .await;
        assert!(
            first_account.is_none(),
            "first full exit should be accepted and completed"
        );

        let second_account = state_query
            .get_validator_account(validators[1].0.clone())
            .await
            .expect("second full exit should be skipped by the minimum validator floor");
        assert_eq!(second_account.status, ValidatorStatus::Active);
        assert_eq!(second_account.balance, min_stake);

        for validator in validators.iter().skip(1) {
            let account = state_query
                .get_validator_account(validator.0.clone())
                .await
                .expect("remaining validator should stay active");
            assert_eq!(account.status, ValidatorStatus::Active);
            assert_eq!(account.balance, min_stake);
        }

        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[validator_uids[0].as_str()])
                .is_ok()
        );
        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[0]).await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_withdrawal_on_last_block_of_epoch_deferred() {
    // Tests that a withdrawal request for an active validator submitted on the last block
    // of an epoch is deferred and processed in the next epoch.
    //
    // This ensures that `removed_validators` is properly included in the header.
    //
    // Test setup:
    // - Genesis validators start with 32 ETH each
    // - Submit a withdrawal request on block 9 (last block of epoch 0)
    // - The withdrawal should be buffered and processed at the penultimate block of epoch 1
    // - Verify the withdrawal happens at the deferred height, not the immediate height
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(42);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create a full-exit withdrawal request (amount 0) for the last validator
        let last_idx = validators.len() - 1;
        let validator_pubkey: [u8; 32] = validators[last_idx].0.as_ref().try_into().unwrap();
        let withdrawal_address = addresses[last_idx];

        let withdrawal = common::create_withdrawal_request(withdrawal_address, validator_pubkey, 0);

        let execution_requests = vec![ExecutionRequest::Withdrawal(withdrawal.clone())];
        let requests = common::execution_requests_to_requests(execution_requests);

        // Submit withdrawal on block 9 (last block of epoch 0, since DEFAULT_BLOCKS_PER_EPOCH=10)
        let withdrawal_block_height = DEFAULT_BLOCKS_PER_EPOCH - 1; // Block 9
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, requests);

        // If the request was processed immediately in epoch 0, withdrawal would happen here:
        let immediate_withdrawal_epoch =
            (withdrawal_block_height / DEFAULT_BLOCKS_PER_EPOCH) + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let immediate_withdrawal_height =
            (immediate_withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;

        // Since the request is deferred to epoch 1, withdrawal should happen here instead:
        let deferred_withdrawal_epoch = 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let deferred_withdrawal_height =
            (deferred_withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;

        // Verify our expectations are different (deferral should delay the withdrawal)
        assert!(
            deferred_withdrawal_height > immediate_withdrawal_height,
            "Deferred height {} should be greater than immediate height {}",
            deferred_withdrawal_height,
            immediate_withdrawal_height
        );

        let stop_height = deferred_withdrawal_height + 1;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        let mut withdrawn_validator_uid = String::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            if idx == last_idx {
                withdrawn_validator_uid = uid.clone();
            }
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Wait for all validators to reach the stop height
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
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

        // Verify the withdrawal occurred at the DEFERRED height, not the immediate height
        let withdrawals = engine_client_network.get_withdrawals();
        assert_eq!(withdrawals.len(), 1, "Expected exactly one withdrawal");

        // Verify there's NO withdrawal at the immediate height (proving deferral worked)
        assert!(
            withdrawals.get(&immediate_withdrawal_height).is_none(),
            "Withdrawal should NOT have occurred at immediate height {} (should be deferred)",
            immediate_withdrawal_height
        );

        // Verify the withdrawal DID occur at the deferred height
        let epoch_withdrawals = withdrawals
            .get(&deferred_withdrawal_height)
            .expect(&format!(
                "Withdrawal should have occurred at deferred height {}",
                deferred_withdrawal_height
            ));
        assert_eq!(epoch_withdrawals.len(), 1);
        assert_eq!(epoch_withdrawals[0].amount, min_stake);
        assert_eq!(epoch_withdrawals[0].address, withdrawal_address);

        // Verify the validator account was removed
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validators[last_idx].0.clone())
            .await;
        assert!(
            account.is_none(),
            "Validator account should be removed after full withdrawal"
        );

        // Verify other genesis validators are still active
        for validator in validators.iter().take(last_idx) {
            let account = state_query
                .get_validator_account(validator.0.clone())
                .await
                .unwrap();
            assert_eq!(account.balance, min_stake);
            assert_eq!(account.status, ValidatorStatus::Active);
        }

        // Skip the withdrawn validator in consensus check since they exit the committee
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &[&withdrawn_validator_uid])
                .is_ok()
        );

        common::assert_state_root_consensus_synced(&context, &consensus_state_queries, &[last_idx])
            .await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_grouped_withdrawal_on_last_block_of_epoch_only_requeues_deferred_request() {
    // Tests that a grouped type-0x01 EIP-7685 entry is not re-queued as a whole
    // when withdrawals are submitted on the last block of an epoch.
    //
    // Test setup:
    // - 5 genesis validators start with 32 ETH each
    // - Submit two withdrawals together on block 9 in a single grouped entry
    // - Both should be deferred to the next epoch boundary
    // - Each withdrawal should execute exactly once at the deferred height
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(43);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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

        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();
        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let idx_a = validators.len() - 2;
        let idx_b = validators.len() - 1;

        // Two full exits (amount 0) grouped in a single entry on the last block.
        let withdrawal_a = common::create_withdrawal_request(
            addresses[idx_a],
            validators[idx_a].0.as_ref().try_into().unwrap(),
            0,
        );
        let withdrawal_b = common::create_withdrawal_request(
            addresses[idx_b],
            validators[idx_b].0.as_ref().try_into().unwrap(),
            0,
        );

        let grouped_requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Withdrawal(withdrawal_a.clone()),
            ExecutionRequest::Withdrawal(withdrawal_b.clone()),
        ]);

        let withdrawal_block_height = DEFAULT_BLOCKS_PER_EPOCH - 1; // block 9
        let deferred_withdrawal_epoch = 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let deferred_withdrawal_height =
            (deferred_withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = deferred_withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, grouped_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut consensus_state_queries = HashMap::new();
        let mut withdrawn_validator_uids = Vec::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            if idx == idx_a || idx == idx_b {
                withdrawn_validator_uids.push(uid.clone());
            }
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
                    }
                }

                if height_reached.len() as u32 == n - 2 {
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
        assert_eq!(
            withdrawals.len(),
            1,
            "expected a single deferred withdrawal height"
        );

        let deferred_epoch_withdrawals = withdrawals
            .get(&deferred_withdrawal_height)
            .expect("missing deferred withdrawal height");
        assert_eq!(deferred_epoch_withdrawals.len(), 2);
        assert!(
            deferred_epoch_withdrawals
                .iter()
                .any(|w| w.address == withdrawal_a.source_address && w.amount == min_stake)
        );
        assert!(
            deferred_epoch_withdrawals
                .iter()
                .any(|w| w.address == withdrawal_b.source_address && w.amount == min_stake)
        );

        let skip_refs: Vec<&str> = withdrawn_validator_uids
            .iter()
            .map(String::as_str)
            .collect();
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &skip_refs)
                .is_ok()
        );

        common::assert_state_root_consensus_synced(
            &context,
            &consensus_state_queries,
            &[idx_a, idx_b],
        )
        .await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_duplicate_last_block_exit_does_not_consume_active_exit_budget() {
    // Regression test: a validator submitting DUPLICATE exit (full-withdrawal) requests
    // for itself on the last block of an epoch must not consume the active-exit budget
    // tracked by `pending_active_validator_exits`, and must not starve a different
    // validator's legitimate exit submitted in the same block.
    //
    // With 5 genesis validators and the default minimum_validator_count of 3, the
    // active-exit budget for an epoch is 5 - 3 = 2. The last block of epoch 0 carries a
    // single grouped type-0x01 entry containing three withdrawal requests, in order:
    //   [A, A, B]   (validator A duplicated, then validator B)
    //
    // Correct behavior: A's duplicate is deduplicated (A is exiting only once), B is
    // admitted, and both A and B are deferred and exit exactly once at the next epoch
    // boundary -> exactly 2 withdrawals, one for A and one for B.
    //
    // Buggy behavior (deferred last-block path never marks the account
    // `has_pending_withdrawal`, so duplicates bypass the dedup guard and each one
    // increments `pending_active_validator_exits`): A's two copies exhaust the budget,
    // the floor guard then skips B, and only A exits -> a single withdrawal. B is griefed
    // into staying active even though its own exit was valid and within the budget.
    let n = 5;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(43);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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

        let addresses: Vec<Address> = (0..n).map(|i| Address::from([i as u8; 20])).collect();
        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // A (the malicious duplicate submitter) and B (the legitimate victim).
        let idx_a = validators.len() - 2;
        let idx_b = validators.len() - 1;

        // Full exits (amount 0): A duplicated, then B.
        let withdrawal_a = common::create_withdrawal_request(
            addresses[idx_a],
            validators[idx_a].0.as_ref().try_into().unwrap(),
            0,
        );
        let withdrawal_b = common::create_withdrawal_request(
            addresses[idx_b],
            validators[idx_b].0.as_ref().try_into().unwrap(),
            0,
        );

        // A is submitted twice ahead of B, so under the bug A's duplicate consumes the
        // last remaining exit slot before B is reached.
        let grouped_requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Withdrawal(withdrawal_a.clone()),
            ExecutionRequest::Withdrawal(withdrawal_a.clone()),
            ExecutionRequest::Withdrawal(withdrawal_b.clone()),
        ]);

        let withdrawal_block_height = DEFAULT_BLOCKS_PER_EPOCH - 1; // block 9
        let deferred_withdrawal_epoch = 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS;
        let deferred_withdrawal_height =
            (deferred_withdrawal_epoch + 1) * DEFAULT_BLOCKS_PER_EPOCH - 1;
        let stop_height = deferred_withdrawal_height + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(withdrawal_block_height, grouped_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, Some(&addresses), None, min_stake);

        let mut consensus_state_queries = HashMap::new();
        let mut withdrawn_validator_uids = Vec::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            if idx == idx_a || idx == idx_b {
                withdrawn_validator_uids.push(uid.clone());
            }
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Only the three surviving validators keep finalizing past the exit.
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
                    }
                }

                if height_reached.len() as u32 == n - 2 {
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
        assert_eq!(
            withdrawals.len(),
            1,
            "expected a single deferred withdrawal height"
        );

        let deferred_epoch_withdrawals = withdrawals
            .get(&deferred_withdrawal_height)
            .expect("missing deferred withdrawal height");

        // Both A and B must exit exactly once. Under the bug, A's duplicate consumes the
        // budget and B is skipped, leaving only a single withdrawal.
        assert_eq!(
            deferred_epoch_withdrawals.len(),
            2,
            "both A and B must exit; B must not be starved by A's duplicate exit request"
        );

        let a_count = deferred_epoch_withdrawals
            .iter()
            .filter(|w| w.address == withdrawal_a.source_address && w.amount == min_stake)
            .count();
        let b_count = deferred_epoch_withdrawals
            .iter()
            .filter(|w| w.address == withdrawal_b.source_address && w.amount == min_stake)
            .count();
        assert_eq!(a_count, 1, "A's duplicate exit must be deduplicated to one");
        assert_eq!(b_count, 1, "B's legitimate exit must be admitted");

        // A and B should be removed; the other three validators must stay active.
        let survivor_query = consensus_state_queries
            .get(&0)
            .expect("a surviving validator should still be running");
        assert!(
            survivor_query
                .get_validator_account(validators[idx_a].0.clone())
                .await
                .is_none(),
            "validator A should be removed after its exit"
        );
        assert!(
            survivor_query
                .get_validator_account(validators[idx_b].0.clone())
                .await
                .is_none(),
            "validator B should be removed after its exit"
        );
        for idx in 0..(n as usize - 2) {
            let account = survivor_query
                .get_validator_account(validators[idx].0.clone())
                .await
                .expect("surviving validator should remain active");
            assert_eq!(account.status, ValidatorStatus::Active);
            assert_eq!(account.balance, min_stake);
        }

        let skip_refs: Vec<&str> = withdrawn_validator_uids
            .iter()
            .map(String::as_str)
            .collect();
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &skip_refs)
                .is_ok()
        );

        common::assert_state_root_consensus_synced(
            &context,
            &consensus_state_queries,
            &[idx_a, idx_b],
        )
        .await;

        context.auditor().state()
    })
}

#[test_traced("INFO")]
fn test_withdrawal_overflow_rescheduled_to_next_epoch() {
    // Tests that when more withdrawals are scheduled for an epoch than max_withdrawals_per_epoch
    // allows, the overflow withdrawals are rescheduled to the next epoch and processed ahead
    // of that epoch's own withdrawals.
    //
    // Setup:
    // - 7 genesis validators with 32 ETH each
    // - max_withdrawals_per_epoch = 2
    // - Epoch 0, block 3: submit withdrawal requests for validators 0, 1, 2
    //   → scheduled for epoch 2 (current_epoch + VALIDATOR_WITHDRAWAL_NUM_EPOCHS)
    // - Epoch 1, block 13: submit withdrawal request for validator 3
    //   → scheduled for epoch 3
    //
    // Expected:
    // - Epoch 2 end (block 29): only 2 of 3 withdrawals processed (validators 0, 1)
    //   Validator 2's withdrawal overflows to epoch 3
    // - Epoch 3 end (block 39): validator 2's overflow withdrawal processed first (priority),
    //   then validator 3's withdrawal
    //
    // Quorum: 7 validators, 2/3+1 = 5. After epoch 2 removes 2 → 5 active (ok).
    // After epoch 3 removes 2 more → 3 active, quorum = 3 (ok).
    let n = 7;
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
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let validator_pubkeys: Vec<[u8; 32]> = validators
            .iter()
            .map(|(pk, _)| pk.as_ref().try_into().unwrap())
            .collect();

        // Full exits (amount 0): each validator leaves and its whole balance is
        // paid out at its scheduled epoch, subject to max_withdrawals_per_epoch.
        let withdrawal0 = common::create_withdrawal_request(Address::ZERO, validator_pubkeys[0], 0);
        let withdrawal1 = common::create_withdrawal_request(Address::ZERO, validator_pubkeys[1], 0);
        let withdrawal2 = common::create_withdrawal_request(Address::ZERO, validator_pubkeys[2], 0);
        let withdrawal3 = common::create_withdrawal_request(Address::ZERO, validator_pubkeys[3], 0);

        // Epoch 0, block 3: three withdrawal requests → scheduled for epoch 2
        let epoch0_requests = common::execution_requests_to_requests(vec![
            ExecutionRequest::Withdrawal(withdrawal0.clone()),
            ExecutionRequest::Withdrawal(withdrawal1.clone()),
            ExecutionRequest::Withdrawal(withdrawal2.clone()),
        ]);

        // Epoch 1, block 13: one withdrawal request → scheduled for epoch 3
        let epoch1_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(
                withdrawal3.clone(),
            )]);

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(3, epoch0_requests);
        execution_requests_map.insert(13, epoch1_requests);

        // Epoch 3 ends at block 39
        let stop_height = 40;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();

        let mut initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        initial_state.set_max_withdrawals_per_epoch(2);

        let mut consensus_state_queries = HashMap::new();
        let mut withdrawn_uids = Vec::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            if idx < 4 {
                withdrawn_uids.push(uid.clone());
            }
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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
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
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("_peers_blocked") {
                    let value = sample.value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
                    }
                }

                // 4 of 7 validators are withdrawn; only 3 remain active
                if height_reached.len() >= (n as usize - 4) {
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

        // Epoch 2 ends at block 29: should have exactly 2 withdrawals (validators 0 and 1)
        let epoch2_withdrawals = withdrawals
            .get(&29)
            .expect("expected withdrawals at epoch 2 end (block 29)");
        assert_eq!(
            epoch2_withdrawals.len(),
            2,
            "max_withdrawals_per_epoch=2 should cap epoch 2 to 2 withdrawals"
        );

        // Epoch 3 ends at block 39: should have 2 withdrawals
        // - validator 2 (overflow from epoch 2, should be first)
        // - validator 3 (originally scheduled for epoch 3)
        let epoch3_withdrawals = withdrawals
            .get(&39)
            .expect("expected withdrawals at epoch 3 end (block 39)");
        assert_eq!(
            epoch3_withdrawals.len(),
            2,
            "overflow withdrawal + epoch 3 withdrawal should both be processed"
        );

        // Verify ordering: overflow withdrawal (validator 2) should come before
        // the epoch 3 withdrawal (validator 3). Validator 2's withdrawal was
        // created before validator 3's, so it has a lower withdrawal index.
        assert!(
            epoch3_withdrawals[0].index < epoch3_withdrawals[1].index,
            "overflow withdrawal (lower index) should be processed before epoch 3's own withdrawal"
        );

        let skip_refs: Vec<&str> = withdrawn_uids.iter().map(|s| s.as_str()).collect();
        assert!(
            engine_client_network
                .verify_consensus_skip(None, Some(stop_height), &skip_refs)
                .is_ok()
        );
        common::assert_state_root_consensus_synced(
            &context,
            &consensus_state_queries,
            &[0, 1, 2, 3],
        )
        .await;

        context.auditor().state()
    })
}

/// A withdrawal targeting a joining validator (activation scheduled for the
/// next epoch) that lands in the last block of the current epoch is deferred
/// to the next epoch. The validator joins for one epoch and exits in the next,
/// so the finalized header deltas match the live committee at every boundary.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2):
///  - 5 genesis validators @ 32 ETH (= min_stake).
///  - Block 5: brand-new validator deposit at 32 ETH.
///  - Block 8 (penultimate of epoch 0): deposit processed, joining_epoch = 2.
///  - Block 19 (last block of epoch 1): user submits a withdrawal targeting
///    the joining validator.
///
/// Assertions (run one block past epoch 2's last block so both boundaries have
/// run and the deferred withdrawal has replayed):
///  - Epoch 1's finalized header lists the joining validator in
///    `added_validators`.
///  - Epoch 2's finalized header lists the validator in `removed_validators`
///    (the deferred withdrawal replays at the start of epoch 2 and stages the
///    exit, which the last-block proposer captures into the header).
///  - Live state shows the validator as Inactive after epoch 2's boundary,
///    confirming the lifecycle: Joining → Active (epoch 2) → Inactive (epoch 3).
#[test_traced("INFO")]
fn test_joining_validator_withdrawal_on_last_block_keeps_header_consistent() {
    let n: u32 = 5;
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
            context.child("network"),
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

        let genesis_hash = from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Brand-new validator deposit at block 5. Processed at block 8
        // (penultimate of epoch 0) → joining_epoch = 0 + VALIDATOR_NUM_WARM_UP_EPOCHS = 2.
        let (new_deposit, new_validator_private_key, _) = common::create_deposit_request(
            n as u64,
            new_validator_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        let new_validator_pubkey = new_validator_private_key.public_key();
        let new_validator_pubkey_bytes: [u8; 32] =
            new_validator_pubkey.as_ref().try_into().unwrap();
        let withdrawal_address =
            utils::parse_withdrawal_credentials(new_deposit.withdrawal_credentials).unwrap();
        let deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(new_deposit)]);

        // Withdrawal for the joining validator, landing on the LAST block of
        // epoch 1. The validator's activation is scheduled for epoch 2, so the
        // last-block header captures them in added_validators[2]. Amount 0 is a
        // full exit, applied once the validator has activated in epoch 2.
        let withdrawal =
            common::create_withdrawal_request(withdrawal_address, new_validator_pubkey_bytes, 0);
        let withdrawal_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(withdrawal)]);

        let deposit_block_height = 5;
        let last_block_epoch_1 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 1);
        let last_block_epoch_2 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 2);
        // Stop one block past the end of epoch 2 so both epoch boundaries have
        // run: validator is activated at block 19 and (with the fix) exited at
        // block 29 via the replayed deferred withdrawal.
        let stop_height = last_block_epoch_2 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, deposit_requests);
        execution_requests_map.insert(last_block_epoch_1, withdrawal_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
            let engine = Engine::new(
                context.child("engine").with_attribute("uid", uid.clone()),
                config,
            )
            .await;
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
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

        let mut mailbox = finalizer_mailboxes.get(&0).unwrap().clone();

        // Epoch 1's finalized header lists the joining validator in
        // added_validators, matching the validator that live state activates
        // at the epoch boundary.
        let header_epoch_1 = mailbox
            .get_finalized_header(1)
            .await
            .expect("missing finalized header for epoch 1");
        let added_epoch_1 = header_epoch_1.header().added_validators();
        assert!(
            added_epoch_1
                .iter()
                .any(|av| av.node_key == new_validator_pubkey),
            "epoch 1 header must include the joining validator in added_validators, \
             but added_validators = {added_epoch_1:?}"
        );

        // Epoch 2's finalized header lists the validator in removed_validators:
        // the deferred withdrawal replays at the start of epoch 2 and stages
        // the (now-active) validator for exit, which the last-block proposer
        // captures into the header.
        let header_epoch_2 = mailbox
            .get_finalized_header(2)
            .await
            .expect("missing finalized header for epoch 2");
        let removed_epoch_2 = header_epoch_2.header().removed_validators();
        assert!(
            removed_epoch_2.contains(&new_validator_pubkey),
            "epoch 2 header must include the joining validator in removed_validators \
             (the deferred withdrawal replays in epoch 2 and exits the activated validator), \
             but removed_validators = {removed_epoch_2:?}"
        );

        // Full lifecycle landed in live state: activated at the epoch-1
        // boundary, exited at the epoch-2 boundary.
        let new_account = mailbox
            .get_validator_account(new_validator_pubkey.clone())
            .await
            .expect("validator account should still exist after the exit");
        assert_eq!(
            new_account.status,
            ValidatorStatus::FullPayoutPending,
            "validator must be FullPayoutPending after the epoch 2 boundary (full exit \
             staged and committee-removed, payout still pending); live state status was {:?}",
            new_account.status
        );

        context.auditor().state()
    })
}

/// A withdrawal that cancels a joining validator's pending activation via the
/// inline cancel path (NOT on the last block of an epoch) transitions the
/// account's status to `Inactive`. The validator is never activated, so
/// `get_active_or_joining_validators`, the `joining_validators` log/metric,
/// and RPC queries all reflect a definitively cancelled validator during the
/// window before withdrawal completion removes the account.
///
/// Setup (DEFAULT_BLOCKS_PER_EPOCH = 10, VALIDATOR_NUM_WARM_UP_EPOCHS = 2,
/// VALIDATOR_WITHDRAWAL_NUM_EPOCHS = 2):
///  - 5 genesis validators @ 32 ETH (= min_stake).
///  - Block 5: brand-new validator deposit at 32 ETH.
///  - Block 8 (penultimate of epoch 0): deposit processed → status = Joining,
///    joining_epoch = 2.
///  - Block 15 (mid-epoch 1, not a last block): user submits a withdrawal
///    targeting the joining validator. This hits the inline-cancel path
///    (joining_epoch (2) > current_epoch (1), not last block).
///
/// Assertions (stop at block 20 — well before withdrawal completion at the end
/// of epoch 3 = block 39):
///  - The validator account still exists (withdrawal hasn't completed yet).
///  - balance is retained (reduced only at payout; the cancel does not force-withdraw).
///  - account.status == Inactive.
#[test_traced("INFO")]
fn test_joining_validator_withdrawal_inline_cancel_clears_status() {
    let n: u32 = 5;
    let min_stake = 32_000_000_000;
    let new_validator_amount = min_stake;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(1);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.child("network"),
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
            from_hex(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Brand-new validator deposit at block 5. Processed at block 8
        // (penultimate of epoch 0) → joining_epoch = 2.
        let (new_deposit, new_validator_private_key, _) = common::create_deposit_request(
            n as u64,
            new_validator_amount,
            common::get_domain(),
            None,
            None,
            None,
        );
        let new_validator_pubkey = new_validator_private_key.public_key();
        let new_validator_pubkey_bytes: [u8; 32] =
            new_validator_pubkey.as_ref().try_into().unwrap();
        let withdrawal_address =
            utils::parse_withdrawal_credentials(new_deposit.withdrawal_credentials).unwrap();
        let deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(new_deposit)]);

        // Withdrawal for the joining validator at block 15 (mid-epoch 1, NOT a
        // last block). joining_epoch (2) > current_epoch (1) and the request
        // is not on the last block of the epoch, so the inline-cancel branch
        // fires: `remove_added_validator(2, pk)`.
        let withdrawal = common::create_withdrawal_request(
            withdrawal_address,
            new_validator_pubkey_bytes,
            new_validator_amount,
        );
        let withdrawal_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(withdrawal)]);

        let deposit_block_height = 5;
        let withdrawal_block_height = 15;
        // Stop one block past the end of epoch 1. Well before the withdrawal
        // completes (end of epoch 3 = block 39), so the account is still
        // present and we can observe its status mid-flight.
        let last_block_epoch_1 = last_block_in_epoch(DEFAULT_BLOCKS_PER_EPOCH, 1);
        let stop_height = last_block_epoch_1 + 1;

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(deposit_block_height, deposit_requests);
        execution_requests_map.insert(withdrawal_block_height, withdrawal_requests);

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

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
            let engine = Engine::new(context.child("engine").with_attribute("uid", uid.clone()), config).await;
            finalizer_mailboxes.insert(idx, engine.finalizer_mailbox.clone());

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                let Some(sample) = common::parse_metric(line) else {
                    continue;
                };

                if sample.name.ends_with("finalizer_height") {
                    let height = sample.value.parse::<u64>().unwrap();
                    if height >= stop_height {
                        height_reached.insert(sample.uid.clone());
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

        let mailbox = finalizer_mailboxes.get(&0).unwrap();

        // The withdrawal completes 2 epochs after submission (end of epoch 3 =
        // block 39), at which point the account is removed. We stop at block
        // 20 so the account is still present and reflects post-cancel state.
        let new_account = mailbox
            .get_validator_account(new_validator_pubkey.clone())
            .await
            .expect(
                "validator account should still exist mid-flight \
                 (withdrawal completes only at end of epoch 3)",
            );

        // The balance is retained; the cancel does not force-withdraw. The
        // enqueued payout reduces the balance only when it completes.
        assert_eq!(
            new_account.balance, new_validator_amount,
            "balance must be retained after cancelling the joining validator (reduced only at payout)"
        );

        // The cancel path transitions the account to Inactive, so the
        // validator is excluded from `get_active_or_joining_validators` and
        // related queries during the window before withdrawal completion
        // removes the account.
        assert_eq!(
            new_account.status,
            ValidatorStatus::Inactive,
            "after cancelling the pending activation, status must be Inactive; \
             live state status was {:?}",
            new_account.status
        );

        context.auditor().state()
    })
}
