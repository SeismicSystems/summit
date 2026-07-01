use super::*;

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
fn test_deposit_less_than_min_stake_creates_inactive_account() {
    // Adds a below-minimum deposit request at height 5. The deposit creates an
    // inactive account that keeps the balance; it is not rejected or refunded.
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

        // A below-minimum initial deposit creates an inactive account that keeps
        // the balance; it is not refunded.
        let state_query = consensus_state_queries.get(&0).unwrap();
        let account = state_query
            .get_validator_account(validator_node_key)
            .await
            .expect("below-minimum deposit must create an inactive account");
        assert_eq!(account.status, ValidatorStatus::Inactive);
        assert_eq!(account.balance, test_deposit.amount);

        // No refund withdrawal is issued.
        assert!(engine_client_network.get_withdrawals().is_empty());

        // Check that all nodes have the same canonical chain
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
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);
        // Raise max_stake so that the post-top-up balance (32 + 8 = 40) is
        // within [min, max]; otherwise the bounds check at deposit
        // verification refunds the deposit and we wouldn't actually be
        // exercising the missing "BLS key must match the account's stored
        // BLS key" check.

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
