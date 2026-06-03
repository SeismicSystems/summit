use crate::engine::Engine;
use crate::test_harness::common;
use crate::test_harness::common::DEFAULT_BLOCKS_PER_EPOCH;
use crate::test_harness::common::{SimulatedOracle, get_default_engine_config, get_initial_state};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use alloy_primitives::Address;
use commonware_codec::Encode as _;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381;
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::{NZUsize, from_hex_formatted};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use summit_types::PrivateKey;
use summit_types::checkpoint::{self, CheckpointVerificationError};
use summit_types::consensus_state::ConsensusState;
use summit_types::execution_request::ExecutionRequest;
use summit_types::genesis::{Genesis, GenesisValidator};
use summit_types::keystore::KeyStore;

#[test_traced("INFO")]
fn test_checkpoint_verification_fixed_committee() {
    // Runs a network for multiple epochs, then fetches all finalized headers
    // and verifies the checkpoint chain cryptographically.
    let n = 5;
    let num_epochs = checkpoint::WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS + 2;
    let namespace = "_SUMMIT";
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
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

        // Build a Genesis struct matching the test validators
        let genesis_validators: Vec<GenesisValidator> = validators
            .iter()
            .enumerate()
            .map(|(i, (node_pk, consensus_pk))| {
                let node_pub_hex = commonware_utils::hex(node_pk.as_ref());
                let consensus_pub_hex = commonware_utils::hex(&consensus_pk.encode());
                GenesisValidator {
                    node_public_key: format!("0x{node_pub_hex}"),
                    consensus_public_key: format!("0x{consensus_pub_hex}"),
                    ip_address: format!("127.0.0.1:{}", 26600 + i * 10),
                    withdrawal_credentials: format!("0x{:040x}", 0x1000u64 + i as u64),
                }
            })
            .collect();
        let genesis = Genesis {
            validators: genesis_validators,
            eth_genesis_hash: common::GENESIS_HASH.to_string(),
            leader_timeout_ms: 1000,
            notarization_timeout_ms: 2000,
            nullify_timeout_ms: 10000,
            activity_timeout_views: 10,
            skip_timeout_views: 5,
            max_message_size_bytes: 1024 * 1024,
            namespace: namespace.to_string(),
            validator_minimum_stake: 32_000_000_000,
            validator_maximum_stake: 32_000_000_000,
            blocks_per_epoch: common::DEFAULT_BLOCKS_PER_EPOCH,
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO.to_string(),
            max_deposits_per_epoch: 10,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
        };

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        let stop_height = num_epochs * DEFAULT_BLOCKS_PER_EPOCH;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");

            let engine_client = engine_client_network.create_client(uid.clone());
            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace.to_string(),
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

        // Wait for all nodes to reach target height
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
                if height_reached.len() as u32 >= n {
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Fetch the latest checkpoint from node 0
        let mut mailbox = consensus_state_queries.get(&0).unwrap().clone();

        let (raw_checkpoint, _) = mailbox
            .clone()
            .get_latest_checkpoint()
            .await
            .0
            .expect("failed to query checkpoint");

        let checkpoint_state =
            ConsensusState::try_from(&raw_checkpoint).expect("failed to parse consensus state");
        let checkpoint_epoch = checkpoint_state.get_epoch();
        assert!(
            checkpoint_epoch >= num_epochs - 1,
            "expected checkpoint at epoch >= {}, got {}",
            num_epochs - 1,
            checkpoint_epoch
        );

        // Fetch all finalized headers from epoch 0 through checkpoint_epoch
        let mut finalized_headers = Vec::new();
        for epoch in 0..=checkpoint_epoch {
            let header = mailbox
                .get_finalized_header(epoch)
                .await
                .unwrap_or_else(|| panic!("missing finalized header for epoch {epoch}"));
            finalized_headers.push(header);
        }

        // Verify the checkpoint chain
        checkpoint::verify_checkpoint_chain(&genesis, &finalized_headers, &raw_checkpoint)
            .expect("checkpoint verification failed");

        assert!(
            checkpoint_epoch > checkpoint::WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS,
            "test needs a checkpoint beyond the weak-subjectivity window"
        );

        let weak_subjectivity_epoch =
            checkpoint_epoch - checkpoint::WEAK_SUBJECTIVITY_MAX_AGE_EPOCHS;
        let weak_subjectivity = checkpoint::WeakSubjectivityHeaderDigest {
            epoch: weak_subjectivity_epoch,
            header_digest: finalized_headers[weak_subjectivity_epoch as usize]
                .header
                .digest,
        };
        checkpoint::verify_checkpoint_chain_with_weak_subjectivity(
            &genesis,
            &finalized_headers,
            &raw_checkpoint,
            Some(&weak_subjectivity),
        )
        .expect("checkpoint verification with weak-subjectivity anchor failed");

        let wrong_weak_subjectivity = checkpoint::WeakSubjectivityHeaderDigest {
            epoch: weak_subjectivity_epoch,
            header_digest: [0xFF; 32].into(),
        };
        let err = checkpoint::verify_checkpoint_chain_with_weak_subjectivity(
            &genesis,
            &finalized_headers,
            &raw_checkpoint,
            Some(&wrong_weak_subjectivity),
        )
        .expect_err("verification should fail with a mismatched weak-subjectivity anchor");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::WeakSubjectivityHeaderDigestMismatch { epoch, .. }
                    if epoch == weak_subjectivity_epoch
            ),
            "expected WeakSubjectivityHeaderDigestMismatch for epoch {weak_subjectivity_epoch}, got: {err}"
        );

        let stale_weak_subjectivity = checkpoint::WeakSubjectivityHeaderDigest {
            epoch: 0,
            header_digest: finalized_headers[0].header.digest,
        };
        let err = checkpoint::verify_checkpoint_chain_with_weak_subjectivity(
            &genesis,
            &finalized_headers,
            &raw_checkpoint,
            Some(&stale_weak_subjectivity),
        )
        .expect_err("verification should fail with a stale weak-subjectivity anchor");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::WeakSubjectivityCheckpointTooOld {
                    weak_subjectivity_epoch: 0,
                    ..
                }
            ),
            "expected WeakSubjectivityCheckpointTooOld for epoch 0, got: {err}"
        );

        let unavailable_weak_subjectivity = checkpoint::WeakSubjectivityHeaderDigest {
            epoch: checkpoint_epoch + 1,
            header_digest: [0u8; 32].into(),
        };
        let err = checkpoint::verify_checkpoint_chain_with_weak_subjectivity(
            &genesis,
            &finalized_headers,
            &raw_checkpoint,
            Some(&unavailable_weak_subjectivity),
        )
        .expect_err("verification should fail when the weak-subjectivity epoch is unavailable");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::WeakSubjectivityEpochUnavailable { .. }
            ),
            "expected WeakSubjectivityEpochUnavailable, got: {err}"
        );

        // Verify that a tampered signature causes verification to fail
        let mut tampered_sig_headers = finalized_headers.clone();
        tampered_sig_headers[1].finalization.proposal.payload.0[0] ^= 0xFF;
        let err =
            checkpoint::verify_checkpoint_chain(&genesis, &tampered_sig_headers, &raw_checkpoint)
                .expect_err("verification should fail with tampered signature");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::SignatureVerificationFailed { epoch: 1 }
            ),
            "expected SignatureVerificationFailed for epoch 1, got: {err}"
        );

        // Verify that removing a header causes verification to fail
        assert!(
            finalized_headers.len() >= 3,
            "need at least 3 headers to test removal"
        );
        let mut tampered_headers = finalized_headers.clone();
        tampered_headers.remove(1); // remove epoch 1
        let err = checkpoint::verify_checkpoint_chain(&genesis, &tampered_headers, &raw_checkpoint)
            .expect_err("verification should fail with missing header");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::NonContiguousEpochs { expected: 1, .. }
            ),
            "expected NonContiguousEpochs for epoch 1, got: {err}"
        );

        // Verify that breaking the epoch-header chain link causes verification
        // to fail. Tampering `prev_epoch_header_hash` does not invalidate the
        // signature (which is over `header.digest`), so this exercises the
        // chain check independently.
        let mut chain_tampered_headers = finalized_headers.clone();
        chain_tampered_headers[1].header.prev_epoch_header_hash.0[0] ^= 0xFF;
        let err =
            checkpoint::verify_checkpoint_chain(&genesis, &chain_tampered_headers, &raw_checkpoint)
                .expect_err("verification should fail with broken chain link");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::PrevEpochHeaderHashMismatch { epoch: 1 }
            ),
            "expected PrevEpochHeaderHashMismatch for epoch 1, got: {err}"
        );

        // Same check for the genesis anchor (epoch 0).
        let mut genesis_anchor_tampered = finalized_headers.clone();
        genesis_anchor_tampered[0].header.prev_epoch_header_hash.0[0] ^= 0xFF;
        let err = checkpoint::verify_checkpoint_chain(
            &genesis,
            &genesis_anchor_tampered,
            &raw_checkpoint,
        )
        .expect_err("verification should fail when genesis anchor is broken");
        assert!(
            matches!(
                err,
                CheckpointVerificationError::PrevEpochHeaderHashMismatch { epoch: 0 }
            ),
            "expected PrevEpochHeaderHashMismatch for epoch 0, got: {err}"
        );

        common::assert_state_root_consensus(&consensus_state_queries).await;

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_checkpoint_verification_dynamic_committee() {
    // Runs a network with a deposit and withdrawal so the validator set changes,
    // then verifies the checkpoint chain handles added/removed validators correctly.
    let n = 5;
    let min_stake = 32_000_000_000u64;
    let namespace = "_SUMMIT";
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
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

        // Build a Genesis struct matching the test validators
        let genesis_validators: Vec<GenesisValidator> = validators
            .iter()
            .enumerate()
            .map(|(i, (node_pk, consensus_pk))| {
                let node_pub_hex = commonware_utils::hex(node_pk.as_ref());
                let consensus_pub_hex = commonware_utils::hex(&consensus_pk.encode());
                GenesisValidator {
                    node_public_key: format!("0x{node_pub_hex}"),
                    consensus_public_key: format!("0x{consensus_pub_hex}"),
                    ip_address: format!("127.0.0.1:{}", 26600 + i * 10),
                    withdrawal_credentials: format!("0x{:040x}", 0x1000u64 + i as u64),
                }
            })
            .collect();
        let genesis = Genesis {
            validators: genesis_validators,
            eth_genesis_hash: common::GENESIS_HASH.to_string(),
            leader_timeout_ms: 1000,
            notarization_timeout_ms: 2000,
            nullify_timeout_ms: 10000,
            activity_timeout_views: 10,
            skip_timeout_views: 5,
            max_message_size_bytes: 1024 * 1024,
            namespace: namespace.to_string(),
            validator_minimum_stake: min_stake,
            validator_maximum_stake: min_stake,
            blocks_per_epoch: common::DEFAULT_BLOCKS_PER_EPOCH,
            allowed_timestamp_future_ms: 10_000,
            treasury_address: Address::ZERO.to_string(),
            max_deposits_per_epoch: 10,
            max_withdrawals_per_epoch: 16,
            observers_per_validator: 0,
        };

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;
        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Create a deposit for a new validator at block 5 (epoch 0)
        // joining_epoch = 0 + VALIDATOR_NUM_WARM_UP_EPOCHS = 2
        // added_validators will appear in epoch 1's finalized header
        let (deposit, _, _) =
            common::create_deposit_request(10, min_stake, common::get_domain(), None, None, None);
        let deposit_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Deposit(deposit)]);

        // Create a withdrawal for genesis validator 1 at block 15 (epoch 1)
        // removed_validators will appear in epoch 1's finalized header
        let withdrawing_idx = 1;
        let withdrawing_pubkey = validators[withdrawing_idx].0.clone();
        let withdrawing_pubkey_bytes: [u8; 32] = withdrawing_pubkey
            .as_ref()
            .try_into()
            .expect("Public key must be 32 bytes");
        let withdrawal =
            common::create_withdrawal_request(Address::ZERO, withdrawing_pubkey_bytes, min_stake);
        let withdrawal_requests =
            common::execution_requests_to_requests(vec![ExecutionRequest::Withdrawal(withdrawal)]);

        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(5u64, deposit_requests);
        execution_requests_map.insert(15u64, withdrawal_requests);

        let stop_height = DEFAULT_BLOCKS_PER_EPOCH * 4;

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .with_stop_at(stop_height)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");

            let engine_client = engine_client_network.create_client(uid.clone());
            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace.to_string(),
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

        // Wait for all non-withdrawing nodes to reach target height
        let withdrawing_uid = format!("validator_{withdrawing_pubkey}");
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
                    // Skip the withdrawing validator — it will exit consensus
                    if metric.starts_with(&withdrawing_uid) {
                        continue;
                    }
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

        // Fetch the latest checkpoint from a non-withdrawing node
        let mut mailbox = consensus_state_queries.get(&0).unwrap().clone();

        let (raw_checkpoint, _) = mailbox
            .clone()
            .get_latest_checkpoint()
            .await
            .0
            .expect("failed to query checkpoint");

        let checkpoint_state =
            ConsensusState::try_from(&raw_checkpoint).expect("failed to parse consensus state");
        let checkpoint_epoch = checkpoint_state.get_epoch();
        assert!(
            checkpoint_epoch >= 3,
            "expected checkpoint at epoch >= 3, got {}",
            checkpoint_epoch
        );

        // Fetch all finalized headers from epoch 0 through checkpoint_epoch
        let mut finalized_headers = Vec::new();
        for epoch in 0..=checkpoint_epoch {
            let header = mailbox
                .get_finalized_header(epoch)
                .await
                .unwrap_or_else(|| panic!("missing finalized header for epoch {epoch}"));
            finalized_headers.push(header);
        }

        // Verify epoch 1's header has both added and removed validators
        let epoch_1_header = &finalized_headers[1];
        assert!(
            !epoch_1_header.header.added_validators.is_empty(),
            "epoch 1 header should have added_validators"
        );
        assert!(
            !epoch_1_header.header.removed_validators.is_empty(),
            "epoch 1 header should have removed_validators"
        );

        // Verify the full checkpoint chain with dynamic validator set
        checkpoint::verify_checkpoint_chain(&genesis, &finalized_headers, &raw_checkpoint)
            .expect("checkpoint verification with dynamic committee failed");

        common::assert_state_root_consensus_skip(&consensus_state_queries, &[withdrawing_idx])
            .await;

        context.auditor().state()
    });
}
