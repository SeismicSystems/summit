//! Tests for execution client syncing behavior during startup and block execution.

use super::mocks::{MockEngineClient, MockNetworkOracle};
use crate::actor::Finalizer;
use crate::config::{FinalizerConfig, ProtocolConsts};
use alloy_primitives::{Address, U256};
use alloy_rpc_types_engine::{
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState,
};
use commonware_consensus::Reporter;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_cryptography::{Signer as _, bls12381, ed25519};
use commonware_math::algebra::Random;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::deterministic::{self, Runner};
use commonware_runtime::{Clock, Metrics, Runner as _};
use commonware_utils::NZUsize;
use commonware_utils::acknowledgement::{Acknowledgement, Exact};
use futures::channel::mpsc as futures_mpsc;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::time::Duration;
use summit_syncer::Update;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::consensus_state::ConsensusState;
use summit_types::{Block, Digest};
use tokio_util::sync::CancellationToken;

/// Helper to create a test block with specific parent and height
fn create_test_block(parent_digest: Digest, height: u64, view: u64, unique_seed: u64) -> Block {
    let mut block_hash = [0u8; 32];
    block_hash[0..8].copy_from_slice(&unique_seed.to_le_bytes());
    block_hash[8..16].copy_from_slice(&height.to_le_bytes());

    let parent_bytes: [u8; 32] = parent_digest.0;

    let payload = ExecutionPayloadV3 {
        payload_inner: ExecutionPayloadV2 {
            payload_inner: ExecutionPayloadV1 {
                base_fee_per_gas: U256::from(1000000000u64),
                block_number: height,
                block_hash: block_hash.into(),
                logs_bloom: Default::default(),
                extra_data: Default::default(),
                gas_limit: 30000000,
                gas_used: 0,
                timestamp: height * 12,
                fee_recipient: Default::default(),
                parent_hash: if height == 0 {
                    [0u8; 32].into()
                } else {
                    parent_bytes.into()
                },
                prev_randao: Default::default(),
                receipts_root: Default::default(),
                state_root: Default::default(),
                transactions: Vec::new(),
            },
            withdrawals: Vec::new().into(),
        },
        blob_gas_used: 0,
        excess_blob_gas: 0,
    };

    Block::compute_digest(
        parent_digest,
        height,
        height * 12,
        payload,
        Vec::new(),
        U256::ZERO,
        height / 10,
        view,
        None,
        [0u8; 32].into(),
        Vec::new(),
        Vec::new(),
        [0u8; 32],
    )
}

/// Create a minimal initial ConsensusState for testing
fn create_test_initial_state(genesis_hash: [u8; 32]) -> ConsensusState {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let mut validator_accounts = BTreeMap::new();

    for i in 0..4u64 {
        let node_key = ed25519::PrivateKey::from_seed(i);
        let node_pubkey = node_key.public_key();
        let consensus_key = bls12381::PrivateKey::random(&mut rng);
        let consensus_pubkey = consensus_key.public_key();

        let account = ValidatorAccount {
            consensus_public_key: consensus_pubkey,
            withdrawal_credentials: Address::from([i as u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 0,
        };

        let key_bytes: [u8; 32] = node_pubkey.as_ref().try_into().unwrap();
        validator_accounts.insert(key_bytes, account);
    }

    let forkchoice = ForkchoiceState {
        head_block_hash: genesis_hash.into(),
        safe_block_hash: genesis_hash.into(),
        finalized_block_hash: genesis_hash.into(),
    };
    let mut state = ConsensusState::new(forkchoice, 32_000_000_000, 64_000_000_000);
    state.set_validator_accounts(validator_accounts);
    state
}

/// Create an initial state that looks like it came from a checkpoint at a non-zero height.
fn create_checkpoint_initial_state(
    checkpoint_hash: [u8; 32],
    height: u64,
    epoch: u64,
) -> ConsensusState {
    let mut state = create_test_initial_state(checkpoint_hash);
    state.set_latest_height(height);
    state.set_view(height);
    state.set_epoch(epoch);
    state.set_forkchoice(ForkchoiceState {
        head_block_hash: checkpoint_hash.into(),
        safe_block_hash: checkpoint_hash.into(),
        finalized_block_hash: checkpoint_hash.into(),
    });
    state
}

fn default_protocol_consts() -> ProtocolConsts {
    ProtocolConsts {
        epoch_num_of_blocks: 10,
        validator_onboarding_limit_per_block: 10,
        validator_num_warm_up_epochs: 2,
        validator_withdrawal_num_epochs: 2,
    }
}

#[test]
fn test_initial_startup_sync_waits_for_valid() {
    // Test that the finalizer's initial forkchoice update loop retries
    // when the execution client returns SYNCING, and proceeds once VALID.
    // After the sync completes, finalized blocks should be processed normally.

    let cfg = deterministic::Config::default().with_seed(100);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let checkpoint_hash = [0xAAu8; 32];
        // Checkpoint at height 5, still in epoch 0 (epoch_num_of_blocks = 10)
        let initial_state = create_checkpoint_initial_state(checkpoint_hash, 5, 0);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // commit_hash returns SYNCING twice, then falls through to VALID
        engine_client.queue_commit_hash_syncing(2);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_startup_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: default_protocol_consts(),
            validator_max_withdrawals_per_block: 16,
            page_cache: CacheRef::new(std::num::NonZero::new(4096).unwrap(), NZUsize!(100)),
            genesis_hash: checkpoint_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start();

        // The initial forkchoice loop sleeps 5s per SYNCING retry.
        // With 2 SYNCING responses, the finalizer needs ~10s before it starts
        // processing messages. Wait long enough for it to complete.
        context.sleep(Duration::from_secs(12)).await;

        // Now send a finalized block — it should be processed normally
        // Height 6, epoch = 6/10 = 0, matches state.epoch
        let block = create_test_block(checkpoint_hash.into(), 6, 6, 2001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block, None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Verify the block was processed by checking the height advanced
        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 6,
            "finalizer should have processed block after sync"
        );

        context.auditor().state()
    });
}

#[test]
fn test_initial_startup_sync_zero_forkchoice_skips_sync() {
    // Test that if the forkchoice head is zero (genesis startup without checkpoint),
    // the initial sync loop is skipped entirely.

    let cfg = deterministic::Config::default().with_seed(101);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0u8; 32];
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_zero_forkchoice".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: default_protocol_consts(),
            validator_max_withdrawals_per_block: 16,
            page_cache: CacheRef::new(std::num::NonZero::new(4096).unwrap(), NZUsize!(100)),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start();
        // Only a short sleep — no sync loop should run
        context.sleep(Duration::from_millis(100)).await;

        // Send a finalized block — should process immediately
        let genesis_block = Block::genesis(genesis_hash);
        let block = create_test_block(genesis_block.digest(), 1, 1, 3001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block, None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 1,
            "block should be processed immediately with zero forkchoice head"
        );

        context.auditor().state()
    });
}

#[test]
fn test_execute_block_retries_on_syncing() {
    // Test that when check_payload returns SYNCING during block execution,
    // the finalizer retries until VALID and then processes the block correctly.

    let cfg = deterministic::Config::default().with_seed(102);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // check_payload returns SYNCING 3 times for the first block, then VALID
        engine_client.queue_check_payload_syncing(3);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_execute_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: default_protocol_consts(),
            validator_max_withdrawals_per_block: 16,
            page_cache: CacheRef::new(std::num::NonZero::new(4096).unwrap(), NZUsize!(100)),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start();
        context.sleep(Duration::from_millis(100)).await;

        // Send a finalized block that will hit the SYNCING retry loop
        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack))
            .await;

        // With 3 SYNCING retries at 5s each, need ~15s for the retries to complete
        context.sleep(Duration::from_secs(17)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 1,
            "block should eventually be processed after SYNCING retries"
        );

        // Send a second block to verify the finalizer continues normally
        let block2 = create_test_block(block1.digest(), 2, 2, 4002);
        let (ack2, _waiter2) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block2, None), ack2))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 2,
            "subsequent block should process immediately without SYNCING"
        );

        context.auditor().state()
    });
}

#[test]
fn test_notarized_block_retries_on_syncing() {
    // Test that when check_payload returns SYNCING during notarized block execution,
    // the block is eventually processed and available in fork_states.

    let cfg = deterministic::Config::default().with_seed(103);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // check_payload returns SYNCING 2 times, then VALID
        engine_client.queue_check_payload_syncing(2);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_notarized_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: default_protocol_consts(),
            validator_max_withdrawals_per_block: 16,
            page_cache: CacheRef::new(std::num::NonZero::new(4096).unwrap(), NZUsize!(100)),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start();
        context.sleep(Duration::from_millis(100)).await;

        // Send a notarized block — triggers execute_block which hits SYNCING
        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 5001);
        let block1_digest = block1.digest();
        mailbox.report(Update::NotarizedBlock(block1)).await;

        // Wait for SYNCING retries to complete (2 retries * 5s = 10s)
        context.sleep(Duration::from_secs(12)).await;

        // Verify the block is in fork_states via notify_at_height
        let notify = mailbox.notify_at_height(1, block1_digest).await;
        let result = notify.await.expect("notify channel closed");
        assert!(
            result,
            "notarized block should be in fork_states after SYNCING retries"
        );

        context.auditor().state()
    });
}

#[test]
fn test_checkpoint_startup_full_flow() {
    // End-to-end test: simulate a node joining with a checkpoint.
    // - Initial forkchoice returns SYNCING (reth doesn't have the chain yet)
    // - After sync, first finalized block's check_payload also returns SYNCING briefly
    // - Eventually everything resolves and blocks are processed

    let cfg = deterministic::Config::default().with_seed(104);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let checkpoint_hash = [0xBBu8; 32];
        // Checkpoint at height 5, epoch 0 (epoch_num_of_blocks = 10)
        let initial_state = create_checkpoint_initial_state(checkpoint_hash, 5, 0);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Initial forkchoice sync: SYNCING once
        engine_client.queue_commit_hash_syncing(1);
        // First block execution: SYNCING once
        engine_client.queue_check_payload_syncing(1);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_checkpoint_flow".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: default_protocol_consts(),
            validator_max_withdrawals_per_block: 16,
            page_cache: CacheRef::new(std::num::NonZero::new(4096).unwrap(), NZUsize!(100)),
            genesis_hash: checkpoint_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start();

        // Wait for initial forkchoice sync (1 SYNCING * 5s)
        context.sleep(Duration::from_secs(7)).await;

        // Send first block after checkpoint (height 6, epoch 0)
        let block6 = create_test_block(checkpoint_hash.into(), 6, 6, 6001);
        let (ack6, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block6.clone(), None), ack6))
            .await;

        // Wait for the check_payload SYNCING retry (1 * 5s)
        context.sleep(Duration::from_secs(7)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 6,
            "first block after checkpoint should be processed"
        );

        // Send second block — no more SYNCING, should be immediate
        let block7 = create_test_block(block6.digest(), 7, 7, 6002);
        let (ack7, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block7.clone(), None), ack7))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(height, 7, "second block should process immediately");

        // Send third block — also immediate
        let block8 = create_test_block(block7.digest(), 8, 8, 6003);
        let (ack8, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block8, None), ack8))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(height, 8, "third block should process immediately");

        context.auditor().state()
    });
}
