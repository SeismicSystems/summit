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
use std::num::NonZeroU64;
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
            withdrawals: Vec::new(),
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
fn create_test_initial_state(genesis_hash: [u8; 32], epoch_length: NonZeroU64) -> ConsensusState {
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
    let mut state = ConsensusState::new(
        forkchoice,
        32_000_000_000,
        64_000_000_000,
        epoch_length,
        10_000,
        Address::ZERO,
        10,
        16,
        0,
        3,
    );
    state.set_validator_accounts(validator_accounts);
    state
}

/// Create an initial state that looks like it came from a checkpoint at a non-zero height.
fn create_checkpoint_initial_state(
    checkpoint_hash: [u8; 32],
    height: u64,
    epoch: u64,
    epoch_length: NonZeroU64,
) -> ConsensusState {
    let mut state = create_test_initial_state(checkpoint_hash, epoch_length);
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
        validator_num_warm_up_epochs: 2,
        validator_withdrawal_num_epochs: 2,
    }
}

#[test]
fn test_initial_startup_sync_waits_for_valid() {
    // Test that the finalizer tolerates a SYNCING initial forkchoice update
    // without blocking: it enters its main loop immediately, and finalized blocks
    // are processed once the execution client returns VALID.

    let cfg = deterministic::Config::default().with_seed(100);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let checkpoint_hash = [0xAAu8; 32];
        // Checkpoint at height 5, still in epoch 0 (epoch_num_of_blocks = 10)
        let initial_state =
            create_checkpoint_initial_state(checkpoint_hash, 5, 0, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Startup forkchoice update returns SYNCING once (the finalizer enters its
        // main loop without blocking); later commit_hash calls fall through to
        // VALID so the block's own forkchoice update succeeds and it applies.
        engine_client.queue_commit_hash_syncing(1);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_startup_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash: checkpoint_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);

        // Startup does not block on SYNCING — it enters the main loop right away.
        // A short pause lets startup finish before we send the block.
        context.sleep(Duration::from_millis(200)).await;

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
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_zero_forkchoice".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
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
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // check_payload returns SYNCING 3 times for the first block, then VALID
        engine_client.queue_check_payload_syncing(3);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_execute_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
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
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // check_payload returns SYNCING 2 times, then VALID
        engine_client.queue_check_payload_syncing(2);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_notarized_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
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
        let initial_state =
            create_checkpoint_initial_state(checkpoint_hash, 5, 0, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Initial forkchoice sync: SYNCING once
        engine_client.queue_commit_hash_syncing(1);
        // First block execution: SYNCING once
        engine_client.queue_check_payload_syncing(1);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_checkpoint_flow".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash: checkpoint_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);

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

/// If the execution layer keeps returning SYNCING for a finalized block, the
/// finalizer's `execute_block` retries indefinitely in an unbounded inline
/// loop. While that loop is running the finalizer task is parked inside
/// `select! { mailbox.next() => handle_finalized_block(...) }`, so no other
/// mailbox arm can fire — aux-data requests, consensus-state queries,
/// orchestrator messages and even cancellation all wait for local EL
/// recovery. This is a liveness/DoS risk for a lagging, restarting or
/// catching-up validator whose EL stays in SYNCING.
///
/// Setup: a single-finalizer harness whose `MockEngineClient` has many
/// SYNCING responses queued for `check_payload` (1000 > any reasonable
/// retry budget). A finalized block is reported to the finalizer, which
/// drives it into the SYNCING retry loop.
///
/// Assertion: after the block has had time to enter `execute_block`, an
/// unrelated mailbox query (`get_latest_height`) must respond within a
/// bounded virtual time. Today the mailbox is fully blocked while the EL
/// is SYNCING, so the bounded sleep wins the race and the test fails —
/// directly exposing the audit's "finalizer mailbox stalled during catch-up"
/// claim. Any fix that bounds the retry (critical-shutdown on cap, or
/// moves the wait to a background task) will make the query resolve.
#[test]
fn test_finalizer_mailbox_responsive_under_persistent_syncing() {
    use futures::FutureExt;
    use futures::pin_mut;

    let cfg = deterministic::Config::default().with_seed(7);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0xAAu8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Effectively infinite for the test window: at 5s per retry, 1000
        // SYNCING responses cover 5000 virtual seconds — far more than the
        // 1s race window we use below to detect a blocked mailbox.
        engine_client.queue_check_payload_syncing(1000);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_persistent_syncing_mailbox".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        // Let the finalizer reach its main mailbox loop.
        context.sleep(Duration::from_millis(100)).await;

        // Drive the finalizer into execute_block. With persistent SYNCING
        // it enters the unbounded retry loop and the actor task stops
        // servicing other mailbox messages.
        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 7001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;

        // Give the finalizer enough virtual time to dequeue the
        // FinalizedBlock update and enter execute_block's SYNCING loop.
        context.sleep(Duration::from_millis(200)).await;

        // Now issue an unrelated mailbox query and race it against a
        // bounded virtual-time deadline. If the finalizer is responsive,
        // `get_latest_height` resolves quickly. If the mailbox is blocked
        // by the SYNCING loop, the deadline wins.
        let query_mailbox = mailbox.clone();
        let query_fut = async move { query_mailbox.get_latest_height().await }.fuse();
        let deadline_fut = context.sleep(Duration::from_secs(1)).fuse();
        pin_mut!(query_fut, deadline_fut);

        futures::select! {
            _height = query_fut => {
                // mailbox responded — finalizer remained responsive
                // while the EL was stuck in SYNCING.
            }
            _ = deadline_fut => {
                panic!(
                    "finalizer mailbox stalled while EL was SYNCING: \
                     get_latest_height did not resolve within 1 virtual \
                     second of dispatch. The finalizer-side execute_block \
                     SYNCING loop is monopolising the actor task; a \
                     lagging/restarting/catch-up validator can lose \
                     mailbox liveness indefinitely until the EL recovers."
                );
            }
        }

        context.auditor().state()
    });
}

/// The finalizer's startup `commit_hash` loop (finalizer/src/actor.rs:271)
/// runs *before* the main mailbox loop begins. If the EL keeps returning
/// SYNCING during that initial forkchoice update, the actor never enters
/// its `select!` — every mailbox arm is starved (queries, cancellation,
/// finalized/notarized updates, runtime stop), and queries against the
/// already-loaded checkpoint state are silently rejected even though the
/// data is available.
///
/// Setup: a finalizer restarted from a checkpoint at height 5. The
/// `MockEngineClient` has many SYNCING responses queued for `commit_hash`
/// (1000 > the test's 1-second race window).
///
/// Assertion: shortly after starting the finalizer, an unrelated mailbox
/// query (`get_latest_height`) must resolve within a bounded virtual time
/// and return the checkpoint-loaded height. Today the startup loop blocks
/// the actor before it ever reaches the mailbox `select!`, so the bounded
/// sleep wins the race and the test fails. Any fix that drops the startup
/// retry loop (one-shot `commit_hash` + fall-through on SYNCING) or moves
/// the wait off the actor task will let the query resolve from the
/// checkpoint-loaded `canonical_state`.
#[test]
fn test_finalizer_mailbox_responsive_during_startup_syncing() {
    use futures::FutureExt;
    use futures::pin_mut;

    let cfg = deterministic::Config::default().with_seed(11);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let checkpoint_hash = [0xCDu8; 32];
        // Checkpoint at height 5, epoch 0.
        let initial_state =
            create_checkpoint_initial_state(checkpoint_hash, 5, 0, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Effectively infinite SYNCING for the test window: 1000 * 5s =
        // 5000 virtual seconds, far longer than the 1s deadline below.
        engine_client.queue_commit_hash_syncing(1000);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_startup_syncing_mailbox".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash: checkpoint_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        // Give the finalizer task time to be scheduled and enter the
        // startup `commit_hash` path.
        context.sleep(Duration::from_millis(100)).await;

        // Issue an unrelated mailbox query and race it against a bounded
        // virtual-time deadline. If the actor entered its main mailbox
        // loop, the query resolves quickly from the checkpoint-loaded
        // `canonical_state` (height = 5). If the startup `commit_hash`
        // loop is still blocking the actor, the deadline wins.
        let query_mailbox = mailbox.clone();
        let query_fut = async move { query_mailbox.get_latest_height().await }.fuse();
        let deadline_fut = context.sleep(Duration::from_secs(1)).fuse();
        pin_mut!(query_fut, deadline_fut);

        futures::select! {
            height = query_fut => {
                assert_eq!(
                    height, 5,
                    "expected the checkpoint-loaded latest height to be visible \
                     via the mailbox once the actor enters its main loop"
                );
            }
            _ = deadline_fut => {
                panic!(
                    "finalizer mailbox stalled at startup while EL was SYNCING: \
                     get_latest_height did not resolve within 1 virtual second of \
                     dispatch. The startup commit_hash loop is blocking the actor \
                     before its main `select!` begins; on a checkpoint-restart, a \
                     validator whose EL needs to catch up cannot answer any RPC or \
                     mailbox query until the EL recovers."
                );
            }
        }

        context.auditor().state()
    });
}

#[test]
fn test_finalizer_shuts_down_when_pending_notarized_cap_is_reached() {
    let cfg = deterministic::Config::default().with_seed(17);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0xEFu8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);
        let engine_client = MockEngineClient::new();
        engine_client.queue_check_payload_syncing(10);

        let cancellation_token = CancellationToken::new();
        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_pending_notarized_cap".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: cancellation_token.clone(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 2,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(20)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block_a = create_test_block(genesis_block.digest(), 1, 1, 17001);
        let block_b = create_test_block(genesis_block.digest(), 1, 1, 17002);
        let block_c = create_test_block(genesis_block.digest(), 1, 1, 17003);

        mailbox.report(Update::NotarizedBlock(block_a)).await;
        mailbox.report(Update::NotarizedBlock(block_b)).await;
        mailbox.report(Update::NotarizedBlock(block_c)).await;

        context.sleep(Duration::from_millis(50)).await;

        assert!(
            cancellation_token.is_cancelled(),
            "finalizer should trigger graceful shutdown once pending_notarized reaches its hard cap"
        );

        context.auditor().state()
    });
}

/// Regression test for an ordering bug in the finalized SYNCING buffer.
///
/// Two finalized blocks at heights H and H+1 arrive during an EL-SYNCING
/// window. Both enter the pending buffer. While they are buffered, the EL
/// finishes catching up. The drain timer must apply them in arrival order
/// (H before H+1); applying H+1 first would mutate `canonical_state` past
/// the height of H, and the subsequent apply of H would silently regress
/// `latest_height` — corrupting Summit's view of the chain while Reth has
/// already moved on.
///
/// Concrete failure mode this test catches (with the broken implementation
/// that calls `pending_finalized.push_back` from inside the handler on
/// Syncing, regardless of whether the caller is the mailbox or the drain
/// timer):
///
///   1. mailbox brings A (height 1); EL returns SYNCING. Buffer = `[A]`.
///   2. mailbox brings B (height 2); EL returns SYNCING. Buffer = `[A, B]`.
///   3. drain pops A; EL returns SYNCING; handler push_back's A.
///      **Buffer = `[B, A]` — ordering broken.**
///   4. Between ticks the EL catches up.
///   5. drain pops B first; `check_payload` returns VALID; `execute_block`
///      sets `latest_height` to 2. Then drain pops A; VALID; `set_latest_height`
///      to 1. Final `latest_height` = 1, B's deposit/withdrawal effects already
///      committed to Reth. Summit's state diverges from the EL.
///
/// We queue exactly three SYNCING responses (A#1 via mailbox, B#1 via
/// mailbox, A#2 via drain). The fourth `check_payload` call falls through
/// to VALID. The expected final `latest_height` is 2 *with both blocks
/// applied in order*. Any fix that preserves drain ordering will pass.
#[test]
fn test_finalizer_finalized_buffer_drains_in_order() {
    let cfg = deterministic::Config::default().with_seed(13);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Exactly enough SYNCING responses to force the ordering bug under
        // the broken implementation: A#1 (mailbox), B#1 (mailbox), A#2
        // (drain retry). Subsequent calls fall through to VALID.
        engine_client.queue_check_payload_syncing(3);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_buffer_in_order".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            // Fast drain so the test doesn't have to sleep for the default 5s.
            drain_interval: Duration::from_millis(50),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        // Let the finalizer reach its main mailbox loop.
        context.sleep(Duration::from_millis(20)).await;

        // Send finalized blocks in height order.
        let genesis_block = Block::genesis(genesis_hash);
        let block_a = create_test_block(genesis_block.digest(), 1, 1, 13001);
        let block_b = create_test_block(block_a.digest(), 2, 2, 13002);

        let (ack_a, _waiter_a) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block_a, None), ack_a))
            .await;

        // Small gap so A's mailbox path runs (and buffers) before B arrives.
        context.sleep(Duration::from_millis(10)).await;

        let (ack_b, _waiter_b) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block_b, None), ack_b))
            .await;

        // Give the drain timer multiple ticks to exhaust the queued SYNCING
        // responses and apply both blocks. Three SYNCING responses at 50ms
        // drain_interval is at most ~200ms of real work; 1s is comfortable.
        context.sleep(Duration::from_secs(1)).await;

        let height = mailbox.get_latest_height().await;
        assert_eq!(
            height, 2,
            "finalized buffer must drain in arrival order. Got latest_height = {height}."
        );

        context.auditor().state()
    });
}

#[test]
fn test_duplicate_finalized_delivery_is_idempotent() {
    // The syncer documents at-least-once finalized delivery (syncer/src/lib.rs: "The actor
    // will deliver a block to the reporter at-least-once. The reporter should be prepared to
    // handle duplicate deliveries."). So the finalizer must tolerate a duplicate
    // Update::FinalizedBlock for a block it has already applied: it must NOT re-execute the
    // block against the execution layer or regress its canonical height, but it MUST still
    // acknowledge the duplicate so the syncer's pending-ack pipeline does not stall.
    //
    // Regression guard for the missing idempotence guard in handle_finalized_block: the
    // notarized path ignores blocks at or below canonical height, the finalized path does
    // not. On the pre-fix code the duplicate is re-executed, so check_payload runs a second
    // time (and execution requests would be re-processed / the height regressed).
    let cfg = deterministic::Config::default().with_seed(77);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Shares the call counter with the client moved into the finalizer (Arc-backed).
        let engine_client_probe = engine_client.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_duplicate_finalized".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(50),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(20)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 77001);

        // First (legitimate) finalized delivery: the block is applied and executed once.
        let (ack1, _waiter1) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack1))
            .await;
        context.sleep(Duration::from_millis(200)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "first finalized block must apply"
        );
        let calls_after_first = engine_client_probe.check_payload_call_count();
        assert_eq!(
            calls_after_first, 1,
            "first finalized delivery should execute the block exactly once"
        );

        // Duplicate finalized delivery of the SAME block (at-least-once contract).
        let (ack2, waiter2) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack2))
            .await;
        context.sleep(Duration::from_millis(200)).await;

        // The duplicate must be acknowledged so the syncer's pending-ack pipeline does not
        // stall. (A guard that returns early without acking would drop the handle and the
        // waiter would resolve Err(Canceled).)
        assert!(
            waiter2.await.is_ok(),
            "duplicate finalized delivery must be acknowledged, not dropped"
        );

        // The duplicate must not change/regress canonical height.
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "duplicate finalized block must not change canonical height"
        );

        // The duplicate must NOT be re-executed against the execution layer.
        assert_eq!(
            engine_client_probe.check_payload_call_count(),
            calls_after_first,
            "duplicate finalized block must not be re-executed (check_payload was called again)"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalized_commit_hash_syncing_buffers_and_retries() {
    // When the forkchoice update (commit_hash) returns SYNCING during finalized
    // block execution, the finalizer must NOT advance — it buffers and retries,
    // applying the block only once the EL adopts the forkchoice.
    let cfg = deterministic::Config::default().with_seed(202);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // forkchoice update returns SYNCING 3 times for the first block, then VALID.
        engine_client.queue_commit_hash_syncing(3);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_fcu_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;

        // Must NOT advance while the forkchoice is still SYNCING.
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            0,
            "must not advance while the EL forkchoice is SYNCING"
        );

        // Once the retries clear and the EL returns VALID, the block applies.
        context.sleep(Duration::from_secs(20)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "block must apply once the EL adopts the forkchoice"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalized_commit_hash_invalid_shuts_down() {
    // A non-valid (INVALID) forkchoice update for a finalized block is an EL/CL
    // inconsistency (the payload was already VALID): the validator must shut down
    // rather than advance on a head the EL has not adopted.
    let cfg = deterministic::Config::default().with_seed(203);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Startup forkchoice update consumes the first override; keep it VALID so
        // only the finalized block's forkchoice update is INVALID.
        engine_client.queue_commit_hash_valid(1);
        engine_client.queue_commit_hash_invalid(1);

        let token = CancellationToken::new();
        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_fcu_invalid".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: token.clone(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;
        context.sleep(Duration::from_millis(500)).await;

        assert!(
            token.is_cancelled(),
            "a non-valid finalized forkchoice update must shut the validator down"
        );

        context.auditor().state()
    });
}

#[test]
fn test_notarized_commit_hash_invalid_discards_fork() {
    // A non-valid (INVALID) forkchoice update for a notarized fork is discarded,
    // not fatal: the finalizer drops the fork and keeps running.
    let cfg = deterministic::Config::default().with_seed(204);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // Startup forkchoice update consumes the first override; keep it VALID so
        // the notarized fork's forkchoice update is the INVALID one.
        engine_client.queue_commit_hash_valid(1);
        engine_client.queue_commit_hash_invalid(1);

        let token = CancellationToken::new();
        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_notarized_fcu_invalid".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: token.clone(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);

        // Notarized block whose forkchoice update is INVALID → fork discarded.
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(500)).await;
        assert!(
            !token.is_cancelled(),
            "a non-valid notarized forkchoice must not shut the validator down"
        );

        // The finalizer must keep working: finalize the same block (commit_hash now
        // VALID) and confirm it advances.
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;
        context.sleep(Duration::from_millis(500)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "finalizer must recover and apply a valid block after discarding the fork"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalized_reuse_path_commits_finalized_forkchoice_and_shuts_down_on_invalid() {
    // A block notarized before finalization is executed speculatively into a fork
    // state with safe=finalized=old_canonical_finalized. When it later finalizes, the
    // reuse path must still send and gate the canonical finalized forkchoice
    // (head=safe=finalized=B). Here that finalized forkchoice is INVALID — an EL/CL
    // inconsistency — so the validator must shut down rather than promote the fork.
    //
    // Regression guard: before the fix the reuse path skipped the finalized forkchoice
    // entirely, so this INVALID would never be sent and the node would advance to
    // height 1 instead of shutting down.
    let cfg = deterministic::Config::default().with_seed(205);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // commit_hash order: startup (VALID), notarized-fork execution (VALID),
        // finalized reuse-path forkchoice (INVALID).
        engine_client.queue_commit_hash_valid(2);
        engine_client.queue_commit_hash_invalid(1);

        let token = CancellationToken::new();
        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_reuse_fcu_invalid".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: token.clone(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);
        let block1_digest = block1.digest();

        // Notarize first → block lands in fork_states (forkchoice VALID).
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(200)).await;
        let notify = mailbox.notify_at_height(1, block1_digest).await;
        assert!(
            notify.await.expect("notify channel closed"),
            "notarized block must be in fork_states before finalization"
        );
        assert!(
            !token.is_cancelled(),
            "notarizing a valid block must not shut the validator down"
        );

        // Finalize the same block → reuse path sends the finalized forkchoice, which
        // the EL rejects as INVALID → fatal shutdown.
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;
        context.sleep(Duration::from_millis(500)).await;

        assert!(
            token.is_cancelled(),
            "a non-valid finalized forkchoice on the reuse path must shut the validator down"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalized_reuse_path_buffers_on_syncing() {
    // When the finalized forkchoice on the reuse path returns SYNCING, the finalizer
    // must NOT advance (canonical state stays untouched so the retry replays cleanly)
    // and must apply the block only once the EL adopts the finalized forkchoice.
    let cfg = deterministic::Config::default().with_seed(206);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let engine_client = MockEngineClient::new();
        // commit_hash order: startup (VALID), notarized-fork execution (VALID), then
        // the finalized reuse-path forkchoice returns SYNCING 3 times before VALID.
        engine_client.queue_commit_hash_valid(2);
        engine_client.queue_commit_hash_syncing(3);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_reuse_fcu_sync".to_string(),
            engine_client,
            oracle: MockNetworkOracle,
            protocol_consts: default_protocol_consts(),
            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let block1 = create_test_block(genesis_block.digest(), 1, 1, 4001);
        let block1_digest = block1.digest();

        // Notarize first → block lands in fork_states (forkchoice VALID). Notarization
        // does not advance the finalized height.
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(200)).await;
        let notify = mailbox.notify_at_height(1, block1_digest).await;
        assert!(
            notify.await.expect("notify channel closed"),
            "notarized block must be in fork_states before finalization"
        );
        assert_eq!(
            mailbox.get_latest_height().await,
            0,
            "notarization must not advance the finalized height"
        );

        // Finalize the same block → reuse path forkchoice is SYNCING: must buffer.
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1, None), ack))
            .await;
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            0,
            "must not advance while the finalized forkchoice is SYNCING"
        );

        // Once the retries clear and the EL adopts the forkchoice, the block applies.
        context.sleep(Duration::from_secs(20)).await;
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "block must apply once the EL adopts the finalized forkchoice"
        );

        context.auditor().state()
    });
}
