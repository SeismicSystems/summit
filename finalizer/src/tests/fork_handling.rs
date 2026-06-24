//! Tests for finalizer fork handling: orphaned blocks, multiple forks, and dead fork detection.

use super::mocks::{MockEngineClient, MockNetworkOracle};
use crate::actor::Finalizer;
use crate::config::{FinalizerConfig, ProtocolConsts};
use alloy_primitives::{Address, B256, U256};
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
use futures::{FutureExt as _, channel::mpsc as futures_mpsc};
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

#[test]
fn test_orphaned_block_processed_when_parent_arrives() {
    // Test that orphaned blocks (arriving before their parent) are processed
    // once the parent arrives.

    let cfg = deterministic::Config::default().with_seed(42);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_orphaned".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Block 1: parent = genesis, height = 1
        // Block 2: parent = block1, height = 2
        let block1 = create_test_block(genesis_digest, 1, 2, 1001);
        let block1_digest = block1.digest();

        let block2 = create_test_block(block1_digest, 2, 3, 1002);
        let block2_digest = block2.digest();

        // Send block2 first (orphaned - parent block1 not yet processed)
        mailbox.report(Update::NotarizedBlock(block2.clone())).await;
        context.sleep(Duration::from_millis(50)).await;

        // Now send block1 (parent is genesis/canonical)
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(100)).await;

        // Verify both blocks are in fork_states
        let notify1 = mailbox.notify_at_height(1, block1_digest).await;
        let notify2 = mailbox.notify_at_height(2, block2_digest).await;

        let result1 = notify1.await.expect("notify channel closed");
        let result2 = notify2.await.expect("notify channel closed");

        assert!(result1, "Block 1 should be in fork_states");
        assert!(result2, "Block 2 should be processed after parent arrived");

        context.auditor().state()
    });
}

#[test]
fn test_fork_aux_data_does_not_finalize_unfinalized_fork_head() {
    // Regression test: aux data for a block proposed on a notarized-but-unfinalized
    // fork must never advertise the speculative fork head as the EL-finalized hash.
    //
    // `execute_block` normalizes a fork state's safe/finalized forkchoice hashes to
    // the fork head so the SSZ state root is independent of processing order. That
    // stored forkchoice must NOT be exposed verbatim to the Engine API: the safe and
    // finalized hashes sent to engine_forkchoiceUpdatedV3 have to keep pointing at the
    // canonical finalized block, exactly as the immediate fork commit does. Otherwise
    // a validator building on a fork tells its EL the speculative head is finalized,
    // and if the fork loses the local EL can no longer follow the canonical finalized
    // branch.

    let cfg = deterministic::Config::default().with_seed(42);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x42u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_fork_aux_finalized".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Notarize (but never finalize) block1 on top of genesis. It lands in
        // fork_states as a speculative fork head; canonical finalized stays at genesis.
        let block1 = create_test_block(genesis_digest, 1, 2, 1001);
        let block1_digest = block1.digest();
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(100)).await;

        let in_forks = mailbox
            .notify_at_height(1, block1_digest)
            .await
            .await
            .expect("notify channel closed");
        assert!(
            in_forks,
            "block1 should be tracked as a notarized fork state"
        );

        // Request aux data for a child proposed on the fork head (height 2).
        let aux = mailbox
            .get_aux_data(2, block1_digest)
            .await
            .await
            .expect("aux data channel closed")
            .expect("aux data should be available for the fork parent");

        let canonical_finalized: B256 = genesis_hash.into();
        let fork_head_el: B256 = block1.eth_block_hash().into();

        // The fork head is notarized but unfinalized: it must never be advertised as
        // the EL-finalized (or safe) hash. Both must stay at the canonical finalized
        // block, while the head we build on is the fork head.
        assert_ne!(
            aux.forkchoice.finalized_block_hash, fork_head_el,
            "fork aux data must not mark the unfinalized fork head as EL-finalized"
        );
        assert_eq!(
            aux.forkchoice.finalized_block_hash, canonical_finalized,
            "fork aux data finalized hash must remain the canonical finalized block"
        );
        assert_eq!(
            aux.forkchoice.safe_block_hash, canonical_finalized,
            "fork aux data safe hash must remain the canonical finalized block"
        );
        assert_eq!(
            aux.forkchoice.head_block_hash, fork_head_el,
            "fork aux data head must be the fork head being built on"
        );

        context.auditor().state()
    });
}

#[test]
fn test_losing_height_waiter_resolves_false_on_conflicting_finalization() {
    // Test that a waiter registered for a future losing digest is completed
    // when a different digest finalizes at that height.

    let cfg = deterministic::Config::default().with_seed(49);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x49u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_losing_waiter".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        let winning_block = create_test_block(genesis_digest, 1, 2, 8001);
        let losing_block = create_test_block(genesis_digest, 1, 2, 8002);
        let winning_digest = winning_block.digest();
        let losing_digest = losing_block.digest();
        assert_ne!(winning_digest, losing_digest);

        let losing_notify = mailbox.notify_at_height(1, losing_digest).await;
        let second_losing_notify = mailbox.notify_at_height(1, losing_digest).await;
        let dropped_losing_notify = mailbox.notify_at_height(1, losing_digest).await;
        drop(dropped_losing_notify);

        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((winning_block.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(mailbox.get_latest_height().await, 1);
        assert_eq!(
            losing_notify.now_or_never(),
            Some(Ok(false)),
            "waiter for finalized-away digest should resolve false"
        );
        assert_eq!(
            second_losing_notify.now_or_never(),
            Some(Ok(false)),
            "all waiters for a finalized-away digest should resolve false"
        );

        context.auditor().state()
    });
}

#[test]
fn test_competing_digest_waiter_stays_pending_until_finalization() {
    // Test that executing one notarized fork does not complete a waiter for a
    // competing digest until finalization chooses the canonical digest.

    let cfg = deterministic::Config::default().with_seed(50);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x50u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_competing_waiter".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        let block1a = create_test_block(genesis_digest, 1, 2, 8101);
        let block1b = create_test_block(genesis_digest, 1, 2, 8102);
        let block1b_digest = block1b.digest();

        let pending_probe = mailbox.notify_at_height(1, block1b_digest).await;
        let losing_notify = mailbox.notify_at_height(1, block1b_digest).await;

        mailbox
            .report(Update::NotarizedBlock(block1a.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(
            pending_probe.now_or_never(),
            None,
            "competing digest waiter should remain pending after a different fork is notarized"
        );

        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1a.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(
            losing_notify.now_or_never(),
            Some(Ok(false)),
            "competing digest waiter should resolve false after finalization"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalization_resolves_lower_waiters_and_preserves_future_waiters() {
    // Test that finalizing height H resolves stale waiters below H but leaves
    // waiters above H pending.

    let cfg = deterministic::Config::default().with_seed(51);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x51u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_waiter_sweep".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        let block1 = create_test_block(genesis_digest, 1, 2, 8201);
        let block1_digest = block1.digest();
        let block2 = create_test_block(block1_digest, 2, 3, 8202);

        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        mailbox.report(Update::NotarizedBlock(block2.clone())).await;
        context.sleep(Duration::from_millis(100)).await;

        let stale_block = create_test_block(genesis_digest, 1, 2, 8203);
        let future_block = create_test_block(block2.digest(), 3, 4, 8204);
        let stale_notify = mailbox.notify_at_height(1, stale_block.digest()).await;
        let future_notify = mailbox.notify_at_height(3, future_block.digest()).await;

        // Finalize sequentially (the syncer never skips a height): canonical
        // advances 0 -> 1 -> 2.
        let (ack1, _waiter1) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack1))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block2.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(mailbox.get_latest_height().await, 2);
        assert_eq!(
            stale_notify.now_or_never(),
            Some(Ok(false)),
            "waiter below finalized height should resolve false"
        );
        assert_eq!(
            future_notify.now_or_never(),
            None,
            "waiter above finalized height should remain pending"
        );

        context.auditor().state()
    });
}

#[test]
fn test_multiple_forks_tracked() {
    // Test that multiple competing forks are tracked simultaneously.

    let cfg = deterministic::Config::default().with_seed(43);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x43u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_forks".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Two competing blocks at height 1 (same parent, different content)
        let block1a = create_test_block(genesis_digest, 1, 2, 2001);
        let block1a_digest = block1a.digest();

        let block1b = create_test_block(genesis_digest, 1, 2, 2002);
        let block1b_digest = block1b.digest();

        assert_ne!(block1a_digest, block1b_digest);

        mailbox
            .report(Update::NotarizedBlock(block1a.clone()))
            .await;
        mailbox
            .report(Update::NotarizedBlock(block1b.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Both should be in fork_states
        let notify1a = mailbox.notify_at_height(1, block1a_digest).await;
        let notify1b = mailbox.notify_at_height(1, block1b_digest).await;

        let result1a = notify1a.await.expect("notify channel closed");
        let result1b = notify1b.await.expect("notify channel closed");

        assert!(result1a, "Block 1a should be in fork_states");
        assert!(result1b, "Block 1b should be in fork_states");

        context.auditor().state()
    });
}

#[test]
fn test_dead_fork_block_discarded() {
    // Test that a block on a dead fork (parent doesn't match canonical) is discarded.

    let cfg = deterministic::Config::default().with_seed(44);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x44u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_dead_fork".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Create and finalize block1 (becomes canonical at height 1)
        let block1 = create_test_block(genesis_digest, 1, 2, 3001);
        let block1_digest = block1.digest();

        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(mailbox.get_latest_height().await, 1);

        // Block at height 2 with WRONG parent (should be discarded)
        let wrong_parent: Digest = [0xDEu8; 32].into();
        let dead_fork_block = create_test_block(wrong_parent, 2, 3, 3002);

        mailbox
            .report(Update::NotarizedBlock(dead_fork_block.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Canonical chain should still be at height 1
        assert_eq!(mailbox.get_latest_height().await, 1);

        // A valid block at height 2 should work
        let valid_block2 = create_test_block(block1_digest, 2, 3, 3003);
        let valid_block2_digest = valid_block2.digest();

        mailbox
            .report(Update::NotarizedBlock(valid_block2.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let notify_valid = mailbox.notify_at_height(2, valid_block2_digest).await;
        let result = notify_valid.await.expect("notify channel closed");
        assert!(result, "Valid block 2 should be in fork_states");

        context.auditor().state()
    });
}

#[test]
fn test_fork_states_pruned_after_finalization() {
    // Test that fork_states at or below the finalized height are pruned.
    //
    // Scenario:
    // 1. Create notarized blocks at heights 1, 2, 3 (all in fork_states)
    // 2. Finalize block at height 2
    // 3. Fork states at heights 1 and 2 should be pruned
    // 4. Fork state at height 3 should remain accessible

    let cfg = deterministic::Config::default().with_seed(45);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x45u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_prune_forks".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Create chain: genesis -> block1 -> block2 -> block3
        let block1 = create_test_block(genesis_digest, 1, 2, 4001);
        let block1_digest = block1.digest();

        let block2 = create_test_block(block1_digest, 2, 3, 4002);
        let block2_digest = block2.digest();

        let block3 = create_test_block(block2_digest, 3, 4, 4003);
        let block3_digest = block3.digest();

        // Send all as notarized (they go to fork_states)
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        mailbox.report(Update::NotarizedBlock(block2.clone())).await;
        mailbox.report(Update::NotarizedBlock(block3.clone())).await;
        context.sleep(Duration::from_millis(100)).await;

        // Verify all three are in fork_states
        let notify1 = mailbox.notify_at_height(1, block1_digest).await;
        let notify2 = mailbox.notify_at_height(2, block2_digest).await;
        let notify3 = mailbox.notify_at_height(3, block3_digest).await;

        assert!(notify1.await.unwrap(), "Block 1 should be in fork_states");
        assert!(notify2.await.unwrap(), "Block 2 should be in fork_states");
        assert!(notify3.await.unwrap(), "Block 3 should be in fork_states");

        // Finalize sequentially: the syncer delivers finalized blocks in
        // monotonic height order with no gaps, so the finalizer advances
        // canonical 0 -> 1 -> 2 rather than jumping straight to height 2.
        let (ack1, _waiter1) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack1))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Now finalize block2 (height 2)
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block2.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Canonical height should be 2
        assert_eq!(mailbox.get_latest_height().await, 2);

        // notify_at_height for height 1 should return false (height is outdated)
        let notify1_after = mailbox.notify_at_height(1, block1_digest).await;
        let result1 = notify1_after.await.unwrap();
        assert!(
            !result1,
            "Height 1 should be outdated after finalizing height 2"
        );

        // notify_at_height for height 2 with correct digest should return true (canonical)
        let notify2_after = mailbox.notify_at_height(2, block2_digest).await;
        let result2 = notify2_after.await.unwrap();
        assert!(result2, "Height 2 with canonical digest should return true");

        // Fork state at height 3 should still exist
        let notify3_after = mailbox.notify_at_height(3, block3_digest).await;
        let result3 = notify3_after.await.unwrap();
        assert!(
            result3,
            "Block 3 should still be in fork_states after pruning"
        );

        context.auditor().state()
    });
}

#[test]
fn test_losing_fork_descendant_rejected_after_conflicting_ancestor_finalizes() {
    // A notarized descendant of a losing fork must not remain usable after a
    // conflicting ancestor finalizes.
    //
    // Scenario:
    // 1. Notarize A1 at height 1 and A2 at height 2.
    // 2. Finalize conflicting B1 at height 1.
    // 3. A2 should no longer satisfy NotifyAtHeight or serve aux data.

    let cfg = deterministic::Config::default().with_seed(49);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x49u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_losing_descendant_pruned".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        let block_a1 = create_test_block(genesis_digest, 1, 2, 8001);
        let block_a1_digest = block_a1.digest();
        let block_a2 = create_test_block(block_a1_digest, 2, 3, 8002);
        let block_a2_digest = block_a2.digest();
        let block_b1 = create_test_block(genesis_digest, 1, 4, 8003);
        let block_b1_digest = block_b1.digest();

        assert_ne!(block_a1_digest, block_b1_digest);

        mailbox
            .report(Update::NotarizedBlock(block_a1.clone()))
            .await;
        mailbox
            .report(Update::NotarizedBlock(block_a2.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        let notify_a2 = mailbox.notify_at_height(2, block_a2_digest).await;
        assert!(
            notify_a2.await.unwrap(),
            "A2 should be tracked before the conflicting ancestor finalizes"
        );

        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block_b1.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(mailbox.get_latest_height().await, 1);
        let notify_b1 = mailbox.notify_at_height(1, block_b1_digest).await;
        assert!(
            notify_b1.await.unwrap(),
            "B1 should be canonical after finalization"
        );

        let notify_a2_after = mailbox.notify_at_height(2, block_a2_digest).await;
        assert!(
            !notify_a2_after.await.unwrap(),
            "A2 descends from losing A1 and must not remain live"
        );

        let aux_data = mailbox
            .get_aux_data(3, block_a2_digest)
            .await
            .await
            .unwrap();
        assert!(
            aux_data.is_none(),
            "A2 must not serve aux data after conflicting B1 finalizes"
        );

        context.auditor().state()
    });
}

#[test]
fn test_finalized_dead_fork_descendant_out_of_sequence_halts() {
    // Defense-in-depth for the finalized-block path: a finalized block must
    // extend the canonical head at exactly canonical_height + 1. If a descendant
    // of a losing fork is delivered as a *finalized* block out of sequence (which
    // can only arise from a consensus safety violation plus out-of-order
    // delivery — the syncer never delivers finalized blocks with a gap), the
    // finalizer must halt rather than execute it onto canonical state.
    //
    // Scenario:
    // 1. Notarize A1 -> A2 -> A3 (heights 1, 2, 3; all in fork_states).
    // 2. Finalize conflicting B1 at height 1 (canonical -> 1; A1/A2/A3 pruned).
    // 3. Deliver A3 (height 3) as a FinalizedBlock while canonical is 1.
    // 4. The strict guard rejects it (3 != 1 + 1) and triggers coordinated
    //    shutdown; canonical never advances to 3.

    let cfg = deterministic::Config::default().with_seed(51);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x51u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        // Hold a clone so we can observe the coordinated shutdown the guard triggers.
        let cancellation_token = CancellationToken::new();
        let token = cancellation_token.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_finalized_dead_fork_out_of_sequence".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

            page_cache: CacheRef::from_pooler(
                &context,
                std::num::NonZero::new(4096).unwrap(),
                NZUsize!(100),
            ),
            genesis_hash,
            initial_state,
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token,
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Losing fork A1 -> A2 -> A3.
        let block_a1 = create_test_block(genesis_digest, 1, 2, 9001);
        let block_a1_digest = block_a1.digest();
        let block_a2 = create_test_block(block_a1_digest, 2, 3, 9002);
        let block_a2_digest = block_a2.digest();
        let block_a3 = create_test_block(block_a2_digest, 3, 4, 9003);
        // Conflicting winner B1 at height 1.
        let block_b1 = create_test_block(genesis_digest, 1, 5, 9004);
        assert_ne!(block_a1_digest, block_b1.digest());

        mailbox
            .report(Update::NotarizedBlock(block_a1.clone()))
            .await;
        mailbox
            .report(Update::NotarizedBlock(block_a2.clone()))
            .await;
        mailbox
            .report(Update::NotarizedBlock(block_a3.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Finalize the conflicting ancestor B1; this prunes the A-fork and
        // advances canonical to height 1.
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block_b1.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(mailbox.get_latest_height().await, 1);
        assert!(
            !token.is_cancelled(),
            "finalizer must still be running after a normal sequential finalization"
        );

        // Deliver the pruned descendant A3 (height 3) as a finalized block while
        // canonical is only at height 1. The strict guard must reject it.
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block_a3.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert!(
            token.is_cancelled(),
            "an out-of-sequence finalized block (height 3 while canonical is 1) \
             must trigger coordinated shutdown rather than execute onto canonical state"
        );

        context.auditor().state()
    });
}

#[test]
fn test_orphaned_blocks_pruned_after_finalization() {
    // Test that orphaned_blocks at or below the finalized height are pruned.
    //
    // Scenario:
    // 1. Send orphaned block at height 3 (parent unknown)
    // 2. Finalize a block at height 3
    // 3. The orphaned block should be pruned
    // 4. When the "parent" later arrives, the orphan should NOT be processed

    let cfg = deterministic::Config::default().with_seed(46);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x46u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_prune_orphans".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Create the canonical chain: genesis -> block1 -> block2 -> block3
        let block1 = create_test_block(genesis_digest, 1, 2, 5001);
        let block1_digest = block1.digest();

        let block2 = create_test_block(block1_digest, 2, 3, 5002);
        let block2_digest = block2.digest();

        let block3 = create_test_block(block2_digest, 3, 4, 5003);

        // Create an orphaned block at height 3 with unknown parent
        let unknown_parent: Digest = [0xAAu8; 32].into();
        let orphan_block = create_test_block(unknown_parent, 3, 4, 5004);
        let orphan_digest = orphan_block.digest();

        // Send the orphan first (goes to orphaned_blocks)
        mailbox
            .report(Update::NotarizedBlock(orphan_block.clone()))
            .await;
        context.sleep(Duration::from_millis(50)).await;

        // Finalize blocks 1, 2, 3 on the canonical chain
        let (ack1, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack1))
            .await;
        let (ack2, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block2.clone(), None), ack2))
            .await;
        let (ack3, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block3.clone(), None), ack3))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Canonical height should be 3
        assert_eq!(mailbox.get_latest_height().await, 3);

        // The orphan at height 3 should have been pruned.
        // notify_at_height for the orphan should return false (outdated height)
        let notify_orphan = mailbox.notify_at_height(3, orphan_digest).await;
        let result = notify_orphan.await.unwrap();
        assert!(
            !result,
            "Orphan digest should not match canonical at height 3"
        );

        context.auditor().state()
    });
}

#[test]
fn test_fork_state_reused_when_notarized_then_finalized() {
    // Test that when a block is first notarized (added to fork_states) and then
    // finalized, the existing fork state is reused and the block becomes canonical.
    //
    // Scenario:
    // 1. Send block1 as notarized (goes to fork_states)
    // 2. Verify block1 is in fork_states
    // 3. Send block1 as finalized
    // 4. Verify block1 is now canonical and fork_states is properly updated

    let cfg = deterministic::Config::default().with_seed(47);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x47u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_reuse".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Create block1
        let block1 = create_test_block(genesis_digest, 1, 2, 6001);
        let block1_digest = block1.digest();

        // Step 1: Send as notarized
        mailbox.report(Update::NotarizedBlock(block1.clone())).await;
        context.sleep(Duration::from_millis(100)).await;

        // Step 2: Verify it's in fork_states
        let notify1 = mailbox.notify_at_height(1, block1_digest).await;
        assert!(
            notify1.await.unwrap(),
            "Block 1 should be in fork_states after notarization"
        );

        // Canonical height should still be 0 (genesis)
        assert_eq!(
            mailbox.get_latest_height().await,
            0,
            "Canonical height should be 0 before finalization"
        );

        // Step 3: Now finalize the same block
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Step 4: Verify block1 is now canonical
        assert_eq!(
            mailbox.get_latest_height().await,
            1,
            "Canonical height should be 1 after finalization"
        );

        // notify_at_height should still return true (now canonical)
        let notify1_after = mailbox.notify_at_height(1, block1_digest).await;
        assert!(
            notify1_after.await.unwrap(),
            "Block 1 should be accessible after finalization"
        );

        context.auditor().state()
    });
}

#[test]
fn test_competing_fork_pruned_on_finalization() {
    // Test that when one fork is finalized, competing forks at the same height
    // are pruned from fork_states.
    //
    // Scenario:
    // 1. Create two competing blocks at height 1 (block1a, block1b)
    // 2. Both are notarized and in fork_states
    // 3. Finalize block1a
    // 4. block1b should be pruned from fork_states

    let cfg = deterministic::Config::default().with_seed(48);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x48u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_compete".to_string(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },

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
            observer_domain: Vec::new(),
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
        let genesis_digest = genesis_block.digest();

        // Two competing blocks at height 1
        let block1a = create_test_block(genesis_digest, 1, 2, 7001);
        let block1a_digest = block1a.digest();

        let block1b = create_test_block(genesis_digest, 1, 2, 7002);
        let block1b_digest = block1b.digest();

        assert_ne!(
            block1a_digest, block1b_digest,
            "Blocks should have different digests"
        );

        // Both notarized
        mailbox
            .report(Update::NotarizedBlock(block1a.clone()))
            .await;
        mailbox
            .report(Update::NotarizedBlock(block1b.clone()))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Both should be in fork_states
        let notify1a = mailbox.notify_at_height(1, block1a_digest).await;
        let notify1b = mailbox.notify_at_height(1, block1b_digest).await;
        assert!(notify1a.await.unwrap(), "Block 1a should be in fork_states");
        assert!(notify1b.await.unwrap(), "Block 1b should be in fork_states");

        // Finalize block1a
        let (ack, _waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block1a.clone(), None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // block1a should be canonical
        assert_eq!(mailbox.get_latest_height().await, 1);

        let notify1a_after = mailbox.notify_at_height(1, block1a_digest).await;
        assert!(
            notify1a_after.await.unwrap(),
            "Block 1a should be canonical"
        );

        // block1b should no longer match (height 1 is finalized with different digest)
        let notify1b_after = mailbox.notify_at_height(1, block1b_digest).await;
        assert!(
            !notify1b_after.await.unwrap(),
            "Block 1b should not match canonical at height 1"
        );

        context.auditor().state()
    });
}
