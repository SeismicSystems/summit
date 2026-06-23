//! Tests for finalizer state query methods.

use super::mocks::{MockEngineClient, MockNetworkOracle, create_test_schemes, make_finalization};
use crate::actor::Finalizer;
use crate::config::{FinalizerConfig, ProtocolConsts};
use alloy_primitives::{Address, U256};
use alloy_rpc_types_engine::{
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkchoiceState,
};
use commonware_consensus::Reporter;
use commonware_consensus::types::Epoch;
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
use summit_types::checkpoint::Checkpoint;
use summit_types::consensus_state::ConsensusState;
use summit_types::ssz_tree_key::SszStateKey;
use summit_types::utils::is_penultimate_block_of_epoch;
use summit_types::{Block, Digest};
use tokio_util::sync::CancellationToken;

/// Helper to create a test block with specific parent, height, and epoch
fn create_test_block_with_epoch(
    parent_digest: Digest,
    height: u64,
    view: u64,
    unique_seed: u64,
    epoch: u64,
) -> Block {
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
        epoch,
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

fn mirror_empty_block_execution_for_root(state: &mut ConsensusState, block: &Block) {
    state.set_forkchoice_head(block.eth_block_hash().into());
    state.set_latest_height(block.height());
    state.set_view(block.view());
    state.set_head_digest(block.digest());

    if is_penultimate_block_of_epoch(state.get_epocher(), block.height()) {
        state.set_pending_checkpoint(Some(Checkpoint::new(state)));
    }

    state.set_forkchoice_safe_and_finalized(state.get_forkchoice().head_block_hash);
    state.capture_state_root(block.payload.payload_inner.payload_inner.block_number);
}

fn mirror_epoch_boundary_finalization_for_root(state: &mut ConsensusState, block: &Block) {
    let _stake_changed = state.apply_protocol_parameter_changes();
    let _checkpoint = state.take_pending_checkpoint();

    let next_epoch = state.get_epoch() + 1;
    state.set_epoch(next_epoch);
    state.get_epocher().advance_epoch(Epoch::new(next_epoch));
    state.set_epoch_genesis_hash(block.digest().0);
    state.reset_pending_active_validator_exits();

    state.remove_added_validators_for_epoch(next_epoch);
    if state.has_removed_validators() {
        state.clear_removed_validators();
    }

    // Mirror the finalizer's post-cleanup re-capture. capture_state_root rebinds
    // the dynamic-epoch-schedule leaf (the epocher just advanced) before freezing
    // the root, so comparing get_state_root() against a raw ssz_tree().root()
    // would diverge on that leaf.
    state.capture_state_root(block.payload.payload_inner.payload_inner.block_number);
}

#[test]
fn test_generate_state_proof_preserves_batch_cardinality_for_missing_keys() {
    let cfg = deterministic::Config::default().with_seed(56);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x56u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_state_proof_cardinality".to_string(),
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
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let requested_keys = vec![
            SszStateKey::Scalar(summit_types::ssz_state_tree::EPOCH),
            SszStateKey::Deposit(0),
            SszStateKey::Scalar(summit_types::ssz_state_tree::LATEST_HEIGHT),
        ];
        let (root, _el_block_number, proofs) =
            mailbox.generate_state_proof(requested_keys.clone()).await;

        assert_eq!(
            proofs.len(),
            requested_keys.len(),
            "state proof batches must preserve one response slot per requested key"
        );
        assert!(
            proofs[0]
                .as_ref()
                .expect("first response slot should contain the epoch proof")
                .verify(&root),
            "first response slot should contain the epoch proof"
        );
        assert!(
            proofs[1].is_none(),
            "second response slot should mark the missing deposit proof"
        );
        assert!(
            proofs[2]
                .as_ref()
                .expect("third response slot should contain the latest_height proof")
                .verify(&root),
            "third response slot should contain the latest_height proof"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_latest_epoch() {
    // Test that get_latest_epoch returns the correct epoch as blocks are finalized.
    //
    // With epoch_num_of_blocks = 5:
    // - is_last_block_of_epoch(5, h) = (h % 5 == 4)
    // - Block 4 is last block of epoch 0, block 9 is last block of epoch 1, etc.

    let cfg = deterministic::Config::default().with_seed(51);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x51u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_epoch".to_string(),
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

        // Initial epoch should be 0
        assert_eq!(
            mailbox.get_latest_epoch().await,
            0,
            "Initial epoch should be 0"
        );

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        // Finalize blocks 1, 2, 3 (still in epoch 0, block 4 is the boundary)
        // With epoch_num_of_blocks = 5, blocks 0-4 are epoch 0
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 10000 + height, 0);
            parent_digest = block.digest();

            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        // Still epoch 0 (blocks 1-3 finalized)
        assert_eq!(
            mailbox.get_latest_epoch().await,
            0,
            "Should still be epoch 0 before block 4"
        );

        // Create BLS signing schemes for finalization certificates
        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Finalize block 4 (last block of epoch 0, triggers epoch change to 1)
        // The last block of an epoch requires a finalization certificate
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 10004, 0);
        let block4_digest = block4.digest();
        let finalization4 = make_finalization(block4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Now should be epoch 1
        assert_eq!(
            mailbox.get_latest_epoch().await,
            1,
            "Should be epoch 1 after block 4 (last of epoch 0)"
        );

        context.auditor().state()
    });
}

/// Regression: after finalizing an epoch-terminal block at a view greater than 1
/// and transitioning to the next epoch, the persisted consensus view (which seeds
/// the syncer's round floor on restart) must be reset to the new epoch's genesis
/// view (0), not carried over as the previous epoch's terminal view. Otherwise a
/// restarted node seeds the floor at (next_epoch, terminal_view) and treats the
/// new epoch's early rounds as past work, dropping their block subscriptions.
///
/// The test finalizes through an epoch boundary (terminal block at view 5), then
/// restarts the finalizer from the same database and asserts the reloaded state's
/// view is 0. `get_epoch() == 1` also confirms the reload actually read the
/// persisted post-boundary state.
#[test]
fn test_epoch_boundary_resets_persisted_view() {
    let cfg = deterministic::Config::default().with_seed(77);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x77u8; 32];
        let db_prefix = "test_epoch_boundary_view_reset".to_string();
        let node_key = ed25519::PrivateKey::from_seed(0);
        let cancel = CancellationToken::new();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: db_prefix.clone(),
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
            initial_state: create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap()),
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: cancel.clone(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        // Finalize blocks 1..3 (epoch 0), then the terminal block 4 at view 5 with
        // a finalization certificate, which transitions to epoch 1.
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 20000 + height, 0);
            parent_digest = block.digest();
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;
        // Terminal block of epoch 0 at view 5 (> 1).
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 20004, 0);
        let block4_digest = block4.digest();
        let finalization4 = make_finalization(block4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(
            mailbox.get_latest_epoch().await,
            1,
            "should have transitioned to epoch 1"
        );

        // Restart: stop the running finalizer via its cancellation token so its
        // run loop breaks and drops the state journal, then re-create it from the
        // same db_prefix to reload the persisted state. The mailbox is kept alive
        // (not dropped) so the run loop exits on cancellation rather than panicking
        // on a closed mailbox.
        cancel.cancel();
        context.sleep(Duration::from_millis(200)).await;

        let reload_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix,
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
            initial_state: create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap()),
            protocol_version: 1,
            node_public_key: node_key.public_key(),
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };
        let (_finalizer2, reloaded_state, _mailbox2, _state_query2) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer_reloaded"),
                reload_cfg,
            )
            .await;

        assert_eq!(
            reloaded_state.get_epoch(),
            1,
            "reload should have read the persisted post-boundary state (epoch 1)"
        );
        assert_eq!(
            reloaded_state.get_view(),
            0,
            "persisted view must reset to the new epoch's genesis view (0), not the \
             terminal block's view (5)"
        );

        context.auditor().state()
    });
}

#[test]
fn test_first_post_epoch_boundary_aux_data_uses_post_transition_state_root() {
    // The first block after an epoch boundary must advertise the state root after
    // the finalized boundary block's epoch-transition mutations have been applied.
    let cfg = deterministic::Config::default().with_seed(56);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x56u8; 32];
        let epoch_length = NonZeroU64::new(5).unwrap();
        let initial_state = create_test_initial_state(genesis_hash, epoch_length);
        let mut expected_state = initial_state.clone();

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_post_boundary_aux_root".to_string(),
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
        let mut parent_digest = genesis_block.digest();

        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 13000 + height, 0);
            parent_digest = block.digest();
            mirror_empty_block_execution_for_root(&mut expected_state, &block);

            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;

        let boundary_block = create_test_block_with_epoch(parent_digest, 4, 5, 13004, 0);
        let boundary_digest = boundary_block.digest();
        mirror_empty_block_execution_for_root(&mut expected_state, &boundary_block);
        let pre_transition_root = expected_state.get_state_root();
        mirror_epoch_boundary_finalization_for_root(&mut expected_state, &boundary_block);
        let expected_post_transition_root = expected_state.get_state_root();

        assert_ne!(
            pre_transition_root, expected_post_transition_root,
            "test setup must produce a root-changing epoch transition"
        );

        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock(
                (boundary_block, Some(finalization)),
                ack,
            ))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        assert_eq!(
            mailbox.get_latest_epoch().await,
            1,
            "boundary block should advance the canonical epoch"
        );

        let aux_data = mailbox
            .get_aux_data(5, boundary_digest)
            .await
            .await
            .unwrap()
            .expect("first post-boundary block should receive aux data");

        assert_eq!(
            aux_data.epoch, 1,
            "aux data should be for the first block of the new epoch"
        );
        assert_eq!(
            aux_data.state_root, expected_post_transition_root,
            "first post-boundary aux data must use the post-transition consensus state root"
        );

        context.auditor().state()
    });
}

#[test]
fn test_epoch_boundary_post_transition_root_survives_restart() {
    // The re-capture of the post-transition root must happen BEFORE the boundary
    // consensus state is persisted, so a node that restarts at the epoch boundary
    // reloads the same post-transition root it advertised live. If the persist ran
    // before the re-capture, the durable root would be the stale pre-transition
    // snapshot and a restarted node would disagree with peers on the first
    // post-boundary block's parent_beacon_block_root.
    let cfg = deterministic::Config::default().with_seed(60);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x60u8; 32];
        let db_prefix = "test_recapture_root_survives_restart".to_string();
        let node_key = ed25519::PrivateKey::from_seed(0);
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );
        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: db_prefix.clone(),
            engine_client: MockEngineClient::new(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
            page_cache: page_cache.clone(),
            genesis_hash,
            initial_state: initial_state.clone(),
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
        let handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 60000 + height, 0);
            parent_digest = block.digest();
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let boundary = create_test_block_with_epoch(parent_digest, 4, 5, 60004, 0);
        let boundary_digest = boundary.digest();
        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Live post-transition root advertised to the first block of the new epoch.
        let live_post_transition_root = mailbox
            .get_aux_data(5, boundary_digest)
            .await
            .await
            .unwrap()
            .expect("first post-boundary block should receive aux data")
            .state_root;

        drop(mailbox);
        handle.abort();
        context.sleep(Duration::from_millis(50)).await;

        // Restart from the same DB. The reloaded consensus state must expose the
        // same post-transition root, proving it was persisted post re-capture.
        let (restarted, reloaded_state, _mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer_restart"),
                FinalizerConfig {
                    mailbox_size: 100,
                    db_prefix,
                    engine_client: MockEngineClient::new(),
                    oracle: MockNetworkOracle,
                    protocol_consts: ProtocolConsts {
                        validator_num_warm_up_epochs: 2,
                        validator_withdrawal_num_epochs: 2,
                    },
                    page_cache,
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
                },
            )
            .await;
        drop(restarted);

        assert_eq!(
            reloaded_state.get_epoch(),
            1,
            "restarted finalizer must load the persisted next-epoch state"
        );
        assert_eq!(
            reloaded_state.get_state_root(),
            live_post_transition_root,
            "persisted post-transition root must match the live root advertised at the boundary"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_epoch_genesis_hash() {
    // Test that get_epoch_genesis_hash returns the correct hash for the current epoch.
    //
    // The epoch genesis hash is the hash of the last block of the previous epoch.
    // For epoch 0, it's the genesis hash. After epoch transition, it becomes
    // the digest of the last block of the previous epoch.

    let cfg = deterministic::Config::default().with_seed(53);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x53u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_epoch_hash".to_string(),
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

        // In epoch 0, the epoch genesis hash should be the genesis hash
        let epoch0_hash = mailbox.get_epoch_genesis_hash(0).await.await.unwrap();
        assert_eq!(
            epoch0_hash, genesis_hash,
            "Epoch 0 genesis hash should be the genesis hash"
        );

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        // Finalize blocks 1-3 (epoch 0 with epoch_num_of_blocks = 5)
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 12000 + height, 0);
            parent_digest = block.digest();

            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        // Create BLS signing schemes for finalization certificates
        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Finalize block 4 (last block of epoch 0, triggers epoch change)
        // The last block of an epoch requires a finalization certificate
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 12004, 0);
        let block4_digest = block4.digest();
        let finalization4 = make_finalization(block4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Now in epoch 1, the epoch genesis hash should be block4's digest
        let epoch1_hash = mailbox.get_epoch_genesis_hash(1).await.await.unwrap();
        assert_eq!(
            epoch1_hash, block4_digest.0,
            "Epoch 1 genesis hash should be block 4's digest"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_epoch_genesis_hash_for_past_epoch() {
    // Regression: after advancing past an epoch, a GetEpochGenesisHash request for that
    // past epoch must return that epoch's genesis — NOT the current epoch's. (A stale
    // Enter(epoch) drained after the finalizer advanced asks for its own epoch's genesis;
    // serving the current one would root an old-epoch engine in the wrong digest.)
    let cfg = deterministic::Config::default().with_seed(354);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x57u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_epoch_hash_past".to_string(),
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

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        // Epoch 0: blocks 1-3, then block 4 (last of epoch 0, with finalization) -> epoch 1.
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 13000 + height, 0);
            parent_digest = block.digest();
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 13004, 0);
        let epoch1_genesis = block4.digest(); // genesis of epoch 1 == last block of epoch 0
        let finalization4 = make_finalization(epoch1_genesis, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;
        parent_digest = epoch1_genesis;
        assert_eq!(mailbox.get_latest_epoch().await, 1, "should be epoch 1");

        // Epoch 1: blocks 5-8, then block 9 (last of epoch 1, with finalization) -> epoch 2.
        for height in 5..9 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 13000 + height, 1);
            parent_digest = block.digest();
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }
        let block9 = create_test_block_with_epoch(parent_digest, 9, 10, 13009, 1);
        let epoch2_genesis = block9.digest(); // genesis of epoch 2 == last block of epoch 1
        let finalization9 = make_finalization(epoch2_genesis, 9, 8, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block9, Some(finalization9)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(mailbox.get_latest_epoch().await, 2, "should be epoch 2");

        // Current epoch (2) genesis is the last block of epoch 1 (fast path, works today).
        assert_eq!(
            mailbox.get_epoch_genesis_hash(2).await.await.unwrap(),
            epoch2_genesis.0,
            "current-epoch genesis must be the last block of the previous epoch"
        );

        // A request for the PAST epoch (1) must still return block 4 — not the current
        // epoch's genesis. Today the finalizer returns the current canonical genesis here.
        assert_eq!(
            mailbox.get_epoch_genesis_hash(1).await.await.unwrap(),
            epoch1_genesis.0,
            "a request for a past epoch must return that epoch's genesis, not the current one"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_epoch_genesis_hash_for_future_epoch() {
    // A request for an epoch the finalizer has NOT reached has no correct genesis, so it
    // must be declined (the response is dropped, surfacing as an error to the caller)
    // rather than answered with the current canonical genesis — which would root consensus
    // in the wrong digest.
    //
    // Written as the intended behavior: red today (the finalizer returns
    // canonical_state.get_epoch_genesis_hash() for any epoch), green once a request above
    // the current epoch is declined.
    let cfg = deterministic::Config::default().with_seed(355);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x58u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_epoch_hash_future".to_string(),
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

        // Finalizer is at epoch 0; epoch 5 has not been reached.
        assert_eq!(mailbox.get_latest_epoch().await, 0);
        let res = mailbox.get_epoch_genesis_hash(5).await.await;
        assert!(
            res.is_err(),
            "a request for a future (not-yet-reached) epoch must be declined, not answered \
             with the current genesis; got {res:?}"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_aux_data_from_canonical_chain() {
    // Test that get_aux_data returns correct data when building on the canonical chain.

    let cfg = deterministic::Config::default().with_seed(54);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x54u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_aux_data".to_string(),
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

        // Request aux data for height 1, with parent = genesis
        let aux_data = mailbox.get_aux_data(1, genesis_digest).await.await.unwrap();

        assert!(
            aux_data.is_some(),
            "Aux data should be returned for valid parent"
        );
        let aux_data = aux_data.unwrap();

        // For non-epoch-boundary blocks, withdrawals should be empty
        assert!(
            aux_data.withdrawals.is_empty(),
            "Withdrawals should be empty for non-boundary block"
        );

        context.auditor().state()
    });
}

#[test]
fn test_get_aux_data_returns_none_for_invalid_parent() {
    // Test that get_aux_data returns None when the parent doesn't connect to any fork
    // or the canonical chain.

    let cfg = deterministic::Config::default().with_seed(55);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x55u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(10).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_aux_invalid".to_string(),
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

        // Request aux data with an invalid parent digest
        let invalid_parent: Digest = [0xFFu8; 32].into();
        let aux_data = mailbox.get_aux_data(1, invalid_parent).await.await.unwrap();

        assert!(
            aux_data.is_none(),
            "Aux data should be None for invalid parent"
        );

        context.auditor().state()
    });
}
