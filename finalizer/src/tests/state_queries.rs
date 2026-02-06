//! Tests for finalizer state query methods.

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
use std::collections::{BTreeMap, VecDeque};
use std::marker::PhantomData;
use std::time::Duration;
use summit_syncer::Update;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::consensus_state::ConsensusState;
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
        epoch,
        view,
        None,
        [0u8; 32].into(),
        Vec::new(),
        Vec::new(),
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
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 0,
        };

        let key_bytes: [u8; 32] = node_pubkey.as_ref().try_into().unwrap();
        validator_accounts.insert(key_bytes, account);
    }

    ConsensusState {
        epoch: 0,
        view: 0,
        latest_height: 0,
        head_digest: genesis_hash.into(),
        next_withdrawal_index: 0,
        deposit_queue: VecDeque::new(),
        withdrawal_queue: BTreeMap::new(),
        validator_accounts,
        protocol_param_changes: Vec::new(),
        pending_checkpoint: None,
        added_validators: BTreeMap::new(),
        removed_validators: Vec::new(),
        pending_execution_requests: Vec::new(),
        forkchoice: ForkchoiceState {
            head_block_hash: genesis_hash.into(),
            safe_block_hash: genesis_hash.into(),
            finalized_block_hash: genesis_hash.into(),
        },
        epoch_genesis_hash: genesis_hash,
        validator_minimum_stake: 32_000_000_000,
        validator_maximum_stake: 64_000_000_000,
    }
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
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let epoch_num_of_blocks = 5;

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_epoch".to_string(),
            engine_client: MockEngineClient,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: ProtocolConsts {
                epoch_num_of_blocks,
                validator_onboarding_limit_per_block: 10,
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
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

        // Finalize block 4 (last block of epoch 0, triggers epoch change to 1)
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 10004, 0);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, None), ack))
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
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let epoch_num_of_blocks = 5;

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_epoch_hash".to_string(),
            engine_client: MockEngineClient,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: ProtocolConsts {
                epoch_num_of_blocks,
                validator_onboarding_limit_per_block: 10,
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
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

        // Finalize block 4 (last block of epoch 0, triggers epoch change)
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 12004, 0);
        let block4_digest = block4.digest();
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, None), ack))
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
fn test_get_aux_data_from_canonical_chain() {
    // Test that get_aux_data returns correct data when building on the canonical chain.

    let cfg = deterministic::Config::default().with_seed(54);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x54u8; 32];
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_aux_data".to_string(),
            engine_client: MockEngineClient,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: ProtocolConsts {
                epoch_num_of_blocks: 10,
                validator_onboarding_limit_per_block: 10,
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
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
        let initial_state = create_test_initial_state(genesis_hash);

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let node_key = ed25519::PrivateKey::from_seed(0);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_aux_invalid".to_string(),
            engine_client: MockEngineClient,
            oracle: MockNetworkOracle,
            orchestrator_mailbox,
            protocol_consts: ProtocolConsts {
                epoch_num_of_blocks: 10,
                validator_onboarding_limit_per_block: 10,
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
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
