//! Tests for validator lifecycle: exit, removal from committee, etc.

use super::mocks::{MockEngineClient, MockNetworkOracle, create_test_schemes, make_finalization};
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
fn test_validator_exit_triggers_cancellation() {
    // Test that when this node is removed from the validator set, the cancellation
    // token is triggered at the first block of the next epoch.
    //
    // Flow:
    // 1. Node is in removed_validators in initial state
    // 2. At epoch boundary, update_validator_committee sets validator_exit = true
    // 3. At first block of next epoch, cancellation triggers

    let cfg = deterministic::Config::default().with_seed(56);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x56u8; 32];
        let node_key = ed25519::PrivateKey::from_seed(0);
        let node_pubkey = node_key.public_key();

        // Create initial state with the node marked for removal
        let mut initial_state = create_test_initial_state(genesis_hash);
        initial_state.removed_validators.push(node_pubkey.clone());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let epoch_num_of_blocks = 5;
        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            archive_mode: false,
            mailbox_size: 100,
            db_prefix: "test_exit".to_string(),
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
            node_public_key: node_pubkey,
            cancellation_token,
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

        // Token should not be cancelled yet
        assert!(
            !token_clone.is_cancelled(),
            "Token should not be cancelled initially"
        );

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        // Create BLS signing schemes for finalization certificates
        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Finalize blocks 1-3 (epoch 0 with epoch_num_of_blocks = 5)
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

        // Token still should not be cancelled
        assert!(
            !token_clone.is_cancelled(),
            "Token should not be cancelled before epoch boundary"
        );

        // Finalize block 4 (last block of epoch 0)
        // This triggers update_validator_committee which sets validator_exit = true
        // The last block of an epoch requires a finalization certificate
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 13004, 0);
        let block4_digest = block4.digest();
        parent_digest = block4_digest;
        let finalization4 = make_finalization(block4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Token still should not be cancelled (we're at block 4, not first of new epoch)
        assert!(
            !token_clone.is_cancelled(),
            "Token should not be cancelled at epoch boundary"
        );

        // Finalize block 5 (first block of epoch 1)
        // This should trigger the cancellation
        let block5 = create_test_block_with_epoch(parent_digest, 5, 6, 13005, 1);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block5, None), ack))
            .await;
        context.sleep(Duration::from_millis(100)).await;

        // Now the token should be cancelled
        assert!(
            token_clone.is_cancelled(),
            "Token should be cancelled at first block of new epoch after validator exit"
        );

        context.auditor().state()
    });
}
