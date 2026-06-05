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
use futures::{StreamExt as _, channel::mpsc as futures_mpsc};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use summit_syncer::Update;
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::consensus_state::ConsensusState;
use summit_types::header::AddedValidator;
use summit_types::network_oracle::NetworkOracle;
use summit_types::{Block, Digest, PublicKey};
use tokio_util::sync::CancellationToken;

/// Helper to create a test block with specific parent, height, and epoch
fn create_test_block_with_epoch(
    parent_digest: Digest,
    height: u64,
    view: u64,
    unique_seed: u64,
    epoch: u64,
) -> Block {
    create_test_block_with_requests(parent_digest, height, view, unique_seed, epoch, Vec::new())
}

/// Helper to create a test block with execution requests attached.
fn create_test_block_with_requests(
    parent_digest: Digest,
    height: u64,
    view: u64,
    unique_seed: u64,
    epoch: u64,
    execution_requests: Vec<alloy_primitives::Bytes>,
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
        execution_requests,
        epoch,
        view,
        None,
        [0u8; 32].into(),
        Vec::new(),
        Vec::new(),
        [0u8; 32],
    )
}

/// Encode a full-exit withdrawal request as a type-0x01 EIP-7685 entry.
fn full_exit_withdrawal_entry(
    validator_pubkey: [u8; 32],
    withdrawal_address: Address,
) -> alloy_primitives::Bytes {
    use commonware_codec::Write as _;
    use summit_types::execution_request::WithdrawalRequest;
    let withdrawal = WithdrawalRequest {
        source_address: withdrawal_address,
        validator_pubkey,
        // Summit ignores the request amount and pays out the full balance;
        // we use 0 to make the intent ("full exit") explicit.
        amount: 0,
    };
    let mut entry = vec![0x01u8];
    withdrawal.write(&mut entry);
    entry.into()
}

/// Encode a MaximumStake protocol-param change as a type-0xFF EIP-7685 entry.
/// Layout: 0xFF | param_id(0x01 = MaximumStake) | length(8) | value (LE u64).
fn maximum_stake_protocol_param_entry(new_max_stake: u64) -> alloy_primitives::Bytes {
    let mut entry = vec![0xFFu8, 0x01u8, 8u8];
    entry.extend_from_slice(&new_max_stake.to_le_bytes());
    entry.into()
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
fn test_checkpoint_restart_keeps_submitted_exit_request_validator_in_current_epoch_committee() {
    let cfg = deterministic::Config::default().with_seed(58);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x58u8; 32];
        let node_key = ed25519::PrivateKey::from_seed(0);
        let exiting_node_key = ed25519::PrivateKey::from_seed(1);
        let exiting_node_pubkey = exiting_node_key.public_key();
        let exiting_pubkey_bytes: [u8; 32] = exiting_node_pubkey.as_ref().try_into().unwrap();

        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());
        let mut exiting_account = initial_state
            .get_account(&exiting_pubkey_bytes)
            .expect("test state must contain the exiting validator")
            .clone();
        exiting_account.status = ValidatorStatus::SubmittedExitRequest;
        exiting_account.balance = 0;
        exiting_account.has_pending_withdrawal = true;
        initial_state.set_account(exiting_pubkey_bytes, exiting_account);
        initial_state.push_removed_validator(exiting_node_pubkey.clone());

        let (orchestrator_tx, mut orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_checkpoint_restart_keeps_exiting_validator".to_string(),
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

        let (finalizer, _state, _mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);

        let enter = orchestrator_rx
            .next()
            .await
            .expect("finalizer must publish the initial epoch transition");
        let summit_orchestrator::Message::Enter(transition) = enter else {
            panic!("expected the initial finalizer message to enter the current epoch");
        };

        let committee_keys: Vec<_> = transition
            .validator_keys
            .iter()
            .map(|(node_key, _)| node_key.clone())
            .collect();

        assert!(
            committee_keys.contains(&exiting_node_pubkey),
            "SubmittedExitRequest validators remain current-epoch signers until the boundary"
        );
        assert_eq!(
            committee_keys.len(),
            4,
            "checkpoint restart must preserve the full current-epoch committee"
        );

        context.auditor().state()
    });
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
        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());
        initial_state.push_removed_validator(node_pubkey.clone());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_exit".to_string(),
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
            node_public_key: node_pubkey,
            cancellation_token,
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
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

/// An active validator's full exit on the last block of an epoch must
/// dominate a concurrent `MaximumStake` reduction at the same boundary:
/// the buffered exit replays on the first block of the next epoch and the
/// validator transitions to `SubmittedExitRequest` with balance zeroed,
/// rather than being clipped to the new maximum by stake-bound enforcement.
#[test]
fn last_block_exit_dominates_concurrent_max_stake_reduction() {
    let cfg = deterministic::Config::default().with_seed(57);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x57u8; 32];

        let local_node_key = ed25519::PrivateKey::from_seed(1);
        let local_node_pubkey = local_node_key.public_key();
        let exiting_node_key = ed25519::PrivateKey::from_seed(0);
        let exiting_node_pubkey = exiting_node_key.public_key();
        let exiting_pubkey_bytes: [u8; 32] = exiting_node_pubkey.as_ref().try_into().unwrap();
        let exiting_withdrawal_address = Address::from([0u8; 20]);
        let initial_balance: u64 = 32_000_000_000;
        let reduced_max_stake: u64 = initial_balance - 1_000_000_000;

        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let cancellation_token = CancellationToken::new();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_last_block_exit_dominates_max_stake".to_string(),
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
            node_public_key: local_node_pubkey,
            cancellation_token,
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Block 1: empty.
        let b1 = create_test_block_with_epoch(parent_digest, 1, 2, 18001, 0);
        parent_digest = b1.digest();
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b1, None), ack))
            .await;
        context.sleep(Duration::from_millis(30)).await;

        // Block 2: queue MaximumStake reduction (activates at the epoch boundary).
        let b2 = create_test_block_with_requests(
            parent_digest,
            2,
            3,
            18002,
            0,
            vec![maximum_stake_protocol_param_entry(reduced_max_stake)],
        );
        parent_digest = b2.digest();
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b2, None), ack))
            .await;
        context.sleep(Duration::from_millis(30)).await;

        // Block 3: empty (penultimate of epoch 0).
        let b3 = create_test_block_with_epoch(parent_digest, 3, 4, 18003, 0);
        parent_digest = b3.digest();
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b3, None), ack))
            .await;
        context.sleep(Duration::from_millis(30)).await;

        // Block 4 (LAST of epoch 0): full exit for the exiting validator.
        let b4 = create_test_block_with_requests(
            parent_digest,
            4,
            5,
            18004,
            0,
            vec![full_exit_withdrawal_entry(
                exiting_pubkey_bytes,
                exiting_withdrawal_address,
            )],
        );
        let b4_digest = b4.digest();
        parent_digest = b4_digest;
        let finalization4 = make_finalization(b4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(50)).await;

        // Block 5 (first of epoch 1): the buffered exit replays.
        let b5 = create_test_block_with_epoch(parent_digest, 5, 6, 18005, 1);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b5, None), ack))
            .await;
        context.sleep(Duration::from_millis(50)).await;

        let account = mailbox
            .get_validator_account(exiting_node_pubkey.clone())
            .await
            .expect("exiting validator account must still exist after the deferred exit replays");

        assert_eq!(
            account.status,
            ValidatorStatus::SubmittedExitRequest,
            "full exit must take effect on replay; validator should be in SubmittedExitRequest"
        );
        assert_eq!(
            account.balance, 0,
            "full exit must zero the balance, not leave it clipped to {reduced_max_stake} gwei"
        );
        assert!(
            account.has_pending_withdrawal,
            "the full-exit withdrawal must be scheduled"
        );

        context.auditor().state()
    });
}

/// A `NetworkOracle` that records every `track` call so a test can assert
/// exactly which keys the finalizer advertises to the P2P/observer layer
/// for each epoch.
#[derive(Clone, Default)]
struct RecordingOracle {
    tracks: Arc<Mutex<Vec<(u64, Vec<PublicKey>)>>>,
}

impl NetworkOracle<PublicKey> for RecordingOracle {
    async fn track(&mut self, index: u64, primary: Vec<PublicKey>, _secondary: Vec<PublicKey>) {
        self.tracks.lock().unwrap().push((index, primary));
    }
}

/// Regression test for the joining-validator withdrawal cancellation path.
///
/// A validator that has processed a new-validator deposit but is still in its
/// warm-up window (`status == Joining`, `joining_epoch > current_epoch`)
/// submits a valid full withdrawal before activation. The finalizer must both
/// cancel the pending activation AND flip the account out of `Joining`, so the
/// canceled validator is excluded from the active-or-joining set advertised to
/// the network oracle at the next epoch transition (and therefore from its
/// derived observer keys) — while its withdrawal record stays processable.
///
/// Before #187, the cancellation branch left the zero-balance account as
/// `Joining`, so `get_active_or_joining_validators()` kept returning it and the
/// finalizer tracked its primary + observer keys for an epoch it would never
/// enter.
#[test]
fn joining_validator_withdrawal_excludes_it_from_oracle_tracking() {
    let cfg = deterministic::Config::default().with_seed(59);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x59u8; 32];

        // Local node is an existing active validator (seed 0); it is never
        // removed, so the finalizer keeps running across the epoch boundary.
        let node_key = ed25519::PrivateKey::from_seed(0);
        let node_pubkey = node_key.public_key();

        // The joining validator under test (seed 4): deposited, warming up to
        // join the committee at epoch 1, and controls its withdrawal address.
        let joining_node_key = ed25519::PrivateKey::from_seed(4);
        let joining_node_pubkey = joining_node_key.public_key();
        let joining_pubkey_bytes: [u8; 32] = joining_node_pubkey.as_ref().try_into().unwrap();
        let joining_withdrawal_address = Address::from([0x44u8; 20]);

        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        // Stage the joining validator: a pending activation queued for epoch 1
        // plus a matching warm-up account with no pending deposit/withdrawal.
        let joining_consensus_key = {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(99);
            bls12381::PrivateKey::random(&mut rng).public_key()
        };
        initial_state.set_account(
            joining_pubkey_bytes,
            ValidatorAccount {
                consensus_public_key: joining_consensus_key.clone(),
                withdrawal_credentials: joining_withdrawal_address,
                balance: 32_000_000_000,
                status: ValidatorStatus::Joining,
                has_pending_deposit: false,
                has_pending_withdrawal: false,
                joining_epoch: 1,
                last_deposit_index: 0,
            },
        );
        initial_state.add_validator(
            1,
            AddedValidator {
                node_key: joining_node_pubkey.clone(),
                consensus_key: joining_consensus_key,
            },
        );

        let oracle = RecordingOracle::default();
        let tracks = oracle.tracks.clone();

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, RecordingOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_joining_withdrawal_oracle".to_string(),
            engine_client: MockEngineClient::new(),
            oracle,
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
            node_public_key: node_pubkey,
            cancellation_token: CancellationToken::new(),
            drain_interval: Duration::from_millis(100),
            buffered_blocks_warn_threshold: 100,
            pending_notarized_max: 1000,
            namespace: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox) =
            Finalizer::<_, MockEngineClient, RecordingOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Block 1 (epoch 0, not the last block): the joining validator submits a
        // full withdrawal during its warm-up window, cancelling onboarding.
        let b1 = create_test_block_with_requests(
            parent_digest,
            1,
            2,
            19001,
            0,
            vec![full_exit_withdrawal_entry(
                joining_pubkey_bytes,
                joining_withdrawal_address,
            )],
        );
        parent_digest = b1.digest();
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b1, None), ack))
            .await;
        context.sleep(Duration::from_millis(30)).await;

        // Blocks 2-3: empty filler to reach the last block of epoch 0.
        for height in 2..4 {
            let b =
                create_test_block_with_epoch(parent_digest, height, height + 1, 19000 + height, 0);
            parent_digest = b.digest();
            let (ack, _) = Exact::handle();
            mailbox.report(Update::FinalizedBlock((b, None), ack)).await;
            context.sleep(Duration::from_millis(30)).await;
        }

        // Block 4 (last block of epoch 0): crossing into epoch 1 triggers the
        // network-oracle update for the new epoch.
        let b4 = create_test_block_with_epoch(parent_digest, 4, 5, 19004, 0);
        let b4_digest = b4.digest();
        let finalization4 = make_finalization(b4_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((b4, Some(finalization4)), ack))
            .await;
        context.sleep(Duration::from_millis(50)).await;

        // The canceled joining validator's account must leave `Joining` (to
        // `Inactive`) with the withdrawal scheduled and the balance zeroed — the
        // withdrawal record stays processable through the withdrawal window.
        let account = mailbox
            .get_validator_account(joining_node_pubkey.clone())
            .await
            .expect(
                "canceled joining validator account must still exist during the withdrawal window",
            );
        assert_eq!(
            account.status,
            ValidatorStatus::Inactive,
            "canceled joining validator must leave the Joining state"
        );
        assert!(
            account.has_pending_withdrawal,
            "the full-exit withdrawal must remain scheduled/processable"
        );
        assert_eq!(account.balance, 0, "full exit must zero the balance");

        // The epoch-1 oracle update must NOT advertise the canceled validator's
        // key (and hence none of its derived observer keys), while still
        // advertising the genuine active validators.
        let epoch1_primary = {
            let tracks = tracks.lock().unwrap();
            tracks
                .iter()
                .rev()
                .find(|(index, _)| *index == 1)
                .map(|(_, primary)| primary.clone())
                .expect("finalizer must track a validator set for epoch 1")
        };
        assert!(
            !epoch1_primary.contains(&joining_node_pubkey),
            "canceled joining validator must be excluded from epoch-1 oracle tracking"
        );
        for seed in 0..4u64 {
            let active = ed25519::PrivateKey::from_seed(seed).public_key();
            assert!(
                epoch1_primary.contains(&active),
                "genuine active validator (seed {seed}) must still be tracked for epoch 1"
            );
        }

        context.auditor().state()
    });
}
