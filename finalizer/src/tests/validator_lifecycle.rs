//! Tests for validator lifecycle: exit, removal from committee, etc.

use super::mocks::{
    MockEngineClient, MockNetworkOracle, RecordingNetworkOracle, create_test_schemes,
    make_finalization,
};
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
        epoch_length,
        10_000,
        Address::ZERO,
        10,
        16,
        0,
        3,
        0,
        3,
    );
    state.set_validator_accounts(validator_accounts);
    state
}

/// Build a `FinalizerConfig` with the settings shared across these tests. Only
/// the fields that vary between cases (persistence prefix, page cache, genesis
/// hash, initial state, this node's key, and cancellation token) are passed in.
#[allow(clippy::too_many_arguments)]
fn finalizer_cfg(
    db_prefix: &str,
    page_cache: CacheRef,
    genesis_hash: [u8; 32],
    initial_state: ConsensusState,
    node_public_key: PublicKey,
    cancellation_token: CancellationToken,
) -> FinalizerConfig<MockEngineClient, MockNetworkOracle, MinPk> {
    FinalizerConfig {
        mailbox_size: 100,
        db_prefix: db_prefix.to_string(),
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
        node_public_key,
        cancellation_token,
        drain_interval: Duration::from_millis(100),
        buffered_blocks_warn_threshold: 100,
        pending_notarized_max: 1000,
        namespace: Vec::new(),
        observer_domain: Vec::new(),
        _variant_marker: PhantomData,
    }
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
            observer_domain: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, _mailbox, _state_query) =
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

/// A finalized block delivered via catch-up (no prior fork state) must extend
/// the canonical finalized head: its parent must equal the current head digest.
///
/// The syncer accepts finalized blocks by height + certificate without checking
/// parent linkage, so the finalizer must reject a wrong-parent block rather than
/// execute it onto canonical state (which would advance the node onto an
/// impossible history). A wrong-parent finalized block must fail-stop the node.
#[test]
fn test_finalizer_rejects_finalized_block_with_wrong_parent() {
    let cfg = deterministic::Config::default().with_seed(56);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x56u8; 32];
        let node_key = ed25519::PrivateKey::from_seed(0);
        let node_pubkey = node_key.public_key();

        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_wrong_parent".to_string(),
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

        // Establish a canonical chain: blocks 1 and 2 with correct parents.
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..3 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 13000 + height, 0);
            parent_digest = block.digest();
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !token_clone.is_cancelled(),
            "token must not cancel for a correctly chained finalized sequence"
        );

        // Deliver block 3 with a WRONG parent (not block 2's digest). Height 3 is
        // not an epoch boundary (epoch_length 5), so it carries no finalization.
        // Without the parent-linkage check the finalizer executes it onto canonical
        // state; it must instead fail-stop.
        let wrong_parent = Digest::from([0xABu8; 32]);
        assert_ne!(wrong_parent, parent_digest);
        let bad_block = create_test_block_with_epoch(wrong_parent, 3, 4, 13003, 0);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((bad_block, None), ack))
            .await;
        context.sleep(Duration::from_millis(150)).await;

        assert!(
            token_clone.is_cancelled(),
            "finalizer must fail-stop on a finalized block whose parent does not \
             extend the canonical head"
        );

        context.auditor().state()
    });
}

/// At an epoch boundary, the finalizer must refuse to construct a finalized
/// header from a block whose digest the certificate does not finalize.
///
/// The syncer pairs the finalized block and its finalization by height from two
/// independently keyed immutable archives (and the block archive silently keeps
/// a stale entry on a duplicate index). If that pairing is ever inconsistent, a
/// release build must NOT export a header bound to a wrong-digest certificate —
/// it must fail-stop (cancel the cancellation token) instead of trusting it.
#[test]
fn test_finalizer_rejects_block_certificate_digest_mismatch() {
    let cfg = deterministic::Config::default().with_seed(56);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x56u8; 32];
        let node_key = ed25519::PrivateKey::from_seed(0);
        let node_pubkey = node_key.public_key();

        // Clean state: the node stays in the validator set, so the only thing
        // that can cancel the token is the digest-binding guard.
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let cancellation_token = CancellationToken::new();
        let token_clone = cancellation_token.clone();

        // Probe the execution layer through a clone of the engine client. Each
        // executed block triggers one check_payload call, so the call count tells
        // us whether the mismatched block was applied.
        let engine_client = MockEngineClient::new();
        let engine_probe = engine_client.clone();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_digest_mismatch".to_string(),
            engine_client,
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
        let mut parent_digest = genesis_block.digest();
        let schemes = create_test_schemes(4);
        let quorum = 3;

        // Finalize blocks 1-3 (epoch 0, epoch_length = 5) — no boundary yet.
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
        assert!(
            !token_clone.is_cancelled(),
            "token must not be cancelled before the epoch boundary"
        );
        // Blocks 1, 2 and 3 each executed once.
        let executions_before = engine_probe.check_payload_call_count();
        assert_eq!(
            executions_before, 3,
            "the three good blocks must have executed"
        );

        // Block 4 is the last block of epoch 0 and carries a finalization. Pair it
        // with a certificate that genuinely signs a different digest, as a stale
        // archived block paired with a fresh finalization by height would.
        let block4 = create_test_block_with_epoch(parent_digest, 4, 5, 13004, 0);
        let other_block = create_test_block_with_epoch(parent_digest, 4, 5, 99_999, 0);
        let wrong_digest = other_block.digest();
        assert_ne!(block4.digest(), wrong_digest);
        let mismatched_finalization = make_finalization(wrong_digest, 4, 3, &schemes, quorum);
        let (ack, _) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock(
                (block4, Some(mismatched_finalization)),
                ack,
            ))
            .await;
        context.sleep(Duration::from_millis(150)).await;

        assert!(
            token_clone.is_cancelled(),
            "finalizer must fail-stop on a block/certificate digest mismatch at the \
             epoch boundary instead of storing a misbound finalized header"
        );
        // The binding is checked before execution, so the mismatched block must
        // never have been applied to the execution layer.
        assert_eq!(
            engine_probe.check_payload_call_count(),
            executions_before,
            "the mismatched block must not have been executed"
        );

        context.auditor().state()
    });
}

/// A deposited validator's P2P peer tier must follow its lifecycle.
///
/// The backfill resolver draws its fetch sources from the PRIMARY peer set, so
/// while a validator is `Joining` (warming up, not yet an active voter) it must
/// be tracked as SECONDARY only — connectable for warm-up but not selectable as
/// a backfill source. Once it activates it must move INTO primary so it serves
/// backfill and is dialed like any voter.
///
/// Drives two epoch boundaries: the validator is Joining at the epoch-1
/// transition (assert secondary, not primary) and activates at the epoch-2
/// transition (assert primary).
#[test]
fn test_joining_validator_peer_tier_follows_activation() {
    let cfg = deterministic::Config::default().with_seed(334);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x33u8; 32];
        let node_key = ed25519::PrivateKey::from_seed(0);
        let node_pubkey = node_key.public_key();

        // 4 active validators, plus a fifth that has deposited and is Joining.
        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        use rand::SeedableRng;
        let joining_key = ed25519::PrivateKey::from_seed(99);
        let joining_pubkey = joining_key.public_key();
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let joining_consensus = bls12381::PrivateKey::random(&mut rng).public_key();
        let joining_account = ValidatorAccount {
            consensus_public_key: joining_consensus.clone(),
            withdrawal_credentials: Address::from([99u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Joining,
            // Activates at epoch 2: still Joining across the epoch-1 boundary,
            // promoted to Active at the epoch-2 boundary.
            joining_epoch: 2,
            last_deposit_index: 0,
        };
        let joining_bytes: [u8; 32] = joining_pubkey.as_ref().try_into().unwrap();
        initial_state.set_account(joining_bytes, joining_account);
        // Registering the validator in the added-validators queue for epoch 2 is
        // what drives the Joining -> Active promotion at that epoch boundary.
        initial_state.add_validator(
            2,
            AddedValidator {
                node_key: joining_pubkey.clone(),
                consensus_key: joining_consensus,
            },
        );

        let oracle = RecordingNetworkOracle::new();
        let track_calls = oracle.calls.clone();

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, RecordingNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: "test_joining_secondary".to_string(),
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
            observer_domain: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) = Finalizer::<
            _,
            MockEngineClient,
            RecordingNetworkOracle,
            ed25519::PrivateKey,
            MinPk,
        >::new(context.with_label("finalizer"), finalizer_cfg)
        .await;

        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(100)).await;

        // Drive two epoch boundaries (epoch_length = 5). A finalization
        // certificate on the last block of each epoch (heights 4 and 9) drives
        // that epoch's transition and its peer-tracking.
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        let schemes = create_test_schemes(4);
        let quorum = 3;

        for height in 1..=10u64 {
            let epoch = height / 5; // heights 1-4 -> epoch 0, 5-9 -> epoch 1, 10 -> epoch 2
            let block = create_test_block_with_epoch(
                parent_digest,
                height,
                height + 1,
                13000 + height,
                epoch,
            );
            let block_digest = block.digest();
            parent_digest = block_digest;
            // The last block of an epoch (heights 4 and 9) carries a finalization
            // and triggers the transition + peer-tracking for the next epoch.
            let finalization = (height % 5 == 4)
                .then(|| make_finalization(block_digest, height, height + 1, &schemes, quorum));
            let (ack, _) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, finalization), ack))
                .await;
            context.sleep(Duration::from_millis(50)).await;
        }

        let calls = track_calls.lock().unwrap();
        assert!(!calls.is_empty(), "finalizer must have tracked peers");

        // While Joining (epoch-1 transition): secondary, never primary.
        let epoch1 = calls
            .iter()
            .find(|c| c.index == 1)
            .expect("expected a track() for epoch 1");
        assert!(
            !epoch1.primary.contains(&joining_pubkey),
            "joining validator must NOT be a primary peer (resolver backfill source) before activation"
        );
        assert!(
            epoch1.secondary.contains(&joining_pubkey),
            "joining validator should be a secondary (warm-up) peer while it is Joining"
        );

        // After activation (epoch-2 transition): promoted into primary.
        let epoch2 = calls
            .iter()
            .find(|c| c.index == 2)
            .expect("expected a track() for epoch 2");
        assert!(
            epoch2.primary.contains(&joining_pubkey),
            "once active, the validator must be a primary peer (eligible backfill source + dialed)"
        );

        context.auditor().state()
    });
}

#[test]
fn epoch_transition_deltas_are_cleared_before_persisted_state_ack() {
    let cfg = deterministic::Config::default().with_seed(58);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        use rand::SeedableRng;

        let genesis_hash = [0x58u8; 32];
        let db_prefix = "test_epoch_transition_deltas_cleared_before_ack".to_string();
        let local_node_key = ed25519::PrivateKey::from_seed(1);
        let removed_node_key = ed25519::PrivateKey::from_seed(0);
        let removed_node_pubkey = removed_node_key.public_key();
        let removed_pubkey_bytes: [u8; 32] = removed_node_pubkey.as_ref().try_into().unwrap();
        let joining_node_key = ed25519::PrivateKey::from_seed(10);
        let joining_node_pubkey = joining_node_key.public_key();
        let joining_pubkey_bytes: [u8; 32] = joining_node_pubkey.as_ref().try_into().unwrap();

        let mut rng = rand::rngs::StdRng::seed_from_u64(58);
        let joining_consensus_key = bls12381::PrivateKey::random(&mut rng);
        let joining_consensus_pubkey = joining_consensus_key.public_key();

        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());
        initial_state.push_removed_validator(removed_node_pubkey.clone());
        initial_state.set_account(
            joining_pubkey_bytes,
            ValidatorAccount {
                consensus_public_key: joining_consensus_pubkey.clone(),
                withdrawal_credentials: Address::from([10u8; 20]),
                balance: 32_000_000_000,
                status: ValidatorStatus::Joining,
                joining_epoch: 1,
                last_deposit_index: 0,
            },
        );
        initial_state.add_validator(
            1,
            AddedValidator {
                node_key: joining_node_pubkey.clone(),
                consensus_key: joining_consensus_pubkey,
            },
        );

        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );
        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let cancellation_token = CancellationToken::new();

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
            node_public_key: local_node_key.public_key(),
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
        let handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 58000 + height, 0);
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("non-boundary block must be acked");
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let boundary = create_test_block_with_epoch(parent_digest, 4, 5, 58004, 0);
        let boundary_digest = boundary.digest();
        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;
        ack_waiter.await.expect("epoch boundary block must be acked");

        drop(mailbox);
        handle.abort();
        context.sleep(Duration::from_millis(50)).await;

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
                    node_public_key: local_node_key.public_key(),
                    cancellation_token: CancellationToken::new(),
                    drain_interval: Duration::from_millis(100),
                    buffered_blocks_warn_threshold: 100,
                    pending_notarized_max: 1000,
                    namespace: Vec::new(),
                    observer_domain: Vec::new(),
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
        assert!(
            reloaded_state.get_removed_validators().is_empty(),
            "removed_validators must not persist after the epoch transition is acked"
        );
        assert!(
            reloaded_state.get_added_validators(1).is_none(),
            "added_validators for the activated epoch must not persist after the transition is acked"
        );
        assert_eq!(
            reloaded_state
                .get_account(&removed_pubkey_bytes)
                .expect("removed validator account must exist")
                .status,
            ValidatorStatus::Inactive,
            "removed validator status must be materialized before clearing transition deltas"
        );
        assert_eq!(
            reloaded_state
                .get_account(&joining_pubkey_bytes)
                .expect("joining validator account must exist")
                .status,
            ValidatorStatus::Active,
            "joining validator status must be materialized before clearing transition deltas"
        );

        let active_validators = reloaded_state.get_active_validators();
        assert_eq!(
            active_validators.len(),
            4,
            "active validator set should replace the removed validator with the joining validator"
        );
        assert!(
            active_validators
                .iter()
                .any(|(node_key, _)| node_key == &joining_node_pubkey),
            "joining validator must be present in the active validator set after restart"
        );
        assert!(
            !active_validators
                .iter()
                .any(|(node_key, _)| node_key == &removed_node_pubkey),
            "removed validator must not be present in the active validator set after restart"
        );

        context.auditor().state()
    });
}

/// A commit failure on the last block of an epoch must NOT ack the syncer and
/// must NOT durably advance the epoch.
///
/// The finalizer acks the syncer only after the epoch-boundary consensus state
/// is persisted (#270/#325). If the EL forkchoice commit fails on the boundary
/// block, the finalizer returns an error before persisting or acking: the
/// syncer's `Exact` waiter must resolve `Err` (withheld ack, so the block is
/// re-delivered later) and the node must trigger a graceful shutdown. A restart
/// from the same DB must still load the pre-boundary epoch, proving the
/// transition was not half-committed.
#[test]
fn epoch_boundary_commit_failure_withholds_ack_and_shuts_down() {
    let cfg = deterministic::Config::default().with_seed(59);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x59u8; 32];
        let db_prefix = "test_epoch_commit_failure_withholds_ack".to_string();
        let local_node_key = ed25519::PrivateKey::from_seed(1);

        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );
        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let cancellation_token = CancellationToken::new();

        // Shared engine client so the test can flip commit_hash to failing only
        // after the non-boundary blocks have been acked. The clone handed to the
        // finalizer shares the failure flag.
        let engine_client = MockEngineClient::new();

        let finalizer_cfg = FinalizerConfig::<MockEngineClient, MockNetworkOracle, MinPk> {
            mailbox_size: 100,
            db_prefix: db_prefix.clone(),
            engine_client: engine_client.clone(),
            oracle: MockNetworkOracle,
            protocol_consts: ProtocolConsts {
                validator_num_warm_up_epochs: 2,
                validator_withdrawal_num_epochs: 2,
            },
            page_cache: page_cache.clone(),
            genesis_hash,
            initial_state: initial_state.clone(),
            protocol_version: 1,
            node_public_key: local_node_key.public_key(),
            cancellation_token: cancellation_token.clone(),
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
        let handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();

        // Non-boundary blocks 1..=3 commit cleanly and must be acked.
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 59000 + height, 0);
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("non-boundary block must be acked");
        }

        // Fail the forkchoice commit for the epoch-boundary block.
        engine_client.fail_commit_hash();

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let boundary = create_test_block_with_epoch(parent_digest, 4, 5, 59004, 0);
        let boundary_digest = boundary.digest();
        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;

        // Ack must be WITHHELD: the finalizer errors on the failed commit before
        // acknowledging, so the Exact waiter resolves Err (sender dropped).
        assert!(
            ack_waiter.await.is_err(),
            "epoch-boundary ack must be withheld when the commit fails"
        );

        // The finalizer must trigger a graceful shutdown.
        context.sleep(Duration::from_millis(50)).await;
        assert!(
            cancellation_token.is_cancelled(),
            "finalizer must shut down after a fatal commit failure"
        );

        drop(mailbox);
        handle.abort();
        context.sleep(Duration::from_millis(50)).await;

        // Restart from the same DB: the epoch must NOT have durably advanced.
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
                    node_public_key: local_node_key.public_key(),
                    cancellation_token: CancellationToken::new(),
                    drain_interval: Duration::from_millis(100),
                    buffered_blocks_warn_threshold: 100,
                    pending_notarized_max: 1000,
                    namespace: Vec::new(),
                    observer_domain: Vec::new(),
                    _variant_marker: PhantomData,
                },
            )
            .await;
        drop(restarted);

        assert_eq!(
            reloaded_state.get_epoch(),
            0,
            "epoch must not durably advance when the boundary commit fails before the ack"
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
/// submits a valid full withdrawal before activation. The withdrawal is buffered
/// and processed at the penultimate block: it cancels the pending activation and
/// flips the account to `FullPayoutPending` (full exit), so the canceled
/// validator is excluded from the active-or-joining set advertised to the
/// network oracle at the next epoch transition (and therefore from its derived
/// observer keys). The balance is retained until the payout epoch.
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
            observer_domain: Vec::new(),
            _variant_marker: PhantomData,
        };

        let (finalizer, _state, mut mailbox, _state_query) =
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
            ValidatorStatus::FullPayoutPending,
            "canceled joining validator must leave Joining for the full-exit payout state"
        );
        assert_eq!(
            account.balance, 32_000_000_000,
            "balance is retained until the payout epoch, reduced only at payout"
        );

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

/// A validator that is still mid-warmup (Joining, scheduled to activate in a
/// future epoch) must survive a restart with its pending activation intact. Here
/// the validator is scheduled for epoch 2, the finalizer is driven only across
/// the epoch 0 -> 1 boundary (before activation), and then restarted. On reload
/// it must still be Joining, still carry joining_epoch 2 and its added_validators
/// entry, and not yet be an active signer. Losing any of these on restart would
/// silently drop an onboarding validator or activate it in the wrong epoch.
#[test]
fn restart_mid_warmup_preserves_pending_joining_validator() {
    let executor = Runner::from(deterministic::Config::default().with_seed(77));
    executor.start(|context| async move {
        use rand::SeedableRng;

        let genesis_hash = [0x77u8; 32];
        let db_prefix = "test_restart_mid_warmup_preserves_joining".to_string();
        let local_node_key = ed25519::PrivateKey::from_seed(1);
        let joining_node_key = ed25519::PrivateKey::from_seed(10);
        let joining_node_pubkey = joining_node_key.public_key();
        let joining_pubkey_bytes: [u8; 32] = joining_node_pubkey.as_ref().try_into().unwrap();

        let mut rng = rand::rngs::StdRng::seed_from_u64(77);
        let joining_consensus_key = bls12381::PrivateKey::random(&mut rng);
        let joining_consensus_pubkey = joining_consensus_key.public_key();

        // A joining validator scheduled to activate in epoch 2 (two boundaries
        // away), so a single epoch transition does not activate it.
        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());
        initial_state.set_account(
            joining_pubkey_bytes,
            ValidatorAccount {
                consensus_public_key: joining_consensus_pubkey.clone(),
                withdrawal_credentials: Address::from([10u8; 20]),
                balance: 32_000_000_000,
                status: ValidatorStatus::Joining,
                joining_epoch: 2,
                last_deposit_index: 0,
            },
        );
        initial_state.add_validator(
            2,
            AddedValidator {
                node_key: joining_node_pubkey.clone(),
                consensus_key: joining_consensus_pubkey,
            },
        );

        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );
        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg(
                    &db_prefix,
                    page_cache.clone(),
                    genesis_hash,
                    initial_state.clone(),
                    local_node_key.public_key(),
                    CancellationToken::new(),
                ),
            )
            .await;
        let handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        // Finalize epoch 0 (blocks 1-3 plus the boundary at 4), crossing only the
        // 0 -> 1 transition. The joining validator (epoch 2) stays mid-warmup.
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 77000 + height, 0);
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("non-boundary block must be acked");
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let boundary = create_test_block_with_epoch(parent_digest, 4, 5, 77004, 0);
        let boundary_digest = boundary.digest();
        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;
        ack_waiter
            .await
            .expect("epoch boundary block must be acked");

        // Restart: drop the running finalizer and reboot on the same persistence
        // prefix and page cache so the reloaded state comes from durable storage.
        drop(mailbox);
        handle.abort();
        context.sleep(Duration::from_millis(50)).await;

        let (restarted, reloaded_state, _mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer_restart"),
                finalizer_cfg(
                    &db_prefix,
                    page_cache,
                    genesis_hash,
                    initial_state,
                    local_node_key.public_key(),
                    CancellationToken::new(),
                ),
            )
            .await;
        drop(restarted);

        // The transition advanced to epoch 1, but the validator scheduled for
        // epoch 2 must still be mid-warmup with its activation intact.
        assert_eq!(
            reloaded_state.get_epoch(),
            1,
            "restarted finalizer must load the persisted post-transition epoch"
        );
        let account = reloaded_state
            .get_account(&joining_pubkey_bytes)
            .expect("joining validator account must survive the restart");
        assert_eq!(
            account.status,
            ValidatorStatus::Joining,
            "a validator scheduled for a later epoch must stay Joining across the restart"
        );
        assert_eq!(
            account.joining_epoch, 2,
            "the pending activation epoch must be preserved"
        );
        assert!(
            reloaded_state.has_added_validators(2),
            "the scheduled activation (added_validators for epoch 2) must survive the restart"
        );
        assert!(
            !reloaded_state
                .get_active_validators()
                .iter()
                .any(|(node_key, _)| node_key == &joining_node_pubkey),
            "the mid-warmup validator must not be an active signer before its activation epoch"
        );

        context.auditor().state()
    });
}

/// A validator whose full-exit payout is still pending (FullPayoutPending, left
/// the committee but not yet paid out) must survive a restart with both its
/// status and its queued withdrawal intact, so the payout still fires post
/// restart. Here the payout is scheduled for epoch 2, the finalizer is driven
/// only across the epoch 0 -> 1 boundary (before the payout epoch), and then
/// restarted. On reload the account must still be FullPayoutPending and the
/// queued withdrawal for epoch 2 must still be present. Losing either on restart
/// would strand the validator's balance (never paid out).
#[test]
fn restart_preserves_pending_full_exit_payout() {
    use summit_types::execution_request::WithdrawalRequest;

    let executor = Runner::from(deterministic::Config::default().with_seed(88));
    executor.start(|context| async move {
        use rand::SeedableRng;

        let genesis_hash = [0x88u8; 32];
        let db_prefix = "test_restart_preserves_pending_payout".to_string();
        let local_node_key = ed25519::PrivateKey::from_seed(1);
        let exiting_node_key = ed25519::PrivateKey::from_seed(11);
        let exiting_node_pubkey = exiting_node_key.public_key();
        let exiting_pubkey_bytes: [u8; 32] = exiting_node_pubkey.as_ref().try_into().unwrap();
        let exit_address = Address::from([11u8; 20]);

        let mut rng = rand::rngs::StdRng::seed_from_u64(88);
        let exiting_consensus_key = bls12381::PrivateKey::random(&mut rng);

        // A validator that has already left the committee and is awaiting its
        // full-exit payout, with the payout queued for epoch 2.
        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());
        initial_state.set_account(
            exiting_pubkey_bytes,
            ValidatorAccount {
                consensus_public_key: exiting_consensus_key.public_key(),
                withdrawal_credentials: exit_address,
                balance: 20_000_000_000,
                status: ValidatorStatus::FullPayoutPending,
                joining_epoch: 0,
                last_deposit_index: 0,
            },
        );
        // Full-exit marker (amount 0): the payout pays the live balance at epoch 2.
        initial_state.push_withdrawal_request(
            WithdrawalRequest {
                source_address: exit_address,
                validator_pubkey: exiting_pubkey_bytes,
                amount: 0,
            },
            2,
        );
        assert_eq!(
            initial_state.get_withdrawals_for_epoch(2).len(),
            1,
            "precondition: one payout queued for epoch 2"
        );

        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );
        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);

        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg(
                    &db_prefix,
                    page_cache.clone(),
                    genesis_hash,
                    initial_state.clone(),
                    local_node_key.public_key(),
                    CancellationToken::new(),
                ),
            )
            .await;
        let handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        // Finalize epoch 0 (blocks 1-3 plus the boundary at 4), crossing only the
        // 0 -> 1 transition. The payout epoch (2) is not reached, so it stays
        // queued.
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..4 {
            let block =
                create_test_block_with_epoch(parent_digest, height, height + 1, 88000 + height, 0);
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("non-boundary block must be acked");
        }

        let schemes = create_test_schemes(4);
        let quorum = 3;
        let boundary = create_test_block_with_epoch(parent_digest, 4, 5, 88004, 0);
        let boundary_digest = boundary.digest();
        let finalization = make_finalization(boundary_digest, 4, 3, &schemes, quorum);
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;
        ack_waiter
            .await
            .expect("epoch boundary block must be acked");

        // Restart on the same persistence prefix and page cache.
        drop(mailbox);
        handle.abort();
        context.sleep(Duration::from_millis(50)).await;

        let (restarted, reloaded_state, _mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer_restart"),
                finalizer_cfg(
                    &db_prefix,
                    page_cache,
                    genesis_hash,
                    initial_state,
                    local_node_key.public_key(),
                    CancellationToken::new(),
                ),
            )
            .await;
        drop(restarted);

        // The pending payout survived: status and the queued withdrawal are intact.
        let account = reloaded_state
            .get_account(&exiting_pubkey_bytes)
            .expect("exiting validator account must survive the restart");
        assert_eq!(
            account.status,
            ValidatorStatus::FullPayoutPending,
            "a validator awaiting its payout must stay FullPayoutPending across the restart"
        );
        assert_eq!(
            account.balance, 20_000_000_000,
            "the balance to be paid out must be preserved"
        );
        let queued = reloaded_state.get_withdrawals_for_epoch(2);
        assert_eq!(
            queued.len(),
            1,
            "the pending payout for epoch 2 must survive the restart"
        );
        assert_eq!(
            queued[0].pubkey, exiting_pubkey_bytes,
            "the queued payout must still target the exiting validator"
        );

        context.auditor().state()
    });
}
