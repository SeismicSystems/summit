//! Tests for withdrawal validation on the finalized execution path.
//!
//! Application verify enforces that a block's EIP 4895 withdrawals equal the
//! payouts emitted from consensus state, but finalized catch up blocks are
//! executed without ever passing verify on this node. A certificate over a
//! block with a mismatched withdrawals list requires a malicious 2/3+1 quorum;
//! when that happens the node must fail stop through the InvalidPayload policy
//! before the EL forkchoice adopts the block, instead of paying out on the EL
//! without debiting consensus state (non terminal) or panicking after the EL
//! already adopted the block (terminal).

use super::mocks::{MockEngineClient, MockNetworkOracle, create_test_schemes, make_finalization};
use crate::actor::Finalizer;
use crate::config::{FinalizerConfig, ProtocolConsts};
use alloy_eips::eip4895::Withdrawal;
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
use summit_types::execution_request::WithdrawalRequest;
use summit_types::{Block, Digest};
use tokio_util::sync::CancellationToken;

/// Helper to create a test block carrying a specific EIP 4895 withdrawals list.
fn create_test_block_with_withdrawals(
    parent_digest: Digest,
    height: u64,
    view: u64,
    unique_seed: u64,
    epoch: u64,
    withdrawals: Vec<Withdrawal>,
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
            withdrawals,
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

fn make_finalizer_cfg(
    db_prefix: &str,
    engine_client: MockEngineClient,
    genesis_hash: [u8; 32],
    initial_state: ConsensusState,
    cancellation_token: CancellationToken,
    page_cache: CacheRef,
) -> FinalizerConfig<MockEngineClient, MockNetworkOracle, MinPk> {
    FinalizerConfig {
        mailbox_size: 100,
        db_prefix: db_prefix.to_string(),
        engine_client,
        oracle: MockNetworkOracle,
        protocol_consts: ProtocolConsts {
            validator_num_warm_up_epochs: 2,
            validator_withdrawal_num_epochs: 2,
        },
        page_cache,
        genesis_hash,
        initial_state,
        protocol_version: 1,
        node_public_key: ed25519::PrivateKey::from_seed(0).public_key(),
        cancellation_token,
        drain_interval: Duration::from_millis(100),
        buffered_blocks_warn_threshold: 100,
        pending_notarized_max: 1000,
        namespace: Vec::new(),
        observer_domain: Vec::new(),
        _variant_marker: PhantomData,
    }
}

fn bogus_withdrawal() -> Withdrawal {
    Withdrawal {
        index: 0,
        validator_index: 0,
        address: Address::from([9u8; 20]),
        amount: 1_000_000_000,
    }
}

// A finalized NON terminal block carrying withdrawals must be rejected as fatal
// before the EL forkchoice adopts it. Consensus never pays anything outside the
// last block of an epoch, so such a block requires a malicious quorum; without
// the execute time check the EL would credit the recipients while consensus
// state never debits them (silent EL/CL divergence).
#[test]
fn finalized_non_terminal_block_with_withdrawals_is_fatal() {
    let cfg = deterministic::Config::default().with_seed(61);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x61u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let cancellation_token = CancellationToken::new();
        let engine_client = MockEngineClient::new();
        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );

        let finalizer_cfg = make_finalizer_cfg(
            "test_nonterminal_withdrawals",
            engine_client.clone(),
            genesis_hash,
            initial_state,
            cancellation_token.clone(),
            page_cache,
        );
        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        // Height 1 with epoch_num_of_blocks = 5 is not a terminal block, so the
        // expected withdrawals list is empty.
        let genesis_block = Block::genesis(genesis_hash);
        let block = create_test_block_with_withdrawals(
            genesis_block.digest(),
            1,
            2,
            61001,
            0,
            vec![bogus_withdrawal()],
        );

        let commits_before = engine_client.commit_hash_call_count();
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((block, None), ack))
            .await;

        // Fail stop: the ack is withheld and the finalizer shuts down.
        assert!(
            ack_waiter.await.is_err(),
            "a non terminal block carrying withdrawals must not be acked"
        );
        context.sleep(Duration::from_millis(50)).await;
        assert!(
            cancellation_token.is_cancelled(),
            "finalizer must shut down on a finalized block with bogus withdrawals"
        );
        // The rejection must happen before the EL forkchoice adopts the block.
        assert_eq!(
            engine_client.commit_hash_call_count(),
            commits_before,
            "EL forkchoice must not be asked to adopt the rejected block"
        );

        context.auditor().state()
    });
}

// A finalized TERMINAL block whose withdrawals differ from the payouts emitted
// by consensus state must be rejected through the same structured fail stop,
// not the raw assert in apply_withdrawal_payouts. The assert fires only after
// commit_forkchoice, so the old behavior panicked with the EL already treating
// the malicious block as finalized, and restart replayed straight into the
// same panic.
#[test]
fn finalized_terminal_block_with_tampered_withdrawals_is_fatal() {
    let cfg = deterministic::Config::default().with_seed(62);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x62u8; 32];
        let initial_state = create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let cancellation_token = CancellationToken::new();
        let engine_client = MockEngineClient::new();
        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );

        let finalizer_cfg = make_finalizer_cfg(
            "test_terminal_tampered_withdrawals",
            engine_client.clone(),
            genesis_hash,
            initial_state,
            cancellation_token.clone(),
            page_cache,
        );
        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        // Finalize blocks 1..=3 cleanly (epoch 0, terminal block is height 4).
        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..4 {
            let block = create_test_block_with_withdrawals(
                parent_digest,
                height,
                height + 1,
                62000 + height,
                0,
                Vec::new(),
            );
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("clean block must be acked");
        }

        // The withdrawal queue is empty, so consensus emits no payouts for the
        // terminal block; a non empty list is a mismatch.
        let schemes = create_test_schemes(4);
        let boundary = create_test_block_with_withdrawals(
            parent_digest,
            4,
            5,
            62004,
            0,
            vec![bogus_withdrawal()],
        );
        let finalization = make_finalization(boundary.digest(), 4, 3, &schemes, 3);

        let commits_before = engine_client.commit_hash_call_count();
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;

        assert!(
            ack_waiter.await.is_err(),
            "a terminal block with tampered withdrawals must not be acked"
        );
        context.sleep(Duration::from_millis(50)).await;
        assert!(
            cancellation_token.is_cancelled(),
            "finalizer must shut down on a terminal block with tampered withdrawals"
        );
        assert_eq!(
            engine_client.commit_hash_call_count(),
            commits_before,
            "EL forkchoice must not be asked to adopt the rejected block"
        );

        context.auditor().state()
    });
}

// Positive control: a terminal block carrying exactly the payouts consensus
// state emits must still apply cleanly. Protects the execute time check from
// false positives on the honest path.
#[test]
fn finalized_terminal_block_with_matching_withdrawals_applies() {
    let cfg = deterministic::Config::default().with_seed(63);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let genesis_hash = [0x63u8; 32];
        let mut initial_state =
            create_test_initial_state(genesis_hash, NonZeroU64::new(5).unwrap());

        // Give one validator headroom above the minimum stake and enqueue a
        // partial withdrawal due in epoch 0, so the terminal block (height 4)
        // pays it out.
        let rich_key: [u8; 32] = ed25519::PrivateKey::from_seed(0)
            .public_key()
            .as_ref()
            .try_into()
            .unwrap();
        let mut account = initial_state.get_account(&rich_key).unwrap().clone();
        account.balance = 42_000_000_000;
        initial_state.set_account(rich_key, account);
        initial_state.push_withdrawal_request(
            WithdrawalRequest {
                source_address: Address::from([0u8; 20]),
                validator_pubkey: rich_key,
                amount: 5_000_000_000,
            },
            0,
        );
        let expected_payouts = initial_state.emit_withdrawal_payouts(0);
        assert_eq!(
            expected_payouts
                .iter()
                .map(|w| w.amount)
                .collect::<Vec<_>>(),
            vec![5_000_000_000],
            "sanity: the partial should be emitted in full"
        );

        let (orchestrator_tx, _orchestrator_rx) = futures_mpsc::channel(100);
        let orchestrator_mailbox = summit_orchestrator::Mailbox::new(orchestrator_tx);
        let cancellation_token = CancellationToken::new();
        let engine_client = MockEngineClient::new();
        let page_cache = CacheRef::from_pooler(
            &context,
            std::num::NonZero::new(4096).unwrap(),
            NZUsize!(100),
        );

        let finalizer_cfg = make_finalizer_cfg(
            "test_terminal_matching_withdrawals",
            engine_client.clone(),
            genesis_hash,
            initial_state,
            cancellation_token.clone(),
            page_cache,
        );
        let (finalizer, _state, mut mailbox, _state_query) =
            Finalizer::<_, MockEngineClient, MockNetworkOracle, ed25519::PrivateKey, MinPk>::new(
                context.with_label("finalizer"),
                finalizer_cfg,
            )
            .await;
        let _handle = finalizer.start(orchestrator_mailbox);
        context.sleep(Duration::from_millis(50)).await;

        let genesis_block = Block::genesis(genesis_hash);
        let mut parent_digest = genesis_block.digest();
        for height in 1..4 {
            let block = create_test_block_with_withdrawals(
                parent_digest,
                height,
                height + 1,
                63000 + height,
                0,
                Vec::new(),
            );
            parent_digest = block.digest();
            let (ack, ack_waiter) = Exact::handle();
            mailbox
                .report(Update::FinalizedBlock((block, None), ack))
                .await;
            ack_waiter.await.expect("clean block must be acked");
        }

        // Terminal block carrying exactly the emitted payouts.
        let schemes = create_test_schemes(4);
        let boundary =
            create_test_block_with_withdrawals(parent_digest, 4, 5, 63004, 0, expected_payouts);
        let finalization = make_finalization(boundary.digest(), 4, 3, &schemes, 3);
        let (ack, ack_waiter) = Exact::handle();
        mailbox
            .report(Update::FinalizedBlock((boundary, Some(finalization)), ack))
            .await;
        ack_waiter
            .await
            .expect("terminal block with matching withdrawals must be acked");

        assert_eq!(mailbox.get_latest_height().await, 4);
        assert_eq!(mailbox.get_latest_epoch().await, 1);
        assert!(!cancellation_token.is_cancelled());

        context.auditor().state()
    });
}
