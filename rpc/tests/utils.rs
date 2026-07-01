use alloy_primitives::Address;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{bls12381, ed25519};
use commonware_math::algebra::Random;
use futures::{FutureExt as _, StreamExt, channel::oneshot};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use summit_types::account::ValidatorAccount;
use summit_types::{
    Block,
    consensus_state_query::{ConsensusStateQuery, ConsensusStateRequest, ConsensusStateResponse},
    scheme::MultisigScheme,
};
use tokio::task::JoinHandle;

// Use the default Block type parameters and the MultisigScheme with ed25519 + MinPk
pub type TestScheme = MultisigScheme;

/// Mock finalizer state that can be customized per test
#[derive(Clone, Debug)]
pub struct MockFinalizerState {
    pub latest_height: u64,
    pub latest_epoch: u64,
    pub checkpoints: HashMap<u64, Option<summit_types::checkpoint::Checkpoint>>,
    pub latest_checkpoint: Option<(Option<summit_types::checkpoint::Checkpoint>, u64)>,
    pub finalized_headers: HashMap<u64, Option<summit_types::FinalizedHeader<TestScheme>>>,
    pub validator_balances: HashMap<summit_types::PublicKey, Option<u64>>,
    pub validator_accounts: HashMap<summit_types::PublicKey, Option<ValidatorAccount>>,
    pub minimum_stake: u64,
}

impl Default for MockFinalizerState {
    fn default() -> Self {
        Self {
            latest_height: 0,
            latest_epoch: 0,
            checkpoints: HashMap::new(),
            latest_checkpoint: Some((None, 0)),
            finalized_headers: HashMap::new(),
            validator_balances: HashMap::new(),
            validator_accounts: HashMap::new(),
            minimum_stake: 32_000_000_000, // 32 ETH in gwei
        }
    }
}

/// Creates a mock finalizer mailbox that responds to queries with test data
pub fn create_test_finalizer_mailbox(
    state: MockFinalizerState,
) -> (ConsensusStateQuery<TestScheme>, JoinHandle<()>) {
    let (query, mut rx) = ConsensusStateQuery::new(100);

    let handle = tokio::spawn(async move {
        while let Some((request, response)) = rx.next().await {
            match request {
                ConsensusStateRequest::GetLatestHeight => {
                    let _ =
                        response.send(ConsensusStateResponse::LatestHeight(state.latest_height));
                }
                ConsensusStateRequest::GetLatestEpoch => {
                    let _ = response.send(ConsensusStateResponse::LatestEpoch(state.latest_epoch));
                }
                ConsensusStateRequest::GetCheckpoint(epoch) => {
                    let checkpoint = state
                        .checkpoints
                        .get(&epoch)
                        .cloned()
                        .flatten()
                        .and_then(|checkpoint| Some((checkpoint, Block::genesis([0; 32]))));
                    let _ = response.send(ConsensusStateResponse::Checkpoint(checkpoint));
                }
                ConsensusStateRequest::GetLatestCheckpoint => {
                    let (latest_checkpoint, epoch) =
                        state.latest_checkpoint.clone().unwrap_or((None, 0));
                    let latest_checkpoint =
                        latest_checkpoint.map(|checkpoint| (checkpoint, Block::genesis([0; 32])));
                    let _ = response.send(ConsensusStateResponse::LatestCheckpoint((
                        latest_checkpoint,
                        epoch,
                    )));
                }
                ConsensusStateRequest::GetValidatorBalance(public_key) => {
                    let balance = state.validator_balances.get(&public_key).cloned().flatten();
                    let _ = response.send(ConsensusStateResponse::ValidatorBalance(balance));
                }
                ConsensusStateRequest::GetValidatorAccount(public_key) => {
                    let account = state.validator_accounts.get(&public_key).cloned().flatten();
                    let _ = response.send(ConsensusStateResponse::ValidatorAccount(account));
                }
                ConsensusStateRequest::GetFinalizedHeader(epoch) => {
                    let header = state.finalized_headers.get(&epoch).cloned().flatten();
                    let _ = response.send(ConsensusStateResponse::FinalizedHeader(header));
                }
                ConsensusStateRequest::GetMinimumStake => {
                    let _ =
                        response.send(ConsensusStateResponse::MinimumStake(state.minimum_stake));
                }
                ConsensusStateRequest::GetStateRoot => {
                    let _ = response.send(ConsensusStateResponse::StateRoot {
                        root: [0; 32],
                        el_block_number: 0,
                    });
                }
                ConsensusStateRequest::GetDeposit(_) => {
                    let _ = response.send(ConsensusStateResponse::Deposit(None));
                }
                ConsensusStateRequest::GetDepositCount => {
                    let _ = response.send(ConsensusStateResponse::DepositCount(0));
                }
                ConsensusStateRequest::GetWithdrawal(_) => {
                    let _ = response.send(ConsensusStateResponse::Withdrawal(None));
                }
                ConsensusStateRequest::GenerateStateProof(keys, _permit) => {
                    // Honor the one-result-per-requested-key contract (#260/#267):
                    // return a positional slot per key so the server's length guard
                    // and keyed-alignment logic are exercised faithfully.
                    let _ = response.send(ConsensusStateResponse::StateProof {
                        root: [0; 32],
                        el_block_number: 0,
                        proofs: keys.iter().map(|_| None).collect(),
                    });
                }
                ConsensusStateRequest::GetEpochLength => {
                    let _ = response.send(ConsensusStateResponse::EpochLength(10));
                }
                ConsensusStateRequest::GetAllowedTimestampFuture => {
                    let _ = response.send(ConsensusStateResponse::AllowedTimestampFuture(10_000));
                }
                ConsensusStateRequest::GetTreasuryAddress => {
                    let _ = response.send(ConsensusStateResponse::TreasuryAddress(Address::ZERO));
                }
                ConsensusStateRequest::GetMaxDepositsPerEpoch => {
                    let _ = response.send(ConsensusStateResponse::MaxDepositsPerEpoch(3));
                }
                ConsensusStateRequest::GetMaxWithdrawalsPerEpoch => {
                    let _ = response.send(ConsensusStateResponse::MaxWithdrawalsPerEpoch(16));
                }
                ConsensusStateRequest::GetObserversPerValidator => {
                    let _ = response.send(ConsensusStateResponse::ObserversPerValidator(0));
                }
                ConsensusStateRequest::GetMinimumValidatorCount => {
                    let _ = response.send(ConsensusStateResponse::MinimumValidatorCount(3));
                }
                ConsensusStateRequest::GetInvalidDepositTax => {
                    let _ = response.send(ConsensusStateResponse::InvalidDepositTax(0));
                }
                ConsensusStateRequest::GetEpochBounds(epoch) => {
                    let first = epoch * 10;
                    let last = first + 9;
                    let _ = response.send(ConsensusStateResponse::EpochBounds(Some((first, last))));
                }
            }
        }
    });

    (query, handle)
}

/// A mock state-query mailbox whose `GenerateStateProof` responses are gated:
/// every received proof request increments `received` and then blocks until the
/// returned one-shot release trigger fires, letting a test hold many proof
/// generations in flight at once. Each request is handled in its own spawned
/// task (mirroring the finalizer's off-loop proof spawn) so the mock keeps
/// accepting requests while earlier ones are held open.
///
/// Returns the query handle, an in-flight-received counter, and the release
/// trigger (drop or send `()` to let all held requests complete).
pub fn create_gated_proof_mailbox() -> (
    ConsensusStateQuery<TestScheme>,
    Arc<AtomicUsize>,
    oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let (query, mut rx) = ConsensusStateQuery::new(1024);
    let received = Arc::new(AtomicUsize::new(0));
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let release = release_rx.shared();
    let received_task = received.clone();

    let handle = tokio::spawn(async move {
        while let Some((request, response)) = rx.next().await {
            match request {
                ConsensusStateRequest::GenerateStateProof(keys, permit) => {
                    let received = received_task.clone();
                    let release = release.clone();
                    tokio::spawn(async move {
                        // Hold the concurrency permit inside this spawned task,
                        // exactly as the finalizer does, so it is dropped only
                        // when the (gated) proof work completes. Capturing it
                        // here is what models the real permit lifetime.
                        let _permit = permit;
                        received.fetch_add(1, Ordering::SeqCst);
                        let _ = release.await;
                        let _ = response.send(ConsensusStateResponse::StateProof {
                            root: [0; 32],
                            el_block_number: 0,
                            proofs: keys.iter().map(|_| None).collect(),
                        });
                    });
                }
                _ => unreachable!("gated mock only serves GenerateStateProof"),
            }
        }
    });

    (query, received, release_tx, handle)
}

/// Creates a temporary key store directory with test keys
pub fn create_test_keystore() -> anyhow::Result<tempfile::TempDir> {
    let temp_dir = tempfile::tempdir()?;

    // Generate ed25519 node key (deterministic for testing)
    let mut rng = StdRng::seed_from_u64(0);
    let node_private_key = ed25519::PrivateKey::random(&mut rng);
    let encoded_node_key = commonware_utils::hex(&node_private_key.encode());
    let node_key_path = temp_dir.path().join("node_key.pem");
    fs::write(node_key_path, encoded_node_key)?;

    // Generate BLS consensus key (deterministic for testing)
    let consensus_private_key = bls12381::PrivateKey::random(&mut rng);
    let encoded_consensus_key = commonware_utils::hex(&consensus_private_key.encode());
    let consensus_key_path = temp_dir.path().join("consensus_key.pem");
    fs::write(consensus_key_path, encoded_consensus_key)?;

    Ok(temp_dir)
}

/// Builds a payload-bound `FinalizedHeader` for the given epoch so tests can
/// exercise finalized-header query paths without a live consensus run.
pub fn create_test_finalized_header(epoch: u64) -> summit_types::FinalizedHeader<TestScheme> {
    use commonware_consensus::simplex::types::{Finalization, Proposal};
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::bls12381::{
        certificate::multisig::Certificate as BlsCertificate,
        primitives::{
            group::Private,
            ops::{aggregate::Signature, sign_message},
            variant::MinPk,
        },
    };
    use commonware_utils::Participant;

    let header = summit_types::Header::new(
        [1u8; 32].into(),
        epoch * 10 + 9,
        1234567890 + epoch,
        epoch,
        1,
        [2u8; 32].into(),
        [3u8; 32].into(),
        [4u8; 32].into(),
        [5u8; 32].into(),
        Vec::new(),
        Vec::new(),
        [0u8; 32],
    );

    let proposal = Proposal {
        round: Round::new(Epoch::new(header.epoch()), View::new(header.view())),
        parent: View::new(header.height()),
        payload: header.get_digest(),
    };

    let mut rng = StdRng::seed_from_u64(42);
    let private = Private::random(&mut rng);
    let g2_signature = sign_message::<MinPk>(&private, b"", b"test message");
    let encoded = g2_signature.encode();
    let signature = Signature::<MinPk>::decode(encoded).expect("valid signature");

    let finalized = Finalization {
        proposal,
        certificate: BlsCertificate::<MinPk> {
            signers: commonware_cryptography::certificate::Signers::from(
                3,
                [0, 1, 2].map(Participant::new),
            ),
            signature: signature.into(),
        },
    };

    summit_types::FinalizedHeader::new(header, finalized, 3)
        .expect("test finalized header should be payload-bound")
}
