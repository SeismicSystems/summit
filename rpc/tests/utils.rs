use commonware_codec::Encode as _;
use commonware_cryptography::{bls12381, ed25519};
use commonware_math::algebra::Random;
use futures::{StreamExt, channel::mpsc};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::fs;
use summit_finalizer::{FinalizerMailbox, FinalizerMessage};
use summit_types::account::ValidatorAccount;
use summit_types::{
    Block,
    consensus_state_query::{ConsensusStateRequest, ConsensusStateResponse},
    scheme::MultisigScheme,
};
use tokio::task::JoinHandle;

// Use the default Block type parameters and the MultisigScheme with ed25519 + MinPk
pub type TestScheme = MultisigScheme<ed25519::PrivateKey, bls12381::primitives::variant::MinPk>;
pub type TestBlock = Block;

/// Mock finalizer state that can be customized per test
#[derive(Clone, Debug)]
pub struct MockFinalizerState {
    pub latest_height: u64,
    pub latest_epoch: u64,
    pub checkpoints: HashMap<u64, Option<summit_types::checkpoint::Checkpoint>>,
    pub latest_checkpoint: Option<(Option<summit_types::checkpoint::Checkpoint>, u64)>,
    pub validator_balances: HashMap<summit_types::PublicKey, Option<u64>>,
    pub validator_accounts: HashMap<summit_types::PublicKey, Option<ValidatorAccount>>,
}

impl Default for MockFinalizerState {
    fn default() -> Self {
        Self {
            latest_height: 0,
            latest_epoch: 0,
            checkpoints: HashMap::new(),
            latest_checkpoint: Some((None, 0)),
            validator_balances: HashMap::new(),
            validator_accounts: HashMap::new(),
        }
    }
}

/// Creates a mock finalizer mailbox that responds to queries with test data
pub fn create_test_finalizer_mailbox(
    state: MockFinalizerState,
) -> (FinalizerMailbox<TestScheme, TestBlock>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<FinalizerMessage<TestScheme, TestBlock>>(100);

    let handle = tokio::spawn(async move {
        while let Some(msg) = rx.next().await {
            match msg {
                FinalizerMessage::QueryState { request, response } => match request {
                    ConsensusStateRequest::GetLatestHeight => {
                        let _ = response
                            .send(ConsensusStateResponse::LatestHeight(state.latest_height));
                    }
                    ConsensusStateRequest::GetLatestEpoch => {
                        let _ =
                            response.send(ConsensusStateResponse::LatestEpoch(state.latest_epoch));
                    }
                    ConsensusStateRequest::GetCheckpoint(epoch) => {
                        let checkpoint = state.checkpoints.get(&epoch).cloned().flatten();
                        let _ = response.send(ConsensusStateResponse::Checkpoint(checkpoint));
                    }
                    ConsensusStateRequest::GetLatestCheckpoint => {
                        let _ = response.send(ConsensusStateResponse::LatestCheckpoint(
                            state.latest_checkpoint.clone().unwrap_or((None, 0)),
                        ));
                    }
                    ConsensusStateRequest::GetValidatorBalance(public_key) => {
                        let balance = state.validator_balances.get(&public_key).cloned().flatten();
                        let _ = response.send(ConsensusStateResponse::ValidatorBalance(balance));
                    }
                    ConsensusStateRequest::GetValidatorAccount(public_key) => {
                        let account = state.validator_accounts.get(&public_key).cloned().flatten();
                        let _ = response.send(ConsensusStateResponse::ValidatorAccount(account));
                    }
                },
                _ => {}
            }
        }
    });

    (FinalizerMailbox::new(tx), handle)
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
