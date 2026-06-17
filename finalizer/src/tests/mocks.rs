//! Mock implementations for finalizer tests.

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3, ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus,
    PayloadStatusEnum,
};
use commonware_consensus::simplex::scheme::bls12381_multisig;
use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381::primitives::{group, variant::MinPk};
use commonware_cryptography::{Signer as _, ed25519};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::ordered::{BiMap, Map};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use summit_types::network_oracle::NetworkOracle;
use summit_types::{Block, Digest, EngineClient, EngineClientError, PublicKey};

pub type MultisigScheme = bls12381_multisig::Scheme<ed25519::PublicKey, MinPk>;

/// Creates BLS multisig schemes for testing finalization certificates.
pub fn create_test_schemes(num_validators: u32) -> Vec<MultisigScheme> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(12345);

    const NAMESPACE: &[u8] = b"test";

    // Generate ed25519 participants
    let mut participants = Vec::with_capacity(num_validators as usize);
    for i in 0..num_validators {
        let key = ed25519::PrivateKey::from_seed(i as u64);
        participants.push(key.public_key());
    }
    let participants = Map::from_iter_dedup(participants.into_iter().map(|p| (p, ())));
    let participants = participants.into_keys();

    // Generate BLS keys
    let mut bls_privates = Vec::with_capacity(num_validators as usize);
    for _ in 0..num_validators {
        bls_privates.push(group::Private::random(&mut rng));
    }
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<MinPk>(sk))
        .collect();

    let signers_map = Map::from_iter_dedup(participants.clone().into_iter().zip(bls_public));
    let signers = BiMap::try_from(signers_map).expect("BLS public keys should be unique");

    bls_privates
        .into_iter()
        .filter_map(|sk| bls12381_multisig::Scheme::signer(NAMESPACE, signers.clone(), sk))
        .collect()
}

/// Creates a finalization certificate for a block.
pub fn make_finalization(
    block_digest: Digest,
    height: u64,
    parent_view: u64,
    schemes: &[MultisigScheme],
    quorum: usize,
) -> Finalization<MultisigScheme, Digest> {
    let proposal = Proposal {
        round: Round::new(Epoch::new(0), View::new(height)),
        parent: View::new(parent_view),
        payload: block_digest,
    };

    let finalizes: Vec<_> = schemes
        .iter()
        .take(quorum)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect();

    Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
}

/// Minimal mock EngineClient that accepts all blocks.
/// Supports queuing override responses for check_payload and commit_hash
/// to simulate SYNCING behavior during tests.
#[derive(Clone)]
pub struct MockEngineClient {
    check_payload_overrides: Arc<Mutex<VecDeque<PayloadStatus>>>,
    commit_hash_overrides: Arc<Mutex<VecDeque<ForkchoiceUpdated>>>,
    check_payload_calls: Arc<AtomicU64>,
    commit_hash_fails: Arc<AtomicBool>,
}

impl MockEngineClient {
    pub fn new() -> Self {
        Self {
            check_payload_overrides: Arc::new(Mutex::new(VecDeque::new())),
            commit_hash_overrides: Arc::new(Mutex::new(VecDeque::new())),
            check_payload_calls: Arc::new(AtomicU64::new(0)),
            commit_hash_fails: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Make every subsequent `commit_hash` call return a non-retryable error,
    /// simulating a failed forkchoice commit. Used to drive the finalizer's
    /// fatal-shutdown path at an epoch boundary.
    #[allow(unused)]
    pub fn fail_commit_hash(&self) {
        self.commit_hash_fails.store(true, Ordering::SeqCst);
    }

    /// Number of times `check_payload` has been invoked. Used to detect whether a
    /// finalized block was (re-)executed against the execution layer.
    #[allow(unused)]
    pub fn check_payload_call_count(&self) -> u64 {
        self.check_payload_calls.load(Ordering::SeqCst)
    }

    /// Queue SYNCING responses for check_payload. After these are consumed,
    /// check_payload falls back to returning VALID.
    #[allow(unused)]
    pub fn queue_check_payload_syncing(&self, count: usize) {
        let mut overrides = self.check_payload_overrides.lock().unwrap();
        for _ in 0..count {
            overrides.push_back(PayloadStatus::new(PayloadStatusEnum::Syncing, None));
        }
    }

    /// Queue SYNCING responses for commit_hash. After these are consumed,
    /// commit_hash falls back to returning VALID.
    #[allow(unused)]
    pub fn queue_commit_hash_syncing(&self, count: usize) {
        let mut overrides = self.commit_hash_overrides.lock().unwrap();
        for _ in 0..count {
            overrides.push_back(ForkchoiceUpdated {
                payload_status: PayloadStatus::new(PayloadStatusEnum::Syncing, None),
                payload_id: None,
            });
        }
    }
}

impl Default for MockEngineClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineClient for MockEngineClient {
    #[allow(unused_variables)]
    async fn start_building_block(
        &mut self,
        _fork_choice_state: ForkchoiceState,
        _timestamp: u64,
        _withdrawals: Vec<alloy_eips::eip4895::Withdrawal>,
        _suggested_fee_recipient: Address,
        _parent_beacon_block_root: Option<FixedBytes<32>>,
        #[cfg(feature = "bench")] height: u64,
    ) -> Result<Option<PayloadId>, summit_types::EngineClientError> {
        Ok(Some(PayloadId::new([0u8; 8])))
    }

    async fn get_payload(
        &mut self,
        _payload_id: PayloadId,
    ) -> Result<ExecutionPayloadEnvelopeV4, summit_types::EngineClientError> {
        Ok(ExecutionPayloadEnvelopeV4 {
            envelope_inner: ExecutionPayloadEnvelopeV3 {
                execution_payload: ExecutionPayloadV3 {
                    payload_inner: ExecutionPayloadV2 {
                        payload_inner: ExecutionPayloadV1 {
                            base_fee_per_gas: U256::from(1000000000u64),
                            block_number: 0,
                            block_hash: [0u8; 32].into(),
                            logs_bloom: Default::default(),
                            extra_data: Default::default(),
                            gas_limit: 30000000,
                            gas_used: 0,
                            timestamp: 0,
                            fee_recipient: Default::default(),
                            parent_hash: [0u8; 32].into(),
                            prev_randao: Default::default(),
                            receipts_root: Default::default(),
                            state_root: Default::default(),
                            transactions: Vec::new(),
                        },
                        withdrawals: Vec::new().into(),
                    },
                    blob_gas_used: 0,
                    excess_blob_gas: 0,
                },
                block_value: U256::ZERO,
                blobs_bundle: Default::default(),
                should_override_builder: false,
            },
            execution_requests: Default::default(),
        })
    }

    async fn check_payload(
        &mut self,
        _block: &Block,
    ) -> Result<PayloadStatus, summit_types::EngineClientError> {
        self.check_payload_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(override_status) = self.check_payload_overrides.lock().unwrap().pop_front() {
            return Ok(override_status);
        }
        Ok(PayloadStatus {
            status: PayloadStatusEnum::Valid,
            latest_valid_hash: Some([0u8; 32].into()),
        })
    }

    async fn commit_hash(
        &mut self,
        _fork_choice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdated, summit_types::EngineClientError> {
        if self.commit_hash_fails.load(Ordering::SeqCst) {
            return Err(EngineClientError::custom("injected commit_hash failure"));
        }
        if let Some(override_response) = self.commit_hash_overrides.lock().unwrap().pop_front() {
            return Ok(override_response);
        }
        Ok(ForkchoiceUpdated {
            payload_status: PayloadStatus {
                status: PayloadStatusEnum::Valid,
                latest_valid_hash: Some([0u8; 32].into()),
            },
            payload_id: None,
        })
    }
}

/// Minimal mock NetworkOracle
#[derive(Clone)]
pub struct MockNetworkOracle;

impl NetworkOracle<PublicKey> for MockNetworkOracle {
    async fn track(&mut self, _index: u64, _primary: Vec<PublicKey>, _secondary: Vec<PublicKey>) {}
}

impl commonware_p2p::Blocker for MockNetworkOracle {
    type PublicKey = PublicKey;
    async fn block(&mut self, _public_key: Self::PublicKey) {}
}

/// A single recorded `track` call: the epoch and the peer tiers handed to the
/// P2P oracle.
#[derive(Clone)]
pub struct TrackCall {
    pub index: u64,
    pub primary: Vec<PublicKey>,
    pub secondary: Vec<PublicKey>,
}

/// A NetworkOracle that records every `track` call so tests can assert how
/// validators are tiered (primary = resolver backfill sources + outbound dial,
/// secondary = connectable-only).
#[derive(Clone, Default)]
pub struct RecordingNetworkOracle {
    pub calls: Arc<Mutex<Vec<TrackCall>>>,
}

impl RecordingNetworkOracle {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NetworkOracle<PublicKey> for RecordingNetworkOracle {
    async fn track(&mut self, index: u64, primary: Vec<PublicKey>, secondary: Vec<PublicKey>) {
        self.calls.lock().unwrap().push(TrackCall {
            index,
            primary,
            secondary,
        });
    }
}

impl commonware_p2p::Blocker for RecordingNetworkOracle {
    type PublicKey = PublicKey;
    async fn block(&mut self, _public_key: Self::PublicKey) {}
}
