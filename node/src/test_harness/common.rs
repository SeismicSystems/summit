use commonware_cryptography::{Hasher, PrivateKeyExt, Sha256, Signer, bls12381};

use crate::engine::{PROTOCOL_VERSION, VALIDATOR_MINIMUM_STAKE};
use crate::test_harness::mock_engine_client::MockEngineNetwork;
use crate::{config::EngineConfig, engine::Engine};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::Write;
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};
use commonware_p2p::{Blocker, Manager};
use commonware_runtime::{
    Clock, Metrics, Runner as _,
    deterministic::{self, Runner},
};
use commonware_utils::from_hex_formatted;
use governor::Quota;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
};
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::consensus_state::ConsensusState;
use summit_types::execution_request::{DepositRequest, ExecutionRequest, WithdrawalRequest};
use summit_types::keystore::KeyStore;
use summit_types::network_oracle::NetworkOracle;
use summit_types::{Digest, EngineClient, PrivateKey, PublicKey};

pub const GENESIS_HASH: &str = "0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616";

pub async fn link_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[PublicKey],
    link: Link,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            // Ignore self
            if v2 == v1 {
                continue;
            }

            // Restrict to certain connections
            if let Some(f) = restrict_to {
                if !f(validators.len(), i1, i2) {
                    continue;
                }
            }

            // Add link
            oracle
                .add_link(v1.clone(), v2.clone(), link.clone())
                .await
                .unwrap();
        }
    }
}

pub async fn join_validator(
    oracle: &mut Oracle<PublicKey>,
    validator: &PublicKey,
    existing_validators: &[PublicKey],
    link: Link,
) {
    for existing in existing_validators {
        // Skip self
        if existing == validator {
            continue;
        }

        // Add links in both directions
        oracle
            .add_link(validator.clone(), existing.clone(), link.clone())
            .await
            .unwrap();
        oracle
            .add_link(existing.clone(), validator.clone(), link.clone())
            .await
            .unwrap();
    }
}

pub async fn register_validators(
    oracle: &Oracle<PublicKey>,
    validators: &[PublicKey],
) -> HashMap<
    PublicKey,
    (
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let mut control = oracle.control(validator.clone());
        let (pending_sender, pending_receiver) = control.register(0).await.unwrap();
        let (recovered_sender, recovered_receiver) = control.register(1).await.unwrap();
        let (resolver_sender, resolver_receiver) = control.register(2).await.unwrap();
        let (orchestrator_sender, orchestrator_receiver) = control.register(3).await.unwrap();
        let (broadcast_sender, broadcast_receiver) = control.register(4).await.unwrap();
        let (backfill_sender, backfill_receiver) = control.register(5).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
                (orchestrator_sender, orchestrator_receiver),
                (broadcast_sender, broadcast_receiver),
                (backfill_sender, backfill_receiver),
            ),
        );
    }
    registrations
}

pub fn run_until_height(
    n: u32,
    seed: u64,
    link: Link,
    stop_height: u64,
    verify_consensus: bool,
) -> String {
    // Create context
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: Some(n as usize * 10), // Each engine may subscribe multiple times
            },
        );

        // Start network
        network.start();

        // Register participants
        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let node_key = PrivateKey::from_seed(i as u64);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::from_seed(i as u64);
            let consensus_public_key = consensus_key.public_key();
            let key_store = KeyStore {
                node_key,
                consensus_key,
            };
            key_stores.push(key_store);
            validators.push((node_public_key, consensus_public_key));
        }
        validators.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        key_stores.sort_by(|lhs, rhs| lhs.node_key.public_key().cmp(&rhs.node_key.public_key()));

        let node_public_keys: Vec<PublicKey> =
            validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = register_validators(&oracle, &node_public_keys).await;

        // Link all validators
        link_validators(&mut oracle, &node_public_keys, link, None).await;

        // Create the engine clients
        let genesis_hash = from_hex_formatted(GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");
        let engine_client_network = MockEngineNetwork::new(genesis_hash);
        let initial_state = get_initial_state(
            genesis_hash,
            &validators,
            None,
            None,
            VALIDATOR_MINIMUM_STAKE,
        );

        // Create instances
        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            // Create signer context
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                namespace,
                key_store,
                validators.clone(),
                initial_state.clone(),
            );

            let engine = Engine::new(context.with_label(&uid), config).await;
            consensus_state_queries.insert(idx, engine.finalizer_mailbox.clone());

            // Get networking
            let (pending, recovered, resolver, orchestrator, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(
                pending,
                recovered,
                resolver,
                orchestrator,
                broadcast,
                backfill,
            );
        }

        // Poll metrics
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();

            // Iterate over all lines
            let mut success = false;
            for line in metrics.lines() {
                // Ensure it is a metrics line
                if !line.starts_with("validator-") {
                    continue;
                }

                // Split metric and value
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                // If ends with peers_blocked, ensure it is zero
                if metric.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                // If ends with contiguous_height, ensure it is at least required_container
                if metric.ends_with("finalizer_height") {
                    let value = value.parse::<u64>().unwrap();
                    if value == stop_height {
                        nodes_finished.insert(metric.to_string());
                        if nodes_finished.len() as u32 == n {
                            success = true;
                            break;
                        }
                    }
                }
            }
            if success {
                break;
            }

            // Still waiting for all validators to complete
            context.sleep(Duration::from_secs(1)).await;
        }

        if verify_consensus {
            // Check that all nodes have the same canonical chain
            assert!(
                engine_client_network
                    .verify_consensus(None, Some(stop_height))
                    .is_ok()
            );
        }

        context.auditor().state()
    })
}

pub fn get_domain() -> Digest {
    Sha256::hash(&PROTOCOL_VERSION.to_le_bytes())
}

pub fn get_initial_state(
    genesis_hash: [u8; 32],
    committee: &Vec<(PublicKey, bls12381::PublicKey)>,
    withdrawal_credentials: Option<&Vec<Address>>,
    checkpoint: Option<ConsensusState>,
    balance: u64,
) -> ConsensusState {
    let addresses = vec![Address::ZERO; committee.len()];
    let addresses = withdrawal_credentials.unwrap_or(&addresses);
    let genesis_hash: B256 = genesis_hash.into();
    checkpoint.unwrap_or_else(|| {
        let forkchoice = ForkchoiceState {
            head_block_hash: genesis_hash,
            safe_block_hash: genesis_hash,
            finalized_block_hash: genesis_hash,
        };
        let mut state = ConsensusState::new(forkchoice);
        // Add the genesis nodes to the consensus state with the minimum stake balance.
        for ((node_pubkey, consensus_pubkey), address) in committee.iter().zip(addresses.iter()) {
            let pubkey_bytes: [u8; 32] = node_pubkey
                .as_ref()
                .try_into()
                .expect("Public key must be 32 bytes");
            let account = ValidatorAccount {
                consensus_public_key: consensus_pubkey.clone(),
                // TODO(matthias): we have to add a withdrawal address to the genesis
                withdrawal_credentials: *address,
                balance,
                pending_withdrawal_amount: 0,
                status: ValidatorStatus::Active,
                // TODO(matthias): this index is comes from the deposit contract.
                // Since there is no deposit transaction for the genesis nodes, the index will still be
                // 0 for the deposit contract. Right now we only use this index to avoid counting the same deposit request twice.
                // Since we set the index to 0 here, we cannot rely on the uniqueness. The first actual deposit request will have
                // index 0 as well.
                last_deposit_index: 0,
            };
            state.validator_accounts.insert(pubkey_bytes, account);
        }
        state
    })
}

/// Parse a substring from a metric name using XML-like tags
///
/// # Arguments
/// * `metric` - The metric name to parse from
/// * `tag` - The tag name to look for (e.g., "pubkey")
///
/// # Returns
/// * `Some(String)` if the tag is found and parsed successfully
/// * `None` if the tag is not found or parsing fails
/// ```
pub fn parse_metric_substring(metric: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    let start = metric.find(&start_tag)?;
    let end = metric.find(&end_tag)?;

    // Make sure end tag comes after start tag
    if end <= start {
        return None;
    }

    let substring_start = start + start_tag.len();
    Some(metric[substring_start..end].to_string())
}

/// Extracts the validator id from a metric string.
///
/// # Arguments
/// * `metric` - The metric name to parse from
///
/// # Returns
/// * `Some(String)` if the validator id is contained in the string
/// * `None` if the validator if doesn't exist
/// ```
pub fn extract_validator_id(metric: &str) -> Option<String> {
    let end = metric.find("_")?;
    Some(metric[..end].to_string())
}

/// Create a single DepositRequest for testing with valid ED25519 and BLS signatures
///
/// This function creates a test deposit request with all required fields, including
/// cryptographically valid signatures that can be verified against the deposit message.
///
/// # Arguments
/// * `index` - The deposit index value used for generating deterministic keys and in the signature
/// * `amount` - The deposit amount in gwei
/// * `domain` - The domain value used in the signature (typically genesis hash)
/// * `private_key` - Optional ED25519 private key to use; if None, generates deterministic key from index
/// * `withdrawal_credentials` - Optional withdrawal credentials; if None, generates Eth1 format credentials
///
/// # Returns
/// * `(DepositRequest, PrivateKey, bls12381::PrivateKey)` - A tuple containing:
///   - `DepositRequest` - A complete deposit request with valid signatures
///   - `PrivateKey` - The ED25519 private key used to sign the request
///   - `bls12381::PrivateKey` - The BLS private key used to sign the request
pub fn create_deposit_request(
    index: u64,
    amount: u64,
    domain: Digest,
    private_key: Option<PrivateKey>,
    withdrawal_credentials: Option<[u8; 32]>,
) -> (DepositRequest, PrivateKey, bls12381::PrivateKey) {
    let withdrawal_credentials = if let Some(withdrawal_credentials) = withdrawal_credentials {
        withdrawal_credentials
    } else {
        // Create valid Eth1 withdrawal credentials: 0x01 + 11 zero bytes + 20-byte address
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01; // Eth1 withdrawal prefix
        // Use seed-based address pattern for the last 20 bytes
        for j in 0..20 {
            withdrawal_credentials[12 + j] = ((index + j as u64) % 256) as u8;
        }
        withdrawal_credentials
    };

    // Generate node (ED25519) key
    let ed25519_private_key = if let Some(private_key) = private_key {
        private_key
    } else {
        PrivateKey::from_seed(index)
    };
    let node_pubkey = ed25519_private_key.public_key();

    // Generate consensus (BLS) key
    let bls_private_key = bls12381::PrivateKey::from_seed(index);
    let consensus_pubkey = bls_private_key.public_key();

    let mut deposit = DepositRequest {
        node_pubkey,
        consensus_pubkey,
        withdrawal_credentials,
        amount,
        node_signature: [0u8; 64],
        consensus_signature: [0u8; 96],
        index,
    };

    // Create the message to sign
    let message = deposit.as_message(domain);

    // Generate both signatures
    let node_signature_bytes = ed25519_private_key.sign(None, &message);
    deposit
        .node_signature
        .copy_from_slice(&node_signature_bytes);

    let consensus_signature_bytes = bls_private_key.sign(None, &message);
    deposit
        .consensus_signature
        .copy_from_slice(&consensus_signature_bytes);

    (deposit, ed25519_private_key, bls_private_key)
}

/// Create a single WithdrawalRequest for testing
///
/// # Arguments
/// * `source_address` - The address that initiated the withdrawal
/// * `validator_pubkey` - The validator BLS public key
/// * `amount` - The withdrawal amount in gwei
///
/// # Returns
/// * `WithdrawalRequest` - A withdrawal request with the specified data
pub fn create_withdrawal_request(
    source_address: Address,
    validator_pubkey: [u8; 32],
    amount: u64,
) -> WithdrawalRequest {
    WithdrawalRequest {
        source_address,
        validator_pubkey,
        amount,
    }
}

/// Convert a list of ExecutionRequests to Requests
///
/// # Arguments
/// * `execution_requests` - A vector of ExecutionRequest instances
///
/// # Returns
/// * `Requests` - The corresponding Requests value for use with the engine
pub fn execution_requests_to_requests(execution_requests: Vec<ExecutionRequest>) -> Requests {
    let mut requests_bytes = Vec::new();

    for execution_request in execution_requests {
        // Serialize the ExecutionRequest to bytes
        let mut request_bytes = Vec::new();
        execution_request.write(&mut request_bytes);
        requests_bytes.push(Bytes::from(request_bytes));
    }

    Requests::from(requests_bytes)
}

/// Create an EngineConfig with default values for testing
///
/// # Arguments
/// * `engine_client` - Generic engine client implementing the EngineClient trait
/// * `partition_prefix` - String identifier for partitioning (typically validator ID)
/// * `genesis_hash` - 32-byte array representing the genesis block hash
/// * `namespace` - String namespace identifier (typically "_SEISMIC_BFT")
/// * `signer` - Private key for signing operations
/// * `participants` - Vector of participant public keys
///
/// # Returns
/// * `EngineConfig<C>` - A fully configured engine config with sensible defaults for testing
pub fn get_default_engine_config<
    C: EngineClient,
    O: NetworkOracle<PublicKey> + Blocker<PublicKey = PublicKey> + Manager<PublicKey = PublicKey>,
>(
    engine_client: C,
    oracle: O,
    partition_prefix: String,
    genesis_hash: [u8; 32],
    namespace: String,
    key_store: KeyStore<PrivateKey>,
    participants: Vec<(PublicKey, bls12381::PublicKey)>,
    initial_state: ConsensusState,
) -> EngineConfig<C, PrivateKey, O> {
    // For tests, generate a dummy BLS key

    EngineConfig {
        engine_client,
        oracle,
        partition_prefix,
        genesis_hash,
        namespace,
        key_store,
        participants,
        mailbox_size: 1024,
        deque_size: 10,
        backfill_quota: Quota::per_second(NonZeroU32::new(10).unwrap()),
        leader_timeout: Duration::from_secs(1),
        notarization_timeout: Duration::from_secs(2),
        nullify_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        activity_timeout: 10,
        skip_timeout: 5,
        max_fetch_count: 10,
        _max_fetch_size: 1024 * 512,
        fetch_concurrent: 10,
        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(10).unwrap()),
        initial_state,
    }
}

#[derive(Clone, Debug)]
pub struct SimulatedOracle {
    inner: simulated::Manager<PublicKey>,
}

impl SimulatedOracle {
    pub fn new(oracle: Oracle<PublicKey>) -> Self {
        Self {
            inner: oracle.manager(),
        }
    }
}

impl NetworkOracle<PublicKey> for SimulatedOracle {
    async fn register(&mut self, index: u64, peers: Vec<PublicKey>) {
        self.inner
            .update(index, commonware_utils::set::Ordered::from(peers))
            .await
    }
}

impl Blocker for SimulatedOracle {
    type PublicKey = PublicKey;

    async fn block(&mut self, _public_key: Self::PublicKey) {
        // Simulated oracle doesn't support blocking individual peers
        // This is only used in production for misbehaving peers
    }
}

impl Manager for SimulatedOracle {
    type PublicKey = PublicKey;
    type Peers = commonware_utils::set::Ordered<PublicKey>;

    async fn update(&mut self, id: u64, peers: Self::Peers) {
        self.inner.update(id, peers).await
    }

    async fn peer_set(&mut self, id: u64) -> Option<Self::Peers> {
        self.inner.peer_set(id).await
    }

    async fn subscribe(
        &mut self,
    ) -> futures::channel::mpsc::UnboundedReceiver<(u64, Self::Peers, Self::Peers)> {
        self.inner.subscribe().await
    }
}
