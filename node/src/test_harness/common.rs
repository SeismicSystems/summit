use commonware_cryptography::{
    PrivateKeyExt, Signer,
    bls12381::{
        dkg::ops,
        primitives::{group::Share, poly::Poly, variant::MinPk},
    },
};

use crate::test_harness::mock_engine_client::MockEngineNetwork;
use crate::{config::EngineConfig, engine::Engine};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{Address, Bytes};
use alloy_signer::k256::elliptic_curve::rand_core::OsRng;
use commonware_codec::Write;
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};
use commonware_runtime::{
    Clock, Metrics, Runner as _,
    deterministic::{self, Runner},
};
use commonware_utils::{from_hex_formatted, quorum};
use governor::Quota;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
};
use summit_application::engine_client::EngineClient;
use summit_types::execution_request::{DepositRequest, ExecutionRequest, WithdrawalRequest};
use summit_types::{Identity, PrivateKey, PublicKey};

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

pub async fn register_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[PublicKey],
) -> HashMap<
    PublicKey,
    (
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
        (Sender<PublicKey>, Receiver<PublicKey>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (broadcast_sender, broadcast_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        let (backfill_sender, backfill_receiver) =
            oracle.register(validator.clone(), 3).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (resolver_sender, resolver_receiver),
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
    let threshold = quorum(n);
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        // Create simulated network
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
            },
        );

        // Start network
        network.start();

        // Register participants
        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let signer = PrivateKey::from_seed(i as u64);
            let pk = signer.public_key();
            signers.push(signer);
            validators.push(pk);
        }
        validators.sort();
        signers.sort_by_key(|s| s.public_key());
        let mut registrations = register_validators(&mut oracle, &validators).await;

        // Link all validators
        link_validators(&mut oracle, &validators, link, None).await;

        // Create the engine clients
        let genesis_hash = from_hex_formatted(GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");
        let engine_client_network = MockEngineNetwork::new(genesis_hash);

        // Derive threshold
        let (polynomial, shares) = ops::generate_shares::<_, MinPk>(&mut OsRng, None, n, threshold);

        // Create instances
        let mut public_keys = HashSet::new();
        for (idx, signer) in signers.into_iter().enumerate() {
            // Create signer context
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = engine_client_network.create_client(uid.clone());

            let config = get_default_engine_config(
                engine_client,
                uid.clone(),
                genesis_hash,
                namespace,
                signer,
                polynomial.clone(),
                shares[idx].clone(),
                validators.clone(),
            );

            let engine = Engine::new(context.with_label(&uid), config).await;

            // Get networking
            let (pending, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, resolver, broadcast, backfill);
        }

        // Poll metrics
        let mut num_nodes_finished = 0;
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
                    if value >= stop_height {
                        num_nodes_finished += 1;
                        if num_nodes_finished == n {
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
                    .verify_consensus(Some(stop_height))
                    .is_ok()
            );
        }

        context.auditor().state()
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

/// Create a single DepositRequest for testing
///
/// # Arguments
/// * `seed` - The seed value used to generate deterministic but unique keys
/// * `amount` - The deposit amount in gwei
///
/// # Returns
/// * `DepositRequest` - A single deposit request with valid test data
pub fn create_deposit_request(seed: u64, amount: u64) -> DepositRequest {
    // Create valid Eth1 withdrawal credentials: 0x01 + 11 zero bytes + 20-byte address
    let mut withdrawal_credentials = [0u8; 32];
    withdrawal_credentials[0] = 0x01; // Eth1 withdrawal prefix
    // Use seed-based address pattern for the last 20 bytes
    for j in 0..20 {
        withdrawal_credentials[12 + j] = ((seed + j as u64) % 256) as u8;
    }

    // Create deterministic but seed-based keys
    // Generate a valid ED25519 private key using the seed
    let ed25519_private_key = PrivateKey::from_seed(seed);
    let pubkey = ed25519_private_key.public_key();

    let mut signature = [0u8; 64];
    for j in 0..64 {
        signature[j] = ((seed + j as u64 + 81) % 256) as u8;
    }

    DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        index: seed,
    }
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
/// * `polynomial` - BLS12-381 polynomial for threshold cryptography
/// * `share` - BLS12-381 cryptographic share for threshold operations
/// * `participants` - Vector of participant public keys
///
/// # Returns
/// * `EngineConfig<C>` - A fully configured engine config with sensible defaults for testing
pub fn get_default_engine_config<C: EngineClient>(
    engine_client: C,
    partition_prefix: String,
    genesis_hash: [u8; 32],
    namespace: String,
    signer: PrivateKey,
    polynomial: Poly<Identity>,
    share: Share,
    participants: Vec<PublicKey>,
) -> EngineConfig<C> {
    EngineConfig {
        engine_client,
        partition_prefix,
        genesis_hash,
        namespace,
        signer,
        polynomial,
        share,
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
    }
}
