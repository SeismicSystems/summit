//use alto_types::{Finalized, Notarized};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{poly::{self, Poly}, group::{self, Share}, variant::MinPk},
    },
    //ed25519::{PublicKey, PrivateKey},

    PrivateKeyExt, Signer,
};

use summit_types::{PublicKey, PrivateKey};
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};
use commonware_runtime::{
    deterministic::{self, Runner},
    Clock, Metrics, Runner as _, Spawner,
};
use commonware_utils::{from_hex_formatted, quorum};
//use engine::{engine::Engine, config::EngineConfig};
use crate::{engine::Engine, config::EngineConfig};
use governor::Quota;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
};
use std::{time::Duration};
use alloy_signer::k256::elliptic_curve::rand_core::OsRng;
use anyhow::Context;
use crate::test_harness::mock_engine_client::MockEngineClient;

async fn link_validators(
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

async fn register_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[PublicKey],
) -> HashMap<
    PublicKey,
    (
        (Sender<PublicKey>, Receiver<PublicKey>),
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
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        let (broadcast_sender, broadcast_receiver) =
            oracle.register(validator.clone(), 3).await.unwrap();
        let (backfill_sender, backfill_receiver) =
            oracle.register(validator.clone(), 4).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
                (broadcast_sender, broadcast_receiver),
                (backfill_sender, backfill_receiver),
            ),
        );
    }
    registrations
}

pub fn all_online(n: u32, seed: u64, link: Link, required: u64) -> String {
    // Create context
    let threshold = quorum(n);
    let cfg = deterministic::Config::default().with_seed(seed);
    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
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

        // Derive threshold
        let (polynomial, shares) =
            ops::generate_shares::<_, MinPk>(&mut OsRng, None, n, threshold);

        // Create instances
        let mut public_keys = HashSet::new();
        for (idx, signer) in signers.into_iter().enumerate() {
            // Create signer context
            let public_key = signer.public_key();
            public_keys.insert(public_key.clone());

            // Configure engine
            let uid = format!("validator-{public_key}");
            // TODO: use different port for each engine?
            let engine_url = format!("http://0.0.0.0:{}", 8551);
            let engine_jwt = std::fs::read_to_string("../testnet/jwt.hex").context("failed to load jwt").expect("failed to read jwt");
            let genesis_hash = from_hex_formatted("0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616").expect("failed to decode genesis hash");
            let namespace = String::from("_SEISMIC_BFT");

            let engine_client = MockEngineClient {};

            let config = EngineConfig {
                engine_client,
                //blocker: oracle.control(public_key.clone()),
                partition_prefix: uid.clone(),
                //blocks_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
                //finalized_freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
                genesis_hash: genesis_hash.try_into().unwrap(),
                namespace,
                signer,
                polynomial: polynomial.clone(),
                share: shares[idx].clone(),
                participants: validators.clone(),
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
                //indexer: None,
            };
            let engine = Engine::new(context.with_label(&uid), config, oracle.control(public_key.clone())).await;

            // Get networking
            let (pending, recovered, resolver, broadcast, backfill) =
                registrations.remove(&public_key).unwrap();

            // Start engine
            engine.start(pending, recovered, resolver, broadcast, backfill);
        }

        // Poll metrics
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
                if metric.ends_with("_syncer_contiguous_height") {
                    let value = value.parse::<u64>().unwrap();
                    if value >= required {
                        success = true;
                        break;
                    }
                }
            }
            if success {
                break;
            }

            // Still waiting for all validators to complete
            context.sleep(Duration::from_secs(1)).await;
        }
        context.auditor().state()
    })
}
