use crate::engine::Engine;
use crate::test_harness::common;
use crate::test_harness::common::{
    DEFAULT_BLOCKS_PER_EPOCH, SimulatedOracle, get_default_engine_config, get_initial_state,
};
use crate::test_harness::mock_engine_client::MockEngineNetworkBuilder;
use commonware_cryptography::{Signer, bls12381};
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated;
use commonware_p2p::simulated::{Link, Network};
use commonware_runtime::deterministic::Runner;
use commonware_runtime::{Clock, Metrics, Runner as _, deterministic};
use commonware_utils::{NZUsize, from_hex_formatted};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashSet;
use std::time::Duration;
use summit_types::ext_private_key::{ExtPrivateKey, derive_child_public};
use summit_types::{PrivateKey, keystore::KeyStore};

#[test_traced("INFO")]
fn test_observer_reaches_end_height() {
    // Spin up a network of validators (observers_per_validator > 0 so each validator
    // registers observer-derived pubkeys as secondary peers), then add an observer
    // node whose p2p identity is derived from validator[0]'s node key. Verify the
    // observer reaches the same finalization height as the validators.
    let n_validators: u32 = 4;
    let observers_per_validator: u32 = 3;
    let observer_index: u32 = 0;

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let total_nodes = n_validators + 1;
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(total_nodes as usize * 10),
            },
        );
        let stop_height = 2 * DEFAULT_BLOCKS_PER_EPOCH;
        network.start();

        // Generate validator key material.
        let mut validator_key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n_validators {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            validators.push((node_key.public_key(), consensus_key.public_key()));
            validator_key_stores.push(KeyStore {
                node_key,
                consensus_key,
            });
        }
        validators.sort_by(|a, b| a.0.cmp(&b.0));
        validator_key_stores.sort_by(|a, b| a.node_key.public_key().cmp(&b.node_key.public_key()));
        let validator_pubkeys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();

        // Derive the observer's p2p identity from validator[0]'s master key.
        let master_priv_key = validator_key_stores[0].node_key.clone();
        let master_consensus_key = validator_key_stores[0].consensus_key.clone();
        let master_pub_key = master_priv_key.public_key();
        // Must match the namespace the nodes run with (below), so the derived observer
        // identity matches the finalizer's authorized observer set (#335).
        let observer_namespace = b"_SUMMIT";
        let observer_signer = ExtPrivateKey::derive_child_signer(
            &master_priv_key,
            observer_namespace,
            observer_index,
        );
        let observer_pubkey = observer_signer.public_key();
        assert_eq!(
            observer_pubkey,
            derive_child_public(master_pub_key.clone(), observer_namespace, observer_index),
            "signer and public-only derivation must agree"
        );

        // Register validators + observer with the simulated p2p network.
        let mut all_pubkeys = validator_pubkeys.clone();
        all_pubkeys.push(observer_pubkey.clone());
        let mut registrations = common::register_validators(&oracle, &all_pubkeys).await;
        common::link_validators(&mut oracle, &all_pubkeys, link.clone(), None).await;

        // Shared genesis + engine client network.
        let genesis_hash = from_hex_formatted(common::GENESIS_HASH).expect("genesis hash hex");
        let genesis_hash: [u8; 32] = genesis_hash.try_into().expect("genesis hash len");
        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        initial_state.set_observers_per_validator(observers_per_validator);

        // Start validator engines with observers_per_validator set so the finalizer
        // authorizes the observer's derived pubkey as a secondary peer.
        for key_store in validator_key_stores.into_iter() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            let engine_client = engine_client_network.create_client(uid.clone());
            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                String::from("_SUMMIT"),
                key_store,
                validators.clone(),
                initial_state.clone(),
            );

            let engine = Engine::new(context.with_label(&uid), config).await;

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Build the observer engine from a validator keystore. The observer must
        // still run verifier-only consensus even though the BLS key can sign.
        let observer_uid = format!("observer_{observer_pubkey}");
        let observer_engine_client = engine_client_network.create_client(observer_uid.clone());
        let observer_key_store = KeyStore {
            node_key: observer_signer,
            consensus_key: master_consensus_key,
        };
        let mut observer_config = get_default_engine_config(
            observer_engine_client,
            SimulatedOracle::new(oracle.clone()),
            observer_uid.clone(),
            genesis_hash,
            String::from("_SUMMIT"),
            observer_key_store,
            validators.clone(),
            initial_state.clone(),
        );
        observer_config.force_verifier_only = true;
        let observer_engine = Engine::new(context.with_label(&observer_uid), observer_config).await;
        let (pending, recovered, resolver, orchestrator, broadcast) =
            registrations.remove(&observer_pubkey).unwrap();
        observer_engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // Poll metrics until every node (validators + observer) reaches stop_height.
        let mut nodes_finished = HashSet::new();
        loop {
            let metrics = context.encode();
            let mut success = false;
            for line in metrics.lines() {
                if !(line.starts_with("validator_") || line.starts_with("observer_")) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                if metric.ends_with("_peers_blocked") {
                    assert_eq!(
                        value.parse::<u64>().unwrap(),
                        0,
                        "no node should have blocked peers"
                    );
                }
                if metric.ends_with("finalizer_height")
                    && value.parse::<u64>().unwrap() >= stop_height
                {
                    nodes_finished.insert(metric.to_string());
                    if nodes_finished.len() as u32 >= total_nodes {
                        success = true;
                        break;
                    }
                }
            }
            if success {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Sanity: the observer-specific metric was among the finished set.
        let observer_metric_prefix = observer_uid.clone();
        assert!(
            nodes_finished
                .iter()
                .any(|m| m.starts_with(&observer_metric_prefix)),
            "observer node did not reach stop_height"
        );

        context.auditor().state()
    });
}

#[test_traced("INFO")]
fn test_observer_backfills_from_parent_validator() {
    // Regression test for the resolver self-exclusion bug: production startup
    // hands the engine the master keystore while p2p runs as the derived child
    // key, so the resolver treated the parent validator's key as "me" and
    // excluded the parent from backfill. Mirror that wiring here (master
    // keystore + observer_network_key override, unlike the test above which
    // puts the child signer in the keystore), late-join the observer, and link
    // it ONLY to its parent validator — the sole possible backfill source.
    let n_validators: u32 = 4;
    let observers_per_validator: u32 = 1;
    let observer_index: u32 = 0;

    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 1.0,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let total_nodes = n_validators + 1;
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(total_nodes as usize * 10),
            },
        );
        let join_height = DEFAULT_BLOCKS_PER_EPOCH / 2;
        let stop_height = 2 * DEFAULT_BLOCKS_PER_EPOCH;
        network.start();

        // Generate validator key material.
        let mut validator_key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n_validators {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            validators.push((node_key.public_key(), consensus_key.public_key()));
            validator_key_stores.push(KeyStore {
                node_key,
                consensus_key,
            });
        }
        validators.sort_by(|a, b| a.0.cmp(&b.0));
        validator_key_stores.sort_by(|a, b| a.node_key.public_key().cmp(&b.node_key.public_key()));
        let validator_pubkeys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();

        // The observer runs from the parent validator's master keystore (as in
        // production) with a child-derived p2p identity.
        let parent_key_store = KeyStore {
            node_key: validator_key_stores[0].node_key.clone(),
            consensus_key: validator_key_stores[0].consensus_key.clone(),
        };
        let parent_pubkey = parent_key_store.node_key.public_key();
        // Must match the namespace the nodes run with so the derived observer
        // identity matches the engine's namespace-bound child key (#335).
        let observer_namespace = b"_SUMMIT";
        let observer_pubkey =
            derive_child_public(parent_pubkey.clone(), observer_namespace, observer_index);

        // Register all nodes, but link the observer ONLY to its parent.
        let mut all_pubkeys = validator_pubkeys.clone();
        all_pubkeys.push(observer_pubkey.clone());
        let mut registrations = common::register_validators(&oracle, &all_pubkeys).await;
        common::link_validators(&mut oracle, &validator_pubkeys, link.clone(), None).await;
        common::join_validator(
            &mut oracle,
            &observer_pubkey,
            std::slice::from_ref(&parent_pubkey),
            link.clone(),
        )
        .await;

        // Shared genesis + engine client network.
        let genesis_hash = from_hex_formatted(common::GENESIS_HASH).expect("genesis hash hex");
        let genesis_hash: [u8; 32] = genesis_hash.try_into().expect("genesis hash len");
        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_stop_at(stop_height)
            .build();
        let mut initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        initial_state.set_observers_per_validator(observers_per_validator);

        // Start the validators.
        for key_store in validator_key_stores.into_iter() {
            let public_key = key_store.node_key.public_key();
            let uid = format!("validator_{public_key}");
            let engine_client = engine_client_network.create_client(uid.clone());
            let config = get_default_engine_config(
                engine_client,
                SimulatedOracle::new(oracle.clone()),
                uid.clone(),
                genesis_hash,
                String::from("_SUMMIT"),
                key_store,
                validators.clone(),
                initial_state.clone(),
            );

            let engine = Engine::new(context.with_label(&uid), config).await;

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();
            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // Let the validators advance past join_height so the observer has
        // history it can only obtain via resolver backfill from its parent.
        let max_polls = 300;
        let mut polls = 0;
        loop {
            let metrics = context.encode();
            let advanced = metrics
                .lines()
                .filter(|l| l.starts_with("validator_"))
                .filter(|l| {
                    let mut parts = l.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();
                    metric.ends_with("finalizer_height")
                        && value.parse::<u64>().unwrap() >= join_height
                })
                .count();
            if advanced as u32 >= n_validators {
                break;
            }
            polls += 1;
            assert!(polls < max_polls, "validators never reached join height");
            context.sleep(Duration::from_secs(1)).await;
        }

        // Late-join the observer with production-style wiring: master keystore,
        // verifier-only consensus, child key as the effective network identity.
        let observer_uid = format!("observer_{observer_pubkey}");
        let observer_engine_client = engine_client_network.create_client(observer_uid.clone());
        let mut observer_config = get_default_engine_config(
            observer_engine_client,
            SimulatedOracle::new(oracle.clone()),
            observer_uid.clone(),
            genesis_hash,
            String::from("_SUMMIT"),
            parent_key_store,
            validators.clone(),
            initial_state.clone(),
        );
        observer_config.force_verifier_only = true;
        observer_config.observer_network_key = Some(observer_pubkey.clone());
        let observer_engine = Engine::new(context.with_label(&observer_uid), observer_config).await;
        let (pending, recovered, resolver, orchestrator, broadcast) =
            registrations.remove(&observer_pubkey).unwrap();
        observer_engine.start(pending, recovered, resolver, orchestrator, broadcast);

        // The observer must backfill the missed blocks from its parent — the
        // only peer it is linked to — and reach stop_height.
        let observer_height_metric = format!("{observer_uid}_finalizer_height");
        let mut polls = 0;
        loop {
            let metrics = context.encode();
            let observer_done = metrics.lines().any(|l| {
                let mut parts = l.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                metric.ends_with(&observer_height_metric)
                    && value.parse::<u64>().unwrap() >= stop_height
            });
            if observer_done {
                break;
            }
            polls += 1;
            assert!(
                polls < max_polls,
                "observer did not catch up via its parent validator: \
                 resolver likely excluded the parent as self"
            );
            context.sleep(Duration::from_secs(1)).await;
        }

        context.auditor().state()
    });
}
