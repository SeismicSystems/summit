use super::*;
use alloy_eips::eip7685::Requests;
use alloy_primitives::Bytes;

/// A single-byte execution request (a bare type byte with no request_data)
/// mirrors the testnet PoC, where a malicious proposer replaces the request
/// list at height 10 with `vec![vec![1].into()]`.
///
/// Summit's verify layer must reject it as a block-level invalid payload rather
/// than relaying it to the execution client. seismic-reth's
/// `validate_execution_requests` rejects `len <= 1` as `EmptyExecutionRequest`,
/// and the resulting engine error is treated as fatal, shutting down every
/// validator instead of rejecting the block.
#[test_traced("INFO")]
fn test_single_byte_execution_request_block_is_rejected() {
    let n = 4;
    let min_stake = 32_000_000_000;
    let link = Link {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(10),
        success_rate: 0.98,
    };

    let cfg = deterministic::Config::default().with_seed(0);
    let executor = Runner::from(cfg);
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(n as usize * 10),
            },
        );

        network.start();

        let mut key_stores = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let node_key = PrivateKey::random(&mut rng);
            let node_public_key = node_key.public_key();
            let consensus_key = bls12381::PrivateKey::random(&mut rng);
            let consensus_public_key = consensus_key.public_key();
            let key_store = KeyStore {
                node_key,
                consensus_key,
            };
            key_stores.push(key_store);
            validators.push((node_public_key, consensus_public_key));
        }
        validators.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        key_stores.sort_by_key(|ks| ks.node_key.public_key());

        let node_public_keys: Vec<_> = validators.iter().map(|(pk, _)| pk.clone()).collect();
        let mut registrations = common::register_validators(&oracle, &node_public_keys).await;

        common::link_validators(&mut oracle, &node_public_keys, link, None).await;

        let genesis_hash =
            from_hex_formatted(common::GENESIS_HASH).expect("failed to decode genesis hash");
        let genesis_hash: [u8; 32] = genesis_hash
            .try_into()
            .expect("failed to convert genesis hash");

        // Mirror the testnet PoC: at height 10 every proposer authors a block
        // whose only execution request is a single withdrawal type byte.
        let malicious_height = 10;
        let mut execution_requests_map = HashMap::new();
        execution_requests_map.insert(
            malicious_height,
            Requests::from(vec![Bytes::from([0x01u8])]),
        );

        let engine_client_network = MockEngineNetworkBuilder::new(genesis_hash)
            .with_execution_requests(execution_requests_map)
            .build();
        let initial_state = get_initial_state(genesis_hash, &validators, None, None, min_stake);

        let mut public_keys = HashSet::new();
        let mut consensus_state_queries = HashMap::new();
        for (idx, key_store) in key_stores.into_iter().enumerate() {
            let public_key = key_store.node_key.public_key();
            public_keys.insert(public_key.clone());

            let uid = format!("validator_{public_key}");
            let namespace = String::from("_SUMMIT");

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

            let (pending, recovered, resolver, orchestrator, broadcast) =
                registrations.remove(&public_key).unwrap();

            engine.start(pending, recovered, resolver, orchestrator, broadcast);
        }

        // All blocks before the malicious one are normal; wait until every
        // validator finalizes the block just before it.
        let settle_height = malicious_height - 1;
        let mut height_reached = HashSet::new();
        loop {
            let metrics = context.encode();
            for line in metrics.lines() {
                if !line.starts_with("validator_") {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                if metric.ends_with("_peers_blocked") {
                    assert_eq!(value.parse::<u64>().unwrap(), 0);
                }
            }

            for (idx, query) in consensus_state_queries.iter() {
                if query.get_latest_height().await >= settle_height {
                    height_reached.insert(*idx);
                }
            }
            if height_reached.len() as u32 == n {
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        // Give the malicious height-10 block ample time to be proposed and,
        // absent the fix, finalized. The verify layer must reject it, so no
        // validator may advance past height 9.
        context.sleep(Duration::from_secs(30)).await;

        for (idx, query) in consensus_state_queries.iter() {
            let height = query.get_latest_height().await;
            assert_eq!(
                height, settle_height,
                "validator {idx} should reject the single-byte execution request block \
                 (height {malicious_height}) and remain at height {settle_height}, \
                 but finalized height {height}"
            );
        }

        context.auditor().state()
    })
}
