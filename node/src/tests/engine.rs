//! Engine-level configuration tests.

use crate::engine::Engine;
use crate::test_harness::common::{
    GENESIS_HASH, SimulatedOracle, get_default_engine_config, get_initial_state,
};
use crate::test_harness::mock_engine_client::MockEngineNetwork;
use commonware_cryptography::{Signer, bls12381};
use commonware_macros::test_traced;
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{self, Network};
use commonware_runtime::{
    Metrics, Runner as _,
    deterministic::{self, Runner},
};
use commonware_utils::{NZUsize, from_hex_formatted};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Duration;
use summit_types::PrivateKey;
use summit_types::keystore::KeyStore;

/// Regression test: the backfill resolver must inherit
/// [`EngineConfig::fetch_timeout`](crate::config::EngineConfig::fetch_timeout) instead of
/// hard-coding its active-request timeout. Commonware's resolver drops in-flight requests
/// when the timeout fires and discards responses that arrive afterwards, so a hard-coded
/// timeout shorter than the configured one prevents catching up from valid finalized
/// history under slow storage/network conditions.
#[test_traced("INFO")]
fn test_backfill_resolver_inherits_fetch_timeout() {
    let executor = Runner::from(deterministic::Config::default());
    executor.start(|context| async move {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(10),
            },
        );
        network.start();

        let mut rng = StdRng::seed_from_u64(0);
        let node_key = PrivateKey::random(&mut rng);
        let consensus_key = bls12381::PrivateKey::random(&mut rng);
        let validators = vec![(node_key.public_key(), consensus_key.public_key())];
        let key_store = KeyStore {
            node_key,
            consensus_key,
        };

        let genesis_hash: [u8; 32] = from_hex_formatted(GENESIS_HASH)
            .expect("failed to decode genesis hash")
            .try_into()
            .expect("failed to convert genesis hash");
        let initial_state =
            get_initial_state(genesis_hash, &validators, None, None, 32_000_000_000);
        let engine_client =
            MockEngineNetwork::new(genesis_hash, None).create_client("engine_config_test".into());

        let mut config = get_default_engine_config(
            engine_client,
            SimulatedOracle::new(oracle),
            "engine_config_test".into(),
            genesis_hash,
            "_SUMMIT".into(),
            key_store,
            validators,
            initial_state,
        );
        let fetch_timeout = Duration::from_secs(7);
        config.fetch_timeout = fetch_timeout;

        let engine = Engine::new(context.with_label("engine"), config).await;
        let resolver_config = engine.backfill_resolver_config();
        assert_eq!(resolver_config.timeout, fetch_timeout);
    });
}
