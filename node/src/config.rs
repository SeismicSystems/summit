use crate::keys::read_keys_from_keystore;
use anyhow::{Context, Result};
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381;
use commonware_utils::from_hex_formatted;
use governor::Quota;
use std::{num::NonZeroU32, time::Duration};
use summit_types::consensus_state::ConsensusState;
use summit_types::keystore::KeyStore;
use summit_types::network_oracle::NetworkOracle;
use summit_types::{EngineClient, Genesis, PrivateKey, PublicKey};
use zeroize::ZeroizeOnDrop;
/* DEFAULTS */
pub const PENDING_CHANNEL: u64 = 0;
pub const RECOVERED_CHANNEL: u64 = 1;
pub const RESOLVER_CHANNEL: u64 = 2;
pub const ORCHESTRATOR_CHANNEL: u64 = 3;
pub const BROADCASTER_CHANNEL: u64 = 4;
pub const BACKFILLER_CHANNEL: u64 = 5;
pub const MAILBOX_SIZE: usize = 16384;

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const FETCH_CONCURRENT: usize = 4;
const MAX_FETCH_COUNT: usize = 16;
const MAX_FETCH_SIZE: usize = 512 * 1024;
const DEQUE_SIZE: usize = 10;
pub const MESSAGE_BACKLOG: usize = 16384;
const BACKFILL_QUOTA: u32 = 10; // in seconds
const FETCH_RATE_P2P: u32 = 128; // in seconds

pub struct EngineConfig<C: EngineClient, S: Signer + ZeroizeOnDrop, O: NetworkOracle<S::PublicKey>>
{
    pub engine_client: C,
    pub partition_prefix: String,
    pub key_store: KeyStore<S>,
    pub participants: Vec<(PublicKey, bls12381::PublicKey)>,
    pub mailbox_size: usize,
    pub backfill_quota: Quota,
    pub deque_size: usize,

    pub oracle: O,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub max_fetch_count: usize,
    pub _max_fetch_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_rate_per_peer: Quota,

    pub namespace: String,
    pub genesis_hash: [u8; 32],

    pub initial_state: ConsensusState,
    pub archive_mode: bool,
}

impl<C: EngineClient, S: Signer + ZeroizeOnDrop, O: NetworkOracle<S::PublicKey>>
    EngineConfig<C, S, O>
{
    pub fn get_engine_config(
        engine_client: C,
        oracle: O,
        key_store: KeyStore<S>,
        participants: Vec<(PublicKey, bls12381::PublicKey)>,
        db_prefix: String,
        genesis: &Genesis,
        initial_state: ConsensusState,
        archive_mode: bool,
    ) -> Result<Self> {
        Ok(Self {
            engine_client,
            partition_prefix: db_prefix,
            key_store,
            participants,
            oracle,
            mailbox_size: MAILBOX_SIZE,
            backfill_quota: Quota::per_second(NonZeroU32::new(BACKFILL_QUOTA).unwrap()),
            deque_size: DEQUE_SIZE,
            leader_timeout: Duration::from_millis(genesis.leader_timeout_ms),
            notarization_timeout: Duration::from_millis(genesis.notarization_timeout_ms),
            nullify_retry: Duration::from_millis(genesis.nullify_timeout_ms),
            fetch_timeout: FETCH_TIMEOUT,
            activity_timeout: genesis.activity_timeout_views,
            skip_timeout: genesis.skip_timeout_views,
            max_fetch_count: MAX_FETCH_COUNT,
            _max_fetch_size: MAX_FETCH_SIZE,
            fetch_concurrent: FETCH_CONCURRENT,
            fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(FETCH_RATE_P2P).unwrap()),
            namespace: genesis.namespace.clone(),
            genesis_hash: from_hex_formatted(&genesis.eth_genesis_hash)
                .map(|hash_bytes| hash_bytes.try_into())
                .expect("bad eth_genesis_hash")
                .expect("bad eth_genesis_hash"),
            initial_state,
            archive_mode,
        })
    }
}

pub(crate) fn load_key_store(key_store_path: &str) -> Result<KeyStore<PrivateKey>> {
    match read_keys_from_keystore(key_store_path).context("failed to load key store") {
        Ok((node_key, consensus_key)) => Ok(KeyStore {
            node_key,
            consensus_key,
        }),
        Err(e) => Err(e),
    }
}

pub(crate) fn expect_key_store(key_store_path: &str) -> KeyStore<PrivateKey> {
    match load_key_store(key_store_path) {
        Ok(key_store) => key_store,
        Err(e) => panic!("Key store error @ path {key_store_path}: {e}\n"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::expect_key_store;

    #[test]
    fn test_expect_keys_node0() {
        let keys_dir = {
            let node_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let repo_root = node_crate_dir.parent().unwrap();
            repo_root.join("testnet/node0")
        };
        expect_key_store(&keys_dir.to_string_lossy());
    }

    #[test]
    #[should_panic]
    fn test_expect_keys_error_msg() {
        expect_key_store("missing-key-store.pem");
    }
}
