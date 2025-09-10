use std::{num::NonZeroU32, time::Duration};

use anyhow::{Context, Result};
use commonware_codec::{Decode as _, DecodeExt as _};
use commonware_cryptography::bls12381::primitives::{
    group::{self, Share},
    poly::{self, Poly},
    variant::MinPk,
};
use commonware_utils::{from_hex_formatted, quorum};
use governor::Quota;
use summit_application::engine_client::EngineClient;
use summit_types::{Genesis, Identity, PrivateKey, PublicKey, utils::get_expanded_path};

use crate::keys::read_ed_key_from_path;

/* DEFAULTS */
pub const PENDING_CHANNEL: u32 = 0;
pub const RESOLVER_CHANNEL: u32 = 1;
pub const BROADCASTER_CHANNEL: u32 = 2;
pub const BACKFILLER_CHANNEL: u32 = 3;

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const FETCH_CONCURRENT: usize = 4;
const MAX_FETCH_COUNT: usize = 16;
const MAX_FETCH_SIZE: usize = 512 * 1024;
const MAILBOX_SIZE: usize = 16384;
const DEQUE_SIZE: usize = 10;
pub const MESSAGE_BACKLOG: usize = 16384;
const BACKFILL_QUOTA: u32 = 10; // in seconds
const FETCH_RATE_P2P: u32 = 128; // in seconds

pub struct EngineConfig<C: EngineClient> {
    pub engine_client: C,
    pub partition_prefix: String,
    pub signer: PrivateKey,
    pub participants: Vec<PublicKey>,
    pub mailbox_size: usize,
    pub backfill_quota: Quota,
    pub deque_size: usize,

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
    pub share: Share,
    pub polynomial: Poly<Identity>,
}

impl<C: EngineClient> EngineConfig<C> {
    pub fn get_engine_config(
        engine_client: C,
        signer: PrivateKey,
        share: Share,
        participants: Vec<PublicKey>,
        db_prefix: String,
        genesis: &Genesis,
    ) -> Result<Self> {
        // TODO(dalton): should we validate polynomial construction after we wait to load genesis?
        let polynomial = from_hex_formatted(&genesis.identity).expect("Could not parse polynomial");
        let threshold = quorum(participants.len() as u32);
        let polynomial =
            poly::Public::<MinPk>::decode_cfg(polynomial.as_ref(), &(threshold as usize))
                .expect("polynomial is invalid");
        Ok(Self {
            engine_client,
            partition_prefix: db_prefix,
            signer,
            participants,
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
            polynomial,
            share,
        })
    }
}

pub(crate) fn load_signer(key_path: &str) -> anyhow::Result<PrivateKey> {
    read_ed_key_from_path(key_path).context("failed to load signer key")
}

pub(crate) fn load_share(poly_share_path: &str) -> anyhow::Result<Share> {
    let share_path = get_expanded_path(poly_share_path).context("failed to expand share path")?;
    let share_hex = std::fs::read_to_string(share_path).context("failed to load share hex")?;

    let share_vec = from_hex_formatted(&share_hex).expect("invalid format for polynomial share");
    let share = group::Share::decode(share_vec.as_ref()).expect("Could not parse share");
    Ok(share)
}

pub(crate) fn expect_signer(key_path: &str) -> PrivateKey {
    match load_signer(key_path) {
        Ok(signer) => signer,
        Err(e) => panic!("Signer error @ path {key_path}: {e}\n"),
    }
}

pub(crate) fn expect_share(poly_share_path: &str) -> Share {
    match load_share(poly_share_path) {
        Ok(share) => share,
        Err(e) => panic!("Share error @ path {poly_share_path}: {e}\n"),
    }
}

#[allow(unused)]
pub(crate) fn expect_keys(key_path: &str, poly_share_path: &str) -> (PrivateKey, Share) {
    let signer_res = load_signer(key_path);
    let share_res = load_share(poly_share_path);
    let (signer, share) = match (signer_res, share_res) {
        (Ok(signer), Ok(share)) => (signer, share),
        (Err(signer_err), Ok(_)) => {
            panic!("\nSigner error @ path {key_path}: {signer_err}\n");
        }
        (Ok(_), Err(share_err)) => {
            panic!("\nShare error @ path {poly_share_path}: {share_err}\n");
        }
        (Err(signer_err), Err(share_err)) => {
            panic!(
                "\nFailed to load signer and share keys\nSigner error @ path {key_path}: {signer_err}\nShare  error @ path {poly_share_path}: {share_err}\n",
            );
        }
    };
    (signer, share)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::expect_keys;

    #[test]
    fn test_expect_keys_node0() {
        let keys_dir = {
            let node_crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let repo_root = node_crate_dir.parent().unwrap();
            repo_root.join("testnet/node0")
        };
        expect_keys(
            &keys_dir.join("key.pem").to_string_lossy(),
            &keys_dir.join("share.pem").to_string_lossy(),
        );
    }

    #[test]
    #[should_panic]
    fn test_expect_keys_error_msg() {
        expect_keys("missing-signer.pem", "missing-share.pem");
    }
}
