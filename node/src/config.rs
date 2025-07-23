use std::{num::NonZeroU32, time::Duration};

use anyhow::Result;
use governor::Quota;
use seismicbft_types::{PrivateKey, PublicKey};

use crate::{keys::read_bls_key_from_path, utils::get_expanded_path};

/* DEFAULTS */
pub const VOTER_CHANNEL: u32 = 0;
pub const RESOLVER_CHANNEL: u32 = 1;
pub const BROADCASTER_CHANNEL: u32 = 2;
pub const BACKFILLER_CHANNEL: u32 = 3;

const LEADER_TIMEOUT: Duration = Duration::from_secs(5);
const NOTARIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const NULLIFY_RETRY: Duration = Duration::from_secs(10);
const ACTIVITY_TIMEOUT: u64 = 256;
const SKIP_TIMEOUT: u64 = 32;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const FETCH_CONCURRENT: usize = 4;
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MAX_FETCH_COUNT: usize = 16;
const MAX_FETCH_SIZE: usize = 512 * 1024;
const MAILBOX_SIZE: usize = 16384;
const DEQUE_SIZE: usize = 10;
pub const MESSAGE_BACKLOG: usize = 16384;
const BACKFILL_QUOTA: u32 = 10; // in seconds
const FETCH_RATE_P2P: u32 = 128; // in seconds

pub struct EngineConfig {
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
    pub max_fetch_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_rate_per_peer: Quota,

    pub engine_url: String,
    pub engine_jwt: String,

    pub indexer_url: Option<String>,
}

impl EngineConfig {
    pub fn get_engine_config(
        engine_url: String,
        engine_jwt_path: String,
        key_path: String,
        participants: Vec<PublicKey>,
        db_prefix: String,
        indexer_url: Option<String>,
    ) -> Result<Self> {
        // read JWT from file
        let jwt_path = get_expanded_path(&engine_jwt_path)?;
        let engine_jwt = std::fs::read_to_string(jwt_path)?;

        // read private key from file
        let signer = read_bls_key_from_path(&key_path)?;

        // read a genesis of initial participants from file
        Ok(Self {
            partition_prefix: db_prefix,
            signer,
            participants,
            mailbox_size: MAILBOX_SIZE,
            backfill_quota: Quota::per_second(NonZeroU32::new(BACKFILL_QUOTA).unwrap()),
            deque_size: DEQUE_SIZE,
            leader_timeout: LEADER_TIMEOUT,
            notarization_timeout: NOTARIZATION_TIMEOUT,
            nullify_retry: NULLIFY_RETRY,
            fetch_timeout: FETCH_TIMEOUT,
            activity_timeout: ACTIVITY_TIMEOUT,
            skip_timeout: SKIP_TIMEOUT,
            max_fetch_count: MAX_FETCH_COUNT,
            max_fetch_size: MAX_FETCH_SIZE,
            fetch_concurrent: FETCH_CONCURRENT,
            fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(FETCH_RATE_P2P).unwrap()),
            engine_url,
            engine_jwt,
            indexer_url,
        })
    }
}
