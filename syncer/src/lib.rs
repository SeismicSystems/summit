pub mod actor;
pub use actor::*;
pub mod ingress;
pub use ingress::*;
pub mod coordinator;
pub mod handler;
pub mod key;

use seismicbft_types::PublicKey;

/// Configuration for the syncer.
pub struct Config {
    pub partition_prefix: String,

    pub public_key: PublicKey,

    pub participants: Vec<PublicKey>,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub backfill_quota: governor::Quota,
    pub activity_timeout: u64,

    pub indexer: Option<String>,
}
