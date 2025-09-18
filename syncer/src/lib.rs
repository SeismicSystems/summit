pub mod actor;
pub use actor::*;
pub mod ingress;
pub use ingress::*;
use summit_types::PublicKey;
pub mod coordinator;
pub mod finalizer;
pub mod handler;
pub mod key;

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

    pub namespace: String,

    pub epoch_num_blocks: u64,
}
