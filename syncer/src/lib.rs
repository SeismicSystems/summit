pub mod actor;
pub use actor::*;
pub mod ingress;
use commonware_runtime::buffer::PoolRef;
pub use ingress::*;
use summit_types::PublicKey;
use summit_types::registry::Registry;
use tokio_util::sync::CancellationToken;

pub mod coordinator;
pub mod handler;
pub mod key;

/// Configuration for the syncer.
pub struct Config {
    pub partition_prefix: String,

    pub public_key: PublicKey,

    pub registry: Registry,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub backfill_quota: governor::Quota,
    pub activity_timeout: u64,

    pub namespace: String,

    pub buffer_pool: PoolRef,

    pub cancellation_token: CancellationToken,
}
