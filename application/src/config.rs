use commonware_consensus::types::Epocher;
use std::time::Duration;
use summit_types::EngineClient;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ApplicationConfig<C: EngineClient, ES: Epocher> {
    pub engine_client: C,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub partition_prefix: String,

    pub genesis_hash: [u8; 32],

    /// Epocher for determining epoch boundaries.
    pub epocher: ES,

    /// Maximum allowed delta between a block's timestamp and the
    /// local wall clock. Blocks with timestamps that differ from
    /// the local time by more than this are rejected during
    /// verification.
    pub allowed_timestamp_future: Duration,

    pub cancellation_token: CancellationToken,
}
