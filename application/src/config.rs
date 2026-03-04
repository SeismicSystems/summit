use commonware_consensus::types::Epocher;
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

    pub cancellation_token: CancellationToken,
}
