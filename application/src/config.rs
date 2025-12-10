use summit_types::EngineClient;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ApplicationConfig<C: EngineClient> {
    pub engine_client: C,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub partition_prefix: String,

    pub genesis_hash: [u8; 32],

    pub epoch_num_of_blocks: u64,

    pub cancellation_token: CancellationToken,
}
