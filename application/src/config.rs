use commonware_consensus::types::Epocher;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::AtomicBool;
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

    /// Maximum P2P message size from genesis.
    pub max_message_size_bytes: u32,

    /// Epocher for determining epoch boundaries.
    pub epocher: ES,

    pub cancellation_token: CancellationToken,

    /// Consensus leader timeout. A proposal whose timestamp cannot enter the
    /// verifier future window within this window is abandoned rather than waited
    /// out, since it could not be notarized before the leader rotates.
    pub leader_timeout: Duration,

    /// When true, the node will not participate in consensus
    /// (skip proposals, reject verifications, skip broadcasts).
    #[cfg(feature = "permissioned")]
    pub paused: Arc<AtomicBool>,
}
