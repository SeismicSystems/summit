use commonware_consensus::Block;
use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::types::{Epoch, Epocher, ViewDelta};
use commonware_cryptography::certificate::Provider;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use std::num::{NonZeroU64, NonZeroUsize};
use summit_types::FinalizedHeader;

/// The state actually selected by the finalizer at startup. Delivery begins at
/// `height + 1`, regardless of acknowledgements from a previous process.
///
/// This height also bounds finalized-archive pruning for this process: entries
/// above it must remain available for replay. Subsequent restarts must recover
/// this state or a newer one. Genesis and durable checkpoint imports satisfy
/// this requirement. Callers supplying a state-only bootstrap to an empty
/// finalizer database must preserve and resupply it until a durable finalizer
/// state supersedes it; restarting from an older baseline after pruning is not
/// supported. The epoch/view are diagnostic; round recovery uses the archives.
pub struct SyncStart {
    pub height: u64,
    pub epoch: u64,
    pub view: u64,
}

/// Terminal-block replay artifacts from a durably committed finalizer import.
/// Ordinary restarts select their delivery position through [`SyncStart`], but
/// must not manufacture checkpoint artifacts or bypass import validation.
pub struct SyncCheckpoint<B: Block, S: Scheme<B::Digest>> {
    pub processed_height: commonware_consensus::types::Height,
    pub finalized_header: FinalizedHeader<S>,
    pub last_block: Option<B>,
}

/// Marshal configuration.
pub struct Config<B, P, ES, T>
where
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Digest>>,
    ES: Epocher,
    T: Strategy,
{
    /// Provider for epoch-specific signing schemes.
    pub scheme_provider: P,

    /// Epocher for determining epoch boundaries.
    pub epocher: ES,

    /// The prefix to use for all partitions.
    pub partition_prefix: String,

    /// Size of backfill request/response mailbox.
    pub mailbox_size: NonZeroUsize,

    /// Minimum number of views to retain temporary data after the application processes a block.
    ///
    /// Useful for keeping around information that peers may desire to have.
    pub view_retention_timeout: ViewDelta,

    /// Namespace for proofs.
    pub namespace: Vec<u8>,

    /// Prunable archive partition prefix.
    pub prunable_items_per_section: NonZeroU64,

    /// The page cache to use for the freezer journal.
    pub page_cache: CacheRef,

    /// The size of the replay buffer for storage archives.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer for the key journal of storage archives.
    pub key_write_buffer: NonZeroUsize,

    /// The size of the write buffer for the value journal of storage archives.
    pub value_write_buffer: NonZeroUsize,

    /// Codec configuration for block type.
    pub block_codec_config: B::Cfg,

    /// Maximum number of blocks to repair at once
    pub max_repair: NonZeroUsize,

    /// Maximum number of blocks dispatched to the application that have not
    /// yet been acknowledged. Increasing this value allows the application
    /// to buffer work while marshal continues dispatching, hiding ack latency.
    pub max_pending_acks: NonZeroUsize,

    /// Strategy for parallel operations.
    pub strategy: T,
}
