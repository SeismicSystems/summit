use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_runtime::buffer::paged::CacheRef;
use std::marker::PhantomData;
use std::time::Duration;
use summit_types::network_oracle::NetworkOracle;
use summit_types::{EngineClient, PublicKey, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;

/// Fixed protocol-level constants governing validator lifecycle.
pub struct ProtocolConsts {
    /// Number of epochs to wait before activating validators after deposit.
    pub validator_num_warm_up_epochs: u64,
    /// Number of epochs after a withdrawal request until the payout.
    pub validator_withdrawal_num_epochs: u64,
}

pub struct FinalizerConfig<C: EngineClient, O: NetworkOracle<PublicKey>, V: Variant> {
    pub mailbox_size: usize,
    pub db_prefix: String,
    pub engine_client: C,
    pub oracle: O,
    pub protocol_consts: ProtocolConsts,
    pub page_cache: CacheRef,
    pub genesis_hash: [u8; 32],
    /// The Summit deployment namespace, mixed into the deposit-signature domain
    /// alongside the genesis hash so deposit authorizations are bound to this
    /// specific deployment (not just the EL genesis).
    pub namespace: Vec<u8>,
    /// Optional initial state to initialize the finalizer with
    pub initial_state: ConsensusState,
    /// Protocol version for the consensus protocol
    pub protocol_version: u32,
    /// The node's own public key
    pub node_public_key: PublicKey,
    pub cancellation_token: CancellationToken,
    /// How often the finalizer retries applying buffered blocks while the
    /// execution layer is recovering from SYNCING.
    pub drain_interval: Duration,
    /// Soft threshold for the SYNCING-buffer size. When either the pending
    /// finalized or pending notarized buffer crosses this threshold, the
    /// finalizer emits a warn log (edge-triggered, once per crossing).
    pub buffered_blocks_warn_threshold: usize,
    /// Hard cap for unique deferred notarized blocks while the execution
    /// layer is SYNCING. Reaching this limit triggers graceful shutdown.
    pub pending_notarized_max: usize,
    pub _variant_marker: PhantomData<V>,
}
