use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_runtime::buffer::paged::CacheRef;
use std::marker::PhantomData;
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
    /// Optional initial state to initialize the finalizer with
    pub initial_state: ConsensusState,
    /// Protocol version for the consensus protocol
    pub protocol_version: u32,
    /// The node's own public key
    pub node_public_key: PublicKey,
    pub cancellation_token: CancellationToken,
    pub _variant_marker: PhantomData<V>,
}
