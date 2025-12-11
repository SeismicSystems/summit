use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_runtime::buffer::PoolRef;
use std::marker::PhantomData;
use summit_orchestrator::Mailbox as OrchestratorMailbox;
use summit_types::network_oracle::NetworkOracle;
use summit_types::{EngineClient, PublicKey, consensus_state::ConsensusState};
use tokio_util::sync::CancellationToken;

pub struct FinalizerConfig<C: EngineClient, O: NetworkOracle<PublicKey>, V: Variant> {
    pub archive_mode: bool,
    pub mailbox_size: usize,
    pub db_prefix: String,
    pub engine_client: C,
    pub oracle: O,
    pub orchestrator_mailbox: OrchestratorMailbox,
    pub epoch_num_of_blocks: u64,
    pub validator_max_withdrawals_per_block: usize,
    pub validator_minimum_stake: u64, // in gwei
    pub validator_withdrawal_period: u64,
    /// The maximum number of validators that will be onboarded at the same time
    pub validator_onboarding_limit_per_block: usize,
    pub buffer_pool: PoolRef,
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
