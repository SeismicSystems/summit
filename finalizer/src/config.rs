use commonware_runtime::buffer::PoolRef;
use summit_types::{EngineClient, consensus_state::ConsensusState};

use crate::registry::Registry;

pub struct FinalizerConfig<C: EngineClient> {
    pub mailbox_size: usize,
    pub db_prefix: String,
    pub engine_client: C,
    pub registry: Registry,
    pub epoch_num_of_blocks: u64,
    pub validator_max_withdrawals_per_block: usize,
    pub validator_minimum_stake: u64, // in gwei
    pub validator_withdrawal_period: u64,
    /// The maximum number of validators that will be onboarded at the same time
    pub validator_onboarding_limit_per_block: usize,
    pub buffer_pool: PoolRef,
    pub genesis_hash: [u8; 32],
    /// Optional initial state to initialize the finalizer with
    pub initial_state: Option<ConsensusState>,
    /// Protocol version for the consensus protocol
    pub protocol_version: u32,
}
