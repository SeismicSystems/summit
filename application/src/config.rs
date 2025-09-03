use crate::Registry;
use crate::engine_client::EngineClient;

#[derive(Clone)]
pub struct ApplicationConfig<C: EngineClient> {
    pub engine_client: C,

    pub registry: Registry,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub partition_prefix: String,

    pub genesis_hash: [u8; 32],

    /// Validators that deposited the minimum stake will be added to the
    /// validator set every `validator_onboarding_interval` blocks
    pub validator_onboarding_interval: u64,

    /// The maximum number of validators that will be onboarded at the same time
    pub validator_onboarding_limit_per_block: usize,

    pub validator_minimum_stake: u64, // in gwei

    pub validator_withdrawal_period: u64,

    pub validator_max_withdrawals_per_block: usize,

    /// How often to checkpoint the ConsensusState to persistent storage (in blocks)
    pub checkpoint_interval: u64,
}
