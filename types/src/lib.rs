pub mod account;
mod block;
pub mod bootstrap;
pub mod checkpoint;
pub mod consensus_state;
pub mod consensus_state_query;
pub mod dynamic_epocher;
pub mod engine_client;
pub mod execution_request;
pub mod ext_private_key;
pub mod genesis;
pub mod header;
pub mod key_paths;
pub mod keystore;
pub mod network_oracle;
pub mod protocol_params;
#[cfg(feature = "e2e")]
pub mod reth;
pub mod rpc;
pub mod scheme;
pub mod ssz_hash;
pub mod ssz_state_tree;
pub mod ssz_tree;
pub mod ssz_tree_key;
pub mod utils;
pub mod withdrawal;

use alloy_primitives::Address;
use alloy_rpc_types_engine::ForkchoiceState;
pub use block::*;
pub use engine_client::*;
pub use genesis::*;
pub use header::*;
pub use key_paths::*;
use withdrawal::PendingWithdrawal;

use commonware_consensus::simplex::types::Activity as CActivity;

pub type Digest = commonware_cryptography::sha256::Digest;
pub type Activity = CActivity<Signature, Digest>;

pub const PROTOCOL_VERSION: u32 = 1;

/// Auxiliary data needed for block construction
#[derive(Debug, Clone)]
pub struct BlockAuxData {
    pub epoch: u64,
    pub withdrawals: Vec<PendingWithdrawal>,
    pub checkpoint_hash: Option<Digest>,
    pub header_hash: Digest,
    pub added_validators: Vec<AddedValidator>,
    pub removed_validators: Vec<PublicKey>,
    pub forkchoice: ForkchoiceState,
    pub suggested_fee_recipient: Address,
    pub state_root: [u8; 32],
    pub allowed_timestamp_future_ms: u64,
}

pub use commonware_cryptography::bls12381;
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub type PrivateKey = commonware_cryptography::ed25519::PrivateKey;
pub type Signature = commonware_cryptography::ed25519::Signature;
