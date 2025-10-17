pub mod account;
mod block;
pub mod checkpoint;
pub mod consensus_state;
pub mod consensus_state_query;
pub mod engine_client;
pub mod execution_request;
pub mod genesis;
pub mod header;
pub mod registry;
pub mod utils;
pub mod withdrawal;

use alloy_rpc_types_engine::ForkchoiceState;
pub use block::*;
pub use engine_client::*;
pub use genesis::*;
pub use header::*;
use withdrawal::PendingWithdrawal;

use commonware_consensus::simplex::types::Activity as CActivity;

pub type Digest = commonware_cryptography::sha256::Digest;
pub type Activity = CActivity<Signature, Digest>;

/// Auxiliary data needed for block construction
#[derive(Debug, Clone)]
pub struct BlockAuxData {
    pub withdrawals: Vec<PendingWithdrawal>,
    pub checkpoint_hash: Option<Digest>,
    pub header_hash: Digest,
    pub added_validators: Vec<PublicKey>,
    pub removed_validators: Vec<PublicKey>,
    pub forkchoice: ForkchoiceState,
}

pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub type PrivateKey = commonware_cryptography::ed25519::PrivateKey;
pub type Signature = commonware_cryptography::ed25519::Signature;
