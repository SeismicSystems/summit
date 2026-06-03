pub mod account;
mod block;
pub mod bootstrap;
pub mod checkpoint;
pub mod consensus_state;
pub mod consensus_state_query;
pub mod dynamic_epocher;
pub mod engine_client;
pub mod execution_request;
pub mod execution_request_origin;
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
use commonware_cryptography::{Hasher as _, Sha256};
pub use engine_client::*;
pub use genesis::*;
pub use header::*;
pub use key_paths::*;
use withdrawal::PendingWithdrawal;

use commonware_consensus::simplex::types::Activity as CActivity;

pub type Digest = commonware_cryptography::sha256::Digest;
pub type Activity = CActivity<Signature, Digest>;

pub const PROTOCOL_VERSION: u32 = 1;
const DEPOSIT_DOMAIN_TAG: &[u8] = b"summit-deposit-v1";

/// Domain for deposit-authorization signatures, bound to the full Summit
/// deployment boundary: the EL genesis hash AND the Summit `namespace`.
pub fn deposit_signature_domain(genesis_hash: [u8; 32], namespace: &[u8]) -> Digest {
    let mut domain_data =
        Vec::with_capacity(DEPOSIT_DOMAIN_TAG.len() + 4 + 32 + 4 + namespace.len());
    domain_data.extend_from_slice(DEPOSIT_DOMAIN_TAG);
    domain_data.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    domain_data.extend_from_slice(&genesis_hash);
    // Length-prefix the variable-length namespace so the domain is unambiguous.
    domain_data.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    domain_data.extend_from_slice(namespace);
    Sha256::hash(&domain_data)
}

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
