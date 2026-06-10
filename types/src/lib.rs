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
const CHAIN_DOMAIN_TAG: &[u8] = b"summit-chain-v1";

/// Domain for live peer authentication and BLS consensus signatures, bound to
/// the immutable identity of this chain deployment: the protocol version, the
/// EL genesis hash, AND the configured `namespace`.
///
/// The configured `namespace` alone is mutable operator input, so deriving the
/// live P2P and consensus domains from it directly lets a separate deployment
/// that reuses the same namespace and validator keys authenticate peers and
/// verify consensus certificates across networks. Folding the genesis hash and
/// protocol version into the domain ties both to immutable chain identity, so a
/// handshake or certificate from one deployment cannot verify against another.
pub fn chain_domain(genesis_hash: [u8; 32], namespace: &[u8]) -> [u8; 32] {
    let mut domain_data = Vec::with_capacity(CHAIN_DOMAIN_TAG.len() + 4 + 32 + 4 + namespace.len());
    domain_data.extend_from_slice(CHAIN_DOMAIN_TAG);
    domain_data.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    domain_data.extend_from_slice(&genesis_hash);
    // Length-prefix the variable-length namespace so the domain is unambiguous.
    domain_data.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    domain_data.extend_from_slice(namespace);
    Sha256::hash(&domain_data).0
}

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

#[cfg(test)]
mod chain_domain_tests {
    use super::{chain_domain, deposit_signature_domain};

    const NS: &[u8] = b"_SUMMIT";

    #[test]
    fn chain_domain_is_deterministic() {
        let g = [7u8; 32];
        assert_eq!(chain_domain(g, NS), chain_domain(g, NS));
    }

    #[test]
    fn chain_domain_separates_genesis_hash() {
        // Same namespace and validator keys, different chain: a peer handshake
        // or consensus certificate from one deployment must not verify against
        // the other, so the domains must differ.
        assert_ne!(chain_domain([1u8; 32], NS), chain_domain([2u8; 32], NS));
    }

    #[test]
    fn chain_domain_separates_namespace() {
        let g = [7u8; 32];
        assert_ne!(chain_domain(g, b"network-a"), chain_domain(g, b"network-b"));
    }

    #[test]
    fn chain_domain_namespace_is_unambiguous() {
        // Length-prefixing prevents a boundary shift between two namespaces from
        // colliding on the same domain.
        let g = [7u8; 32];
        assert_ne!(chain_domain(g, b"ab"), chain_domain(g, b"a"));
        assert_ne!(chain_domain(g, b"aab"), chain_domain(g, b"aa"));
    }

    #[test]
    fn chain_domain_is_distinct_from_deposit_domain() {
        // The live consensus/p2p domain and the deposit-authorization domain are
        // separate trust contexts even for identical chain inputs.
        let g = [7u8; 32];
        assert_ne!(chain_domain(g, NS), deposit_signature_domain(g, NS).0);
    }

    #[test]
    fn chain_domain_blocks_cross_deployment_signature_replay() {
        use crate::PrivateKey;
        use commonware_cryptography::{Signer, Verifier};
        use commonware_math::algebra::Random;
        use rand_core::OsRng;

        // One validator node key and one namespace, deployed on two chains that
        // differ only in their genesis hash.
        let key = PrivateKey::random(&mut OsRng);
        let pk = key.public_key();
        let msg = b"peer-handshake";

        let domain_a = chain_domain([1u8; 32], NS);
        let domain_b = chain_domain([2u8; 32], NS);

        // A signature scoped to chain A's live domain authenticates on chain A,
        // but cannot be replayed against chain B even with the same key and
        // namespace, because the live domain carries the genesis hash.
        let sig = key.sign(domain_a.as_slice(), msg);
        assert!(pk.verify(domain_a.as_slice(), msg, &sig));
        assert!(!pk.verify(domain_b.as_slice(), msg, &sig));
    }
}
