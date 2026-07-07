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
const PAUSE_DOMAIN_TAG: &[u8] = b"summit-pause-v1";

/// Domain for live peer authentication and BLS consensus signatures, bound to
/// the immutable identity of this chain deployment: the protocol version and
/// the genesis config digest (see [`crate::genesis::Genesis::config_digest`]).
///
/// The config digest folds in the EL genesis hash, the configured `namespace`,
/// the genesis validator set, and every consensus/economic parameter fixed at
/// launch. Any of those is mutable operator input, so deriving the live P2P and
/// consensus domains from them directly lets a separate deployment that reuses
/// the same configuration authenticate peers and verify consensus certificates
/// across networks. Folding the config digest and protocol version into the
/// domain ties both to immutable chain identity, so a handshake or certificate
/// from one deployment cannot verify against another that differs in any
/// identity-bearing genesis field.
pub fn chain_domain(config_digest: [u8; 32]) -> [u8; 32] {
    let mut domain_data = Vec::with_capacity(CHAIN_DOMAIN_TAG.len() + 4 + 32);
    domain_data.extend_from_slice(CHAIN_DOMAIN_TAG);
    domain_data.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    domain_data.extend_from_slice(&config_digest);
    Sha256::hash(&domain_data).0
}

/// Folds a purpose tag, protocol version, EL genesis hash, and (length-prefixed)
/// Summit `namespace` into a single domain digest. The genesis hash + namespace
/// pin a signature to one deployment; the tag separates signing purposes so a
/// signature minted for one domain can never be reinterpreted under another.
fn signature_domain(tag: &[u8], genesis_hash: [u8; 32], namespace: &[u8]) -> Digest {
    let mut domain_data = Vec::with_capacity(tag.len() + 4 + 32 + 4 + namespace.len());
    domain_data.extend_from_slice(tag);
    domain_data.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    domain_data.extend_from_slice(&genesis_hash);
    // Length-prefix the variable-length namespace so the domain is unambiguous.
    domain_data.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    domain_data.extend_from_slice(namespace);
    Sha256::hash(&domain_data)
}

/// Domain for deposit-authorization signatures, bound to the full Summit
/// deployment boundary: the EL genesis hash AND the Summit `namespace`.
pub fn deposit_signature_domain(genesis_hash: [u8; 32], namespace: &[u8]) -> Digest {
    signature_domain(DEPOSIT_DOMAIN_TAG, genesis_hash, namespace)
}

/// Domain for consensus-pause RPC authorization signatures, bound to the full
/// Summit deployment boundary: the EL genesis hash AND the Summit `namespace`.
///
/// Binding the deployment scope means a pause/unpause signature minted for one
/// network cannot be replayed against another that happens to trust the same
/// admin key. The distinct tag also prevents a deposit signature from being
/// reinterpreted as a pause authorization (and vice versa).
pub fn pause_signature_domain(genesis_hash: [u8; 32], namespace: &[u8]) -> Digest {
    signature_domain(PAUSE_DOMAIN_TAG, genesis_hash, namespace)
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
    pub treasury_address: Address,
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
        let d = [7u8; 32];
        assert_eq!(chain_domain(d), chain_domain(d));
    }

    #[test]
    fn chain_domain_separates_config_digest() {
        // Different chain identity (genesis config digest) => different domain,
        // so a peer handshake or consensus certificate from one deployment must
        // not verify against the other. Per-field separation (genesis hash,
        // namespace, params, validators) is covered by the `config_digest` tests
        // in `genesis.rs`.
        assert_ne!(chain_domain([1u8; 32]), chain_domain([2u8; 32]));
    }

    #[test]
    fn chain_domain_is_distinct_from_deposit_domain() {
        // The live consensus/p2p domain and the deposit-authorization domain are
        // separate trust contexts even for identical chain inputs.
        let g = [7u8; 32];
        assert_ne!(chain_domain(g), deposit_signature_domain(g, NS).0);
    }

    #[test]
    fn chain_domain_blocks_cross_deployment_signature_replay() {
        use crate::PrivateKey;
        use commonware_cryptography::{Signer, Verifier};
        use commonware_math::algebra::Random;
        use rand_core::OsRng;

        let key = PrivateKey::random(&mut OsRng);
        let pk = key.public_key();
        let msg = b"peer-handshake";

        // Two chains with distinct genesis config digests.
        let domain_a = chain_domain([1u8; 32]);
        let domain_b = chain_domain([2u8; 32]);

        // A signature scoped to chain A's live domain authenticates on chain A,
        // but cannot be replayed against chain B, because the live domain carries
        // the chain's config digest.
        let sig = key.sign(domain_a.as_slice(), msg);
        assert!(pk.verify(domain_a.as_slice(), msg, &sig));
        assert!(!pk.verify(domain_b.as_slice(), msg, &sig));
    }
}
