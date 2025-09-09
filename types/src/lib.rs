pub mod account;
mod block;
mod chechkpoint;
pub mod consensus_state;
pub mod execution_request;
pub mod genesis;
pub mod utils;
pub mod withdrawal;

pub use block::*;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
pub use genesis::*;

use commonware_consensus::threshold_simplex::types::Activity as CActivity;

pub type Digest = commonware_cryptography::sha256::Digest;
pub type Activity = CActivity<MinPk, Digest>;

pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub type PrivateKey = commonware_cryptography::ed25519::PrivateKey;
pub type Signature = commonware_cryptography::ed25519::Signature;
pub type Identity = <MinPk as Variant>::Public;
