mod block;
use std::{net::SocketAddr, path::PathBuf};

pub use block::*;

use commonware_codec::DecodeExt;
use commonware_consensus::simplex::types::{Activity as CActivity, View};

use commonware_utils::from_hex_formatted;

pub type Digest = commonware_cryptography::sha256::Digest;
pub type Activity = CActivity<commonware_cryptography::bls12381::Signature, Digest>;

pub type PublicKey = commonware_cryptography::bls12381::PublicKey;
pub type PrivateKey = commonware_cryptography::bls12381::PrivateKey;
pub type Signature = commonware_cryptography::bls12381::Signature;

pub mod wasm;
pub const NAMESPACE: &[u8] = b"_SEISMIC_BFT";

// Kind enum for message types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Kind::Seed),
            1 => Some(Kind::Notarization),
            2 => Some(Kind::Finalization),
            _ => None,
        }
    }
}
/// Seed represents a threshold signature over the current view.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Seed {
    pub view: View,
}

// temporary until we have true genesis file
pub struct GenesisCommittee {
    pub validators: Vec<(PublicKey, SocketAddr)>,
}

impl GenesisCommittee {
    pub fn load_from_file(path: PathBuf) -> Self {
        let file_string = std::fs::read_to_string(path).unwrap();

        let parsed: toml::Value = toml::from_str(&file_string).unwrap();

        let nodes: Vec<Vec<String>> = parsed["validators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arr| {
                arr.as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().to_string())
                    .collect()
            })
            .collect();

        let validators: Vec<(PublicKey, SocketAddr)> = nodes
            .into_iter()
            .map(|mut v| {
                let public_key_bytes = from_hex_formatted(&v.remove(0)).unwrap();
                let pub_key = PublicKey::decode(&*public_key_bytes).unwrap();

                let ip: SocketAddr = v.remove(0).parse().unwrap();

                (pub_key, ip)
            })
            .collect();

        GenesisCommittee { validators }
    }

    pub fn ip_of(&self, public_key: &PublicKey) -> Option<SocketAddr> {
        self.validators
            .iter()
            .find_map(|v| if &v.0 == public_key { Some(v.1) } else { None })
    }
}

#[test]
fn test_loading_committee() {
    GenesisCommittee::load_from_file(PathBuf::from("test_committee.toml"));
}

#[test]
fn gen_private_keys() {
    for i in 0..4 {
        let pk = <PrivateKey as commonware_cryptography::PrivateKeyExt>::from_seed(i);
        println!("Private key:");
        println!("{}", pk.to_string());

        println!("Public Key:");
        println!("{}", commonware_cryptography::Signer::public_key(&pk));
        println!("_____________________");
    }
}
