use crate::{PrivateKey, utils::get_expanded_path};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::primitives::{group, variant::MinPk};
use commonware_utils::{from_hex_formatted, hex};

/// Helper struct for managing key paths and loading keys from a key store directory.
///
/// The key store directory should contain:
/// - `consensus_key.pem`: ED25519 private key for node identity (node key)
/// - `share.pem`: BLS12-381 DKG share (consensus key)
pub struct KeyPaths(String);

impl KeyPaths {
    /// Create a new KeyPaths instance from a key store path
    pub fn new(key_store_path: String) -> Self {
        Self(key_store_path)
    }

    /// Get the path to the node key file (ED25519)
    pub fn node_key_path(&self) -> String {
        format!("{}/consensus_key.pem", self.0)
    }

    /// Get the path to the consensus key file (BLS share)
    pub fn consensus_key_path(&self) -> String {
        format!("{}/share.pem", self.0)
    }

    /// Load the node private key (ED25519) from the key store
    pub fn node_private_key(&self) -> Result<PrivateKey, String> {
        let path = get_expanded_path(&self.node_key_path())
            .map_err(|_| "unable to get node key path")?;
        let encoded_pk = std::fs::read_to_string(path)
            .map_err(|_| "Failed to read node private key file")?;

        let key = from_hex_formatted(&encoded_pk)
            .ok_or("Invalid hex format for node private key")?;
        let pk = PrivateKey::decode(&*key).map_err(|_| "unable to decode node private key")?;

        Ok(pk)
    }

    /// Load the consensus private key (BLS share) from the key store
    pub fn consensus_private_key(&self) -> Result<group::Share, String> {
        let path = get_expanded_path(&self.consensus_key_path()).map_err(|_| "unable to get consensus key path")?;
        let encoded_share =
            std::fs::read_to_string(path).map_err(|_| "Failed to read consensus key file")?;

        let share_bytes =
            from_hex_formatted(&encoded_share).ok_or("Invalid hex format for consensus key")?;
        let share = group::Share::decode(&*share_bytes).map_err(|_| "unable to decode consensus key")?;

        Ok(share)
    }

    /// Get the node public key (ED25519) as a hex string
    pub fn node_public_key(&self) -> Result<String, String> {
        let private_key = self.node_private_key()?;
        Ok(private_key.public_key().to_string())
    }

    /// Get the consensus public key (BLS) as a hex string
    pub fn consensus_public_key(&self) -> Result<String, String> {
        let share = self.consensus_private_key()?;
        let public_key: group::G1 = share.public::<MinPk>();
        Ok(hex(&public_key.encode()))
    }
}
