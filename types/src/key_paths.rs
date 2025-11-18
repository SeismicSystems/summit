use crate::{PrivateKey, utils::get_expanded_path};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::primitives::{group, variant::MinPk};
use commonware_utils::{from_hex_formatted, hex};

/// Helper struct for managing key paths and loading keys from a key store directory.
///
/// The key store directory should contain:
/// - `consensus_key.pem`: ED25519 private key for consensus
/// - `share.pem`: BLS12-381 DKG share
pub struct KeyPaths(String);

impl KeyPaths {
    /// Create a new KeyPaths instance from a key store path
    pub fn new(key_store_path: String) -> Self {
        Self(key_store_path)
    }

    /// Get the path to the consensus key file
    pub fn consensus_path(&self) -> String {
        format!("{}/consensus_key.pem", self.0)
    }

    /// Get the path to the share file
    pub fn share_path(&self) -> String {
        format!("{}/share.pem", self.0)
    }

    /// Load the consensus private key from the key store
    pub fn consensus_private_key(&self) -> Result<PrivateKey, String> {
        let path = get_expanded_path(&self.consensus_path())
            .map_err(|_| "unable to get consensus key path")?;
        let encoded_pk = std::fs::read_to_string(path)
            .map_err(|_| "Failed to read consensus private key file")?;

        let key = from_hex_formatted(&encoded_pk)
            .ok_or("Invalid hex format for consensus private key")?;
        let pk = PrivateKey::decode(&*key).map_err(|_| "unable to decode consensus private key")?;

        Ok(pk)
    }

    /// Load the share private key from the key store
    pub fn share_private_key(&self) -> Result<group::Share, String> {
        let path = get_expanded_path(&self.share_path()).map_err(|_| "unable to get share path")?;
        let encoded_share =
            std::fs::read_to_string(path).map_err(|_| "Failed to read share file")?;

        let share_bytes =
            from_hex_formatted(&encoded_share).ok_or("Invalid hex format for share")?;
        let share = group::Share::decode(&*share_bytes).map_err(|_| "unable to decode share")?;

        Ok(share)
    }

    /// Get the consensus public key as a hex string
    pub fn consensus_public_key(&self) -> Result<String, String> {
        let private_key = self.consensus_private_key()?;
        Ok(private_key.public_key().to_string())
    }

    /// Get the share public key as a hex string
    pub fn share_public_key(&self) -> Result<String, String> {
        let share = self.share_private_key()?;
        let public_key: group::G1 = share.public::<MinPk>();
        Ok(hex(&public_key.encode()))
    }
}
