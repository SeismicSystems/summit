use std::path::PathBuf;

use crate::{PrivateKey, utils::get_expanded_path};
use anyhow::{Context, Result};
use commonware_codec::DecodeExt;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::PrivateKey as BlsPrivateKey;
use commonware_formatting::from_hex;

/// Helper struct for managing key paths and loading keys from a key store directory.
///
/// The key store directory should contain:
/// - `node_key.pem`: ED25519 private key for node identity (node key)
/// - `share.pem`: BLS12-381 DKG share (consensus key)
pub struct KeyPaths(String);

impl KeyPaths {
    /// Create a new KeyPaths instance from a key store path
    pub fn new(key_store_path: String) -> Self {
        Self(key_store_path)
    }

    pub fn expanded(&self) -> anyhow::Result<PathBuf> {
        get_expanded_path(&self.0)
    }

    /// Get the path to the node key file (ED25519)
    pub fn node_key_path_str(&self) -> String {
        format!("{}/node_key.pem", self.0)
    }

    /// Get the path to the consensus key file (BLS share)
    pub fn consensus_key_path_str(&self) -> String {
        format!("{}/consensus_key.pem", self.0)
    }

    pub fn node_key_path(&self) -> anyhow::Result<PathBuf> {
        get_expanded_path(&self.node_key_path_str())
    }

    pub fn consensus_key_path(&self) -> anyhow::Result<PathBuf> {
        get_expanded_path(&self.consensus_key_path_str())
    }

    /// Load the node private key (ED25519) from the key store
    pub fn node_private_key(&self) -> Result<PrivateKey, String> {
        self.read_node_key_from_file().map_err(|e| e.to_string())
    }

    /// Load the consensus private key (BLS) from the key store
    pub fn consensus_private_key(&self) -> Result<BlsPrivateKey, String> {
        self.read_bls_key_from_file().map_err(|e| e.to_string())
    }

    /// Get the node public key (ED25519) as a hex string
    pub fn node_public_key(&self) -> Result<String, String> {
        let private_key = self.node_private_key()?;
        Ok(private_key.public_key().to_string())
    }

    /// Get the consensus public key (BLS) as a hex string
    pub fn consensus_public_key(&self) -> Result<String, String> {
        let private_key = self.consensus_private_key()?;
        Ok(private_key.public_key().to_string())
    }

    /// Read the node private key from file (using anyhow::Result for compatibility)
    pub fn read_node_key_from_file(&self) -> Result<PrivateKey> {
        let path = self.node_key_path()?;
        warn_if_permissions_too_open(&path);
        let encoded_pk = std::fs::read_to_string(&path)
            .context(format!("Failed to read node key from {:?}", path))?;
        let key = from_hex(&encoded_pk).context("Invalid hex format for node key")?;
        let pk = PrivateKey::decode(&*key).context("Unable to decode node private key")?;
        Ok(pk)
    }

    /// Read the BLS private key from file (using anyhow::Result for compatibility)
    pub fn read_bls_key_from_file(&self) -> Result<BlsPrivateKey> {
        let path = self.consensus_key_path()?;
        warn_if_permissions_too_open(&path);
        let encoded_pk = std::fs::read_to_string(&path)
            .context(format!("Failed to read BLS key from {:?}", path))?;
        let key = from_hex(&encoded_pk).context("Invalid hex format for BLS key")?;
        let pk = BlsPrivateKey::decode(&*key).context("Unable to decode BLS private key")?;
        Ok(pk)
    }
}

/// Warn (Unix only) when a private-key file is readable or writable by group or
/// other. We warn rather than reject so an existing validator with legacy file
/// modes is not taken offline on restart; `chmod 600` clears it. On non-Unix
/// platforms this is a no-op.
#[cfg(unix)]
fn warn_if_permissions_too_open(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o7777),
                "private key file is accessible by group/other; tighten it with `chmod 600`"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_permissions_too_open(_path: &std::path::Path) {}
