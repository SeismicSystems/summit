use crate::PublicKey;
use alloy_primitives::Address;
use anyhow::Context;
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381;
use commonware_utils::{from_hex, from_hex_formatted};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    /// List of all validators at genesis block
    pub validators: Vec<GenesisValidator>,
    /// The hash of the genesis file used for the EVM client
    pub eth_genesis_hash: String,
    /// Amount of time to wait for a leader to propose a payload
    /// in a view.
    pub leader_timeout_ms: u64,
    /// Amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    pub notarization_timeout_ms: u64,
    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub nullify_timeout_ms: u64,
    /// Number of views behind finalized tip to track
    /// and persist activity derived from validator messages.
    pub activity_timeout_views: u64,
    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many views.
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking).
    pub skip_timeout_views: u64,
    /// Maximum size allowed for messages over any connection.
    ///
    /// The actual size of the network message will be higher due to overhead from the protocol;
    /// this may include additional metadata, data from the codec, and/or cryptographic signatures.
    pub max_message_size_bytes: u64,
    /// Prefix for all signed messages to prevent replay attacks.
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub node_public_key: String,
    pub consensus_public_key: String,
    pub ip_address: String,
    pub withdrawal_credentials: String,
}

impl GenesisValidator {
    fn ed25519_pubkey(key: &str) -> PublicKey {
        let pubkey_bytes = from_hex(key).unwrap();
        PublicKey::decode(&pubkey_bytes[..]).unwrap()
    }

    pub fn node_pubkey(&self) -> PublicKey {
        GenesisValidator::ed25519_pubkey(&self.node_public_key)
    }
}

#[derive(Debug, Clone)]
pub struct Validator {
    pub node_public_key: PublicKey,
    pub consensus_public_key: bls12381::PublicKey,
    pub ip_address: SocketAddr,
    pub withdrawal_credentials: Address,
}

impl TryFrom<&GenesisValidator> for Validator {
    type Error = anyhow::Error;

    fn try_from(value: &GenesisValidator) -> Result<Self, Self::Error> {
        let node_key_bytes =
            from_hex_formatted(&value.node_public_key).context("Node PublicKey bad format")?;
        let node_public_key = PublicKey::decode(&*node_key_bytes)?;

        let consensus_key_bytes = from_hex_formatted(&value.consensus_public_key)
            .context("Consensus PublicKey bad format")?;
        let consensus_public_key = bls12381::PublicKey::decode(&*consensus_key_bytes)?;

        Ok(Validator {
            node_public_key,
            consensus_public_key,
            ip_address: value.ip_address.parse()?,
            withdrawal_credentials: value.withdrawal_credentials.parse()?,
        })
    }
}

impl Genesis {
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file_string = std::fs::read_to_string(path)?;
        let genesis: Genesis = toml::from_str(&file_string)?;
        Ok(genesis)
    }

    pub fn ip_of(&self, target_public_key: &PublicKey) -> Option<SocketAddr> {
        for validator in &self.validators {
            #[allow(clippy::collapsible_if)]
            if let Some(public_key_bytes) = from_hex_formatted(&validator.node_public_key) {
                if let Ok(pub_key) = PublicKey::decode(&*public_key_bytes) {
                    if &pub_key == target_public_key {
                        if let Ok(socket_addr) = validator.ip_address.parse() {
                            return Some(socket_addr);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    pub fn get_validators(&self) -> Result<Vec<Validator>, anyhow::Error> {
        let mut validators = Vec::with_capacity(self.validators.len());
        for validator in &self.validators {
            validators.push(validator.try_into()?);
        }
        Ok(validators)
    }

    pub fn get_consensus_keys(
        &self,
    ) -> Result<Vec<bls12381::PublicKey>, Box<dyn std::error::Error>> {
        let mut keys = Vec::new();
        for validator in &self.validators {
            let key_bytes = from_hex_formatted(&validator.consensus_public_key)
                .ok_or("Invalid hex format for consensus public key")?;
            let key = bls12381::PublicKey::decode(&*key_bytes)?;
            keys.push(key);
        }
        Ok(keys)
    }

    pub fn get_validator_keys(
        &self,
    ) -> Result<Vec<(PublicKey, bls12381::PublicKey)>, Box<dyn std::error::Error>> {
        let mut keys = Vec::new();
        for validator in &self.validators {
            let node_key_bytes = from_hex_formatted(&validator.node_public_key)
                .ok_or("Invalid hex format for node public key")?;
            let node_key = PublicKey::decode(&*node_key_bytes)?;

            let consensus_key_bytes = from_hex_formatted(&validator.consensus_public_key)
                .ok_or("Invalid hex format for consensus public key")?;
            let consensus_key = bls12381::PublicKey::decode(&*consensus_key_bytes)?;

            keys.push((node_key, consensus_key));
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loading_genesis() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        assert_eq!(genesis.validator_count(), 4);

        let keys = genesis.get_validator_keys().unwrap();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn test_validator_lookup() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();

        // Test that we can find the IP for each validator
        let validators = &genesis.get_validators().unwrap();
        for validator in validators {
            let found_addr = genesis.ip_of(&validator.node_public_key);
            assert_eq!(found_addr, Some(validator.ip_address));
        }
    }
}
