use crate::PublicKey;
use alloy_primitives::Address;
use commonware_codec::DecodeExt;
use commonware_utils::from_hex_formatted;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    /// List of all validators at genesis block
    pub validators: Vec<Validator>,
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
pub struct Validator {
    pub public_key: String,
    pub ip_address: String,
    pub withdrawal_credentials: String,
}

impl TryInto<(PublicKey, SocketAddr, Address)> for &Validator {
    type Error = String;

    fn try_into(self) -> Result<(PublicKey, SocketAddr, Address), Self::Error> {
        let pub_key_bytes = from_hex_formatted(&self.public_key).ok_or("PublicKey bad format")?;

        Ok((
            PublicKey::decode(&*pub_key_bytes).map_err(|_| "Unable to decode Public Key")?,
            self.ip_address.parse().map_err(|_| "Invalid ip address")?,
            self.withdrawal_credentials
                .parse()
                .map_err(|_| "Invalid withdrawal credentials")?,
        ))
    }
}

impl Genesis {
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file_string = std::fs::read_to_string(path)?;
        let genesis: Genesis = toml::from_str(&file_string)?;
        Ok(genesis)
    }

    pub fn get_validator_addresses(
        &self,
    ) -> Result<Vec<(PublicKey, SocketAddr)>, Box<dyn std::error::Error>> {
        let mut validators = Vec::new();

        for validator in &self.validators {
            let public_key_bytes = from_hex_formatted(&validator.public_key)
                .ok_or("Invalid hex format for public key")?;
            let pub_key = PublicKey::decode(&*public_key_bytes)?;
            let socket_addr: SocketAddr = validator.ip_address.parse()?;

            validators.push((pub_key, socket_addr));
        }

        Ok(validators)
    }

    pub fn ip_of(&self, target_public_key: &PublicKey) -> Option<SocketAddr> {
        for validator in &self.validators {
            if let Some(public_key_bytes) = from_hex_formatted(&validator.public_key) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loading_genesis() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        assert_eq!(genesis.validator_count(), 4);

        let addresses = genesis.get_validator_addresses().unwrap();
        assert_eq!(addresses.len(), 4);
    }

    #[test]
    fn test_validator_lookup() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        let addresses = genesis.get_validator_addresses().unwrap();

        // Test that we can find the IP for each validator
        for (pub_key, expected_addr) in &addresses {
            let found_addr = genesis.ip_of(pub_key);
            assert_eq!(found_addr, Some(*expected_addr));
        }
    }
}
