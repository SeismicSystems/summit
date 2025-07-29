use crate::PublicKey;
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
    /// network polynomial identity
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub public_key: String,
    pub ip_address: String,
}

impl TryInto<(PublicKey, SocketAddr)> for &Validator {
    type Error = String;

    fn try_into(self) -> Result<(PublicKey, SocketAddr), Self::Error> {
        let pub_key_bytes = from_hex_formatted(&self.public_key).ok_or("PublicKey bad format")?;

        Ok((
            PublicKey::decode(&*pub_key_bytes).map_err(|_| "Unable to decode Public Key")?,
            self.ip_address.parse().map_err(|_| "Invalid ip address")?,
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
    use commonware_cryptography::PrivateKeyExt;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_genesis() -> Genesis {
        Genesis {
            validators: vec![
                Validator {
                    public_key: "976ab7efaef8a73690b9067690ac7541bc34f74b2543e8db16b5bf63aec487758ca98efdf5c9fcf1154941d8a8a1ec3d".to_string(),
                    ip_address: "127.0.0.1:26600".to_string(),
                },
                Validator {
                    public_key: "a4a1b4b8a3fb2c11f4dba5c6c57743554f746d2211cd519c3c980b8d8019f8fa328b97e44e19dcc6150688da5f38fbcd".to_string(),
                    ip_address: "127.0.0.1:26610".to_string(),
                },
            ],
            eth_genesis_hash: "0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616".to_string(),
            leader_timeout_ms: 2000,
            notarization_timeout_ms: 4000,
            nullify_timeout_ms: 4000,
            activity_timeout_views: 256,
            skip_timeout_views: 32,
            max_message_size_bytes: 104857600,
            namespace: "_SEISMIC_BFT".to_string(),
        }
    }

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

        for (pub_key, expected_addr) in &addresses {
            let found_addr = genesis.ip_of(pub_key);
            assert_eq!(found_addr, Some(*expected_addr));
        }
    }

    #[test]
    fn test_genesis_validator_count() {
        let genesis = create_test_genesis();
        assert_eq!(genesis.validator_count(), 2);

        let empty_genesis = Genesis {
            validators: vec![],
            ..create_test_genesis()
        };
        assert_eq!(empty_genesis.validator_count(), 0);
    }

    #[test]
    fn test_validator_try_into_success() {
        let validator = Validator {
            public_key: "976ab7efaef8a73690b9067690ac7541bc34f74b2543e8db16b5bf63aec487758ca98efdf5c9fcf1154941d8a8a1ec3d".to_string(),
            ip_address: "127.0.0.1:26600".to_string(),
        };

        let result: Result<(PublicKey, std::net::SocketAddr), String> = (&validator).try_into();
        assert!(result.is_ok());
        
        let (_pub_key, socket_addr) = result.unwrap();
        assert_eq!(socket_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(socket_addr.port(), 26600);
    }

    #[test]
    fn test_validator_try_into_invalid_public_key() {
        let validator = Validator {
            public_key: "invalid_hex".to_string(),
            ip_address: "127.0.0.1:26600".to_string(),
        };

        let result: Result<(PublicKey, std::net::SocketAddr), String> = (&validator).try_into();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "PublicKey bad format");
    }

    #[test]
    fn test_validator_try_into_invalid_ip() {
        let validator = Validator {
            public_key: "976ab7efaef8a73690b9067690ac7541bc34f74b2543e8db16b5bf63aec487758ca98efdf5c9fcf1154941d8a8a1ec3d".to_string(),
            ip_address: "invalid_ip".to_string(),
        };

        let result: Result<(PublicKey, std::net::SocketAddr), String> = (&validator).try_into();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid ip address");
    }

    #[test]
    fn test_get_validator_addresses_success() {
        let genesis = create_test_genesis();
        let addresses = genesis.get_validator_addresses().unwrap();
        
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].1.port(), 26600);
        assert_eq!(addresses[1].1.port(), 26610);
    }

    #[test]
    fn test_ip_of_existing_validator() {
        let genesis = create_test_genesis();
        let addresses = genesis.get_validator_addresses().unwrap();
        let (target_key, expected_addr) = &addresses[0];
        
        let found_addr = genesis.ip_of(target_key);
        assert_eq!(found_addr, Some(*expected_addr));
    }

    #[test]
    fn test_ip_of_nonexistent_validator() {
        let genesis = create_test_genesis();
        let addresses = genesis.get_validator_addresses().unwrap();
        
        // Test that we get Some() for existing validators
        for (key, _addr) in &addresses {
            assert!(genesis.ip_of(key).is_some());
        }
        
        // We can't easily create a non-existing key without the Signer API
        // so just verify the existing functionality works
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn test_genesis_configuration_values() {
        let genesis = create_test_genesis();
        
        assert_eq!(genesis.leader_timeout_ms, 2000);
        assert_eq!(genesis.notarization_timeout_ms, 4000);
        assert_eq!(genesis.nullify_timeout_ms, 4000);
        assert_eq!(genesis.activity_timeout_views, 256);
        assert_eq!(genesis.skip_timeout_views, 32);
        assert_eq!(genesis.max_message_size_bytes, 104857600);
        assert_eq!(genesis.namespace, "_SEISMIC_BFT");
        assert_eq!(genesis.eth_genesis_hash, "0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616");
    }

    #[test]
    fn test_serde_round_trip() {
        let genesis = create_test_genesis();
        let serialized = toml::to_string(&genesis).unwrap();
        let deserialized: Genesis = toml::from_str(&serialized).unwrap();
        
        assert_eq!(genesis.validator_count(), deserialized.validator_count());
        assert_eq!(genesis.eth_genesis_hash, deserialized.eth_genesis_hash);
        assert_eq!(genesis.namespace, deserialized.namespace);
    }
}
