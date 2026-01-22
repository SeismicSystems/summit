use crate::PublicKey;
use crate::utils::get_expanded_path;
use commonware_codec::DecodeExt as _;
use commonware_p2p::Ingress;
use commonware_utils::{Hostname, from_hex_formatted};
use serde::Deserialize;
use std::net::SocketAddr;

/// A single bootstrapper node
#[derive(Debug, Clone, Deserialize)]
pub struct Bootstrapper {
    /// Hex-encoded public key (ed25519, 32 bytes)
    pub node_public_key: String,
    /// Address - either IP:port (e.g., "127.0.0.1:18551") or domain:port (e.g., "node.example.com:18551")
    pub address: String,
}

/// List of bootstrapper nodes loaded from a TOML file
#[derive(Debug, Clone, Deserialize)]
pub struct Bootstrappers {
    pub bootstrappers: Vec<Bootstrapper>,
}

/// Parse an address string into an Ingress.
/// Supports both IP:port (e.g., "127.0.0.1:18551") and domain:port (e.g., "node.example.com:18551")
fn parse_ingress(address: &str) -> Result<Ingress, Box<dyn std::error::Error>> {
    // Try to parse as a socket address first (IP:port)
    if let Ok(socket_addr) = address.parse::<SocketAddr>() {
        return Ok(Ingress::from(socket_addr));
    }

    // Otherwise, try to parse as hostname:port
    let (host, port_str) = address
        .rsplit_once(':')
        .ok_or_else(|| format!("Invalid address format (expected host:port): {address}"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("Invalid port number: {port_str}"))?;

    let hostname = Hostname::new(host).map_err(|e| format!("Invalid hostname '{host}': {e}"))?;

    Ok(Ingress::Dns {
        host: hostname,
        port,
    })
}

impl Bootstrappers {
    /// Load bootstrappers from a TOML file
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let expanded_path = get_expanded_path(path)?;
        let content = std::fs::read_to_string(expanded_path)?;
        let bootstrappers: Bootstrappers = toml::from_str(&content)?;
        Ok(bootstrappers)
    }

    /// Convert to a list of (PublicKey, Ingress) pairs
    pub fn to_ingress_list(&self) -> Result<Vec<(PublicKey, Ingress)>, Box<dyn std::error::Error>> {
        let mut result = Vec::with_capacity(self.bootstrappers.len());
        for entry in &self.bootstrappers {
            let pk_bytes: Vec<u8> = from_hex_formatted(&entry.node_public_key)
                .ok_or("Invalid hex-encoded public key")?;
            let pk =
                PublicKey::decode(&pk_bytes[..]).map_err(|e| format!("Invalid public key: {e}"))?;
            let ingress = parse_ingress(&entry.address)?;
            result.push((pk, ingress));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use commonware_math::algebra::Random;
    use commonware_utils::hex;
    use rand::rngs::OsRng;

    fn generate_test_pk_hex() -> String {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        format!("0x{}", hex(public_key.as_ref()))
    }

    #[test]
    fn test_parse_bootstrappers_toml() {
        let pk1 = generate_test_pk_hex();
        let pk2 = generate_test_pk_hex();

        let toml_content = format!(
            r#"
[[bootstrappers]]
node_public_key = "{pk1}"
address = "127.0.0.1:18551"

[[bootstrappers]]
node_public_key = "{pk2}"
address = "192.168.1.100:18552"
"#
        );

        let bootstrappers: Bootstrappers = toml::from_str(&toml_content).unwrap();
        assert_eq!(bootstrappers.bootstrappers.len(), 2);
        assert_eq!(bootstrappers.bootstrappers[0].address, "127.0.0.1:18551");
        assert_eq!(
            bootstrappers.bootstrappers[1].address,
            "192.168.1.100:18552"
        );
    }

    #[test]
    fn test_to_ingress_list() {
        let pk1 = generate_test_pk_hex();
        let pk2 = generate_test_pk_hex();

        let bootstrappers = Bootstrappers {
            bootstrappers: vec![
                Bootstrapper {
                    node_public_key: pk1,
                    address: "127.0.0.1:18551".to_string(),
                },
                Bootstrapper {
                    node_public_key: pk2,
                    address: "192.168.1.100:18552".to_string(),
                },
            ],
        };

        let ingress_list = bootstrappers.to_ingress_list().unwrap();
        assert_eq!(ingress_list.len(), 2);

        // Verify the addresses were parsed correctly
        let addr1: SocketAddr = "127.0.0.1:18551".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.100:18552".parse().unwrap();
        assert_eq!(ingress_list[0].1, Ingress::from(addr1));
        assert_eq!(ingress_list[1].1, Ingress::from(addr2));
    }

    #[test]
    fn test_invalid_public_key_hex() {
        let bootstrappers = Bootstrappers {
            bootstrappers: vec![Bootstrapper {
                node_public_key: "invalid_hex".to_string(),
                address: "127.0.0.1:18551".to_string(),
            }],
        };

        let result = bootstrappers.to_ingress_list();
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length_public_key() {
        // Valid hex but wrong length (31 bytes instead of 32)
        let bootstrappers = Bootstrappers {
            bootstrappers: vec![Bootstrapper {
                node_public_key: "0x01010101010101010101010101010101010101010101010101010101010101"
                    .to_string(),
                address: "127.0.0.1:18551".to_string(),
            }],
        };

        let result = bootstrappers.to_ingress_list();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_address() {
        let pk = generate_test_pk_hex();
        let bootstrappers = Bootstrappers {
            bootstrappers: vec![Bootstrapper {
                node_public_key: pk,
                address: "not_an_address".to_string(),
            }],
        };

        let result = bootstrappers.to_ingress_list();
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_address() {
        let pk = generate_test_pk_hex();
        let bootstrappers = Bootstrappers {
            bootstrappers: vec![Bootstrapper {
                node_public_key: pk,
                address: "node.example.com:18551".to_string(),
            }],
        };

        let ingress_list = bootstrappers.to_ingress_list().unwrap();
        assert_eq!(ingress_list.len(), 1);

        // Verify it's a DNS ingress
        match &ingress_list[0].1 {
            Ingress::Dns { host, port } => {
                assert_eq!(host.as_str(), "node.example.com");
                assert_eq!(*port, 18551);
            }
            Ingress::Socket(_) => panic!("Expected DNS ingress, got Socket"),
        }
    }

    #[test]
    fn test_mixed_addresses() {
        let pk1 = generate_test_pk_hex();
        let pk2 = generate_test_pk_hex();

        let bootstrappers = Bootstrappers {
            bootstrappers: vec![
                Bootstrapper {
                    node_public_key: pk1,
                    address: "127.0.0.1:18551".to_string(),
                },
                Bootstrapper {
                    node_public_key: pk2,
                    address: "validator.example.com:18552".to_string(),
                },
            ],
        };

        let ingress_list = bootstrappers.to_ingress_list().unwrap();
        assert_eq!(ingress_list.len(), 2);

        // First should be Socket
        assert!(matches!(ingress_list[0].1, Ingress::Socket(_)));

        // Second should be DNS
        assert!(matches!(ingress_list[1].1, Ingress::Dns { .. }));
    }

    #[test]
    fn test_parse_ingress_socket() {
        let ingress = parse_ingress("192.168.1.1:8080").unwrap();
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        assert_eq!(ingress, Ingress::from(addr));
    }

    #[test]
    fn test_parse_ingress_dns() {
        let ingress = parse_ingress("example.com:443").unwrap();
        match ingress {
            Ingress::Dns { host, port } => {
                assert_eq!(host.as_str(), "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected DNS ingress"),
        }
    }

    #[test]
    fn test_parse_ingress_missing_port() {
        let result = parse_ingress("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ingress_invalid_port() {
        let result = parse_ingress("example.com:notaport");
        assert!(result.is_err());
    }
}
