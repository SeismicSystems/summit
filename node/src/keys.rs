use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::{self, Write};

use commonware_cryptography::bls12381::PrivateKey as BlsPrivateKey;
use commonware_cryptography::{PrivateKeyExt as _, Signer};
use summit_types::{KeyPaths, PrivateKey};

#[derive(Subcommand, PartialEq, Eq, Debug, Clone)]
pub enum KeySubCmd {
    /// Print the node's public keys.
    Show {
        #[command(flatten)]
        flags: KeyFlags,
    },
    /// Generate new private keys.
    /// This command will fail if the keys already exist.
    Generate {
        #[command(flatten)]
        flags: KeyFlags,
    },
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct KeyFlags {
    /// Path to your keystore directory containing node_key.pem and consensus_key.pem
    #[arg(long, default_value_t = String::from("~/.seismic/consensus/keys"))]
    pub key_store_path: String,
    #[arg(short = 'n', long, conflicts_with = "yes_overwrite")]
    pub no_overwrite: bool,
    #[arg(short = 'y', long, conflicts_with = "no_overwrite")]
    pub yes_overwrite: bool,
}

impl KeyFlags {
    fn overwrite(&self) -> Option<bool> {
        if self.no_overwrite {
            return Some(false);
        }
        if self.yes_overwrite {
            return Some(true);
        }
        None
    }
}

impl KeySubCmd {
    pub fn exec(&self) {
        match self {
            KeySubCmd::Show { flags } => self.show_key(flags),
            KeySubCmd::Generate { flags } => self.generate_keys(flags),
        }
    }

    fn generate_keys(&self, flags: &KeyFlags) {
        let key_paths = KeyPaths::new(flags.key_store_path.clone());
        let keystore_dir = key_paths.expanded().expect("Invalid --key-store-path");
        let node_key_path = key_paths.node_key_path().expect("Invalid node key path");
        let consensus_key_path = key_paths
            .consensus_key_path()
            .expect("Invalid consensus key path");

        // Check if key files already exist
        let keys_exist = node_key_path.exists() || consensus_key_path.exists();
        if keys_exist {
            match flags.overwrite() {
                Some(true) => {
                    println!("Overwriting existing keys at {}", keystore_dir.display());
                }
                Some(false) => {
                    println!("Keys already exist at {}", keystore_dir.display());
                    return;
                }
                None => {
                    print!(
                        "Keys already exist at {}. Overwrite? (y/N): ",
                        keystore_dir.display()
                    );
                    io::stdout().flush().expect("Failed to flush stdout");

                    let mut input = String::new();
                    io::stdin()
                        .read_line(&mut input)
                        .expect("Failed to read input");

                    let input = input.trim().to_lowercase();
                    if input != "y" && input != "yes" {
                        println!("Key generation cancelled.");
                        return;
                    }
                }
            }
        }

        // Create keystore directory
        std::fs::create_dir_all(&keystore_dir).expect("Unable to create keystore directory");

        // Generate ed25519 node key
        let node_private_key = PrivateKey::from_rng(&mut rand::thread_rng());
        let node_pub_key = node_private_key.public_key();
        let encoded_node_key = node_private_key.to_string();
        std::fs::write(node_key_path, encoded_node_key).expect("Unable to write node key to disk");

        // Generate BLS consensus key
        let consensus_private_key = BlsPrivateKey::from_rng(&mut rand::thread_rng());
        let consensus_pub_key = consensus_private_key.public_key();
        let encoded_consensus_key = consensus_private_key.to_string();
        std::fs::write(consensus_key_path, encoded_consensus_key)
            .expect("Unable to write consensus key to disk");

        println!("Keys generated at {}:", keystore_dir.display());
        println!("Node Public Key (ed25519): {}", node_pub_key);
        println!("Consensus Public Key (BLS): {}", consensus_pub_key);
    }

    fn show_key(&self, flags: &KeyFlags) {
        let key_paths = KeyPaths::new(flags.key_store_path.clone());

        let node_pub_key = key_paths
            .node_public_key()
            .expect("Unable to read node key from disk");
        let consensus_pub_key = key_paths
            .consensus_public_key()
            .expect("Unable to read consensus key from disk");

        println!("Node Public Key (ed25519): {}", node_pub_key);
        println!("Consensus Public Key (BLS): {}", consensus_pub_key);
    }
}

pub fn read_keys_from_keystore(keystore_path: &str) -> Result<(PrivateKey, BlsPrivateKey)> {
    let key_paths = KeyPaths::new(keystore_path.to_string());
    let node_key = key_paths.read_node_key_from_file()?;
    let consensus_key = key_paths.read_bls_key_from_file()?;
    Ok((node_key, consensus_key))
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//    use commonware_cryptography::Signer;
//
//    #[test]
//    fn test_generate_testnet_keys() {
//        // Generate 4 BLS private keys for testnet nodes
//        for i in 0..4 {
//            let node_dir = format!("../testnet/node{}", i);
//
//            // Create directory
//            std::fs::create_dir_all(&node_dir).expect("Unable to create testnet directory");
//
//            // Generate BLS consensus key deterministically from seed
//            let consensus_private_key = BlsPrivateKey::from_seed(i as u64);
//            let consensus_pub_key = consensus_private_key.public_key();
//
//            // Save consensus key
//            let consensus_key_path = format!("{}/{}", node_dir, CONSENSUS_KEY_FILENAME);
//            let encoded_consensus_key = consensus_private_key.to_string();
//            std::fs::write(&consensus_key_path, encoded_consensus_key)
//                .expect("Unable to write consensus key to disk");
//
//            println!("Generated keys for node{} at {consensus_key_path}:", i);
//            println!("  Consensus Public Key (BLS): {}", consensus_pub_key);
//
//            // Verify we can read the key back
//            let read_consensus_key = read_bls_key_from_file(std::path::Path::new(&consensus_key_path))
//                .expect("Unable to read consensus key");
//
//            assert_eq!(consensus_pub_key, read_consensus_key.public_key());
//        }
//
//        println!("\nSuccessfully generated and verified BLS keys for 4 testnet nodes");
//    }
//}
