use anyhow::Result;
use clap::{Args, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use commonware_codec::Encode;
use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::PrivateKey as BlsPrivateKey;
use commonware_math::algebra::Random;
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

        // Create keystore directory with owner-only access on Unix (0700) so the
        // private keys written into it are not exposed via a permissive umask.
        create_keystore_dir(&keystore_dir).expect("Unable to create keystore directory");

        // Generate ed25519 node key
        let node_private_key = PrivateKey::random(&mut rand::thread_rng());
        let node_pub_key = node_private_key.public_key();
        let encoded_node_key = commonware_utils::hex(&node_private_key.encode());
        write_private_key_file(&node_key_path, &encoded_node_key)
            .expect("Unable to write node key to disk");

        // Generate BLS consensus key
        let consensus_private_key = BlsPrivateKey::random(&mut rand::thread_rng());
        let consensus_pub_key = consensus_private_key.public_key();
        let encoded_consensus_key = commonware_utils::hex(&consensus_private_key.encode());
        write_private_key_file(&consensus_key_path, &encoded_consensus_key)
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

/// Create the keystore directory, restricting it to the owner (`0700`) on Unix.
///
/// `fs::create_dir_all` would create the directory with `0777 & !umask`, which
/// under the common `022` umask leaves it group/world traversable. The keys
/// written inside are private, so the directory is owner-only.
fn create_keystore_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Write private-key material to `path` with owner read/write only (`0600`) on
/// Unix.
///
/// Plain `fs::write` creates files with `0666 & !umask`, so a permissive umask
/// (e.g. `022`) yields a group/world-readable private key. We instead create
/// the file with mode `0600`, and — because the create-mode is ignored when the
/// file already exists (the overwrite path) and truncation preserves the old
/// mode — re-assert `0600` explicitly afterwards.
fn write_private_key_file(path: &Path, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
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
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temporary keystore path (no external tempfile dependency).
    fn unique_keystore_dir() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("summit-keys-test-{}-{}", std::process::id(), n))
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn generated_keys_and_dir_are_owner_only() {
        let dir = unique_keystore_dir();
        let flags = KeyFlags {
            key_store_path: dir.to_string_lossy().into_owned(),
            no_overwrite: false,
            yes_overwrite: true,
        };
        let cmd = KeySubCmd::Generate {
            flags: flags.clone(),
        };
        cmd.generate_keys(&flags);

        let key_paths = KeyPaths::new(flags.key_store_path.clone());
        let node_key_path = key_paths.node_key_path().unwrap();
        let consensus_key_path = key_paths.consensus_key_path().unwrap();

        // Directory must not be group/other accessible.
        assert_eq!(
            mode_of(&dir) & 0o077,
            0,
            "keystore dir mode {:o} exposes bits to group/other",
            mode_of(&dir)
        );
        // Both private-key files must be owner-only (0600).
        for p in [&node_key_path, &consensus_key_path] {
            assert_eq!(
                mode_of(p) & 0o077,
                0,
                "key file {:?} mode {:o} exposes bits to group/other",
                p,
                mode_of(p)
            );
        }

        // Keys must still load back correctly after tightening.
        let (_node, _consensus) =
            read_keys_from_keystore(&flags.key_store_path).expect("generated keys must load");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn overwrite_tightens_preexisting_loose_mode() {
        let dir = unique_keystore_dir();
        create_keystore_dir(&dir).unwrap();
        let key_paths = KeyPaths::new(dir.to_string_lossy().into_owned());
        let node_key_path = key_paths.node_key_path().unwrap();

        // Simulate a legacy world-readable key file at the target path.
        fs::write(&node_key_path, "stale").unwrap();
        fs::set_permissions(&node_key_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(mode_of(&node_key_path) & 0o077, 0);

        // Re-writing through the secure helper must re-assert 0600.
        write_private_key_file(&node_key_path, "fresh").unwrap();
        assert_eq!(mode_of(&node_key_path) & 0o077, 0);
        assert_eq!(fs::read_to_string(&node_key_path).unwrap(), "fresh");

        fs::remove_dir_all(&dir).ok();
    }
}
