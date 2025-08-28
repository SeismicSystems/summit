use crate::args::DEFAULT_KEY_PATH;
use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use commonware_codec::extensions::DecodeExt;
use std::io::{self, Write};

use commonware_cryptography::{PrivateKeyExt as _, Signer};
use commonware_utils::from_hex_formatted;
use summit_types::{PrivateKey, utils::get_expanded_path};

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
    /// Path to your private key or where you want it generated
    #[arg(long, default_value_t = DEFAULT_KEY_PATH.into())]
    pub key_path: String,
}

impl KeySubCmd {
    pub fn exec(&self) {
        match self {
            KeySubCmd::Show { flags } => self.show_key(flags),
            KeySubCmd::Generate { flags } => self.generate_keys(flags),
        }
    }

    fn generate_keys(&self, flags: &KeyFlags) {
        let path = get_expanded_path(&flags.key_path).expect("Invalid path");

        // Check if key file already exists
        if path.exists() {
            print!(
                "Key file already exists at {}. Overwrite? (y/N): ",
                path.display()
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

        std::fs::create_dir_all(path.parent().expect("Invalid file path"))
            .expect("Unable to create file path to generate key");

        let private_key = PrivateKey::from_rng(&mut rand::thread_rng());
        let pub_key = private_key.public_key();

        let encoded_priv_key = private_key.to_string();
        std::fs::write(path, encoded_priv_key).expect("Unable to write private key to disk");

        println!("Key generated:");
        println!("Public Key: {pub_key}");
    }

    fn show_key(&self, flags: &KeyFlags) {
        let pk =
            read_ed_key_from_path(&flags.key_path).expect("Unable to read private key from disk");

        println!("Your nodes public key is : {}", pk.public_key());
    }
}

// pub fn read_bls_key_from_path(key_path: &str) -> Result<PrivateKey> {
//     let path = get_expanded_path(key_path)?;
//     let encoded_pk = std::fs::read_to_string(path)?;

//     let key = from_hex_formatted(&encoded_pk).context("Invalid pk format")?;
//     let pk = PrivateKey::decode(&*key)?;

//     Ok(pk)
// }

pub fn read_ed_key_from_path(key_path: &str) -> Result<PrivateKey> {
    let path = get_expanded_path(key_path)?;
    let encoded_pk = std::fs::read_to_string(path)?;

    let key = from_hex_formatted(&encoded_pk).context("Invalid pk format")?;
    let pk = PrivateKey::decode(&*key)?;

    Ok(pk)
}
