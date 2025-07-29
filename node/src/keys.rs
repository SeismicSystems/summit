use crate::{args::Flags, utils::get_expanded_path};
use anyhow::{Context as _, Result};
use clap::Subcommand;
use commonware_codec::extensions::DecodeExt;

use commonware_cryptography::{PrivateKeyExt as _, Signer};
use commonware_utils::from_hex_formatted;
use summit_types::PrivateKey;

#[derive(Subcommand, PartialEq, Eq, Debug, Clone)]
pub enum KeySubCmd {
    /// Print the node's public keys.
    Show,
    /// Generate new private keys.
    /// This command will fail if the keys already exist.
    Generate,
}

impl KeySubCmd {
    pub fn exec(&self, flags: &Flags) {
        match self {
            KeySubCmd::Show => self.show_key(flags),
            KeySubCmd::Generate => self.generate_keys(flags),
        }
    }

    fn generate_keys(&self, flags: &Flags) {
        // todo(dalton): Add key overwrite safety. Currently if there is already key this function will overwrite it with a new one
        let path = get_expanded_path(&flags.key_path).expect("invalid path");
        std::fs::create_dir_all(path.parent().expect("Invalide file path"))
            .expect("Unable to create file path to generate key");

        let private_key = PrivateKey::from_rng(&mut rand::thread_rng());
        let pub_key = private_key.public_key();

        let encoded_priv_key = private_key.to_string();
        std::fs::write(path, encoded_priv_key).expect("Unable to write private key to disk");

        println!("Key generated:");
        println!("Public Key: {}", pub_key);
    }

    fn show_key(&self, flags: &Flags) {
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
