use clap::Parser;
use commonware_codec::{DecodeExt, Encode as _};
use commonware_cryptography::bls12381::{
    dkg::ops,
    primitives::{poly, variant::MinPk},
};
use commonware_utils::{from_hex, hex, quorum};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use summit_types::PublicKey;

const DEFAULT_GENESIS_FILE: &'static str = "./example_genesis.toml";

#[derive(Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    eth_genesis_hash: String,
    leader_timeout_ms: u64,
    notarization_timeout_ms: u64,
    nullify_timeout_ms: u64,
    activity_timeout_views: u64,
    skip_timeout_views: u64,
    max_message_size_bytes: u64,
    namespace: String,
    pub identity: String,
    pub validators: Vec<Validator>,
}

impl GenesisConfig {
    pub fn load(path: &str) -> Result<GenesisConfig, Box<dyn std::error::Error>> {
        let genesis_content = std::fs::read_to_string(path)?;
        let genesis_config: GenesisConfig = toml::from_str(&genesis_content)?;
        Ok(genesis_config)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Validator {
    pub public_key: String,
    pub ip_address: String,
}

impl Validator {
    pub fn ed25519_pubkey(&self) -> PublicKey {
        let pubkey_bytes = from_hex(&self.public_key).unwrap();
        let pubkey = PublicKey::decode(&pubkey_bytes[..]).unwrap();
        pubkey
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// input for genesis file
    #[arg(short = 'i', long, default_value_t = String::from(DEFAULT_GENESIS_FILE))]
    genesis_in: String,
    /// output for genesis file
    #[arg(short = 'o', long)]
    out_dir: String,
    /// Filepath with IP addresses
    #[arg(short = 'v', long)]
    validators_path: String,
}

fn parse_validators(
    validators_path: &String,
) -> Result<Vec<Validator>, Box<dyn std::error::Error>> {
    let rdr = std::fs::File::open(validators_path)?;
    let mut validators: Vec<Validator> = serde_json::from_reader(rdr)?;
    // NOTE: (important!)
    // Sort public keys in the same order we do in summit
    validators.sort_by(|a, b| {
        let a_pubkey = a.ed25519_pubkey();
        let b_pubkey = b.ed25519_pubkey();
        a_pubkey.partial_cmp(&b_pubkey).unwrap()
    });
    Ok(validators)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let validators = parse_validators(&args.validators_path)?;
    let node_count = validators.len() as u32;
    let threshold = quorum(node_count);

    let (polynomial, shares) =
        ops::generate_shares::<_, MinPk>(&mut OsRng, None, node_count, threshold);

    println!("Network polynomial: {}", hex(&polynomial.encode()));
    println!("Network pub key: {}", poly::public::<MinPk>(&polynomial));

    // Read the genesis config
    let mut genesis_config = GenesisConfig::load(&args.genesis_in)?;

    // Update the identity with the hex of the polynomial
    genesis_config.identity = hex(&polynomial.encode());
    genesis_config.validators = validators;

    // Write the shares we generated
    for (i, _v) in genesis_config.validators.iter().enumerate() {
        let node_dir = format!("{}/node{i}", args.out_dir);
        fs::create_dir_all(&node_dir)?;

        let share_path = Path::new(&node_dir).join("share.pem");
        let share_hex = hex(&shares[i].encode());
        fs::write(&share_path, share_hex)?;
        println!("Node {i}: wrote share to {share_path:?}");
    }

    // Write the updated genesis config
    let updated_genesis = toml::to_string_pretty(&genesis_config)?;
    fs::write(&format!("{}/genesis.toml", args.out_dir), updated_genesis)?;
    println!("Updated genesis config at {}", args.out_dir);
    println!("\nSetup complete for {} nodes", node_count);

    Ok(())
}
