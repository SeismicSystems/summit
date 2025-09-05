use clap::Parser;
use commonware_codec::{DecodeExt, Encode as _};
use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::MinPk},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::{from_hex, hex, quorum};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const DEFAULT_GENESIS_FILE: &'static str = "./example_genesis.toml";

#[derive(Parser, Debug)]
struct Args {
    /// Number of nodes you want to do dkg with
    #[arg(short = 'n', long, default_value_t = 4)]
    nodes: u32,
    /// input for genesis file
    #[arg(short = 'i', long, default_value_t = String::from(DEFAULT_GENESIS_FILE))]
    genesis_in: String,
    /// output for genesis file
    #[arg(short = 'o', long, default_value_t = String::from(DEFAULT_GENESIS_FILE))]
    genesis_out: String,
    /// Filepath with IP addresses
    #[arg(short = 'v', long)]
    validators_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenesisConfig {
    eth_genesis_hash: String,
    leader_timeout_ms: u64,
    notarization_timeout_ms: u64,
    nullify_timeout_ms: u64,
    activity_timeout_views: u64,
    skip_timeout_views: u64,
    max_message_size_bytes: u64,
    namespace: String,
    identity: String,
    validators: Vec<Validator>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Validator {
    public_key: String,
    ip_address: String,
}

fn parse_validators(
    validators_path: &String,
    nodes: usize,
) -> Result<(Vec<(PublicKey, Option<PrivateKey>)>, Option<Vec<String>>), Box<dyn std::error::Error>>
{
    let rdr = std::fs::File::open(validators_path)?;
    let validators: Vec<Validator> = serde_json::from_reader(rdr)?;
    if validators.len() != nodes as usize {
        panic!(
            "Node count ({}) does not match length of validators file ({}) at {}",
            nodes,
            validators.len(),
            validators_path
        );
    }
    let mut private_keys = vec![];
    let mut ip_addresses = vec![];
    for v in validators {
        let pubkey_bytes = from_hex(&v.public_key).unwrap();
        let pubkey = PublicKey::decode(&pubkey_bytes[..]).unwrap();
        private_keys.push((pubkey, None));
        ip_addresses.push(v.ip_address);
    }
    Ok((private_keys, Some(ip_addresses)))
}

fn generate_private_keys(nodes: usize) -> Vec<(PublicKey, Option<PrivateKey>)> {
    let mut private_keys = Vec::with_capacity(nodes);
    for _ in 0..nodes as usize {
        let private_key = PrivateKey::from_rng(&mut OsRng);
        private_keys.push((private_key.public_key(), Some(private_key)));
    }
    private_keys
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let threshold = quorum(args.nodes);

    let (polynomial, shares) =
        ops::generate_shares::<_, MinPk>(&mut OsRng, None, args.nodes, threshold);

    println!("Network polynomial: {}", hex(&polynomial.encode()));
    println!("Network pub key: {}", poly::public::<MinPk>(&polynomial));

    // Read the genesis config
    let genesis_content = fs::read_to_string(&args.genesis_in)?;
    let mut genesis_config: GenesisConfig = toml::from_str(&genesis_content)?;

    // Update the identity with the hex of the polynomial
    genesis_config.identity = hex(&polynomial.encode());

    let (mut private_keys, ip_addresses) = match args.validators_path {
        None => (generate_private_keys(args.nodes as usize), None),
        Some(p) => parse_validators(&p, args.nodes as usize)?,
    };
    // sort public keys in the same order we do in summit
    private_keys.sort();

    // Ensure we have the right number of validators in the config
    if genesis_config.validators.len() != args.nodes as usize {
        return Err(format!(
            "Number of validators in genesis config ({}) doesn't match nodes argument ({})",
            genesis_config.validators.len(),
            args.nodes
        )
        .into());
    }

    // Process each node
    for i in 0usize..args.nodes as usize {
        let node_dir = format!("./testnet/node{i}");

        // Create directory if it doesn't exist
        fs::create_dir_all(&node_dir)?;

        // Write share
        let share_path = Path::new(&node_dir).join("share.pem");
        let share_hex = hex(&shares[i].encode());
        fs::write(&share_path, share_hex)?;
        println!("Written share to {share_path:?}");

        if let Some(pk) = &private_keys[i].1 {
            let key_path = Path::new(&node_dir).join("key.pem");
            let private_key_hex = hex(&pk);
            fs::write(&key_path, private_key_hex)?;
            println!("Written private key to {key_path:?}");
        }

        // Update the public key in genesis config
        genesis_config.validators[i].public_key = hex(&private_keys[i].0);
        if let Some(ips) = &ip_addresses {
            genesis_config.validators[i].ip_address = ips[i].clone();
        }
    }

    // Write the updated genesis config
    let updated_genesis = toml::to_string_pretty(&genesis_config)?;
    fs::write(&args.genesis_out, updated_genesis)?;
    println!("Updated genesis config at {}", args.genesis_out);

    println!("\nSetup complete for {} nodes", args.nodes);

    Ok(())
}
