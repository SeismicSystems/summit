use alloy_primitives::FixedBytes;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use summit_types::GenesisValidator;

const DEFAULT_GENESIS_FILE: &str = "./example_genesis.toml";

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
    pub validators: Vec<GenesisValidator>,
}

impl GenesisConfig {
    pub fn load(path: &str) -> Result<GenesisConfig, Box<dyn std::error::Error>> {
        let genesis_content = std::fs::read_to_string(path)?;
        let genesis_config: GenesisConfig = toml::from_str(&genesis_content)?;
        Ok(genesis_config)
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
    /// Genesis hash
    #[arg(short = 'g', long)]
    genesis_hash: Option<FixedBytes<32>>,
}

fn parse_validators(
    validators_path: &String,
) -> Result<Vec<GenesisValidator>, Box<dyn std::error::Error>> {
    let rdr = std::fs::File::open(validators_path)?;
    let mut validators: Vec<GenesisValidator> = serde_json::from_reader(rdr)?;
    // NOTE: (important!)
    // Sort public keys in the same order we do in summit
    validators.sort_by(|a, b| {
        let a_pubkey = a.node_pubkey();
        let b_pubkey = b.node_pubkey();
        a_pubkey.partial_cmp(&b_pubkey).unwrap()
    });
    Ok(validators)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let validators = parse_validators(&args.validators_path)?;
    let node_count = validators.len() as u32;

    let mut genesis_config = GenesisConfig::load(&args.genesis_in)?;
    if let Some(genesis_hash) = args.genesis_hash {
        let hash_str = genesis_hash.to_string();
        println!("Overriding eth_genesis_hash to {hash_str}");
        genesis_config.eth_genesis_hash = hash_str;
    }
    genesis_config.validators = validators;

    // Write the updated genesis config
    let updated_genesis = toml::to_string_pretty(&genesis_config)?;
    fs::write(format!("{}/genesis.toml", args.out_dir), updated_genesis)?;
    println!("Updated genesis config at {}", args.out_dir);
    println!("\nSetup complete for {} nodes", node_count);

    Ok(())
}
