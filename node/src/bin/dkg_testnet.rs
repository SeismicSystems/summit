use clap::Parser;
use commonware_codec::Encode as _;
use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::MinPk},
    },
    ed25519::PrivateKey,
};
use commonware_utils::{hex, quorum};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
struct Args {
    /// Number of nodes you want to do dkg with
    #[arg(long, default_value_t = 4)]
    nodes: u32,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let threshold = quorum(args.nodes);

    let (polynomial, shares) =
        ops::generate_shares::<_, MinPk>(&mut OsRng, None, args.nodes, threshold);

    println!("Network polynomial: {}", hex(&polynomial.encode()));
    println!("Network pub key: {}", poly::public::<MinPk>(&polynomial));

    // Read the genesis config
    let genesis_path = "./example_genesis.toml";
    let genesis_content = fs::read_to_string(genesis_path)?;
    let mut genesis_config: GenesisConfig = toml::from_str(&genesis_content)?;

    // Update the identity with the hex of the polynomial
    genesis_config.identity = hex(&polynomial.encode());

    let mut private_keys = Vec::with_capacity(args.nodes as usize);

    // Generate the private keys first so we can sort them in the same order we do in summit
    for _ in 0usize..args.nodes as usize {
        let private_key = PrivateKey::from_rng(&mut OsRng);
        private_keys.push((private_key.public_key(), private_key));
    }

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

        // Write private key
        let key_path = Path::new(&node_dir).join("key.pem");
        let private_key_hex = hex(&private_keys[i].1);
        fs::write(&key_path, private_key_hex)?;
        println!("Written private key to {key_path:?}");

        // Write share
        let share_path = Path::new(&node_dir).join("share.pem");
        let share_hex = hex(&shares[i].encode());
        fs::write(&share_path, share_hex)?;
        println!("Written share to {share_path:?}");

        // Update the public key in genesis config
        genesis_config.validators[i].public_key = hex(&private_keys[i].0);
    }

    // Write the updated genesis config
    let updated_genesis = toml::to_string_pretty(&genesis_config)?;
    fs::write(genesis_path, updated_genesis)?;
    println!("Updated genesis config at {genesis_path}");

    println!("\nSetup complete for {} nodes", args.nodes);

    Ok(())
}
