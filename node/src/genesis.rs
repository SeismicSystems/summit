use clap::Subcommand;
use commonware_utils::from_hex_formatted;
use std::fs;
use summit_types::{Genesis, GenesisValidator};

/// Offline genesis-file utilities. Both subcommands go through summit's own
/// `Genesis` type, so the file a network is founded on and the digest that
/// identifies it come from the same definition a validator loads at startup.
#[derive(Subcommand, PartialEq, Eq, Debug, Clone)]
pub enum GenesisSubCmd {
    /// Set the genesis validator set, replacing any the template declares.
    ///
    /// The validators read from JSON become the whole set: whatever the input
    /// declared is discarded, never appended to. Everything else comes from the
    /// input untouched — EL genesis hash, namespace, timeouts, stake bounds.
    ///
    /// The set is emitted sorted by node public key, because `config_digest`
    /// hashes the validators in file order: their order is part of the chain
    /// identity every node has to agree on.
    SetValidators {
        /// Genesis template to fill in
        #[arg(short = 'i', long)]
        genesis_in: String,
        /// JSON file listing the genesis validators
        #[arg(short = 'v', long)]
        validators_path: String,
        /// File the completed genesis is written to; stdout if omitted
        #[arg(short = 'o', long)]
        genesis_out: Option<String>,
    },
    /// Load a genesis file and print its config digest.
    ///
    /// The digest identifies the chain the file founds: it domain-separates
    /// every consensus signature, and it is what a network manifest pins to
    /// commit to a validator set. Output is a single 0x-prefixed 32-byte hex
    /// line, so tooling can shell out for it.
    ///
    /// The file is loaded exactly as a starting validator loads it, so a
    /// successful digest doubles as a verdict that the genesis is well formed:
    /// anything this accepts a validator accepts, and anything it rejects a
    /// validator would refuse to start on.
    Digest {
        /// Path to the summit genesis.toml
        genesis_path: String,
    },
}

impl GenesisSubCmd {
    pub fn exec(&self) {
        match self {
            GenesisSubCmd::SetValidators {
                genesis_in,
                validators_path,
                genesis_out,
            } => {
                let genesis = fill_template(&read(genesis_in), &read(validators_path))
                    .unwrap_or_else(|e| fail(format!("failed to fill the genesis template: {e}")));
                let rendered = toml::to_string_pretty(&genesis)
                    .unwrap_or_else(|e| fail(format!("failed to render genesis: {e}")));

                // Re-parse what we are about to emit, down the same path a
                // starting validator takes. Emitting a genesis no node can load
                // is the failure this command exists to prevent, so it surfaces
                // here rather than at someone's boot.
                Genesis::from_toml_str(&rendered)
                    .unwrap_or_else(|e| fail(format!("the genesis produced does not load: {e}")));

                match genesis_out {
                    Some(genesis_out) => {
                        fs::write(genesis_out, rendered).unwrap_or_else(|e| {
                            fail(format!("failed to write {genesis_out}: {e}"))
                        });
                        // Progress goes to stderr so stdout carries genesis and
                        // nothing else, whichever destination was chosen.
                        eprintln!(
                            "Wrote genesis for {} validators to {genesis_out}",
                            genesis.validator_count()
                        );
                    }
                    None => print!("{rendered}"),
                }
            }
            GenesisSubCmd::Digest { genesis_path } => {
                let genesis = load(genesis_path);
                println!("0x{}", commonware_utils::hex(&genesis.config_digest()));
            }
        }
    }
}

/// Fill `template` with the validator set from `validators_json`.
///
/// The template is parsed into summit's canonical `Genesis` type rather than a
/// local copy of the schema: a private struct here silently drops fields the
/// runtime requires (e.g. `validator_minimum_stake`), producing a genesis the
/// node can't load.
fn fill_template(
    template: &str,
    validators_json: &str,
) -> Result<Genesis, Box<dyn std::error::Error>> {
    let mut genesis: Genesis = toml::from_str(template)?;
    let validators: Vec<GenesisValidator> = serde_json::from_str(validators_json)?;

    // Sort by decoded node key, the order `config_digest` — and so the chain
    // domain every node derives — is computed over. Decoding also accepts the
    // `0x`-prefixed and mixed-case spellings `Genesis` itself accepts on load.
    let mut keyed = validators
        .into_iter()
        .map(|validator| {
            let key = from_hex_formatted(&validator.node_public_key).ok_or_else(|| {
                format!(
                    "validator node_public_key is not valid hex: {:?}",
                    validator.node_public_key
                )
            })?;
            Ok((key, validator))
        })
        .collect::<Result<Vec<_>, String>>()?;
    keyed.sort_by(|(lhs, _), (rhs, _)| lhs.cmp(rhs));

    genesis.validators = keyed.into_iter().map(|(_, validator)| validator).collect();
    Ok(genesis)
}

/// Load a genesis file, exiting non-zero with the parse/validation error on
/// stderr. This is shelled out to by tooling that pins the digest, so failures
/// must be an exit code and a message, not a panic backtrace.
fn load(genesis_path: &str) -> Genesis {
    Genesis::load_from_file(genesis_path)
        .unwrap_or_else(|e| fail(format!("failed to load genesis from {genesis_path}: {e}")))
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| fail(format!("failed to read {path}: {e}")))
}

fn fail(message: String) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "../example_genesis.toml";

    /// The emitter must produce a complete genesis: every template field
    /// preserved, and the validator set sorted by node key whatever order it
    /// arrived in — file order is what the config digest commits to.
    #[test]
    fn emits_complete_genesis_sorted_by_node_key() {
        let example = Genesis::load_from_file(EXAMPLE).unwrap();

        // Feed the validators back in reverse, one of them respelled with a
        // `0x` prefix and upper-case digits — a spelling `Genesis` accepts.
        let mut shuffled = example.validators.clone();
        shuffled.reverse();
        shuffled[0].node_public_key = format!("0x{}", shuffled[0].node_public_key.to_uppercase());
        let validators_json = serde_json::to_string(&shuffled).unwrap();

        let built = fill_template(&read(EXAMPLE), &validators_json).unwrap();

        // Template fields the validator set doesn't carry must survive.
        assert_eq!(built.namespace, example.namespace);
        assert_eq!(built.eth_genesis_hash, example.eth_genesis_hash);
        assert_eq!(
            built.validator_minimum_stake,
            example.validator_minimum_stake
        );
        assert_eq!(built.blocks_per_epoch, example.blocks_per_epoch);

        let keys: Vec<Vec<u8>> = built
            .validators
            .iter()
            .map(|v| from_hex_formatted(&v.node_public_key).unwrap())
            .collect();
        assert_eq!(keys.len(), example.validators.len());
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "emitted validators must be ascending by node key"
        );
    }

    /// What the emitter writes must load through summit's own loader and keep
    /// the chain identity intact — the guard against emitting a genesis that
    /// parses here but not in the node, or that quietly founds a different chain.
    #[test]
    fn emitted_genesis_loads_back_with_the_same_identity() {
        let example = Genesis::load_from_file(EXAMPLE).unwrap();
        let validators_json = serde_json::to_string(&example.validators).unwrap();
        let built = fill_template(&read(EXAMPLE), &validators_json).unwrap();

        let rendered = toml::to_string_pretty(&built).unwrap();
        let loaded = Genesis::from_toml_str(&rendered).unwrap();

        assert_eq!(loaded.validator_count(), example.validator_count());
        assert_eq!(loaded.config_digest(), example.config_digest());
    }

    #[test]
    fn rejects_a_validator_whose_node_key_is_not_hex() {
        let example = Genesis::load_from_file(EXAMPLE).unwrap();
        let mut validators = example.validators.clone();
        validators[0].node_public_key = "not-a-key".into();
        let validators_json = serde_json::to_string(&validators).unwrap();
        assert!(fill_template(&read(EXAMPLE), &validators_json).is_err());
    }
}
