use clap::Subcommand;
use summit_types::Genesis;

/// Offline genesis-file utilities.
#[derive(Subcommand, PartialEq, Eq, Debug, Clone)]
pub enum GenesisSubCmd {
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
            GenesisSubCmd::Digest { genesis_path } => {
                let genesis = load(genesis_path);
                println!("0x{}", commonware_utils::hex(&genesis.config_digest()));
            }
        }
    }
}

/// Load a genesis file, exiting non-zero with the parse/validation error on
/// stderr. This is shelled out to by tooling that pins the digest, so failures
/// must be an exit code and a message, not a panic backtrace.
fn load(genesis_path: &str) -> Genesis {
    match Genesis::load_from_file(genesis_path) {
        Ok(genesis) => genesis,
        Err(e) => {
            eprintln!("failed to load genesis from {genesis_path}: {e}");
            std::process::exit(1);
        }
    }
}
