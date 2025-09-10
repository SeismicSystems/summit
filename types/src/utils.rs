use anyhow::{Context, Result};
use dirs::home_dir;
use std::{fs, path::PathBuf, str::FromStr};
use std::collections::HashMap;
use std::path::Path;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

pub fn get_expanded_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from_str(path).context("unable to parse path")?;

    if path_buf.starts_with("~") {
        let home_dir = home_dir().context("Unable to find a home directory to use with path")?;

        if path_buf == PathBuf::from("~") {
            return Ok(home_dir);
        } else if let Ok(relative) = path_buf.strip_prefix("~/") {
            return Ok(home_dir.join(relative));
        }
    }

    Ok(path_buf)
}

#[cfg(feature = "prom")]
pub mod benchmarking {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use alloy_primitives::B256;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct BlockIndex {
        block_num_to_filename: HashMap<u64, String>,
        hash_to_block_num: HashMap<B256, u64>,
    }

    impl BlockIndex {
        pub fn new() -> Self {
            Self {
                block_num_to_filename: HashMap::new(),
                hash_to_block_num: HashMap::new(),
            }
        }

        pub fn add_block(&mut self, block_number: u64, block_hash: B256, filename: String) {
            self.block_num_to_filename.insert(block_number, filename);
            self.hash_to_block_num.insert(block_hash, block_number);
        }

        pub fn get_block_file(&self, block_number: u64) -> Option<&String> {
            self.block_num_to_filename.get(&block_number)
        }

        pub fn get_block_number(&self, block_hash: &B256) -> Option<u64> {
            self.hash_to_block_num.get(block_hash).copied()
        }

        pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
            let json = serde_json::to_string_pretty(self)?;
            fs::write(path, json)?;
            Ok(())
        }

        pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
            if path.as_ref().exists() {
                let json = fs::read_to_string(path)?;
                Ok(serde_json::from_str(&json)?)
            } else {
                Ok(Self::new())
            }
        }
    }
}

