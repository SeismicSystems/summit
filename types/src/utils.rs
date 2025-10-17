use anyhow::{Context, Result};
use dirs::home_dir;
use std::{path::PathBuf, str::FromStr};

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

pub fn is_last_block_of_epoch(height: u64, epoch_num_blocks: u64) -> bool {
    height > 0 && height % epoch_num_blocks == 0
}

pub fn is_penultimate_block_of_epoch(height: u64, epoch_num_blocks: u64) -> bool {
    height > 0 && (height + 1) % epoch_num_blocks == 0
}

#[cfg(any(feature = "base-bench", feature = "bench"))]
pub mod benchmarking {
    use alloy_primitives::B256;
    use anyhow::{anyhow, bail};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::default::Default;
    use std::fs;
    use std::path::Path;

    #[derive(Clone, Debug, Serialize, Deserialize, Default)]
    pub struct BlockIndex {
        block_num_to_filename: HashMap<u64, String>,
        hash_to_block_num: HashMap<B256, u64>,
    }

    impl BlockIndex {
        pub fn new() -> Self {
            Self::default()
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
            let mut temp_file = path.as_ref().to_path_buf();
            temp_file.set_extension("temp");
            fs::write(&temp_file, json)?;
            fs::rename(&temp_file, path)?;
            Ok(())
        }

        pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
            if path.as_ref().exists() {
                let json = fs::read_to_string(path)?;
                let block_index: Self = serde_json::from_str(&json)?;
                assert_eq!(
                    block_index.hash_to_block_num.len(),
                    block_index.block_num_to_filename.len()
                );
                Ok(block_index)
            } else {
                Ok(Self::new())
            }
        }

        pub fn verify(&self, block_dir: &Path) -> anyhow::Result<()> {
            if self.block_num_to_filename.len() != self.hash_to_block_num.len() {
                bail!(
                    "block_num_to_filename ({}) and hash_to_block_num ({}) length do not match",
                    self.block_num_to_filename.len(),
                    self.hash_to_block_num.len()
                );
            }
            let max_block = *self
                .block_num_to_filename
                .keys()
                .max()
                .ok_or(anyhow!("no blocks in index"))?;
            for block_num in 0..=max_block {
                let filename = self
                    .get_block_file(block_num)
                    .ok_or(anyhow!("missing block {} in block index", block_num))?;
                let file_path = block_dir.join(filename);
                if !file_path.exists() {
                    bail!(anyhow!("missing block file for block {}", block_num));
                }
            }
            Ok(())
        }

        pub fn create_sub_index(&self, max_block: u64) -> Self {
            let mut block_num_to_filename = HashMap::new();
            let mut hash_to_block_num = HashMap::new();
            for (block_number, filename) in self.block_num_to_filename.iter() {
                if block_number > &max_block {
                    break;
                }
                block_num_to_filename.insert(*block_number, filename.clone());
            }
            for (block_hash, block_number) in self.hash_to_block_num.iter() {
                if block_number > &max_block {
                    break;
                }
                hash_to_block_num.insert(*block_hash, *block_number);
            }
            Self {
                block_num_to_filename,
                hash_to_block_num,
            }
        }
    }
}
