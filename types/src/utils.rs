use alloy_primitives::Address;
use anyhow::{Context, Result, anyhow};
use commonware_consensus::types::{Epocher, Height};
use dirs::home_dir;
use std::{path::PathBuf, str::FromStr};

pub fn get_expanded_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from_str(path).context("unable to parse path")?;

    if path_buf.starts_with("~") {
        let home_dir = home_dir().context("Unable to find a home directory to use with path")?;

        if *path_buf == *"~" {
            return Ok(home_dir);
        } else if let Ok(relative) = path_buf.strip_prefix("~/") {
            return Ok(home_dir.join(relative));
        }
    }

    Ok(path_buf)
}

/// Returns true if `height` is the first block in its epoch.
pub fn is_first_block_of_epoch(epocher: &impl Epocher, height: u64) -> bool {
    epocher
        .containing(Height::new(height))
        .is_some_and(|info| info.first() == info.height())
}

/// Returns true if `height` is the last block in its epoch.
pub fn is_last_block_of_epoch(epocher: &impl Epocher, height: u64) -> bool {
    epocher
        .containing(Height::new(height))
        .is_some_and(|info| info.last() == info.height())
}

/// Returns true if `height` is the penultimate (second-to-last) block in its epoch.
pub fn is_penultimate_block_of_epoch(epocher: &impl Epocher, height: u64) -> bool {
    epocher
        .containing(Height::new(height))
        .is_some_and(|info| info.last() == Height::new(height + 1))
}

pub fn parse_withdrawal_credentials(withdrawal_credentials: [u8; 32]) -> Result<Address> {
    // Validate the withdrawal credentials format
    // Eth1 withdrawal credentials: 0x01 + 11 zero bytes + 20 bytes Ethereum address
    if withdrawal_credentials.len() != 32 {
        return Err(anyhow!(
            "Invalid withdrawal credentials length: {} bytes, expected 32",
            withdrawal_credentials.len()
        ));
    }
    // Check prefix is 0x01 (Eth1 withdrawal)
    if withdrawal_credentials[0] != 0x01 {
        return Err(anyhow!(
            "Invalid withdrawal credentials prefix: 0x{:02x}, expected 0x01",
            withdrawal_credentials[0]
        ));
    }
    // Check 11 zero bytes after the prefix
    if !withdrawal_credentials[1..12].iter().all(|&b| b == 0) {
        return Err(anyhow!(
            "Invalid withdrawal credentials format: non-zero bytes in positions 1-11"
        ));
    }
    // Take last 20 bytes
    Ok(Address::from_slice(&withdrawal_credentials[12..32]))
}

pub fn invalid_deposit_refund_split(amount: u64, invalid_deposit_tax: u64) -> (u64, u64) {
    let tax = (u128::from(amount) * u128::from(invalid_deposit_tax)) / 100;
    let tax = tax as u64;
    (amount.saturating_sub(tax), tax)
}

#[cfg(test)]
mod tests {
    use super::invalid_deposit_refund_split;

    #[test]
    fn invalid_deposit_refund_split_preserves_original_amount() {
        let amounts = [
            0,
            1,
            2,
            3,
            99,
            100,
            101,
            1_000_000_000,
            32_000_000_000,
            u64::MAX,
        ];

        for amount in amounts {
            for tax_percent in 0..=100 {
                let (refund_amount, tax_amount) = invalid_deposit_refund_split(amount, tax_percent);
                assert_eq!(
                    refund_amount + tax_amount,
                    amount,
                    "amount={amount}, tax_percent={tax_percent}"
                );
            }
        }
    }

    #[test]
    fn invalid_deposit_refund_split_handles_boundary_tax_values() {
        let amount = 32_000_000_000;

        assert_eq!(invalid_deposit_refund_split(amount, 0), (amount, 0));
        assert_eq!(invalid_deposit_refund_split(amount, 100), (0, amount));
    }
}

#[cfg(feature = "bench")]
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
