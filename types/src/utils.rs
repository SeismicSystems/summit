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
