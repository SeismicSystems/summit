//! Key descriptors for the SSZ state tree.
//!
//! Maps human-readable key strings (used in the RPC API) to typed
//! SSZ state tree locations: either a scalar leaf index or a
//! collection element identified by pubkey.

use crate::ssz_state_tree;
use alloy_primitives::hex;

/// A typed key descriptor for the SSZ state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SszStateKey {
    /// A scalar field at the given top-level leaf index.
    Scalar(usize),
    /// A validator account identified by its 32-byte pubkey.
    Validator([u8; 32]),
    /// A single field of a validator account: (pubkey, field_index).
    ValidatorField([u8; 32], usize),
    /// A deposit request at the given queue index.
    Deposit(usize),
    /// A pending withdrawal identified by its 32-byte pubkey.
    Withdrawal([u8; 32]),
}

/// Parse a human-readable key descriptor into an [`SszStateKey`].
///
/// Scalar keys: `"epoch"`, `"view"`, `"latest_height"`, etc.
/// Validator keys: `"validator:0xABCD..."` (hex-encoded 32-byte pubkey after colon).
/// Deposit keys: `"deposit:<index>"` (queue position, e.g. `"deposit:0"`).
/// Withdrawal keys: `"withdrawal:0xABCD..."` (hex-encoded 32-byte pubkey after colon).
pub fn parse_key(descriptor: &str) -> Result<SszStateKey, String> {
    match descriptor {
        "epoch" => Ok(SszStateKey::Scalar(ssz_state_tree::EPOCH)),
        "view" => Ok(SszStateKey::Scalar(ssz_state_tree::VIEW)),
        "latest_height" => Ok(SszStateKey::Scalar(ssz_state_tree::LATEST_HEIGHT)),
        "head_digest" => Ok(SszStateKey::Scalar(ssz_state_tree::HEAD_DIGEST)),
        "epoch_genesis_hash" => Ok(SszStateKey::Scalar(ssz_state_tree::EPOCH_GENESIS_HASH)),
        "validator_minimum_stake" => {
            Ok(SszStateKey::Scalar(ssz_state_tree::VALIDATOR_MINIMUM_STAKE))
        }
        "validator_maximum_stake" => {
            Ok(SszStateKey::Scalar(ssz_state_tree::VALIDATOR_MAXIMUM_STAKE))
        }
        "next_withdrawal_index" => Ok(SszStateKey::Scalar(ssz_state_tree::NEXT_WITHDRAWAL_INDEX)),
        "forkchoice_head_block_hash" => Ok(SszStateKey::Scalar(
            ssz_state_tree::FORKCHOICE_HEAD_BLOCK_HASH,
        )),
        "forkchoice_safe_block_hash" => Ok(SszStateKey::Scalar(
            ssz_state_tree::FORKCHOICE_SAFE_BLOCK_HASH,
        )),
        "forkchoice_finalized_block_hash" => Ok(SszStateKey::Scalar(
            ssz_state_tree::FORKCHOICE_FINALIZED_BLOCK_HASH,
        )),
        _ => {
            if let Some(rest) = descriptor.strip_prefix("validator_field:") {
                // Format: "validator_field:0xPUBKEY:field_name"
                let (hex_str, field_name) = rest.rsplit_once(':').ok_or_else(|| {
                    "validator_field requires format 'validator_field:0xPUBKEY:field_name'"
                        .to_string()
                })?;
                let pubkey = parse_hex_pubkey(hex_str)?;
                let field_index = parse_validator_field_name(field_name)?;
                Ok(SszStateKey::ValidatorField(pubkey, field_index))
            } else if let Some(hex_str) = descriptor.strip_prefix("validator:") {
                let pubkey = parse_hex_pubkey(hex_str)?;
                Ok(SszStateKey::Validator(pubkey))
            } else if let Some(index_str) = descriptor.strip_prefix("deposit:") {
                let index = index_str
                    .parse::<usize>()
                    .map_err(|e| format!("invalid deposit index: {e}"))?;
                Ok(SszStateKey::Deposit(index))
            } else if let Some(hex_str) = descriptor.strip_prefix("withdrawal:") {
                let pubkey = parse_hex_pubkey(hex_str)?;
                Ok(SszStateKey::Withdrawal(pubkey))
            } else {
                Err(format!("unknown key: {descriptor}"))
            }
        }
    }
}

fn parse_validator_field_name(name: &str) -> Result<usize, String> {
    match name {
        "consensus_pubkey" | "consensus_public_key" => {
            Ok(ssz_state_tree::VALIDATOR_FIELD_CONSENSUS_PUBKEY)
        }
        "withdrawal_credentials" => Ok(ssz_state_tree::VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS),
        "balance" => Ok(ssz_state_tree::VALIDATOR_FIELD_BALANCE),
        "status" => Ok(ssz_state_tree::VALIDATOR_FIELD_STATUS),
        "has_pending_deposit" => Ok(ssz_state_tree::VALIDATOR_FIELD_HAS_PENDING_DEPOSIT),
        "has_pending_withdrawal" => Ok(ssz_state_tree::VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL),
        "joining_epoch" => Ok(ssz_state_tree::VALIDATOR_FIELD_JOINING_EPOCH),
        "last_deposit_index" => Ok(ssz_state_tree::VALIDATOR_FIELD_LAST_DEPOSIT_INDEX),
        _ => Err(format!("unknown validator field: {name}")),
    }
}

fn parse_hex_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "pubkey must be exactly 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scalar_keys() {
        assert_eq!(parse_key("epoch").unwrap(), SszStateKey::Scalar(0));
        assert_eq!(parse_key("view").unwrap(), SszStateKey::Scalar(1));
        assert_eq!(parse_key("latest_height").unwrap(), SszStateKey::Scalar(2));
        assert_eq!(
            parse_key("forkchoice_finalized_block_hash").unwrap(),
            SszStateKey::Scalar(10)
        );
    }

    #[test]
    fn parse_validator_key() {
        let hex_key =
            "validator:0x0101010101010101010101010101010101010101010101010101010101010101";
        let key = parse_key(hex_key).unwrap();
        assert_eq!(key, SszStateKey::Validator([1u8; 32]));
    }

    #[test]
    fn parse_validator_key_no_prefix() {
        let hex_key = "validator:0202020202020202020202020202020202020202020202020202020202020202";
        let key = parse_key(hex_key).unwrap();
        assert_eq!(key, SszStateKey::Validator([2u8; 32]));
    }

    #[test]
    fn parse_deposit_key() {
        assert_eq!(parse_key("deposit:0").unwrap(), SszStateKey::Deposit(0));
        assert_eq!(parse_key("deposit:42").unwrap(), SszStateKey::Deposit(42));
    }

    #[test]
    fn parse_deposit_key_invalid() {
        assert!(parse_key("deposit:abc").is_err());
    }

    #[test]
    fn parse_withdrawal_key() {
        let hex_key =
            "withdrawal:0x0303030303030303030303030303030303030303030303030303030303030303";
        let key = parse_key(hex_key).unwrap();
        assert_eq!(key, SszStateKey::Withdrawal([3u8; 32]));
    }

    #[test]
    fn parse_validator_field_key() {
        let hex_key = "validator_field:0x0101010101010101010101010101010101010101010101010101010101010101:balance";
        let key = parse_key(hex_key).unwrap();
        assert_eq!(
            key,
            SszStateKey::ValidatorField([1u8; 32], ssz_state_tree::VALIDATOR_FIELD_BALANCE)
        );
    }

    #[test]
    fn parse_validator_field_all_fields() {
        let pk_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let fields = [
            (
                "consensus_pubkey",
                ssz_state_tree::VALIDATOR_FIELD_CONSENSUS_PUBKEY,
            ),
            (
                "consensus_public_key",
                ssz_state_tree::VALIDATOR_FIELD_CONSENSUS_PUBKEY,
            ),
            (
                "withdrawal_credentials",
                ssz_state_tree::VALIDATOR_FIELD_WITHDRAWAL_CREDENTIALS,
            ),
            ("balance", ssz_state_tree::VALIDATOR_FIELD_BALANCE),
            ("status", ssz_state_tree::VALIDATOR_FIELD_STATUS),
            (
                "has_pending_deposit",
                ssz_state_tree::VALIDATOR_FIELD_HAS_PENDING_DEPOSIT,
            ),
            (
                "has_pending_withdrawal",
                ssz_state_tree::VALIDATOR_FIELD_HAS_PENDING_WITHDRAWAL,
            ),
            (
                "joining_epoch",
                ssz_state_tree::VALIDATOR_FIELD_JOINING_EPOCH,
            ),
            (
                "last_deposit_index",
                ssz_state_tree::VALIDATOR_FIELD_LAST_DEPOSIT_INDEX,
            ),
        ];
        for (name, expected_idx) in fields {
            let key_str = format!("validator_field:0x{pk_hex}:{name}");
            let key = parse_key(&key_str).unwrap();
            assert_eq!(
                key,
                SszStateKey::ValidatorField([1u8; 32], expected_idx),
                "field: {name}"
            );
        }
    }

    #[test]
    fn parse_validator_field_unknown_field_errors() {
        let hex_key = "validator_field:0x0101010101010101010101010101010101010101010101010101010101010101:nonexistent";
        assert!(parse_key(hex_key).is_err());
    }

    #[test]
    fn parse_validator_field_missing_field_errors() {
        let hex_key =
            "validator_field:0x0101010101010101010101010101010101010101010101010101010101010101";
        assert!(parse_key(hex_key).is_err());
    }

    #[test]
    fn parse_unknown_key_errors() {
        assert!(parse_key("nonexistent").is_err());
    }

    #[test]
    fn parse_bad_hex_errors() {
        assert!(parse_key("validator:0xZZZZ").is_err());
    }

    #[test]
    fn parse_wrong_length_errors() {
        assert!(parse_key("validator:0x0101").is_err());
    }
}
