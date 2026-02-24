//! SSZ hash-tree-root implementations for Summit types.
//!
//! Provides the `SszHashTreeRoot` trait and implementations for all types
//! that participate in the SSZ binary Merkle tree.

use crate::PublicKey;
use crate::account::{ValidatorAccount, ValidatorStatus};
use crate::execution_request::DepositRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use crate::ssz_tree::merkleize;
use crate::withdrawal::PendingWithdrawal;
use alloy_primitives::Address;
use commonware_cryptography::bls12381;
use ethereum_hashing::hash32_concat;

/// Trait for computing the SSZ hash-tree-root of a value.
pub trait SszHashTreeRoot {
    fn hash_tree_root(&self) -> [u8; 32];
}

// --- Primitives ---

impl SszHashTreeRoot for u64 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut chunk = [0u8; 32];
        chunk[0..8].copy_from_slice(&self.to_le_bytes());
        chunk
    }
}

impl SszHashTreeRoot for bool {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut chunk = [0u8; 32];
        chunk[0] = *self as u8;
        chunk
    }
}

impl SszHashTreeRoot for [u8; 32] {
    fn hash_tree_root(&self) -> [u8; 32] {
        *self
    }
}

impl SszHashTreeRoot for Address {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut chunk = [0u8; 32];
        chunk[0..20].copy_from_slice(&self.0[..]);
        chunk
    }
}

// --- Crypto types ---

impl SszHashTreeRoot for bls12381::PublicKey {
    /// BLS public key (48 bytes) → 2 chunks: bytes[0..32], pad(bytes[32..48]).
    fn hash_tree_root(&self) -> [u8; 32] {
        let bytes: &[u8] = self.as_ref();
        debug_assert_eq!(bytes.len(), 48);
        let mut chunk0 = [0u8; 32];
        let mut chunk1 = [0u8; 32];
        chunk0.copy_from_slice(&bytes[0..32]);
        chunk1[0..16].copy_from_slice(&bytes[32..48]);
        hash32_concat(&chunk0, &chunk1)
    }
}

impl SszHashTreeRoot for PublicKey {
    /// Ed25519 public key (32 bytes) → identity.
    fn hash_tree_root(&self) -> [u8; 32] {
        self.as_ref()
            .try_into()
            .expect("ed25519 PublicKey is 32 bytes")
    }
}

// --- Enums ---

impl SszHashTreeRoot for ValidatorStatus {
    fn hash_tree_root(&self) -> [u8; 32] {
        let val: u8 = match self {
            ValidatorStatus::Active => 0,
            ValidatorStatus::Inactive => 1,
            ValidatorStatus::SubmittedExitRequest => 2,
            ValidatorStatus::Joining => 3,
        };
        let mut chunk = [0u8; 32];
        chunk[0] = val;
        chunk
    }
}

impl SszHashTreeRoot for ProtocolParam {
    /// ProtocolParam as a 2-field container: (tag, value).
    fn hash_tree_root(&self) -> [u8; 32] {
        let (tag, value) = match self {
            ProtocolParam::MinimumStake(v) => (0u64, *v),
            ProtocolParam::MaximumStake(v) => (1u64, *v),
        };
        merkleize(&[tag.hash_tree_root(), value.hash_tree_root()])
    }
}

// --- Containers ---

impl SszHashTreeRoot for ValidatorAccount {
    /// 8-field container: consensus_public_key, withdrawal_credentials, balance,
    /// status, has_pending_deposit, has_pending_withdrawal, joining_epoch, last_deposit_index.
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.consensus_public_key.hash_tree_root(),
            self.withdrawal_credentials.hash_tree_root(),
            self.balance.hash_tree_root(),
            self.status.hash_tree_root(),
            self.has_pending_deposit.hash_tree_root(),
            self.has_pending_withdrawal.hash_tree_root(),
            self.joining_epoch.hash_tree_root(),
            self.last_deposit_index.hash_tree_root(),
        ])
    }
}

impl SszHashTreeRoot for DepositRequest {
    /// 7-field container: node_pubkey, consensus_pubkey, withdrawal_credentials,
    /// amount, node_signature, consensus_signature, index.
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.node_pubkey.hash_tree_root(),
            self.consensus_pubkey.hash_tree_root(),
            self.withdrawal_credentials.hash_tree_root(),
            self.amount.hash_tree_root(),
            hash_fixed_bytes_64(&self.node_signature),
            hash_fixed_bytes_96(&self.consensus_signature),
            self.index.hash_tree_root(),
        ])
    }
}

impl SszHashTreeRoot for PendingWithdrawal {
    /// 7-field container: index, validator_index, address, amount,
    /// pubkey, balance_deduction, epoch.
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.inner.index.hash_tree_root(),
            self.inner.validator_index.hash_tree_root(),
            self.inner.address.hash_tree_root(),
            self.inner.amount.hash_tree_root(),
            self.pubkey.hash_tree_root(),
            self.balance_deduction.hash_tree_root(),
            self.epoch.hash_tree_root(),
        ])
    }
}

impl SszHashTreeRoot for AddedValidator {
    /// 2-field container: node_key, consensus_key.
    fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            self.node_key.hash_tree_root(),
            self.consensus_key.hash_tree_root(),
        ])
    }
}

// --- Helpers ---

/// Hash a 64-byte array as SSZ Vector[uint8, 64] → 2 chunks.
fn hash_fixed_bytes_64(bytes: &[u8; 64]) -> [u8; 32] {
    let mut chunk0 = [0u8; 32];
    let mut chunk1 = [0u8; 32];
    chunk0.copy_from_slice(&bytes[0..32]);
    chunk1.copy_from_slice(&bytes[32..64]);
    hash32_concat(&chunk0, &chunk1)
}

/// Hash a 96-byte array as SSZ Vector[uint8, 96] → 3 chunks padded to 4.
fn hash_fixed_bytes_96(bytes: &[u8; 96]) -> [u8; 32] {
    let mut chunks = [[0u8; 32]; 3];
    chunks[0].copy_from_slice(&bytes[0..32]);
    chunks[1].copy_from_slice(&bytes[32..64]);
    chunks[2].copy_from_slice(&bytes[64..96]);
    merkleize(&chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip4895::Withdrawal;
    use commonware_codec::DecodeExt;
    use commonware_cryptography::Signer;

    #[test]
    fn u64_zero() {
        assert_eq!(0u64.hash_tree_root(), [0u8; 32]);
    }

    #[test]
    fn u64_one() {
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(1u64.hash_tree_root(), expected);
    }

    #[test]
    fn u64_max() {
        let mut expected = [0u8; 32];
        expected[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(u64::MAX.hash_tree_root(), expected);
    }

    #[test]
    fn bool_values() {
        assert_eq!(false.hash_tree_root(), [0u8; 32]);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(true.hash_tree_root(), expected);
    }

    #[test]
    fn bytes32_identity() {
        let val = [0xAA; 32];
        assert_eq!(val.hash_tree_root(), val);
    }

    #[test]
    fn address_zero_padded() {
        let addr = Address::from([0xFF; 20]);
        let root = addr.hash_tree_root();
        assert_eq!(&root[0..20], &[0xFF; 20]);
        assert_eq!(&root[20..32], &[0u8; 12]);
    }

    #[test]
    fn bls_pubkey_deterministic() {
        let key = bls12381::PrivateKey::from_seed(1).public_key();
        let root1 = key.hash_tree_root();
        let root2 = key.hash_tree_root();
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn bls_pubkey_different_keys_different_roots() {
        let key1 = bls12381::PrivateKey::from_seed(1).public_key();
        let key2 = bls12381::PrivateKey::from_seed(2).public_key();
        assert_ne!(key1.hash_tree_root(), key2.hash_tree_root());
    }

    #[test]
    fn ed25519_pubkey_is_identity() {
        // Known valid ed25519 public key (test vector)
        let bytes: [u8; 32] = alloy_primitives::hex!(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let pk = PublicKey::decode(&bytes[..]).unwrap();
        assert_eq!(pk.hash_tree_root(), bytes);
    }

    #[test]
    fn validator_status_distinct_roots() {
        let statuses = [
            ValidatorStatus::Active,
            ValidatorStatus::Inactive,
            ValidatorStatus::SubmittedExitRequest,
            ValidatorStatus::Joining,
        ];
        let roots: Vec<[u8; 32]> = statuses.iter().map(|s| s.hash_tree_root()).collect();
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j], "status {i} and {j} should differ");
            }
        }
    }

    #[test]
    fn protocol_param_different_variants() {
        let min = ProtocolParam::MinimumStake(100);
        let max = ProtocolParam::MaximumStake(100);
        assert_ne!(min.hash_tree_root(), max.hash_tree_root());
    }

    #[test]
    fn protocol_param_different_values() {
        let a = ProtocolParam::MinimumStake(100);
        let b = ProtocolParam::MinimumStake(200);
        assert_ne!(a.hash_tree_root(), b.hash_tree_root());
    }

    #[test]
    fn validator_account_deterministic() {
        let key = bls12381::PrivateKey::from_seed(1).public_key();
        let account = ValidatorAccount {
            consensus_public_key: key,
            withdrawal_credentials: Address::from([1u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 42,
        };

        let root1 = account.hash_tree_root();
        let root2 = account.hash_tree_root();
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn validator_account_each_field_affects_root() {
        let key = bls12381::PrivateKey::from_seed(1).public_key();
        let base = ValidatorAccount {
            consensus_public_key: key,
            withdrawal_credentials: Address::from([1u8; 20]),
            balance: 32_000_000_000,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: 0,
        };
        let base_root = base.hash_tree_root();

        let mut m = base.clone();
        m.balance = 64_000_000_000;
        assert_ne!(base_root, m.hash_tree_root(), "balance");

        let mut m = base.clone();
        m.status = ValidatorStatus::Inactive;
        assert_ne!(base_root, m.hash_tree_root(), "status");

        let mut m = base.clone();
        m.has_pending_deposit = true;
        assert_ne!(base_root, m.hash_tree_root(), "has_pending_deposit");

        let mut m = base.clone();
        m.has_pending_withdrawal = true;
        assert_ne!(base_root, m.hash_tree_root(), "has_pending_withdrawal");

        let mut m = base.clone();
        m.joining_epoch = 42;
        assert_ne!(base_root, m.hash_tree_root(), "joining_epoch");

        let mut m = base.clone();
        m.last_deposit_index = 99;
        assert_ne!(base_root, m.hash_tree_root(), "last_deposit_index");

        let mut m = base.clone();
        m.withdrawal_credentials = Address::from([2u8; 20]);
        assert_ne!(base_root, m.hash_tree_root(), "withdrawal_credentials");

        let mut m = base;
        m.consensus_public_key = bls12381::PrivateKey::from_seed(2).public_key();
        assert_ne!(base_root, m.hash_tree_root(), "consensus_public_key");
    }

    #[test]
    fn pending_withdrawal_deterministic() {
        let withdrawal = PendingWithdrawal {
            inner: Withdrawal {
                index: 1,
                validator_index: 2,
                address: Address::from([3u8; 20]),
                amount: 1000,
            },
            pubkey: [4u8; 32],
            balance_deduction: 1000,
            epoch: 5,
        };
        assert_eq!(withdrawal.hash_tree_root(), withdrawal.hash_tree_root());
        assert_ne!(withdrawal.hash_tree_root(), [0u8; 32]);
    }

    #[test]
    fn added_validator_deterministic() {
        let node_key = PublicKey::decode(&[1u8; 32][..]).unwrap();
        let consensus_key = bls12381::PrivateKey::from_seed(1).public_key();
        let av = AddedValidator {
            node_key,
            consensus_key,
        };
        assert_eq!(av.hash_tree_root(), av.hash_tree_root());
        assert_ne!(av.hash_tree_root(), [0u8; 32]);
    }

    #[test]
    fn deposit_request_deterministic() {
        let deposit = DepositRequest {
            node_pubkey: PublicKey::decode(&[1u8; 32][..]).unwrap(),
            consensus_pubkey: bls12381::PrivateKey::from_seed(1).public_key(),
            withdrawal_credentials: [2u8; 32],
            amount: 32_000_000_000,
            node_signature: [3u8; 64],
            consensus_signature: [4u8; 96],
            index: 0,
        };
        assert_eq!(deposit.hash_tree_root(), deposit.hash_tree_root());
        assert_ne!(deposit.hash_tree_root(), [0u8; 32]);
    }

    #[test]
    fn hash_fixed_bytes_64_deterministic() {
        let bytes = [0xAB; 64];
        let h1 = hash_fixed_bytes_64(&bytes);
        let h2 = hash_fixed_bytes_64(&bytes);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);

        // Different input produces different output
        let bytes2 = [0xCD; 64];
        assert_ne!(h1, hash_fixed_bytes_64(&bytes2));
    }

    #[test]
    fn hash_fixed_bytes_96_deterministic() {
        let bytes = [0xEF; 96];
        let h1 = hash_fixed_bytes_96(&bytes);
        let h2 = hash_fixed_bytes_96(&bytes);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }
}
