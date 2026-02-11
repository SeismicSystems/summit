use crate::account::ValidatorAccount;
use alloy_primitives::{hex, keccak256};
use commonware_codec::Encode;
use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB};
use std::collections::BTreeMap;
use std::fmt;
use trie_db::{TrieDBMutBuilder, TrieMut};

type KeccakHasher = keccak_hasher::KeccakHasher;
type Layout = reference_trie::ExtensionLayout;
type TrieMemDB = MemoryDB<KeccakHasher, HashKey<KeccakHasher>, Vec<u8>>;
type TrieRoot = <KeccakHasher as Hasher>::Out;

/// In-memory Merkle Patricia Trie over validator accounts.
///
/// Keys are `keccak256(validator_pubkey)` for uniform distribution.
/// Values are `ValidatorAccount` encoded via `commonware_codec::Encode`.
///
pub struct StateTrie {
    memdb: TrieMemDB,
    root: TrieRoot,
}

impl StateTrie {
    /// Build a trie from a complete set of validator accounts.
    pub fn build(accounts: &BTreeMap<[u8; 32], ValidatorAccount>) -> Self {
        let mut memdb = TrieMemDB::default();
        let mut root = Default::default();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut memdb, &mut root).build();
            for (pubkey, account) in accounts {
                let key = keccak256(pubkey);
                let value = account.encode().to_vec();
                trie.insert(key.as_slice(), &value)
                    .expect("trie insert failed");
            }
        }
        Self { memdb, root }
    }

    /// Insert or update a validator account in the trie.
    pub fn insert(&mut self, pubkey: &[u8; 32], account: &ValidatorAccount) {
        let key = keccak256(pubkey);
        let value = account.encode().to_vec();
        let mut trie =
            TrieDBMutBuilder::<Layout>::from_existing(&mut self.memdb, &mut self.root).build();
        trie.insert(key.as_slice(), &value)
            .expect("trie insert failed");
    }

    /// Remove a validator account from the trie.
    pub fn remove(&mut self, pubkey: &[u8; 32]) {
        let key = keccak256(pubkey);
        let mut trie =
            TrieDBMutBuilder::<Layout>::from_existing(&mut self.memdb, &mut self.root).build();
        trie.remove(key.as_slice()).expect("trie remove failed");
    }

    /// Returns the current Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Generate a Merkle proof for the given validator public keys.
    pub fn generate_proof(&self, pubkeys: &[[u8; 32]]) -> Vec<Vec<u8>> {
        let keys: Vec<Vec<u8>> = pubkeys
            .iter()
            .map(|pk| keccak256(pk).as_slice().to_vec())
            .collect();
        let key_refs: Vec<&Vec<u8>> = keys.iter().collect();
        trie_db::proof::generate_proof::<_, Layout, _, _>(&self.memdb, &self.root, key_refs)
            .expect("proof generation failed")
    }

    /// Verify a Merkle proof for a set of validator accounts.
    ///
    /// Each item is `(pubkey, Some(account))` for inclusion proofs
    /// or `(pubkey, None)` for exclusion proofs.
    pub fn verify_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        items: &[([u8; 32], Option<&ValidatorAccount>)],
    ) -> bool {
        let encoded_items: Vec<(Vec<u8>, Option<Vec<u8>>)> = items
            .iter()
            .map(|(pubkey, account)| {
                let key = keccak256(pubkey).as_slice().to_vec();
                let value = account.map(|a| a.encode().to_vec());
                (key, value)
            })
            .collect();
        let item_refs: Vec<&(Vec<u8>, Option<Vec<u8>>)> = encoded_items.iter().collect();
        trie_db::proof::verify_proof::<Layout, _, _, _>(root, proof, item_refs).is_ok()
    }
}

impl Clone for StateTrie {
    fn clone(&self) -> Self {
        Self {
            memdb: self.memdb.clone(),
            root: self.root,
        }
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        let mut memdb = TrieMemDB::default();
        let mut root = Default::default();
        // Build an empty trie so the root node is registered in memdb
        TrieDBMutBuilder::<Layout>::new(&mut memdb, &mut root).build();
        Self { memdb, root }
    }
}

impl fmt::Debug for StateTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateTrie")
            .field("root", &hex::encode(self.root))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::ValidatorStatus;
    use alloy_primitives::Address;
    use commonware_cryptography::{Signer, bls12381};

    fn test_account(index: u64, balance: u64) -> ValidatorAccount {
        let consensus_key = bls12381::PrivateKey::from_seed(index);
        ValidatorAccount {
            consensus_public_key: consensus_key.public_key(),
            withdrawal_credentials: Address::from([index as u8; 20]),
            balance,
            pending_withdrawal_amount: 0,
            status: ValidatorStatus::Active,
            has_pending_deposit: false,
            has_pending_withdrawal: false,
            joining_epoch: 0,
            last_deposit_index: index,
        }
    }

    #[test]
    fn build_and_root_deterministic() {
        let mut accounts = BTreeMap::new();
        for i in 0..10u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie1 = StateTrie::build(&accounts);
        let trie2 = StateTrie::build(&accounts);
        assert_eq!(trie1.root(), trie2.root());
        assert_ne!(trie1.root(), [0u8; 32]);
    }

    #[test]
    fn incremental_matches_full_build() {
        let mut accounts = BTreeMap::new();
        for i in 0..5u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }

        let full = StateTrie::build(&accounts);

        let mut incremental = StateTrie::default();
        for (pubkey, account) in &accounts {
            incremental.insert(pubkey, account);
        }

        assert_eq!(full.root(), incremental.root());
    }

    #[test]
    fn insert_update_remove() {
        let mut trie = StateTrie::default();
        let pubkey = [1u8; 32];
        let account = test_account(1, 32_000_000_000);

        trie.insert(&pubkey, &account);
        let root_after_insert = trie.root();
        assert_ne!(root_after_insert, [0u8; 32]);

        let updated = test_account(1, 64_000_000_000);
        trie.insert(&pubkey, &updated);
        assert_ne!(trie.root(), root_after_insert);

        trie.remove(&pubkey);
        assert_eq!(trie.root(), StateTrie::default().root());
    }

    #[test]
    fn proof_generation_and_verification() {
        let mut accounts = BTreeMap::new();
        for i in 0..10u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie = StateTrie::build(&accounts);

        let target_pubkey = [5u8; 32];
        let target_account = accounts.get(&target_pubkey).unwrap();

        let proof = trie.generate_proof(&[target_pubkey]);
        let root = trie.root();

        assert!(StateTrie::verify_proof(
            &root,
            &proof,
            &[(target_pubkey, Some(target_account))],
        ));

        let wrong_account = test_account(5, 99_000_000_000);
        assert!(!StateTrie::verify_proof(
            &root,
            &proof,
            &[(target_pubkey, Some(&wrong_account))],
        ));
    }

    #[test]
    fn clone_preserves_state() {
        let mut accounts = BTreeMap::new();
        for i in 0..5u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie = StateTrie::build(&accounts);
        let cloned = trie.clone();
        assert_eq!(trie.root(), cloned.root());
    }
}
