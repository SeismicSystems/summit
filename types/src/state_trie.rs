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

    #[test]
    fn clone_is_independent() {
        let mut accounts = BTreeMap::new();
        for i in 0..3u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let mut trie = StateTrie::build(&accounts);
        let cloned = trie.clone();

        // Mutate original — clone should be unaffected
        trie.insert(&[99u8; 32], &test_account(99, 1_000_000_000));
        assert_ne!(trie.root(), cloned.root());

        // Clone still matches a fresh build from the original accounts
        let fresh = StateTrie::build(&accounts);
        assert_eq!(cloned.root(), fresh.root());
    }

    #[test]
    fn empty_trie_root_is_consistent() {
        let t1 = StateTrie::default();
        let t2 = StateTrie::default();
        assert_eq!(t1.root(), t2.root());

        let empty_accounts = BTreeMap::new();
        let t3 = StateTrie::build(&empty_accounts);
        assert_eq!(t1.root(), t3.root());
    }

    #[test]
    fn single_account_trie() {
        let mut accounts = BTreeMap::new();
        let pubkey = [42u8; 32];
        let account = test_account(42, 32_000_000_000);
        accounts.insert(pubkey, account.clone());

        let trie = StateTrie::build(&accounts);
        assert_ne!(trie.root(), StateTrie::default().root());

        // Proof works for the single entry
        let proof = trie.generate_proof(&[pubkey]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(pubkey, Some(&account))],
        ));
    }

    #[test]
    fn remove_nonexistent_key_is_noop() {
        let mut accounts = BTreeMap::new();
        accounts.insert([1u8; 32], test_account(1, 32_000_000_000));
        let mut trie = StateTrie::build(&accounts);
        let root_before = trie.root();

        // Removing a key that doesn't exist should not change the root
        trie.remove(&[99u8; 32]);
        assert_eq!(trie.root(), root_before);
    }

    #[test]
    fn insert_order_does_not_affect_root() {
        let accounts: Vec<([u8; 32], ValidatorAccount)> = (0..5u64)
            .map(|i| ([i as u8; 32], test_account(i, 32_000_000_000)))
            .collect();

        // Forward order
        let mut t1 = StateTrie::default();
        for (pk, acc) in accounts.iter() {
            t1.insert(pk, acc);
        }

        // Reverse order
        let mut t2 = StateTrie::default();
        for (pk, acc) in accounts.iter().rev() {
            t2.insert(pk, acc);
        }

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn different_accounts_produce_different_roots() {
        let mut accounts_a = BTreeMap::new();
        accounts_a.insert([1u8; 32], test_account(1, 32_000_000_000));

        let mut accounts_b = BTreeMap::new();
        accounts_b.insert([1u8; 32], test_account(1, 64_000_000_000));

        let trie_a = StateTrie::build(&accounts_a);
        let trie_b = StateTrie::build(&accounts_b);
        assert_ne!(trie_a.root(), trie_b.root());
    }

    #[test]
    fn different_keys_same_account_produce_different_roots() {
        let account = test_account(1, 32_000_000_000);

        let mut accounts_a = BTreeMap::new();
        accounts_a.insert([1u8; 32], account.clone());

        let mut accounts_b = BTreeMap::new();
        accounts_b.insert([2u8; 32], account);

        let trie_a = StateTrie::build(&accounts_a);
        let trie_b = StateTrie::build(&accounts_b);
        assert_ne!(trie_a.root(), trie_b.root());
    }

    #[test]
    fn proof_for_multiple_keys() {
        let mut accounts = BTreeMap::new();
        for i in 0..10u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie = StateTrie::build(&accounts);

        let keys = [[2u8; 32], [5u8; 32], [8u8; 32]];
        let proof = trie.generate_proof(&keys);
        let root = trie.root();

        let items: Vec<([u8; 32], Option<&ValidatorAccount>)> = keys
            .iter()
            .map(|k| (*k, accounts.get(k).map(|a| a)))
            .collect();
        assert!(StateTrie::verify_proof(&root, &proof, &items));
    }

    #[test]
    fn exclusion_proof_for_absent_key() {
        let mut accounts = BTreeMap::new();
        for i in 0..5u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie = StateTrie::build(&accounts);

        let absent_key = [99u8; 32];
        let proof = trie.generate_proof(&[absent_key]);
        let root = trie.root();

        // Verify exclusion (None value)
        assert!(StateTrie::verify_proof(
            &root,
            &proof,
            &[(absent_key, None)],
        ));

        // Claiming it exists with some account should fail
        let fake_account = test_account(99, 32_000_000_000);
        assert!(!StateTrie::verify_proof(
            &root,
            &proof,
            &[(absent_key, Some(&fake_account))],
        ));
    }

    #[test]
    fn proof_invalid_against_wrong_root() {
        let mut accounts = BTreeMap::new();
        for i in 0..5u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let trie = StateTrie::build(&accounts);

        let target = [3u8; 32];
        let proof = trie.generate_proof(&[target]);

        let wrong_root = [0xFFu8; 32];
        assert!(!StateTrie::verify_proof(
            &wrong_root,
            &proof,
            &[(target, accounts.get(&target).map(|a| a))],
        ));
    }

    #[test]
    fn proof_valid_after_update() {
        let mut accounts = BTreeMap::new();
        for i in 0..5u64 {
            accounts.insert([i as u8; 32], test_account(i, 32_000_000_000));
        }
        let mut trie = StateTrie::build(&accounts);

        // Update an account
        let updated = test_account(2, 50_000_000_000);
        trie.insert(&[2u8; 32], &updated);

        // Old proof against new root should fail
        let old_root = StateTrie::build(&accounts).root();
        assert_ne!(trie.root(), old_root);

        // New proof against new root should succeed
        let proof = trie.generate_proof(&[[2u8; 32]]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[([2u8; 32], Some(&updated))],
        ));
    }

    #[test]
    fn rebuild_after_many_mutations_matches_full_build() {
        let mut trie = StateTrie::default();

        // Insert 20 accounts
        let mut accounts = BTreeMap::new();
        for i in 0..20u64 {
            let acc = test_account(i, 32_000_000_000 + i);
            accounts.insert([i as u8; 32], acc.clone());
            trie.insert(&[i as u8; 32], &acc);
        }

        // Remove some
        for i in [3u64, 7, 12, 18] {
            accounts.remove(&[i as u8; 32]);
            trie.remove(&[i as u8; 32]);
        }

        // Update some
        for i in [0u64, 5, 15] {
            let updated = test_account(i, 99_000_000_000);
            accounts.insert([i as u8; 32], updated.clone());
            trie.insert(&[i as u8; 32], &updated);
        }

        let fresh = StateTrie::build(&accounts);
        assert_eq!(trie.root(), fresh.root());
    }

    #[test]
    fn insert_remove_reinsert_same_key() {
        let mut trie = StateTrie::default();
        let pubkey = [7u8; 32];

        let acc1 = test_account(7, 32_000_000_000);
        trie.insert(&pubkey, &acc1);
        let root1 = trie.root();

        trie.remove(&pubkey);
        assert_eq!(trie.root(), StateTrie::default().root());

        // Reinsert same account — should get same root
        trie.insert(&pubkey, &acc1);
        assert_eq!(trie.root(), root1);

        // Reinsert with different value — should get different root
        trie.remove(&pubkey);
        let acc2 = test_account(7, 64_000_000_000);
        trie.insert(&pubkey, &acc2);
        assert_ne!(trie.root(), root1);
    }

    #[test]
    fn large_trie_proof() {
        let mut accounts = BTreeMap::new();
        for i in 0..200u64 {
            let mut pubkey = [0u8; 32];
            pubkey[0..8].copy_from_slice(&i.to_le_bytes());
            accounts.insert(pubkey, test_account(i, 32_000_000_000 + i));
        }
        let trie = StateTrie::build(&accounts);

        // Prove a subset
        let keys_to_prove: Vec<[u8; 32]> = (0..200u64)
            .step_by(17)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0..8].copy_from_slice(&i.to_le_bytes());
                k
            })
            .collect();

        let proof = trie.generate_proof(&keys_to_prove);

        let items: Vec<([u8; 32], Option<&ValidatorAccount>)> = keys_to_prove
            .iter()
            .map(|k| (*k, accounts.get(k).map(|a| a)))
            .collect();
        assert!(StateTrie::verify_proof(&trie.root(), &proof, &items));
    }

    #[test]
    fn account_status_change_updates_root() {
        let pubkey = [1u8; 32];
        let mut acc = test_account(1, 32_000_000_000);
        let mut trie = StateTrie::default();
        trie.insert(&pubkey, &acc);
        let root_active = trie.root();

        acc.status = ValidatorStatus::Inactive;
        trie.insert(&pubkey, &acc);
        assert_ne!(trie.root(), root_active);

        acc.status = ValidatorStatus::Joining;
        trie.insert(&pubkey, &acc);
        assert_ne!(trie.root(), root_active);
    }

    #[test]
    fn debug_shows_root_hash() {
        let trie = StateTrie::default();
        let debug_str = format!("{:?}", trie);
        assert!(debug_str.contains("StateTrie"));
        assert!(debug_str.contains("root"));
        // Root hash should be a hex string (64 hex chars for 32 bytes)
        assert!(debug_str.len() > 64);
    }
}
