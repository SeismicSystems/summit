use alloy_primitives::{hex, keccak256};
use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB};
use std::fmt;
use trie_db::{Trie, TrieDBBuilder, TrieDBMutBuilder, TrieMut};

type KeccakHasher = keccak_hasher::KeccakHasher;
type Layout = reference_trie::ExtensionLayout;
type TrieMemDB = MemoryDB<KeccakHasher, HashKey<KeccakHasher>, Vec<u8>>;
type TrieRoot = <KeccakHasher as Hasher>::Out;

/// In-memory Merkle Patricia Trie for ConsensusState fields.
///
/// All logical keys are hashed with `keccak256` before insertion.
/// Use [`crate::state_trie_key`] constants and functions to generate logical keys.
pub struct StateTrie {
    memdb: TrieMemDB,
    root: TrieRoot,
}

impl StateTrie {
    /// Insert a raw key-value pair. The logical key is hashed with keccak256.
    pub fn insert_raw(&mut self, logical_key: &[u8], value: &[u8]) {
        let key = keccak256(logical_key);
        let mut trie =
            TrieDBMutBuilder::<Layout>::from_existing(&mut self.memdb, &mut self.root).build();
        trie.insert(key.as_slice(), value)
            .expect("trie insert failed");
    }

    /// Remove a key from the trie. The logical key is hashed with keccak256.
    pub fn remove_raw(&mut self, logical_key: &[u8]) {
        let key = keccak256(logical_key);
        let mut trie =
            TrieDBMutBuilder::<Layout>::from_existing(&mut self.memdb, &mut self.root).build();
        trie.remove(key.as_slice()).expect("trie remove failed");
    }

    /// Insert a u64 value as big-endian bytes.
    pub fn insert_u64(&mut self, field_key: &[u8], value: u64) {
        self.insert_raw(field_key, &value.to_be_bytes());
    }

    /// Insert a 32-byte hash value.
    pub fn insert_hash(&mut self, field_key: &[u8], value: &[u8; 32]) {
        self.insert_raw(field_key, value);
    }

    /// Insert a bool as a single byte (0 or 1).
    pub fn insert_bool(&mut self, field_key: &[u8], value: bool) {
        self.insert_raw(field_key, &[value as u8]);
    }

    /// Look up the value for a logical key. The key is hashed with keccak256.
    pub fn get_raw(&self, logical_key: &[u8]) -> Option<Vec<u8>> {
        let key = keccak256(logical_key);
        let trie = TrieDBBuilder::<Layout>::new(&self.memdb, &self.root).build();
        trie.get(key.as_slice()).expect("trie get failed")
    }

    /// Returns the current Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Generate a Merkle proof for the given logical keys.
    pub fn generate_proof(&self, logical_keys: &[&[u8]]) -> Vec<Vec<u8>> {
        let keys: Vec<Vec<u8>> = logical_keys
            .iter()
            .map(|k| keccak256(k).as_slice().to_vec())
            .collect();
        let key_refs: Vec<&Vec<u8>> = keys.iter().collect();
        trie_db::proof::generate_proof::<_, Layout, _, _>(&self.memdb, &self.root, key_refs)
            .expect("proof generation failed")
    }

    /// Verify a Merkle proof for a set of key-value pairs.
    ///
    /// Each item is `(logical_key, Some(value))` for inclusion proofs
    /// or `(logical_key, None)` for exclusion proofs.
    pub fn verify_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        items: &[(&[u8], Option<&[u8]>)],
    ) -> bool {
        let encoded_items: Vec<(Vec<u8>, Option<Vec<u8>>)> = items
            .iter()
            .map(|(key, value)| {
                let hashed_key = keccak256(key).as_slice().to_vec();
                let value = value.map(|v| v.to_vec());
                (hashed_key, value)
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

    #[test]
    fn empty_trie_root_is_consistent() {
        let t1 = StateTrie::default();
        let t2 = StateTrie::default();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn insert_raw_changes_root() {
        let mut trie = StateTrie::default();
        let empty_root = trie.root();
        trie.insert_raw(b"key", b"value");
        assert_ne!(trie.root(), empty_root);
    }

    #[test]
    fn remove_raw_restores_root() {
        let mut trie = StateTrie::default();
        let empty_root = trie.root();
        trie.insert_raw(b"key", b"value");
        trie.remove_raw(b"key");
        assert_eq!(trie.root(), empty_root);
    }

    #[test]
    fn insert_order_independent() {
        let mut t1 = StateTrie::default();
        t1.insert_raw(b"a", b"1");
        t1.insert_raw(b"b", b"2");
        t1.insert_raw(b"c", b"3");

        let mut t2 = StateTrie::default();
        t2.insert_raw(b"c", b"3");
        t2.insert_raw(b"a", b"1");
        t2.insert_raw(b"b", b"2");

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn different_values_different_roots() {
        let mut t1 = StateTrie::default();
        t1.insert_raw(b"key", b"value1");

        let mut t2 = StateTrie::default();
        t2.insert_raw(b"key", b"value2");

        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn different_keys_same_value_different_roots() {
        let mut t1 = StateTrie::default();
        t1.insert_raw(b"key1", b"value");

        let mut t2 = StateTrie::default();
        t2.insert_raw(b"key2", b"value");

        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn insert_u64_works() {
        let mut trie = StateTrie::default();
        trie.insert_u64(b"epoch", 42);

        let proof = trie.generate_proof(&[b"epoch"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"epoch", Some(&42u64.to_be_bytes()))],
        ));
    }

    #[test]
    fn insert_hash_works() {
        let mut trie = StateTrie::default();
        let hash = [0xABu8; 32];
        trie.insert_hash(b"digest", &hash);

        let proof = trie.generate_proof(&[b"digest"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"digest", Some(&hash))],
        ));
    }

    #[test]
    fn insert_bool_works() {
        let mut trie = StateTrie::default();
        trie.insert_bool(b"flag", true);

        let proof = trie.generate_proof(&[b"flag"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"flag", Some(&[1u8]))],
        ));
    }

    #[test]
    fn proof_inclusion() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key1", b"value1");
        trie.insert_raw(b"key2", b"value2");

        let proof = trie.generate_proof(&[b"key1"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"key1", Some(b"value1"))],
        ));

        // Wrong value should fail
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"key1", Some(b"wrong"))],
        ));
    }

    #[test]
    fn proof_exclusion() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key1", b"value1");

        let proof = trie.generate_proof(&[b"absent"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"absent", None)],
        ));

        // Claiming it exists should fail
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"absent", Some(b"anything"))],
        ));
    }

    #[test]
    fn proof_multiple_keys() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"a", b"1");
        trie.insert_raw(b"b", b"2");
        trie.insert_raw(b"c", b"3");

        let proof = trie.generate_proof(&[b"a", b"c"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"a", Some(b"1")), (b"c", Some(b"3"))],
        ));
    }

    #[test]
    fn proof_invalid_against_wrong_root() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");

        let proof = trie.generate_proof(&[b"key"]);
        let wrong_root = [0xFFu8; 32];
        assert!(!StateTrie::verify_proof(
            &wrong_root,
            &proof,
            &[(b"key", Some(b"value"))],
        ));
    }

    #[test]
    fn clone_preserves_state() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");
        let cloned = trie.clone();
        assert_eq!(trie.root(), cloned.root());
    }

    #[test]
    fn clone_is_independent() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");
        let cloned = trie.clone();

        trie.insert_raw(b"key2", b"value2");
        assert_ne!(trie.root(), cloned.root());
    }

    #[test]
    fn remove_nonexistent_key_is_noop() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");
        let root_before = trie.root();
        trie.remove_raw(b"nonexistent");
        assert_eq!(trie.root(), root_before);
    }

    #[test]
    fn update_value_changes_root() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"v1");
        let root1 = trie.root();
        trie.insert_raw(b"key", b"v2");
        assert_ne!(trie.root(), root1);
    }

    #[test]
    fn insert_remove_reinsert() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");
        let root1 = trie.root();

        trie.remove_raw(b"key");
        assert_eq!(trie.root(), StateTrie::default().root());

        // Reinsert same kv — should get same root
        trie.insert_raw(b"key", b"value");
        assert_eq!(trie.root(), root1);
    }

    #[test]
    fn debug_shows_root_hash() {
        let trie = StateTrie::default();
        let debug_str = format!("{:?}", trie);
        assert!(debug_str.contains("StateTrie"));
        assert!(debug_str.contains("root"));
    }

    #[test]
    fn many_entries_proof() {
        let mut trie = StateTrie::default();
        for i in 0..100u64 {
            let key = format!("key_{}", i);
            let val = i.to_be_bytes();
            trie.insert_raw(key.as_bytes(), &val);
        }

        // Prove a subset
        let keys_to_prove: Vec<String> = (0..100u64)
            .step_by(13)
            .map(|i| format!("key_{}", i))
            .collect();
        let key_refs: Vec<&[u8]> = keys_to_prove.iter().map(|k| k.as_bytes()).collect();
        let proof = trie.generate_proof(&key_refs);

        let owned_vals: Vec<[u8; 8]> = (0..100u64).step_by(13).map(|i| i.to_be_bytes()).collect();
        let items: Vec<(&[u8], Option<&[u8]>)> = keys_to_prove
            .iter()
            .zip(owned_vals.iter())
            .map(|(k, v)| (k.as_bytes() as &[u8], Some(v.as_slice())))
            .collect();

        assert!(StateTrie::verify_proof(&trie.root(), &proof, &items));
    }

    #[test]
    fn mixed_proof_scalars_and_prefixed() {
        let mut trie = StateTrie::default();

        // Simulate scalar field
        trie.insert_u64(b"epoch", 42);

        // Simulate prefixed field (like a validator account field)
        let mut key = Vec::from(b"validator_balance_" as &[u8]);
        key.extend_from_slice(&[1u8; 32]);
        trie.insert_u64(&key, 32_000_000_000);

        // Prove both
        let proof = trie.generate_proof(&[b"epoch", &key]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[
                (b"epoch", Some(&42u64.to_be_bytes())),
                (&key, Some(&32_000_000_000u64.to_be_bytes())),
            ],
        ));
    }

    #[test]
    fn proof_valid_after_update() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"old_value");
        let old_root = trie.root();

        trie.insert_raw(b"key", b"new_value");
        assert_ne!(trie.root(), old_root);

        // New proof against new root should succeed
        let proof = trie.generate_proof(&[b"key"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"key", Some(b"new_value"))],
        ));

        // Old value should fail with new root
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proof,
            &[(b"key", Some(b"old_value"))],
        ));
    }
}
