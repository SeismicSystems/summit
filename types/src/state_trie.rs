use alloy_primitives::{B256, Bytes, hex, keccak256};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, proof::verify_proof as alloy_verify_proof};
use nybbles::Nibbles;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

/// In-memory Merkle Patricia Trie for ConsensusState fields.
///
/// All logical keys are hashed with `keccak256` before insertion.
/// Use [`crate::state_trie_key`] constants and functions to generate logical keys.
///
/// Proof format is compatible with Ethereum's `eth_getProof` endpoint.
pub struct StateTrie {
    /// keccak256(logical_key) → value
    entries: BTreeMap<B256, Vec<u8>>,
    /// Cached root hash, invalidated on mutation.
    root_cache: Mutex<Option<B256>>,
}

impl StateTrie {
    /// Insert a raw key-value pair. The logical key is hashed with keccak256.
    pub fn insert_raw(&mut self, logical_key: &[u8], value: &[u8]) {
        let key = keccak256(logical_key);
        self.entries.insert(key, value.to_vec());
        *self.root_cache.lock().unwrap() = None;
    }

    /// Remove a key from the trie. The logical key is hashed with keccak256.
    pub fn remove_raw(&mut self, logical_key: &[u8]) {
        let key = keccak256(logical_key);
        if self.entries.remove(&key).is_some() {
            *self.root_cache.lock().unwrap() = None;
        }
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
        self.entries.get(&key).cloned()
    }

    /// Returns the current Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        let mut cache = self.root_cache.lock().unwrap();
        if let Some(cached) = *cache {
            return cached.0;
        }
        let root = self.build_root();
        *cache = Some(root);
        root.0
    }

    /// Generate Merkle proofs for the given logical keys.
    ///
    /// Returns a per-key proof: for each logical key, the RLP-encoded trie nodes
    /// from root to leaf, compatible with Ethereum's `eth_getProof` format.
    pub fn generate_proof(&self, logical_keys: &[&[u8]]) -> Vec<Vec<Vec<u8>>> {
        let targets: Vec<Nibbles> = logical_keys
            .iter()
            .map(|k| Nibbles::unpack(keccak256(k)))
            .collect();

        let retainer = ProofRetainer::new(targets.clone());
        let mut builder = HashBuilder::default().with_proof_retainer(retainer);

        for (key, value) in &self.entries {
            builder.add_leaf(Nibbles::unpack(key), value);
        }

        let root = builder.root();
        *self.root_cache.lock().unwrap() = Some(root);

        let proof_nodes = builder.take_proof_nodes();
        targets
            .iter()
            .map(|target| {
                proof_nodes
                    .matching_nodes_sorted(target)
                    .into_iter()
                    .map(|(_, node)| node.to_vec())
                    .collect()
            })
            .collect()
    }

    /// Verify a Merkle proof for a single key-value pair.
    ///
    /// The proof should contain the trie nodes from root to leaf for the given key,
    /// as returned by [`Self::generate_proof`] (one element of the per-key proof vector).
    ///
    /// Provide `Some(value)` for inclusion proofs or `None` for exclusion proofs.
    /// Compatible with Ethereum's `eth_getProof` verification.
    pub fn verify_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        logical_key: &[u8],
        expected_value: Option<&[u8]>,
    ) -> bool {
        let root = B256::from(*root);
        let key = Nibbles::unpack(keccak256(logical_key));
        let expected = expected_value.map(|v| v.to_vec());
        let proof_bytes: Vec<Bytes> = proof.iter().map(|n| Bytes::from(n.clone())).collect();
        alloy_verify_proof(root, key, expected, &proof_bytes).is_ok()
    }

    /// Build the root hash from all entries using HashBuilder.
    fn build_root(&self) -> B256 {
        let mut builder = HashBuilder::default();
        for (key, value) in &self.entries {
            builder.add_leaf(Nibbles::unpack(key), value);
        }
        builder.root()
    }
}

impl Clone for StateTrie {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            root_cache: Mutex::new(*self.root_cache.lock().unwrap()),
        }
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            root_cache: Mutex::new(None),
        }
    }
}

impl fmt::Debug for StateTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let root_hex = match *self.root_cache.lock().unwrap() {
            Some(r) => hex::encode(r),
            None => "<not computed>".to_string(),
        };
        f.debug_struct("StateTrie")
            .field("root", &root_hex)
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

        let proofs = trie.generate_proof(&[b"epoch"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"epoch",
            Some(&42u64.to_be_bytes()),
        ));
    }

    #[test]
    fn insert_hash_works() {
        let mut trie = StateTrie::default();
        let hash = [0xABu8; 32];
        trie.insert_hash(b"digest", &hash);

        let proofs = trie.generate_proof(&[b"digest"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"digest",
            Some(&hash),
        ));
    }

    #[test]
    fn insert_bool_works() {
        let mut trie = StateTrie::default();
        trie.insert_bool(b"flag", true);

        let proofs = trie.generate_proof(&[b"flag"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"flag",
            Some(&[1u8]),
        ));
    }

    #[test]
    fn proof_inclusion() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key1", b"value1");
        trie.insert_raw(b"key2", b"value2");

        let proofs = trie.generate_proof(&[b"key1"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"key1",
            Some(b"value1"),
        ));

        // Wrong value should fail
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"key1",
            Some(b"wrong"),
        ));
    }

    #[test]
    fn proof_exclusion() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key1", b"value1");

        let proofs = trie.generate_proof(&[b"absent"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"absent",
            None,
        ));

        // Claiming it exists should fail
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"absent",
            Some(b"anything"),
        ));
    }

    #[test]
    fn proof_multiple_keys() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"a", b"1");
        trie.insert_raw(b"b", b"2");
        trie.insert_raw(b"c", b"3");

        let proofs = trie.generate_proof(&[b"a", b"c"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"a",
            Some(b"1"),
        ));
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[1],
            b"c",
            Some(b"3"),
        ));
    }

    #[test]
    fn proof_invalid_against_wrong_root() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key", b"value");

        let proofs = trie.generate_proof(&[b"key"]);
        let wrong_root = [0xFFu8; 32];
        assert!(!StateTrie::verify_proof(
            &wrong_root,
            &proofs[0],
            b"key",
            Some(b"value"),
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
        let proofs = trie.generate_proof(&key_refs);

        let owned_vals: Vec<[u8; 8]> = (0..100u64).step_by(13).map(|i| i.to_be_bytes()).collect();
        for ((k, v), proof) in keys_to_prove
            .iter()
            .zip(owned_vals.iter())
            .zip(proofs.iter())
        {
            assert!(StateTrie::verify_proof(
                &trie.root(),
                proof,
                k.as_bytes(),
                Some(v.as_slice()),
            ));
        }
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
        let proofs = trie.generate_proof(&[b"epoch", &key]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"epoch",
            Some(&42u64.to_be_bytes()),
        ));
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[1],
            &key,
            Some(&32_000_000_000u64.to_be_bytes()),
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
        let proofs = trie.generate_proof(&[b"key"]);
        assert!(StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"key",
            Some(b"new_value"),
        ));

        // Old value should fail with new root
        assert!(!StateTrie::verify_proof(
            &trie.root(),
            &proofs[0],
            b"key",
            Some(b"old_value"),
        ));
    }
}
