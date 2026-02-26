use alloy_primitives::{hex, keccak256};
use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB};
use rlp::{Prototype, Rlp};
use std::{collections::HashMap, fmt};
use trie_db::{NodeCodec, Recorder, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieMut};

type KeccakHasher = keccak_hasher::KeccakHasher;
type Layout = crate::rlp_node_codec::EthLayout;
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

    /// Generate per-key Ethereum-format Merkle proofs for a set of logical keys.
    ///
    /// Returns one proof per key, each containing the ordered list of RLP-encoded
    /// trie nodes from root to the target (compatible with `eth_getProof` and
    /// `alloy_trie::proof::verify_proof`).
    pub fn generate_proof(&self, logical_keys: &[&[u8]]) -> Vec<Vec<Vec<u8>>> {
        let mut per_key_proofs = Vec::with_capacity(logical_keys.len());
        for logical_key in logical_keys {
            let key = keccak256(logical_key);
            let mut recorder = Recorder::<Layout>::new();
            {
                let trie = TrieDBBuilder::<Layout>::new(&self.memdb, &self.root)
                    .with_recorder(&mut recorder)
                    .build();
                // Perform the lookup to record all visited nodes
                let _ = trie.get(key.as_slice()).expect("trie get failed");
            }
            let mut key_nodes = Vec::new();
            for record in recorder.drain() {
                if !key_nodes.contains(&record.data) {
                    key_nodes.push(record.data);
                }
            }
            per_key_proofs.push(key_nodes);
        }
        per_key_proofs
    }

    /// Verify per-key Ethereum-format Merkle proofs for a set of key-value pairs.
    ///
    /// Each item is `(logical_key, Some(value))` for inclusion proofs
    /// or `(logical_key, None)` for exclusion proofs.
    /// Each item has a corresponding per-key proof (ordered root-to-leaf trie nodes).
    pub fn verify_proof(
        root: &[u8; 32],
        per_key_proofs: &[Vec<Vec<u8>>],
        items: &[(&[u8], Option<&[u8]>)],
    ) -> bool {
        assert_eq!(per_key_proofs.len(), items.len());
        for (i, &(key, expected_value)) in items.iter().enumerate() {
            let hashed_key: [u8; 32] = keccak256(key).into();
            if !verify_mpt_proof(root, &per_key_proofs[i], &hashed_key, expected_value) {
                return false;
            }
        }
        true
    }
}

/// Verify an Ethereum-format MPT proof for a single pre-hashed key.
///
/// This is the shared verification function used by both Summit consensus state proofs
/// and Ethereum `eth_getProof` proofs. The `0x6A` precompile calls this directly.
///
/// - `root`: the expected trie root hash
/// - `proof`: list of RLP-encoded trie nodes (any order, may be a superset)
/// - `hashed_key`: the trie key (already `keccak256`-hashed)
/// - `expected_value`: `Some(bytes)` for inclusion, `None` for exclusion
pub fn verify_mpt_proof(
    root: &[u8; 32],
    proof: &[impl AsRef<[u8]>],
    hashed_key: &[u8; 32],
    expected_value: Option<&[u8]>,
) -> bool {
    let node_map: HashMap<[u8; 32], &[u8]> = proof
        .iter()
        .map(|n| (<[u8; 32]>::from(keccak256(n.as_ref())), n.as_ref()))
        .collect();
    let key_nibbles: Vec<u8> = hashed_key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect();
    let got = walk_trie(root, &key_nibbles, &node_map);
    got.as_deref() == expected_value
}

/// Walk the trie from root following `key_nibbles`, returning the value if found.
/// Looks up nodes by hash in `node_map`. Handles inline children recursively.
fn walk_trie(
    root: &[u8; 32],
    key_nibbles: &[u8],
    node_map: &HashMap<[u8; 32], &[u8]>,
) -> Option<Vec<u8>> {
    let root_data = node_map.get(root)?;
    walk_node(root_data, key_nibbles, 0, node_map)
}

/// Recursively walk a single trie node, returning the value at `key_nibbles[nibble_idx..]`.
fn walk_node(
    node_data: &[u8],
    key_nibbles: &[u8],
    nibble_idx: usize,
    node_map: &HashMap<[u8; 32], &[u8]>,
) -> Option<Vec<u8>> {
    let rlp = Rlp::new(node_data);
    match rlp.prototype().ok()? {
        Prototype::List(2) => {
            // Leaf or Extension
            let path_data = rlp.at(0).ok()?.data().ok()?;
            let prefix = path_data[0];
            let is_leaf = prefix & 0x20 != 0;
            let odd = prefix & 0x10 != 0;

            // Extract path nibbles from hex-prefix encoding
            let mut path_nibbles = Vec::new();
            if odd {
                path_nibbles.push(prefix & 0x0f);
            }
            for &byte in &path_data[1..] {
                path_nibbles.push(byte >> 4);
                path_nibbles.push(byte & 0x0f);
            }

            // Check path match
            if nibble_idx + path_nibbles.len() > key_nibbles.len() {
                return None; // key not found
            }
            if key_nibbles[nibble_idx..nibble_idx + path_nibbles.len()] != path_nibbles[..] {
                return None; // path diverges
            }
            let new_idx = nibble_idx + path_nibbles.len();

            if is_leaf {
                if new_idx != key_nibbles.len() {
                    return None; // key is longer than leaf path
                }
                Some(rlp.at(1).ok()?.data().ok()?.to_vec())
            } else {
                // Extension: follow child reference
                follow_child(&rlp.at(1).ok()?, key_nibbles, new_idx, node_map)
            }
        }
        Prototype::List(17) => {
            // Branch node
            if nibble_idx == key_nibbles.len() {
                // Value stored at this branch
                let value_rlp = rlp.at(16).ok()?;
                if value_rlp.is_empty() {
                    return None;
                }
                return Some(value_rlp.data().ok()?.to_vec());
            }

            let nibble = key_nibbles[nibble_idx] as usize;
            let child_rlp = rlp.at(nibble).ok()?;
            if child_rlp.is_empty() {
                return None; // no child at this nibble
            }
            follow_child(&child_rlp, key_nibbles, nibble_idx + 1, node_map)
        }
        Prototype::Data(0) => None, // empty node
        _ => None,
    }
}

/// Follow a child reference — either a 32-byte hash (look up in map) or inline RLP node.
fn follow_child(
    child_rlp: &Rlp,
    key_nibbles: &[u8],
    nibble_idx: usize,
    node_map: &HashMap<[u8; 32], &[u8]>,
) -> Option<Vec<u8>> {
    match child_rlp.prototype().ok()? {
        Prototype::Data(32) => {
            // Hash reference: look up in node map
            let hash: [u8; 32] = child_rlp.data().ok()?.try_into().ok()?;
            let child_data = node_map.get(&hash)?;
            walk_node(child_data, key_nibbles, nibble_idx, node_map)
        }
        _ => {
            // Inline node: decode directly from raw RLP
            walk_node(child_rlp.as_raw(), key_nibbles, nibble_idx, node_map)
        }
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
        // Ethereum's empty node is [0x80] (RLP empty string), not [0x00].
        // MemoryDB must be initialized with the correct null node so that
        // lookups for the empty trie root hash (keccak256([0x80])) succeed.
        let null_node = <crate::rlp_node_codec::RlpNodeCodec as NodeCodec>::empty_node();
        let mut memdb = TrieMemDB::from_null_node(null_node, null_node.to_vec());
        let mut root = Default::default();
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
    fn get_raw_works() {
        let mut trie = StateTrie::default();
        trie.insert_raw(b"key1", b"value1");
        trie.insert_raw(b"key2", b"value2");
        assert_eq!(trie.get_raw(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(trie.get_raw(b"key2"), Some(b"value2".to_vec()));
        assert_eq!(trie.get_raw(b"absent"), None);
    }

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
