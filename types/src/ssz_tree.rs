//! Array-based binary Merkle tree with incremental updates using SHA256.
//!
//! The tree is stored as a flat `Vec<[u8; 32]>` where:
//! - Index 0 is unused (sentinel)
//! - Index 1 is the root
//! - Index `2*i` is the left child of `i`
//! - Index `2*i + 1` is the right child of `i`
//! - Leaves occupy indices `[capacity .. 2*capacity)`
//!
//! When a leaf is updated, only the `O(log n)` path from leaf to root is rehashed.

use ethereum_hashing::{ZERO_HASHES, hash32_concat};

/// Array-based binary Merkle tree with incremental updates.
#[derive(Clone, Debug)]
pub struct SszTree {
    /// Complete binary tree stored as a flat array. 1-indexed, length = 2 * capacity.
    nodes: Vec<[u8; 32]>,
    /// Number of leaf slots (always a power of 2).
    capacity: usize,
    /// Tree depth (log2(capacity)).
    depth: usize,
}

impl SszTree {
    /// Create a new tree with at least `num_leaves` leaf slots.
    ///
    /// The actual capacity is rounded up to the next power of 2.
    /// All leaves and internal nodes are initialized to the appropriate zero hashes.
    pub fn new(num_leaves: usize) -> Self {
        let capacity = num_leaves.next_power_of_two().max(1);
        let depth = capacity.ilog2() as usize;
        let mut nodes = vec![[0u8; 32]; 2 * capacity];

        // Initialize internal nodes with pre-computed zero hashes.
        // Leaves (depth 0) are all zeros. Node at depth d is ZERO_HASHES[d].
        for d in 1..=depth {
            let start = capacity >> d;
            let end = capacity >> (d - 1);
            for node in nodes.iter_mut().take(end).skip(start) {
                *node = ZERO_HASHES[d];
            }
        }

        Self {
            nodes,
            capacity,
            depth,
        }
    }

    /// Returns the root hash (always up to date).
    #[inline]
    pub fn root(&self) -> [u8; 32] {
        if self.capacity == 0 {
            return [0u8; 32];
        }
        self.nodes[1]
    }

    /// Returns the leaf value at the given 0-based index.
    #[inline]
    pub fn get_leaf(&self, leaf_index: usize) -> [u8; 32] {
        self.nodes[self.capacity + leaf_index]
    }

    /// Set a leaf value and incrementally rehash the path to root.
    pub fn set_leaf(&mut self, leaf_index: usize, value: [u8; 32]) {
        let mut i = self.capacity + leaf_index;
        self.nodes[i] = value;
        while i > 1 {
            i /= 2;
            self.nodes[i] = hash32_concat(&self.nodes[2 * i], &self.nodes[2 * i + 1]);
        }
    }

    /// Generate a Merkle proof for the leaf at `leaf_index`.
    ///
    /// Returns sibling hashes in bottom-up order (from leaf level to root level).
    /// The proof has exactly `depth` elements.
    pub fn generate_proof(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        let mut idx = self.capacity + leaf_index;
        let mut proof = Vec::with_capacity(self.depth);
        for _ in 0..self.depth {
            proof.push(self.nodes[idx ^ 1]); // XOR flips last bit to get sibling
            idx /= 2;
        }
        proof
    }

    /// Verify a Merkle proof against a given root.
    ///
    /// `proof` must be in bottom-up order with exactly `depth` elements.
    pub fn verify_proof(
        root: &[u8; 32],
        leaf_index: usize,
        leaf_value: &[u8; 32],
        proof: &[[u8; 32]],
        depth: usize,
    ) -> bool {
        if proof.len() != depth {
            return false;
        }
        let mut hash = *leaf_value;
        let mut idx = (1 << depth) + leaf_index;
        for sibling in proof {
            if idx.is_multiple_of(2) {
                // We are a left child; sibling is on the right
                hash = hash32_concat(&hash, sibling);
            } else {
                // We are a right child; sibling is on the left
                hash = hash32_concat(sibling, &hash);
            }
            idx /= 2;
        }
        hash == *root
    }

    /// Number of leaf slots.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Tree depth (log2(capacity)).
    #[inline]
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Compute the SSZ List root: `SHA256(tree_root || little_endian_u64(length))`.
pub fn mix_in_length(root: [u8; 32], length: usize) -> [u8; 32] {
    let mut length_bytes = [0u8; 32];
    length_bytes[0..8].copy_from_slice(&(length as u64).to_le_bytes());
    hash32_concat(&root, &length_bytes)
}

/// Build a Merkle root from a slice of 32-byte chunks.
///
/// Pads to the next power of 2 with zero chunks and hashes bottom-up.
pub fn merkleize(chunks: &[[u8; 32]]) -> [u8; 32] {
    if chunks.is_empty() {
        return ZERO_HASHES[0];
    }
    let n = chunks.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(chunks);
    layer.resize(n, [0u8; 32]);
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(hash32_concat(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_zero_hash() {
        let tree = SszTree::new(1);
        // A single-leaf tree with a zero leaf should have root = the zero leaf itself.
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn empty_tree_depth_4_matches_zero_hashes() {
        let tree = SszTree::new(16);
        assert_eq!(tree.depth(), 4);
        assert_eq!(tree.root(), ZERO_HASHES[4]);
    }

    #[test]
    fn set_single_leaf_changes_root() {
        let mut tree = SszTree::new(4);
        let zero_root = tree.root();

        tree.set_leaf(0, [0xAA; 32]);
        assert_ne!(tree.root(), zero_root);
    }

    #[test]
    fn set_leaf_and_verify_proof() {
        let mut tree = SszTree::new(4);
        let leaf = [0xBB; 32];
        tree.set_leaf(2, leaf);

        let proof = tree.generate_proof(2);
        assert_eq!(proof.len(), tree.depth());

        let root = tree.root();
        assert!(SszTree::verify_proof(&root, 2, &leaf, &proof, tree.depth()));
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let mut tree = SszTree::new(4);
        tree.set_leaf(1, [0xCC; 32]);

        let proof = tree.generate_proof(1);
        let root = tree.root();
        let wrong_leaf = [0xDD; 32];
        assert!(!SszTree::verify_proof(
            &root,
            1,
            &wrong_leaf,
            &proof,
            tree.depth()
        ));
    }

    #[test]
    fn wrong_root_fails_verification() {
        let mut tree = SszTree::new(4);
        let leaf = [0xEE; 32];
        tree.set_leaf(0, leaf);

        let proof = tree.generate_proof(0);
        let wrong_root = [0xFF; 32];
        assert!(!SszTree::verify_proof(
            &wrong_root,
            0,
            &leaf,
            &proof,
            tree.depth()
        ));
    }

    #[test]
    fn all_leaves_provable() {
        let mut tree = SszTree::new(8);
        let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| [i + 1; 32]).collect();
        for (i, leaf) in leaves.iter().enumerate() {
            tree.set_leaf(i, *leaf);
        }

        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i);
            assert!(
                SszTree::verify_proof(&root, i, leaf, &proof, tree.depth()),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn incremental_matches_full_rebuild() {
        // Build a tree incrementally
        let mut incremental = SszTree::new(4);
        let leaves = [[0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32]];
        for (i, leaf) in leaves.iter().enumerate() {
            incremental.set_leaf(i, *leaf);
        }

        // Build via merkleize
        let full_root = merkleize(&leaves);

        assert_eq!(incremental.root(), full_root);
    }

    #[test]
    fn clone_independence() {
        let mut tree = SszTree::new(4);
        tree.set_leaf(0, [0xAA; 32]);
        let cloned = tree.clone();

        tree.set_leaf(1, [0xBB; 32]);
        assert_ne!(tree.root(), cloned.root());
    }

    #[test]
    fn mix_in_length_changes_root() {
        let root = [0xAA; 32];
        let mixed = mix_in_length(root, 5);
        assert_ne!(root, mixed);

        // Different lengths produce different results
        let mixed2 = mix_in_length(root, 6);
        assert_ne!(mixed, mixed2);
    }

    #[test]
    fn merkleize_empty_returns_zero() {
        assert_eq!(merkleize(&[]), [0u8; 32]);
    }

    #[test]
    fn merkleize_single_chunk() {
        let chunk = [0xAA; 32];
        assert_eq!(merkleize(&[chunk]), chunk);
    }

    #[test]
    fn merkleize_two_chunks() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let expected = hash32_concat(&a, &b);
        assert_eq!(merkleize(&[a, b]), expected);
    }

    #[test]
    fn merkleize_matches_tree() {
        let chunks: Vec<[u8; 32]> = (0..5u8).map(|i| [i + 1; 32]).collect();
        let root_merkleize = merkleize(&chunks);

        // Build same tree via SszTree (5 leaves -> capacity 8)
        let mut tree = SszTree::new(5);
        for (i, chunk) in chunks.iter().enumerate() {
            tree.set_leaf(i, *chunk);
        }
        assert_eq!(tree.root(), root_merkleize);
    }

    #[test]
    fn large_tree_proofs() {
        let mut tree = SszTree::new(1024);
        assert_eq!(tree.depth(), 10);

        // Set scattered leaves
        tree.set_leaf(0, [0x01; 32]);
        tree.set_leaf(500, [0x02; 32]);
        tree.set_leaf(1023, [0x03; 32]);

        let root = tree.root();

        let proof0 = tree.generate_proof(0);
        assert!(SszTree::verify_proof(
            &root,
            0,
            &[0x01; 32],
            &proof0,
            tree.depth()
        ));

        let proof500 = tree.generate_proof(500);
        assert!(SszTree::verify_proof(
            &root,
            500,
            &[0x02; 32],
            &proof500,
            tree.depth()
        ));

        let proof1023 = tree.generate_proof(1023);
        assert!(SszTree::verify_proof(
            &root,
            1023,
            &[0x03; 32],
            &proof1023,
            tree.depth()
        ));
    }

    #[test]
    fn update_leaf_invalidates_old_proof() {
        let mut tree = SszTree::new(4);
        tree.set_leaf(0, [0xAA; 32]);

        let old_root = tree.root();
        let old_proof = tree.generate_proof(0);

        // Update a different leaf — root changes, old proof for leaf 0 should fail
        tree.set_leaf(1, [0xBB; 32]);
        let new_root = tree.root();
        assert_ne!(old_root, new_root);

        // Old proof no longer valid against new root
        assert!(!SszTree::verify_proof(
            &new_root,
            0,
            &[0xAA; 32],
            &old_proof,
            tree.depth()
        ));

        // But still valid against old root
        assert!(SszTree::verify_proof(
            &old_root,
            0,
            &[0xAA; 32],
            &old_proof,
            tree.depth()
        ));
    }

    #[test]
    fn capacity_rounds_up() {
        let tree = SszTree::new(3);
        assert_eq!(tree.capacity(), 4);
        assert_eq!(tree.depth(), 2);

        let tree = SszTree::new(5);
        assert_eq!(tree.capacity(), 8);
        assert_eq!(tree.depth(), 3);
    }
}
