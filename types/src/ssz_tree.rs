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

    /// Returns the value of any node (leaf or internal) by its 1-based tree index.
    #[inline]
    pub fn get_node(&self, node_index: usize) -> [u8; 32] {
        self.nodes[node_index]
    }

    /// Generate a Merkle proof from an arbitrary node (not just a leaf) to the root.
    ///
    /// Returns sibling hashes in bottom-up order. The proof length equals the
    /// depth of the node from the root (i.e., `floor(log2(node_index))`).
    pub fn generate_proof_from_node(&self, node_index: usize) -> Vec<[u8; 32]> {
        let mut idx = node_index;
        let mut proof = Vec::new();
        while idx > 1 {
            proof.push(self.nodes[idx ^ 1]);
            idx /= 2;
        }
        proof
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

    /// Set a leaf value without rehashing the path to root.
    ///
    /// Use this for bulk leaf writes, followed by `rehash_from` to recompute
    /// internal nodes in a single bottom-up pass.
    #[inline]
    pub fn set_leaf_no_rehash(&mut self, leaf_index: usize, value: [u8; 32]) {
        self.nodes[self.capacity + leaf_index] = value;
    }

    /// Bottom-up rehash of all internal nodes from `start_index` level up to root.
    ///
    /// `start_index` is the first 1-based node index at the level to start from.
    /// For example, `capacity / 8` is the per-validator subtree root level.
    /// Rehashes every node from that level up to and including the root.
    pub fn rehash_from(&mut self, start_index: usize) {
        // Walk up levels: start_index..start_index*2 is one level,
        // parent level is start_index/2..start_index, etc.
        let mut level_start = start_index;
        while level_start >= 1 {
            let level_end = level_start * 2;
            for i in level_start..level_end {
                if i * 2 + 1 < self.nodes.len() {
                    self.nodes[i] = hash32_concat(&self.nodes[2 * i], &self.nodes[2 * i + 1]);
                }
            }
            if level_start == 1 {
                break;
            }
            level_start /= 2;
        }
    }

    /// Shift `count` blocks of `block_size` leaves starting at `from_slot` right by 1 block.
    ///
    /// Copies all 4 levels of nodes (leaves + 3 internal levels per block).
    /// Zeros the vacated slot at `from_slot`. Does NOT rehash.
    pub fn shift_blocks_right(&mut self, from_slot: usize, count: usize, block_size: usize) {
        if count == 0 {
            return;
        }
        let log_block = block_size.ilog2() as usize; // 3 for block_size=8

        // Shift each level: leaves, then each internal level up to subtree root
        for level in 0..=log_block {
            let stride = block_size >> level; // 8, 4, 2, 1
            let base = self.capacity >> level; // C, C/2, C/4, C/8
            let src_start = base + from_slot * stride;
            let src_end = src_start + count * stride;
            let dst_start = src_start + stride;
            // Use copy_within for overlapping memmove
            self.nodes.copy_within(src_start..src_end, dst_start);
            // Zero the vacated slot
            for i in src_start..src_start + stride {
                self.nodes[i] = [0u8; 32];
            }
        }
    }

    /// Shift `count` blocks of `block_size` leaves starting at `from_slot+1` left by 1 block.
    ///
    /// Copies all 4 levels. Zeros the last block. Does NOT rehash.
    pub fn shift_blocks_left(&mut self, from_slot: usize, count: usize, block_size: usize) {
        if count == 0 {
            return;
        }
        let log_block = block_size.ilog2() as usize;

        for level in 0..=log_block {
            let stride = block_size >> level;
            let base = self.capacity >> level;
            let src_start = base + (from_slot + 1) * stride;
            let src_end = src_start + count * stride;
            let dst_start = base + from_slot * stride;
            self.nodes.copy_within(src_start..src_end, dst_start);
            // Zero the vacated last block
            let zero_start = dst_start + count * stride;
            for i in zero_start..zero_start + stride {
                self.nodes[i] = [0u8; 32];
            }
        }
    }

    /// Grow the tree to accommodate at least `min_leaves` leaves.
    ///
    /// Copies existing leaves to the new tree and does a full bottom-up rehash.
    /// No-op if the current capacity is sufficient.
    pub fn grow(&mut self, min_leaves: usize) {
        if min_leaves <= self.capacity {
            return;
        }
        let new_capacity = min_leaves.next_power_of_two();
        let new_depth = new_capacity.ilog2() as usize;
        let mut new_nodes = vec![[0u8; 32]; 2 * new_capacity];

        // Copy existing leaves
        let old_leaf_start = self.capacity;
        let old_leaf_end = 2 * self.capacity;
        let new_leaf_start = new_capacity;
        new_nodes[new_leaf_start..new_leaf_start + self.capacity]
            .copy_from_slice(&self.nodes[old_leaf_start..old_leaf_end]);

        self.nodes = new_nodes;
        self.capacity = new_capacity;
        self.depth = new_depth;

        // Full bottom-up rehash from leaf parents
        self.rehash_from(self.capacity / 2);
    }

    /// Shrink the tree so that its capacity matches `min_leaves.next_power_of_two()`.
    ///
    /// Copies existing leaves into the smaller tree and does a full bottom-up rehash.
    /// No-op if the new capacity would be >= the current capacity.
    pub fn shrink(&mut self, min_leaves: usize) {
        let new_capacity = min_leaves.max(1).next_power_of_two();
        if new_capacity >= self.capacity {
            return;
        }
        let new_depth = new_capacity.ilog2() as usize;
        let mut new_nodes = vec![[0u8; 32]; 2 * new_capacity];

        // Copy the first new_capacity leaves
        let old_leaf_start = self.capacity;
        let new_leaf_start = new_capacity;
        new_nodes[new_leaf_start..new_leaf_start + new_capacity]
            .copy_from_slice(&self.nodes[old_leaf_start..old_leaf_start + new_capacity]);

        self.nodes = new_nodes;
        self.capacity = new_capacity;
        self.depth = new_depth;

        self.rehash_from(self.capacity / 2);
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

    /// Verify a Merkle proof using a generalized index.
    ///
    /// The generalized index encodes the full path from root to leaf.
    /// `proof` contains sibling hashes in bottom-up order.
    /// The proof length must equal `floor(log2(gindex))`.
    pub fn verify_proof_gindex(
        root: &[u8; 32],
        gindex: u64,
        leaf_value: &[u8; 32],
        proof: &[[u8; 32]],
    ) -> bool {
        if gindex == 0 {
            return false;
        }
        let expected_depth = 63 - gindex.leading_zeros() as usize;
        if proof.len() != expected_depth {
            return false;
        }
        let mut hash = *leaf_value;
        let mut idx = gindex;
        for sibling in proof {
            if idx.is_multiple_of(2) {
                hash = hash32_concat(&hash, sibling);
            } else {
                hash = hash32_concat(sibling, &hash);
            }
            idx /= 2;
        }
        idx == 1 && hash == *root
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
    fn get_node_returns_internal_nodes() {
        let mut tree = SszTree::new(4);
        tree.set_leaf(0, [0xAA; 32]);
        tree.set_leaf(1, [0xBB; 32]);

        // Internal node at index 2 should be hash of leaves 0 and 1
        let expected = hash32_concat(&[0xAA; 32], &[0xBB; 32]);
        assert_eq!(tree.get_node(2), expected);

        // Root (node 1) should also be accessible
        assert_eq!(tree.get_node(1), tree.root());
    }

    #[test]
    fn proof_from_internal_node_verifies() {
        let mut tree = SszTree::new(8);
        // Set 8 leaves
        for i in 0..8u8 {
            tree.set_leaf(i as usize, [i + 1; 32]);
        }

        // Node at index 2 is the left child of the root (depth 1)
        let node_idx = 2;
        let node_value = tree.get_node(node_idx);
        let proof = tree.generate_proof_from_node(node_idx);
        assert_eq!(proof.len(), 1); // depth 1 from root

        // Manually verify: hash(node_value, sibling) should equal root
        let expected_root = hash32_concat(&node_value, &proof[0]);
        assert_eq!(expected_root, tree.root());

        // Node at index 4 is at depth 2
        let node_idx = 4;
        let node_value = tree.get_node(node_idx);
        let proof = tree.generate_proof_from_node(node_idx);
        assert_eq!(proof.len(), 2);

        // Also verifiable via gindex: node_idx IS the gindex
        assert!(SszTree::verify_proof_gindex(
            &tree.root(),
            node_idx as u64,
            &node_value,
            &proof,
        ));
    }

    #[test]
    fn proof_from_node_at_various_depths() {
        let mut tree = SszTree::new(16); // depth 4
        for i in 0..16u8 {
            tree.set_leaf(i as usize, [i + 1; 32]);
        }

        // Leaf (depth 4): proof length 4
        let leaf_proof = tree.generate_proof_from_node(tree.capacity() + 0);
        assert_eq!(leaf_proof.len(), 4);

        // One level above leaves (depth 3): proof length 3
        let mid_proof = tree.generate_proof_from_node(tree.capacity() / 2);
        assert_eq!(mid_proof.len(), 3);

        // Two levels above (depth 2): proof length 2
        let upper_proof = tree.generate_proof_from_node(tree.capacity() / 4);
        assert_eq!(upper_proof.len(), 2);

        // All should be verifiable via gindex
        for node_idx in [
            tree.capacity() + 0,
            tree.capacity() / 2,
            tree.capacity() / 4,
        ] {
            let val = tree.get_node(node_idx);
            let proof = tree.generate_proof_from_node(node_idx);
            assert!(SszTree::verify_proof_gindex(
                &tree.root(),
                node_idx as u64,
                &val,
                &proof,
            ));
        }
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
