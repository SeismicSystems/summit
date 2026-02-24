// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SszProofVerifier
/// @notice Verifies SSZ binary Merkle proofs on-chain using SHA256.
///         Reads the state root from the EIP-4788 beacon root contract and
///         verifies proofs against it.
contract SszProofVerifier {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice Verify a scalar (top-level) SSZ Merkle proof.
    /// @param timestamp  EL block timestamp whose beacon root to look up.
    /// @param leafIndex  Index of the leaf in the top-level tree (0-16).
    /// @param leafValue  The 32-byte leaf value.
    /// @param branch     Sibling hashes from leaf to root (bottom-up).
    /// @return root      The state root from the beacon root contract.
    function verifyScalar(
        uint256 timestamp,
        uint256 leafIndex,
        bytes32 leafValue,
        bytes32[] calldata branch
    ) external view returns (bytes32 root) {
        root = _getBeaconRoot(timestamp);
        bytes32 computed = _walkBranch(leafValue, leafIndex, branch);
        require(computed == root, "scalar proof invalid");
    }

    /// @notice Verify a collection (two-level) SSZ Merkle proof.
    /// @param timestamp        EL block timestamp whose beacon root to look up.
    /// @param itemIndex        Index of the item in the subtree.
    /// @param leafValue        Hash-tree-root of the item.
    /// @param subtreeBranch    Siblings from item leaf to subtree root.
    /// @param subtreeRoot      Expected subtree root (before mix_in_length).
    /// @param collectionLength Number of items in the collection.
    /// @param topLeafIndex     Index of the collection root in the top-level tree.
    /// @param topBranch        Siblings from collection leaf to state root.
    /// @return root            The state root from the beacon root contract.
    function verifyCollection(
        uint256 timestamp,
        uint256 itemIndex,
        bytes32 leafValue,
        bytes32[] calldata subtreeBranch,
        bytes32 subtreeRoot,
        uint256 collectionLength,
        uint256 topLeafIndex,
        bytes32[] calldata topBranch
    ) external view returns (bytes32 root) {
        // 1. Verify subtree proof
        bytes32 computedSubtreeRoot = _walkBranch(leafValue, itemIndex, subtreeBranch);
        require(computedSubtreeRoot == subtreeRoot, "subtree proof invalid");

        // 2. mix_in_length: sha256(subtreeRoot || le_u64(collectionLength))
        bytes32 collectionLeaf = _mixInLength(subtreeRoot, collectionLength);

        // 3. Verify top-level proof
        root = _getBeaconRoot(timestamp);
        bytes32 computedRoot = _walkBranch(collectionLeaf, topLeafIndex, topBranch);
        require(computedRoot == root, "top-level proof invalid");
    }

    /// @dev Walk a Merkle branch bottom-up, returning the computed root.
    function _walkBranch(
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata branch
    ) internal pure returns (bytes32) {
        bytes32 current = leaf;
        uint256 idx = (1 << branch.length) + leafIndex;
        for (uint256 i = 0; i < branch.length; i++) {
            if (idx % 2 == 0) {
                // Left child: current || sibling
                current = sha256(abi.encodePacked(current, branch[i]));
            } else {
                // Right child: sibling || current
                current = sha256(abi.encodePacked(branch[i], current));
            }
            idx /= 2;
        }
        return current;
    }

    /// @dev SSZ mix_in_length: sha256(root || le_u64(length) ++ zeros)
    function _mixInLength(bytes32 root, uint256 length) internal pure returns (bytes32) {
        // Encode length as 8-byte little-endian, zero-padded to 32 bytes
        bytes32 lengthBytes = bytes32(_toLittleEndian64(uint64(length)));
        return sha256(abi.encodePacked(root, lengthBytes));
    }

    /// @dev Convert a uint64 to 32-byte little-endian (LE bytes in low positions).
    function _toLittleEndian64(uint64 v) internal pure returns (bytes32) {
        // Swap bytes to convert from big-endian (Solidity native) to little-endian
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
        // Place the 8 LE bytes in the leftmost (most significant) position of bytes32
        // so that when stored as bytes32, they appear at bytes[0..8]
        return bytes32(uint256(v) << 192);
    }

    /// @dev Look up the beacon root for the given timestamp.
    function _getBeaconRoot(uint256 timestamp) internal view returns (bytes32 root) {
        (bool ok, bytes memory data) = BEACON_ROOTS.staticcall(
            abi.encode(timestamp)
        );
        require(ok && data.length == 32, "beacon root lookup failed");
        root = abi.decode(data, (bytes32));
    }
}
