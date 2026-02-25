// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SszProofVerifier
/// @notice Verifies SSZ binary Merkle proofs on-chain using SHA256 and generalized indices.
///         Reads the state root from the EIP-4788 beacon root contract and
///         verifies proofs against it.
contract SszProofVerifier {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice Verify an SSZ Merkle proof using a generalized index.
    /// @param timestamp  EL block timestamp whose beacon root to look up.
    /// @param gindex     Generalized index of the leaf in the state tree.
    /// @param leaf       The 32-byte leaf value.
    /// @param branch     Sibling hashes from leaf to root (bottom-up).
    /// @return root      The state root from the beacon root contract.
    function verify(
        uint256 timestamp,
        uint256 gindex,
        bytes32 leaf,
        bytes32[] calldata branch
    ) external view returns (bytes32 root) {
        root = _getBeaconRoot(timestamp);
        bytes32 computed = _walkBranch(leaf, gindex, branch);
        require(computed == root, "proof invalid");
    }

    /// @dev Walk a Merkle branch bottom-up using a generalized index.
    function _walkBranch(
        bytes32 leaf,
        uint256 gindex,
        bytes32[] calldata branch
    ) internal pure returns (bytes32) {
        bytes32 current = leaf;
        uint256 idx = gindex;
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
        require(idx == 1, "proof length mismatch");
        return current;
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
