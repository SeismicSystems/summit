// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MptProofVerifier
/// @notice Reads a state root from the EIP-4788 beacon root contract and
///         verifies an MPT proof against it via the seismic precompile at 0x6A.
contract MptProofVerifier {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    address constant MPT_PRECOMPILE = 0x000000000000000000000000000000000000006a;

    /// @param timestamp  EL block timestamp whose beacon root to look up.
    /// @param proofData  Precompile payload **without** the leading 32-byte root
    ///                   (item_count ++ items ++ proof_count ++ proof_nodes).
    /// @return root      The state root retrieved from the beacon root contract.
    function verify(uint256 timestamp, bytes calldata proofData)
        external
        view
        returns (bytes32 root)
    {
        // 1. Read state root from beacon root contract
        (bool ok, bytes memory rootData) = BEACON_ROOTS.staticcall(
            abi.encode(timestamp)
        );
        require(ok && rootData.length == 32, "beacon root lookup failed");
        root = abi.decode(rootData, (bytes32));

        // 2. Call MPT verify precompile with root ++ proofData
        (bool ok2, bytes memory result) = MPT_PRECOMPILE.staticcall(
            abi.encodePacked(root, proofData)
        );
        require(
            ok2 && result.length >= 32 && uint8(result[31]) == 1,
            "MPT verification failed"
        );
    }
}
