//! Tests proving that Summit consensus state proofs and Ethereum `eth_getProof` proofs
//! are verified by the same [`crate::state_trie::verify_mpt_proof`] function.

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address, b256, keccak256};
    use alloy_rlp::Encodable;

    use crate::state_trie::{StateTrie, verify_mpt_proof};

    // ── Real eth_getProof data ──────────────────────────────────────────
    //
    // Captured from `eth_getProof` at block 0x3d11f on internal-0.seismictest.net
    // for address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

    const STATE_ROOT: [u8; 32] =
        hex_literal::hex!("b492fb62fa9e69f28f670b8f5dd0e908a2f3d8402ca38c90c505095e523eb4ac");

    const PROOF_NODE_0: [u8; 468] = hex_literal::hex!(
        "f901d1a06ebb4246197b62d28134e8d031d7e2e572a1d3dded175e6fc3ecee781a5412c1a053bb9f9b8b6a82296b134ebb60ab4f6ffbe62ea5f7cd1934cb170d1dfe739ffaa0fbdef595f1ee6630f9d91e0016963b7637518accfe9c91f87457cb5b22b61ffda056e50ab906bbbc187b56f08e6aff841965eddd01017ceb01709f161188d79566a002cdb67081bec4ec8c16c72dd55f986895f47db6b838a00b29da822b526564cca09cef32e7699886d60eca324a3ace71582bd6bb76b78a2b4a222e899e77c6d479a005feed882f717c35f0813dba9ac62c62ec6d5dd0835fe4761ed69660e0082e7ca018f2c13f239a44af3ea863f08a701c5d295cea45b08b3fb524d91a84a4bc3d7fa0d77fdb6ad9c9a57957a42bc18f162cc47b68552c928510875f6c7b333d5ec194a0d9f406a457e312b61467cb1b11e29b1a2fa6a023babdedfda1a5421297d042c480a0d102b3b59a6c23ba0143404225d4c39bd238e5d6bbef499ba5dba2cfc7abede6a085c72aed114057439c56df86944fc77d751801f734f927880bd71ffd54b47edca036200cafef57c0613465d5946f264ff15a142c47f3a613f70ecbc30e88c5b6ffa0587d256cddc5bd1b79d2563ddb22f39609ddf291e9a753f633c915894569fa468080"
    );

    const PROOF_NODE_1: [u8; 117] = hex_literal::hex!(
        "f873a030314e565e0574cb412563df634608d76f5c59d9f817e85966100ec1d48005c0b850f84e808ad3c21bcf3f864a3de000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    /// Build the expected account value: RLP([nonce, balance, storageHash, codeHash])
    fn eth_account_rlp() -> Vec<u8> {
        let nonce: u64 = 0;
        let balance = U256::from_be_bytes(hex_literal::hex!(
            "00000000000000000000000000000000000000000000d3c21bcf3f864a3de000"
        ));
        let storage_hash =
            b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
        let code_hash = b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

        let mut value = Vec::new();
        let payload_len =
            nonce.length() + balance.length() + storage_hash.length() + code_hash.length();
        alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        }
        .encode(&mut value);
        nonce.encode(&mut value);
        balance.encode(&mut value);
        storage_hash.encode(&mut value);
        code_hash.encode(&mut value);
        value
    }

    // ── The actual tests ────────────────────────────────────────────────

    /// Verify a real `eth_getProof` account proof using `verify_mpt_proof`.
    #[test]
    fn verify_eth_get_proof_with_verify_mpt_proof() {
        let address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let hashed_key: [u8; 32] = keccak256(address).into();
        let account_value = eth_account_rlp();

        let proof: Vec<&[u8]> = vec![&PROOF_NODE_0, &PROOF_NODE_1];

        assert!(verify_mpt_proof(
            &STATE_ROOT,
            &proof,
            &hashed_key,
            Some(&account_value),
        ));
    }

    /// Verify a Summit consensus state proof using `verify_mpt_proof`.
    #[test]
    fn verify_summit_proof_with_verify_mpt_proof() {
        let mut trie = StateTrie::default();
        trie.insert_u64(b"epoch", 42);
        trie.insert_u64(b"view", 100);
        trie.insert_hash(b"finalized_block_hash", &[0xAB; 32]);

        let root = trie.root();
        let per_key_proofs = trie.generate_proof(&[b"epoch"]);

        let hashed_key: [u8; 32] = keccak256(b"epoch").into();
        let value = 42u64.to_be_bytes();

        assert!(verify_mpt_proof(
            &root,
            &per_key_proofs[0],
            &hashed_key,
            Some(&value),
        ));
    }

    /// The critical test: both Summit and Ethereum proofs verified by the same function.
    ///
    /// This proves the `0x6A` precompile can use a single `verify_mpt_proof` implementation
    /// to verify both proof types — Summit's consensus state proofs produce byte-identical
    /// RLP-encoded trie nodes to Ethereum's `eth_getProof`.
    #[test]
    fn same_verifier_for_summit_and_ethereum_proofs() {
        // ── Ethereum eth_getProof proof ────────────────────────────────
        let eth_address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let eth_key: [u8; 32] = keccak256(eth_address).into();
        let eth_value = eth_account_rlp();
        let eth_proof: Vec<&[u8]> = vec![&PROOF_NODE_0, &PROOF_NODE_1];

        // ── Summit consensus state proof ───────────────────────────────
        let mut trie = StateTrie::default();
        trie.insert_u64(b"epoch", 42);
        trie.insert_u64(b"view", 100);
        trie.insert_hash(b"finalized_block_hash", &[0xAB; 32]);

        let summit_root = trie.root();
        let summit_per_key_proofs = trie.generate_proof(&[b"epoch"]);
        let summit_key: [u8; 32] = keccak256(b"epoch").into();
        let summit_value = 42u64.to_be_bytes();

        // ── Same function verifies both ────────────────────────────────
        assert!(
            verify_mpt_proof(&STATE_ROOT, &eth_proof, &eth_key, Some(&eth_value)),
            "verify_mpt_proof failed on Ethereum eth_getProof data"
        );
        assert!(
            verify_mpt_proof(
                &summit_root,
                &summit_per_key_proofs[0],
                &summit_key,
                Some(&summit_value)
            ),
            "verify_mpt_proof failed on Summit consensus state proof"
        );

        // ── Cross-check: wrong values rejected for both ───────────────
        assert!(
            !verify_mpt_proof(&STATE_ROOT, &eth_proof, &eth_key, Some(b"wrong")),
            "verify_mpt_proof should reject wrong Ethereum value"
        );
        assert!(
            !verify_mpt_proof(
                &summit_root,
                &summit_per_key_proofs[0],
                &summit_key,
                Some(&99u64.to_be_bytes())
            ),
            "verify_mpt_proof should reject wrong Summit value"
        );
    }
}
