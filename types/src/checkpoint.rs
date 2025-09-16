use crate::consensus_state::ConsensusState;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::{Hasher, Sha256};
use crate::PublicKey;

#[allow(unused)]
pub struct Checkpoint {
    pub data: Bytes,
    pub added_validators: Vec<PublicKey>,
    pub removed_validators: Vec<PublicKey>,
    pub previous_digest: Digest,
    pub digest: Digest,
}


impl Checkpoint {
    fn new(state: &ConsensusState, mut added_validators: Vec<PublicKey>, mut removed_validators: Vec<PublicKey>, previous_digest: Digest) -> Self {
        let data = state.encode().freeze();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        // TODO(matthias): check if sorting is necessary
        added_validators.sort();
        removed_validators.sort();
        for validator in &added_validators {
            hasher.update(&validator);
        }
        // This byte acts as a divider between the two lists
        // This is to avoid that the two lists
        // added_validators = [A, B], removed_validators = [C]
        // and
        // added_validators = [A], removed_validators = [B, C]
        // have the same hash
        hasher.update(&[0x00]);
        for validator in &removed_validators {
            hasher.update(&validator);
        }
        hasher.update(&previous_digest);
        let digest = hasher.finalize();
        Self {
            data,
            added_validators,
            removed_validators,
            previous_digest,
            digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use commonware_codec::DecodeExt;
    use crate::checkpoint::Checkpoint;
    use crate::consensus_state::ConsensusState;

    fn parse_public_key(public_key: &str) -> commonware_cryptography::ed25519::PublicKey {
        commonware_cryptography::ed25519::PublicKey::decode(
            commonware_utils::from_hex_formatted(public_key)
                .unwrap()
                .as_ref(),
        )
            .unwrap()
    }

    #[test]
    fn test_digest() {
        let state = ConsensusState {
            latest_height: 10,
            next_withdrawal_index: 100,
            deposit_queue: VecDeque::new(),
            withdrawal_queue: VecDeque::new(),
            validator_accounts: HashMap::new(),
        };

        let key1 = parse_public_key(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let key2 = parse_public_key(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        );
        let key3 = parse_public_key(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        );

        let added_validators1 = vec![key1.clone(), key2.clone()];
        let removed_validators1 = vec![key3.clone()];

        let added_validators2 = vec![key1];
        let removed_validators2 = vec![key2, key3];

        let previous_digest = [1; 32].into();

        let ckpt1 = Checkpoint::new(&state, added_validators1, removed_validators1, previous_digest);
        let ckpt2 = Checkpoint::new(&state, added_validators2, removed_validators2, previous_digest);

        // Make sure the digest are different
        assert_ne!(ckpt1.digest, ckpt2.digest);
    }
}
