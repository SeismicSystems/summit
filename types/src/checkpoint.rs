use crate::consensus_state::ConsensusState;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::{Hasher, Sha256};

#[allow(unused)]
pub struct Checkpoint {
    pub height: u64, // just for convenience, the height is included in the checkpoint data
    pub digest: Digest,
    pub data: Bytes,
}

impl From<&ConsensusState> for Checkpoint {
    fn from(state: &ConsensusState) -> Checkpoint {
        let data = state.encode().freeze();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = hasher.finalize();
        Self {
            height: state.latest_height,
            digest,
            data,
        }
    }
}
