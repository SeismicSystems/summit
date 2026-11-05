use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Round, View};
use serde::{Deserialize, Serialize};
use summit_syncer::ingress::handler::Key;
use summit_types::Digest;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeysResponse {
    pub node: String,
    pub consensus: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DepositTransactionResponse {
    pub node_pubkey: [u8; 32],
    pub consensus_pubkey: Vec<u8>,
    pub withdrawal_credentials: [u8; 32],
    pub node_signature: Vec<u8>,
    pub consensus_signature: Vec<u8>,
    pub deposit_data_root: [u8; 32],
}

pub use summit_types::rpc::{
    CheckpointInfoRes, CheckpointRes, DepositResponse, EpochBoundsResponse,
    FinalizedHeaderDigestRes, FinalizedHeaderRes, PendingWithdrawalResponse, StateProofResponse,
    StateProofResult, StateRootResponse, ValidatorAccountResponse,
};

/// A syncer resolver key, as `getResolverValue` takes it. Mirrors the
/// syncer's `Key`, which has no serde form.
///
/// In JSON: `{"kind": "finalized", "height": 1}`,
/// `{"kind": "block", "digest": "0x…"}`, or
/// `{"kind": "notarized", "epoch": 1, "view": 2}`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ResolverKey {
    /// A block, by its consensus digest.
    Block { digest: B256 },
    /// A finalized block and its finalization, by height.
    Finalized { height: u64 },
    /// A notarized block and its notarization, by round.
    Notarized { epoch: u64, view: u64 },
}

impl From<ResolverKey> for Key<Digest> {
    fn from(key: ResolverKey) -> Self {
        match key {
            ResolverKey::Block { digest } => {
                Self::Block(commonware_cryptography::sha256::Digest(digest.0))
            }
            ResolverKey::Finalized { height } => Self::Finalized { height },
            ResolverKey::Notarized { epoch, view } => Self::Notarized {
                round: Round::new(Epoch::new(epoch), View::new(view)),
            },
        }
    }
}

impl From<Key<Digest>> for ResolverKey {
    fn from(key: Key<Digest>) -> Self {
        match key {
            Key::Block(digest) => Self::Block {
                digest: B256::from(digest.0),
            },
            Key::Finalized { height } => Self::Finalized { height },
            Key::Notarized { round } => Self::Notarized {
                epoch: round.epoch().get(),
                view: round.view().get(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_key_json_shape_and_round_trip() {
        let cases = [
            (
                ResolverKey::Finalized { height: 1 },
                serde_json::json!({"kind": "finalized", "height": 1}),
            ),
            (
                ResolverKey::Block {
                    digest: B256::repeat_byte(0xab),
                },
                serde_json::json!({"kind": "block", "digest": format!("0x{}", "ab".repeat(32))}),
            ),
            (
                ResolverKey::Notarized { epoch: 3, view: 7 },
                serde_json::json!({"kind": "notarized", "epoch": 3, "view": 7}),
            ),
        ];
        for (key, json) in cases {
            assert_eq!(serde_json::to_value(key).unwrap(), json);
            assert_eq!(serde_json::from_value::<ResolverKey>(json).unwrap(), key);
            assert_eq!(ResolverKey::from(Key::<Digest>::from(key)), key);
        }
    }
}
