use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    routing::{get, post},
};
use commonware_codec::DecodeExt as _;
use commonware_consensus::Block as ConsensusBlock;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_cryptography::Committable;
use commonware_utils::{from_hex_formatted, hex};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use summit_types::{KeyPaths, PublicKey, utils::get_expanded_path};

use crate::{GenesisRpcState, PathSender, RpcState};

#[derive(Serialize)]
struct PublicKeysResponse {
    node: String,
    consensus: String,
}

#[derive(Deserialize)]
struct ValidatorBalanceQuery {
    public_key: String,
}

pub(crate) struct RpcRoutes;

impl RpcRoutes {
    pub fn mount<S: Scheme + 'static, B: ConsensusBlock + Committable + 'static>(
        state: RpcState<S, B>,
    ) -> Router {
        // todo(dalton): Add cors
        let state = Arc::new(state);

        Router::new()
            .route("/health", get(Self::handle_health_check))
            .route("/get_public_keys", get(Self::handle_get_pub_keys::<S, B>))
            .route("/get_checkpoint", get(Self::handle_get_checkpoint::<S, B>))
            .route(
                "/get_latest_height",
                get(Self::handle_latest_height::<S, B>),
            )
            .route(
                "/get_validator_balance",
                get(Self::handle_get_validator_balance::<S, B>),
            )
            .with_state(state)
    }

    pub fn mount_for_genesis(state: GenesisRpcState) -> Router {
        // todo(dalton): Add cors
        let state = Arc::new(state);

        Router::new()
            .route("/health", get(Self::handle_health_check))
            .route("/get_public_keys", get(Self::handle_get_pub_keys_genesis))
            .route("/send_genesis", post(Self::handle_send_genesis))
            .with_state(state)
    }

    async fn handle_health_check() -> &'static str {
        "Ok"
    }

    async fn handle_get_pub_keys<S: Scheme, B: ConsensusBlock + Committable>(
        State(state): State<Arc<RpcState<S, B>>>,
    ) -> Result<String, String> {
        let key_paths = KeyPaths::new(state.key_store_path.clone());

        let response = PublicKeysResponse {
            node: key_paths.node_public_key()?,
            consensus: key_paths.consensus_public_key()?,
        };

        serde_json::to_string(&response).map_err(|e| format!("Failed to serialize response: {}", e))
    }

    async fn handle_get_pub_keys_genesis(
        State(state): State<Arc<GenesisRpcState>>,
    ) -> Result<String, String> {
        let key_paths = KeyPaths::new(state.key_store_path.clone());

        let response = PublicKeysResponse {
            node: key_paths.node_public_key()?,
            consensus: key_paths.consensus_public_key()?,
        };

        serde_json::to_string(&response).map_err(|e| format!("Failed to serialize response: {}", e))
    }

    async fn handle_get_checkpoint<S: Scheme, B: ConsensusBlock + Committable>(
        State(state): State<Arc<RpcState<S, B>>>,
    ) -> Result<String, String> {
        let maybe_checkpoint = state
            .finalizer_mailbox
            .clone()
            .get_latest_checkpoint()
            .await;
        let Some(checkpoint) = maybe_checkpoint else {
            return Err("checkpoint not found".into());
        };

        let encoded = checkpoint.as_ssz_bytes();
        Ok(hex(&encoded))
    }

    async fn handle_latest_height<S: Scheme, B: ConsensusBlock + Committable>(
        State(state): State<Arc<RpcState<S, B>>>,
    ) -> Result<String, String> {
        Ok(state
            .finalizer_mailbox
            .get_latest_height()
            .await
            .to_string())
    }

    async fn handle_get_validator_balance<S: Scheme, B: ConsensusBlock + Committable>(
        State(state): State<Arc<RpcState<S, B>>>,
        Query(params): Query<ValidatorBalanceQuery>,
    ) -> Result<String, String> {
        // Parse the public key from hex string
        let key_bytes =
            from_hex_formatted(&params.public_key).ok_or("Invalid hex format for public key")?;
        let public_key =
            PublicKey::decode(&*key_bytes).map_err(|_| "Unable to decode public key")?;

        let balance = state
            .finalizer_mailbox
            .get_validator_balance(public_key)
            .await;

        match balance {
            Some(balance) => Ok(balance.to_string()),
            None => Err("Validator not found".to_string()),
        }
    }

    async fn handle_send_genesis(
        State(state): State<Arc<GenesisRpcState>>,
        body: String,
    ) -> Result<String, String> {
        Self::handle_send_file(&state.genesis, body, "genesis")
    }

    fn handle_send_file(
        PathSender { path, sender }: &PathSender,
        body: String,
        kind: &'static str,
    ) -> Result<String, String> {
        let path_buf = get_expanded_path(path).map_err(|_| format!("invalid {kind} path"))?;

        if let Some(parent) = path_buf.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {e}"))?;
        }

        std::fs::write(&path_buf, &body)
            .map_err(|e| format!("Failed to write {kind} file: {e}"))?;

        // Signal that file is ready
        if let Some(sender) = sender.lock().expect("poisoned").take() {
            let _ = sender.send(());
            Ok(format!(
                "{kind} file written at location {path} and node notified"
            ))
        } else {
            Ok(format!(
                "{kind} file written at location {path} (no notification needed)"
            ))
        }
    }
}
