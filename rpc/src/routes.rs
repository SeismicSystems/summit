use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    routing::{get, post},
};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::Signer;
use commonware_utils::{from_hex_formatted, hex};
use ssz::Encode;
use summit_types::{PrivateKey, utils::get_expanded_path};

use crate::{GenesisRpcState, PathSender, RpcState};

pub(crate) struct RpcRoutes;

impl RpcRoutes {
    pub fn mount(state: RpcState) -> Router {
        // todo(dalton): Add cors
        let state = Arc::new(state);

        Router::new()
            .route("/health", get(Self::handle_health_check))
            .route("/get_public_key", get(Self::handle_get_pub_key))
            .route("/get_checkpoint", get(Self::handle_get_checkpoint))
            .with_state(state)
    }

    pub fn mount_for_genesis(state: GenesisRpcState) -> Router {
        // todo(dalton): Add cors
        let state = Arc::new(state);

        Router::new()
            .route("/send_genesis", post(Self::handle_send_genesis))
            .with_state(state)
    }

    async fn handle_health_check() -> &'static str {
        "Ok"
    }

    async fn handle_get_pub_key(State(state): State<Arc<RpcState>>) -> Result<String, String> {
        let private_key = Self::read_ed_key_from_path(&state.key_path)?;

        Ok(private_key.public_key().to_string())
    }

    fn read_ed_key_from_path(key_path: &str) -> Result<PrivateKey, String> {
        let path = get_expanded_path(key_path).map_err(|_| "unable to get key_path")?;
        let encoded_pk =
            std::fs::read_to_string(path).map_err(|_| "Failed to read Private key file")?;

        let key = from_hex_formatted(&encoded_pk).ok_or("Invalid hex format for private key")?;
        let pk = PrivateKey::decode(&*key).map_err(|_| "unable to decode private key")?;

        Ok(pk)
    }

    async fn handle_get_checkpoint(State(state): State<Arc<RpcState>>) -> Result<String, String> {
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
