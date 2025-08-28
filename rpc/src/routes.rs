use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    routing::{get, post},
};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::Signer;
use commonware_utils::from_hex_formatted;
use summit_types::{PrivateKey, utils::get_expanded_path};

use crate::RpcState;

pub(crate) struct RpcRoutes;

impl RpcRoutes {
    pub fn mount(state: RpcState) -> Router {
        // todo(dalton): Add cors
        let state = Arc::new(state);

        Router::new()
            .route("/health", get(Self::handle_health_check))
            .route("/get_public_key", get(Self::handle_get_pub_key))
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

    async fn handle_send_genesis(
        State(state): State<Arc<RpcState>>,
        body: String,
    ) -> Result<String, String> {
        // Write genesis to file
        let genesis_path =
            get_expanded_path(&state.genesis_path).map_err(|_| "invalid genesis path")?;

        if let Some(parent) = genesis_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {e}"))?;
        }

        std::fs::write(&genesis_path, &body)
            .map_err(|e| format!("Failed to write genesis file: {e}"))?;

        // Signal that genesis is ready
        if let Some(sender) = state.genesis_sender.lock().expect("poisoned").take() {
            let _ = sender.send(());
            Ok("Genesis file written and node notified".to_string())
        } else {
            Ok("Genesis file written (no notification needed)".to_string())
        }
    }
}
