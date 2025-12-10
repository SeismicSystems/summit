use std::sync::Arc;

use alloy_primitives::{Address, U256, hex::FromHex as _};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::Block as ConsensusBlock;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_cryptography::{Committable, Hasher as _, Sha256, Signer as _};
use commonware_utils::{from_hex_formatted, hex};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use summit_types::{
    KeyPaths, PROTOCOL_VERSION, PublicKey,
    execution_request::{DepositRequest, compute_deposit_data_root},
    utils::get_expanded_path,
};

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

#[derive(Serialize, Deserialize)]
struct DepositTransactionResponse {
    node_pubkey: [u8; 32],
    consensus_pubkey: Vec<u8>, // 48 bytes
    withdrawal_credentials: [u8; 32],
    node_signature: Vec<u8>,      // 48 bytes
    consensus_signature: Vec<u8>, // 96 bytes
    deposit_data_root: [u8; 32],
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
            .route(
                "/get_deposit_signature/{amount}/{address}",
                get(Self::handle_get_deposit_signature),
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

    async fn handle_get_deposit_signature<S: Scheme, B: ConsensusBlock + Committable>(
        State(state): State<Arc<RpcState<S, B>>>,
        Path((amount, address)): Path<(u64, String)>,
    ) -> Result<Json<DepositTransactionResponse>, String> {
        // Withdrawal credentials (32 bytes) - 0x01 prefix for execution address withdrawal
        // Format: 0x01 || 0x00...00 (11 bytes) || execution_address (20 bytes)
        let mut withdrawal_credentials = [0u8; 32];
        withdrawal_credentials[0] = 0x01; // ETH1 withdrawal prefix
        // Bytes 1-11 remain zero
        // Set the last 20 bytes to the withdrawal address (using the same address as the sender)
        let withdrawal_address = Address::from_hex(address).unwrap();
        withdrawal_credentials[12..32].copy_from_slice(withdrawal_address.as_slice());

        //let amount = VALIDATOR_MINIMUM_STAKE;

        let key_paths = KeyPaths::new(state.key_store_path.clone());

        let consenus_priv_key = key_paths.consensus_private_key()?;
        let consensus_pub = consenus_priv_key.public_key();

        let node_priv_key = key_paths.node_private_key()?;
        let node_pub = node_priv_key.public_key();

        let req = DepositRequest {
            node_pubkey: node_pub.clone(),
            consensus_pubkey: consensus_pub.clone(),
            withdrawal_credentials,
            amount,
            node_signature: [0; 64],
            consensus_signature: [0; 96],
            index: 0, // not included in the signature
        };

        let protocol_version_digest = Sha256::hash(&PROTOCOL_VERSION.to_le_bytes());
        let message = req.as_message(protocol_version_digest);

        // Sign with node (ed25519) key
        let node_signature = node_priv_key.sign(&[], &message);
        let node_signature_bytes: [u8; 64] = node_signature
            .as_ref()
            .try_into()
            .expect("ed25519 sig is alway 64 bytes");

        // Sign with consensus (BLS) key
        let consensus_signature = consenus_priv_key.sign(&[], &message);
        let consensus_signature_slice: &[u8] = consensus_signature.as_ref();
        let consensus_signature_bytes: [u8; 96] = consensus_signature_slice
            .try_into()
            .expect("bls sig is alway 96 bytes");

        let node_pubkey_bytes: [u8; 32] = node_pub.to_vec().try_into().expect("Cannot fail");
        let consensus_pubkey_bytes: [u8; 48] =
            consensus_pub.encode().as_ref()[..48].try_into().unwrap();

        let deposit_amount = U256::from(amount) * U256::from(1_000_000_000u64); // gwei to wei

        let deposit_root = compute_deposit_data_root(
            &node_pubkey_bytes,
            &consensus_pubkey_bytes,
            &withdrawal_credentials,
            deposit_amount,
            &node_signature_bytes,
            &consensus_signature_bytes,
        );

        Ok(Json(DepositTransactionResponse {
            node_pubkey: node_pubkey_bytes,
            consensus_pubkey: consensus_pubkey_bytes.to_vec(),
            withdrawal_credentials,
            node_signature: node_signature_bytes.to_vec(),
            consensus_signature: consensus_signature_bytes.to_vec(),
            deposit_data_root: deposit_root,
        }))
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
        let (Some(checkpoint), _) = maybe_checkpoint else {
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
