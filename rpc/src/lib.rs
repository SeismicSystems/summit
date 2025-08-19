use axum::{routing::{get, post}, Router, extract::State, Json};
use tokio::net::TcpListener;
use commonware_codec::extensions::DecodeExt;
use commonware_cryptography::Signer;
use commonware_utils::from_hex_formatted;
use summit_types::PrivateKey;

#[derive(Clone)]
pub struct RPCState {
    key_path: String,
    genesis_sender: Option<std::sync::Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>>,
}

#[derive(serde::Deserialize)]
pub struct GenesisRequest {
    pub genesis_data: String,
}

pub async fn send_genesis(State(state): State<RPCState>, Json(payload): Json<GenesisRequest>) -> Result<String, String> {
    // Write genesis to file 
    let genesis_path = dirs::home_dir()
        .ok_or("Unable to determine home directory")?
        .join(".seismic/consensus/genesis.toml");
    
    
    if let Some(parent) = genesis_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    
    std::fs::write(&genesis_path, &payload.genesis_data)
        .map_err(|e| format!("Failed to write genesis file: {}", e))?;
    
    // Signal that genesis is ready
    if let Some(sender_arc) = &state.genesis_sender {
        if let Ok(mut sender_opt) = sender_arc.lock() {
            if let Some(sender) = sender_opt.take() {
                let _ = sender.send(());
                return Ok("Genesis file written and node notified".to_string());
            }
        }
    }
    
    Ok("Genesis file written (no notification needed)".to_string())
}

pub async fn health_check() -> &'static str {
    "OK"
}

pub async fn get_public_key(State(state): State<RPCState>) -> Result<String, String> {
    match read_ed_key_from_path(state.key_path) {
        Ok(private_key) => Ok(private_key.public_key().to_string()),
        Err(e) => Err(format!("Failed to read public key: {}", e)),
    }
}

fn read_ed_key_from_path(key_path: String) -> anyhow::Result<PrivateKey> {
    let path = if key_path.starts_with("~/") {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Unable to determine home directory"))?;
        home.join(&key_path[2..])
    } else {
        std::path::PathBuf::from(key_path)
    };
    let encoded_pk = std::fs::read_to_string(path)?;
    
    let key = from_hex_formatted(&encoded_pk)
        .ok_or_else(|| anyhow::anyhow!("Invalid hex format"))?;
    let pk = PrivateKey::decode(&*key)?;
    
    Ok(pk)
}

pub fn create_router(state: RPCState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/get_public_key", get(get_public_key))
        .route("/send_genesis", post(send_genesis))
        .with_state(state)
}

pub async fn run_server(port: u16, key_path: String, genesis_sender: Option<tokio::sync::oneshot::Sender<()>>) -> anyhow::Result<()> {
    let genesis_sender = genesis_sender.map(|s| std::sync::Arc::new(std::sync::Mutex::new(Some(s))));
    let state = RPCState { key_path, genesis_sender };
    let router = create_router(state);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    println!("RPC Server listening on http://0.0.0.0:{}", port);
    println!("Available endpoints:");
    println!("  GET /health - Health check");
    println!("  GET /get_public_key - Get node's public key");

    axum::serve(listener, router).await?;

    Ok(())
}