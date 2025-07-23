use axum::{
    Router,
    body::Bytes,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use commonware_codec::{DecodeExt as _, Encode};
use futures::{SinkExt as _, stream::StreamExt};
use seismicbft_types::{Finalized, Kind, Notarized};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    // Initialize shared state
    let state = Arc::new(AppState::new());

    // Configure CORS
    let cors = CorsLayer::new()
        // Allow any origin - you can restrict this to specific origins
        .allow_origin(Any)
        // Allow specific HTTP methods
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // Allow any headers
        .allow_headers(Any)
        // Allow credentials if needed
        .allow_credentials(false);

    // Build our application with routes
    let app = Router::new()
        // Seed endpoints
        .route("/seed", post(seed_upload))
        // Notarization endpoints
        .route("/notarization", post(notarization_upload))
        .route("/notarization/:query", get(notarization_get))
        // Finalization endpoints
        .route("/finalization", post(finalization_upload))
        .route("/finalization/:query", get(finalization_get))
        .route("/health", get(health))
        // WebSocket endpoint for consensus
        .route("/consensus/ws", get(ws_handler))
        .with_state(state)
        // Add CORS layer
        .layer(cors);

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7777")
        .await
        .unwrap();

    println!("Server running on http://127.0.0.1:7777");

    axum::serve(listener, app).await.unwrap();
}

// State management
struct AppState {
    notarizations: RwLock<Vec<Notarized>>,
    finalizations: RwLock<Vec<Finalized>>,
    // Broadcast channel for consensus messages
    consensus_tx: broadcast::Sender<ConsensusMessage>,
}

impl AppState {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            notarizations: RwLock::new(Vec::new()),
            finalizations: RwLock::new(Vec::new()),
            consensus_tx: tx,
        }
    }
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedData {
    index: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotarizationData {
    index: u64,
    data: Vec<u8>,
    block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FinalizationData {
    index: u64,
    data: Vec<u8>,
    block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockData {
    hash: String,
    index: u64,
    data: Vec<u8>,
}

// Consensus message types
#[derive(Debug, Clone)]
enum ConsensusMessage {
    Seed(Vec<u8>),
    Notarization(Vec<u8>),
    Finalization(Vec<u8>),
}

// Query types
#[derive(Debug, Clone)]
pub enum IndexQuery {
    Latest,
    Index(u64),
}

impl IndexQuery {
    fn serialize(&self) -> String {
        match self {
            IndexQuery::Latest => "latest".to_string(),
            IndexQuery::Index(idx) => idx.to_string(),
        }
    }

    fn from_str(s: &str) -> Result<Self, String> {
        if s == "latest" {
            Ok(IndexQuery::Latest)
        } else {
            s.parse::<u64>()
                .map(IndexQuery::Index)
                .map_err(|_| "Invalid query parameter".to_string())
        }
    }
}

// Handler functions

// Seed handlers
async fn seed_upload(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    // Broadcast to consensus listeners
    // In a real implementation, you'd encode the seed data properly
    let message = ConsensusMessage::Seed(body.to_vec());
    let _ = state.consensus_tx.send(message);

    (StatusCode::CREATED, ())
}

// Notarization handlers
async fn notarization_upload(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    // Create associated block
    let Ok(notarized) = Notarized::decode(&*body) else {
        return (StatusCode::BAD_REQUEST, ());
    };

    let mut notarizations = state.notarizations.write().await;

    notarizations.push(notarized.clone());

    // Broadcast to consensus listeners
    let message = ConsensusMessage::Notarization(body.to_vec());
    let _ = state.consensus_tx.send(message);

    (StatusCode::CREATED, ())
}

async fn notarization_get(
    State(state): State<Arc<AppState>>,
    Path(query): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let query = IndexQuery::from_str(&query)?;
    let notarizations = state.notarizations.read().await;

    match query {
        IndexQuery::Latest => notarizations
            .last()
            .cloned()
            .map(|n| (StatusCode::OK, n.encode()))
            .ok_or(AppError::NotFound),
        IndexQuery::Index(idx) => notarizations
            .iter()
            .find(|n| n.block.height == idx)
            .cloned()
            .map(|n| (StatusCode::OK, n.encode()))
            .ok_or(AppError::NotFound),
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, ())
}

// Finalization handlers
async fn finalization_upload(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    let Ok(finalized) = Finalized::decode(&*body) else {
        return (StatusCode::BAD_REQUEST, ());
    };

    let mut finalizations = state.finalizations.write().await;

    finalizations.push(finalized.clone());

    // Broadcast to consensus listeners
    let message = ConsensusMessage::Finalization(body.to_vec());
    let _ = state.consensus_tx.send(message);

    (StatusCode::CREATED, ())
}

async fn finalization_get(
    State(state): State<Arc<AppState>>,
    Path(query): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let query = IndexQuery::from_str(&query)?;
    let finalizations = state.finalizations.read().await;

    match query {
        IndexQuery::Latest => finalizations
            .last()
            .cloned()
            .map(|f| (StatusCode::OK, f.encode()))
            .ok_or(AppError::NotFound),
        IndexQuery::Index(idx) => finalizations
            .iter()
            .find(|f| f.block.height == idx)
            .cloned()
            .map(|f| (StatusCode::OK, f.encode()))
            .ok_or(AppError::NotFound),
    }
}

// WebSocket handler
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    println!("New listener");
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.consensus_tx.subscribe();

    // Spawn task to handle incoming messages from client
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            // Handle any incoming messages from the client if needed
            if let Ok(WsMessage::Close(_)) = msg {
                break;
            }
        }
    });

    // Send consensus messages to the client
    let send_task = tokio::spawn(async move {
        while let Ok(consensus_msg) = rx.recv().await {
            println!("Handling message");
            let binary_msg = match consensus_msg {
                ConsensusMessage::Seed(data) => {
                    let mut msg = vec![Kind::Seed as u8];
                    msg.extend(&data);
                    msg
                }
                ConsensusMessage::Notarization(data) => {
                    let mut msg = vec![Kind::Notarization as u8];
                    msg.extend_from_slice(&data);
                    msg
                }
                ConsensusMessage::Finalization(data) => {
                    let mut msg = vec![Kind::Finalization as u8];
                    msg.extend_from_slice(&data);
                    msg
                }
            };

            if sender.send(WsMessage::Binary(binary_msg)).await.is_err() {
                break;
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = recv_task => {},
        _ = send_task => {},
    }
}

// Error handling
#[derive(Debug)]
enum AppError {
    NotFound,
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found").into_response(),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
        }
    }
}

impl From<String> for AppError {
    fn from(err: String) -> Self {
        AppError::BadRequest(err)
    }
}

#[allow(dead_code)]
fn notarization_upload_path(base: String) -> String {
    format!("{}/notarization", base)
}

#[allow(dead_code)]
fn notarization_get_path(base: String, query: &IndexQuery) -> String {
    format!("{}/notarization/{}", base, query.serialize())
}

#[allow(dead_code)]
fn finalization_upload_path(base: String) -> String {
    format!("{}/finalization", base)
}

#[allow(dead_code)]
fn finalization_get_path(base: String, query: &IndexQuery) -> String {
    format!("{}/finalization/{}", base, query.serialize())
}

#[allow(dead_code)]
fn listen_path(base: String) -> String {
    format!("{}/consensus/ws", base)
}
