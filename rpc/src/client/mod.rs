//! Summit RPC client
//!
//! # Example
//!
//! ```no_run
//! use summit_rpc::client::{Client, SummitClient, NodeClient, GenesisClient};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = Client::new("http://localhost:8080");
//!
//!     // Check server mode
//!     let mode = client.server_mode().await.unwrap();
//!
//!     // Use node-specific methods
//!     let height = client.get_latest_height().await.unwrap();
//!
//!     // Use genesis-specific methods
//!     let genesis = std::fs::read_to_string("genesis.json").unwrap();
//!     client.send_genesis(genesis).await.unwrap();
//! }
//! ```

mod client;
mod traits;
mod types;

pub use client::*;
pub use traits::*;
pub use types::*;

// Re-export API response types from summit_types for convenience
pub use summit_types::rpc::{
    CheckpointInfoRes, CheckpointRes, DepositTransactionResponse, PublicKeysResponse, ServerMode,
    ServerModeResponse,
};
