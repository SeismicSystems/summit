pub mod routes;
use std::sync::Mutex;

use futures::channel::oneshot;
use tokio::net::TcpListener;

use crate::routes::RpcRoutes;

pub struct RpcState {
    key_path: String,
    genesis_path: String,
    genesis_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl RpcState {
    pub fn new(
        key_path: String,
        genesis_path: String,
        genesis_sender: Mutex<Option<oneshot::Sender<()>>>,
    ) -> Self {
        Self {
            key_path,
            genesis_path,
            genesis_sender,
        }
    }
}

pub async fn start_rpc_server(
    genesis_sender: Option<oneshot::Sender<()>>,
    key_path: String,
    genesis_path: String,
    port: u16,
) -> anyhow::Result<()> {
    let state = RpcState::new(key_path, genesis_path, Mutex::new(genesis_sender));

    let server = RpcRoutes::mount(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("RPC Server listening on http://0.0.0.0:{port}");

    axum::serve(listener, server).await?;

    Ok(())
}
