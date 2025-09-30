pub mod routes;
use std::sync::Mutex;

use crate::routes::RpcRoutes;
use futures::channel::oneshot;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct PathSender {
    path: String,
    sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl PathSender {
    pub fn new(path: String, sender: Option<oneshot::Sender<()>>) -> PathSender {
        PathSender {
            path,
            sender: Mutex::new(sender),
        }
    }
}

pub struct RpcState {
    key_path: String,
    genesis: PathSender,
}

impl RpcState {
    pub fn new(key_path: String, genesis: PathSender) -> Self {
        Self { key_path, genesis }
    }
}

pub async fn start_rpc_server(
    key_path: String,
    genesis: PathSender,
    port: u16,
) -> anyhow::Result<()> {
    let state = RpcState::new(key_path, genesis);

    let server = RpcRoutes::mount(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("RPC Server listening on http://0.0.0.0:{port}");

    axum::serve(listener, server).await?;

    Ok(())
}

pub async fn start_rpc_server_for_genesis(
    key_path: String,
    genesis: PathSender,
    port: u16,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let state = RpcState::new(key_path, genesis);

    let server = RpcRoutes::mount_for_genesis(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("Genesis RPC Server listening on http://0.0.0.0:{port}");

    axum::serve(listener, server)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
            println!("Genesis RPC server stopped");
        })
        .await?;
    Ok(())
}
