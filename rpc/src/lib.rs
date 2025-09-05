pub mod routes;
use std::sync::Mutex;

use futures::channel::oneshot;
use tokio::net::TcpListener;

use crate::routes::RpcRoutes;

pub struct PathSender {
    path: String,
    sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl PathSender {
    pub fn new(path: String, sender: Option<oneshot::Sender<()>>) -> PathSender {
        PathSender {
            path: path,
            sender: Mutex::new(sender),
        }
    }
}

pub struct RpcState {
    key_path: String,
    share: PathSender,
    genesis: PathSender,
}

impl RpcState {
    pub fn new(key_path: String, share: PathSender, genesis: PathSender) -> Self {
        Self {
            key_path,
            share,
            genesis,
        }
    }
}

pub async fn start_rpc_server(
    key_path: String,
    share: PathSender,
    genesis: PathSender,
    port: u16,
) -> anyhow::Result<()> {
    let state = RpcState::new(key_path, share, genesis);

    let server = RpcRoutes::mount(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("RPC Server listening on http://0.0.0.0:{port}");

    axum::serve(listener, server).await?;

    Ok(())
}
