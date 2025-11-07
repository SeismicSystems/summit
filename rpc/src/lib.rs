pub mod routes;
use crate::routes::RpcRoutes;
use commonware_consensus::Block as ConsensusBlock;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_cryptography::Committable;
use commonware_runtime::signal::Signal;
use futures::channel::oneshot;
use std::sync::Mutex;
use summit_finalizer::FinalizerMailbox;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub struct RpcState<S: Scheme, B: ConsensusBlock + Committable> {
    key_path: String,
    finalizer_mailbox: FinalizerMailbox<S, B>,
}

impl<S: Scheme, B: ConsensusBlock + Committable> RpcState<S, B> {
    pub fn new(key_path: String, finalizer_mailbox: FinalizerMailbox<S, B>) -> Self {
        Self {
            key_path,
            finalizer_mailbox,
        }
    }
}

pub async fn start_rpc_server<S: Scheme, B: ConsensusBlock + Committable>(
    finalizer_mailbox: FinalizerMailbox<S, B>,
    key_path: String,
    port: u16,
    stop_signal: Signal,
) -> anyhow::Result<()> {
    let state = RpcState::new(key_path, finalizer_mailbox);

    let server = RpcRoutes::mount(state);

    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;

    println!("RPC Server listening on http://0.0.0.0:{port}");
    axum::serve(listener, server)
        .with_graceful_shutdown(async move {
            let sig = stop_signal.await.unwrap();
            println!("RPC server stopped: {sig}");
        })
        .await?;

    Ok(())
}

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

pub struct GenesisRpcState {
    genesis: PathSender,
}

impl GenesisRpcState {
    pub fn new(genesis: PathSender) -> Self {
        Self { genesis }
    }
}

pub async fn start_rpc_server_for_genesis(
    genesis: PathSender,
    port: u16,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let state = GenesisRpcState::new(genesis);

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
