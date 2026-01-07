mod api;
mod builder;
mod error;
mod genesis;
mod server;
mod types;

pub use genesis::{PathSender, SummitGenesisRpcServer};
pub use server::SummitRpcServer;
pub use types::*;

pub use api::{SummitApiClient, SummitApiServer, SummitGenesisApiClient, SummitGenesisApiServer};

use commonware_consensus::Block as ConsensusBlock;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_cryptography::Committable;
use commonware_runtime::signal::Signal;
use jsonrpsee::server::ServerHandle;
use std::net::SocketAddr;
use summit_finalizer::FinalizerMailbox;
use tokio_util::sync::CancellationToken;

pub async fn start_rpc_server<
    S: Scheme + Send + Sync + 'static,
    B: ConsensusBlock + Committable + Send + Sync + 'static,
>(
    finalizer_mailbox: FinalizerMailbox<S, B>,
    key_store_path: String,
    port: u16,
    stop_signal: Signal,
) -> anyhow::Result<()> {
    let rpc_impl = SummitRpcServer::new(key_store_path, finalizer_mailbox);

    let methods = rpc_impl.into_rpc();

    let server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let handle = server.start(methods);

    tracing::info!("RPC Server listening on http://0.0.0.0:{port}");

    let sig = stop_signal.await?;
    tracing::info!("RPC server stopped: {sig}");
    handle.stop()?;

    Ok(())
}

/// Starts the RPC server and returns the handle and bound address (useful for testing)
pub async fn start_rpc_server_with_handle<
    S: Scheme + Send + Sync + 'static,
    B: ConsensusBlock + Committable + Send + Sync + 'static,
>(
    finalizer_mailbox: FinalizerMailbox<S, B>,
    key_store_path: String,
    port: u16,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
    let rpc_impl = SummitRpcServer::new(key_store_path, finalizer_mailbox);

    let methods = rpc_impl.into_rpc();

    let server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(methods);

    tracing::info!("RPC Server listening on http://{}", addr);

    Ok((handle, addr))
}

pub async fn start_rpc_server_for_genesis(
    genesis: PathSender,
    key_store_path: String,
    port: u16,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let rpc_impl = SummitGenesisRpcServer::new(key_store_path, genesis);

    let methods = rpc_impl.into_rpc();

    let server = builder::RpcServerBuilder::new(port)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;
    let handle = server.start(methods);

    tracing::info!("Genesis RPC Server listening on http://0.0.0.0:{port}");

    cancel_token.cancelled().await;
    tracing::info!("Genesis RPC server stopped");
    handle.stop()?;

    Ok(())
}

/// Starts the genesis RPC server and returns the handle and bound address (useful for testing)
pub async fn start_rpc_server_for_genesis_with_handle(
    genesis: PathSender,
    key_store_path: String,
    port: u16,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
    let rpc_impl = SummitGenesisRpcServer::new(key_store_path, genesis);

    let methods = rpc_impl.into_rpc();

    let server = builder::RpcServerBuilder::new(port)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(methods);

    tracing::info!("Genesis RPC Server listening on http://{}", addr);

    Ok((handle, addr))
}
