mod api;
#[cfg(feature = "permissioned")]
mod auth;
mod builder;
mod error;
mod genesis;
mod server;
mod types;

pub use genesis::{PathSender, SummitGenesisRpcServer};
pub use server::SummitRpcServer;
pub use types::*;

pub use api::{
    SummitAdminApiClient, SummitAdminApiServer, SummitApiClient, SummitApiServer,
    SummitGenesisApiClient, SummitGenesisApiServer, SummitProofApiClient, SummitProofApiServer,
};
#[cfg(feature = "permissioned")]
pub use api::{SummitPermissionedApiClient, SummitPermissionedApiServer};

use commonware_runtime::signal::Signal;
use jsonrpsee::server::ServerHandle;
use std::net::SocketAddr;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::AtomicBool;
use summit_finalizer::FinalizerMailbox;
use summit_types::Block;
use summit_types::scheme::MultisigScheme;
use tokio_util::sync::CancellationToken;

pub async fn start_rpc_server(
    finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
    key_store_path: String,
    port: u16,
    admin_port: u16,
    stop_signal: Signal,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        finalizer_mailbox,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl.clone()))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let public_handle = public_server.start(public_methods);

    tracing::info!("RPC Server listening on http://0.0.0.0:{port}");

    // Admin RPC: hosts `SummitAdminApi` (validator-key signing methods).
    let admin_methods = SummitAdminApiServer::into_rpc(rpc_impl);

    let admin_server = builder::RpcServerBuilder::new_localhost(admin_port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .build()
        .await?;

    let admin_handle = admin_server.start(admin_methods);

    tracing::info!("Admin RPC Server listening on http://127.0.0.1:{admin_port}");

    let sig = stop_signal.await?;
    tracing::info!("RPC server stopped: {sig}");
    public_handle.stop()?;
    admin_handle.stop()?;

    Ok(())
}

/// Bundle of public + admin RPC handles + bound addresses returned by
/// `start_rpc_server_pair_with_handle` for tests that need both listeners.
pub struct RpcHandles {
    pub public_handle: ServerHandle,
    pub public_addr: SocketAddr,
    pub admin_handle: ServerHandle,
    pub admin_addr: SocketAddr,
}

/// Starts only the public RPC listener and returns its handle/address. Used
/// by tests that don't exercise the admin RPC surface.
pub async fn start_rpc_server_with_handle(
    finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
    key_store_path: String,
    port: u16,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        finalizer_mailbox,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let public_addr = public_server.local_addr()?;
    let public_handle = public_server.start(public_methods);

    tracing::info!("RPC Server listening on http://{}", public_addr);

    Ok((public_handle, public_addr))
}

/// Starts the public RPC listener and the admin RPC listener and returns
/// handles + bound addresses for both. Used by tests that exercise the
/// admin (localhost-only) RPC surface. Passing `0` for either port asks
/// the OS to allocate a free port.
pub async fn start_rpc_server_pair_with_handle(
    finalizer_mailbox: FinalizerMailbox<MultisigScheme, Block>,
    key_store_path: String,
    port: u16,
    admin_port: u16,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<RpcHandles> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        finalizer_mailbox,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl.clone()))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let public_addr = public_server.local_addr()?;
    let public_handle = public_server.start(public_methods);

    let admin_methods = SummitAdminApiServer::into_rpc(rpc_impl);

    let admin_server = builder::RpcServerBuilder::new_localhost(admin_port)
        .with_max_connections(1000)
        .with_max_request_body_size(10 * 1024 * 1024)
        .with_max_response_body_size(10 * 1024 * 1024)
        .build()
        .await?;

    let admin_addr = admin_server.local_addr()?;
    let admin_handle = admin_server.start(admin_methods);

    Ok(RpcHandles {
        public_handle,
        public_addr,
        admin_handle,
        admin_addr,
    })
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
