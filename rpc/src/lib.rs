mod api;
#[cfg(feature = "permissioned")]
mod auth;
mod builder;
mod error;
mod genesis;
mod server;
mod types;

pub use genesis::{PathSender, SummitGenesisRpcServer};
pub use server::{MAX_CONCURRENT_STATE_PROOFS, SummitRpcServer};
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
use summit_types::consensus_state_query::ConsensusStateQuery;
use summit_types::scheme::MultisigScheme;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_RPC_BODY_LIMIT_BYTES: u32 = 50 * 1024 * 1024;

/// Default per-request timeout, in seconds. Bounds how long a single HTTP
/// request may hold a connection permit (jsonrpsee acquires the permit before
/// reading the body and has no body read deadline of its own).
pub const DEFAULT_RPC_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default maximum number of calls in a single JSON-RPC batch. jsonrpsee
/// defaults to unlimited; this bounds batch fan-out (`0` would disable
/// batching).
pub const DEFAULT_RPC_MAX_BATCH_SIZE: u32 = 50;

#[derive(Debug, Clone, Copy)]
pub struct RpcBodyLimits {
    pub max_request_body_size: u32,
    pub max_response_body_size: u32,
    /// Per-request timeout (accept through body read and method dispatch).
    pub request_timeout: std::time::Duration,
    /// Maximum calls per JSON-RPC batch (`0` disables batching).
    pub max_batch_size: u32,
}

impl Default for RpcBodyLimits {
    fn default() -> Self {
        Self {
            max_request_body_size: DEFAULT_RPC_BODY_LIMIT_BYTES,
            max_response_body_size: DEFAULT_RPC_BODY_LIMIT_BYTES,
            request_timeout: std::time::Duration::from_secs(DEFAULT_RPC_REQUEST_TIMEOUT_SECS),
            max_batch_size: DEFAULT_RPC_MAX_BATCH_SIZE,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    state_query: ConsensusStateQuery<MultisigScheme>,
    key_store_path: String,
    genesis_hash: [u8; 32],
    namespace: Vec<u8>,
    port: u16,
    admin_port: u16,
    body_limits: RpcBodyLimits,
    stop_signal: Signal,
    observer_node_key: Option<String>,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        state_query,
        genesis_hash,
        &namespace,
        observer_node_key,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl.clone()))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(body_limits.max_request_body_size)
        .with_max_response_body_size(body_limits.max_response_body_size)
        .with_request_timeout(body_limits.request_timeout)
        .with_batch_limit(body_limits.max_batch_size)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let public_handle = public_server.start(public_methods);

    tracing::info!("RPC Server listening on http://0.0.0.0:{port}");

    // Admin RPC: hosts `SummitAdminApi` (validator-key signing methods).
    let admin_methods = SummitAdminApiServer::into_rpc(rpc_impl);

    let admin_server = builder::RpcServerBuilder::new_localhost(admin_port)
        .with_max_connections(1000)
        .with_max_request_body_size(body_limits.max_request_body_size)
        .with_max_response_body_size(body_limits.max_response_body_size)
        .with_request_timeout(body_limits.request_timeout)
        .with_batch_limit(body_limits.max_batch_size)
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
    state_query: ConsensusStateQuery<MultisigScheme>,
    key_store_path: String,
    genesis_hash: [u8; 32],
    namespace: Vec<u8>,
    port: u16,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
    start_rpc_server_with_handle_and_batch_limit(
        state_query,
        key_store_path,
        genesis_hash,
        namespace,
        port,
        DEFAULT_RPC_MAX_BATCH_SIZE,
        #[cfg(feature = "permissioned")]
        paused,
    )
    .await
}

/// Like [`start_rpc_server_with_handle`] but with an explicit JSON-RPC batch
/// limit, so tests can exercise a custom `--rpc-max-batch-size` value (and `0`,
/// which disables batching entirely).
pub async fn start_rpc_server_with_handle_and_batch_limit(
    state_query: ConsensusStateQuery<MultisigScheme>,
    key_store_path: String,
    genesis_hash: [u8; 32],
    namespace: Vec<u8>,
    port: u16,
    max_batch_size: u32,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        state_query,
        genesis_hash,
        &namespace,
        // This helper is only used by tests of validator-mode behavior, so
        // observer mode is irrelevant here.
        None,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_max_response_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_batch_limit(max_batch_size)
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
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server_pair_with_handle(
    state_query: ConsensusStateQuery<MultisigScheme>,
    key_store_path: String,
    genesis_hash: [u8; 32],
    namespace: Vec<u8>,
    port: u16,
    admin_port: u16,
    observer_node_key: Option<String>,
    #[cfg(feature = "permissioned")] paused: Arc<AtomicBool>,
) -> anyhow::Result<RpcHandles> {
    let rpc_impl = SummitRpcServer::new(
        key_store_path,
        state_query,
        genesis_hash,
        &namespace,
        observer_node_key,
        #[cfg(feature = "permissioned")]
        paused,
    );

    let mut public_methods = SummitApiServer::into_rpc(rpc_impl.clone());
    public_methods.merge(SummitProofApiServer::into_rpc(rpc_impl.clone()))?;
    #[cfg(feature = "permissioned")]
    public_methods.merge(SummitPermissionedApiServer::into_rpc(rpc_impl.clone()))?;

    let public_server = builder::RpcServerBuilder::new(port)
        .with_max_connections(1000)
        .with_max_request_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_max_response_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_cors(Some("*".to_string()))
        .build()
        .await?;

    let public_addr = public_server.local_addr()?;
    let public_handle = public_server.start(public_methods);

    let admin_methods = SummitAdminApiServer::into_rpc(rpc_impl);

    let admin_server = builder::RpcServerBuilder::new_localhost(admin_port)
        .with_max_connections(1000)
        .with_max_request_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_max_response_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
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
    body_limits: RpcBodyLimits,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let rpc_impl = SummitGenesisRpcServer::new(key_store_path, genesis);

    let methods = rpc_impl.into_rpc();

    // First-boot genesis provisioning installs the chain's authoritative
    // identity (namespace, execution genesis hash, validator committee,
    // peer addresses, initial protocol params). Bind to loopback so a
    // remote caller cannot install genesis on this node before startup
    // loads it.
    let server = builder::RpcServerBuilder::new_localhost(port)
        .with_max_request_body_size(body_limits.max_request_body_size)
        .with_max_response_body_size(body_limits.max_response_body_size)
        .with_request_timeout(body_limits.request_timeout)
        .with_batch_limit(body_limits.max_batch_size)
        .build()
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(methods);

    tracing::info!("Genesis RPC Server listening on http://{}", addr);

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

    // See note on the production variant: localhost-only binding for the
    // first-boot genesis writer.
    let server = builder::RpcServerBuilder::new_localhost(port)
        .with_max_request_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .with_max_response_body_size(DEFAULT_RPC_BODY_LIMIT_BYTES)
        .build()
        .await?;
    let addr = server.local_addr()?;
    let handle = server.start(methods);

    tracing::info!("Genesis RPC Server listening on http://{}", addr);

    Ok((handle, addr))
}
