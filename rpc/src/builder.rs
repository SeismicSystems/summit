use http::{HeaderValue, Method};
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder, ServerConfigBuilder, ServerHandle};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;

pub struct RpcServerBuilder {
    addr: SocketAddr,
    config: ServerConfigBuilder,
    cors_domains: Option<String>,
    request_timeout: Duration,
}

/// The HTTP middleware stack applied to every RPC server: a per-request
/// timeout wrapping an optional CORS layer (see `build`).
type RpcHttpMiddleware = tower::layer::util::Stack<
    TimeoutLayer,
    tower::layer::util::Stack<
        tower::util::Either<CorsLayer, tower::layer::util::Identity>,
        tower::layer::util::Identity,
    >,
>;

pub struct RpcServer {
    inner: jsonrpsee::server::Server<RpcHttpMiddleware>,
}

impl RpcServer {
    pub fn start<M>(self, methods: M) -> ServerHandle
    where
        M: Into<jsonrpsee::server::Methods>,
    {
        self.inner.start(methods)
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        self.inner.local_addr().map_err(Into::into)
    }
}

impl RpcServerBuilder {
    /// Listen on all interfaces (`0.0.0.0`).
    pub fn new(port: u16) -> Self {
        Self::new_with_listen_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }

    /// Listen on 127.0.0.1 only. Used for the admin RPC listener so the
    /// validator-key signing methods (`SummitAdminApi`) can't be reached
    /// from off-host even if the firewall is misconfigured.
    pub fn new_localhost(port: u16) -> Self {
        Self::new_with_listen_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Listen on an explicit address (e.g. from `--rpc-ip`); `new` /
    /// `new_localhost` are the `0.0.0.0` / `127.0.0.1` shorthands. Holds the
    /// canonical server config so the hardening below lives in exactly one place.
    pub fn new_with_listen_addr(listen_addr: IpAddr, port: u16) -> Self {
        Self {
            addr: SocketAddr::new(listen_addr, port),
            // http-only: Summit's RPC is request/response (no subscriptions), so
            // websockets are not needed. jsonrpsee enables websockets with pings
            // disabled by default, and an idle upgraded connection holds its
            // max_connections permit until the client closes; disabling websocket
            // upgrades removes that idle-permit-exhaustion vector entirely.
            // The batch config caps calls per JSON-RPC batch (see `with_batch_limit`).
            config: ServerConfigBuilder::new()
                .http_only()
                .set_batch_request_config(default_batch_config()),
            cors_domains: None,
            request_timeout: Duration::from_secs(crate::DEFAULT_RPC_REQUEST_TIMEOUT_SECS),
        }
    }

    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.config = self.config.max_connections(max);
        self
    }

    pub fn with_max_request_body_size(mut self, max: u32) -> Self {
        self.config = self.config.max_request_body_size(max);
        self
    }

    pub fn with_max_response_body_size(mut self, max: u32) -> Self {
        self.config = self.config.max_response_body_size(max);
        self
    }

    pub fn with_cors(mut self, cors_domains: Option<String>) -> Self {
        self.cors_domains = cors_domains;
        self
    }

    /// Sets the per-request timeout. jsonrpsee takes the `max_connections`
    /// permit before reading the HTTP body and has no body read deadline of its
    /// own, so without a bound a slow or withheld body holds a permit
    /// indefinitely and a few hundred such requests can deny all RPC. This caps
    /// how long any single request may hold its permit, from accept through body
    /// read and method dispatch.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Limits the number of calls in a single JSON-RPC batch. jsonrpsee defaults
    /// to unlimited, which lets one body-size-bounded request fan out into very
    /// many (potentially expensive, finalizer-bound) method calls. `0` disables
    /// batching entirely; any other value caps the batch at that many calls.
    pub fn with_batch_limit(mut self, limit: u32) -> Self {
        self.config = self
            .config
            .set_batch_request_config(batch_config_for(limit));
        self
    }

    pub async fn build(self) -> anyhow::Result<RpcServer> {
        let cors_layer = self
            .cors_domains
            .as_deref()
            .map(create_cors_layer)
            .transpose()?;

        let http_middleware = ServiceBuilder::new()
            .option_layer(cors_layer)
            .layer(TimeoutLayer::new(self.request_timeout));

        let server = ServerBuilder::new()
            .set_config(self.config.build())
            .set_http_middleware(http_middleware)
            .build(self.addr)
            .await?;

        Ok(RpcServer { inner: server })
    }
}

fn default_batch_config() -> BatchRequestConfig {
    batch_config_for(crate::DEFAULT_RPC_MAX_BATCH_SIZE)
}

/// Maps a batch-size limit to a [`BatchRequestConfig`]: `0` disables batching,
/// any other value caps a batch at that many calls.
fn batch_config_for(limit: u32) -> BatchRequestConfig {
    if limit == 0 {
        BatchRequestConfig::Disabled
    } else {
        BatchRequestConfig::Limit(limit)
    }
}

fn create_cors_layer(http_cors_domains: &str) -> anyhow::Result<CorsLayer> {
    let cors = match http_cors_domains.trim() {
        "*" => CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_origin(Any)
            .allow_headers(Any),
        _ => {
            let iter = http_cors_domains.split(',');
            if iter.clone().any(|o| o == "*") {
                anyhow::bail!(
                    "wildcard origin (`*`) cannot be passed as part of a list: {}",
                    http_cors_domains
                );
            }

            let origins = iter
                .map(|domain| {
                    domain
                        .parse::<HeaderValue>()
                        .map_err(|_| anyhow::anyhow!("{} is an invalid header value", domain))
                })
                .collect::<Result<Vec<HeaderValue>, _>>()?;

            let origin = AllowOrigin::list(origins);
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_origin(origin)
                .allow_headers(Any)
        }
    };
    Ok(cors)
}
