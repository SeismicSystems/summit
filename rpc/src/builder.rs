use http::{HeaderValue, Method};
use jsonrpsee::server::{ServerBuilder, ServerConfigBuilder, ServerHandle};
use std::net::SocketAddr;
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
    pub fn new(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            // http-only: Summit's RPC is request/response (no subscriptions), so
            // websockets are not needed. jsonrpsee enables websockets with pings
            // disabled by default, and an idle upgraded connection holds its
            // max_connections permit until the client closes; disabling websocket
            // upgrades removes that idle-permit-exhaustion vector entirely.
            config: ServerConfigBuilder::new().http_only(),
            cors_domains: None,
            request_timeout: Duration::from_secs(crate::DEFAULT_RPC_REQUEST_TIMEOUT_SECS),
        }
    }

    /// Bind to 127.0.0.1 only. Used for the admin RPC listener so the
    /// validator-key signing methods (`SummitAdminApi`) can't be reached
    /// from off-host even if the firewall is misconfigured.
    pub fn new_localhost(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            // http-only: see `new`. websockets are unused, so disabling upgrades
            // closes the idle-connection permit-exhaustion vector.
            config: ServerConfigBuilder::new().http_only(),
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
