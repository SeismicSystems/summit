use crate::auth::{AdminAuthLayer, BearerTokenLayer};
use http::{HeaderValue, Method};
use jsonrpsee::server::middleware::rpc::RpcServiceBuilder;
use jsonrpsee::server::{ServerBuilder, ServerConfigBuilder, ServerHandle};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub struct RpcServerBuilder {
    addr: SocketAddr,
    config: ServerConfigBuilder,
    cors_domains: Option<String>,
    admin_token: Option<String>,
}

/// Opaque wrapper that hides the concrete `Server<HttpMiddleware, RpcMiddleware>` type.
/// Callers interact through `start()` and `local_addr()` only.
pub struct RpcServer {
    handle_fn: Box<dyn FnOnce(jsonrpsee::server::Methods) -> ServerHandle + Send>,
    addr: SocketAddr,
}

impl RpcServer {
    pub fn start<M>(self, methods: M) -> ServerHandle
    where
        M: Into<jsonrpsee::server::Methods>,
    {
        (self.handle_fn)(methods.into())
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.addr)
    }
}

impl RpcServerBuilder {
    pub fn new(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            config: ServerConfigBuilder::new(),
            cors_domains: None,
            admin_token: None,
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

    pub fn with_admin_token(mut self, admin_token: Option<String>) -> Self {
        self.admin_token = admin_token;
        self
    }

    pub async fn build(self) -> anyhow::Result<RpcServer> {
        let cors_layer = self
            .cors_domains
            .as_deref()
            .map(create_cors_layer)
            .transpose()?;

        let config = self.config.build();
        let addr = self.addr;

        if let Some(token) = self.admin_token {
            // With admin auth: add BearerTokenLayer (HTTP) + AdminAuthLayer (RPC)
            let http_middleware = ServiceBuilder::new()
                .option_layer(cors_layer)
                .layer(BearerTokenLayer);

            let rpc_middleware = RpcServiceBuilder::new().layer(AdminAuthLayer::new(token));

            let server = ServerBuilder::new()
                .set_config(config)
                .set_http_middleware(http_middleware)
                .set_rpc_middleware(rpc_middleware)
                .build(addr)
                .await?;

            let bound_addr = server.local_addr()?;
            Ok(RpcServer {
                handle_fn: Box::new(move |methods| server.start(methods)),
                addr: bound_addr,
            })
        } else {
            // No admin auth: original middleware stack
            let http_middleware = ServiceBuilder::new().option_layer(cors_layer);

            let server = ServerBuilder::new()
                .set_config(config)
                .set_http_middleware(http_middleware)
                .build(addr)
                .await?;

            let bound_addr = server.local_addr()?;
            Ok(RpcServer {
                handle_fn: Box::new(move |methods| server.start(methods)),
                addr: bound_addr,
            })
        }
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
