use http::{HeaderValue, Method};
use jsonrpsee::server::{ServerBuilder, ServerConfigBuilder, ServerHandle};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub struct RpcServerBuilder {
    addr: SocketAddr,
    config: ServerConfigBuilder,
    cors_domains: Option<String>,
}

pub struct RpcServer {
    inner: jsonrpsee::server::Server<
        tower::layer::util::Stack<
            tower::util::Either<CorsLayer, tower::layer::util::Identity>,
            tower::layer::util::Identity,
        >,
    >,
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
            config: ServerConfigBuilder::new(),
            cors_domains: None,
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

    pub async fn build(self) -> anyhow::Result<RpcServer> {
        let cors_layer = self
            .cors_domains
            .as_deref()
            .map(create_cors_layer)
            .transpose()?;

        let http_middleware = ServiceBuilder::new().option_layer(cors_layer);

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
