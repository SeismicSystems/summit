use jsonrpsee::server::{Server, ServerBuilder, ServerConfigBuilder};
use std::net::SocketAddr;

pub struct RpcServerBuilder {
    addr: SocketAddr,
    config: ServerConfigBuilder,
}

impl RpcServerBuilder {
    pub fn new(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            config: ServerConfigBuilder::new(),
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

    pub async fn build(self) -> anyhow::Result<Server> {
        let server = ServerBuilder::new()
            .set_config(self.config.build())
            .build(self.addr)
            .await?;
        Ok(server)
    }
}
