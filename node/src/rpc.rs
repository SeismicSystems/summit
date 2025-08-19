use summit_rpc;

pub struct RPC {
    key_path: String,
    port: u16,
}

impl RPC {
    pub fn new(key_path: String, port: u16) -> Self {
        Self { key_path, port }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        summit_rpc::run_server(self.port, self.key_path).await
    }
}