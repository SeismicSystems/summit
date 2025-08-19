use summit_rpc::run_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting basic RPC server on port 3030");
    run_server(3030, "~/.seismic/consensus/key.pem".to_string()).await
}