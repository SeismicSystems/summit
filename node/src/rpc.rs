// use summit_rpc;
// use tokio::sync::oneshot;

// pub struct Rpc {
//     key_path: String,
//     genesis_path: String,
//     port: u16,
//     genesis_sender: Option<oneshot::Sender<()>>,
// }

// impl Rpc {
//     pub fn new(key_path: String, genesis_path: String, port: u16) -> Self {
//         Self {
//             key_path,
//             genesis_path,
//             port,
//             genesis_sender: None,
//         }
//     }

//     pub fn with_genesis_sender(mut self, sender: oneshot::Sender<()>) -> Self {
//         self.genesis_sender = Some(sender);
//         self
//     }

//     pub async fn start(self) -> anyhow::Result<()> {
//         summit_rpc::run_server(self.port, self.key_path, self.genesis_path, self.genesis_sender).await
//     }
// }
