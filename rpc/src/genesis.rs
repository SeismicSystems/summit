use crate::api::SummitGenesisApiServer;
use crate::error::RpcError;
use crate::types::PublicKeysResponse;
use async_trait::async_trait;
use futures::channel::oneshot;
use jsonrpsee::core::RpcResult;
use std::fs;
use std::sync::Mutex;
use summit_types::KeyPaths;
use summit_types::utils::get_expanded_path;

pub struct PathSender {
    pub path: String,
    pub sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl PathSender {
    pub fn new(path: String, sender: Option<oneshot::Sender<()>>) -> PathSender {
        PathSender {
            path,
            sender: Mutex::new(sender),
        }
    }
}

pub struct SummitGenesisRpcServer {
    key_store_path: String,
    genesis: PathSender,
}

impl SummitGenesisRpcServer {
    pub fn new(key_store_path: String, genesis: PathSender) -> Self {
        Self {
            key_store_path,
            genesis,
        }
    }
}

#[async_trait]
impl SummitGenesisApiServer for SummitGenesisRpcServer {
    async fn health(&self) -> RpcResult<String> {
        Ok("Ok".to_string())
    }

    async fn get_public_keys(&self) -> RpcResult<PublicKeysResponse> {
        let key_paths = KeyPaths::new(self.key_store_path.clone());

        let node = key_paths.node_public_key().map_err(|e| {
            RpcError::KeyStoreError(format!("Failed to read node public key: {}", e))
        })?;

        let consensus = key_paths.consensus_public_key().map_err(|e| {
            RpcError::KeyStoreError(format!("Failed to read consensus public key: {}", e))
        })?;

        Ok(PublicKeysResponse { node, consensus })
    }

    async fn send_genesis(&self, genesis_content: String) -> RpcResult<String> {
        let path_buf = get_expanded_path(&self.genesis.path)
            .map_err(|e| RpcError::GenesisPathError(format!("Invalid genesis path: {}", e)))?;

        if let Some(parent) = path_buf.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| RpcError::IoError(format!("Failed to create directory: {}", e)))?;
        }

        fs::write(&path_buf, &genesis_content)
            .map_err(|e| RpcError::IoError(format!("Failed to write genesis file: {}", e)))?;

        if let Some(sender) = self.genesis.sender.lock().unwrap().take() {
            let _ = sender.send(());
            Ok(format!(
                "Genesis file written at location {} and node notified",
                self.genesis.path
            ))
        } else {
            Ok(format!(
                "Genesis file written at location {} (no notification needed)",
                self.genesis.path
            ))
        }
    }
}
