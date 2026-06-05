use crate::api::SummitGenesisApiServer;
use crate::error::RpcError;
use crate::types::PublicKeysResponse;
use async_trait::async_trait;
use futures::channel::oneshot;
use jsonrpsee::core::RpcResult;
use std::fs;
use std::sync::Mutex;
use summit_types::KeyPaths;
use summit_types::genesis::Genesis;
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

        // Stage the genesis to a temp file in the same directory, validate it, then
        // atomically rename it into place. This guarantees the target path only ever
        // holds a fully-written, parse-valid genesis: a partial/interrupted write or
        // invalid content never appears there, so startup can treat path presence as
        // a usable genesis without risking a crash loop.
        let tmp_path = path_buf.with_extension("toml.tmp");

        fs::write(&tmp_path, &genesis_content).map_err(|e| {
            RpcError::IoError(format!("Failed to write temporary genesis file: {}", e))
        })?;

        if let Err(e) = Genesis::load_from_file(&tmp_path.to_string_lossy()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(RpcError::InvalidGenesis(format!("rejected genesis content: {e}")).into());
        }

        fs::rename(&tmp_path, &path_buf).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            RpcError::IoError(format!("Failed to install genesis file: {}", e))
        })?;

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
