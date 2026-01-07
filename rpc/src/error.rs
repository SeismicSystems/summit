use jsonrpsee::types::ErrorObjectOwned;

pub enum RpcError {
    KeyStoreError(String),
    CheckpointNotFound,
    ValidatorNotFound,
    InvalidPublicKey(String),
    GenesisPathError(String),
    IoError(String),
    Internal(String),
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::KeyStoreError(msg) => {
                ErrorObjectOwned::owned(1000, "Keystore error", Some(msg))
            }
            RpcError::CheckpointNotFound => {
                ErrorObjectOwned::owned(2000, "Checkpoint not found", None::<()>)
            }
            RpcError::ValidatorNotFound => {
                ErrorObjectOwned::owned(3000, "Validator not found", None::<()>)
            }
            RpcError::InvalidPublicKey(msg) => {
                ErrorObjectOwned::owned(3001, "Invalid public key", Some(msg))
            }
            RpcError::GenesisPathError(msg) => {
                ErrorObjectOwned::owned(2001, "Invalid genesis path", Some(msg))
            }
            RpcError::IoError(msg) => ErrorObjectOwned::owned(2002, "I/O error", Some(msg)),
            RpcError::Internal(msg) => ErrorObjectOwned::owned(5000, "Internal error", Some(msg)),
        }
    }
}
