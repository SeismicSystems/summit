use jsonrpsee::types::ErrorObjectOwned;

pub enum RpcError {
    KeyStoreError(String),
    CheckpointNotFound,
    FinalizedHeaderNotFound,
    ValidatorNotFound,
    DepositNotFound,
    WithdrawalNotFound,
    EpochNotFound,
    InvalidPublicKey(String),
    GenesisPathError(String),
    IoError(String),
    InvalidKey(String),
    Internal(String),
    #[cfg(feature = "permissioned")]
    InvalidAdminKey(String),
    #[cfg(feature = "permissioned")]
    TimestampOutOfWindow,
    #[cfg(feature = "permissioned")]
    InvalidSignature,
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
            RpcError::FinalizedHeaderNotFound => {
                ErrorObjectOwned::owned(2003, "Finalized header not found", None::<()>)
            }
            RpcError::EpochNotFound => ErrorObjectOwned::owned(2004, "Epoch not found", None::<()>),
            RpcError::ValidatorNotFound => {
                ErrorObjectOwned::owned(3000, "Validator not found", None::<()>)
            }
            RpcError::DepositNotFound => {
                ErrorObjectOwned::owned(3003, "Deposit not found", None::<()>)
            }
            RpcError::WithdrawalNotFound => {
                ErrorObjectOwned::owned(3004, "Withdrawal not found", None::<()>)
            }
            RpcError::InvalidPublicKey(msg) => {
                ErrorObjectOwned::owned(3001, "Invalid public key", Some(msg))
            }
            RpcError::GenesisPathError(msg) => {
                ErrorObjectOwned::owned(2001, "Invalid genesis path", Some(msg))
            }
            RpcError::IoError(msg) => ErrorObjectOwned::owned(2002, "I/O error", Some(msg)),
            RpcError::InvalidKey(msg) => {
                ErrorObjectOwned::owned(3002, "Invalid key descriptor", Some(msg))
            }
            RpcError::Internal(msg) => ErrorObjectOwned::owned(5000, "Internal error", Some(msg)),
            #[cfg(feature = "permissioned")]
            RpcError::InvalidAdminKey(msg) => {
                ErrorObjectOwned::owned(4000, "Invalid admin public key", Some(msg))
            }
            #[cfg(feature = "permissioned")]
            RpcError::TimestampOutOfWindow => {
                ErrorObjectOwned::owned(4001, "Timestamp outside allowed window", None::<()>)
            }
            #[cfg(feature = "permissioned")]
            RpcError::InvalidSignature => {
                ErrorObjectOwned::owned(4002, "Invalid signature", None::<()>)
            }
        }
    }
}
