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
    InvalidGenesis(String),
    IoError(String),
    InvalidKey(String),
    StateProofKeyLimit {
        max: usize,
        actual: usize,
    },
    StateProofCostLimit {
        max: usize,
        actual: usize,
    },
    Internal(String),
    DisabledInObserverMode,
    #[cfg(feature = "permissioned")]
    InvalidAdminAddress(String),
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
            RpcError::InvalidGenesis(msg) => {
                ErrorObjectOwned::owned(2005, "Invalid genesis content", Some(msg))
            }
            RpcError::IoError(msg) => ErrorObjectOwned::owned(2002, "I/O error", Some(msg)),
            RpcError::InvalidKey(msg) => {
                ErrorObjectOwned::owned(3002, "Invalid key descriptor", Some(msg))
            }
            RpcError::StateProofKeyLimit { max, actual } => ErrorObjectOwned::owned(
                3005,
                "State proof key limit exceeded",
                Some(format!("requested {actual} keys, maximum is {max}")),
            ),
            RpcError::StateProofCostLimit { max, actual } => ErrorObjectOwned::owned(
                3006,
                "State proof cost limit exceeded",
                Some(format!("requested cost {actual}, maximum is {max}")),
            ),
            RpcError::Internal(msg) => ErrorObjectOwned::owned(5000, "Internal error", Some(msg)),
            RpcError::DisabledInObserverMode => ErrorObjectOwned::owned(
                4003,
                "Method disabled in observer mode",
                Some(
                    "this node runs with --observer and does not sign with the validator keystore",
                ),
            ),
            #[cfg(feature = "permissioned")]
            RpcError::InvalidAdminAddress(msg) => {
                ErrorObjectOwned::owned(4000, "Invalid admin address", Some(msg))
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
