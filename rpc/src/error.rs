use jsonrpsee::types::ErrorObjectOwned;

/// Errors summit's RPC methods return, each with its own error code.
///
/// JSON-RPC 2.0 reserves -32768 to -32000 for protocol errors, which jsonrpsee
/// emits itself (e.g. -32601 method not found, -32602 invalid params). Our
/// codes are positive, in the space the spec leaves to applications, and are
/// grouped by what they concern:
///
/// - 1xxx: the node's keystore.
/// - 2xxx: chain data and files: checkpoints, finalized headers, epochs,
///   genesis, I/O.
/// - 3xxx: validators, deposits, withdrawals and state proofs.
/// - 4xxx: access control: this caller may not do this on this node (pause
///   authorization, observer mode, a bound withdrawal address).
/// - 5xxx: internal errors.
///
/// Callers should match on the code, not the message; `data` carries details.
///
/// Each variant's code is its discriminant, so the compiler rejects two
/// variants with the same code (E0081). Keep the variants in code order.
#[repr(i32)]
pub enum RpcError {
    KeyStoreError(String) = 1000,
    CheckpointNotFound = 2000,
    GenesisPathError(String) = 2001,
    IoError(String) = 2002,
    FinalizedHeaderNotFound = 2003,
    EpochNotFound = 2004,
    InvalidGenesis(String) = 2005,
    ValidatorNotFound = 3000,
    InvalidPublicKey(String) = 3001,
    InvalidKey(String) = 3002,
    DepositNotFound = 3003,
    WithdrawalNotFound = 3004,
    StateProofKeyLimit {
        max: usize,
        actual: usize,
    } = 3005,
    StateProofCostLimit {
        max: usize,
        actual: usize,
    } = 3006,
    StateProofBusy {
        max: usize,
    } = 3007,
    InvalidWithdrawalAddress(String) = 3008,
    #[cfg(feature = "permissioned")]
    InvalidAdminAddress(String) = 4000,
    #[cfg(feature = "permissioned")]
    TimestampOutOfWindow = 4001,
    #[cfg(feature = "permissioned")]
    InvalidSignature = 4002,
    DisabledInObserverMode = 4003,
    /// Signature is valid and the signer is known, but its role does not
    /// permit the requested action.
    #[cfg(feature = "permissioned")]
    Forbidden = 4004,
    WithdrawalAddressBound(crate::WithdrawalAddress) = 4005,
    Internal(String) = 5000,
}

impl RpcError {
    /// The JSON-RPC error code: the variant's discriminant.
    pub fn code(&self) -> i32 {
        // SAFETY: `RpcError` is `#[repr(i32)]`, so every variant is laid out
        // as a `#[repr(C)]` union of `#[repr(C)]` structs whose first field is
        // the `i32` discriminant. Reading an `i32` through a pointer to the
        // enum reads that discriminant:
        // https://doc.rust-lang.org/reference/items/enumerations.html#pointer-casting
        unsafe { *(self as *const Self as *const i32) }
    }
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        let code = err.code();
        match err {
            RpcError::KeyStoreError(msg) => {
                ErrorObjectOwned::owned(code, "Keystore error", Some(msg))
            }
            RpcError::CheckpointNotFound => {
                ErrorObjectOwned::owned(code, "Checkpoint not found", None::<()>)
            }
            RpcError::GenesisPathError(msg) => {
                ErrorObjectOwned::owned(code, "Invalid genesis path", Some(msg))
            }
            RpcError::IoError(msg) => ErrorObjectOwned::owned(code, "I/O error", Some(msg)),
            RpcError::FinalizedHeaderNotFound => {
                ErrorObjectOwned::owned(code, "Finalized header not found", None::<()>)
            }
            RpcError::EpochNotFound => ErrorObjectOwned::owned(code, "Epoch not found", None::<()>),
            RpcError::InvalidGenesis(msg) => {
                ErrorObjectOwned::owned(code, "Invalid genesis content", Some(msg))
            }
            RpcError::ValidatorNotFound => {
                ErrorObjectOwned::owned(code, "Validator not found", None::<()>)
            }
            RpcError::InvalidPublicKey(msg) => {
                ErrorObjectOwned::owned(code, "Invalid public key", Some(msg))
            }
            RpcError::InvalidKey(msg) => {
                ErrorObjectOwned::owned(code, "Invalid key descriptor", Some(msg))
            }
            RpcError::DepositNotFound => {
                ErrorObjectOwned::owned(code, "Deposit not found", None::<()>)
            }
            RpcError::WithdrawalNotFound => {
                ErrorObjectOwned::owned(code, "Withdrawal not found", None::<()>)
            }
            RpcError::StateProofKeyLimit { max, actual } => ErrorObjectOwned::owned(
                code,
                "State proof key limit exceeded",
                Some(format!("requested {actual} keys, maximum is {max}")),
            ),
            RpcError::StateProofCostLimit { max, actual } => ErrorObjectOwned::owned(
                code,
                "State proof cost limit exceeded",
                Some(format!("requested cost {actual}, maximum is {max}")),
            ),
            RpcError::StateProofBusy { max } => ErrorObjectOwned::owned(
                code,
                "State proof generation at capacity",
                Some(format!(
                    "at the limit of {max} concurrent state proof requests; retry shortly"
                )),
            ),
            RpcError::InvalidWithdrawalAddress(msg) => {
                ErrorObjectOwned::owned(code, "Invalid withdrawal address", Some(msg))
            }
            #[cfg(feature = "permissioned")]
            RpcError::InvalidAdminAddress(msg) => {
                ErrorObjectOwned::owned(code, "Invalid admin address", Some(msg))
            }
            #[cfg(feature = "permissioned")]
            RpcError::TimestampOutOfWindow => {
                ErrorObjectOwned::owned(code, "Timestamp outside allowed window", None::<()>)
            }
            #[cfg(feature = "permissioned")]
            RpcError::InvalidSignature => {
                ErrorObjectOwned::owned(code, "Invalid signature", None::<()>)
            }
            RpcError::DisabledInObserverMode => ErrorObjectOwned::owned(
                code,
                "Method disabled in observer mode",
                Some(
                    "this node runs with --observer and does not sign with the validator keystore",
                ),
            ),
            #[cfg(feature = "permissioned")]
            RpcError::Forbidden => {
                ErrorObjectOwned::owned(code, "Signer not authorized for this action", None::<()>)
            }
            RpcError::WithdrawalAddressBound(bound) => ErrorObjectOwned::owned(
                code,
                "Withdrawal address already bound",
                Some(format!(
                    "this node's withdrawal address is bound to {bound}; it signs deposits only for that address"
                )),
            ),
            RpcError::Internal(msg) => ErrorObjectOwned::owned(code, "Internal error", Some(msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `code()` reads the discriminant through a pointer cast; check it on
    /// unit, tuple and struct variants.
    #[test]
    fn code_is_the_discriminant() {
        assert_eq!(RpcError::CheckpointNotFound.code(), 2000);
        assert_eq!(RpcError::Internal(String::from("x")).code(), 5000);
        assert_eq!(RpcError::StateProofBusy { max: 7 }.code(), 3007);
        let bound = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        let err = ErrorObjectOwned::from(RpcError::WithdrawalAddressBound(bound));
        assert_eq!(err.code(), 4005);
    }
}
