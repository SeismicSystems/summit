use crate::error::RpcError;
use alloy_primitives::{Address, Signature};
use commonware_utils::from_hex_formatted;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default pause admin address, used when `--pause-admin-address` is not provided.
pub const DEFAULT_PAUSE_ADMIN_ADDRESS_HEX: &str = "0xD9b09DCAe1B5D2fFd36200E12f2617414D5fcC30";

/// Parses a pause admin address from its hex representation.
///
/// Intended to be called once at startup so that a misconfigured address
/// fails fast instead of surfacing on the first `pause`/`unpause` call.
pub fn parse_admin_address(hex: &str) -> Result<Address, RpcError> {
    Address::from_str(hex)
        .map_err(|e| RpcError::InvalidAdminAddress(format!("admin address parse failed: {e}")))
}

pub const TIMESTAMP_WINDOW_SECS: u64 = 30;
pub const DOMAIN: &str = "summit-pause-v1";

pub const ACTION_PAUSE: &str = "pause";
pub const ACTION_UNPAUSE: &str = "unpause";

fn now_secs() -> Result<u64, RpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| RpcError::Internal(format!("system clock before unix epoch: {e}")))
}

pub fn verify_action(
    admin: &Address,
    action: &str,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<(), RpcError> {
    verify_action_with(admin, now_secs()?, action, timestamp_secs, signature_hex)
}

pub(crate) fn verify_action_with(
    expected: &Address,
    now_secs: u64,
    action: &str,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<(), RpcError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > TIMESTAMP_WINDOW_SECS {
        return Err(RpcError::TimestampOutOfWindow);
    }

    let sig_bytes = from_hex_formatted(signature_hex).ok_or(RpcError::InvalidSignature)?;
    let signature = Signature::from_raw(&sig_bytes).map_err(|_| RpcError::InvalidSignature)?;

    let message = format!("{DOMAIN}:{action}:{timestamp_secs}");
    let recovered = signature
        .recover_address_from_msg(message.as_bytes())
        .map_err(|_| RpcError::InvalidSignature)?;

    if &recovered != expected {
        return Err(RpcError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    fn sign(action: &str, timestamp_secs: u64, signer: &PrivateKeySigner) -> String {
        let message = format!("{DOMAIN}:{action}:{timestamp_secs}");
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    #[test]
    fn happy_path_pause() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, now, &signer);

        assert!(verify_action_with(&addr, now, ACTION_PAUSE, now, &sig).is_ok());
    }

    #[test]
    fn happy_path_unpause() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let sig = sign(ACTION_UNPAUSE, now, &signer);

        assert!(verify_action_with(&addr, now, ACTION_UNPAUSE, now, &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_action_replay() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let pause_sig = sign(ACTION_PAUSE, now, &signer);

        let err = verify_action_with(&addr, now, ACTION_UNPAUSE, now, &pause_sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let signed_at = 1_700_000_000;
        let now = signed_at + TIMESTAMP_WINDOW_SECS + 1;
        let sig = sign(ACTION_PAUSE, signed_at, &signer);

        let err = verify_action_with(&addr, now, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_future_timestamp_outside_window() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let signed_at = now + TIMESTAMP_WINDOW_SECS + 1;
        let sig = sign(ACTION_PAUSE, signed_at, &signer);

        let err = verify_action_with(&addr, now, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_signature_from_non_admin() {
        let attacker = PrivateKeySigner::random();
        let admin = PrivateKeySigner::random();
        let now = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, now, &attacker);

        let err = verify_action_with(&admin.address(), now, ACTION_PAUSE, now, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_garbage_signature_hex() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;

        let err = verify_action_with(&addr, now, ACTION_PAUSE, now, "not-hex-at-all").unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let signed_at = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, signed_at, &signer);

        let tampered_ts = signed_at + 5;
        let err =
            verify_action_with(&addr, tampered_ts, ACTION_PAUSE, tampered_ts, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn default_admin_address_parses() {
        assert!(parse_admin_address(DEFAULT_PAUSE_ADMIN_ADDRESS_HEX).is_ok());
    }

    #[test]
    fn rejects_malformed_admin_address() {
        let err = parse_admin_address("0xnot-an-address").unwrap_err();
        assert!(matches!(err, RpcError::InvalidAdminAddress(_)));
    }
}
