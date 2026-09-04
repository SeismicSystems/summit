use crate::error::RpcError;
use alloy_primitives::{Address, Signature};
use commonware_formatting::from_hex;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// TODO: replace with the real admin address before production use.
pub const PAUSE_ADMIN_ADDRESS_HEX: &str = "0xD9b09DCAe1B5D2fFd36200E12f2617414D5fcC30";

pub const TIMESTAMP_WINDOW_SECS: u64 = 30;
pub const DOMAIN: &str = "summit-pause-v1";

pub const ACTION_PAUSE: &str = "pause";
pub const ACTION_UNPAUSE: &str = "unpause";

fn admin_address() -> Result<Address, RpcError> {
    Address::from_str(PAUSE_ADMIN_ADDRESS_HEX)
        .map_err(|e| RpcError::InvalidAdminAddress(format!("admin address parse failed: {e}")))
}

fn now_secs() -> Result<u64, RpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| RpcError::Internal(format!("system clock before unix epoch: {e}")))
}

/// `scope` is the hex of the deployment-bound pause domain
/// (`summit_types::pause_signature_domain` over the EL genesis hash +
/// namespace). Binding it into the signed message scopes the authorization to
/// this deployment, so a pause/unpause signature cannot be replayed against
/// another network that trusts the same admin key.
pub fn verify_action(
    scope: &str,
    action: &str,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<(), RpcError> {
    let admin = admin_address()?;
    verify_action_with(
        &admin,
        now_secs()?,
        scope,
        action,
        timestamp_secs,
        signature_hex,
    )
}

pub(crate) fn verify_action_with(
    expected: &Address,
    now_secs: u64,
    scope: &str,
    action: &str,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<(), RpcError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > TIMESTAMP_WINDOW_SECS {
        return Err(RpcError::TimestampOutOfWindow);
    }

    let sig_bytes = from_hex(signature_hex).ok_or(RpcError::InvalidSignature)?;
    let signature = Signature::from_raw(&sig_bytes).map_err(|_| RpcError::InvalidSignature)?;

    let message = format!("{DOMAIN}:{scope}:{action}:{timestamp_secs}");
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
    use summit_types::pause_signature_domain;

    // Two deployments that share an admin key but differ in their chain
    // identity (genesis hash and/or namespace).
    fn scope_a() -> String {
        alloy_primitives::hex::encode(pause_signature_domain([0x11; 32], b"net-a"))
    }
    fn scope_b() -> String {
        alloy_primitives::hex::encode(pause_signature_domain([0x22; 32], b"net-b"))
    }

    fn sign(scope: &str, action: &str, timestamp_secs: u64, signer: &PrivateKeySigner) -> String {
        let message = format!("{DOMAIN}:{scope}:{action}:{timestamp_secs}");
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    #[test]
    fn happy_path_pause() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_PAUSE, now, &signer);

        assert!(verify_action_with(&addr, now, &scope, ACTION_PAUSE, now, &sig).is_ok());
    }

    #[test]
    fn happy_path_unpause() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_UNPAUSE, now, &signer);

        assert!(verify_action_with(&addr, now, &scope, ACTION_UNPAUSE, now, &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_action_replay() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let scope = scope_a();
        let pause_sig = sign(&scope, ACTION_PAUSE, now, &signer);

        let err =
            verify_action_with(&addr, now, &scope, ACTION_UNPAUSE, now, &pause_sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    /// A pause/unpause signature minted for deployment A must not authorize the
    /// same action on deployment B, even though both trust the same admin key.
    #[test]
    fn rejects_other_deployment_scope() {
        let admin = PrivateKeySigner::random();
        let addr = admin.address();
        let now = 1_700_000_000;

        // Admin legitimately signs a pause for deployment A.
        let sig = sign(&scope_a(), ACTION_PAUSE, now, &admin);

        // Deployment A accepts it...
        assert!(verify_action_with(&addr, now, &scope_a(), ACTION_PAUSE, now, &sig).is_ok());
        // ...but deployment B rejects the very same signature.
        let err = verify_action_with(&addr, now, &scope_b(), ACTION_PAUSE, now, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let signed_at = 1_700_000_000;
        let now = signed_at + TIMESTAMP_WINDOW_SECS + 1;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_PAUSE, signed_at, &signer);

        let err =
            verify_action_with(&addr, now, &scope, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_future_timestamp_outside_window() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;
        let signed_at = now + TIMESTAMP_WINDOW_SECS + 1;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_PAUSE, signed_at, &signer);

        let err =
            verify_action_with(&addr, now, &scope, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_wrong_signer() {
        let attacker = PrivateKeySigner::random();
        let admin = PrivateKeySigner::random();
        let now = 1_700_000_000;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_PAUSE, now, &attacker);

        let err =
            verify_action_with(&admin.address(), now, &scope, ACTION_PAUSE, now, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_garbage_signature_hex() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let now = 1_700_000_000;

        let err = verify_action_with(&addr, now, &scope_a(), ACTION_PAUSE, now, "not-hex-at-all")
            .unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let signed_at = 1_700_000_000;
        let scope = scope_a();
        let sig = sign(&scope, ACTION_PAUSE, signed_at, &signer);

        let tampered_ts = signed_at + 5;
        let err = verify_action_with(&addr, tampered_ts, &scope, ACTION_PAUSE, tampered_ts, &sig)
            .unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn placeholder_admin_address_parses() {
        assert!(admin_address().is_ok());
    }
}
