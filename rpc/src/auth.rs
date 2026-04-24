use crate::error::RpcError;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::Verifier as _;
use commonware_utils::from_hex_formatted;
use std::time::{SystemTime, UNIX_EPOCH};
use summit_types::{PublicKey, Signature};

// TODO: replace with the real admin pubkey before production use.
pub const PAUSE_ADMIN_PUBKEY_HEX: &str = "0xD9b09DCAe1B5D2fFd36200E12f2617414D5fcC30";

pub const TIMESTAMP_WINDOW_SECS: u64 = 30;
pub const DOMAIN: &str = "summit-pause-v1";

pub const ACTION_PAUSE: &str = "pause";
pub const ACTION_UNPAUSE: &str = "unpause";

fn admin_pubkey() -> Result<PublicKey, RpcError> {
    let bytes = from_hex_formatted(PAUSE_ADMIN_PUBKEY_HEX)
        .ok_or_else(|| RpcError::InvalidAdminKey("malformed hex in admin pubkey const".into()))?;
    PublicKey::decode(&*bytes)
        .map_err(|e| RpcError::InvalidAdminKey(format!("admin pubkey decode failed: {e}")))
}

fn now_secs() -> Result<u64, RpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| RpcError::Internal(format!("system clock before unix epoch: {e}")))
}

pub fn verify_action(
    action: &str,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<(), RpcError> {
    let pubkey = admin_pubkey()?;
    verify_action_with(&pubkey, now_secs()?, action, timestamp_secs, signature_hex)
}

pub(crate) fn verify_action_with(
    pubkey: &PublicKey,
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
    let signature = Signature::decode(&*sig_bytes).map_err(|_| RpcError::InvalidSignature)?;

    let message = format!("{DOMAIN}:{action}:{timestamp_secs}");
    if !pubkey.verify(&[], message.as_bytes(), &signature) {
        return Err(RpcError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer as _;
    use commonware_math::algebra::Random as _;
    use commonware_utils::hex;
    use rand::rngs::OsRng;
    use summit_types::PrivateKey;

    fn sign(action: &str, timestamp_secs: u64, sk: &PrivateKey) -> String {
        let message = format!("{DOMAIN}:{action}:{timestamp_secs}");
        let sig = sk.sign(&[], message.as_bytes());
        format!("0x{}", hex(sig.as_ref()))
    }

    fn new_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng)
    }

    #[test]
    fn happy_path_pause() {
        let sk = new_key();
        let pk = sk.public_key();
        let now = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, now, &sk);

        assert!(verify_action_with(&pk, now, ACTION_PAUSE, now, &sig).is_ok());
    }

    #[test]
    fn happy_path_unpause() {
        let sk = new_key();
        let pk = sk.public_key();
        let now = 1_700_000_000;
        let sig = sign(ACTION_UNPAUSE, now, &sk);

        assert!(verify_action_with(&pk, now, ACTION_UNPAUSE, now, &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_action_replay() {
        let sk = new_key();
        let pk = sk.public_key();
        let now = 1_700_000_000;
        let pause_sig = sign(ACTION_PAUSE, now, &sk);

        let err = verify_action_with(&pk, now, ACTION_UNPAUSE, now, &pause_sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let sk = new_key();
        let pk = sk.public_key();
        let signed_at = 1_700_000_000;
        let now = signed_at + TIMESTAMP_WINDOW_SECS + 1;
        let sig = sign(ACTION_PAUSE, signed_at, &sk);

        let err = verify_action_with(&pk, now, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_future_timestamp_outside_window() {
        let sk = new_key();
        let pk = sk.public_key();
        let now = 1_700_000_000;
        let signed_at = now + TIMESTAMP_WINDOW_SECS + 1;
        let sig = sign(ACTION_PAUSE, signed_at, &sk);

        let err = verify_action_with(&pk, now, ACTION_PAUSE, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_wrong_signer() {
        let attacker = new_key();
        let admin = new_key();
        let now = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, now, &attacker);

        let err =
            verify_action_with(&admin.public_key(), now, ACTION_PAUSE, now, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_garbage_signature_hex() {
        let sk = new_key();
        let pk = sk.public_key();
        let now = 1_700_000_000;

        let err = verify_action_with(&pk, now, ACTION_PAUSE, now, "not-hex-at-all").unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let sk = new_key();
        let pk = sk.public_key();
        let signed_at = 1_700_000_000;
        let sig = sign(ACTION_PAUSE, signed_at, &sk);

        let tampered_ts = signed_at + 5;
        let err =
            verify_action_with(&pk, tampered_ts, ACTION_PAUSE, tampered_ts, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn placeholder_admin_pubkey_decodes() {
        assert!(admin_pubkey().is_ok());
    }
}
