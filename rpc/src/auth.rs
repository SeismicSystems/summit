use crate::error::RpcError;
use alloy_primitives::{Address, Signature};
use commonware_formatting::from_hex;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// TODO: replace with the real admin/master addresses before production use.
//
// Two-tier authorization:
// - `admin` can pause and read the pause state, but cannot unpause. A
//   compromised admin key can at worst halt this node (fail-closed).
// - `master` can pause, unpause, and read the pause state. Resuming
//   consensus is the privileged direction and stays with the colder key.
pub const PAUSE_ADMIN_ADDRESS_HEX: &str = "0x63A68da40b5B5Df905960EE72d9f670aC37fDbe9";
pub const PAUSE_MASTER_ADDRESS_HEX: &str = "0xd412c5Ecd343e264381fF15aFC0aD78a67B79F35";

pub const TIMESTAMP_WINDOW_SECS: u64 = 30;
pub const DOMAIN: &str = "summit-pause-v1";

/// An authorized pause-RPC action. The string form is bound into the signed
/// message, so a signature for one action can never authorize another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pause,
    Unpause,
    IsPaused,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Pause => "pause",
            Action::Unpause => "unpause",
            Action::IsPaused => "isPaused",
        }
    }
}

/// The role a recovered signer holds. `Master` is a strict superset of
/// `Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Master,
}

impl Role {
    fn permits(self, action: Action) -> bool {
        match (self, action) {
            (Role::Master, _) => true,
            (Role::Admin, Action::Pause | Action::IsPaused) => true,
            (Role::Admin, Action::Unpause) => false,
        }
    }
}

/// The set of addresses trusted to authorize pause-RPC actions.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PauseKeys {
    pub admin: Address,
    pub master: Address,
}

impl PauseKeys {
    fn from_consts() -> Result<Self, RpcError> {
        let parse = |hex: &str, what: &str| {
            Address::from_str(hex).map_err(|e| {
                RpcError::InvalidAdminAddress(format!("{what} address parse failed: {e}"))
            })
        };
        Ok(Self {
            admin: parse(PAUSE_ADMIN_ADDRESS_HEX, "admin")?,
            master: parse(PAUSE_MASTER_ADDRESS_HEX, "master")?,
        })
    }

    /// Master is checked first so that an address configured for both roles
    /// gets the superset.
    fn role_of(&self, addr: &Address) -> Option<Role> {
        if addr == &self.master {
            Some(Role::Master)
        } else if addr == &self.admin {
            Some(Role::Admin)
        } else {
            None
        }
    }
}

fn now_secs() -> Result<u64, RpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| RpcError::Internal(format!("system clock before unix epoch: {e}")))
}

/// Verifies a signed pause-RPC request and returns the role of the signer.
///
/// `scope` is the hex of the deployment-bound pause domain
/// (`summit_types::pause_signature_domain` over the EL genesis hash +
/// namespace). Binding it into the signed message scopes the authorization to
/// this deployment, so a pause/unpause signature cannot be replayed against
/// another network that trusts the same admin key.
pub fn verify_action(
    scope: &str,
    action: Action,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<Role, RpcError> {
    let keys = PauseKeys::from_consts()?;
    verify_action_with(
        &keys,
        now_secs()?,
        scope,
        action,
        timestamp_secs,
        signature_hex,
    )
}

pub(crate) fn verify_action_with(
    keys: &PauseKeys,
    now_secs: u64,
    scope: &str,
    action: Action,
    timestamp_secs: u64,
    signature_hex: &str,
) -> Result<Role, RpcError> {
    let skew = now_secs.abs_diff(timestamp_secs);
    if skew > TIMESTAMP_WINDOW_SECS {
        return Err(RpcError::TimestampOutOfWindow);
    }

    let sig_bytes = from_hex(signature_hex).ok_or(RpcError::InvalidSignature)?;
    let signature = Signature::from_raw(&sig_bytes).map_err(|_| RpcError::InvalidSignature)?;

    let message = format!("{DOMAIN}:{scope}:{}:{timestamp_secs}", action.as_str());
    let recovered = signature
        .recover_address_from_msg(message.as_bytes())
        .map_err(|_| RpcError::InvalidSignature)?;

    let role = keys.role_of(&recovered).ok_or(RpcError::InvalidSignature)?;

    if !role.permits(action) {
        return Err(RpcError::Forbidden);
    }

    Ok(role)
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

    fn sign(scope: &str, action: Action, timestamp_secs: u64, signer: &PrivateKeySigner) -> String {
        let message = format!("{DOMAIN}:{scope}:{}:{timestamp_secs}", action.as_str());
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    /// Fresh admin + master signers and the key set that trusts them.
    fn keys() -> (PrivateKeySigner, PrivateKeySigner, PauseKeys) {
        let admin = PrivateKeySigner::random();
        let master = PrivateKeySigner::random();
        let keys = PauseKeys {
            admin: admin.address(),
            master: master.address(),
        };
        (admin, master, keys)
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn master_permits_every_action() {
        let (_, master, keys) = keys();
        let scope = scope_a();
        for action in [Action::Pause, Action::Unpause, Action::IsPaused] {
            let sig = sign(&scope, action, NOW, &master);
            let role = verify_action_with(&keys, NOW, &scope, action, NOW, &sig)
                .ok()
                .expect("master must be authorized");
            assert_eq!(role, Role::Master, "{action:?}");
        }
    }

    #[test]
    fn admin_permits_pause_and_read() {
        let (admin, _, keys) = keys();
        let scope = scope_a();
        for action in [Action::Pause, Action::IsPaused] {
            let sig = sign(&scope, action, NOW, &admin);
            let role = verify_action_with(&keys, NOW, &scope, action, NOW, &sig)
                .ok()
                .expect("admin must be authorized");
            assert_eq!(role, Role::Admin, "{action:?}");
        }
    }

    /// A valid admin signature over `unpause` is rejected with `Forbidden`
    /// (not `InvalidSignature`): the signer is known, just under-privileged.
    #[test]
    fn admin_cannot_unpause() {
        let (admin, _, keys) = keys();
        let scope = scope_a();
        let sig = sign(&scope, Action::Unpause, NOW, &admin);

        let err = verify_action_with(&keys, NOW, &scope, Action::Unpause, NOW, &sig).unwrap_err();
        assert!(matches!(err, RpcError::Forbidden));
    }

    /// If one address is configured for both roles it gets the superset.
    #[test]
    fn same_address_in_both_roles_is_master() {
        let signer = PrivateKeySigner::random();
        let keys = PauseKeys {
            admin: signer.address(),
            master: signer.address(),
        };
        let scope = scope_a();
        let sig = sign(&scope, Action::Unpause, NOW, &signer);

        let role = verify_action_with(&keys, NOW, &scope, Action::Unpause, NOW, &sig)
            .ok()
            .expect("dual-role signer must be authorized");
        assert_eq!(role, Role::Master);
    }

    #[test]
    fn rejects_wrong_action_replay() {
        let (_, master, keys) = keys();
        let scope = scope_a();
        let pause_sig = sign(&scope, Action::Pause, NOW, &master);

        let err =
            verify_action_with(&keys, NOW, &scope, Action::Unpause, NOW, &pause_sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    /// A pause/unpause signature minted for deployment A must not authorize the
    /// same action on deployment B, even though both trust the same admin key.
    #[test]
    fn rejects_other_deployment_scope() {
        let (admin, _, keys) = keys();

        // Admin legitimately signs a pause for deployment A.
        let sig = sign(&scope_a(), Action::Pause, NOW, &admin);

        // Deployment A accepts it...
        assert!(verify_action_with(&keys, NOW, &scope_a(), Action::Pause, NOW, &sig).is_ok());
        // ...but deployment B rejects the very same signature.
        let err = verify_action_with(&keys, NOW, &scope_b(), Action::Pause, NOW, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let (admin, _, keys) = keys();
        let signed_at = NOW;
        let now = signed_at + TIMESTAMP_WINDOW_SECS + 1;
        let scope = scope_a();
        let sig = sign(&scope, Action::Pause, signed_at, &admin);

        let err =
            verify_action_with(&keys, now, &scope, Action::Pause, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_future_timestamp_outside_window() {
        let (admin, _, keys) = keys();
        let signed_at = NOW + TIMESTAMP_WINDOW_SECS + 1;
        let scope = scope_a();
        let sig = sign(&scope, Action::Pause, signed_at, &admin);

        let err =
            verify_action_with(&keys, NOW, &scope, Action::Pause, signed_at, &sig).unwrap_err();
        assert!(matches!(err, RpcError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_unknown_signer() {
        let (_, _, keys) = keys();
        let attacker = PrivateKeySigner::random();
        let scope = scope_a();
        let sig = sign(&scope, Action::Pause, NOW, &attacker);

        let err = verify_action_with(&keys, NOW, &scope, Action::Pause, NOW, &sig).unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_garbage_signature_hex() {
        let (_, _, keys) = keys();

        let err = verify_action_with(&keys, NOW, &scope_a(), Action::Pause, NOW, "not-hex-at-all")
            .unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let (admin, _, keys) = keys();
        let signed_at = NOW;
        let scope = scope_a();
        let sig = sign(&scope, Action::Pause, signed_at, &admin);

        let tampered_ts = signed_at + 5;
        let err = verify_action_with(&keys, tampered_ts, &scope, Action::Pause, tampered_ts, &sig)
            .unwrap_err();
        assert!(matches!(err, RpcError::InvalidSignature));
    }

    #[test]
    fn placeholder_addresses_parse() {
        assert!(PauseKeys::from_consts().is_ok());
    }
}
