use crate::PublicKey;
use crate::protocol_params::{
    DEFAULT_MINIMUM_VALIDATOR_COUNT, MAX_INVALID_WITHDRAWAL_TAX, MAX_MESSAGE_SIZE_BYTES_MAX,
    MAX_MESSAGE_SIZE_BYTES_MIN, MIN_MINIMUM_VALIDATOR_COUNT, ProtocolParam,
};
use alloy_primitives::Address;
use anyhow::Context;
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_utils::{from_hex, from_hex_formatted};
use serde::{Deserialize, Serialize};
use ssz::Encode as _;
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize, ssz_derive::Encode)]
pub struct Genesis {
    /// List of all validators at genesis block
    pub validators: Vec<GenesisValidator>,
    /// The hash of the genesis file used for the EVM client
    #[ssz(with = "ssz_string")]
    pub eth_genesis_hash: String,
    /// Amount of time to wait for a leader to propose a payload
    /// in a view.
    pub leader_timeout_ms: u64,
    /// Amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    pub notarization_timeout_ms: u64,
    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub nullify_timeout_ms: u64,
    /// Number of views behind finalized tip to track
    /// and persist activity derived from validator messages.
    pub activity_timeout_views: u64,
    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many views.
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking).
    pub skip_timeout_views: u64,
    /// Maximum size allowed for messages over any connection.
    ///
    /// The actual size of the network message will be higher due to overhead from the protocol;
    /// this may include additional metadata, data from the codec, and/or cryptographic signatures.
    pub max_message_size_bytes: u64,
    /// Prefix for all signed messages to prevent replay attacks.
    #[ssz(with = "ssz_string")]
    pub namespace: String,
    /// Minimum validator stake in gwei
    pub validator_minimum_stake: u64,
    /// Maximum validator stake in gwei
    pub validator_maximum_stake: u64,
    /// Number of blocks in each epoch
    pub blocks_per_epoch: u64,
    /// Maximum allowed delta (in milliseconds) between a block's timestamp
    /// and the local wall clock. Blocks with timestamps that exceed local
    /// time by more than this are rejected during verification.
    pub allowed_timestamp_future_ms: u64,
    /// Address that receives treasury funds. Defaults to the zero address.
    #[serde(default = "default_treasury_address")]
    #[ssz(with = "ssz_string")]
    pub treasury_address: String,
    /// Maximum number of validators that can join per epoch via deposits.
    #[serde(default = "default_max_deposits_per_epoch")]
    pub max_deposits_per_epoch: u64,
    /// Maximum number of withdrawals that can be processed per epoch.
    #[serde(default = "default_max_withdrawals_per_epoch")]
    pub max_withdrawals_per_epoch: u64,
    /// Number of observer keys authorized per validator as secondary p2p peers.
    /// Each validator's node key implicitly authorizes observers with derivation
    /// indices `0..observers_per_validator`. Mutable via the
    /// [`ObserversPerValidator`](crate::protocol_params::ProtocolParam::ObserversPerValidator)
    /// execution request.
    #[serde(default = "default_observers_per_validator")]
    pub observers_per_validator: u32,
    /// Minimum number of active validators that full exits must preserve.
    #[serde(default = "default_minimum_validator_count")]
    pub minimum_validator_count: u64,
    /// Percentage tax applied to invalid-deposit refunds. Must be between 0 and 100.
    #[serde(default = "default_invalid_withdrawal_tax")]
    pub invalid_withdrawal_tax: u64,
}

fn default_treasury_address() -> String {
    Address::ZERO.to_string()
}

fn default_max_deposits_per_epoch() -> u64 {
    3
}

fn default_max_withdrawals_per_epoch() -> u64 {
    16
}

fn default_observers_per_validator() -> u32 {
    5
}

fn default_minimum_validator_count() -> u64 {
    DEFAULT_MINIMUM_VALIDATOR_COUNT
}

fn default_invalid_withdrawal_tax() -> u64 {
    0
}

#[derive(Debug, Clone, Serialize, Deserialize, ssz_derive::Encode)]
pub struct GenesisValidator {
    #[ssz(with = "ssz_string")]
    pub node_public_key: String,
    #[ssz(with = "ssz_string")]
    pub consensus_public_key: String,
    /// Network topology, not consensus identity: excluded from `config_digest`.
    #[ssz(skip_serializing)]
    pub ip_address: String,
    #[ssz(with = "ssz_string")]
    pub withdrawal_credentials: String,
}

impl GenesisValidator {
    fn ed25519_pubkey(key: &str) -> PublicKey {
        let pubkey_bytes = from_hex(key).unwrap();
        PublicKey::decode(&pubkey_bytes[..]).unwrap()
    }

    pub fn node_pubkey(&self) -> PublicKey {
        GenesisValidator::ed25519_pubkey(&self.node_public_key)
    }
}

#[derive(Debug, Clone)]
pub struct Validator {
    pub node_public_key: PublicKey,
    pub consensus_public_key: bls12381::PublicKey,
    pub ip_address: SocketAddr,
    pub withdrawal_credentials: Address,
}

impl TryFrom<&GenesisValidator> for Validator {
    type Error = anyhow::Error;

    fn try_from(value: &GenesisValidator) -> Result<Self, Self::Error> {
        let node_key_bytes =
            from_hex_formatted(&value.node_public_key).context("Node PublicKey bad format")?;
        let node_public_key = PublicKey::decode(&*node_key_bytes)?;

        let consensus_key_bytes = from_hex_formatted(&value.consensus_public_key)
            .context("Consensus PublicKey bad format")?;
        let consensus_public_key = bls12381::PublicKey::decode(&*consensus_key_bytes)?;

        Ok(Validator {
            node_public_key,
            consensus_public_key,
            ip_address: value.ip_address.parse()?,
            withdrawal_credentials: value.withdrawal_credentials.parse()?,
        })
    }
}

/// Domain tag for [`Genesis::config_digest`], separating it from any other
/// SHA-256 use over genesis bytes.
const GENESIS_CONFIG_DOMAIN_TAG: &[u8] = b"summit-genesis-config-v1";

/// `#[ssz(with = "ssz_string")]` codec that lets `ssz_derive` encode a `String`
/// field as an SSZ `List[uint8]` (its raw UTF-8 bytes). Only the `encode` side
/// is provided because `Genesis` derives `ssz::Encode` solely to feed
/// [`Genesis::config_digest`]; it is never SSZ-decoded.
mod ssz_string {
    pub mod encode {
        pub fn is_ssz_fixed_len() -> bool {
            false
        }
        pub fn ssz_fixed_len() -> usize {
            ssz::BYTES_PER_LENGTH_OFFSET
        }
        pub fn ssz_bytes_len(value: &str) -> usize {
            value.len()
        }
        pub fn ssz_append(value: &String, buf: &mut Vec<u8>) {
            buf.extend_from_slice(value.as_bytes());
        }
    }
}

impl Genesis {
    /// The EL genesis hash as raw bytes, the immutable identity of this chain
    /// deployment. Panics if `eth_genesis_hash` is not a 32-byte hex string;
    /// genesis files are operator-provided and validated at load time.
    pub fn genesis_hash(&self) -> [u8; 32] {
        from_hex_formatted(&self.eth_genesis_hash)
            .map(|bytes| bytes.try_into())
            .expect("bad eth_genesis_hash")
            .expect("bad eth_genesis_hash")
    }

    /// Deterministic digest over the immutable Summit genesis configuration that
    /// defines this chain's identity: the EL genesis hash, namespace, every
    /// consensus/economic parameter fixed at launch, and the genesis validator
    /// set (node key, consensus key, withdrawal credentials). Used to derive the
    /// live P2P and consensus [`chain_domain`](crate::chain_domain), so two
    /// deployments that differ in ANY of these fields derive distinct domains
    /// and cannot cross-authenticate peers or cross-verify consensus
    /// certificates.
    ///
    /// The bytes come from the `ssz::Encode` derive on `Genesis` (canonical,
    /// spec-stable, and complete — a new field is automatically included unless
    /// explicitly `#[ssz(skip_serializing)]`'d). Per-validator `ip_address` is
    /// skipped: it is network topology, not consensus identity.
    pub fn config_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_CONFIG_DOMAIN_TAG);
        hasher.update(&self.as_ssz_bytes());
        hasher.finalize().0
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file_string = std::fs::read_to_string(path)?;
        let genesis: Genesis = toml::from_str(&file_string)?;
        genesis.validate()?;
        Ok(genesis)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Genesis epoch length must satisfy the same bounds as a runtime
        // EpochLength protocol-parameter update (hence the shared ProtocolParam
        // validation). An oversized launch value defers every epoch-boundary
        // mechanic — checkpoints, final-block withdrawals, committee transitions,
        // queued param changes — until that boundary, turning epoch functionality
        // into a liveness failure.
        ProtocolParam::EpochLength(self.blocks_per_epoch).validate()?;
        if self.validator_minimum_stake > self.validator_maximum_stake {
            return Err(format!(
                "validator_minimum_stake {} exceeds validator_maximum_stake {}",
                self.validator_minimum_stake, self.validator_maximum_stake
            )
            .into());
        }
        // The P2P message ceiling must hold the largest legitimate message (full
        // blocks, checkpoints) yet stay bounded against per-message allocation DoS,
        // and must not exceed u32::MAX (the p2p config converts it with `as u32`,
        // which would otherwise silently truncate). A zero value would reject every
        // message and brick networking.
        if self.max_message_size_bytes < MAX_MESSAGE_SIZE_BYTES_MIN
            || self.max_message_size_bytes > MAX_MESSAGE_SIZE_BYTES_MAX
        {
            return Err(format!(
                "max_message_size_bytes must be between {MAX_MESSAGE_SIZE_BYTES_MIN} and {MAX_MESSAGE_SIZE_BYTES_MAX}"
            )
            .into());
        }
        ProtocolParam::AllowedTimestampFuture(self.allowed_timestamp_future_ms).validate()?;
        self.treasury_address
            .parse::<Address>()
            .map_err(|e| format!("invalid treasury_address: {e}"))?;
        if self.leader_timeout_ms == 0 {
            return Err("leader_timeout_ms must be greater than 0".into());
        }
        if self.notarization_timeout_ms == 0 {
            return Err("notarization_timeout_ms must be greater than 0".into());
        }
        if self.nullify_timeout_ms == 0 {
            return Err("nullify_timeout_ms must be greater than 0".into());
        }
        if self.activity_timeout_views == 0 {
            return Err("activity_timeout_views must be greater than 0".into());
        }
        if self.skip_timeout_views == 0 {
            return Err("skip_timeout_views must be greater than 0".into());
        }
        if self.leader_timeout_ms > self.notarization_timeout_ms {
            return Err(
                "leader_timeout_ms must be less than or equal to notarization_timeout_ms".into(),
            );
        }
        if self.skip_timeout_views > self.activity_timeout_views {
            return Err(
                "skip_timeout_views must be less than or equal to activity_timeout_views".into(),
            );
        }
        // Genesis must respect the same bounds the runtime protocol-parameter
        // update path enforces; otherwise an unchecked genesis value (e.g. supplied
        // over a first-boot RPC) can drive consensus state outside any limit Summit
        // policy was designed for. These reuse the single ProtocolParam validator so
        // the genesis and runtime bounds cannot drift apart.
        ProtocolParam::MaxDepositsPerEpoch(self.max_deposits_per_epoch).validate()?;
        ProtocolParam::MaxWithdrawalsPerEpoch(self.max_withdrawals_per_epoch).validate()?;
        ProtocolParam::ObserversPerValidator(u64::from(self.observers_per_validator)).validate()?;
        // `minimum_validator_count` has no scalar bound in `ProtocolParam::validate`
        // (it carries no `ParamBoundsError` variant), so its floor is enforced here.
        if self.minimum_validator_count < MIN_MINIMUM_VALIDATOR_COUNT {
            return Err(format!(
                "minimum_validator_count {} is below minimum {}",
                self.minimum_validator_count, MIN_MINIMUM_VALIDATOR_COUNT
            )
            .into());
        }
        if self.invalid_withdrawal_tax > MAX_INVALID_WITHDRAWAL_TAX {
            return Err(format!(
                "invalid_withdrawal_tax {} exceeds maximum {}",
                self.invalid_withdrawal_tax, MAX_INVALID_WITHDRAWAL_TAX
            )
            .into());
        }
        Ok(())
    }

    pub fn ip_of(&self, target_public_key: &PublicKey) -> Option<SocketAddr> {
        for validator in &self.validators {
            #[allow(clippy::collapsible_if)]
            if let Some(public_key_bytes) = from_hex_formatted(&validator.node_public_key) {
                if let Ok(pub_key) = PublicKey::decode(&*public_key_bytes) {
                    if &pub_key == target_public_key {
                        if let Ok(socket_addr) = validator.ip_address.parse() {
                            return Some(socket_addr);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    pub fn get_validators(&self) -> Result<Vec<Validator>, anyhow::Error> {
        let mut validators = Vec::with_capacity(self.validators.len());
        for validator in &self.validators {
            validators.push(validator.try_into()?);
        }
        Ok(validators)
    }

    pub fn get_consensus_keys(
        &self,
    ) -> Result<Vec<bls12381::PublicKey>, Box<dyn std::error::Error>> {
        let mut keys = Vec::new();
        for validator in &self.validators {
            let key_bytes = from_hex_formatted(&validator.consensus_public_key)
                .ok_or("Invalid hex format for consensus public key")?;
            let key = bls12381::PublicKey::decode(&*key_bytes)?;
            keys.push(key);
        }
        Ok(keys)
    }

    pub fn get_validator_keys(
        &self,
    ) -> Result<Vec<(PublicKey, bls12381::PublicKey)>, Box<dyn std::error::Error>> {
        let mut keys = Vec::new();
        for validator in &self.validators {
            let node_key_bytes = from_hex_formatted(&validator.node_public_key)
                .ok_or("Invalid hex format for node public key")?;
            let node_key = PublicKey::decode(&*node_key_bytes)?;

            let consensus_key_bytes = from_hex_formatted(&validator.consensus_public_key)
                .ok_or("Invalid hex format for consensus public key")?;
            let consensus_key = bls12381::PublicKey::decode(&*consensus_key_bytes)?;

            keys.push((node_key, consensus_key));
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_params::{
        MAX_EPOCH_LENGTH, MAX_MAX_DEPOSITS_PER_EPOCH, MAX_OBSERVERS_PER_VALIDATOR,
        MAX_WITHDRAWALS_PER_EPOCH_MAX, MAX_WITHDRAWALS_PER_EPOCH_MIN, MIN_EPOCH_LENGTH,
    };

    #[test]
    fn test_loading_genesis() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        assert_eq!(genesis.validator_count(), 4);
        assert_eq!(genesis.blocks_per_epoch, 10000);
        assert_eq!(
            genesis.minimum_validator_count,
            DEFAULT_MINIMUM_VALIDATOR_COUNT
        );

        let keys = genesis.get_validator_keys().unwrap();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn test_validator_lookup() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();

        // Test that we can find the IP for each validator
        let validators = &genesis.get_validators().unwrap();
        for validator in validators {
            let found_addr = genesis.ip_of(&validator.node_public_key);
            assert_eq!(found_addr, Some(validator.ip_address));
        }
    }

    /// A genesis value equal to the runtime upper bound is the largest
    /// value Summit policy ever accepts, so it must validate.
    #[test]
    fn accepts_max_deposits_per_epoch_at_upper_bound() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_deposits_per_epoch = MAX_MAX_DEPOSITS_PER_EPOCH;
        assert!(genesis.validate().is_ok());
    }

    /// Anything above the runtime cap must be rejected at genesis load —
    /// otherwise the first-boot genesis path can seed consensus state
    /// outside the bound the runtime update path enforces.
    #[test]
    fn rejects_max_deposits_per_epoch_above_upper_bound() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_deposits_per_epoch = MAX_MAX_DEPOSITS_PER_EPOCH + 1;
        assert!(genesis.validate().is_err());
    }

    /// u64::MAX is the worst case: with no genesis cap, the penultimate
    /// deposit-processing loop would iterate u64::MAX times on an empty
    /// queue and stall finalization.
    #[test]
    fn rejects_max_deposits_per_epoch_u64_max() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_deposits_per_epoch = u64::MAX;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn rejects_inverted_validator_stake_interval() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.validator_minimum_stake = genesis.validator_maximum_stake + 1;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn accepts_max_withdrawals_per_epoch_at_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_withdrawals_per_epoch = MAX_WITHDRAWALS_PER_EPOCH_MIN;
        assert!(genesis.validate().is_ok());
        genesis.max_withdrawals_per_epoch = MAX_WITHDRAWALS_PER_EPOCH_MAX;
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn rejects_max_withdrawals_per_epoch_outside_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_withdrawals_per_epoch = 0; // below MAX_WITHDRAWALS_PER_EPOCH_MIN (1)
        assert!(genesis.validate().is_err());
        genesis.max_withdrawals_per_epoch = MAX_WITHDRAWALS_PER_EPOCH_MAX + 1;
        assert!(genesis.validate().is_err());
        genesis.max_withdrawals_per_epoch = u64::MAX;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn accepts_blocks_per_epoch_at_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.blocks_per_epoch = MIN_EPOCH_LENGTH;
        assert!(genesis.validate().is_ok());
        genesis.blocks_per_epoch = MAX_EPOCH_LENGTH;
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn rejects_blocks_per_epoch_outside_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.blocks_per_epoch = 0;
        assert!(genesis.validate().is_err());
        genesis.blocks_per_epoch = MIN_EPOCH_LENGTH - 1;
        assert!(genesis.validate().is_err());
        genesis.blocks_per_epoch = MAX_EPOCH_LENGTH + 1;
        assert!(genesis.validate().is_err());
        genesis.blocks_per_epoch = u64::MAX;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn accepts_max_message_size_bytes_at_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_message_size_bytes = MAX_MESSAGE_SIZE_BYTES_MIN;
        assert!(genesis.validate().is_ok());
        genesis.max_message_size_bytes = MAX_MESSAGE_SIZE_BYTES_MAX;
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn rejects_max_message_size_bytes_outside_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.max_message_size_bytes = 0;
        assert!(genesis.validate().is_err());
        genesis.max_message_size_bytes = MAX_MESSAGE_SIZE_BYTES_MIN - 1;
        assert!(genesis.validate().is_err());
        genesis.max_message_size_bytes = MAX_MESSAGE_SIZE_BYTES_MAX + 1;
        assert!(genesis.validate().is_err());
        genesis.max_message_size_bytes = u64::MAX;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn rejects_zero_simplex_timeouts() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.leader_timeout_ms = 0;
        assert!(genesis.validate().is_err());

        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.notarization_timeout_ms = 0;
        assert!(genesis.validate().is_err());

        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.nullify_timeout_ms = 0;
        assert!(genesis.validate().is_err());

        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.activity_timeout_views = 0;
        assert!(genesis.validate().is_err());

        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.skip_timeout_views = 0;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn rejects_misordered_leader_and_notarization_timeouts() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.leader_timeout_ms = genesis.notarization_timeout_ms + 1;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn rejects_skip_timeout_above_activity_timeout() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.skip_timeout_views = genesis.activity_timeout_views + 1;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn accepts_observers_per_validator_at_upper_bound() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.observers_per_validator = MAX_OBSERVERS_PER_VALIDATOR as u32;
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn rejects_observers_per_validator_above_upper_bound() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.observers_per_validator = (MAX_OBSERVERS_PER_VALIDATOR as u32) + 1;
        assert!(genesis.validate().is_err());
        genesis.observers_per_validator = u32::MAX;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn rejects_zero_minimum_validator_count() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.minimum_validator_count = 0;
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn config_digest_is_deterministic() {
        let genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        assert_eq!(genesis.config_digest(), genesis.config_digest());
    }

    /// Every identity-bearing genesis field must change the digest, so two
    /// deployments that differ in any of them derive distinct chain domains.
    #[test]
    fn config_digest_separates_every_identity_field() {
        let base = Genesis::load_from_file("../example_genesis.toml").unwrap();
        let digest = base.config_digest();

        let cases: Vec<(&str, Box<dyn Fn(&mut Genesis)>)> = vec![
            (
                "eth_genesis_hash",
                Box::new(|g| g.eth_genesis_hash = format!("0x{}", "11".repeat(32))),
            ),
            (
                "namespace",
                Box::new(|g| g.namespace = "different-ns".into()),
            ),
            ("leader_timeout_ms", Box::new(|g| g.leader_timeout_ms += 1)),
            (
                "notarization_timeout_ms",
                Box::new(|g| g.notarization_timeout_ms += 1),
            ),
            (
                "nullify_timeout_ms",
                Box::new(|g| g.nullify_timeout_ms += 1),
            ),
            (
                "activity_timeout_views",
                Box::new(|g| g.activity_timeout_views += 1),
            ),
            (
                "skip_timeout_views",
                Box::new(|g| g.skip_timeout_views += 1),
            ),
            (
                "max_message_size_bytes",
                Box::new(|g| g.max_message_size_bytes += 1),
            ),
            (
                "validator_minimum_stake",
                Box::new(|g| g.validator_minimum_stake += 1),
            ),
            (
                "validator_maximum_stake",
                Box::new(|g| g.validator_maximum_stake += 1),
            ),
            ("blocks_per_epoch", Box::new(|g| g.blocks_per_epoch += 1)),
            (
                "allowed_timestamp_future_ms",
                Box::new(|g| g.allowed_timestamp_future_ms += 1),
            ),
            (
                "treasury_address",
                Box::new(|g| g.treasury_address = format!("0x{}", "22".repeat(20))),
            ),
            (
                "max_deposits_per_epoch",
                Box::new(|g| g.max_deposits_per_epoch += 1),
            ),
            (
                "max_withdrawals_per_epoch",
                Box::new(|g| g.max_withdrawals_per_epoch += 1),
            ),
            (
                "observers_per_validator",
                Box::new(|g| g.observers_per_validator += 1),
            ),
            (
                "minimum_validator_count",
                Box::new(|g| g.minimum_validator_count += 1),
            ),
            (
                "validator consensus key",
                Box::new(|g| {
                    g.validators[0].consensus_public_key = format!("0x{}", "33".repeat(48))
                }),
            ),
            (
                "validator node key",
                Box::new(|g| g.validators[0].node_public_key = format!("0x{}", "44".repeat(32))),
            ),
            (
                "validator withdrawal credentials",
                Box::new(|g| {
                    g.validators[0].withdrawal_credentials = format!("0x{}", "55".repeat(20))
                }),
            ),
            (
                "validator set size",
                Box::new(|g| {
                    g.validators.pop();
                }),
            ),
        ];

        for (label, mutate) in cases {
            let mut g = base.clone();
            mutate(&mut g);
            assert_ne!(
                g.config_digest(),
                digest,
                "config_digest must change when `{label}` changes"
            );
        }
    }

    /// A validator's `ip_address` is network topology, not consensus identity,
    /// so it is excluded from the digest: changing it must NOT change identity.
    #[test]
    fn config_digest_excludes_ip_address() {
        let base = Genesis::load_from_file("../example_genesis.toml").unwrap();
        let digest = base.config_digest();
        let mut g = base.clone();
        g.validators[0].ip_address = "127.0.0.1:65000".into();
        assert_eq!(g.config_digest(), digest);
    }

    #[test]
    fn accepts_invalid_withdrawal_tax_at_bounds() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.invalid_withdrawal_tax = 0;
        assert!(genesis.validate().is_ok());
        genesis.invalid_withdrawal_tax = MAX_INVALID_WITHDRAWAL_TAX;
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_withdrawal_tax_above_upper_bound() {
        let mut genesis = Genesis::load_from_file("../example_genesis.toml").unwrap();
        genesis.invalid_withdrawal_tax = MAX_INVALID_WITHDRAWAL_TAX + 1;
        assert!(genesis.validate().is_err());
        genesis.invalid_withdrawal_tax = u64::MAX;
        assert!(genesis.validate().is_err());
    }
}
