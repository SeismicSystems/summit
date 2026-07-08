use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::simplex::scheme::{self, Scheme};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::group;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::certificate::Provider;
use commonware_cryptography::{Digest, PublicKey, Signer, ed25519};
use commonware_utils::TryCollect;
use commonware_utils::ordered::BiMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// BLS multisig from simplex module for use with Simplex consensus
pub type MultisigScheme =
    scheme::bls12381_multisig::Scheme<<ed25519::PrivateKey as Signer>::PublicKey, MinPk>;

/// Supplies the signing scheme the marshal should use for a given epoch.
pub trait SchemeProvider<D: Digest>: Clone + Send + Sync + 'static {
    /// The signing scheme to provide.
    type Scheme: Scheme<D>;

    /// Return the signing scheme that corresponds to `epoch`.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>>;

    /// Return a certificate verifier that can validate certificates independent of epoch.
    ///
    /// This method allows implementations to provide a verifier that can validate
    /// certificates from any epoch (without epoch-specific state). For example,
    /// [`bls12381_threshold::Scheme`](crate::simplex::signing_scheme::bls12381_threshold::Scheme)
    /// maintains a static public key across epochs that can be used to verify certificates from any
    /// epoch, even after the committee has rotated and the underlying secret shares have been refreshed.
    ///
    /// The default implementation returns `None`. Callers should fall back to
    /// [`SchemeProvider::scheme`] for epoch-specific verification.
    fn certificate_verifier(&self) -> Option<Arc<Self::Scheme>> {
        None
    }
}

#[derive(Clone)]
pub struct SummitSchemeProvider {
    #[allow(clippy::type_complexity)]
    schemes: Arc<Mutex<HashMap<Epoch, Arc<MultisigScheme>>>>,
    bls_private_key: Option<group::Private>,
    namespace: Vec<u8>,
}

impl SummitSchemeProvider {
    pub fn new(bls_private_key: group::Private, namespace: Vec<u8>) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            bls_private_key: Some(bls_private_key),
            namespace,
        }
    }

    pub fn verifier_only(namespace: Vec<u8>) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            bls_private_key: None,
            namespace,
        }
    }

    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: MultisigScheme) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }

    /// Unregisters the signing scheme for the given epoch.
    ///
    /// Returns `false` if no scheme was registered for the epoch.
    pub fn unregister(&self, epoch: &Epoch) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.remove(epoch).is_some()
    }
}

pub trait EpochSchemeProvider<D: Digest> {
    type Variant: Variant;
    type PublicKey: PublicKey;
    type Scheme: Scheme<D>;

    /// Returns a [Scheme] for the given [EpochTransition].
    fn scheme_for_epoch(&self, transition: &EpochTransition) -> Self::Scheme;
}

impl<D: Digest> SchemeProvider<D> for SummitSchemeProvider {
    type Scheme = MultisigScheme;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<MultisigScheme>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}

// Implement the commonware Provider trait
impl Provider for SummitSchemeProvider {
    type Scope = Epoch;
    type Scheme = MultisigScheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&scope).cloned()
    }
}

impl<D: Digest> EpochSchemeProvider<D> for SummitSchemeProvider {
    type Variant = MinPk;
    type PublicKey = ed25519::PublicKey;
    type Scheme = MultisigScheme;

    fn scheme_for_epoch(&self, transition: &EpochTransition) -> Self::Scheme {
        let participants: BiMap<Self::PublicKey, <Self::Variant as Variant>::Public> = transition
            .validator_keys
            .iter()
            .map(|(pk, bls_pk)| {
                let minpk_public: &<MinPk as Variant>::Public = bls_pk.as_ref();
                let encoded = minpk_public.encode();
                let variant_pk = <MinPk as Variant>::Public::decode(&mut encoded.as_ref())
                    .expect("failed to decode BLS public key");
                (pk.clone(), variant_pk)
            })
            .try_collect()
            .expect("failed to build BiMap");

        if let Some(bls_private_key) = &self.bls_private_key {
            // Try to create a signer if our private key is in the participant set.
            // If not, fall back to verifier mode (observer/non-validator).
            match MultisigScheme::signer(
                &self.namespace,
                participants.clone(),
                bls_private_key.clone(),
            ) {
                Some(scheme) => {
                    tracing::debug!(
                        epoch = transition.epoch.get(),
                        "created signing scheme for epoch (active validator)"
                    );
                    return scheme;
                }
                None => {
                    tracing::info!(
                        epoch = transition.epoch.get(),
                        "private key not in validator set, entering verifier mode"
                    );
                }
            }
        } else {
            tracing::info!(
                epoch = transition.epoch.get(),
                "consensus signing disabled, entering verifier mode"
            );
        }

        MultisigScheme::verifier(&self.namespace, participants)
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<BLS = crate::bls12381::PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The public keys of the validator set
    pub validator_keys: Vec<(crate::PublicKey, BLS)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Digest, bls12381};
    use commonware_consensus::simplex::types::{Notarize, Proposal};
    use commonware_consensus::types::{Round, View};
    use commonware_cryptography::certificate::Scheme as _;

    const NAMESPACE: &[u8] = b"test-scheme";

    fn private_scalar(private_key: &bls12381::PrivateKey) -> group::Private {
        let encoded = private_key.encode();
        group::Private::decode(&mut encoded.as_ref()).expect("valid BLS private key")
    }

    fn sample_proposal(epoch: Epoch) -> Proposal<Digest> {
        Proposal {
            round: Round::new(epoch, View::new(1)),
            parent: View::new(0),
            payload: Digest::from([1u8; 32]),
        }
    }

    #[test]
    fn signing_provider_signs_when_key_matches_validator_set() {
        let node_key = ed25519::PrivateKey::from_seed(1);
        let consensus_key = bls12381::PrivateKey::from_seed(2);
        let epoch = Epoch::new(3);
        let transition = EpochTransition {
            epoch,
            validator_keys: vec![(node_key.public_key(), consensus_key.public_key())],
        };
        let provider =
            SummitSchemeProvider::new(private_scalar(&consensus_key), NAMESPACE.to_vec());

        let scheme = <SummitSchemeProvider as EpochSchemeProvider<Digest>>::scheme_for_epoch(
            &provider,
            &transition,
        );

        assert!(scheme.me().is_some());
        assert!(Notarize::sign(&scheme, sample_proposal(epoch)).is_some());
    }

    #[test]
    fn verifier_only_provider_never_signs_with_matching_validator_key() {
        let node_key = ed25519::PrivateKey::from_seed(1);
        let consensus_key = bls12381::PrivateKey::from_seed(2);
        let epoch = Epoch::new(3);
        let transition = EpochTransition {
            epoch,
            validator_keys: vec![(node_key.public_key(), consensus_key.public_key())],
        };
        let provider = SummitSchemeProvider::verifier_only(NAMESPACE.to_vec());

        let scheme = <SummitSchemeProvider as EpochSchemeProvider<Digest>>::scheme_for_epoch(
            &provider,
            &transition,
        );

        assert!(scheme.me().is_none());
        assert!(Notarize::sign(&scheme, sample_proposal(epoch)).is_none());
    }
}

/// Provides the certified genesis payload digest for an epoch.
///
/// Consensus no longer queries the automaton for the epoch genesis; the
/// orchestrator fetches it through this trait when spawning an epoch's engine
/// and passes it to consensus via `simplex::Config::floor`.
pub trait EpochGenesisProvider: Send + 'static {
    /// Returns the genesis payload digest for the given epoch.
    fn genesis(&mut self, epoch: Epoch)
    -> impl core::future::Future<Output = crate::Digest> + Send;
}
