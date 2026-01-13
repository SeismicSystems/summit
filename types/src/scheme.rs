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
    bls_private_key: group::Private,
    namespace: Vec<u8>,
}

impl SummitSchemeProvider {
    pub fn new(bls_private_key: group::Private, namespace: Vec<u8>) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            bls_private_key,
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

        // Try to create a signer if our private key is in the participant set.
        // If not, fall back to verifier mode (observer/non-validator).
        match MultisigScheme::signer(
            &self.namespace,
            participants.clone(),
            self.bls_private_key.clone(),
        ) {
            Some(scheme) => {
                tracing::debug!(
                    epoch = transition.epoch.get(),
                    "created signing scheme for epoch (active validator)"
                );
                scheme
            }
            None => {
                tracing::info!(
                    epoch = transition.epoch.get(),
                    "private key not in validator set, entering verifier mode (observer only)"
                );
                MultisigScheme::verifier(&self.namespace, participants)
            }
        }
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<BLS = crate::bls12381::PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The public keys of the validator set
    pub validator_keys: Vec<(crate::PublicKey, BLS)>,
}
