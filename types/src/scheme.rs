use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::simplex::signing_scheme::{self, Scheme};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::group;
use commonware_cryptography::bls12381::primitives::variant::{MinPk, Variant};
use commonware_cryptography::{PublicKey, Signer};
use commonware_utils::set::OrderedAssociated;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type MultisigScheme<C, V> =
    signing_scheme::bls12381_multisig::Scheme<<C as Signer>::PublicKey, V>;

/// Supplies the signing scheme the marshal should use for a given epoch.
pub trait SchemeProvider: Clone + Send + Sync + 'static {
    /// The signing scheme to provide.
    type Scheme: Scheme;

    /// Return the signing scheme that corresponds to `epoch`.
    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>>;
}

#[derive(Clone)]
pub struct SummitSchemeProvider<C: Signer, V: Variant> {
    #[allow(clippy::type_complexity)]
    schemes: Arc<Mutex<HashMap<Epoch, Arc<MultisigScheme<C, V>>>>>,
    bls_private_key: group::Private,
}

impl<C: Signer, V: Variant> SummitSchemeProvider<C, V> {
    pub fn new(bls_private_key: group::Private) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            bls_private_key,
        }
    }

    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: MultisigScheme<C, V>) -> bool {
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

pub trait EpochSchemeProvider {
    type Variant: Variant;
    type PublicKey: PublicKey;
    type Scheme: Scheme;

    /// Returns a [Scheme] for the given [EpochTransition].
    fn scheme_for_epoch(&self, transition: &EpochTransition) -> Self::Scheme;
}

impl<C: Signer, V: Variant> SchemeProvider for SummitSchemeProvider<C, V> {
    type Scheme = MultisigScheme<C, V>;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<MultisigScheme<C, V>>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}

impl<C: Signer<PublicKey = crate::PublicKey>, V: Variant> EpochSchemeProvider
    for SummitSchemeProvider<C, V>
{
    type Variant = V;
    type PublicKey = C::PublicKey;
    type Scheme = MultisigScheme<C, V>;

    fn scheme_for_epoch(&self, transition: &EpochTransition) -> Self::Scheme {
        let participants: OrderedAssociated<Self::PublicKey, V::Public> = transition
            .validator_keys
            .iter()
            .map(|(pk, bls_pk)| {
                let minpk_public: &<MinPk as Variant>::Public = bls_pk.as_ref();
                let encoded = minpk_public.encode();
                let variant_pk = V::Public::decode(&mut encoded.as_ref())
                    .expect("failed to decode BLS public key");
                (pk.clone(), variant_pk)
            })
            .collect();

        MultisigScheme::<C, V>::new(participants, self.bls_private_key.clone())
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<BLS = crate::bls12381::PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The public keys of the validator set
    pub validator_keys: Vec<(crate::PublicKey, BLS)>,
}
