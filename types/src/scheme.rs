use commonware_consensus::simplex::signing_scheme::{self, Scheme};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::group;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_cryptography::{PublicKey, Signer};
use commonware_utils::set::{Ordered, OrderedAssociated};
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
    signer: C,
    bls_private_key: group::Private,
}

impl<C: Signer, V: Variant> SummitSchemeProvider<C, V> {
    pub fn new(signer: C, bls_private_key: group::Private) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            signer,
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
    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme;
}

impl<C: Signer, V: Variant> SchemeProvider for SummitSchemeProvider<C, V> {
    type Scheme = MultisigScheme<C, V>;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<MultisigScheme<C, V>>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }
}

impl<C: Signer, V: Variant> EpochSchemeProvider for SummitSchemeProvider<C, V> {
    type Variant = V;
    type PublicKey = C::PublicKey;
    type Scheme = MultisigScheme<C, V>;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        let participants: OrderedAssociated<Self::PublicKey, V::Public> = transition
            .dealers
            .iter()
            .cloned()
            .zip(transition.bls_keys.iter().cloned())
            .collect();

        MultisigScheme::<C, V>::new(participants, self.bls_private_key.clone())
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, P: PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The dealers for the epoch (identity keys).
    pub dealers: Ordered<P>,
    /// The BLS public keys for the epoch.
    /// Contains the BLS public keys corresponding to each dealer.
    pub bls_keys: Vec<V::Public>,
}
