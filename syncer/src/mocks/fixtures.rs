//! Deterministic test fixtures for `simplex` signing scheme.
//!
//! Copied from commonware_consensus::simplex::mocks::fixtures since that module
//! is gated behind #[cfg(test)] and not available to external crates.

use commonware_consensus::simplex::scheme::{
    bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme,
};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg,
        primitives::{group, sharing::Mode, variant::Variant},
    },
    ed25519,
};
use commonware_math::algebra::Random;
use commonware_utils::N3f1;
use commonware_utils::ordered::{BiMap, Map};
use rand::{CryptoRng, RngCore};

/// A test fixture consisting of ed25519 keys and signing schemes for each validator, and a single
/// scheme verifier.
pub struct Fixture<S> {
    /// A sorted vector of participant public keys.
    pub participants: Vec<ed25519::PublicKey>,
    /// A vector of signing schemes for each participant.
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

/// Generates ed25519 participants.
pub fn ed25519_participants<R>(rng: &mut R, n: u32) -> Map<ed25519::PublicKey, ed25519::PrivateKey>
where
    R: RngCore + CryptoRng,
{
    let mut pairs = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let private_key = ed25519::PrivateKey::random(&mut *rng);
        let public_key = private_key.public_key();
        pairs.push((public_key, private_key));
    }
    Map::from_iter_dedup(pairs)
}

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn ed25519<R>(rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    const NAMESPACE: &[u8] = b"test";
    let ed25519_associated = ed25519_participants(rng, n);
    let participants = ed25519_associated.keys().clone();

    let schemes = ed25519_associated
        .into_iter()
        .filter_map(|(_, sk)| ed_scheme::Scheme::signer(NAMESPACE, participants.clone(), sk))
        .collect();
    let verifier = ed_scheme::Scheme::verifier(NAMESPACE, participants.clone());

    Fixture {
        participants: participants.into(),
        schemes,
        verifier,
    }
}

/// Builds ed25519 identities and matching BLS multisig schemes for tests.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn bls12381_multisig<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_multisig::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    const NAMESPACE: &[u8] = b"test";
    let participants = ed25519_participants(rng, n).into_keys();
    let mut bls_privates = Vec::with_capacity(n as usize);
    for _ in 0..n {
        bls_privates.push(group::Private::random(&mut *rng));
    }
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
        .collect();

    let signers_map = Map::from_iter_dedup(participants.clone().into_iter().zip(bls_public));
    let signers = BiMap::try_from(signers_map).expect("BLS public keys should be unique");
    let schemes: Vec<_> = bls_privates
        .into_iter()
        .filter_map(|sk| bls12381_multisig::Scheme::signer(NAMESPACE, signers.clone(), sk))
        .collect();
    let verifier = bls12381_multisig::Scheme::verifier(NAMESPACE, signers.clone());

    Fixture {
        participants: participants.into(),
        schemes,
        verifier,
    }
}

/// Builds ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns a [`Fixture`] whose keys and scheme instances share a consistent ordering.
pub fn bls12381_threshold<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_threshold::standard::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    const NAMESPACE: &[u8] = b"test";
    let participants = ed25519_participants(rng, n).into_keys();

    let (output, shares_map) =
        dkg::deal::<V, _, N3f1>(rng, Mode::NonZeroCounter, participants.clone())
            .expect("deal should succeed");
    let polynomial = output.public().clone();

    let schemes = shares_map
        .into_iter()
        .filter_map(|(_, share)| {
            bls12381_threshold::standard::Scheme::signer(
                NAMESPACE,
                participants.clone(),
                polynomial.clone(),
                share,
            )
        })
        .collect();
    let verifier = bls12381_threshold::standard::Scheme::verifier(
        NAMESPACE,
        participants.clone(),
        polynomial.clone(),
    );

    Fixture {
        participants: participants.into(),
        schemes,
        verifier,
    }
}
