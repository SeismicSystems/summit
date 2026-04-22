use crate::{PrivateKey, PublicKey, Signature};
use commonware_cryptography::Signer;
use commonware_math::algebra::Random;
use rand_core::CryptoRngCore;

/// An extended private key derived from a base [`PrivateKey`] and a derivation index.
/// Used by observer nodes to obtain a distinct identity without provisioning a separate key.
#[derive(Clone)]
pub struct ExtPrivateKey {
    pub private_key: PrivateKey,
    pub index: u32,
}

impl ExtPrivateKey {
    pub fn new(private_key: PrivateKey, index: u32) -> Self {
        Self { private_key, index }
    }
}

impl Random for ExtPrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            private_key: PrivateKey::random(rng),
            index: 0,
        }
    }
}

impl Signer for ExtPrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.private_key.public_key()
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.private_key.sign(namespace, msg)
    }
}
