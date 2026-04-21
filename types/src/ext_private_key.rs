use crate::{PrivateKey, PublicKey, Signature};
use commonware_cryptography::Signer;
use commonware_math::algebra::Random;
use rand_core::CryptoRngCore;

/// Wraps the ed25519 [`PrivateKey`] used by the networking layer.
#[derive(Clone)]
pub struct ExtPrivateKey {
    pub private_key: PrivateKey,
}

impl ExtPrivateKey {
    pub fn new(private_key: PrivateKey) -> Self {
        Self { private_key }
    }
}

impl Random for ExtPrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            private_key: PrivateKey::random(rng),
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
