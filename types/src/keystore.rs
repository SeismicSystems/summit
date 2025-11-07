use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::PrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyStore<C: Signer + ZeroizeOnDrop> {
    pub node_key: C,
    pub consensus_key: PrivateKey,
}

// TODO(matthias): do we have to explicitly call zeroize() on the members?
