use commonware_cryptography::Signer;
use commonware_cryptography::bls12381::PrivateKey;

pub struct KeyStore<C: Signer> {
    pub node_key: C,
    pub consensus_key: PrivateKey,
}
