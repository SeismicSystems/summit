use crate::{PrivateKey, PublicKey, Signature};
use commonware_codec::{DecodeExt, Encode, ReadExt as _};
use commonware_cryptography::{Secret, Signer};
use commonware_math::algebra::Random;
use commonware_utils::union_unique;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};

const DERIVE_TAG: &[u8] = b"ed25519-additive-derive/tweak/v1";
const PREFIX_TAG: &[u8] = b"ed25519-additive-derive/prefix/v1";

#[derive(Clone)]
struct ExtPrivateKeyInner {
    scalar: Scalar,
    prefix: [u8; 32],
}

/// An extended private key derived from a base [`PrivateKey`] and a derivation index.
/// Taken from this POC: https://github.com/daltoncoder/commonware-ed25519-child-derivation-poc
#[derive(Clone)]
pub struct ExtPrivateKey {
    secrets: Secret<ExtPrivateKeyInner>,
    #[allow(unused)]
    index: u32,
}

impl ExtPrivateKey {
    pub fn derive_child_signer(private_key: &PrivateKey, index: u32) -> Self {
        let path = format!("m/seismic/observer/{}", index).into_bytes();
        let seed_vec = private_key.encode();
        let master_pk = private_key.public_key();
        let master_pub: [u8; 32] = master_pk.as_ref().try_into().unwrap();

        let master_seed: [u8; 32] = seed_vec.as_ref().try_into().unwrap();
        let (scalar, master_prefix) = expand_seed(&master_seed);
        let t = compute_tweak(&master_pub, &path);
        let scalar_child = scalar + t;

        let mut h = Sha512::new();
        h.update(PREFIX_TAG);
        h.update(master_prefix);
        h.update(t.as_bytes());
        let out: [u8; 64] = h.finalize().into();
        let mut child_prefix = [0u8; 32];
        child_prefix.copy_from_slice(&out[..32]);

        Self {
            secrets: Secret::new(ExtPrivateKeyInner {
                scalar: scalar_child,
                prefix: child_prefix,
            }),
            index,
        }
    }
}

impl Random for ExtPrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        let master = PrivateKey::random(rng);
        ExtPrivateKey::derive_child_signer(&master, 0)
    }
}

impl Signer for ExtPrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.secrets.expose(|inner| {
            let bytes = (inner.scalar * ED25519_BASEPOINT_POINT).compress().0;
            PublicKey::decode(bytes.as_ref()).expect("child pubkey is a valid Ed25519 point")
        })
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        let payload = union_unique(namespace, msg);
        let pubkey = self.public_key();

        self.secrets.expose(|inner| {
            let mut hr = Sha512::new();
            hr.update(inner.prefix);
            hr.update(&payload);
            let r_bytes: [u8; 64] = hr.finalize().into();
            let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

            let r_point = (r * ED25519_BASEPOINT_POINT).compress();

            let mut hk = Sha512::new();
            hk.update(r_point.as_bytes());
            hk.update(pubkey);
            hk.update(&payload);
            let k_bytes: [u8; 64] = hk.finalize().into();
            let k = Scalar::from_bytes_mod_order_wide(&k_bytes);

            let s = r + k * inner.scalar;

            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(r_point.as_bytes());
            sig[32..].copy_from_slice(s.as_bytes());
            let mut sig_buf = &sig[..];
            Signature::read(&mut sig_buf).expect("invalid signature bytes")
        })
    }
}

pub fn derive_child_public(master_pk: PublicKey, index: u32) -> PublicKey {
    let path = format!("m/seismic/observer/{}", index).into_bytes();
    let master_pub: [u8; 32] = master_pk.as_ref().try_into().unwrap();
    let a_point = CompressedEdwardsY(master_pub)
        .decompress()
        .expect("pubkey is y-coordinate of curve point");
    let t = compute_tweak(&master_pub, &path);
    let t_point = t * ED25519_BASEPOINT_POINT;
    let bytes = (a_point + t_point).compress().0;
    PublicKey::decode(bytes.as_ref()).expect("child pubkey is a valid Ed25519 point")
}

/// For each validator master pubkey, derive the first `n` child pubkeys via
/// [`derive_child_public`] and flatten into a single list.
pub fn derive_observer_keys(validator_pks: &[PublicKey], n: u32) -> Vec<PublicKey> {
    validator_pks
        .iter()
        .flat_map(|pk| (0..n).map(move |i| derive_child_public(pk.clone(), i)))
        .collect()
}

fn expand_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let h = Sha512::digest(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..]);
    (a, prefix)
}

fn compute_tweak(master_pub: &[u8; 32], path: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(DERIVE_TAG);
    h.update(master_pub);
    h.update(path);
    let out: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Verifier;
    use rand_core::OsRng;

    #[test]
    fn test_derived_pubkey_matches() {
        // Create master key
        let master_sk = PrivateKey::random(&mut OsRng);
        let master_pk = master_sk.public_key();

        // Derive first child
        let child_index = 0;
        let child_sk = ExtPrivateKey::derive_child_signer(&master_sk, child_index);
        let child_pk = child_sk.public_key();

        // Verify child is derived from master
        let pub_derived_child = derive_child_public(master_pk, child_index);

        assert_eq!(pub_derived_child, child_pk);
    }

    #[test]
    fn test_signing() {
        let namespace: &[u8] = b"demo";
        let msg: &[u8] = b"hello, world!";

        // Create master key
        let master_sk = PrivateKey::random(&mut OsRng);
        let master_pk = master_sk.public_key();

        // Derive first child
        let child_index = 0;
        let child_sk = ExtPrivateKey::derive_child_signer(&master_sk, child_index);
        let child_pk = child_sk.public_key();

        // Sign message with child key
        let sig = child_sk.sign(namespace, msg);

        // Verify signature with both pubkeys
        let pub_derived_child = derive_child_public(master_pk, child_index);
        assert!(child_pk.verify(namespace, msg, &sig));
        assert!(pub_derived_child.verify(namespace, msg, &sig));
    }

    #[test]
    fn test_siblings_different() {
        // Create master key
        let master_sk = PrivateKey::random(&mut OsRng);

        // Derive first child
        let child_index = 0;
        let first_child_sk = ExtPrivateKey::derive_child_signer(&master_sk, child_index);
        let first_child_pk = first_child_sk.public_key();

        // Derive the second child
        let child_index = 1;
        let second_child_sk = ExtPrivateKey::derive_child_signer(&master_sk, child_index);
        let second_child_pk = second_child_sk.public_key();

        // Verify that different indices lead to different derived child keys
        assert_ne!(first_child_pk, second_child_pk);
    }

    #[test]
    fn test_derivation_deterministic() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let child_a = ExtPrivateKey::derive_child_signer(&master_sk, 42);
        let child_b = ExtPrivateKey::derive_child_signer(&master_sk, 42);

        assert_eq!(child_a.public_key(), child_b.public_key());

        let sig_a = child_a.sign(b"ns", b"msg");
        let sig_b = child_b.sign(b"ns", b"msg");
        assert_eq!(sig_a.encode().as_ref(), sig_b.encode().as_ref());
    }

    #[test]
    fn test_different_masters_different_children() {
        let master_a = PrivateKey::random(&mut OsRng);
        let master_b = PrivateKey::random(&mut OsRng);
        let index = 0;

        let child_a = ExtPrivateKey::derive_child_signer(&master_a, index);
        let child_b = ExtPrivateKey::derive_child_signer(&master_b, index);

        assert_ne!(child_a.public_key(), child_b.public_key());
    }

    #[test]
    fn test_wrong_index_verify_fails() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let master_pk = master_sk.public_key();
        let signer = ExtPrivateKey::derive_child_signer(&master_sk, 5);
        let sig = signer.sign(b"ns", b"msg");

        let wrong_pk = derive_child_public(master_pk, 6);
        assert!(!wrong_pk.verify(b"ns", b"msg", &sig));
    }

    #[test]
    fn test_wrong_master_verify_fails() {
        let master_a = PrivateKey::random(&mut OsRng);
        let master_b = PrivateKey::random(&mut OsRng);
        let index = 0;

        let signer = ExtPrivateKey::derive_child_signer(&master_a, index);
        let sig = signer.sign(b"ns", b"msg");

        let wrong_pk = derive_child_public(master_b.public_key(), index);
        assert!(!wrong_pk.verify(b"ns", b"msg", &sig));
    }

    #[test]
    fn test_tampered_message_verify_fails() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let signer = ExtPrivateKey::derive_child_signer(&master_sk, 0);
        let pubkey = signer.public_key();
        let sig = signer.sign(b"ns", b"original");

        assert!(!pubkey.verify(b"ns", b"tampered", &sig));
        assert!(!pubkey.verify(b"other", b"original", &sig));
    }

    #[test]
    fn test_clone_equivalence() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let original = ExtPrivateKey::derive_child_signer(&master_sk, 7);
        let cloned = original.clone();

        assert_eq!(original.public_key(), cloned.public_key());

        let sig_original = original.sign(b"ns", b"msg");
        let sig_cloned = cloned.sign(b"ns", b"msg");
        assert_eq!(sig_original.encode().as_ref(), sig_cloned.encode().as_ref());
    }

    #[test]
    fn test_empty_namespace_and_msg() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let signer = ExtPrivateKey::derive_child_signer(&master_sk, 0);
        let pubkey = signer.public_key();

        let sig = signer.sign(b"", b"");
        assert!(pubkey.verify(b"", b"", &sig));
    }

    #[test]
    fn test_index_boundaries() {
        let master_sk = PrivateKey::random(&mut OsRng);
        let child_min = ExtPrivateKey::derive_child_signer(&master_sk, 0);
        let child_max = ExtPrivateKey::derive_child_signer(&master_sk, u32::MAX);

        assert_ne!(child_min.public_key(), child_max.public_key());
    }
}
