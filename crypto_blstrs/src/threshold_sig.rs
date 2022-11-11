use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hasher;
use std::ops::Mul;

use crypto::{anyhow, Polynomial};
use anyhow::{ensure, Result};
use blstrs::{Bls12, G2Affine, G2Projective, G1Affine, G2Prepared, G1Projective, Scalar};
use digest::Digest;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use group::prime::PrimeCurveAffine;
use group::ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};

use crypto::threshold_sig::{CombinableSignature, PartialKey, PublicKey, SamplableKey, SecretKey, SharableKey, Signature};
use crate::blstrs_lagrange_G2Projective;
use crate::polynomial::BlstrsPolynomial;

/// BLS12-381 Secret key
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlstrsSecretKey {
    pub sk: Scalar
}

impl BlstrsSecretKey {
    fn new(sk: Scalar) -> Self {
        Self { sk }
    }

}

impl std::hash::Hash for BlstrsSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sk.to_bytes_le().hash(state)
    }
}

impl SecretKey for BlstrsSecretKey {
    type PK = BlstrsPublicKey;
    type Sig = BlstrsSignature;

    fn to_pk(&self) -> Self::PK {
        Self::PK::new(G1Affine::generator().mul(&self.sk).into())
    }

    fn sign<M: AsRef<[u8]>, D: Display>(&self, msg: M, dst: D) -> Self::Sig {
        let dst = format!("{}-with-expander-SHA256-128", dst);
        Self::Sig::new(G2Affine::from(G2Projective::hash_to_curve(msg.as_ref(), dst.as_bytes(), &[]).mul(&self.sk)))
    }
}

impl SamplableKey for BlstrsSecretKey {
    fn sample() -> Self {
        Self{ sk: Scalar::random(OsRng) }
    }
}

/// BLS12-381 Public key
#[derive(Debug, Copy, Clone, Default, Eq, Serialize, Deserialize)]
pub struct BlstrsPublicKey {
    pub pk: G1Affine,
}

impl BlstrsPublicKey {
    pub fn new(pk: G1Affine) -> Self {
        Self { pk }
    }
}

impl std::hash::Hash for BlstrsPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.to_compressed().hash(state)
    }
}

impl PartialEq for BlstrsPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk.to_compressed() == other.pk.to_compressed()
    }
}

impl PublicKey for BlstrsPublicKey {
    type SK = BlstrsSecretKey;
    type Sig = BlstrsSignature;

    fn verify<M: AsRef<[u8]>, D: Display>(&self, sig: &Self::Sig, msg: M, dst: D) -> bool {
        let dst = format!("{}-with-expander-SHA256-128", dst);
        let res = Bls12::multi_miller_loop(&[ (&-G1Affine::generator(), &G2Prepared::from(sig.sig)), (&self.pk, &G2Prepared::from(G2Projective::hash_to_curve(msg.as_ref(), dst.as_bytes(), &[]).to_affine())) ]).final_exponentiation();  // SED REPLACE 2A
        res.is_identity().into()
    }
}

impl From<BlstrsPublicKey> for G1Affine {
    fn from(pk: BlstrsPublicKey) -> Self {
        pk.pk
    }
}

/// BLS12-381 Signature
#[derive(Debug, Copy, Clone, Default, Eq, Serialize, Deserialize)]
pub struct BlstrsSignature {
    sig: G2Affine,
}

impl BlstrsSignature {
    fn new(sig: G2Affine) -> Self {
        Self { sig }
    }
}

impl std::hash::Hash for BlstrsSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sig.to_compressed().hash(state)
    }
}

impl PartialEq for BlstrsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig.to_compressed() == other.sig.to_compressed()
    }
}

impl Signature for BlstrsSignature {
    fn sha256_hash(&self) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(self.sig.to_compressed());
        hash.finalize().to_vec()
    }
}

/// Partial wrapper that adds an index to the contained data
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct Partial<T>
{
    idx: usize,
    pub data: T,
}

impl<T> PartialKey for Partial<T> {
    fn index(&self) -> usize {
        self.idx - 1
    }
}

impl<T> Partial<T> {
    pub fn new(idx: usize, data: T) -> Self {
        Self { idx, data }
    }
}

/// Partial BLS12-381 secret key
pub type PartialBlstrsSecretKey = Partial<BlstrsSecretKey>;

impl SecretKey for PartialBlstrsSecretKey {
    type PK = PartialBlstrsPublicKey;
    type Sig = PartialBlstrsSignature;

    fn to_pk(&self) -> Self::PK {
        PartialBlstrsPublicKey::new(self.idx, self.data.to_pk())
    }

    fn sign<M: AsRef<[u8]>, D: Display>(&self, msg: M, dst: D) -> Self::Sig {
        PartialBlstrsSignature::new(self.idx, self.data.sign(msg, dst))
    }
}

impl PartialBlstrsSecretKey {
    pub fn add(&mut self, x: &Scalar) {
        self.data.sk += x;
    }
}

/// Partial BLS12-381 public key
pub type PartialBlstrsPublicKey = Partial<BlstrsPublicKey>;

impl PublicKey for PartialBlstrsPublicKey {
    type SK = PartialBlstrsSecretKey;
    type Sig = PartialBlstrsSignature;

    fn verify<M: AsRef<[u8]>, D: Display>(&self, sig: &Self::Sig, msg: M, dst: D) -> bool {
        self.idx == sig.idx && self.data.verify(&sig.data, msg, dst)
    }
}

impl PartialBlstrsPublicKey {
    pub fn add(&mut self, x: &G1Projective) {
        self.data.pk = (self.data.pk + x).to_affine();
    }
}

/// Partial BLS12-381 signature
pub type PartialBlstrsSignature = Partial<BlstrsSignature>;

impl Signature for PartialBlstrsSignature {
    fn sha256_hash(&self) -> Vec<u8> {
        self.data.sha256_hash()
    }
}

impl SharableKey for BlstrsSecretKey {
    type PSK = PartialBlstrsSecretKey;

    fn share(self, n: usize, threshold: usize) -> Vec<Self::PSK> {
        let poly = BlstrsPolynomial::sample(threshold - 1, HashMap::from_iter(vec![(0, self.sk)]));
        (1..=n).map(|i| PartialBlstrsSecretKey::new(i, Self::new(poly.eval(&Scalar::from(i as u64))))).collect()
    }
}

impl CombinableSignature for BlstrsSignature {
    type SK = BlstrsSecretKey;
    type PK = BlstrsPublicKey;
    type PSK = PartialBlstrsSecretKey;
    type PPK = PartialBlstrsPublicKey;
    type PSig = PartialBlstrsSignature;

    fn combine(threshold: usize, sigs: Vec<Self::PSig>) -> Result<Self> {
        ensure!(sigs.len() >= threshold, "Not enough sigs!");
        let xs = sigs.iter().map(|x|  Scalar::from(x.idx as u64)).collect();
        let ys = sigs.into_iter().map(|x| G2Projective::from(x.data.sig)).collect();
        Ok(Self::new(blstrs_lagrange_G2Projective(&xs, ys, &Scalar::zero()).to_affine()))
    }
}

#[cfg(test)]
pub mod tests {
    use std::ops::BitAnd;

    use bincode;
    use crypto::threshold_sig::SignatureSet;

    use super::*;

    #[test]
    pub fn test_sign() {
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let sig = sk.sign("test", "None");
        assert!(pk.verify(&sig, "test", "None"))
    }

    #[test]
    pub fn test_sign_dst_fail() {
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let sig = sk.sign("test", "None");
        assert!(!pk.verify(&sig, "test", "Some"))
    }

    #[test]
    pub fn test_sign_msg_fail() {
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let sig = sk.sign("test2", "None");
        assert!(!pk.verify(&sig, "test", "None"))
    }

    #[test]
    pub fn test_threshold_sign() {
        let n = 10;
        let d = 7;
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let psks = sk.share(n, d);
        let ppks: Vec<_> = psks.iter().map(PartialBlstrsSecretKey::to_pk).collect();

        let msg = "test";
        let dst = "Test";
        let psigs: Vec<PartialBlstrsSignature> = psks.iter().take(d).map(|psk| psk.sign(&msg, &dst)).collect();
        assert!(ppks.iter().zip(psigs.iter()).map(|(ppk, psig)| ppk.verify(psig, &msg, &dst)).fold(true, bool::bitand));

        let sig = BlstrsSignature::combine(d, psigs).unwrap();
        assert!(pk.verify(&sig, &msg, &dst))
    }

    #[test]
    pub fn test_threshold_sign_set() {
        let n = 10;
        let d = 7;
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let psks = sk.share(n, d);
        let ppks: Vec<_> = psks.iter().map(PartialBlstrsSecretKey::to_pk).collect();

        let msg = "test";
        let dst = "Test";
        let psigs: Vec<_>  = psks.iter().take(d).map(|psk| psk.sign(&msg, &dst)).collect();
        assert!(ppks.iter().zip(psigs.iter()).map(|(ppk, psig)| ppk.verify(psig, &msg, &dst)).fold(true, bool::bitand));

        let mut set = SignatureSet::new(d, &msg, &dst);
        for (ppk, psig) in ppks.iter().zip(psigs.into_iter()) {
            set.insert(ppk, psig);
        }

        let sig = set.combine().unwrap();
        assert!(pk.verify(&sig, &msg, &dst))
    }

    #[test]
    pub fn test_threshold_sign_all() {
        let n = 10;
        let d = 7;
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let psks = sk.share(n, d);
        let ppks: Vec<_> = psks.iter().map(PartialBlstrsSecretKey::to_pk).collect();

        let msg = "test";
        let dst = "Test";
        let psigs: Vec<PartialBlstrsSignature> = psks.iter().map(|psk| psk.sign(&msg, &dst)).collect();
        assert!(ppks.iter().zip(psigs.iter()).map(|(ppk, psig)| ppk.verify(psig, &msg, &dst)).fold(true, bool::bitand));

        let sig = BlstrsSignature::combine(d, psigs).unwrap();
        assert!(pk.verify(&sig, &msg, &dst))
    }

    #[test]
    pub fn test_threshold_fail() {
        let n = 10;
        let d = 7;
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let psks = sk.share(n, d);

        let msg = "test";
        let dst = "Test";
        let psigs: Vec<PartialBlstrsSignature> = psks.iter().take(d).map(|psk| psk.sign(&msg, &dst)).collect();

        let sig = BlstrsSignature::combine(d, psigs).unwrap();
        assert!(!pk.verify(&sig, "test2", &dst))
    }

    #[test]
    pub fn test_serialize() {
        let sk = BlstrsSecretKey::sample();
        let pk = sk.to_pk();
        let ser = bincode::serialize(&sk).unwrap();
        let serpk = bincode::serialize(&pk).unwrap();
        assert_eq!(sk, bincode::deserialize(&ser[..]).unwrap());
        assert_eq!(pk, bincode::deserialize(&serpk[..]).unwrap());
    }
}
