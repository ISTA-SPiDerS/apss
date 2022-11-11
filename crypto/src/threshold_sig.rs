use std::fmt::Display;
use std::collections::HashSet;

use anyhow::{ensure, Result};
use bincode::Options;
use serde::Serialize;

/// Convenience trait to turn an object into a value suitable for signing/verifying.
pub trait Signable {
    /// Prepares a value to be signable/verifiable.
    fn prepare(&self) -> Result<Vec<u8>>;

    // Like prepare but panics if it fails. This is useful in most cases.
    #[inline]
    fn prepare_panic(&self) -> Vec<u8> {
        self.prepare().expect("Prepare returned an error!")
    }
}

impl<T: Serialize> Signable for T {
    #[inline]
    fn prepare(&self) -> Result<Vec<u8>> {
        Ok(bincode::DefaultOptions::new().serialize(self)?)
    }
}

/// Trait returning the index of a share. The indices start at `0`.
pub trait PartialKey {
    fn index(&self) -> usize;
}

/// A public key
pub trait PublicKey {
    type SK: SecretKey<PK = Self>;
    type Sig: Signature;

    /// Takes a signature [sig], message [msg] and domain separation tag [dst] and outputs true
    /// if and only if the corresponding secret key signed [msg] under [dst].
    fn verify<M: AsRef<[u8]>, D: Display>(&self, sig: &Self::Sig, msg: M, dst: D) -> bool;
}

/// A secret key
pub trait SecretKey {
    type PK: PublicKey<SK = Self, Sig = Self::Sig>;
    type Sig: Signature;

    /// Returns the public key corresponding to this secret key.
    fn to_pk(&self) -> Self::PK;

    /// Signs message [msg] under domain separation tag [dst] with this secret key.
    fn sign<M: AsRef<[u8]>, D: Display>(&self, msg: M, dst: D) -> Self::Sig;
}

/// A secret key that can be sampled
pub trait SamplableKey: SecretKey {
    /// Samples a secret key
    fn sample() -> Self;
}

/// Threshold secret key
pub trait SharableKey: SecretKey {
    type PSK: SecretKey;

    /// Splits this secret key into [n] shares where [threshold] shares are required to create a
    /// signature under this secret key.
    fn share(self, n: usize, threshold: usize) -> Vec<Self::PSK>;
}

/// Threshold signature
pub trait CombinableSignature
    where
        Self: Signature + Sized
{
    type SK: SharableKey<PK = Self::PK, Sig = Self, PSK = Self::PSK> + SamplableKey;
    type PK: PublicKey<SK = Self::SK, Sig = Self>;
    type PSK: SecretKey<PK = Self::PPK, Sig = Self::PSig> + PartialKey;
    type PPK: PublicKey<SK = Self::PSK, Sig = Self::PSig> + PartialKey;
    type PSig: Signature;

    /// Takes a  [threshold] and a at least [threshold] partial signatures [sigs] and turns them
    /// into a signature.
    ///
    /// The partial signatures in [sigs] **must** be verified beforehand!
    fn combine(threshold: usize, sigs: Vec<Self::PSig>) -> Result<Self>;
}

pub struct SignatureSet<'a, 'c, T, M, D>
    where
        T: CombinableSignature,
        T::PPK: Eq + std::hash::Hash,
{
    keys: HashSet<&'a T::PPK>,
    sigs: Option<Vec<T::PSig>>,
    threshold: usize,
    msg: M,
    dst: &'c D,
}

impl<'a, 'c, T, M, D> SignatureSet<'a, 'c, T, M, D>
    where
        T: CombinableSignature,
        T::PPK: Eq + std::hash::Hash,
        M: AsRef<[u8]>,
        D: Display,
{
    pub fn new(threshold: usize, msg: M, dst: &'c D) -> Self {
        Self { keys: HashSet::with_capacity(threshold), sigs: Some(Vec::with_capacity(threshold)), threshold, msg, dst }
    }

    pub fn insert(&mut self, key: &'a T::PPK, sig: T::PSig) {
        if !self.keys.contains(&key) && key.verify(&sig, &self.msg, &self.dst) {
            self.keys.insert(key);
            if self.sigs.is_some() {
                let mut sigs = self.sigs.take().unwrap();
                sigs.push(sig);
                self.sigs = Some(sigs);
            }
        }
    }

    #[inline]
    pub fn can_combine(&self) -> bool {
        self.sigs.is_some() && self.sigs.as_ref().unwrap().len() >= self.threshold
    }

    pub fn combine(&mut self) -> Result<T> {
        ensure!(self.can_combine(), "Cannot combine yet!");
        T::combine(self.threshold, self.sigs.replace(Vec::new()).unwrap())
    }
}

pub trait Signature {
    /// Outputs the SHA256 hash of the signature.
    fn sha256_hash(&self) -> Vec<u8>;

    // TODO: maybe use rejection sampling here so we don't require powers of two (but not necessary for our usecase)
    /// Outputs a random value in the range [[min], [max]) based on the signature's [sha256_hash()]
    ///
    /// [min] - [max] must be positive and a power of two.
    fn rand_range(&self, min: usize, max: usize) -> Result<usize> {
        ensure!(min <= max, "min > max which is not allowed!");
        let interval = max - min;
        ensure!(interval.is_power_of_two(), "high-low is not a power of two!");

        let hash = self.sha256_hash();
        // Convert the hash bits to a usize. The try_into should never fail as we restrict it with size_of.
        // Then mask it with the bits we care about.
        let hash_val = usize::from_be_bytes(hash[..std::mem::size_of::<usize>()]
            .try_into().unwrap()) & (interval-1);

        Ok(min + hash_val)
    }

    /// Flips a random coin and outputs [true] with probability [p_true_num]/[p_true_denom] based on
    /// the signature's [sha256_hash()].
    ///
    /// [p_true_denom] must be a power of two.
    fn rand_coin(&self, p_true_num: usize, p_true_denom: usize) -> Result<bool> {
        ensure!(p_true_denom != 0, "Denominator can't be 0!");

        Ok(self.rand_range(0, p_true_denom)? < p_true_num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::Sha256;
    use sha2::Digest;

    struct FakeSig(String);

    impl Signature for FakeSig {
        fn sha256_hash(&self) -> Vec<u8> {
            let mut hash = Sha256::new();
            hash.update(&self.0.clone().into_bytes());
            hash.finalize().to_vec()
        }
    }
    #[test]
    fn test_rand_range() {
        let sig = FakeSig(String::from("Test"));
        // the 8th byte in the hash of sig is 13 and the last bits are 101 = 5.
        assert_eq!(sig.rand_range(5, 13).unwrap(), 10)
    }

    #[test]
    fn test_coin_range() {
        let sig = FakeSig(String::from("Test"));
        assert!(sig.rand_coin(6, 8).unwrap());
        assert!(!sig.rand_coin(5, 8).unwrap());
    }
}
