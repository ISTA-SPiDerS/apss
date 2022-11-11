use blstrs::{G2Projective, G1Projective, Scalar};
use blst::{blst_fr, blst_fr_from_scalar, blst_scalar};
use ff::Field;
use crypto::{PolyCommit, VecCommit, Polynomial};
use crypto::anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::poly_commit::kzg::BlstrsKZG;


/*
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlstrsKZGVecParams {
    pub generators: <BlstrsKZG as PolyCommit>::Parameters,
    pub dst: String,
}

impl BlstrsKZGVecParams {
    pub fn new(g2_gen: G1Projective, g1_gen: G2Projective, dst: String) -> Self {
        let generators = (g2_gen, g1_gen);
        Self { generators, dst }
    }
}

 */

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlstrsKZGVec {
    poly: BlstrsKZG,
    dst: String
}

impl BlstrsKZGVec {
    pub fn new(max_len: usize, generators: (G1Projective, G2Projective), dst: String) -> Self {
        Self { poly: BlstrsKZG::new(max_len - 1, generators), dst }
    }
}

impl VecCommit for BlstrsKZGVec {
    type Commitment = <BlstrsKZG as PolyCommit>::Commitment;
    type Witness = <BlstrsKZG as PolyCommit>::Witness;

    fn commit<T: AsRef<[u8]>>(&self, vec: &Vec<T>) -> Result<Self::Commitment> {
        let xs: Vec<_> = (0..vec.len()).map(|i| Scalar::from(i as u64)).collect();
        let ys: Vec<_> = vec.iter()
            .map(|y| hash_to_scalar(y.as_ref(), self.dst.as_bytes())).collect();
        let poly = Polynomial::new(crypto::interpolate(&xs, ys, |s| s.invert().unwrap(), Scalar::zero()));
        self.poly.commit(&poly)
    }

    fn open<T: AsRef<[u8]>>(&self, vec: &Vec<T>, index: usize) -> Result<Self::Witness> {
        let xs: Vec<_> = (0..vec.len()).map(|i| Scalar::from(i as u64)).collect();
        let ys: Vec<_> = vec.iter()
            .map(|y| hash_to_scalar(y.as_ref(), self.dst.as_bytes())).collect();
        let poly = Polynomial::new(crypto::interpolate(&xs, ys, |s| s.invert().unwrap(), Scalar::zero()));
        Ok(self.poly.open(&poly, &Scalar::from(index as u64))?.1)
    }

    fn verify<T: AsRef<[u8]>>(&self, commitment: &Self::Commitment, index: usize, item: &T, witness: &Self::Witness) -> bool {
        self.poly.verify(commitment, &Scalar::from(index as u64), &hash_to_scalar(item.as_ref(), self.dst.as_bytes()), witness)
    }
}

fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let scalar = blst_scalar::hash_to(msg, dst).expect("Hash failed!");
    let mut fr = blst_fr::default();
    unsafe {
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    let scalar = Scalar::from(fr);
    Scalar::from(scalar)
}

#[cfg(test)]
mod tests {
    use blstrs::G2Projective;
    use group::Group;
    use super::*;

    #[test]
    fn test_hash_to_scalar() {
        assert_eq!(hash_to_scalar("test".as_bytes(), "dst".as_bytes()), hash_to_scalar("test".as_bytes(), "dst".as_bytes()));
        assert_ne!(hash_to_scalar("test".as_bytes(), "dst".as_bytes()), hash_to_scalar("test".as_bytes(), "ds".as_bytes()));
        assert_ne!(hash_to_scalar("test".as_bytes(), "dst".as_bytes()), hash_to_scalar("tes".as_bytes(), "dst".as_bytes()));
    }

    #[test]
    fn test_vec_kzg() {
        let vec = vec!["This", "is", "a", "test", "!"];
        let pp = BlstrsKZGVec::new(8, (G1Projective::generator(), G2Projective::generator()), "DST".to_string());
        let comm = pp.commit(&vec).unwrap();
        let open = pp.open(&vec, 2).unwrap();
        assert!(pp.verify(&comm, 2, &"a", &open));
        assert!(!pp.verify(&comm, 3, &"a", &open));
    }
}
