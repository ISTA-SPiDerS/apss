use std::ops::Mul;
use anyhow::{ensure, Result};
use blstrs::{G1Projective, Scalar};
use group::Group;
use serde::{Serialize, Deserialize};
use crypto::{PolyCommit, Polynomial};
use crate::polynomial::BlstrsPolynomial;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlstrsFeldman {
    generator: G1Projective,
    max_degree: usize,
}

impl BlstrsFeldman {
    pub fn new(max_degree: usize, parameters: G1Projective) -> Self {
        Self { max_degree, generator: parameters }
    }
}
impl PolyCommit for BlstrsFeldman {
    type Field = Scalar;
    type Group = G1Projective;
    type Polynomial = BlstrsPolynomial;
    type Commitment = Vec<G1Projective>;
    type Witness = ();

    fn commit(&self, poly: &Self::Polynomial) -> Result<Self::Commitment> {
        ensure!(poly.degree() <= self.max_degree, "Polynomial degree is too large!");
        let mut commitment = Vec::with_capacity(poly.degree());
        for coeff in poly.iter() {
            commitment.push(self.generator.mul(coeff));
        }
        Ok(commitment)
    }

    fn open(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Field, Self::Witness)> {
        ensure!(poly.degree() <= self.max_degree, "Polynomial degree is too large!");
        let eval = poly.eval(x);
        Ok((eval, ()))
    }

    fn open_commit(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Group, Self::Witness)> {
        let (y, witness) = self.open(poly, x)?;
        Ok((self.generator.mul(y), witness))
    }


    fn verify(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Field, witness: &Self::Witness) -> bool {
        self.verify_from_commitment(commitment, x, &self.generator.mul(value), witness)
    }

    #[allow(unused_variables)]
    // TODO this isn't really used in the code but this is slow and should be changed to multi exp.
    fn verify_from_commitment(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Group, witness: &Self::Witness) -> bool {
        if commitment.len() == 0 {
            return value == &G1Projective::identity();
        }

        let mut x_pows = x.clone();
        let mut sum = commitment[0].clone();
        for i in 1..commitment.len() {
            sum += commitment[i].mul(&x_pows);
            x_pows *= x;
        }
        value == &sum
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn test_feldman() {
        let poly = BlstrsPolynomial::sample(5, HashMap::new());
        let pp = BlstrsFeldman::new(8, G1Projective::generator());
        let comm = pp.commit(&poly).unwrap();
        let (value, open) = pp.open(&poly, &Scalar::from(42)).unwrap();
        assert!(pp.verify(&comm, &Scalar::from(42), &value, &open));
        assert!(!pp.verify(&comm, &Scalar::from(41), &value, &open));
    }
}
