use std::ops::{Mul, Sub};
use serde::{Serialize, Deserialize};
use anyhow::{ensure, Result};
use blstrs::{Bls12, G2Projective, G1Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::Engine;
use rand::rngs::OsRng;
use crypto::{PolyCommit, Polynomial};
use crate::polynomial::BlstrsPolynomial;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlstrsKZG {
    powers_of_tau: Vec<G1Projective>,
    g2_tau: G2Projective,
    generators: (G1Projective, G2Projective),
}

impl BlstrsKZG {
    pub fn new(max_degree: usize, generators: (G1Projective, G2Projective)) -> Self {
        let tau = Scalar::random(OsRng);
        let g2_tau = generators.1.mul(&tau);
        let powers_of_tau = powers_of_tau(max_degree, &generators.0, &tau);
        Self { generators, powers_of_tau, g2_tau }
    }
}

impl PolyCommit for BlstrsKZG {
    type Field = Scalar;
    type Group = G1Projective;
    type Polynomial = BlstrsPolynomial;
    type Commitment = G1Projective;
    type Witness = G1Projective;

    fn commit(&self, poly: &Self::Polynomial) -> Result<Self::Commitment> {
        ensure!(poly.degree().overflowing_add(1).0 <= self.powers_of_tau.len(), "Polynomial degree too large!");
        Ok(eval_poly_at_tau(&self.powers_of_tau, poly))
    }

    fn open(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Field, Self::Witness)> {
        ensure!(poly.degree().overflowing_add(1).0 <= self.powers_of_tau.len(), "Polynomial degree too large!");
        let divisor = Self::Polynomial::from(vec![-x.clone(), Scalar::one()]);
        let eval = poly.eval(x);
        let dividend = poly.clone() + Self::Polynomial::new(vec![-eval.clone()]);
        let witness = dividend.div_ref(&divisor).unwrap();
        Ok((eval, eval_poly_at_tau(&self.powers_of_tau, &witness)))
    }

    fn open_commit(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Group, Self::Witness)> {
        let (y, witness) = self.open(poly, x)?;
        Ok((self.generators.0.mul(y), witness))
    }

    fn verify(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Field, witness: &Self::Witness) -> bool {
        self.verify_from_commitment(commitment, x, &self.generators.0.mul(value), witness)
    }

    fn verify_from_commitment(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Group, witness: &Self::Witness) -> bool {
        Bls12::pairing(&commitment.sub(value).to_affine(), &self.generators.1.to_affine()) == Bls12::pairing(&witness.to_affine(), &self.g2_tau.sub(&self.generators.1.mul(x)).to_affine())  // SED REPLACE 1A
    }
}

fn powers_of_tau(max_degree: usize, generator: &G1Projective, tau: &Scalar) -> Vec<G1Projective> {
    let mut powers_of_tau = Vec::with_capacity(max_degree + 1);
    let mut exp = Scalar::one();
    for _ in 0..=max_degree {
        powers_of_tau.push(generator.mul(&exp));
        exp *= tau;
    }
    powers_of_tau
}

fn eval_poly_at_tau(powers_of_tau: &Vec<G1Projective>, poly: &BlstrsPolynomial) -> G1Projective {
    powers_of_tau.iter().zip(poly.iter())
        .map(|(x, y)| x.mul(y)).fold(G1Projective::identity(), std::ops::Add::add)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn test_powers_of_tau() {
        let max_degree = 3u64;
        let powers = powers_of_tau(max_degree as usize, &G1Projective::generator(), &Scalar::from(2));
        let should_powers: Vec<_> = (0u64..=max_degree).map(|i| G1Projective::generator().mul(Scalar::from(2).pow_vartime([i]))).collect();
        assert_eq!(powers, should_powers)
    }

    #[test]
    fn test_eval_poly_at_tau() {
        let max_degree = 3u64;
        let powers = powers_of_tau(max_degree as usize, &G1Projective::generator(), &Scalar::from(2));
        let poly = BlstrsPolynomial::sample(2, HashMap::new());
        let eval = poly.eval(&Scalar::from(2));
        assert_eq!(eval_poly_at_tau(&powers, &poly), G1Projective::generator().mul(eval))
    }

    #[test]
    fn test_kzg() {
        let poly = BlstrsPolynomial::sample(5, HashMap::new());
        let pp = BlstrsKZG::new(8, (G1Projective::generator(), G2Projective::generator()));
        let comm = pp.commit(&poly).unwrap();
        let (value, open) = pp.open(&poly, &Scalar::from(42)).unwrap();
        assert!(pp.verify(&comm, &Scalar::from(42), &value, &open));
        assert!(!pp.verify(&comm, &Scalar::from(41), &value, &open));
    }
}
