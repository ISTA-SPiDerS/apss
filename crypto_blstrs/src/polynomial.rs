use std::collections::HashMap;
use std::vec;
use std::ops::{Add, Mul};
use blstrs::Scalar;
use ff::Field;
use serde::{Serialize, Deserialize};
use crypto::{eval, interpolate, Polynomial, Zero};
use crypto::anyhow::{Result, ensure};
use rand::rngs::OsRng;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlstrsPolynomial {
    coeffs: Vec<Scalar>
}

impl Polynomial for BlstrsPolynomial {
    type Field = Scalar;

    fn new(mut coeffs: Vec<Scalar>) -> Self {
        while Some(&Scalar::zero()) == coeffs.last() {
            coeffs.pop();
        }
        Self { coeffs }
    }

    fn eval(&self, x: &Scalar) -> Scalar {
        eval(&self.coeffs, x, Scalar::zero())
    }

    fn degree(&self) -> usize {
        self.coeffs.len().overflowing_sub(1).0
    }

    fn sample(degree: usize, mut fixed_points: HashMap<usize, Scalar>) -> Self {
        let degree_plus_one = degree.overflowing_add(1).0;
        assert!(fixed_points.len() <= degree_plus_one, "More fixed points than degree!");

        let mut ys = Vec::with_capacity(degree_plus_one);
        let mut xs = Vec::with_capacity(degree_plus_one);

        let mut i = 0;
        while fixed_points.len() < degree_plus_one {
            if !fixed_points.contains_key(&i) {
                let _ = fixed_points.insert(i, Scalar::random(OsRng));
            }
            i += 1;
        }

        for (x, y) in fixed_points {
            xs.push(Scalar::from(x as u64));
            ys.push(y);
        }

        Self::new(interpolate(&xs, ys, |s| s.invert().unwrap(), Scalar::zero()))
    }

    fn div_ref(&self, rhs: &Self) -> Result<Self> {
        ensure!(!rhs.is_zero(), "Division by 0!");
        if self.is_zero() || self.degree() < rhs.degree() {
            return Ok(Self::zero());
        }
        let d = rhs.degree();
        let mut q = vec![Scalar::zero(); self.degree() - d + 1];
        let mut r = self.clone();
        let c = rhs.coeffs.last().unwrap().invert().unwrap();

        while !r.is_zero() && r.degree() >= d {
            let s_coeff = r.coeffs.last().unwrap().mul(&c);
            let s_index = r.degree() - d;
            r = Self::new(r.coeffs.into_iter().enumerate().map(|(i, f)| {
                match i {
                    x if x >= s_index => {
                        let offset = x - s_index;
                        f - s_coeff.mul(&rhs.coeffs[offset])
                    },
                    _ => f
                }
            }).collect());
            q[s_index] = s_coeff;
        }
        Ok(Self::new(q))
    }

    fn iter(&self) -> std::slice::Iter<Scalar> {
            self.coeffs.iter()
    }
}

impl From<Vec<Scalar>> for BlstrsPolynomial {
    fn from(coeffs: Vec<Scalar>) -> Self {
        Self::new(coeffs)
    }
}

impl Into<Vec<Scalar>> for BlstrsPolynomial {
    fn into(self) -> Vec<Scalar> {
        self.coeffs
    }
}

impl Add<Self> for BlstrsPolynomial {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let self_coeffs: Vec<Scalar> = self.into();
        let rhs_coeffs: Vec<Scalar> = rhs.into();
        let (mut larger, smaller) = if self_coeffs.len() > rhs_coeffs.len() { (self_coeffs, rhs_coeffs) } else { (rhs_coeffs, self_coeffs) };
        for i in 0..smaller.len() {
            larger[i] += smaller[i];
        }
        Self::new(larger)
    }
}

impl Zero for BlstrsPolynomial {
    fn zero() -> Self {
        Self::new(vec![])
    }

    fn is_zero(&self) -> bool {
        self.degree() == usize::MAX
    }
}

impl IntoIterator for BlstrsPolynomial {
    type Item = Scalar;
    type IntoIter = vec::IntoIter<Scalar>;

    fn into_iter(self) -> Self::IntoIter {
        self.coeffs.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_is_zero() {
        assert!(BlstrsPolynomial::zero().is_zero())
    }

    #[test]
    fn test_degree() {
        let poly = BlstrsPolynomial::new(vec![]);
        assert_eq!(poly.degree(), usize::MAX);
        let poly = BlstrsPolynomial::new(vec![Scalar::from(1), Scalar::from(0)]);
        assert_eq!(poly.degree(), 0);
        let poly = BlstrsPolynomial::new(vec![Scalar::from(1), Scalar::from(2), Scalar::from(0), Scalar::from(0)]);
        assert_eq!(poly.degree(), 1);
        let poly = BlstrsPolynomial::from(vec![Scalar::from(2), Scalar::zero(), Scalar::from(8)]);
        assert_eq!(poly.degree(), 2);
    }

    #[test]
    fn test_eval() {
        let poly = BlstrsPolynomial::new(vec![Scalar::from(2), Scalar::from(3), Scalar::from(5)]);
        assert_eq!(poly.eval(&Scalar::from(0)), Scalar::from(2));
        assert_eq!(poly.eval(&Scalar::from(1)), Scalar::from(10));
        assert_eq!(poly.eval(&Scalar::from(2)), Scalar::from(2+3*2+5*4));
    }

    #[test]
    fn test_sample() {
        let poly = BlstrsPolynomial::sample(3, HashMap::from_iter(vec![(0, Scalar::from(1))]));
        assert_eq!(poly.degree(), 3);
        assert_eq!(poly.eval(&Scalar::from(0)), Scalar::from(1));
        let poly = BlstrsPolynomial::sample(usize::MAX, HashMap::new());
        assert_eq!(poly.degree(), usize::MAX);
    }

    #[test]
    fn test_div() {
        let poly = BlstrsPolynomial::new(vec![Scalar::from(10), Scalar::from(84), Scalar::from(46), Scalar::from(336), Scalar::from(24)]);
        let divisor = BlstrsPolynomial::from(vec![Scalar::from(2), Scalar::zero(), Scalar::from(8)]);
        let res = poly.div_ref(&divisor).unwrap();
        assert_eq!(res.coeffs, vec![Scalar::from(5), Scalar::from(42), Scalar::from(3)]);

    }

    #[test]
    fn test_add() {
        let a = BlstrsPolynomial::from(vec![Scalar::from(2), Scalar::zero(), Scalar::from(8)]);
        let b = BlstrsPolynomial::from(vec![Scalar::from(3), Scalar::from(2)]);
        let res = BlstrsPolynomial::from(vec![Scalar::from(5), Scalar::from(2), Scalar::from(8)]);
        assert_eq!(a.clone() + b.clone(), res);
        assert_eq!(b + a, res);

        let a = BlstrsPolynomial::from(vec![Scalar::from(2), Scalar::zero(), Scalar::from(8)]);
        let b = BlstrsPolynomial::zero();
        assert_eq!(a.clone() + b.clone(), a.clone());
        assert_eq!(b + a.clone(), a);

    }
}
