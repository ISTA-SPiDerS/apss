use std::collections::HashMap;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use anyhow::Result;

pub use anyhow;
pub use num_traits::Zero;

pub mod threshold_sig;

/// Polynomial commitment
pub trait PolyCommit {
    type Field;
    type Group;
    type Polynomial: Polynomial<Field=Self::Field>;
    type Commitment;
    type Witness;

    fn commit(&self, poly: &Self::Polynomial) -> Result<Self::Commitment>;

    fn open(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Field, Self::Witness)>;

    fn open_commit(&self, poly: &Self::Polynomial, x: &Self::Field) -> Result<(Self::Group, Self::Witness)>;

    fn verify(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Field, witness: &Self::Witness) -> bool;

    fn verify_from_commitment(&self, commitment: &Self::Commitment, x: &Self::Field, value: &Self::Group, witness: &Self::Witness) -> bool;
}

/// Vector commitment
pub trait VecCommit {
    type Commitment;
    type Witness;

    fn commit<T: AsRef<[u8]>>(&self, vec: &Vec<T>) -> Result<Self::Commitment>;

    fn open<T: AsRef<[u8]>>(&self, vec: &Vec<T>, index: usize) -> Result<Self::Witness>;

    fn verify<T: AsRef<[u8]>>(&self, commitment: &Self::Commitment, index: usize, item: &T, witness: &Self::Witness) -> bool;
}

/// Polynomial
pub trait Polynomial:
    Sized
    + Clone
    + Into<Vec<Self::Field>>
    + IntoIterator<Item=Self::Field>
    + Add<Self, Output=Self>
    + Zero
{
    type Field;

    fn new(coeffs: Vec<Self::Field>) -> Self;

    fn eval(&self, x: &Self::Field) -> Self::Field;

    fn degree(&self) -> usize;

    fn sample(degree: usize, fixed_points: HashMap<usize, Self::Field>) -> Self;

    fn div_ref(&self, rhs: &Self) -> Result<Self>;

    fn iter(&self) -> std::slice::Iter<Self::Field>;
}

pub fn eval<G, S>(coeff: &Vec<G>, x: &S, zero: G) -> G
    where
        G: Clone,
        for<'a> G: AddAssign<&'a G>,
        for<'a> G: MulAssign<&'a S>,
{
    let mut b = match coeff.last() {
        None => return zero,
        Some(b) => b.clone(),
    };
    for c in coeff.iter().rev().skip(1) {
        b *= x;
        b += c;
    }
    b
}

pub fn interpolate<G, S>(xs: &Vec<S>, ys: Vec<G>, inv: fn(S) -> S, identity: G) -> Vec<G>
    where
        G: Clone + SubAssign<G>,
        for<'a> G: MulAssign<&'a S>,
        for<'a, 'b> &'a S: Sub<&'b S, Output=S>,
        for<'a, 'b> &'a G: Sub<&'b G, Output=G>
{
    assert_eq!(xs.len(), ys.len(), "xs and ys are not same length!");
    let mut polys: Vec<_> = ys.into_iter().map(|g| vec![g]).collect();
    let mul_poly = |poly: &mut Vec<G>, x| {
        poly.push(identity.clone());
        for l in (0..poly.len()).rev() {
            poly[l] *= x;
            let (m, overflow) = l.overflowing_sub(1);
            if !overflow {
                poly[l] = &poly[l] - &poly[m];
            }
        }
    };
    for j in 1..polys.len() {
        for (k, i) in (0..j).rev().enumerate() {
            let mut poly_j = polys[j-k].clone();
            mul_poly(&mut poly_j, &xs[i]);
            mul_poly(&mut polys[i], &xs[j]);
            let diff = inv(&xs[j] - &xs[i]);
            polys[i].iter_mut().zip(poly_j.into_iter()).for_each(|(x, y)| {
                *x -= y;
                *x *= &diff;
            });
        }
    }
    if polys.is_empty() {
        vec![]  // When no points given; P(x) = 0
    } else {
        polys.swap_remove(0)
    }
}

pub fn interpolate_at<G, S>(xs: &Vec<S>, ys: Vec<G>, x: &S, inv: fn(S) -> S, identity: G) -> G
    where
        G: Clone + SubAssign<G>,
        for<'a> G: MulAssign<&'a S>,
        for<'a, 'b> &'a G: Mul<&'b S, Output=G>,
        for<'a, 'b> &'a S: Sub<&'b S, Output=S>,
        for<'a, 'b> &'a G: Sub<&'b G, Output=G>
{
    assert_eq!(xs.len(), ys.len(), "xs and ys are not same length!");
    let mut polys = ys;
    for j in 1..polys.len() {
        for (k, i) in (0..j).rev().enumerate() {
            let poly_j = polys[j-k].mul(&(&xs[i]-x));
            polys[i] *= &(&xs[j]-x);
            let diff = inv(&xs[j] - &xs[i]);
            polys[i] -= poly_j;
            polys[i] *= &diff;
        }
    }
    if polys.is_empty() {
        identity
    } else {
        polys.swap_remove(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::*;
    use group::ff::Field;
    use group::Group;

    #[test]
    fn test_eval() {
        let coeff = vec![Scalar::from(2), Scalar::from(3), Scalar::from(5)];
        assert_eq!(eval(&coeff, &Scalar::from(0), Scalar::zero()), Scalar::from(2));
        assert_eq!(eval(&coeff, &Scalar::from(1), Scalar::zero()), Scalar::from(10));
        assert_eq!(eval(&coeff, &Scalar::from(2), Scalar::zero()), Scalar::from(2+3*2+5*4));

        let coeff = coeff.iter().map(|s| G2Projective::generator().mul(s)).collect();
        assert_eq!(eval(&coeff, &Scalar::from(0), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(2)));
        assert_eq!(eval(&coeff, &Scalar::from(1), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(10)));
        assert_eq!(eval(&coeff, &Scalar::from(2), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(2+3*2+5*4)));

        let coeff: Vec<Scalar> = vec![];
        assert_eq!(eval(&coeff, &Scalar::from(2), Scalar::zero()), Scalar::zero());
        let coeff: Vec<G2Projective> = vec![];
        assert_eq!(eval(&coeff, &Scalar::from(2), G2Projective::identity()), G2Projective::identity());
    }

    #[test]
    fn test_interpolate() {
        let xs: Vec<Scalar> = vec![];
        let ys: Vec<Scalar> = vec![];
        let poly = interpolate(&xs, ys.clone(), |s| s.invert().unwrap(), Scalar::zero());
        assert_eq!(poly.len(), 0);

        let xs: Vec<_> = vec![0u64, 1, 2, 3].into_iter().map(|i| Scalar::from(i)).collect();
        let ys: Vec<_> = vec![1u64, 3, 7, 11].into_iter().map(|i| Scalar::from(i)).collect();
        let poly = interpolate(&xs, ys.clone(), |s| s.invert().unwrap(), Scalar::zero());
        assert_eq!(poly.len(), 4);
        assert_eq!(eval(&poly, &Scalar::from(0), Scalar::zero()), Scalar::from(1));
        assert_eq!(eval(&poly, &Scalar::from(1), Scalar::zero()), Scalar::from(3));
        assert_eq!(eval(&poly, &Scalar::from(2), Scalar::zero()), Scalar::from(7));
        assert_eq!(eval(&poly, &Scalar::from(3), Scalar::zero()), Scalar::from(11));

        let ys = ys.iter().map(|s| G2Projective::generator().mul(s)).collect();
        let poly = interpolate(&xs, ys, |s| s.invert().unwrap(), G2Projective::identity());
        assert_eq!(poly.len(), 4);
        assert_eq!(eval(&poly, &Scalar::from(0), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(1)));
        assert_eq!(eval(&poly, &Scalar::from(1), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(3)));
        assert_eq!(eval(&poly, &Scalar::from(2), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(7)));
        assert_eq!(eval(&poly, &Scalar::from(3), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(11)));
    }

    #[test]
    fn test_interpolate_at() {
        let xs: Vec<_> = vec![0u64, 1, 2, 3].into_iter().map(|i| Scalar::from(i)).collect();
        let ys: Vec<_> = vec![1u64, 3, 7, 11].into_iter().map(|i| Scalar::from(i)).collect();
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(0), |s| s.invert().unwrap(), Scalar::zero()), Scalar::from(1));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(1), |s| s.invert().unwrap(), Scalar::zero()), Scalar::from(3));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(2), |s| s.invert().unwrap(), Scalar::zero()), Scalar::from(7));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(3), |s| s.invert().unwrap(), Scalar::zero()), Scalar::from(11));

        let ys: Vec<G2Projective> = ys.iter().map(|s| G2Projective::generator().mul(s)).collect();
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(0), |s| s.invert().unwrap(), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(1)));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(1), |s| s.invert().unwrap(), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(3)));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(2), |s| s.invert().unwrap(), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(7)));
        assert_eq!(interpolate_at(&xs, ys.clone(), &Scalar::from(3), |s| s.invert().unwrap(), G2Projective::identity()), G2Projective::generator().mul(Scalar::from(11)));
    }
}
