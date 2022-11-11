extern crate core;

use std::ops::{Mul, Sub};
pub use blstrs;
use blstrs::{G1Projective, G2Projective, Scalar};
pub use ff;
use ff::Field;
pub use group;
use group::Group;

pub mod polynomial;
pub mod threshold_sig;
pub mod poly_commit;
pub mod vector_commit;
pub mod dleq;

#[allow(non_snake_case)]
#[allow(unused)]
pub fn blstrs_eval_G1Projective(coeff: &Vec<G1Projective>, x: &Scalar) -> G1Projective {
    match coeff.len() {
        0 => return G1Projective::identity(),
        1 => return coeff[0],
        _ => {
            let mut scalars = Vec::with_capacity(coeff.len()-1);
            let mut xx = *x;
            for _ in 1..coeff.len() {
                scalars.push(xx);
                xx *= x;
            }
            G1Projective::multi_exp(&coeff[1..], scalars.as_slice()) + coeff[0]
        }
    }
}

#[allow(non_snake_case)]
#[allow(unused)]
pub fn blstrs_eval_G2Projective(coeff: &Vec<G2Projective>, x: &Scalar) -> G2Projective {
    match coeff.len() {
        0 => return G2Projective::identity(),
        1 => return coeff[0],
        _ => {
            let mut scalars = Vec::with_capacity(coeff.len()-1);
            let mut xx = *x;
            for _ in 1..coeff.len() {
                scalars.push(xx);
                xx *= x;
            }
            G2Projective::multi_exp(&coeff[1..], scalars.as_slice()) + coeff[0]
        }
    }
}

fn lagrange_helper(k: &Scalar, j: &Scalar, x: &Scalar) -> Scalar {
    x.sub(k).mul(j.sub(k).invert().unwrap())
}

fn lagrange(idxes: &Vec<Scalar>, j: &Scalar, x: &Scalar) -> Scalar {
    idxes.iter().filter_map(|k| {
        if k != j {
            Some(lagrange_helper(k, j, x))
        } else {
            None
        }
    }).product()
}

#[allow(non_snake_case)]
#[allow(unused)]
pub fn blstrs_lagrange_G1Projective<T: AsRef<Vec<G1Projective>>>(xs: &Vec<Scalar>, ys: T, z: &Scalar) -> G1Projective {
    let xs: Vec<_> = xs.iter().map(|x| lagrange(&xs, x, z)).collect();
    G1Projective::multi_exp(ys.as_ref().as_slice(), xs.as_slice())
}

#[allow(non_snake_case)]
#[allow(unused)]
pub fn blstrs_lagrange_G2Projective(xs: &Vec<Scalar>, ys: Vec<G2Projective>, z: &Scalar) -> G2Projective {
    let xs: Vec<_> = xs.iter().map(|x| lagrange(&xs, x, z)).collect();
    G2Projective::multi_exp(ys.as_slice(), xs.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval() {
        let coeff = vec![Scalar::from(2), Scalar::from(3), Scalar::from(5)];
        let coeff = coeff.iter().map(|s| G2Projective::generator().mul(s)).collect();
        assert_eq!(blstrs_eval_G2Projective(&coeff, &Scalar::from(0)), G2Projective::generator().mul(Scalar::from(2)));
        assert_eq!(blstrs_eval_G2Projective(&coeff, &Scalar::from(1)), G2Projective::generator().mul(Scalar::from(10)));
        assert_eq!(blstrs_eval_G2Projective(&coeff, &Scalar::from(2)), G2Projective::generator().mul(Scalar::from(2+3*2+5*4)));

        let coeff: Vec<G2Projective> = vec![];
        assert_eq!(blstrs_eval_G2Projective(&coeff, &Scalar::from(2)), G2Projective::identity());

        let coeff = vec![Scalar::from(2), Scalar::from(3), Scalar::from(5)];
        let coeff = coeff.iter().map(|s| G1Projective::generator().mul(s)).collect();
        assert_eq!(blstrs_eval_G1Projective(&coeff, &Scalar::from(0)), G1Projective::generator().mul(Scalar::from(2)));
        assert_eq!(blstrs_eval_G1Projective(&coeff, &Scalar::from(1)), G1Projective::generator().mul(Scalar::from(10)));
        assert_eq!(blstrs_eval_G1Projective(&coeff, &Scalar::from(2)), G1Projective::generator().mul(Scalar::from(2+3*2+5*4)));

        let coeff: Vec<G1Projective> = vec![];
        assert_eq!(blstrs_eval_G1Projective(&coeff, &Scalar::from(2)), G1Projective::identity());
    }

    #[test]
    fn test_interpolate_at() {
        let xs: Vec<_> = vec![0u64, 1, 2, 3].into_iter().map(|i| Scalar::from(i)).collect();

        let ys: Vec<_> = vec![1u64, 3, 7, 11].into_iter().map(|i| Scalar::from(i)).collect();
        let ys: Vec<G2Projective> = ys.iter().map(|s| G2Projective::generator().mul(s)).collect();
        assert_eq!(blstrs_lagrange_G2Projective(&xs, ys.clone(), &Scalar::from(0)), G2Projective::generator().mul(Scalar::from(1)));
        assert_eq!(blstrs_lagrange_G2Projective(&xs, ys.clone(), &Scalar::from(1)), G2Projective::generator().mul(Scalar::from(3)));
        assert_eq!(blstrs_lagrange_G2Projective(&xs, ys.clone(), &Scalar::from(2)), G2Projective::generator().mul(Scalar::from(7)));
        assert_eq!(blstrs_lagrange_G2Projective(&xs, ys.clone(), &Scalar::from(3)), G2Projective::generator().mul(Scalar::from(11)));

        let ys: Vec<_> = vec![1u64, 3, 7, 11].into_iter().map(|i| Scalar::from(i)).collect();
        let ys: Vec<G1Projective> = ys.iter().map(|s| G1Projective::generator().mul(s)).collect();
        assert_eq!(blstrs_lagrange_G1Projective(&xs, ys.clone(), &Scalar::from(0)), G1Projective::generator().mul(Scalar::from(1)));
        assert_eq!(blstrs_lagrange_G1Projective(&xs, ys.clone(), &Scalar::from(1)), G1Projective::generator().mul(Scalar::from(3)));
        assert_eq!(blstrs_lagrange_G1Projective(&xs, ys.clone(), &Scalar::from(2)), G1Projective::generator().mul(Scalar::from(7)));
        assert_eq!(blstrs_lagrange_G1Projective(&xs, ys.clone(), &Scalar::from(3)), G1Projective::generator().mul(Scalar::from(11)));
    }

}
