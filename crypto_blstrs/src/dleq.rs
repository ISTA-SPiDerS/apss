use blstrs::{G1Projective, Scalar};
use ff::Field;
use serde::{Serialize, Deserialize};
use sha2;
use rand::rngs::{OsRng, StdRng};
use sha2::Sha256;
use digest::{Digest};
use rand::SeedableRng;

#[derive(Debug, Clone)]
pub struct BlstrsDLEq<'a, 'b, 'c> {
    g: &'a G1Projective,
    h: &'b G1Projective,
    dst: &'c String,
}

impl<'a, 'b, 'c> BlstrsDLEq<'a, 'b, 'c> {
    pub fn new(g: &'a G1Projective, h: &'b G1Projective, dst: &'c String) -> Self {
        Self { g, h, dst }
    }

    pub fn prove(&self, witness: &Scalar) -> BlstrsDLEqProof{
        let r = Scalar::random(OsRng);
        let a = self.g * &r;
        let b = self.h * &r;
        let c = self.fiat_shamir(&a, &b);
        let z = r - witness * c;

        BlstrsDLEqProof::new(a, b, z)
    }

    pub fn verify(&self, x: &G1Projective, y: &G1Projective, proof: &BlstrsDLEqProof) -> bool {
        let c = self.fiat_shamir(&proof.a, &proof.b);
        proof.a == self.g * &proof.z + x  * &c
        && proof.b == self.h * &proof.z + y * &c
    }

    fn fiat_shamir(&self, a: &G1Projective, b: &G1Projective) -> Scalar {
        let hash = Sha256::new()
            .chain_update(&self.dst)
            .chain_update(self.g.to_compressed())
            .chain_update(self.h.to_compressed())
            .chain_update(a.to_compressed())
            .chain_update(b.to_compressed())
            .finalize();
        Scalar::random(StdRng::from_seed(hash.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlstrsDLEqProof {
    a: G1Projective,
    b: G1Projective,
    z: Scalar,
}

impl BlstrsDLEqProof {
    fn new(a: G1Projective, b: G1Projective, z: Scalar) -> Self {
        Self { a, b, z }
    }
}

#[cfg(test)]
mod tests {
    use group::Group;
    use super::*;

    #[test]
    fn test_dleq() {
        let g = G1Projective::generator();
        let h = G1Projective::random(OsRng);
        let a = Scalar::from(42);
        let dst = "DST".to_string();
        let dleq = BlstrsDLEq::new(&g, &h, &dst);

        let x = g * a;
        let y = h * a;
        let proof = dleq.prove(&a);
        assert!(dleq.verify(&x, &y, &proof));

        let proof = dleq.prove(&Scalar::from(43));
        assert!(!dleq.verify(&x, &y, &proof));

        let z = h * Scalar::from(41);
        assert!(!dleq.verify(&x, &z, &proof));

    }
}
