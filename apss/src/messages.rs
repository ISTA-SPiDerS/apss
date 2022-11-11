// PartialProof if zero poly
// Proof upon getting enough partialproof
// propose to vaba upon enough proofs
// Reveal if vaba delivered and correspond ACSS done
// Deliver(s, g^pk) upon enough reveal

use serde::{Serialize, Deserialize};
use crypto_blstrs::blstrs::{G1Projective, Scalar};
use crypto_blstrs::dleq::BlstrsDLEqProof;
use crypto_blstrs::threshold_sig::{BlstrsSignature, PartialBlstrsSignature};
use network::tokio::sync::oneshot;


#[derive(Debug)]
pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialProof(pub PartialBlstrsSignature);

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof(pub BlstrsSignature);

#[derive(Debug, Serialize, Deserialize)]
pub struct Reveal {
    pub share_commitment: G1Projective,
    pub dleq_proof: BlstrsDLEqProof,
}

impl Reveal {
    pub fn new(share_commitment: G1Projective, dleq_proof: BlstrsDLEqProof) -> Self {
        Self { share_commitment, dleq_proof }
    }
}

#[derive(Debug)]
pub struct APSSDeliver {
    pub share: Scalar,
    pub pks: Vec<G1Projective>,
}

impl APSSDeliver {
    pub fn new(share: Scalar, pks: Vec<G1Projective>) -> Self {
        APSSDeliver { share, pks }
    }
}
