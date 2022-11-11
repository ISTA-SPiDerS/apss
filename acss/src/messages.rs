use serde::{Deserialize, Serialize};

use crypto::{PolyCommit, VecCommit};
use crypto_blstrs::poly_commit::kzg::BlstrsKZG;
use crypto_blstrs::vector_commit::BlstrsKZGVec;
use network::tokio::sync::oneshot;

use crate::{G1Projective, Scalar};

pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Debug)]
pub struct ACSSDeliver {
    pub y: Scalar,
    pub feldman: Vec<G1Projective>,
    pub sender: usize,
}

impl ACSSDeliver {
    pub fn new(y: Scalar, feldman: Vec<G1Projective>, sender: usize) -> Self {
        Self { y, feldman, sender }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SendMsg {
    pub c: G1Projective,
    pub r: Vec<G1Projective>,
    pub r_incl: G1Projective,
    pub s: Vec<G1Projective>,
    pub s_incls: Vec<G1Projective>,
    pub y_s: Vec<(Scalar, G1Projective)>,
    pub y_r: Vec<(G1Projective, G1Projective)>,
}

impl SendMsg {
    pub fn new(c: G1Projective, r: Vec<G1Projective>, r_incl: G1Projective, s: Vec<G1Projective>, s_incls: Vec<G1Projective>, y_s: Vec<(Scalar, G1Projective)>,
               y_r: Vec<(G1Projective, G1Projective)>) -> Self {
        Self { c, r, r_incl, s, s_incls, y_s, y_r }
    }

    pub fn is_correct(&self, poly_commit: &BlstrsKZG, vec_commit: &BlstrsKZGVec, own_idx: usize, num_peers: usize) -> bool {
        if num_peers != self.s.len()
            || num_peers != self.s_incls.len()
            || num_peers != self.y_s.len()
            || num_peers != self.y_r.len()
        {
            return false;
        }
        if !vec_commit.verify(&self.c, 0, &bincode::serialize(&self.r).expect("Serialize failed!"), &self.r_incl) {
            return false;
        }
        for i in 0..num_peers {
            if !vec_commit.verify(&self.c, i+1, &bincode::serialize(&self.s[i]).expect("Serialize failed!"), &self.s_incls[i])
                || !poly_commit.verify(&self.s[i], &Scalar::from((own_idx+1) as u64), &self.y_s[i].0, &self.y_s[i].1)
                || !poly_commit.verify_from_commitment(&self.s[i], &Scalar::from((i+1) as u64), &self.y_r[i].0, &self.y_r[i].1)
                || crypto_blstrs::blstrs_eval_G1Projective(&self.r, &Scalar::from((i+1) as u64)) != self.y_r[i].0
            {
                return false;
            }
        }
        true
    }
}

#[derive(Serialize, Deserialize)]
pub struct EchoMsg {
    pub c: G1Projective,
    pub r: Vec<G1Projective>,
    pub r_incl: G1Projective,
    pub s: G1Projective,
    pub s_incl: G1Projective,
    pub y: (Scalar, G1Projective),
}

impl EchoMsg {
    pub fn new(c: G1Projective, r: Vec<G1Projective>, r_incl: G1Projective, s: G1Projective, s_incl: G1Projective, y: (Scalar, G1Projective)) -> Self {
        Self { c, r, r_incl, s, s_incl, y }
    }

    pub fn is_correct(&self, poly_commit: &BlstrsKZG, vec_commit: &BlstrsKZGVec, own_idx: usize, sender_idx: usize) -> bool {
        vec_commit.verify(&self.c, own_idx+1, &bincode::serialize(&self.s).expect("Serialize failed!"), &self.s_incl)
            && vec_commit.verify(&self.c, 0, &bincode::serialize(&self.r).expect("Serialize failed!"), &self.r_incl)
            && poly_commit.verify(&self.s, &Scalar::from((sender_idx+1) as u64), &self.y.0, &self.y.1)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReadyMsg {
    pub c: G1Projective
}

impl ReadyMsg {
    pub fn new(c: G1Projective) -> Self {
        Self { c }
    }
}

#[derive(Debug)]
pub struct HavenSenderDone;
