extern crate core;

use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use rand::SeedableRng;
pub use acss::HavenPublicParams;
use acss::{HavenReceiver, HavenReceiverParams, HavenSender, HavenSenderParams};
use acss::messages::ACSSDeliver;
use crypto::threshold_sig::{PublicKey, SecretKey, Signable, Signature, SignatureSet};
use crypto_blstrs::blstrs::{G1Projective, Scalar};
use crypto_blstrs::blstrs_lagrange_G1Projective;
use crypto_blstrs::dleq::BlstrsDLEq;
use crypto_blstrs::ff::Field;
use crypto_blstrs::group::Group;
use crypto_blstrs::threshold_sig::BlstrsSignature;
use network::{subscribe_msg, tokio};
use network::tokio::sync::mpsc;
use network::tokio::task::yield_now;
use protocol::{Protocol, ProtocolParams, run_protocol};
use utils::{close_and_drain, shutdown, shutdown_done, spawn_blocking};
use utils::rayon;
use vaba::messages::VabaControlMsg;
use vaba::Vaba;
use crate::messages::{APSSDeliver, Shutdown, PartialProof, Proof, Reveal};
use crate::tokio::{select, task};
use rand_chacha::ChaCha20Rng;
use tss::messages::TSSControlMsg;
use tss::TSS;

pub mod messages;

#[derive(Debug, Clone)]
pub struct APSSParams {
    pub g: G1Projective,
    pub h: G1Projective,
    pub committee_prob: Option<(usize, usize)>,
}

impl APSSParams {
    pub fn new(g: G1Projective, h: G1Projective, committee_prob: Option<(usize, usize)>) -> Self {
        Self { g, h, committee_prob }
    }
}

pub struct APSS {
    params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, APSSDeliver>,
    additional_params: Option<APSSParams>,
}


impl Protocol<BlstrsSignature, HavenPublicParams, APSSParams, Shutdown, APSSDeliver> for APSS {
    fn new(params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, APSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: APSSParams) {
        self.additional_params = Some(params);
    }
}

impl APSS {
    pub async fn run(&mut self) {
        let APSSParams{ g, h, committee_prob } = self.additional_params.take().expect("No additional params!");

        let num_peers = self.params.node.peer_count();
        
        // Sample committee
        let mut committee = (0..num_peers).collect();
        let mut comm_corruption_limit = self.params.node.get_corruption_limit();
        if let Some((num, denom)) = committee_prob {
            let comm_size = num_peers/denom*num;
            comm_corruption_limit = comm_size/2 + 1;
            let sample_dst = format!("APSS-SAMPLE-{}", self.params.dst);
            let (tx_sample, mut rx_sample) = run_protocol!(TSS<_, _, _>,
                self.params.handle.clone(), self.params.node.clone(), self.params.id.clone(), sample_dst, self.params.id.clone());
            tx_sample.send(TSSControlMsg::Sign).await.expect("Sign failed!");
            select! {
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    shutdown!(tx_sample, TSSControlMsg::Shutdown);
                    close_and_drain!(rx_sample);
                    shutdown_done!(tx_shutdown);
                },
                Some(deliver) = rx_sample.recv() => {
                    let hash = deliver.proof.sha256_hash();
                    let mut rng = ChaCha20Rng::from_seed(hash.try_into().expect("Hash conversion failed!"));
                    let mut range: Vec<usize> = (0..num_peers).collect();
                    let (comm, _) = range.partial_shuffle(&mut rng, comm_size);
                    committee = comm.to_vec();
                }
            }
        }

        // Start VABA
        let mut id_vaba = self.params.id.clone();
        id_vaba.push(1);
        let pk = self.params.node.get_pk().clone();
        let mut id = self.params.id.clone();
        id.push(0);
        let dst = self.params.dst.clone();
        let validation_fn = Arc::new(move |map: &Vec<(usize, BlstrsSignature)>| -> bool {
            if map.len() < comm_corruption_limit {
                return false;
            }
            for (i, sig) in map.iter() {
                let mut id = id.clone();
                id.push(*i);
                if let Ok(id_ser) = id.prepare() {
                    if pk.verify(
                        sig,
                    format!("ACSS{:?}", id_ser),
                        &dst) {
                        continue;
                    }
                }
                return false;
            }
            true
        });

        yield_now().await;

        // The vaba value needs to be a vec because a hashmap has non-deterministic iters that break vaba interally
        let (tx_vaba, mut rx_vaba) =
            run_protocol!(Vaba<BlstrsSignature, _, _, _>, self.params.handle.clone(),
                self.params.node.clone(), id_vaba, self.params.dst.clone(), validation_fn.clone());
        let mut vaba_decision: Option<HashSet<usize>> = None;

        // Start ACSS receivers
        let (tx_acss_recv, mut rx_acss_recv) = mpsc::channel(network::network::CHANNEL_LIMIT);
        let mut acss_recv_txs = Vec::with_capacity(num_peers);
        let mut id_acss = self.params.id.clone();
        id_acss.push(0);

        for sender in committee.iter() {
            let mut id = id_acss.clone();
            id.push(*sender);

            let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
            let params = ProtocolParams::new_raw(self.params.handle.clone(),
                                                 self.params.node.clone(), id, self.params.dst.clone(), tx_acss_recv.clone(), rx);
            let mut acss_recv = HavenReceiver::new(params);
            let add_params = HavenReceiverParams::new(*sender);
            acss_recv.additional_params(add_params);
            acss_recv_txs.push(tx);

            tokio::spawn(async move { acss_recv.run().await });
            task::yield_now().await;
        }
        let mut acss_y_received = HashMap::new();
        let mut acss_feldman_received = HashMap::new();

        // ACSS Sender
        let mut id_acss_sender = id_acss.clone();
        id_acss_sender.push(self.params.node.get_own_idx());

        let mut tx_acss_sender = None;
        if committee.contains(&self.params.node.get_own_idx()) {
            // Start ACSS Sender
            let sender_params = HavenSenderParams::new(Scalar::zero(), h.clone());
            let (tx, _) = run_protocol!(HavenSender, self.params.handle.clone(),
                    self.params.node.clone(), id_acss_sender.clone(), self.params.dst.clone(), sender_params);
            tx_acss_sender = Some(tx);
        }

        // Subscribe to partial proof messages
        let mut rx_partial_proof = subscribe_msg!(self.params.handle, &self.params.id, PartialProof);
        let mut partial_proof_set = SignatureSet::new(self.params.node.get_threshold(),
                                                      format!("ACSS{:?}", id_acss_sender.prepare_panic()),
                                                      &self.params.dst);
        // Subscribe to proofs
        let mut proof_map = HashMap::with_capacity(comm_corruption_limit);
        let mut rx_proof = subscribe_msg!(self.params.handle, &self.params.id, Proof);

        let vaba_decision = loop {
            select! {
                Some(ACSSDeliver { y, feldman, sender }) = rx_acss_recv.recv() => {
                    match feldman.get(0) {
                        None => continue,
                        Some(f_0) => {
                            if f_0 != &G1Projective::identity() {
                                continue;
                            }
                        }
                    }
                    let mut id_acss_sender = id_acss.clone();
                    id_acss_sender.push(sender);
                    let share_ok_msg = format!("ACSS{:?}", &id_acss_sender.prepare_panic());

                    let partial_proof = PartialProof(self.params.node.get_sk_share().sign(&share_ok_msg, &self.params.dst));
                    self.params.handle.send(sender, &self.params.id, &partial_proof).await;
                    acss_y_received.insert(sender, y);
                    acss_feldman_received.insert(sender, feldman);

                    if let Some(set) = &vaba_decision {
                        if set.intersection(&acss_y_received.keys().map(|k| *k).collect::<HashSet<usize>>()).count() == set.len() {
                            break vaba_decision.unwrap();
                        }
                    }
                },

                Some(msg) = rx_partial_proof.recv() => {
                    let sender = *msg.get_sender();
                    if let Ok(partial_proof) = msg.get_content::<PartialProof>() {
                        if let Some(sender_pk) = self.params.node.get_peer_pk_share(sender) {
                            partial_proof_set.insert(sender_pk, partial_proof.0);
                            if partial_proof_set.can_combine() {
                                let proof = Proof(spawn_blocking!(partial_proof_set.combine().expect("Combine failed!")));
                                self.params.handle.broadcast(&self.params.id, &proof).await;
                                self.params.handle.unsubscribe::<PartialProof>(&self.params.id).await;
                                close_and_drain!(rx_partial_proof);
                            }
                        }
                    }
                },

                Some(msg) = rx_proof.recv() => {
                    if let Ok(proof) = msg.get_content::<Proof>() {
                        let mut id_acss_j = id_acss.clone();
                        let j = *msg.get_sender();
                        id_acss_j.push(j);
                        if self.params.node.get_pk().verify(&proof.0,
                                                      format!("ACSS{:?}", id_acss_j.prepare_panic()),
                                                      &self.params.dst) {
                            proof_map.insert(j, proof.0);
                            if proof_map.len() >= comm_corruption_limit {
                                let map: Vec<_> = proof_map.clone().into_iter().collect();
                                let _ = tx_vaba.send(VabaControlMsg::Propose(map)).await; // Vaba might finish in time
                                self.params.handle.unsubscribe::<Proof>(&self.params.id).await;
                                close_and_drain!(rx_proof);
                            }
                        }
                    }
                },

                Some(decision) = rx_vaba.recv() => {
                    let mut set = HashSet::new();
                    for (k, _) in decision.0.into_iter() {
                        set.insert(k);
                        task::yield_now().await;
                    }
                    if set.intersection(&acss_y_received.keys().map(|k| *k).collect::<HashSet<usize>>()).count() == set.len() {
                        break set;
                    }
                    vaba_decision = Some(set);
                },

                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    // Stop ACSS Sender
                    if let Some(tx) = tx_acss_sender {
                        shutdown!(tx, acss::messages::Shutdown);
                    }

                    // Close ACSS receivers
                    for tx in acss_recv_txs {
                        shutdown!(tx, acss::messages::Shutdown);
                    }
                    close_and_drain!(rx_acss_recv);

                    // Close partial proofs
                    self.params.handle.unsubscribe::<PartialProof>(&self.params.id).await;
                    close_and_drain!(rx_partial_proof);

                    // Close proof
                    self.params.handle.unsubscribe::<Proof>(&self.params.id).await;
                    close_and_drain!(rx_proof);

                    // Shutdown VABA (should not be necessary)
                    shutdown!(tx_vaba, VabaControlMsg::Shutdown);
                    close_and_drain!(rx_vaba);

                    shutdown_done!(tx_shutdown);
                },
            }
        };

        // Stop ACSS Sender
        if let Some(tx) = tx_acss_sender {
            shutdown!(tx, acss::messages::Shutdown);
        }
        // Close ACSS receivers
        for tx in acss_recv_txs {
            shutdown!(tx, acss::messages::Shutdown);
        }
        close_and_drain!(rx_acss_recv);

        // Close partial proofs
        self.params.handle.unsubscribe::<PartialProof>(&self.params.id).await;
        close_and_drain!(rx_partial_proof);

        // Close proof
        self.params.handle.unsubscribe::<Proof>(&self.params.id).await;
        close_and_drain!(rx_proof);

        // Shutdown VABA (should not be necessary)
        shutdown!(tx_vaba, VabaControlMsg::Shutdown);
        close_and_drain!(rx_vaba);

        // Reveal
        let mut rx_reveal = subscribe_msg!(self.params.handle, &self.params.id, Reveal);
        let dleq = BlstrsDLEq::new(&g, &h, &self.params.dst);
        let mut reveal_map = HashMap::with_capacity(self.params.node.get_threshold());

        // Compute own share and combined feldman commitment
        let (share, feldman_h, proof) = spawn_blocking!({
            let share = acss_y_received.drain()
                .filter_map(|(i, s)| if vaba_decision.contains(&i) { Some(s) } else { None })
                .fold(Scalar::zero(), |x, y| x + y);
            let mut feldman_h = Vec::with_capacity(self.params.node.get_threshold());
            for _ in 0..self.params.node.get_threshold() {
                feldman_h.push(G1Projective::identity());
            }
            for (i, feldman_partial) in acss_feldman_received.iter() {
                if vaba_decision.contains(i) {
                    for j in 0..feldman_h.len() {
                        feldman_h[j] += feldman_partial[j];
                    }
                }
            }
            let proof = dleq.prove(&share);
            (share, feldman_h, proof)
        });

        let g_share = g * &share;
        let reveal = Reveal::new(g_share, proof);

        self.params.handle.broadcast(&self.params.id, &reveal).await;

        'outer: loop {
            select! {
                Some(msg) = rx_reveal.recv() => {
                    let sender_idx = *msg.get_sender();
                    if let Ok(Reveal { share_commitment, dleq_proof }) = msg.get_content::<Reveal>() {
                        if spawn_blocking!(dleq.verify(&share_commitment,
                                       &crypto_blstrs::blstrs_eval_G1Projective(&feldman_h, &Scalar::from(sender_idx as u64 + 1)),
                                       &dleq_proof)) {
                            reveal_map.insert(sender_idx + 1, share_commitment);
                            if reveal_map.len() >= self.params.node.get_threshold() {
                                break 'outer;
                            }
                        }
                    }
                },
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<Reveal>(&self.params.id).await;
                    close_and_drain!(rx_reveal);
                    shutdown_done!(tx_shutdown);
                }
            }
        }
        // Shutdown reveal
        self.params.handle.unsubscribe::<Reveal>(&self.params.id).await;
        close_and_drain!(rx_reveal);

        // Output
        let mut xs = Vec::with_capacity(self.params.node.get_threshold());
        let mut ys = Vec::with_capacity(self.params.node.get_threshold());
        for (x, y) in reveal_map {
            xs.push(Scalar::from(x as u64));
            ys.push(y);
            task::yield_now().await;
        }
        let pks = spawn_blocking!({
            let mut pks = Vec::with_capacity(num_peers);
            for i in 1..=num_peers {
                pks.push(blstrs_lagrange_G1Projective(&xs, &ys, &Scalar::from(i as u64)))
            }
            pks
        });

        self.params.tx.send(APSSDeliver::new(share, pks)).await.expect("Parent unreachable!");
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use crypto_blstrs::blstrs::G2Projective;
    use network::message::Id;
    use protocol::tests::generate_nodes;
    use crypto_blstrs::group::Group;
    use crypto_blstrs::vector_commit::BlstrsKZGVec;
    use crypto_blstrs::poly_commit::kzg::BlstrsKZG;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_apss() {
        let g = G1Projective::generator();
        let h = G1Projective::random(OsRng);
        let hh = G2Projective::random(OsRng);
        let generators = (h, hh);
        let kzg_params = BlstrsKZG::new(1, generators);
        let vec_params = BlstrsKZGVec::new(6, generators, "DST".to_string());
        let pp = HavenPublicParams::new(kzg_params, vec_params);
        let (nodes, handles) = generate_nodes::<BlstrsSignature, HavenPublicParams>(10103, 10107, 2, 3, pp.clone());

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();

        let prob: Option<(usize, usize)> = None;
        let add_params = APSSParams::new(g, h, prob);
        for i in 0..nodes.len() {
            let (tx, rx) =
                run_protocol!(APSS, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params.clone());
            txs.push(tx);
            rxs.push(rx);
        }

        let mut idxs = HashSet::from([1,2,3,4]);
        let mut other_pks: Option<Vec<G1Projective>> = None;
        for (_i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(APSSDeliver{ share, pks }) => {
                    if let Some(other_pks) = &other_pks {
                        assert_eq!(other_pks, &pks)
                    } else {
                        other_pks = Some(pks.clone());
                    }
                    assert!(pks.len() == 4);
                    for j in 1..=4 {
                        if pks[j-1] ==  g * &share {
                            assert!(idxs.remove(&j));
                        }
                    }
                },
                None => assert!(false),
            }
        }
        assert_eq!(idxs.len(), 0);
        for tx in txs.iter() {
            shutdown!(tx, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
}
