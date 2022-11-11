extern crate core;

use std::collections::{HashMap, HashSet};
use std::thread;

use crypto::{PolyCommit, Polynomial};
use crypto::VecCommit;
use crypto_blstrs::blstrs::{G1Projective, Scalar};
use crypto_blstrs::ff::Field;
use crypto_blstrs::poly_commit::feldman::BlstrsFeldman;
use crypto_blstrs::poly_commit::kzg::BlstrsKZG;
use crypto_blstrs::polynomial::BlstrsPolynomial;
use crypto_blstrs::threshold_sig::BlstrsSignature;
use crypto_blstrs::vector_commit::BlstrsKZGVec;
use network::subscribe_msg;
use protocol::{Protocol, ProtocolParams, PublicParameters};
use utils::{close_and_drain, shutdown_done, spawn_blocking};
use utils::{rayon, tokio};
use serde::{Serialize, Deserialize};
use utils::tokio::task::yield_now;

use crate::messages::*;
use crate::tokio::select;
use crate::tokio::sync::oneshot;

pub mod messages;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HavenPublicParams {
    poly: BlstrsKZG,
    vec: BlstrsKZGVec,
}

impl HavenPublicParams {
    pub fn new(poly: BlstrsKZG, vec: BlstrsKZGVec) -> Self {
        Self { poly, vec }
    }
}

impl PublicParameters<BlstrsKZG> for HavenPublicParams {
    fn get_pp(&self) -> &BlstrsKZG {
        &self.poly
    }
}

impl PublicParameters<BlstrsKZGVec> for HavenPublicParams {
    fn get_pp(&self) -> &BlstrsKZGVec {
        &self.vec
    }
}

// This would be nicer if it were generic. However, to sensibly do this, one would have to define
// traits for groups/fields (because e.g., Ark does not use the RustCrypto group, field, etc. traits)
// which is out of scope.
pub struct HavenSenderParams {
    pub value: Scalar,
    pub generator: G1Projective,
}

impl HavenSenderParams {
    pub fn new(value: Scalar, generator: G1Projective) -> Self {
        Self { value, generator }
    }
}
pub struct HavenSender {
    params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, ()>,
    additional_params: Option<HavenSenderParams>,
}


impl Protocol<BlstrsSignature, HavenPublicParams, HavenSenderParams, Shutdown, ()> for HavenSender {
    fn new(params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, ()>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: HavenSenderParams) {
        self.additional_params = Some(params);
    }
}

impl HavenSender {
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("ACSS Sender");

        let HavenSenderParams{value, generator} = self.additional_params.take().expect("No additional params given!");

        let num_peers = self.params.node.peer_count();
        let node = self.params.node.clone();

        let (tx_oneshot, rx_oneshot) = oneshot::channel();
        let _ = thread::spawn(move || {
            // Sample reconstruction arithmetic
            let rec_poly = BlstrsPolynomial::sample(node.get_threshold() - 1, HashMap::from_iter(vec![(0, value)]));
            let feldman = BlstrsFeldman::new(node.get_threshold() - 1, generator);
            let rec_poly_commit = feldman.commit(&rec_poly).expect("Feldman commit failed!");

            // Sample share polynomials
            let mut share_polys: Vec<BlstrsPolynomial> = Vec::with_capacity(num_peers);
            let mut share_poly_comms = Vec::with_capacity(num_peers);
            for i in 1..=num_peers {
                let i_scalar = Scalar::from(i as u64);
                let rec_value = rec_poly.eval(&i_scalar);
                let share_poly = BlstrsPolynomial::sample(node.get_corruption_limit()-1, HashMap::from_iter(vec![(i, rec_value)]));
                let share_poly_comm = PublicParameters::<BlstrsKZG>::get_pp(node.as_ref()).commit(&share_poly).expect("Commit failed");
                share_polys.push(share_poly);
                share_poly_comms.push(share_poly_comm);
            }
            let mut c_vec = Vec::with_capacity(num_peers + 1);
            c_vec.push(bincode::serialize(&rec_poly_commit).unwrap());
            for share_poly_comm in share_poly_comms.iter() {
                c_vec.push(bincode::serialize(&share_poly_comm).unwrap());
            }

            // Vector commit
            let c = PublicParameters::<BlstrsKZGVec>::get_pp(node.as_ref()).commit(&c_vec).expect("Vector commit failed!");

            // Witnesses of inclusion
            let r_incl = PublicParameters::<BlstrsKZGVec>::get_pp(node.as_ref()).open(&c_vec, 0).expect("Vector open failed!");
            let mut s_incls = Vec::with_capacity(num_peers);
            for idx in 1..=num_peers {
                s_incls.push(PublicParameters::<BlstrsKZGVec>::get_pp(node.as_ref()).open(&c_vec, idx).expect("Vector open failed!"));
            }

            // Witness linking R and S_i
            let mut y_r = Vec::with_capacity(num_peers);
            for (i, share_poly) in share_polys.iter().enumerate() {
                y_r.push(PublicParameters::<BlstrsKZG>::get_pp(node.as_ref()).open_commit(share_poly, &Scalar::from((i+1) as u64)).expect("Open commit failed!"));
            }

            // Openings for each party
            let mut y_ss = Vec::with_capacity(num_peers);
            for i in 0..num_peers {
                let mut y_s = Vec::with_capacity(num_peers);
                for share_poly in share_polys.iter() {
                    y_s.push(PublicParameters::<BlstrsKZG>::get_pp(node.as_ref()).open(share_poly, &Scalar::from((i+1) as u64)).expect("Open failed!"));
                }
                y_ss.push(y_s);
            }

            tx_oneshot.send((c, rec_poly_commit, r_incl, share_poly_comms, s_incls, y_ss, y_r))
        });

        // Values for each party


        select! {
            Ok((c, rec_poly_commit, r_incl, share_poly_comms, s_incls, mut y_ss, y_r)) = rx_oneshot => {
                for (i, y_s) in y_ss.drain(0..).enumerate() {
                    let send_msg = SendMsg::new(c, rec_poly_commit.clone(), r_incl.clone(), share_poly_comms.clone(), s_incls.clone(), y_s, y_r.clone());
                    self.params.handle.send(i, &self.params.id, &send_msg).await;
                }
                self.params.handle.handle_stats_end().await;
            },
            Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                self.params.handle.handle_stats_end().await;
                shutdown_done!(tx_shutdown);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct HavenReceiverParams {
    pub sender: usize,
}

impl HavenReceiverParams {
    pub fn new(sender: usize) -> Self {
        Self { sender }
    }
}

pub struct HavenReceiver {
    params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, ACSSDeliver>,
    additional_params: Option<HavenReceiverParams>
}

impl Protocol<BlstrsSignature, HavenPublicParams, HavenReceiverParams, Shutdown, ACSSDeliver> for HavenReceiver {
    fn new(params: ProtocolParams<BlstrsSignature, HavenPublicParams, Shutdown, ACSSDeliver>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: HavenReceiverParams) {
        self.additional_params = Some(params)
    }
}

impl HavenReceiver {
    pub async fn run(&mut self) {
        let HavenReceiverParams{ sender: acss_sender} = self.additional_params.take().expect("No additional params!");
        self.params.handle.handle_stats_start(format!("ACSS Receiver {}", acss_sender));

        let mut rx_send = subscribe_msg!(self.params.handle, &self.params.id, SendMsg);
        let mut rx_echo = subscribe_msg!(self.params.handle, &self.params.id, EchoMsg);
        let mut rx_ready = subscribe_msg!(self.params.handle, &self.params.id, ReadyMsg);


        let c_to_key = |c: &G1Projective| c.to_compressed();
        let mut c_data: HashMap<[u8; 48], (Vec<G1Projective>, HashMap<usize, Scalar>)> = HashMap::new();
        let mut echo_set = HashSet::new();  // Tracks parties we have received echos from
        let mut ready_sent = false;
        let mut ready_for_output = None;
        let mut ready_set = HashSet::new();  // Tracks parties we have received readys from
        let mut c_count: HashMap<[u8; 48], usize> = HashMap::new();

        loop {
            select! {
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                    close_and_drain!(rx_echo);
                    self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                    close_and_drain!(rx_send);
                    self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                    close_and_drain!(rx_ready);
                    close_and_drain!(self.params.rx);

                    self.params.handle.handle_stats_end().await;

                    shutdown_done!(tx_shutdown);
                },

                Some(msg) = rx_send.recv() => {
                    if msg.get_sender() == &acss_sender {
                        if let Ok(send_msg) = msg.get_content::<SendMsg>() {
                            self.params.handle.handle_stats_event("Before send_msg.is_correct");
                            if spawn_blocking!(send_msg.is_correct(
                                PublicParameters::<BlstrsKZG>::get_pp(self.params.node.as_ref()),
                                PublicParameters::<BlstrsKZGVec>::get_pp(self.params.node.as_ref()),
                                self.params.node.get_own_idx(),
                                self.params.node.peer_count())
                            ) {
                                self.params.handle.handle_stats_event("After send_msg.is_correct");
                                // Echo message
                                for i in 0..self.params.node.peer_count() {
                                    let echo = EchoMsg::new(send_msg.c.clone(), send_msg.r.clone(), send_msg.r_incl.clone(), send_msg.s[i].clone(), send_msg.s_incls[i].clone(), send_msg.y_s[i].clone());
                                    self.params.handle.send(i, &self.params.id, &echo).await;
                                    self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                    close_and_drain!(rx_send);
                                }
                                self.params.handle.handle_stats_event("After sending echo");
                            }
                        }
                    }
                },

                Some(msg) = rx_echo.recv() => {
                    // Get sender
                    let sender_idx = msg.get_sender();
                    if !echo_set.contains(sender_idx) {
                        echo_set.insert(*sender_idx);
                        if let Ok(echo_msg) = msg.get_content::<EchoMsg>() {
                            if spawn_blocking!(echo_msg.is_correct(
                                PublicParameters::<BlstrsKZG>::get_pp(self.params.node.as_ref()),
                                PublicParameters::<BlstrsKZGVec>::get_pp(self.params.node.as_ref()),
                                self.params.node.get_own_idx(),
                                *sender_idx
                            )) {
                                let EchoMsg { c, r, y: (y, _), .. } = echo_msg;
                                let c_key = c_to_key(&c);
                                let (r, points) = match c_data.remove(&c_key) {
                                    None => (r, HashMap::from([(*sender_idx+1, y)])),
                                    Some((r, mut points)) => {
                                        points.insert(*sender_idx+1, y);
                                        (r, points)
                                    }
                                };
                                let c_count = points.len();

                                // Output
                                if let Some(ready_c_key) = ready_for_output {
                                    if ready_c_key == c_key && c_count >= self.params.node.get_corruption_limit() {
                                        let mut xs = Vec::with_capacity(self.params.node.get_corruption_limit());
                                        let mut ys = Vec::with_capacity(self.params.node.get_corruption_limit());
                                        for (x, y) in points {
                                            xs.push(Scalar::from(x as u64));
                                            ys.push(y);
                                            yield_now().await;
                                        }
                                        let x = Scalar::from((self.params.node.get_own_idx()+1) as u64);
                                        let y = spawn_blocking!(crypto::interpolate_at(&xs, ys, &x, |s| s.invert().unwrap(), Scalar::zero()));
                                        let deliver = ACSSDeliver::new(y, r, acss_sender);
                                        self.params.tx.send(deliver).await.expect("Send to parent failed!");

                                        // Close everything
                                        self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                        close_and_drain!(rx_echo);
                                        self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                        close_and_drain!(rx_send);
                                        close_and_drain!(self.params.rx);

                                        self.params.handle.handle_stats_event("Output");
                                        self.params.handle.handle_stats_end().await;

                                        return;
                                    }
                                }
                                c_data.insert(c_key, (r, points));

                                // Send ready
                                if c_count >= 2 * self.params.node.get_corruption_limit() - 1 {
                                    self.params.handle.handle_stats_event("Send ready from echo");
                                    self.send_ready(&mut ready_sent, c).await;
                                }
                            }
                        }
                    }
                },


                Some(msg) = rx_ready.recv() => {
                    // Get sender
                    let sender_idx = msg.get_sender();

                    if !ready_set.contains(sender_idx) {
                        ready_set.insert(*sender_idx);
                        if let Ok(ReadyMsg { c }) = msg.get_content::<ReadyMsg>() {
                            let c_key = c_to_key(&c);
                            let count = match c_count.remove(&c_key) {
                                None => 1,
                                Some(x) => x + 1,
                            };
                            c_count.insert(c_key.clone(), count);

                            // Send ready
                            if count >= self.params.node.get_corruption_limit() {
                                self.params.handle.handle_stats_event("Send ready from ready");
                                self.send_ready(&mut ready_sent, c).await;
                            }

                            // Ready for output
                            if count >= 2 * self.params.node.get_corruption_limit() - 1 {
                                self.params.handle.unsubscribe::<ReadyMsg>(&self.params.id).await;
                                close_and_drain!(rx_ready);
                                if let Some((_, points)) = c_data.get(&c_key) {
                                    if points.len() >= self.params.node.get_corruption_limit() {
                                        let (r, points) = c_data.remove(&c_key).unwrap();
                                        let mut xs = Vec::with_capacity(self.params.node.get_corruption_limit());
                                        let mut ys = Vec::with_capacity(self.params.node.get_corruption_limit());
                                        for (x, y) in points {
                                            xs.push(Scalar::from(x as u64));
                                            ys.push(y);
                                            yield_now().await;
                                        }
                                        let x = Scalar::from((self.params.node.get_own_idx()+1) as u64);
                                        let y = spawn_blocking!(crypto::interpolate_at(&xs, ys, &x, |s| s.invert().unwrap(), Scalar::zero()));
                                        let deliver = ACSSDeliver::new(y, r, acss_sender.clone());
                                        self.params.tx.send(deliver).await.expect("Send to parent failed!");

                                        // Close everything
                                        self.params.handle.unsubscribe::<EchoMsg>(&self.params.id).await;
                                        close_and_drain!(rx_echo);
                                        self.params.handle.unsubscribe::<SendMsg>(&self.params.id).await;
                                        close_and_drain!(rx_send);
                                        close_and_drain!(self.params.rx);


                                        self.params.handle.handle_stats_event("Output");
                                        self.params.handle.handle_stats_end().await;

                                        return;
                                    }
                                    ready_for_output = Some(c_key);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn send_ready(&mut self, ready_sent: &mut bool, c: G1Projective) {
        if !*ready_sent {
            *ready_sent = true;
            let ready = ReadyMsg::new(c.clone());
            self.params.handle.broadcast(&self.params.id, &ready).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_blstrs::group::Group;
    use std::ops::Mul;
    use crypto::interpolate_at;
    use crypto_blstrs::blstrs::G2Projective;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::shutdown;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_acss() {
        let generators = (G1Projective::generator(), G2Projective::generator());
        let kzg_params = BlstrsKZG::new(1, generators);
        let vec_params = BlstrsKZGVec::new(6, generators, "DST".to_string());
        let pp = HavenPublicParams::new(kzg_params, vec_params);
        let (nodes, handles) = generate_nodes::<BlstrsSignature, HavenPublicParams>(10098, 10103, 2, 3, pp.clone());

        let id = Id::default();
        let dst = "DST".to_string();
        let generator = G1Projective::generator();
        let value = Scalar::from(42);

        let mut txs = Vec::new();
        let mut rxs = Vec::new();

        let params = HavenSenderParams::new(value.clone(), generator.clone());
        let _ = run_protocol!(HavenSender, handles[0].clone(), nodes[0].clone(), id.clone(), dst.clone(), params);

        let add_params = HavenReceiverParams::new(nodes[0].get_own_idx());
        for i in 0..nodes.len() {
            let (tx, rx) =
                run_protocol!(HavenReceiver, handles[i].clone(), nodes[i].clone(), id.clone(), dst.clone(), add_params.clone());
            txs.push(tx);
            rxs.push(rx);
        }

        let mut points = Vec::new();
        for (i, rx) in rxs.iter_mut().enumerate() {
            match rx.recv().await {
                Some(ACSSDeliver { y, feldman, .. }) => {
                    assert_eq!(crypto::eval(&feldman, &Scalar::zero(), G1Projective::identity()), generator.mul(&value));
                    points.push((Scalar::from(nodes[i].get_own_idx() as u64 + 1), y));
                },
                None => assert!(false),
            }
        }
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for (x, y) in points {
            xs.push(x);
            ys.push(y);
        }
        assert_eq!(value, interpolate_at(&xs, ys, &Scalar::zero(), |s| s.invert().unwrap(), Scalar::zero()));
        for tx in txs.iter() {
            shutdown!(tx, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }

    }
}
