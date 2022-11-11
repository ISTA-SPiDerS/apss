use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use crypto::threshold_sig::{CombinableSignature, PublicKey, Signable};
use network::message::Id;
use network::{subscribe_msg, tokio};
use network::tokio::sync::mpsc;
use protocol::{Protocol, ProtocolParams, run_protocol};
use tss::TSS;
use tss::messages::{Deliver, TSSControlMsg};
use utils::{rayon, close_and_drain, shutdown, spawn_blocking, shutdown_done};
use utils::tokio::task::yield_now;
use crate::messages::{Decide, Done, Exit, VabaControlMsg, ViewChange};
use crate::pb::fspb::{FSPBReceiverParams, FSPBReceiver, FSPBSender};
use crate::pb::messages::{FSPBDeliver, FSPBSenderMsg, PBProof};

mod pb;
pub mod messages;

#[derive(Debug, Clone)]
struct Key<V, P> {
    view: usize,
    value: V,
    proof: P,
}

impl<V, P> Key<V, P> {
    fn new(view: usize, value: V, proof: P) -> Self {
        Self { view, value, proof }
    }
}

/// Validated Asynchronous Byzantine Agreement similar to [Vaba, Alg. 6 & 7].
/// As we only use one set of high-threshold keys, we combine the skip and elect steps.
pub struct Vaba<T, PP, V, F>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, VabaControlMsg<V>, Decide<V>>,
    additional_params: Option<Arc<F>>,
}

impl<T, PP, V, F> Protocol<T, PP, Arc<F>, VabaControlMsg<V>, Decide<V>> for Vaba<T, PP, V, F>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, VabaControlMsg<V>, Decide<V>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: Arc<F>) {
        self.additional_params = Some(params);
    }
}

impl<T, PP, V, F> Vaba<T, PP, V, F>
    where
        T: 'static + Send + Sync + std::fmt::Debug + Clone + Serialize + DeserializeOwned + CombinableSignature,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PSig: 'static + Send + Sync + Serialize + DeserializeOwned,
        T::PSK: Send + Sync,
        T::PK: Send + Sync + Clone,
        F: 'static + Fn(&V) -> bool + Send + Sync + Clone,
        V: 'static + Send + Sync + std::fmt::Debug + Clone + DeserializeOwned + Serialize,
        PP: 'static + Send + Sync,
{
    pub async fn run(&mut self) {
        self.params.handle.handle_stats_start("VABA");

        let mut lock = 0usize;
        let mut key: Option<Key<V, Option<T>>> = None;
        let mut value: Option<V> = None;
        let mut proof: (usize, Option<T>) = (0, None);
        let mut leaders: Vec<usize> = Vec::new();
        leaders.push(usize::MAX);  // So that leaders is 1-indexable
        let mut d_key: HashMap<(usize, usize), (V, T)> = HashMap::new();
        let mut d_lock: HashMap<(usize, usize), (V, T)> = HashMap::new();
        let mut d_commit: HashMap<(usize, usize), (V, T)> = HashMap::new();


        let ex_validation_fn = self.additional_params.as_ref().expect("Expected additional params but got none!").clone();
        let pk = Arc::new(self.params.node.get_pk().clone());
        let dst = Arc::new(self.params.dst.clone());

        let num_peers = self.params.node.peer_count();
        assert!(num_peers.is_power_of_two(), "Number of nodes needs to be power of two! (cf. Signature rand_range)");

        //let own_pk = self.params.node.sk_share.to_pk();
        //let own_idx = self.params.node.peer_idx_map.get(&own_pk).expect("Node itself not in peers!");

        // Early exit channel
        let mut rx_exit = subscribe_msg!(&self.params.handle, &self.params.id, Exit<T, V>);

        for j in 1..usize::MAX {
            // ID for this round
            let mut id_j = self.params.id.clone();
            id_j.push(j);

            // Prepare external validation function for view j.
            let ex_validation_fn_closure = ex_validation_fn.clone();
            let pk_closure = pk.clone();
            let leaders_closure = leaders.clone();
            let dst_closure = dst.clone();

            let validation_fn = Arc::new(move |id: &Id, v: &V, (j, sig): &(usize, Option<T>)| {
                if !(ex_validation_fn_closure)(v) {
                    return false;
                }
                if j > &1 {
                    if let Some(l) = leaders_closure.get(*j) {
                        let mut id = id.clone();
                        let _ = id.pop();
                        let _ = id.pop();
                        id.push(*j);
                        id.push(*l);
                        id.push(1);
                        if let Ok(msg) = (&id, &v).prepare() {
                            if let Some(sig) = sig {
                                if pk_closure.verify(&sig, &msg, &dst_closure) {
                                    if j >= &lock {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if j >= &lock {
                        return true;
                    }
                }
                return false;
            });

            // Start FSPB instances for view j.
            // We need to wire up the channels manually here instead of using run_protocol.
            let (tx_fspb_child, mut rx_fspb_receiver) = mpsc::channel(network::network::CHANNEL_LIMIT);
            let mut fspb_receiver_txs = Vec::with_capacity(num_peers);
            for sender in 0..num_peers {
                // Start FSPB receiver
                let add_params = FSPBReceiverParams::new(sender, validation_fn.clone());
                let mut id = id_j.clone();
                id.push(sender);

                // Manual channel management...
                let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
                let params = ProtocolParams::new_raw(self.params.handle.clone(),
                                                     self.params.node.clone(), id, self.params.dst.clone(), tx_fspb_child.clone(), rx);
                let mut fspb_recv = FSPBReceiver::<T, PP, V, (usize, Option<T>), _>::new(params);
                fspb_recv.additional_params(add_params);
                fspb_receiver_txs.push(tx);
                // ... and spawning
                tokio::spawn(async move { fspb_recv.run().await });
                yield_now().await;
            }

            // Start FSPB sender.
            let mut id = id_j.clone();
            id.push(self.params.node.get_own_idx());
            let (tx_fspb_sender, mut rx_fspb_sender) =
                run_protocol!(FSPBSender<T, PP, V, (usize, Option<T>)>, self.params.handle.clone(), self.params.node.clone(), id, self.params.dst.clone());

            // If we have a value, pass it to FSPBSender immediately.
            if let Some(v) = &value {
                tx_fspb_sender.send(FSPBSenderMsg::Send(v.clone(), proof.clone())).await.expect("FSPB Sender unreachable!");
            }

            // Subscribe to done messages
            let mut done_set = HashSet::with_capacity(self.params.node.get_threshold());
            let mut rx_done = subscribe_msg!(&self.params.handle, &id_j, Done<T, V>);

            // Election
            let election_dst = format!("VABA-ELECT-{}", self.params.dst);
            let (tx_election, mut rx_election) = run_protocol!(TSS<T, PP, Id>,
                self.params.handle.clone(), self.params.node.clone(), id_j.clone(), election_dst, id_j.clone());

            // Manually set-up view-change channels
            let (tx_view_change, mut rx_view_change) = mpsc::channel(network::network::CHANNEL_LIMIT);
            let mut view_change_set = HashSet::with_capacity(self.params.node.get_threshold());

            'outer: loop {
                tokio::select! {
                    Some(vaba_msg) = self.params.rx.recv() => {
                        match vaba_msg {
                            VabaControlMsg::Propose(v) => {
                                // Check if we also need to set the key.
                                self.params.handle.handle_stats_event("Propose");
                                if let None = key {
                                    key = Some(Key::new(0, v.clone(), None));
                                }
                                // If there is no value set, set it and try sending the value.
                                if let None = value {
                                    value = Some(v.clone());
                                    // This might return an error if we have already shut down the FSPB sender
                                    let _ = tx_fspb_sender.send(FSPBSenderMsg::Send(v, proof.clone())).await;
                                }
                            },
                            VabaControlMsg::Shutdown(tx_shutdown) => {
                                shutdown!(tx_election, TSSControlMsg::Shutdown);
                                close_and_drain!(rx_election);

                                self.params.handle.unsubscribe::<Done<T, V>>(&id_j).await;
                                close_and_drain!(rx_done);

                                shutdown!(tx_fspb_sender, FSPBSenderMsg::Shutdown);
                                close_and_drain!(rx_fspb_sender);
                                for tx in fspb_receiver_txs.iter() {
                                    shutdown!(tx, pb::messages::Shutdown);
                                }
                                close_and_drain!(rx_fspb_receiver);

                                self.params.handle.unsubscribe::<ViewChange<T, V>>(&id_j).await;
                                close_and_drain!(rx_view_change);

                                self.params.handle.unsubscribe::<Exit<T, V>>(&self.params.id).await;
                                close_and_drain!(rx_exit);

                                close_and_drain!(self.params.rx);

                                self.params.handle.handle_stats_end().await;

                                shutdown_done!(tx_shutdown);
                            }
                        }
                    },

                    // Get FSPB deliveries
                    Some(fspb_deliver) = rx_fspb_receiver.recv() => {
                        match fspb_deliver {
                            FSPBDeliver::Key(mut id, value, proof) => {
                                let k = id.pop().unwrap();
                                d_key.insert((j, k), (value, proof));
                            },
                            FSPBDeliver::Lock(mut id, value, proof) => {
                                let k = id.pop().unwrap();
                                d_lock.insert((j, k), (value, proof));
                            },
                            FSPBDeliver::Commit(mut id, value, proof) => {
                                let k = id.pop().unwrap();
                                d_commit.insert((j, k), (value, proof));
                            }
                        }
                    },

                    // Wait for PB to succeed and broadcast done proof
                    Some(PBProof { id: _, proof }) = rx_fspb_sender.recv() => {
                        let done = Done::new(value.clone().unwrap(), proof);
                        self.params.handle.broadcast(&id_j, &done).await;
                    },

                    // Receive Done proofs and start leader election after having received sufficiently many
                    Some(msg) = rx_done.recv() => {
                        if let Ok(Done{ value, proof }) = msg.get_content::<Done<T, V>>() {
                            let sender = *msg.get_sender();
                            let mut id = id_j.clone();
                            id.push(sender);
                            id.push(4);
                            if spawn_blocking!(self.params.node.get_pk().verify(&proof, &(&id, &value).prepare_panic(), &self.params.dst)) {
                                done_set.insert(sender);
                                if done_set.len() >= self.params.node.get_threshold() {
                                    // This might fail if the signature has already been completed
                                    let _ = tx_election.send(TSSControlMsg::Sign).await;

                                    // Unsubscribe and drain Done messages
                                    self.params.handle.unsubscribe::<Done<T, V>>(&id_j).await;
                                    close_and_drain!(rx_done);
                                }
                            }
                        }
                    },

                    // Election results
                    Some(Deliver { id: _, proof }) = rx_election.recv() => {
                        assert_eq!(leaders.len(), j, "Leader got inserted twice!");
                        let leader = proof.rand_range(0, num_peers).expect("Rand range failed!");
                        leaders.push(leader);

                        // Shutdown election
                        shutdown!(tx_election, TSSControlMsg::Shutdown);
                        close_and_drain!(rx_election);

                        // Unsubscribe and drain Done messages
                        self.params.handle.unsubscribe::<Done<T, V>>(&id_j).await;
                        close_and_drain!(rx_done);

                        // Shutdown FSPB
                        shutdown!(tx_fspb_sender, FSPBSenderMsg::Shutdown);
                        close_and_drain!(rx_fspb_sender);
                        for tx in fspb_receiver_txs.iter() {
                            shutdown!(tx, pb::messages::Shutdown);
                        }
                        close_and_drain!(rx_fspb_receiver);

                        // Subscribe to view-change message
                        self.params.handle.subscribe::<ViewChange<T, V>>(&id_j, tx_view_change.clone()).await;

                        // Send view change
                        let view_change = ViewChange::new(j, leader, &mut d_key, &mut d_lock, &mut d_commit);
                        self.params.handle.broadcast(&id_j, &view_change).await;
                    },

                    // View change
                    Some(msg) = rx_view_change.recv() => {
                        let mut decided = false;

                        let sender = *msg.get_sender();
                        if view_change_set.contains(&sender) { continue; }
                        view_change_set.insert(sender);

                        if let Ok(ViewChange { key: keyy, lock: lockk, commit }) = msg.get_content::<ViewChange<T, V>>() {
                            let leader = leaders.get(j).expect("Leader not given. This should never happen.");
                            let mut id = id_j.clone();
                            id.push(*leader);
                            if let Some((value, proof)) = commit {
                                id.push(3);
                                if spawn_blocking!(self.params.node.get_pk().verify(&proof, &(&id, &value).prepare_panic(), &self.params.dst)) {
                                    self.params.tx.send(Decide(value.clone())).await.expect("Parent unreachable!");
                                    let exit = Exit::new(j, *leader, value, proof);
                                    self.params.handle.broadcast(&self.params.id, &exit).await;
                                    decided = true;
                                }
                                id.pop();
                            }
                            if let Some((value, proof)) = lockk {
                                id.push(2);
                                if spawn_blocking!(self.params.node.get_pk().verify(&proof, &(&id, &value).prepare_panic(), &self.params.dst)) {
                                    lock = j;
                                }
                                id.pop();
                            }
                            if let Some((value, proof)) = keyy {
                                if key.is_none() || j > key.as_ref().unwrap().view {
                                    id.push(1);
                                    if spawn_blocking!(self.params.node.get_pk().verify(&proof, &(&id, &value).prepare_panic(), &self.params.dst)) {
                                        key = Some(Key::new(j, value, Some(proof)));
                                    }
                                    id.pop();
                                }
                            }
                        }
                        if decided || view_change_set.len() >= self.params.node.get_threshold() {
                            // Unsubscribe view change
                            self.params.handle.unsubscribe::<ViewChange<T, V>>(&id_j).await;
                            close_and_drain!(rx_view_change);

                            match key.clone() {
                                Some(key) => {
                                    value = Some(key.value);
                                    proof = (key.view, key.proof);
                                },
                                None => log::warn!("Key none. This probably shouldn't happen?"),
                            }
                            break 'outer;
                        }
                        if decided {
                            // Shut down the remaining channels
                            self.params.handle.unsubscribe::<Exit<T, V>>(&self.params.id).await;
                            close_and_drain!(rx_exit);
                            close_and_drain!(self.params.rx);
                            self.params.handle.handle_stats_end().await;
                            return;
                        }
                    },

                    // Premature exit
                    Some(msg) = rx_exit.recv() => {
                        if let Ok(Exit { view, leader, value, proof }) = msg.get_content::<Exit<T, V>>() {
                            let mut id = self.params.id.clone();
                            id.push(view);
                            id.push(leader);
                            id.push(3);

                            if spawn_blocking!(self.params.node.get_pk().verify(&proof, &(&id, &value).prepare_panic(), &self.params.dst)) {
                                self.params.tx.send(Decide(value.clone())).await.expect("Parent unreachable!");
                                let exit = Exit::new(j, leader, value, proof);
                                self.params.handle.broadcast(&self.params.id, &exit).await;

                                // Shutdown election
                                shutdown!(tx_election, TSSControlMsg::Shutdown);
                                close_and_drain!(rx_election);

                                // Unsubscribe and drain Done messages
                                self.params.handle.unsubscribe::<Done<T, V>>(&id_j).await;
                                close_and_drain!(rx_done);

                                // Shutdown FSPB
                                shutdown!(tx_fspb_sender, FSPBSenderMsg::Shutdown);
                                close_and_drain!(rx_fspb_sender);
                                for tx in fspb_receiver_txs.iter() {
                                    shutdown!(tx, pb::messages::Shutdown);
                                }
                                close_and_drain!(rx_fspb_receiver);

                                self.params.handle.unsubscribe::<ViewChange<T, V>>(&id_j).await;
                                close_and_drain!(rx_view_change);

                                self.params.handle.unsubscribe::<Exit<T, V>>(&self.params.id).await;
                                close_and_drain!(rx_exit);

                                close_and_drain!(self.params.rx);

                                self.params.handle.handle_stats_end().await;

                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_blstrs::threshold_sig::BlstrsSignature;
    use protocol::tests::generate_nodes;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_vaba() {
        let (nodes, handles) = generate_nodes::<BlstrsSignature, ()>(10094, 10098, 2, 2, ());

        let id = Id::default();
        let dst = "DST".to_string();

        let mut txs = Vec::new();
        let mut rxs = Vec::new();

        for (node, handle) in nodes.iter().zip(handles.iter()) {
            let (tx, rx) =
                run_protocol!(Vaba::<BlstrsSignature, (), usize, _>, handle.clone(), node.clone(), id.clone(), dst.clone(), Arc::new(|v: &usize| *v == 1));
            txs.push(tx);
            rxs.push(rx);
        }
        for (i, tx) in txs.iter().enumerate() {
            tx.send(VabaControlMsg::Propose(i % 2)).await.unwrap();  // Add some non-determinism where nodes propose bad values
        }
        for rx in rxs.iter_mut() {
            match rx.recv().await {
                Some(Decide { 0: value }) => {
                    assert_eq!(value, 1);
                },
                None => assert!(false),
            }
        }
        for tx in txs.iter() {
            shutdown!(tx, VabaControlMsg::Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
}
