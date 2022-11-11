use std::marker::PhantomData;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use crypto::threshold_sig::{CombinableSignature, PublicKey, Signable};
use network::message::Id;
use network::tokio;
use network::tokio::sync::mpsc;
use protocol::{Protocol, ProtocolParams, run_protocol};
use utils::{close_and_drain, shutdown, shutdown_done};
use utils::tokio::task::yield_now;
use crate::pb::messages::FSPBSenderMsg;
use super::messages::{Shutdown, PBProof, FSPBDeliver, PBDeliver};
use super::sspb::{SSPBReceiver, SSPBReceiverParams, SSPBSender};


/// FSPB Sender [VABA, Alg. 3]
pub struct FSPBSender<T, PP, V, PEx>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, FSPBSenderMsg<V, PEx>, PBProof<T>>,
}

impl<T, PP, V, PEx> Protocol<T, PP, (V, PEx), FSPBSenderMsg<V, PEx>, PBProof<T>> for FSPBSender<T, PP, V, PEx>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, FSPBSenderMsg<V, PEx>, PBProof<T>>) -> Self {
        Self { params }
    }
}

impl<T, PP, V, PEx> FSPBSender<T, PP, V, PEx>
    where
        T: 'static + Send + Sync + std::fmt::Debug + Clone + Serialize + CombinableSignature,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PSK: Send + Sync,
        T::PSig: 'static + Send + Sync + DeserializeOwned,
        T::PK: Send + Sync,
        V: 'static + Send + Sync + Clone + Serialize,
        PEx: 'static + Send + Sync + Clone + Serialize,
        PP: 'static + Send + Sync
{
    pub async fn run(&mut self) {
        // Wait for initial value or shut down.
        if let Some(msg) = self.params.rx.recv().await {
            match msg {
                // Shutdown before sending something
                FSPBSenderMsg::Shutdown(tx_shutdown) => {
                    close_and_drain!(self.params.rx);
                    shutdown_done!(tx_shutdown);
                },
                // Broadcast a message
                FSPBSenderMsg::Send(value, proof) => {
                    // Initially, internal validity proof is empty.
                    let mut p_in: Option<T> = None;
                    // Repeat PB four times.
                    for j in 1..=4usize {
                        let mut id = self.params.id.clone();
                        id.push(j);
                        let add_params = (value.clone(), (proof.clone(), p_in.take()));
                        let (tx, mut rx) = run_protocol!(SSPBSender<T, PP, V, (PEx, Option<T>)>,
                            self.params.handle.clone(), self.params.node.clone(), id, self.params.dst.clone(), add_params);
                        tokio::select! {
                            // Wait until previous PB instance returns a proof
                            Some(pb_proof) = rx.recv() => {
                                p_in = Some(pb_proof.proof);
                            },
                            // Shutdown handler
                            Some(FSPBSenderMsg::Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                                shutdown!(tx, Shutdown);
                                close_and_drain!(self.params.rx);
                                shutdown_done!(tx_shutdown);
                            }
                        }
                        // Close connection to previous instance
                        close_and_drain!(rx);
                    }
                    // Unwrap here is safe since we know that p_in will be set in the select!
                    self.params.tx.send(PBProof::new(self.params.id.clone(), p_in.unwrap())).await.expect("Parent unreachable!");

                    // Shut down cleanly
                    close_and_drain!(self.params.rx);
                    return;
                }
            }
        }
    }
}

/// FSPB Receiver parameters which comprise the [sender] and the external validity predicate [validation_fn].
pub struct FSPBReceiverParams<V, PEx, F> {
    sender: usize,
    validation_fn: Arc<F>,
    _value: PhantomData<(V, PEx)>,
}

impl<V, PEx, F> FSPBReceiverParams<V, PEx, F> {
    pub fn new(sender: usize, validation_fn: Arc<F>) -> Self {
        Self { sender, validation_fn, _value: PhantomData }
    }
}

pub struct FSPBReceiver<T, PP, V, PEx, F>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, Shutdown, FSPBDeliver<V, T>>,
    additional_params: Option<FSPBReceiverParams<V, PEx, F>>,
}

impl<T, PP, V, PEx, F> Protocol<T, PP, FSPBReceiverParams<V, PEx, F>, Shutdown, FSPBDeliver<V, T>> for FSPBReceiver<T, PP, V, PEx, F>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, Shutdown, FSPBDeliver<V, T>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: FSPBReceiverParams<V, PEx, F>) {
        self.additional_params = Some(params);
    }
}

impl<T, PP, V, PEx, F> FSPBReceiver<T, PP, V, PEx, F>
    where
        T: 'static + Send + Sync + std::fmt::Debug + Serialize + DeserializeOwned + CombinableSignature,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PSig: 'static + Send + Sync + Serialize,
        T::PSK: Send + Sync,
        T::PK: Send + Sync + Clone,
        V: 'static + Send + Sync + std::fmt::Debug + DeserializeOwned + Serialize,
        PEx: 'static + Send + Sync + DeserializeOwned + Serialize,
        F: Fn(&Id, &V, &PEx) -> bool + 'static + Send + Sync,
        PP: 'static + Send + Sync,
{
    pub async fn run(&mut self) {
        let additional_params = Arc::new(self.additional_params.take().expect("Expected additional params but got none!"));

        // Create external validity function closure [VABA, Alg. 3 Lines 6-11]
        let fn_add_params = additional_params.clone();
        let pk = self.params.node.get_pk().clone();
        let dst = self.params.dst.clone();
        let validation_fn = Arc::new(move |id: &Id, v: &V, (p_ex, p_in): &(PEx, Option<T>)| {
            match id.last() {
                Some(1) => {
                    let ret = (fn_add_params.validation_fn)(id, v, p_ex);
                    ret
                },
                Some(j) => {
                    let mut id = id.clone();
                    id.pop();
                    id.push(j-1);
                    let ack = (&id, &v).prepare_panic();
                    let ret = pk.verify(p_in.as_ref().unwrap(), &ack, &dst);
                    ret
                }
                _ => {
                    false
                },
            }
        });

        // Start all four instances of the PB. We wire the channels manually.
        let mut txs = Vec::with_capacity(4);
        let (tx_sspb, mut rx_sspb) = mpsc::channel(network::network::CHANNEL_LIMIT);  // Channel child -> parent

        for j in 1..=4usize {
            // Set up id
            let mut id = self.params.id.clone();
            id.push(j);
            // Channel parent -> child
            let (tx, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
            txs.push(tx);

            let params = ProtocolParams::new_raw(self.params.handle.clone(),
                                                 self.params.node.clone(), id, self.params.dst.clone(), tx_sspb.clone(), rx);
            let add_params = SSPBReceiverParams::new(additional_params.sender, validation_fn.clone());
            let mut sspb_recv = SSPBReceiver::<T, PP, V, (PEx, Option<T>), _>::new(params);
            sspb_recv.additional_params(add_params);
            tokio::spawn(async move { sspb_recv.run().await });
            yield_now().await;
        }

        loop {
            tokio::select! {
                Some(PBDeliver{mut id, value, proof: (_, proof)}) = rx_sspb.recv() => {
                    let last = id.pop().unwrap();  // Since we started PB, we know that it contains at least one element.
                    match last {
                        1 => {},
                        j @ 2..=4 => {
                            if let Some(proof) = proof {
                                match j {
                                    2 => self.params.tx.send(FSPBDeliver::Key(id, value, proof)).await.expect("Parent unreachable!"),
                                    3 => self.params.tx.send(FSPBDeliver::Lock(id, value, proof)).await.expect("Parent unreachable!"),
                                    4 => self.params.tx.send(FSPBDeliver::Commit(id, value, proof)).await.expect("Parent unreachable!"),
                                    _ => unreachable!()
                                }
                            }
                        },
                        i => log::warn!("Received deliver with j = {}! This should never happen.", i),
                    }
                },
                // Shutdown handler
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    for tx in txs {
                        shutdown!(tx, Shutdown);
                    }
                    close_and_drain!(self.params.rx);
                    shutdown_done!(tx_shutdown);
                }
            }
        }
    }
}
#[cfg(test)]
pub mod test {
    use crypto_blstrs::threshold_sig::BlstrsSignature;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_fspb() {
        let (nodes, handles) = generate_nodes::<BlstrsSignature, ()>(10091, 10094, 2, 2, ());

        let id = Id::new(0, vec![0]);
        let dst = "DST".to_string();
        let msg = "Test".to_string();

        let mut recvs: Vec<_> = Vec::new();
        let mut sender = None;
        let sender_idx = nodes[0].get_own_idx();
        for (node, handle) in nodes.iter().zip(handles.iter()) {
            if sender_idx == node.get_own_idx() {
                let tx = run_protocol!(FSPBSender<BlstrsSignature, (), String, usize>, handle.clone(), node.clone(), id.clone(), dst.clone());
                tx.0.send(FSPBSenderMsg::Send(msg.clone(), 42)).await.unwrap();
                sender = Some(tx)
            }
            let add = FSPBReceiverParams::new(sender_idx, Arc::new(|_: &Id, _: &String, p: &usize| *p == 42));
            recvs.push(run_protocol!(FSPBReceiver<BlstrsSignature, (), String, usize, _>, handle.clone(), node.clone(), id.clone(), dst.clone(), add));
        }
        let proof = sender.take().unwrap().1.recv().await.unwrap();
        let mut id_proof = id.clone();
        assert_eq!(id_proof, proof.id);
        id_proof.push(4);
        let ack = (&id_proof, &msg).prepare_panic();
        assert!(nodes[0].get_pk().verify(&proof.proof, &ack, &dst));
        for recv in recvs.iter_mut() {
            let mut key = false;
            let mut lock = false;
            let mut commit = false;
            for _ in 0..3 {
                let val = recv.1.recv().await.unwrap();
                let (id, value, proof, j) = match val {
                    FSPBDeliver::Key(id, value, proof) => {
                        key = true;
                        (id, value, proof, 1)
                    },
                    FSPBDeliver::Lock(id, value, proof) => {
                        lock = true;
                        (id, value, proof, 2)
                    },
                    FSPBDeliver::Commit(id, value, proof) => {
                        commit = true;
                        (id, value, proof, 3)
                    },
                };
                assert_eq!(&value, &msg);
                let mut id_proof = id.clone();
                id_proof.push(j);
                let ack = (&id_proof, &msg).prepare_panic();
                assert!(nodes[0].get_pk().verify(&proof, &ack, &dst));
            }
            assert!(key && lock && commit);
            shutdown!(recv.0, Shutdown);
        }
        for handle in handles {
            handle.shutdown().await;
        }
    }
}