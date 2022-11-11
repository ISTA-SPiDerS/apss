use std::marker::PhantomData;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use crypto::threshold_sig::{CombinableSignature, SecretKey, Signable, SignatureSet};
use network::message::Id;
use network::subscribe_msg;
use network::tokio;
use protocol::{Protocol, ProtocolParams};
use utils::{close_and_drain, rayon, shutdown_done, spawn_blocking};
use super::messages::{Shutdown, PBProof, PBDeliver};


/// Single stage (= f+1) Provable Broadcast Sender [VABA, Alg. 1]
pub struct SSPBSender<T, PP, V, P>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, Shutdown, PBProof<T>>,
    additional_params: Option<(V, P)>,
}

impl<T, PP, V, P> Protocol<T, PP, (V, P), Shutdown, PBProof<T>> for SSPBSender<T, PP, V, P>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, Shutdown, PBProof<T>>) -> Self {
        Self { params, additional_params: None }
    }


    fn additional_params(&mut self, params: (V, P)) {
        self.additional_params = Some(params);
    }
}

impl<T, PP, V, P> SSPBSender<T, PP, V, P>
    where
        T: Send + std::fmt::Debug + CombinableSignature,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PSK: Send + Sync,
        T::PSig: 'static + Send + Sync + DeserializeOwned,
        T::PK: Send + Sync,
        V: 'static + Clone + Serialize,
        P: 'static + Clone + Serialize,
        PP: Send + Sync
{
    pub async fn run(&mut self) {
        let (value, proof) = self.additional_params.take().expect("Expected additional params but got none!");

        // Setup signature set
        let ack = (&self.params.id, &value).prepare_panic();
        let mut partial_sigs = SignatureSet::new(self.params.node.get_threshold(), &ack, &self.params.dst);

        // Broadcast value and subscribe to messages
        self.params.handle.broadcast(&self.params.id, &(value, proof)).await;
        let mut rx_sub = subscribe_msg!(self.params.handle, &self.params.id, T::PSig);

        loop {
            tokio::select! {
                // Receive replies from other nodes
                Some(resp) = rx_sub.recv() => {
                    // Try to extract signature and verify
                    if let Ok(sig) = resp.get_content::<T::PSig>() {
                        if let Some(sender) = self.params.node.get_peer_pk_share(*resp.get_sender()) {
                            spawn_blocking!(partial_sigs.insert(sender, sig));
                            if partial_sigs.can_combine() {
                                // Combine signature
                                let combined = spawn_blocking!(partial_sigs.combine()).expect("Combine failed! This shouldn't happen.");
                                self.params.tx.send(PBProof::new(self.params.id.clone(), combined)).await.expect("Parent unreachable!");

                                // Shut down
                                self.params.handle.unsubscribe::<T::PSig>(&self.params.id).await;
                                close_and_drain!(rx_sub);
                                close_and_drain!(self.params.rx);
                                return;
                            }
                        }
                    }
                },
                // Shutdown handler
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<T::PSig>(&self.params.id).await;
                    close_and_drain!(rx_sub);
                    close_and_drain!(self.params.rx);
                    shutdown_done!(tx_shutdown);
                }
            }
        }
    }
}

/// Single stage (= f+1) PB Receiver parameters which comprise the [sender] and the external validity predicate [validation_fn].
pub struct SSPBReceiverParams<V, P, F> {
    sender: usize,
    validation_fn: Arc<F>,
    _value: PhantomData<(V, P)>,
}

impl<V, P, F> SSPBReceiverParams<V, P, F> {
    /// Creates new parameters given the [sender] and [validation_fn].
    pub fn new(sender: usize, validation_fn: Arc<F>) -> Self {
        Self { sender, validation_fn, _value: PhantomData }
    }
}

/// Single stage (= f+1) PB Receiver [VABA, Alg. 2]
pub struct SSPBReceiver<T, PP, V, P, F>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, Shutdown, PBDeliver<V, P>>,
    additional_params: Option<SSPBReceiverParams<V, P, F>>,
}

impl<T, PP, V, P, F> Protocol<T, PP, SSPBReceiverParams<V, P, F>, Shutdown, PBDeliver<V, P>> for SSPBReceiver<T, PP, V, P, F>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, Shutdown, PBDeliver<V, P>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: SSPBReceiverParams<V, P, F>) {
        self.additional_params = Some(params);
    }
}

impl<T, PP, V, P, F> SSPBReceiver<T, PP, V, P, F>
    where
        T: CombinableSignature,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PSig: 'static + Send + Serialize,
        T::PSK: Send + Sync,
        T::PK: Send + Sync,
        V: 'static + Send + Sync + DeserializeOwned + Serialize,
        P: 'static + Send + Sync + DeserializeOwned + Serialize,
        F: Fn(&Id, &V, &P) -> bool + Send + Sync,
        PP: Send + Sync,
{
    pub async fn run(&mut self) {
        let additional_params = self.additional_params.take().expect("Expected additional params but got none!");

        // Subscribe to messages and receive broadcast
        let mut rx_sub = subscribe_msg!(self.params.handle, &self.params.id, (V, P));
        loop {
            tokio::select! {
                Some(msg) = rx_sub.recv() => {
                    let sender = *msg.get_sender();
                    // Only handle messages by the PB sender
                    if sender == additional_params.sender {
                        // Try to extract value and check that it's externally valid
                        if let Ok((value, proof)) = msg.get_content::<(V, P)>() {
                            if spawn_blocking!((additional_params.validation_fn)(&self.params.id, &value, &proof)) {
                                // Sign ack and reply to sender
                                let ack = (&self.params.id, &value).prepare_panic();
                                let sig = spawn_blocking!(self.params.node.get_sk_share().sign(&ack, &self.params.dst));
                                self.params.handle.send(sender, &self.params.id, &sig).await;

                                // Deliver value to parent
                                log::debug!("Delivering value for id {:?}!", self.params.id);
                                let _ = self.params.tx.send(PBDeliver::new(self.params.id.clone(), value, proof)).await;

                                // Shut down
                                self.params.handle.unsubscribe::<(V, P)>(&self.params.id).await;
                                close_and_drain!(rx_sub);
                                close_and_drain!(self.params.rx);
                                return;
                            }
                        }
                    }
                },
                // Shutdown handler
                Some(Shutdown(tx_shutdown)) = self.params.rx.recv() => {
                    self.params.handle.unsubscribe::<(V, P)>(&self.params.id).await;
                    close_and_drain!(rx_sub);
                    close_and_drain!(self.params.rx);
                    shutdown_done!(tx_shutdown);
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use crypto::threshold_sig::PublicKey;
    use crypto_blstrs::threshold_sig::BlstrsSignature;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::shutdown;
    use super::*;

    async fn test_pb_thresh(port_start: u16, port_end: u16, corruption_limit: usize, threshold: usize) {
        let (nodes, handles) = generate_nodes::<BlstrsSignature, ()>(port_start, port_end, corruption_limit, threshold, ());

        let id = Id::default();
        let dst = "DST".to_string();
        let msg = "Test".to_string();

        let mut recvs: Vec<_> = Vec::new();
        let mut sender = None;
        let sender_idx = nodes[0].get_own_idx();
        for (node, handle) in nodes.iter().zip(handles.iter()) {
            if sender_idx == node.get_own_idx() {
                let add = (msg.clone(), 42);
                sender = Some(run_protocol!(SSPBSender<BlstrsSignature, (), String, usize>, handle.clone(), node.clone(), id.clone(), dst.clone(), add));
            }
            let add = SSPBReceiverParams::new(sender_idx, Arc::new(|_: &Id, _: &String, p: &usize| *p == 42));
            recvs.push(run_protocol!(SSPBReceiver<BlstrsSignature, (), String, usize, _>, handle.clone(), node.clone(), id.clone(), dst.clone(), add));
        }
        let proof = sender.unwrap().1.recv().await.unwrap();
        assert_eq!(&proof.id, &id);
        let ack = (&id, &msg).prepare_panic();
        assert!(nodes[0].get_pk().verify(&proof.proof, &ack, &dst));
        for recv in recvs.iter_mut() {
            let val = recv.1.recv().await.unwrap();
            assert_eq!(val.id, id);
            assert_eq!(val.value, msg.clone());
            assert_eq!(val.proof, 42);
            shutdown!(recv.0, Shutdown);
        }
        for handle in handles.into_iter() {
            handle.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_pb() {
        test_pb_thresh(10085, 10088, 1, 2).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_pb_n_of_n() {
        test_pb_thresh(10088, 10091, 1, 3).await;
    }
}