use serde::de::DeserializeOwned;
use serde::Serialize;

use crypto::threshold_sig::{CombinableSignature, SecretKey, Signable, SignatureSet};
use network::{tokio, subscribe_msg};
use protocol::{Protocol, ProtocolParams};
use utils::{close_and_drain, rayon, shutdown_done, spawn_blocking};

use crate::messages::{Deliver, TSSControlMsg};

pub mod messages;

pub struct TSS<T, PP, M>
    where
        T: CombinableSignature,
{
    params: ProtocolParams<T, PP, TSSControlMsg, Deliver<T>>,
    additional_params: Option<M>,
}

impl<T, PP, M> Protocol<T, PP, M, TSSControlMsg, Deliver<T>> for TSS<T, PP, M>
    where
        T: CombinableSignature,
{
    fn new(params: ProtocolParams<T, PP, TSSControlMsg, Deliver<T>>) -> Self {
        Self { params, additional_params: None }
    }

    fn additional_params(&mut self, params: M) {
        self.additional_params = Some(params);
    }
}

impl<T, PP, M> TSS<T, PP, M>
    where
        T: Send + CombinableSignature + std::fmt::Debug,
        T::PPK: 'static + Send + Sync + Eq + std::hash::Hash + std::fmt::Debug + Clone + Serialize + DeserializeOwned,
        T::PK: Send + Sync,
        T::PSK: Send + Sync,
        T::PSig: 'static + Send + Sync + Serialize + DeserializeOwned,
        M: Sync + Signable,
        PP: Send + Sync
{
    pub async fn run(&mut self) {
        let msg = self.additional_params.take().expect("Expected additional params but got none!");
        let msg_prepared = msg.prepare_panic();

        // Prepare partial signature for broadcast

        // Initialize partial signature set
        let mut partial_sigs = SignatureSet::new(self.params.node.get_threshold(), &msg_prepared, &self.params.dst);

        // Subscribe to ID to receive other partial signatures
        let mut rx_sub = subscribe_msg!(self.params.handle, &self.params.id, T::PSig);

        // Handle partial signatures
        loop {
            tokio::select! {
                // Handle partial signatures
                Some(sig_msg) = rx_sub.recv() => {
                    if let Some(sender) = self.params.node.get_peer_pk_share(*sig_msg.get_sender()) {
                        match sig_msg.get_content::<T::PSig>() {
                            Ok(sig) => {
                                spawn_blocking!(partial_sigs.insert(sender, sig));
                                if partial_sigs.can_combine() {
                                    let combined = spawn_blocking!(partial_sigs.combine()).expect("Combine failed!");
                                    self.params.tx.send(Deliver::new(self.params.id.clone(), combined)).await.expect("Parent unreachable!");

                                    // Shut down
                                    self.params.handle.unsubscribe::<T::PSig>(&self.params.id).await;
                                    close_and_drain!(rx_sub);
                                    close_and_drain!(self.params.rx);
                                    return;
                                }
                            },
                            Err(_) => continue,
                        }
                    }
                },
                Some(msg) = self.params.rx.recv() => {
                    match msg {
                        // Shutdown handler
                        TSSControlMsg::Shutdown(tx_shutdown) => {
                            self.params.handle.unsubscribe::<T::PSig>(&self.params.id).await;
                            close_and_drain!(rx_sub);
                            close_and_drain!(self.params.rx);
                            shutdown_done!(tx_shutdown);
                        },
                        // Start signing
                        TSSControlMsg::Sign => {
                            let sig = spawn_blocking!(self.params.node.get_sk_share().sign(&msg_prepared, &self.params.dst));
                            self.params.handle.broadcast(&self.params.id, &sig).await;
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
    use crypto::threshold_sig::PublicKey;
    use network::message::Id;
    use protocol::run_protocol;
    use protocol::tests::generate_nodes;
    use utils::shutdown;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_tss() {
        let (nodes, handles) = generate_nodes::<BlstrsSignature, ()>(10082, 10085, 2, 2, ());

        let id = Id::default();
        let dst = "DST".to_string();
        let msg = "Test".to_string();

        let mut chans: Vec<_> = Vec::new();
        for (node, handle) in nodes.iter().zip(handles.iter()) {
            chans.push(run_protocol!(TSS<BlstrsSignature, (), String>, handle.clone(), node.clone(), id.clone(), dst.clone(), msg.clone()));
        }
        for (tx, _) in chans.iter() {
            tx.send(TSSControlMsg::Sign).await.unwrap();
        }
        for (tx, mut rx) in chans.into_iter() {
            let deliver = rx.recv().await.unwrap();
            assert!(nodes[0].get_pk().verify(&deliver.proof, &msg.prepare_panic(), &dst));
            shutdown!(tx, TSSControlMsg::Shutdown);
        }
        for handle in handles.into_iter() {
            handle.shutdown().await;
        }
    }
}