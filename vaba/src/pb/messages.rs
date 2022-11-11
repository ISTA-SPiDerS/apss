use network::tokio::sync::oneshot;
use network::message::Id;

/// Message delivered by receiver to parent
#[derive(Debug)]
pub struct PBDeliver<V, P> {
    pub id: Id,
    pub value: V,
    pub proof: P,
}

impl<V, P> PBDeliver<V, P> {
    pub fn new(id: Id, value: V, proof: P) -> Self {
        Self { id, value, proof }
    }
}

/// Proof delivered by the sender to the parent
#[derive(Debug)]
pub struct PBProof<P> {
    pub id: Id,
    pub proof: P,
}

impl<P> PBProof<P> {
    pub fn new(id: Id, proof: P) -> Self {
        Self { id, proof }
    }
}

/// Shutdown message
#[derive(Debug)]
pub struct Shutdown(pub oneshot::Sender<()>);

#[derive(Debug)]
pub enum FSPBSenderMsg<V, P> {
    Send(V, P),
    Shutdown(oneshot::Sender<()>),
}
/// Key, Lock and Commit messages that might be delivered by the FSPB receiver
#[derive(Debug)]
pub enum FSPBDeliver<V, P> {
    Key(Id, V, P),
    Lock(Id, V, P),
    Commit(Id, V, P),
}