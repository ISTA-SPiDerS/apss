use network::message::Id;
use network::tokio::sync::oneshot;

/// TSS delivery message
#[derive(Debug)]
pub struct Deliver<T>{
    pub id: Id,
    pub proof: T,
}

impl<T> Deliver<T> {
    pub fn new(id: Id, proof: T) -> Self {
        Self { id, proof }
    }
}

/// Shutdown message
#[derive(Debug)]
pub enum TSSControlMsg {
    Sign,
    Shutdown(oneshot::Sender<()>),
}

