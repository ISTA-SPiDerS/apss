//! The protocols considered here identify nodes by public keys of the shares of a global secret.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec::Drain;
use anyhow::{Result, ensure};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crypto::threshold_sig::{CombinableSignature, SamplableKey, SecretKey, SharableKey};
use crypto::threshold_sig::PartialKey;
use network::message::Id;
use network::network::manager::ManagerHandle;

/// Enables the caller to extract public parameters [P].
pub trait PublicParameters<P> {
    /// Returns a reference to public parameters [P].
    fn get_pp(&self) -> &P;
}

/// A [Node] is generic over a [CombinableSignature] scheme. The index of the partial public key
/// serve as a node's identifier.
///
/// A node is defined by
/// - a global public key [pk],
/// - a node's share [sk_share] of the secret key corresponding to [pk],
/// - the peers' [pk_shares] (note that the node must also be a peer to itself)
/// - a limit on corrupt parties such that [corruption_limit] is strictly larger than the number of corrupt parties,
/// - a global reconstruction threshold such that at least [threshold] parties are required to reconstruct [pk],
/// - the socket addresses of the node's [peers],
/// - other public parameters [pp].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node<T, PP>
    where
        T: CombinableSignature,
{
    pk: T::PK,
    sk_share: T::PSK,
    pk_shares: Vec<T::PPK>,
    corruption_limit: usize,
    threshold: usize,
    // Serde is not able to derive the correct bounds here
    #[serde(bound(serialize = "T::PPK: Serialize + Eq + std::hash::Hash"))]
    #[serde(bound(deserialize = "T::PPK: Deserialize<'de> + Eq + std::hash::Hash"))]
    socket_addrs: Vec<SocketAddr>,
    pp: PP,
}

impl<T, PP> Node<T, PP>
    where
        T: CombinableSignature,
{
    /// Creates a new node given [pk], [threshold], [sk_share], [peers] and public parameters for the commitments ([poly_commit] & [vec_commit]).
    #[inline]
    pub fn new(pk: T::PK, sk_share: T::PSK, pk_shares: Vec<T::PPK>, corruption_limit: usize, threshold: usize, socket_addrs: Vec<SocketAddr>, pp: PP) -> Self {
        Self { pk, sk_share, pk_shares, corruption_limit, threshold, socket_addrs, pp }
    }

    /// Returns the [pk].
    #[inline]
    pub fn get_pk(&self) -> &T::PK {
        &self.pk
    }

    /// Returns the [sk_share].
    #[inline]
    pub fn get_sk_share(&self) -> &T::PSK {
        &self.sk_share
    }

    /// Returns the node's index.
    #[inline]
    pub fn get_own_idx(&self) -> usize {
        self.sk_share.index()
    }

    /// Returns the node's partial public key corresponding to [sk_share].
    #[inline]
    pub fn get_own_pk_share(&self) -> T::PPK {
        self.sk_share.to_pk()
    }

    /// Returns a peer's public key given its index.
    #[inline]
    pub fn get_peer_pk_share(&self, idx: usize) -> Option<&T::PPK> {
        self.pk_shares.get(idx)
    }

    /// Returns the number of peers.
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.pk_shares.len()
    }

    /// Returns the [corruption_limit].
    #[inline]
    pub fn get_corruption_limit(&self) -> usize {
        self.corruption_limit
    }

    /// Returns the [threshold].
    #[inline]
    pub fn get_threshold(&self) -> usize {
        self.threshold
    }

    /// Sets the [sk_share].
    #[inline]
    pub fn set_sk_share(&mut self, sk_share: T::PSK) {
        self.sk_share = sk_share;
    }

    /// Sets the [pk_shares].
    #[inline]
    pub fn set_pk_shares(&mut self, pk_shares: Vec<T::PPK>) {
        self.pk_shares = pk_shares;
    }

    /// Drains the [pk_shares].
    #[inline]
    pub fn drain_pk_shares(&mut self) -> Drain<T::PPK> {
        self.pk_shares.drain(..)
    }

    /// Returns the node's IP
    #[inline]
    pub fn get_own_socket_addr(&self) -> &SocketAddr {
        self.socket_addrs.get(self.get_own_idx()).expect("Self not in socket_addrs!")
    }
}

impl<T, PP> Node<T, PP>
    where
        T: CombinableSignature,
        T::PK: Clone,
        T::PPK: Clone,
        PP: Clone,
{
    /// Generates a set of nodes with corresponding [node_addrs] and correlated keys (given a [corruption_limit] and reconstruction [threshold]).
    pub fn generate_nodes(peers: Vec<SocketAddr>, corruption_limit: usize, threshold: usize, pp: PP) ->  Result<Vec<Node<T, PP>>> {
        let n = peers.len();
        ensure!(threshold <= n, "threshold must be less or equal than node count!");

        let sk = T::SK::sample();
        let pk = sk.to_pk();
        let sk_shares = sk.share(n, threshold);
        let pk_shares: Vec<_> = sk_shares.iter().map(T::PSK::to_pk).collect();

        let mut nodes = Vec::with_capacity(n);
        for sk_share in sk_shares.into_iter() {
            let node: Self = Self::new(pk.clone(), sk_share, pk_shares.clone(), corruption_limit, threshold, peers.clone(), pp.clone());
            nodes.push(node);
        }
        Ok(nodes)
    }

    /// Returns a hashmap suitable for a manager.
    pub fn get_peer_map(&self) -> HashMap<usize, SocketAddr> {
        HashMap::from_iter(self.pk_shares.iter()
            .map(|ppk| (ppk.index(), self.socket_addrs.get(ppk.index()).expect("Peer not in socket_addrs!").clone())))
    }

    /// Spawns the [Manager] for this node and returns a handle.
    /// If [stats] is [true], the manager will track performance statistics.
    pub fn spawn_manager(&self, stats: bool) -> ManagerHandle<usize> {
        let addr = self.get_own_socket_addr();
        ManagerHandle::new(self.get_own_idx(),addr.port(), self.get_peer_map(), stats)
    }
}

// Implement PublicParameters for the Node itself.
impl<A, T, PP> PublicParameters<A> for Node<T, PP>
    where
        T: CombinableSignature,
        PP: PublicParameters<A>
{
    #[inline]
    fn get_pp(&self) -> &A {
        self.pp.get_pp()
    }
}

/// Common parameters required by a protocol. Namely,
/// - a [ManagerHandle] to interact with the network,
/// - a reference to a [Node],
/// - the protocol [id],
/// - a domain separation tag [dst],
/// - [tx] and [rx] channels to interact with the caller.
///
/// This is just a convenience struct bundling all necessary objects and hence no getters are
/// implemented.
pub struct ProtocolParams<T, PP, I, O>
    where
        T: CombinableSignature
{
    pub handle: ManagerHandle<usize>,
    pub node: Arc<Node<T, PP>>,
    pub id: Id,
    pub dst: String,
    pub tx: mpsc::Sender<O>,
    pub rx: mpsc::Receiver<I>,
}

impl<T, PP, I, O>  ProtocolParams<T, PP, I, O>
    where
        T: CombinableSignature,
{
    /// Given a [handle], a reference to a [node] and protocol [id], it sets up communication
    /// channels and returns an instance of [Self] and the appropriate sender and receiver.
    pub fn new(handle: ManagerHandle<usize>, node: Arc<Node<T, PP>>, id: Id, dst: String) -> (Self, mpsc::Sender<I>, mpsc::Receiver<O>) {
        let (tx_o, rx) = mpsc::channel(network::network::CHANNEL_LIMIT);
        let (tx, rx_o) = mpsc::channel(network::network::CHANNEL_LIMIT);

        (Self::new_raw(handle, node, id, dst, tx, rx) , tx_o, rx_o)
    }

    /// Just returns a ProtocolParams and does not set up all the channels.
    #[inline]
    pub fn new_raw(handle: ManagerHandle<usize>, node: Arc<Node<T, PP>>, id: Id, dst: String, tx: mpsc::Sender<O>, rx: mpsc::Receiver<I>) -> Self {
        Self { handle, node, id, dst, tx, rx }
    }
}

/// A protocol is defined by a CombinableSignature scheme [T], public parameters [PP],
/// additional params [A], incoming messages [I] and outgoing messages [O].
pub trait Protocol<T, PP, A, I, O>
    where
        Self: Sized,
        T: CombinableSignature,
{
    /// Given a [handle], a reference to a [node], protocol [id] and domain separation tag [dst]
    /// it sets up communication channels and returns a protocol instance and the appropriate sender
    /// and receiver.
    fn new(params: ProtocolParams<T, PP, I, O>) -> Self;

    /// Allows a protocol to take optional, additional parameters [params].
    /// This trait has a default implementation that panics if it is called.
    #[inline]
    #[allow(unused)]
    fn additional_params(&mut self, params: A) {
        panic!("Protocol does not expect additional params!")
    }

    // Sadly, async traits do not yet exist and therefore we can't specify run() here and make use of macros instead (cf. [run_protocol] below)
}

/// Macro that runs a protocol. Here, a protocol must implement the [Protocol] trait and
/// additionally have an async [run] method that takes no parameters and executes the protocol.
#[macro_export]
macro_rules! run_protocol {
    ($p: ty, $handle: expr, $node: expr, $id: expr, $dst: expr $(, $add_params: expr)?) => {{
        let (params, tx, rx) = ProtocolParams::new($handle, $node, $id, $dst);
        let mut x = <$p>::new(params);
        $(x.additional_params($add_params);)?
        tokio::spawn(async move { x.run().await });
        (tx, rx)
    }};
}

pub mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    pub fn generate_nodes<T, PP>(port_start: u16, port_end: u16, corruption_limit: usize, threshold: usize, pp: PP) -> (Vec<Arc<Node<T, PP>>>, Vec<ManagerHandle<usize>>)
        where
            T: CombinableSignature,
            T::PK: Clone,
            T::PPK: Clone,
            PP: Clone,
    {
        let node_addrs = (port_start..port_end).map(|p| SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), p)).collect();
        let nodes: Vec<_>= Node::<T, PP>::generate_nodes(node_addrs, corruption_limit, threshold, pp).unwrap().into_iter().map(|n| Arc::new(n)).collect();
        let handles: Vec<_> = nodes.iter().map(|n| n.spawn_manager(false)).collect();
        (nodes, handles)
    }
}
