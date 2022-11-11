use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use network::tokio::sync::oneshot;

#[derive(Debug)]
pub enum VabaControlMsg<V> {
    Propose(V),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Done<T, V> {
    pub value: V,
    pub proof: T,
}

impl<T, V> Done<T, V> {
    pub fn new(value: V, proof: T) -> Self {
        Self { value, proof }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ViewChange<T, V> {
    pub key: Option<(V, T)>,
    pub lock: Option<(V, T)>,
    pub commit: Option<(V, T)>,
}

impl<T, V> ViewChange<T, V> {
    pub fn new(view: usize, leader: usize, key_map: &mut HashMap<(usize, usize), (V, T)>, lock_map: &mut HashMap<(usize, usize), (V, T)>, commit_map: &mut HashMap<(usize, usize), (V, T)>) -> Self {
        let map_key = (view, leader);
        let key = key_map.remove(&map_key);
        let lock = lock_map.remove(&map_key);
        let commit = commit_map.remove(&map_key);

        Self { key, lock, commit }
    }
}

#[derive(Debug)]
pub struct Decide<V>(pub V);

#[derive(Debug, Deserialize, Serialize)]
pub struct Exit<T, V> {
    pub view: usize,
    pub leader: usize,
    pub value: V,
    pub proof: T,
}

impl<T, V> Exit<T, V> {
    pub fn new(view: usize, leader: usize, value: V, proof: T) -> Self {
        Self { view, leader, value, proof }
    }
}