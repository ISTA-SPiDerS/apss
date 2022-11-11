use std::{fs, io};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, ensure, Result};
use tokio;
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use apss::{APSS, APSSParams, HavenPublicParams};
use crypto_blstrs::blstrs::{G2Projective, G1Projective};
use crypto_blstrs::group::Group;
use crypto_blstrs::poly_commit::kzg::BlstrsKZG;
use crypto_blstrs::threshold_sig::BlstrsSignature;
use crypto_blstrs::vector_commit::BlstrsKZGVec;
use serde::{Deserialize, Serialize};
use apss::messages::APSSDeliver;
use crypto::threshold_sig::{PartialKey, PublicKey, Signable};
use network::message::Id;
use protocol::{Node, Protocol, ProtocolParams, run_protocol};
use tss::TSS;

#[derive(Parser)]
#[clap(version)]
struct Cli {
    /// Enables debug output. Multiple occurrences increase its verbosity
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
    #[clap(subcommand)]
    command: Commands
}

enum Stats {
    Off,
    Partial,
    Full,
}

impl Stats {
    fn should_collect(&self) -> bool {
        match self {
            Stats::Off => false,
            _ => true,
        }
    }
}

impl FromStr for Stats {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "partial" => Ok(Self::Partial),
            "full" => Ok(Self::Full),
            x => Err(anyhow!("{} can't be turned into Stats!", x))
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Generates an initial setup for all nodes given a list of socket addresses.
    Generate {
        /// Directory where the config files will be stored.
        #[clap(short, long, parse(from_os_str), value_name = "DIR")]
        dir: PathBuf,
        /// File to read the socket addresses from; one address per line. If not given, uses STDIN.
        #[clap(short, long, parse(from_os_str), value_name = "FILE")]
        file: Option<PathBuf>,

        /// Whether to name the files using IPs
        #[clap(short, long)]
        ips: bool
        // /// Reconstruction threshold of the secret.
        // #[clap(short, long)]
        // threshold: usize,
    },
    /// Runs a node given an initial config and a list of peers.
    Run {
        /// Config file.
        #[clap(short, long, parse(from_os_str), value_name = "FILE")]
        config: PathBuf,

        /// Committee probability
        #[clap(short, long, parse(from_str), value_name = "PROB")]
        probability: Option<String>,

        #[clap(short, long, value_name = "TOKIO_THREADS")]
        tokio_threads: Option<usize>,

        #[clap(short, long, value_name = "RAYON_THREADS")]
        rayon_threads: Option<usize>,

        #[clap(short, long)]
        stats: Stats,
    }
}


fn read_to_string(path: &Option<PathBuf>) -> Result<String> {
    // Bit dirty but it's only for configs so doesn't really matter
    Ok(match path {
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        },
        Some(f) => fs::read_to_string(f)?
    })
}

#[derive(Serialize, Deserialize)]
struct NodeWithGens {
    pub node: Node<BlstrsSignature, HavenPublicParams>,
    pub g: G1Projective,
    pub h: G1Projective,
}

fn main() -> Result<()> {
    simple_logger::init_with_level(log::Level::Warn).expect("Initializing logger failed!");
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { mut dir, file, ips} => {
            ensure!(dir.is_dir(), "dir is not a directory!");

            let contents = read_to_string(&file)?;
            let mut node_addrs: Vec<_> = contents.lines().map(|x| SocketAddr::from_str(x.trim())).collect::<Result<Vec<_>, _>>()?;
            let n = node_addrs.len();
            // deduplicate addresses
            node_addrs.sort();
            node_addrs.dedup();
            ensure!(node_addrs.len() == n, "Contains at least one duplicate socket address!");


            let f = n/3;
            let g = G1Projective::generator();
            let h = G1Projective::random(OsRng);
            let hh = G2Projective::random(OsRng);
            let poly_commit = BlstrsKZG::new(f+1, (h.clone(), hh.clone()));
            let vec_commit = BlstrsKZGVec::new(n+1, (h.clone(), hh.clone()), "DST".to_string());
            let params = HavenPublicParams::new(poly_commit, vec_commit);
            let configs: Vec<_>= Node::<BlstrsSignature, HavenPublicParams>::
            generate_nodes(node_addrs, f+1, 2*f+1,params)?;

            for (i, cfg) in configs.into_iter().enumerate() {
                if ips {
                    dir.push(format!("{}.cfg", cfg.get_own_socket_addr().ip()));
                } else {
                    dir.push(format!("node_{}.cfg", i));
                }
                let file = File::create(&dir)?;
                let node_gen = NodeWithGens { node: cfg, g, h };
                bincode::serialize_into(&file, &node_gen)?;
                dir.pop();
            }
            Ok(())
        }
        Commands::Run { config, probability, tokio_threads, rayon_threads, stats } => {
            let err_string = format!("Can't open config file! {:#?}", config);
            let mut reader = File::open(config).expect(&err_string);
            let NodeWithGens{mut node, g, h} = bincode::deserialize_from(&mut reader).expect("Can't deserialize config!");
            let mut rt = tokio::runtime::Builder::new_multi_thread();

            if let Some(num_threads) = rayon_threads {
                rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global().unwrap();
            }

            if let Some(num_threads) = tokio_threads {
                rt.worker_threads(num_threads);
            }
            rt.enable_all().build().unwrap().block_on(async move {
                let mut handle = node.spawn_manager(stats.should_collect());
                let committee_prob = probability.map(|s| {
                    let split: Vec<_> = s.split("/").map(|i| usize::from_str(i).expect("Bad committee probability!")).collect();
                    assert_eq!(split.len(), 2, "Bad committee probability!");
                    (split[0], split[1])
                });
                let add_params = APSSParams::new(g, h, committee_prob);

                // Start timer
                handle.handle_stats_start("Node");

                let max_round = 1;
                for round in 0..max_round {
                    let id = Id::new(round, vec![0]);
                    let (_, mut rx) = run_protocol!(APSS, handle.clone(), Arc::new(node.clone()), id.clone(), "DST".to_string(), add_params.clone());
                    let APSSDeliver{ share, pks } = rx.recv().await.unwrap();
                    let mut new_sk_share = node.get_sk_share().clone();
                    new_sk_share.add(&share);
                    let mut new_pk_shares = Vec::with_capacity(node.peer_count());
                    for mut ppk in node.drain_pk_shares() {
                        ppk.add(&pks[ppk.index()]);
                        new_pk_shares.push(ppk);
                    }
                    node.set_sk_share(new_sk_share);
                    node.set_pk_shares(new_pk_shares);
                    handle.round(round+1, Some(node.get_peer_map())).await;
                }
                // End timer
                handle.handle_stats_end().await;

                // Check that the original PK still works
                let id = Id::new(max_round, vec![0]);
                let (tx, mut rx) = run_protocol!(TSS<_,_,_>, handle.clone(), Arc::new(node.clone()), id.clone(), "DST".to_string(), "Test".to_string());
                tx.send(tss::messages::TSSControlMsg::Sign).await.unwrap();
                let tss::messages::Deliver {proof: sig, ..} = rx.recv().await.unwrap();
                assert!(node.get_pk().verify(&sig, "Test".to_string().prepare_panic(), "DST".to_string()));

                // Stats
                let manager_stats = handle.sender_stats().await;
                // Shutdown handle gracefully
                handle.shutdown().await;

                if let Some(manager_stats) = manager_stats {
                    match stats {
                        Stats::Full => {
                            let serialized = serde_json::to_string(&manager_stats)?;
                            println!("{}", serialized);
                        }
                        Stats::Partial => {
                            for handle_stat in manager_stats.handle_stats().iter() {
                                let label = handle_stat.get_label();
                                if label.is_some() && label.as_ref().unwrap() == "Node" {
                                    // csv node_id,sent_bytes,sent_count,duration
                                    println!("{},{},{},{}", node.get_own_idx(),
                                             manager_stats.sent_bytes(),
                                             manager_stats.sent_count(),
                                             handle_stat.duration().expect("No duration!"));
                                }
                            }
                        }
                        Stats::Off => {}
                    }

                }

                Ok(())
            })
        }
    }
}
