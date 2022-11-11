# APSS
This is a proof-of-concept implementation for a research paper. It is not intended for production use and has not been audited. Use at your own risk.

## Running
The project is fully written in Rust and should compile using `cargo` on any reasonable machine. If you use `nix`, `shell.nix` and `flake.nix` are provided.

After building, you can execute the `cli` binary. Alternatively, it might be easier to use `cargo run`. There are two steps needed to run the protocol locally.
1. Generate a config using `cli generate`. You need to provide a file where each line contains a pair `<IP>:<PORT>`.
2. Run each node using `cli run`. You need to pass a config file (generated in the previous step) to each node.
For further information, please check `cli --help` (or `cargo run -- --help`). This also works for subcommands, e.g., `cli generate --help`.

As a convenience, you can also use `run.sh`. It automates the config generation and node execution. For example, to run a test across 16 nodes use `./run.sh bash 16`. If you are on a cluster managed by `slurm`, you can instead use `./run.sh sbatch 16`.

Furthermore, `aws/` contains Python scripts to deploy and benchmark the system on AWS. Check out the README in the directory for more details.

## Structure
The design is reasonably modular and reusable. Especially the lower-level crates (`utils` and `networking`) are useful on their own and might be useful for other asynchronous protocol projects. The documentation of the `networking` crate is quite decent and explains what the crate exactly does and how to use it.

In more detail, the code is split across the following crates:
* `utils` offers some useful macros (primarily for dealing with `tokio` channels).
* `network` handles asynchronous network conditions, e.g., retrying after transmission failures, caching messages which are not yet required. It offers a pub-sub-style interface for sub-protocols.
* `protocol` offers common traits that describe protocols.
* `crypto` offers some cryptography traits.
* `crypto_blstrs` implements these traits and also offers additional constructions (e.g., KZG commitments).
* `tss` is a simple threshold signing protocol
* `vaba`, `acss` and `apss` implement the (sub-)protocols as defined and described in the paper.
* `cli` is a CLI interface for APSS. After building, run `cli --help` to learn more.
