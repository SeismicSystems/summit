# WIP
# Summit

<img alt="Summit consensus client" src="assets/graphic.png" />

Summit is a high-performance consensus client designed to drive EVM-based blockchains. Originally built to power the Seismic Blockchain, Summit works with any EVM client that implements the Engine API.

## Key Features

- **Responsive Consensus**: Powered by the [Simplex consensus protocol](https://eprint.iacr.org/2023/463), enabling sub-second block times
- **High Throughput**: Significantly higher TPS than Ethereum
- **EVM Compatible**: Works with any execution client supporting the Engine API
- **BLS12-381 & Ed25519 Cryptography**: Secure validator key management
- **Built with Commonware**: Leverages primitives from the [Commonware library](https://commonware.xyz)
- **Dynamic Validator Set**: Supports validator deposits (EIP-6110) and withdrawals (EIP-7002)

Summit uses the Simplex protocol, a responsive consensus mechanism that adapts to network conditions rather than waiting for predetermined timeouts. This allows the network to move as fast as conditions permit, achieving sub-second block times in most cases.

## Benchmarks

We run our benchmarks using EC2 instances spread across these regions: `["us-west-2", "eu-central-1", "us-east-1", "ap-northeast-1", "sa-east-1"]`. We use 100 kB blocks.

| Metric             | 5 nodes  | 10 nodes  | 20 nodes   | 100 nodes  |  500 nodes  |  1000 nodes  |
|--------            |----------|-----------|------------|------------|-------------|-------------|
| Average TPS        | 707 tx/s | 962 tx/s  | 1051 tx/s  | TBD        | TBD         | TBD         |
| Average Block Time | 1290ms   | 940ms     | 870ms      | TBD        | TBD         | TBD         |

The TBD benchmarks are currently running (7/24/25). With 20 nodes and under, the mempool is more of a bottleneck than consensus. This is why we see performance increasing for the first few columns.

You can reproduce these results by running the sequence in [this repository](https://github.com/SeismicSystems/testnet-benchmarking). 

## Installation

### Prerequisites
- Rust (latest stable)
- An EVM execution client (e.g., Reth, Geth) with Engine API support
- (Optional) Reth binary in PATH for local testnet

### Building from Source
```bash
git clone https://github.com/SeismicSystems/summit.git
cd summit
cargo build --release
```

## Quick Start

### 1. Generate Validator Keys
```bash
cargo run -- --key-path path/to/store/key keys generate
```

### 2. View Your Public Key
```bash
cargo run -- --key-path path/to/store/key keys show
```

### 3. Configure Genesis
Create a genesis file that references your EVM genesis configuration. See [example_genesis.toml](https://github.com/SeismicSystems/summit/blob/main/example_genesis.toml) for the required format.

### 4. Start Your Validator
Ensure your EVM client is running, then:
```bash
cargo run -- \
  --key-path /path/to/priv-key \
  --store-path /storage/directory \
  --engine-jwt-path /path/to/evm/jwt.hex \
  --genesis-path /path/to/genesis.toml
```

The validator will automatically discover other nodes listed in the genesis file and begin participating in consensus. Transactions can be submitted through the EVM client's RPC interface as usual.

## Local Development

To spin up a 4-node testnet locally (requires `reth` in PATH):
```bash
cargo run --bin testnet
```

## Architecture

Summit acts as the consensus layer, communicating with EVM execution clients through the Engine API. The execution client remains responsible for building blocks and processing transactions, while Summit handles:
- Validator coordination
- Block proposals
- Consensus finalization
- Network communication

## Next steps / Future Roadmap
- Deeper benchmarks
- More optimizations (potentially DKG threshold signatures to improve throughput)
- Full Audit and completeness Q4 2025

## Resources

- [Simplex Consensus Protocol Paper](https://eprint.iacr.org/2023/463)
- [Commonware Library](https://commonware.xyz)
- [Alto Consensus Example](https://github.com/commonwarexyz/alto)

## Status

⚠️ **Work in Progress** - This project is under active development. APIs and features may change.
