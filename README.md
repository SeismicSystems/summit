# Summit

<img alt="Summit consensus client" src="assets/graphic.png" />

Summit is a high-performance consensus client designed to drive EVM-based blockchains. Originally built to power the Seismic Blockchain, Summit works with any EVM client that implements the Engine API.

## Key Features

- **Responsive Consensus**: Powered by the [Simplex consensus protocol](https://eprint.iacr.org/2023/463), enabling sub-second block times
- **High Throughput**: Significantly higher TPS than Ethereum
- **EVM Compatible**: Works with any execution client supporting the Engine API (Reth, Geth, etc.)
- **Epoch-based Checkpointing**: Periodic consensus state checkpoints for improved resilience and state verification
- **BLS12-381 Cryptography**: Secure validator key management with BLS signature aggregation
- **Dynamic Validator Management**: Support for validator deposits, withdrawals, and onboarding via execution requests
- **Built with Commonware**: Leverages battle-tested primitives from the [Commonware library](https://commonware.xyz)

Summit uses the Simplex protocol, a responsive consensus mechanism that adapts to network conditions rather than waiting for predetermined timeouts. This allows the network to move as fast as conditions permit, achieving sub-second block times in most cases.

## Architecture

Summit acts as the consensus layer, communicating with EVM execution clients through the Engine API. The execution client remains responsible for building blocks and processing transactions, while Summit handles:

- **Validator Coordination**: Managing validator sets and coordinating consensus participation
- **Block Proposals**: Selecting leaders and building blocks through the execution client
- **Consensus Finalization**: Achieving Byzantine Fault Tolerant finality using Simplex
- **Network Communication**: Peer-to-peer networking, block propagation, and state synchronization
- **Checkpointing**: Creating and validating periodic checkpoints of consensus state

### Epoch System

Summit organizes blocks into epochs for efficient checkpointing and state management:

- **Epoch Length**: 1000 blocks (production), 10 blocks (debug/testing)
- **Checkpoint Creation**: At the end of each epoch, validators create a checkpoint hash from the consensus state
- **Checkpoint Validation**: The checkpoint hash is included in the final block of each epoch and finalized through consensus
- **State Recovery**: Checkpoints enable efficient state synchronization and recovery

### Validator Management

Summit implements a comprehensive validator lifecycle system:

- **Minimum Stake**: 32 ETH (32,000,000,000 gwei) required to become a validator
- **Onboarding Rate**: Up to 3 validators can be onboarded per block
- **Withdrawal Period**: 100 blocks (production), 5 blocks (debug/testing)
- **Max Withdrawals**: Up to 16 validator withdrawals can be processed per block
- **Deposit Requests**: Validators join by submitting signed deposit requests via execution layer
- **Withdrawal Requests**: Validators exit through withdrawal requests with configurable delay

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

### Building with Benchmarking Support
For running benchmarks with historical Ethereum or Base blocks:
```bash
# For Ethereum historical blocks
cargo build --release --features bench

# For Base (Optimism) historical blocks
cargo build --release --features base-bench
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

The genesis configuration includes:
- Initial validator set with BLS public keys
- Genesis block hash from the execution client
- Network parameters and chain ID
- Bootstrap peer addresses

### 4. Start Your Validator
Ensure your EVM client is running and the Engine API is accessible, then:
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

This will:
1. Generate validator keys for 4 nodes
2. Initialize Reth execution clients with a shared genesis
3. Start 4 Summit consensus nodes
4. Connect them in a local network for testing

## Configuration

Summit supports several configuration options:

- `--key-path`: Path to your BLS validator private key
- `--store-path`: Directory for consensus state storage
- `--engine-jwt-path`: Path to JWT secret for Engine API authentication
- `--genesis-path`: Path to genesis configuration file
- `--mailbox-size`: Size of actor mailboxes (default: optimized for hardware)
- `--partition-prefix`: Namespace prefix for distributed storage

## Engine API Clients

Summit supports multiple Engine API client implementations:

### RethEngineClient (Production)
The standard client for production use with Reth, Geth, or any Engine API v3-compatible execution client.

### EthereumHistoricalEngineClient (Benchmarking)
Available with `--features bench`, this client replays historical Ethereum blocks for benchmarking consensus performance without requiring live transaction traffic.

### HistoricalEngineClient (Base Benchmarking)
Available with `--features base-bench`, this client replays historical Base (Optimism) blocks for benchmarking Layer 2 performance characteristics.

## Protocol Details

### Protocol Version
Current protocol version: **v1**

The protocol version is included in signed messages (such as deposit requests) to ensure compatibility and prevent replay attacks across different protocol versions.

### Consensus Parameters
- **Replay Buffer**: 8 MB for supporting peers during network instability
- **Write Buffer**: 1 MB for consensus message buffering
- **Buffer Pool**: 4 KB pages, 32 MB total capacity
- **Max Participants**: 10,000 validators supported

### Timeouts
Configurable timeout parameters allow tuning for different network conditions:
- `leader_timeout`: Maximum time to wait for leader proposal
- `notarization_timeout`: Time to wait for notarization quorum
- `activity_timeout`: Peer activity monitoring timeout
- `skip_timeout`: Timeout for view changes
- `fetch_timeout`: Timeout for block fetching

## Next Steps / Future Roadmap
- **Dynamic Validator Sets**: Full integration with Ethereum staking contract
  - Currently Summit uses a static validator set defined at genesis
  - Planned: Leverage EVM staking contract to dynamically add and remove validators similar to Ethereum
- **Deeper Benchmarks**: Extended benchmarks with 100, 500, and 1000+ node networks
- **Performance Optimizations**:
  - Potential DKG threshold signatures to improve throughput
  - Further consensus optimizations based on production learnings
- **State Sync Improvements**: Enhanced checkpoint-based state synchronization
- **Full Audit**: Comprehensive security audit and completeness review (Q4 2025)

## Resources

- [Simplex Consensus Protocol Paper](https://eprint.iacr.org/2023/463)
- [Commonware Library](https://commonware.xyz)
- [Alto Consensus Example](https://github.com/commonwarexyz/alto)
- [Seismic Blockchain](https://seismic.systems)

## Changelog

### Recent Updates (September-October 2025)

#### v0.3.0 - Ethereum Historical Benchmarking Support
**October 1, 2025** - [PR #50](https://github.com/SeismicSystems/summit/pull/50)

- Added `EthereumHistoricalEngineClient` for benchmarking with pre-built Ethereum blocks
- Introduced `bench` feature flag for compiling with benchmarking support
- Moved pending checkpoint and validator change tracking into consensus state
- Enhanced state management for improved checkpoint handling

#### v0.2.1 - Database Configuration Improvements
**September 25, 2025** - [PR #49](https://github.com/SeismicSystems/summit/pull/49)

- Refactored database configuration across application and syncer components
- Improved storage management and configuration consistency
- Enhanced partition handling for distributed deployments

#### v0.2.0 - Deposit Request Signatures
**September 24, 2025** - [PR #47](https://github.com/SeismicSystems/summit/pull/47)

- Added cryptographic signature verification for deposit requests
- Introduced protocol version (v1) in signed messages
- Added comprehensive end-to-end tests for deposit request validation
- Enhanced security for validator onboarding process

#### v0.1.2 - Syncer Improvements
**September 24, 2025** - [PR #48](https://github.com/SeismicSystems/summit/pull/48)

- Optimized synchronization logic in syncer component
- Improved block fetching and state synchronization reliability

#### v0.1.1 - Checkpointing Enhancements
**September 23, 2025** - [PR #46](https://github.com/SeismicSystems/summit/pull/46)

- Refactored application finalizer for improved clarity and performance
- Optimized checkpoint storage: pending checkpoints kept in memory until epoch end
- Modified block headers to include validator set changes (additions/removals)
- Improved checkpoint finalization process

#### v0.1.0 - Initial Checkpointing Implementation
**September 19, 2025** - [PR #45](https://github.com/SeismicSystems/summit/pull/45)

- Introduced epoch-based checkpointing system
  - Epochs defined as fixed number of blocks (1000 in production, 10 in debug)
  - Checkpoint created at end of each epoch from consensus state
  - Checkpoint hash included in final block of epoch
- Added new `Header` type as part of blocks
  - Block digest now computed from header digest
  - Headers form a verifiable chain back to genesis
  - Enables efficient state verification without storing all blocks
- Enhanced syncer to include signatures with last block of each epoch
- Implemented checkpoint persistence in application finalizer
- Added comprehensive end-to-end tests for checkpointing functionality
- Introduced `Block::Header` for maintaining finalized header chain

#### Earlier Updates

**September 2025**
- Refactored threshold key parameters for cleaner API ([PR #43](https://github.com/SeismicSystems/summit/pull/43))
- Added block headers to support checkpoint chain ([PR #44](https://github.com/SeismicSystems/summit/pull/44))
- Reintroduced and enhanced syncer component ([PR #41](https://github.com/SeismicSystems/summit/pull/41))

## Development Status

⚠️ **Active Development** - This project is under active development. APIs and features may change. Summit is being prepared for production use with ongoing testing, benchmarking, and security reviews.

### Current Focus
- Comprehensive benchmarking across various network sizes and conditions
- Security hardening and edge case testing
- Performance optimization and throughput improvements
- Documentation and developer tooling

## Contributing

We welcome contributions! Please see our contributing guidelines for more information on how to get involved.

## License

[License information to be added]

## Community

- [GitHub Discussions](https://github.com/SeismicSystems/summit/discussions)
- [Twitter/X: @SeismicSystems](https://twitter.com/SeismicSystems)

## Security

If you discover a security vulnerability, please email security@seismic.systems. Please do not create public issues for security vulnerabilities.
