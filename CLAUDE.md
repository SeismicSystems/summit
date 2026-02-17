# Summit

High-performance consensus client for EVM-based blockchains, built by [Seismic Systems](https://github.com/SeismicSystems). Uses the [Simplex consensus protocol](https://eprint.iacr.org/2023/463) for sub-second block finality. Communicates with any EVM execution client (Reth, Geth) via the Engine API.

## Commonware

[Commonware](https://commonware.xyz) is Summit's core infrastructure layer. Summit depends on 12 Commonware crates (version pinned in root `Cargo.toml`). Nearly every component in Summit is built on top of Commonware primitives.

| Crate | What it provides |
| --- | --- |
| `commonware-consensus` | Simplex BFT protocol — leader election, notarization (2/3+1), finalization |
| `commonware-cryptography` | BLS12-381 multisig, Ed25519 identity, SHA256 hashing |
| `commonware-runtime` | Async runtime abstractions — Clock, Spawner, Metrics, Signal/Stopper |
| `commonware-storage` | QMDB key-value store, immutable & prunable archives |
| `commonware-p2p` | Authenticated P2P connections, peer management, simulated network for tests |
| `commonware-broadcast` | Buffered reliable broadcast between validators |
| `commonware-codec` | Streaming encode/decode for blocks, checkpoints, and messages |
| `commonware-resolver` | Request-response backfill for missing blocks from peers |
| `commonware-utils` | Channels (mpsc, oneshot), ordered sets, byte utilities, non-zero types |
| `commonware-macros` | `select!`/`select_loop!` async macros, `test_traced!` for instrumented tests |
| `commonware-math` | Cryptographic randomness for key generation |
| `commonware-parallel` | Sequential/parallel processing strategies |

Summit integrates with Simplex by implementing Commonware's `Automaton` and `Relay` traits (see `application/src/actor.rs`). The orchestrator spawns Simplex engines per epoch, and all inter-actor communication uses Commonware channels and async primitives.

### Commonware MCP Server

Commonware provides an MCP server for querying its library documentation directly from Claude Code. Add it with:

```bash
claude mcp add --transport http commonware-library https://mcp.commonware.xyz
```

This gives Claude Code searchable access to Commonware docs — useful when working with Simplex, QMDB, P2P, codec, or any other Commonware crate.

## Build

Rust workspace (edition 2024) with toolchain pinned in `rust-toolchain.toml`. The toolchain auto-installs on first build.

### macOS (arm64/x86_64)

```bash
cargo build                           # debug
cargo build --release                 # release
```

### Linux (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
cargo build
```

### Verify

```bash
target/debug/summit --help
# Usage: summit <COMMAND>
# Commands: run, keys, help
```

## Test

### Unit & integration tests (153 tests)

```bash
cargo test                            # default features — 153 tests
cargo test --all-features             # includes e2e test harness — 170 tests
```

Test breakdown by crate:

- `summit` (node): 40 tests (syncer, checkpointing, execution requests, deposits, withdrawals)
- `summit-finalizer`: 19 tests (validator lifecycle, fork handling, state queries)
- `summit-syncer`: 11 tests
- `summit-types`: 75 tests (codec, consensus state, headers, withdrawals, protocol params)
- `summit-rpc`: 8 integration tests

### CI checks (must pass before PR)

```bash
cargo +nightly fmt --all --check      # formatting (nightly rustfmt)
RUSTFLAGS="-D warnings" cargo check   # no warnings (default features)
RUSTFLAGS="-D warnings" cargo check --all-features  # no warnings (all features)
```

### Benchmarks

```bash
cargo bench -p summit-finalizer       # consensus_state_write benchmark
```

## Local Testnet

The `testnet` binary spins up a multi-node network locally — this is the main way to test end-to-end during development.

### Prerequisites

- A binary named `reth` must be in PATH. If using [seismic-reth](https://github.com/SeismicSystems/seismic-reth), the build produces a `seismic-reth` binary — symlink or copy it as `reth`:
  ```bash
  ln -s /path/to/seismic-reth ~/.cargo/bin/reth
  ```

### Quick start

```bash
cargo run --bin testnet
```

This starts 4 Reth execution nodes + 4 Summit consensus validators, all wired together via Engine API over IPC.

### CLI flags

| Flag | Default | Description |
| --- | --- | --- |
| `--nodes <N>` | 4 | Number of nodes to run |
| `--only-reth` | off | Start only Reth execution nodes (no consensus) |
| `--log-dir <PATH>` | none | Write per-node logs (`node0.log`, `node1.log`, ...) |

### Port layout (default 4 nodes)

| Service | Ports |
| --- | --- |
| Reth RPC | 8545, 8546, 8547, 8548 |
| Summit RPC | 3030, 3040, 3050, 3060 |
| P2P | 26600, 26610, 26620, 26630 |
| Engine API IPC | `/tmp/reth_engine_api{0-3}.ipc` |

### Interact with the network

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Reset state

```bash
cd testnet && ./reset.sh
```

### Config files (`testnet/`)

- `dev.json` — Ethereum genesis with pre-funded test accounts
- `jwt.hex` — Engine API auth token
- `node{0-3}/` — per-node keys (`consensus_key.pem`, `node_key.pem`) and data directories

## Binaries

| Binary                                    | Feature gate | Purpose                                             |
| ----------------------------------------- | ------------ | --------------------------------------------------- |
| `summit`                                  | —            | Main validator node                                 |
| `testnet`                                 | —            | Spin up 4-node local testnet (needs `reth` in PATH) |
| `genesis`                                 | —            | Generate genesis files from validator list          |
| `stake-and-checkpoint`                    | `e2e`        | E2E: stake validator + checkpoint test              |
| `stake-and-join-with-outdated-checkpoint` | `e2e`        | E2E: join with outdated checkpoint                  |
| `withdraw-and-exit`                       | `e2e`        | E2E: withdrawal flow test                           |
| `protocol-params`                         | `e2e`        | E2E: protocol parameter test                        |
| `sync-from-genesis`                       | `e2e`        | E2E: sync from genesis test                         |
| `execute-blocks`                          | `bench`      | Block execution benchmarking                        |

## Project Layout

```
node/                  Main binary crate (summit, testnet, genesis)
  src/engine.rs          Central coordinator — component lifecycle, message routing
  src/args.rs            CLI argument parsing (clap)
  src/config.rs          Channel sizes, timeouts, default paths
  src/keys.rs            Key management (generate/show)
  src/test_harness/      Shared test harness for e2e tests
  src/tests/             Integration tests (syncer, checkpointing, execution requests)
  src/bin/               Additional binaries (testnet, genesis, e2e, bench)

application/           Consensus interface — implements Simplex Automaton + Relay traits
  src/actor.rs           Propose, verify, broadcast blocks

finalizer/             Block execution & finalization
  src/actor.rs           Canonical state, fork states, Engine API calls, checkpoints
  src/db.rs              Persistent storage (QMDB via commonware-storage)
  src/tests/             Validator lifecycle, fork handling, state queries

syncer/                Block sync & coordination hub
  src/actor.rs           Block cache, finalization archive, subscription management
  src/resolver/          Backfill missing blocks from peers
  src/mocks/             Mock implementations for testing

orchestrator/          Epoch management
  src/actor.rs           Simplex engine lifecycle, epoch transitions, channel multiplexing

rpc/                   JSON-RPC server
  src/api.rs             RPC method definitions
  src/server.rs          Server setup (jsonrpsee + tower + CORS)
  tests/                 Integration tests

types/                 Shared types & engine client
  src/engine_client.rs   Engine API client (forkchoice, payload building)
  src/consensus_state.rs Validator set, staking, epoch tracking
  src/checkpoint.rs      Checkpoint creation & verification
  src/block.rs           Block type definitions
  src/genesis.rs         Genesis configuration parsing
  src/scheme.rs          BLS12-381 multisig scheme

docs/                  Architecture docs, protocol descriptions
testnet/               Local testnet config (4 validators, JWT, genesis JSON)
```

## Architecture

Actor-based design with message passing between components:

```
Orchestrator → spawns/aborts Simplex engines per epoch
    ↓
Simplex Consensus (commonware-consensus) → leader election, notarization (2/3+1), finalization
    ↓ Automaton + Relay traits
Application → proposes & verifies blocks via Engine API
    ↓ broadcast/verified/subscribe
Syncer → block cache, finalization archive, P2P resolver, network broadcast
    ↓ notarized/finalized block updates
Finalizer → executes blocks against EVM client, manages validator set, creates checkpoints
    ↓
Engine Client → Engine API calls to Reth/Geth (forkchoice, payload, new block)
```

See the **Commonware** section above for details on the consensus and infrastructure layer.

## Code Style

- **Edition 2024**, toolchain pinned in `rust-toolchain.toml`
- `cargo +nightly fmt` for formatting (CI enforces nightly rustfmt)
- No `.rustfmt.toml` or `.clippy.toml` — uses defaults
- `RUSTFLAGS="-D warnings"` — zero warnings policy
- Workspace dependencies in root `Cargo.toml`, crates reference via `workspace = true`
- Actor pattern: each component has `actor.rs` (main logic) + `ingress.rs` (message types/mailbox)

## CI

GitHub Actions (`.github/workflows/ci.yml`) on push/PR to `main`:

1. **rustfmt** — `cargo +nightly fmt --all --check`
2. **build** — default, no-default-features, `prom`, `jemalloc`, all-features
3. **warnings** — `RUSTFLAGS="-D warnings" cargo check` (default + all-features)
4. **test** — `cargo test` + `cargo test --all-features`

## Troubleshooting

| Problem                                             | Fix                                                                                                                           |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `rustup` installs toolchain on first build          | Expected — `rust-toolchain.toml` pins the required version, auto-installed by rustup                                           |
| `testnet` binary exits immediately without `reth`   | Requires `reth` in PATH. Install [seismic-reth](https://github.com/SeismicSystems/seismic-reth) or upstream reth              |
| `prom` feature fails to build                       | Pulls `reth-metrics` from `SeismicSystems/seismic-reth` git — needs network access                                            |
| `procfs` compile error on macOS with `prom` feature | `procfs` is Linux-only, gated behind `cfg(target_os = "linux")` — build `prom` on Linux or use `--features jemalloc` on macOS |
| `e2e` binaries not found                            | Build with `cargo build --features e2e`                                                                                       |
| `bench` binaries not found                          | Build with `cargo build --features bench`                                                                                     |
