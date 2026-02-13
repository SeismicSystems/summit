# Summit

High-performance consensus client for EVM-based blockchains, built by [Seismic Systems](https://github.com/SeismicSystems). Uses the [Simplex consensus protocol](https://eprint.iacr.org/2023/463) for sub-second block finality. Communicates with any EVM execution client (Reth, Geth) via the Engine API.

## Build

Rust workspace (edition 2024) pinned to **toolchain 1.91.1** via `rust-toolchain.toml`. The toolchain auto-installs on first build.

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

### Feature flags

| Flag            | Effect                                                 |
| --------------- | ------------------------------------------------------ |
| `prom`          | Prometheus metrics (requires `reth-metrics` git dep)   |
| `jemalloc`      | jemalloc allocator (unix only)                         |
| `tokio-console` | tokio console subscriber for runtime debugging         |
| `bench`         | Historical block replay benchmarking binaries          |
| `e2e`           | End-to-end test binaries (stake, withdraw, sync, etc.) |

```bash
cargo build --features prom           # with metrics
cargo build --all-features            # everything
cargo build --no-default-features     # minimal
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

Key external dependency: [Commonware](https://commonware.xyz) (`2026.2.0`) provides consensus (Simplex), cryptography (BLS12-381, Ed25519), P2P networking, broadcast, storage (QMDB), and runtime.

## Code Style

- **Edition 2024**, Rust 1.91.1
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
| `rustup` installs toolchain on first build          | Expected — `rust-toolchain.toml` pins 1.91.1, auto-installed by rustup                                                        |
| `testnet` binary exits immediately without `reth`   | Requires `reth` in PATH. Install [seismic-reth](https://github.com/SeismicSystems/seismic-reth) or upstream reth              |
| `prom` feature fails to build                       | Pulls `reth-metrics` from `SeismicSystems/seismic-reth` git — needs network access and SSH key for private repos              |
| `procfs` compile error on macOS with `prom` feature | `procfs` is Linux-only, gated behind `cfg(target_os = "linux")` — build `prom` on Linux or use `--features jemalloc` on macOS |
| `e2e` binaries not found                            | Build with `cargo build --features e2e`                                                                                       |
| `bench` binaries not found                          | Build with `cargo build --features bench`                                                                                     |
