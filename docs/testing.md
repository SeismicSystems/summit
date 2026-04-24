# Testing

Summit has three levels of testing: unit/integration tests, end-to-end tests, and benchmarks.

## Unit & Integration Tests

### Test Harness

Unit and integration tests use a simulated network (`node/src/test_harness/`) with mock components:

- **`MockEngineNetwork`** — simulates Reth execution client behavior without a real EVM
- **Commonware simulated P2P** — in-process networking (no real sockets)
- **Helper functions** — `link_validators()`, `run_until_height()`, `register_validators()`, `join_validator()`

Tests in `node/src/tests/` are organized by feature area:

```
tests/
├── checkpointing/
│   ├── creation.rs                    # Checkpoint creation
│   ├── joining.rs                     # Joining network with checkpoint
│   └── verification.rs               # Checkpoint integrity verification
├── execution_requests/
│   ├── deposits.rs                    # Validator registration
│   ├── withdrawals.rs                 # Validator exit
│   ├── protocol_params.rs            # Parameter updates
│   ├── deposit_withdrawal_combined.rs # Mixed operations
│   └── validator_set.rs              # Validator set transitions
└── syncer.rs                          # Block sync & cache
```

## End-to-End Tests

E2E tests run real Reth instances alongside Summit. They exercise the full stack: Engine API IPC, P2P networking, consensus, finalization, and on-chain contract interactions.

### Important: Genesis Hash

The `eth_genesis_hash` field in the Summit genesis config must match the genesis block hash produced by Reth. If they differ, Summit will fail to initialize. This applies both to production deployments and to e2e tests — when running e2e tests, the hash in the test configuration must match the Reth genesis file.

### Prerequisites

- `reth` binary in PATH (see main README for setup)
- Ports 8545-8548, 3030-3060, 26600-26630 available

### Building

```bash
cargo build --features e2e
```

### Running

Each test is a standalone binary. Pass `--log-dir` to capture per-node Reth logs (`node0.log`, `node1.log`, ...):

```bash
cargo run --features e2e --bin stake-and-checkpoint -- --log-dir /tmp/rethlogs
cargo run --features e2e --bin stake-and-join-with-outdated-checkpoint -- --log-dir /tmp/rethlogs
cargo run --features e2e --bin withdraw-and-exit -- --log-dir /tmp/rethlogs
cargo run --features e2e --bin protocol-params -- --log-dir /tmp/rethlogs
cargo run --features e2e --bin sync-from-genesis -- --log-dir /tmp/rethlogs
```

### Common Configuration

All E2E tests share:

- **4 Reth instances** with IPC Engine API at `/tmp/reth_engine_api{0-3}.ipc`
- **4 genesis validators** (some tests add a 5th joining validator)
- **`blocks_per_epoch = 50`** (reduced from production default of 10,000 to accelerate epoch transitions)

### Test Descriptions

#### `stake-and-checkpoint`

Tests checkpoint creation and joining the network with a checkpoint.

- **Nodes**: 4 genesis + 1 joining
- **Contract**: Deposit contract (`0x00000000219ab540356cBB839Cbe05303d7705Fa`) — must be pre-deployed in the Reth genesis file.
- **Flow**: Starts 4 validators, sends a deposit to register a 5th validator, waits for a checkpoint at the configured height (default 50), then starts node4 bootstrapped from that checkpoint and a copy of node0's Reth DB.
- **Verifies**: The new node syncs from the checkpoint (not genesis) and all 5 nodes reach the stop height (default 100).

#### `stake-and-join-with-outdated-checkpoint`

Tests joining with an outdated checkpoint that requires partial resync.

- **Nodes**: 4 genesis + 1 joining
- **Contract**: Deposit contract (`0x00000000219ab540356cBB839Cbe05303d7705Fa`) — must be pre-deployed in the Reth genesis file.
- **Flow**: Similar to `stake-and-checkpoint`, but uses epoch-based milestones (default `checkpoint_epoch=1`, `join_epoch=2`, `stop_epoch=4`). The joining node uses an older checkpoint and must backfill missing blocks before participating.
- **Verifies**: New validator syncs from the outdated checkpoint, catches up, and all nodes reach the stop epoch.

#### `withdraw-and-exit`

Tests the full validator withdrawal lifecycle.

- **Nodes**: 4 genesis
- **Contract**: Withdrawal contract (`0x00000961Ef480Eb55e80D19ad83579A64c007002`) — must be pre-deployed in the Reth genesis file. Implements the EIP-7002 withdrawal request format.
- **Flow**: Sends a withdrawal transaction via the withdrawal contract, waits for the withdrawal delay (`VALIDATOR_WITHDRAWAL_NUM_EPOCHS + 1` epochs), then checks that the withdrawal amount arrived at the withdrawal address.
- **Verifies**: Withdrawal balance (32 ETH, with gas tolerance) transferred correctly, validator removed from consensus state.

#### `protocol-params`

Tests on-chain protocol parameter updates.

- **Nodes**: 4 genesis
- **Contract**: Protocol params contract (`0x0000000000000000000000000000506172616D73`) — must be pre-deployed in the Reth genesis file with owner set to `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, because only the owner can call `set_param(uint8,bytes)`.
- **Flow**: Sends two transactions to the protocol params contract — one updating `MaximumStake` to 64 ETH, another updating `EpochLength` to 100. Waits for `2 * blocks_per_epoch + 1` blocks so both changes are active.
- **Verifies**: RPC queries confirm `MaximumStake == 64_000_000_000` gwei and `EpochLength == 100`.

#### `sync-from-genesis`

Tests a new validator joining by syncing from genesis with no checkpoint.

- **Nodes**: 4 genesis + 1 joining
- **Contracts**: Deposit contract (`0x00000000219ab540356cBB839Cbe05303d7705Fa`) and withdrawal contract (`0x00000961Ef480Eb55e80D19ad83579A64c007002`) — both must be pre-deployed in the Reth genesis file.
- **Flow**: First withdraws one validator (modifying the peer set from genesis config), then generates new keys for a joining validator, sends a deposit, creates a `bootstrappers.toml` for peer discovery, and starts node4 with no checkpoint.
- **Verifies**: The new node syncs the entire chain from genesis, catches up to the current epoch, and joins the active validator set.

## Fuzz Testing

Coverage-guided fuzz testing lives in the `fuzz/` crate and runs under nightly Rust via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). The fuzz crate is excluded from the main workspace (`[workspace] members = ["."]` in `fuzz/Cargo.toml`) so the nightly-only libFuzzer runtime doesn't pollute stable builds.

### Target categories

- **Parser targets** — every `Read` impl in `summit-types` (`ProtocolParam`, `ConsensusState`, `Checkpoint`, `Block`, `Header`, `FinalizedHeader`, `ExecutionRequest`, `ValidatorAccount`, `WithdrawalQueue`, `DynamicEpocher`). Arbitrary bytes must parse to `Ok` / `Err` without panicking, and successful decode roundtrips to byte-identical output.
- **Non-codec targets** — `ssz_tree_key::parse_key` (RPC string input), `derive_child_public` (confirms `PublicKey::decode` filters non-curve points before reaching `CompressedEdwardsY::decompress().expect(...)`), `SszProof::verify` (adversarial gindex/branch must not overflow).
- **Property-based targets** — `WithdrawalQueue` op-sequence invariants (`len` / iterator / per-epoch counts consistent; `next_index` monotonic), `ExtPrivateKey` sign-verify roundtrip, `SszStateTree` incremental-setter updates plus `apply_protocol_parameter_changes` must match a full `rebuild_ssz_tree()` root, and any proof generated from a captured `ConsensusState` must verify against that state's captured root across all proof kinds (scalars, validators, deposits, withdrawals, protocol params, added / removed validators).

### Running

```bash
cargo install cargo-fuzz          # one-time
cd fuzz
cargo +nightly fuzz run <target>                          # runs until Ctrl+C
cargo +nightly fuzz run <target> -- -max_total_time=120   # bounded by seconds
```

Full battery, 2 minutes per target, stop on first crash:

```bash
cd fuzz && set -e && for t in $(cargo fuzz list); do \
  echo "=== $t ==="; \
  cargo +nightly fuzz run "$t" -- -max_total_time=120; \
done && echo "All targets passed."
```

### Reproducing a crash

libFuzzer writes reproducers to `fuzz/artifacts/<target>/crash-<hash>`:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

Distill each crash into a unit-level regression test in the source crate (e.g. `test_read_truncated_input_returns_err`) so `cargo test` catches future reintroductions even without running the fuzzer. See `fuzz/README.md` for the full target list, invariants, and instructions for adding new targets.

## Benchmarks

### Consensus State Benchmark

```bash
cargo bench -p summit-finalizer
```
