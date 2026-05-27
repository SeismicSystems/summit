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
cargo run --features e2e --bin observer -- --log-dir /tmp/rethlogs
cargo run --features e2e --bin verify-consensus-state-proof -- --log-dir /tmp/rethlogs
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

#### `observer`

Tests observer-mode nodes — RPC-only nodes that follow the chain without participating in consensus.

- **Nodes**: 4 genesis + 1 observer
- **Flow**: Starts 4 validators, then starts an observer node using `--observer 0`. The observer derives its p2p identity from validator 1's master node key (slot 0), uses a fresh BLS consensus key that is not in the validator set, and is authorized as a secondary peer by every validator via the genesis `observers_per_validator` field. Runs its own Reth instance and executes finalized blocks via Engine API IPC. Waits for all nodes — including the observer — to reach `--stop-height` (default 100).
- **Verifies**: The observer reaches the stop height, is not in the active validator set, and its pubkey does not appear in any finalization certificate's signer set (i.e., it never votes).

#### `verify-consensus-state-proof`

Tests end-to-end SSZ proof verification on-chain — the full pipeline from Summit's state-root capture through the EIP-4788 beacon roots contract into a deployed Solidity verifier.

- **Nodes**: 4 genesis
- **Contracts**: EIP-4788 beacon roots contract (`0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`, built into Reth); deploys the embedded `SszProofVerifier.sol` bytecode at runtime.
- **Flow**: Waits for the network to finalize several blocks so the SSZ proof tree is captured, then:
  - **TEST A** — reads the `parent_beacon_block_root` via the beacon-roots contract and asserts it matches Summit's captured state root.
  - **TEST B** — deploys `SszProofVerifier`, requests scalar proof results via `getStateProof(["epoch", "latest_height"])`, and verifies each proof on-chain against the beacon root.
  - **TEST C** — requests a collection (validator) proof for genesis validator 0 and verifies it on-chain via the same verifier.
- **Verifies**: Both scalar and collection SSZ proofs verify on-chain against the beacon root surfaced by EIP-4788, confirming the end-to-end trust chain from Summit consensus state → Reth EL block → Solidity verifier.

## Fuzz Testing

Coverage-guided fuzz testing lives in the `fuzz/` crate and runs under nightly Rust via [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). Three categories:

- **Parser targets** — every `Read` impl in `summit-types`. Arbitrary bytes must parse to `Ok` / `Err` without panicking, and successful decodes roundtrip to byte-identical output.
- **Non-codec targets** — `ssz_tree_key::parse_key`, `derive_child_public`, `SszProof::verify` with adversarial inputs.
- **Property-based targets** — `WithdrawalQueue` op-sequence invariants, `ExtPrivateKey` sign-verify roundtrip, SSZ incremental-update-vs-rebuild root equality, and generate→verify proof roundtrip across all proof kinds.

See [`fuzz/README.md`](../fuzz/README.md) for the full target list, running instructions, crash reproduction, and how to add new targets.

## Benchmarks

### Consensus State Benchmark

```bash
cargo bench -p summit-finalizer
```
