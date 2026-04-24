# Fuzz Testing

Coverage-guided fuzz testing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). All targets live in a standalone crate under `fuzz/` (excluded from the main workspace via `[workspace] members = ["."]` in `fuzz/Cargo.toml`) so the nightly-only libFuzzer runtime doesn't pollute stable builds.

## Requirements

- Nightly Rust toolchain — libFuzzer needs `-Z sanitizer` support.
- `cargo install cargo-fuzz`.

## Running

Single target, runs forever until `Ctrl+C` or a crash:

```bash
cd fuzz
cargo +nightly fuzz run <target>
```

Time-bounded:

```bash
cargo +nightly fuzz run <target> -- -max_total_time=120
```

Iteration-bounded:

```bash
cargo +nightly fuzz run <target> -- -runs=10000000
```

Full battery, 2 minutes per target, stops on the first crash:

```bash
cd fuzz && for t in $(cargo fuzz list); do \
  echo "=== $t ==="; \
  cargo +nightly fuzz run "$t" -- -max_total_time=120 || exit 1; \
done && echo "All targets passed."
```

`|| exit 1` is required — inside a `for` loop body, `set -e` doesn't reliably propagate an inner failure, so a crash in one target would otherwise be followed by "All targets passed.".

## Reproducing a crash

libFuzzer writes reproducers to `fuzz/artifacts/<target>/crash-<hash>`:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

For any crash found, the fix belongs in the source crate — plus a unit-level regression test (e.g. `test_read_truncated_input_returns_err`) so `cargo test` catches future reintroductions even without running the fuzzer.

## Targets

### Parser targets

Arbitrary bytes must parse cleanly (`Ok` or `Err`, never panic). When decoding succeeds, the encode-decode roundtrip must be byte-identical (canonical encoding).

| Target | Type | Source module |
|---|---|---|
| `protocol_param_read` | `ProtocolParam` | `types/src/protocol_params.rs` |
| `consensus_state_read` | `ConsensusState` | `types/src/consensus_state.rs` |
| `checkpoint_read` | `Checkpoint` | `types/src/checkpoint.rs` |
| `block_read` | `Block` | `types/src/block.rs` |
| `header_read` | `Header` | `types/src/header.rs` |
| `finalized_header_read` | `FinalizedHeader<MultisigScheme>` | `types/src/header.rs` |
| `execution_request_read` | `ExecutionRequest` (parse-only; no `EncodeSize`) | `types/src/execution_request.rs` |
| `validator_account_read` | `ValidatorAccount` | `types/src/account.rs` |
| `withdrawal_queue_read` | `WithdrawalQueue` | `types/src/withdrawal.rs` |
| `dynamic_epocher_read` | `DynamicEpocher` | `types/src/dynamic_epocher.rs` |

### Non-codec targets

- **`ssz_tree_key_parse_key`** — arbitrary `&str` from RPC must parse to `Result<SszStateKey, String>` without panicking.
- **`derive_child_public`** — confirms canonical `PublicKey::decode` prevents non-curve points from reaching `CompressedEdwardsY::decompress().expect(...)` in `derive_child_public`.
- **`ssz_proof_verify`** — adversarial `(gindex, leaf, branch, state_root)` must make `SszProof::verify` return a `bool` without arithmetic overflow panic in the gindex-walk loop.

### Property-based targets

Random operation sequences applied to fresh state, with post-condition invariants asserted.

- **`withdrawal_queue_ops`** — random `push_request` / `pop` / `reschedule_epoch` / `set_next_index` sequences. Invariants:
  - `len()` == `withdrawals_iter().count()`.
  - Sum of `count_for_epoch(e)` over all `e` equals `len()`.
  - `next_index()` is non-decreasing across push-type ops.
  - Encode-decode roundtrip is byte-identical.
- **`ext_private_key_sign_verify`** — for any `(master_seed, index, namespace, msg)`:
  - `ExtPrivateKey::derive_child_signer(master, index).public_key()` equals `derive_child_public(master.public_key(), index)`.
  - Signatures produced by the child signer verify under both pubkeys.
- **`ssz_tree_incremental_vs_rebuild`** — any decoded `ConsensusState` subjected to scalar-field mutations plus an `apply_protocol_parameter_changes` pass yields the same `ssz_tree.root()` as a fresh `rebuild_ssz_tree()`-produced root. Guards against drift between incremental setter updates (including the setters driven by `apply_protocol_parameter_changes`) and full rebuilds.
- **`ssz_proof_roundtrip`** — any proof generated from a captured `ConsensusState` proof tree must verify against that state's captured root. Covers the generate side for all supported proof kinds: top-level scalars, validators, deposits, withdrawals, protocol params, and added / removed validators. Complements `ssz_proof_verify`, which fuzzes the verify path with adversarial inputs.

## What not to commit

The root `.gitignore` covers these; they're regenerated per run and belong on disk only:

- `fuzz/target/` — libFuzzer build artifacts.
- `fuzz/corpus/` — synthesized input corpora. Re-accumulated on subsequent runs; first run starts from empty.
- `fuzz/artifacts/` — crash reproducers. Once distilled into a unit test, not needed.
- `fuzz/coverage/` — output of `cargo fuzz coverage`.

## Adding a new target

1. Create `fuzz/fuzz_targets/<name>.rs`. Use one of the existing targets as a template:
   - Parser targets: model on `protocol_param_read.rs`.
   - Property-based targets: model on `withdrawal_queue_ops.rs` (uses `Arbitrary` derive).
2. Add a matching `[[bin]]` entry in `fuzz/Cargo.toml`.
3. Verify: `cd fuzz && cargo +nightly check --bins`.
4. Smoke run: `cargo +nightly fuzz run <name> -- -max_total_time=60`.
5. If it finds a panic, fix the underlying bug, add a regression unit test in the source crate, and re-run to confirm.
