# SSZ Merklization

Summit maintains an SSZ binary Merkle tree over its consensus state and commits the tree root to each execution layer block header as `parent_beacon_block_root`. During block execution, Reth stores this root in the EIP-4788 system contract, making it available for on-chain verification. Any consensus state field — validator balances, epoch number, withdrawal queue entries — can be proven on-chain without a trusted oracle.

## Overview

```
┌──────────────────────────┐
│       Summit Node        │
│                          │
│  ConsensusState          │       Engine API           ┌───────────────┐
│  ├─ epoch                │  ──────────────────────▶  │     Reth      │
│  ├─ validator_accounts   │  parent_beacon_block_root  │               │
│  ├─ deposit_queue        │  = ssz_tree.root()         │  EIP-4788     │
│  ├─ withdrawal_queue     │                            │  Contract     │
│  └─ ssz_tree ────┐       │                            │  stores root  │
│                  SSZ     │                            │  by timestamp │
│              Merkle Tree │                            │               │
└──────────────│───────────┘                            └───────┬───────┘
               │                                                │
               │                                                │
         ┌─────▼──────┐                                  ┌──────▼──────┐
         │ RPC: get   │                                  │  On-chain   │
         │ StateProof │                                  │  Solidity   │
         │ (root +    │                                  │  contract   │
         │  gindex +  │  ────────── proof ──────────▶   │  verifies   │
         │  branch)   │                                  │  SSZ proof  │
         └────────────┘                                  └─────────────┘
```

SSZ proof verification is a loop of `SHA256(left || right)` calls with ordering determined by the generalized index. Since SHA256 is available as a precompile (`0x02`) on Ethereum, verification can be implemented in a few lines of Solidity without a custom precompile.

## Tree Structure

The state tree is a two-level design: a fixed top-level tree containing scalar fields and collection roots, with dedicated subtrees for each collection.

### Top-Level Tree

32 leaf slots (depth 5), 25 used. Each leaf is a 32-byte `hash_tree_root` value. Leaves 25–31 are unused (zero-filled).

| Leaf Index | Field | Type |
|------------|-------|------|
| 0 | `epoch` | Scalar |
| 1 | `view` | Scalar |
| 2 | `latest_height` | Scalar |
| 3 | `head_digest` | Scalar |
| 4 | `epoch_genesis_hash` | Scalar |
| 5 | `validator_minimum_stake` | Scalar |
| 6 | `validator_maximum_stake` | Scalar |
| 7 | `next_withdrawal_index` | Scalar |
| 8 | `forkchoice_head_block_hash` | Scalar |
| 9 | `forkchoice_safe_block_hash` | Scalar |
| 10 | `forkchoice_finalized_block_hash` | Scalar |
| 11 | `allowed_timestamp_future_ms` | Scalar |
| 12 | `validator_accounts` | Collection root |
| 13 | `deposit_queue` | Collection root |
| 14 | `withdrawal_queue` | Collection root |
| 15 | `protocol_param_changes` | Collection root |
| 16 | `added_validators` | Collection root |
| 17 | `removed_validators` | Collection root |
| 18 | `treasury_address` | Scalar |
| 19 | `max_deposits_per_epoch` | Scalar |
| 20 | `max_withdrawals_per_epoch` | Scalar |
| 21 | `observers_per_validator` | Scalar |
| 22 | `pending_execution_requests` | Collection root |
| 23 | `pending_checkpoint` | Scalar (checkpoint digest, or zero when absent) |
| 24 | `dynamic_epoch_schedule` | Scalar (SSZ byte-list root of the encoded `DynamicEpocher`) |

### Collection Subtrees

Each collection leaf in the top-level tree holds `mix_in_length(subtree.root(), count)`, following SSZ List encoding. The `mix_in_length` operation is `SHA256(tree_root || LE_u64(length))`, encoding the list length alongside the content hash.

#### Validator Accounts

Each validator occupies 8 contiguous leaves (depth-3 per-validator subtree):

| Field Index | Field |
|-------------|-------|
| 0 | `consensus_pubkey` |
| 1 | `withdrawal_credentials` |
| 2 | `balance` |
| 3 | `status` |
| 4 | `has_pending_deposit` |
| 5 | `has_pending_withdrawal` |
| 6 | `joining_epoch` |
| 7 | `last_deposit_index` |

Slot assignment is positional: the i-th entry in `BTreeMap` iteration order occupies leaves `[i*8 .. i*8+7]`. The subtree capacity is always a power of 2, growing/shrinking as validators are added/removed.

#### Deposit Queue

Same 8-leaf-per-item structure as validators (7 fields + 1 zero padding leaf):

| Field Index | Field |
|-------------|-------|
| 0 | `node_pubkey` |
| 1 | `consensus_pubkey` |
| 2 | `withdrawal_credentials` |
| 3 | `amount` |
| 4 | `node_signature` |
| 5 | `consensus_signature` |
| 6 | `index` |
| 7 | (zero padding) |

#### Withdrawal Queue

The withdrawal queue uses a three-level structure organized by epoch:

```
withdrawal collection root = mix_in_length(epoch_tree.root(), epoch_count)

epoch_tree:
  leaf[0] = mix_in_length(epoch_0_subtree.root(), epoch_0_count)
  leaf[1] = mix_in_length(epoch_1_subtree.root(), epoch_1_count)
  ...

epoch_N_subtree:
  8 leaves per withdrawal (same field layout as below)
```

Each withdrawal occupies 8 leaves (7 fields + 1 zero padding):

| Field Index | Field |
|-------------|-------|
| 0 | `index` |
| 1 | `validator_index` |
| 2 | `address` |
| 3 | `amount` |
| 4 | `pubkey` |
| 5 | `balance_deduction` |
| 6 | `epoch` |
| 7 | (zero padding) |

A `HashMap<pubkey, (epoch_slot, item_slot)>` index enables O(1) proof lookup by validator pubkey.

#### Protocol Parameter Changes

2 leaves per item (tag + value), depth-1 subtree per parameter.

#### Added Validators

2 leaves per item (node_key + consensus_key), flattened across all epochs.

#### Removed Validators

1 leaf per item (validator pubkey hash).

#### Pending Execution Requests

1 leaf per item. Each deferred request is an opaque byte blob hashed as an SSZ
byte list: packed into 32-byte chunks (final chunk zero-padded), merkleized, then
`mix_in_length(chunks_root, byte_len)`. The collection root is
`mix_in_length(subtree.root(), request_count)`, like the other collections.

#### Dynamic Epoch Schedule

A single scalar leaf, not a collection. The leaf is the SSZ byte-list root of the
encoded `DynamicEpocher` (same `hash_byte_list` encoding as a pending execution
request). Because the epocher uses interior mutability and can change without a
`ConsensusState` setter, this leaf is refreshed at `capture_state_root` (and in
`rebuild`) rather than maintained incrementally.

## Leaf Encoding

All leaf values are 32 bytes, produced by SSZ `hash_tree_root`:

- **`u64`**: Little-endian encoded, zero-padded to 32 bytes. Used by: epoch, view, latest_height, balance, amount, index, joining_epoch, last_deposit_index, next_withdrawal_index, minimum/maximum_stake, allowed_timestamp_future_ms, max_deposits_per_epoch, max_withdrawals_per_epoch, validator_index, balance_deduction.
- **`u32`**: Little-endian encoded, zero-padded to 32 bytes. Used by: observers_per_validator.
- **`bool`**: `0x01` or `0x00`, zero-padded to 32 bytes. Used by: has_pending_deposit, has_pending_withdrawal.
- **`ValidatorStatus` (enum)**: Single byte (Active=0, Inactive=1, SubmittedExitRequest=2, Joining=3), zero-padded to 32 bytes.
- **`[u8; 32]`**: Used directly as the leaf value. Used by: head_digest, epoch_genesis_hash, forkchoice hashes, withdrawal_credentials (deposit), pubkey (withdrawal), pending_checkpoint (the checkpoint digest, or the zero hash when no checkpoint is pending).
- **`Address` (20 bytes)**: Zero-padded to 32 bytes. Used by: withdrawal_credentials (validator), address (withdrawal), treasury_address.
- **Ed25519 public key (32 bytes)**: Used directly as the leaf value. Used by: node_pubkey (deposit), node_key (added validator), removed validator pubkeys.
- **BLS public key (48 bytes)**: `SHA256(bytes[0..32] || pad(bytes[32..48]))` — 2 chunks hashed. Used by: consensus_pubkey (validator, deposit), consensus_key (added validator).
- **Ed25519 signature (64 bytes)**: `SHA256(bytes[0..32] || bytes[32..64])` — 2 chunks hashed. Used by: node_signature (deposit).
- **BLS signature (96 bytes)**: `merkleize(bytes[0..32], bytes[32..64], bytes[64..96])` — 3 chunks merkleized. Used by: consensus_signature (deposit).

## Tree Updates

Every mutation to `ConsensusState` has a corresponding SSZ tree update. Updates are organized into tiers by optimization strategy.

One exception: the `dynamic_epoch_schedule` leaf is not driven by a `ConsensusState` setter. The `DynamicEpocher` uses interior mutability and can change (epoch advance, length update) without a `&mut ConsensusState` call, so its leaf is recomputed in `capture_state_root` (and `rebuild`) instead.

### Tier 1: Scalar Fields — O(1)

Single top-level leaf write + rehash of the 5-level path to root.

| Method | SSZ Tree Call |
|--------|---------------|
| `set_epoch()` | `ssz_tree.set_epoch()` |
| `set_view()` | `ssz_tree.set_view()` |
| `set_latest_height()` | `ssz_tree.set_latest_height()` |
| `set_head_digest()` | `ssz_tree.set_head_digest()` |
| `set_epoch_genesis_hash()` | `ssz_tree.set_epoch_genesis_hash()` |
| `set_minimum_stake()` | `ssz_tree.set_validator_minimum_stake()` |
| `set_maximum_stake()` | `ssz_tree.set_validator_maximum_stake()` |
| `set_allowed_timestamp_future_ms()` | `ssz_tree.set_allowed_timestamp_future_ms()` |
| `set_treasury_address()` | `ssz_tree.set_treasury_address()` |
| `set_max_deposits_per_epoch()` | `ssz_tree.set_max_deposits_per_epoch()` |
| `set_max_withdrawals_per_epoch()` | `ssz_tree.set_max_withdrawals_per_epoch()` |
| `set_observers_per_validator()` | `ssz_tree.set_observers_per_validator()` |
| `set_next_withdrawal_index()` | `ssz_tree.set_next_withdrawal_index()` |
| `set_pending_checkpoint()` | `ssz_tree.set_pending_checkpoint_digest()` |
| `take_pending_checkpoint()` | `ssz_tree.set_pending_checkpoint_digest(None)` |
| `set_forkchoice_head()` | `ssz_tree.set_forkchoice_head_block_hash()` |
| `set_forkchoice_safe_and_finalized()` | Two setter calls (safe + finalized) |
| `set_forkchoice()` | Three setter calls (head + safe + finalized) |

### Tier 2: Validator Field Update — O(8 log N)

When updating an existing validator's fields (`set_account()` with an existing key), each of the 8 field leaves is written with `set_leaf()`, which rehashes the full path from leaf to root. No tree restructuring needed.

### Tier 3: Validator Insert/Remove — O(N) memcpy + O(N/8) rehash

The key optimization. When inserting or removing a validator, the tree avoids a full rebuild by exploiting the block structure of the per-validator subtrees.

**Insert (`insert_validator_at_slot`):**

1. `grow()` the tree if the new count exceeds capacity (doubles capacity, full rehash).
2. `shift_blocks_right(slot, count, 8)` — copies all 4 levels of per-validator subtree nodes (leaves + 3 internal levels) via `memmove`. The shifted validators' internal hashes remain valid because the subtree structure is preserved.
3. Write the new validator's 8 field leaves with `set_leaf_no_rehash()`.
4. `rehash_block(slot, 8)` — recompute only the 3 internal levels of the new validator's subtree.
5. `rehash_from_position(parent_level, parent_node)` — rehash the suffix of each level above the subtree root, from the affected position upward to the root. Only nodes whose children changed are recomputed.

**Remove (`remove_validator_at_slot`):**

1. `shift_blocks_left(slot, count, 8)` — shifts subsequent validators left, copies all 4 subtree levels, zeros the vacated last block.
2. `rehash_block(vacated_slot, 8)` — fix the vacated block's internal nodes (shift zeros them with `[0u8; 32]` but internal nodes should be `ZERO_HASHES`).
3. `shrink()` if the new count fits in a smaller capacity (full rehash), otherwise `rehash_from_position()` for partial upper-level rehash.

This reduces insert/remove from O(N * 8 * log(N * 8)) (full rebuild) to O(N) memcpy + O(N/8) SHA256 hashes.

### Tier 4: Queue Push — O(8 log N)

**Deposit push (`push_deposit`):** Grows the subtree if needed, then writes 8 field leaves with `set_leaf()` (each rehashes to root). Amortized O(8 log N).

**Withdrawal push (`push_withdrawal`):**
- Append to existing epoch: grows the epoch subtree, writes 8 field leaves, refreshes the epoch leaf. O(8 log N).
- New epoch: creates a new subtree, rebuilds the epoch-level tree. O(E) where E = number of epochs.

**Withdrawal merge (`update_withdrawal`):** When a withdrawal request merges with an existing one (same pubkey), only the 8 leaves in the existing item are overwritten. O(8 log N).

### Tier 5: Small Collection Rebuild — O(K log K)

Protocol parameters, added validators, and removed validators always rebuild their subtree from scratch. These collections are typically very small (single-digit items), so the rebuild cost is negligible.

| Method | SSZ Tree Call |
|--------|---------------|
| `push_protocol_param_change()` | `rebuild_protocol_params()` |
| `apply_protocol_parameter_changes()` | Scalar setters + `rebuild_protocol_params()` |
| `add_validator()` | `rebuild_added_validators()` |
| `remove_added_validators_for_epoch()` | `rebuild_added_validators()` |
| `remove_added_validator()` | `rebuild_added_validators()` |
| `push_removed_validator()` | `rebuild_removed_validators()` |
| `set_removed_validators()` | `rebuild_removed_validators()` |
| `clear_removed_validators()` | `rebuild_removed_validators()` |
| `push_pending_execution_request()` | `rebuild_pending_execution_requests()` |
| `take_pending_execution_requests()` | `rebuild_pending_execution_requests()` |

### Tier 6: Queue Pop — Full Rebuild

**Deposit pop (`pop_deposit`):** Rebuilds the entire deposit subtree from the remaining items. Since items shift forward in the `VecDeque`, the positional mapping changes for every remaining item.

**Withdrawal pop (`pop_withdrawal`):** If items remain in the epoch, rebuilds that epoch's subtree from scratch. If the epoch is now empty, removes it and rebuilds the epoch-level tree.

Both are called in loops during block execution — deposits up to `validator_onboarding_limit_per_block` times, withdrawals once per withdrawal in the block payload. Each pop triggers a full rebuild, so K consecutive pops cost O(K * D * log D) where D is the queue size.

### Bulk Operations

| Method | SSZ Tree Call |
|--------|---------------|
| `ConsensusState::new()` | `rebuild_ssz_tree()` (full rebuild) |
| `set_validator_accounts()` | `rebuild_ssz_tree()` (full rebuild) |
| Deserialization (`Read::read_cfg`) | `rebuild_ssz_tree()` (full rebuild) |

## Proof Format

Proofs use the `SszProof` struct:

```rust
pub struct SszProof {
    pub gindex: u64,           // Generalized index of the leaf
    pub leaf: [u8; 32],        // The leaf value (hash_tree_root)
    pub branch: Vec<[u8; 32]>, // Sibling hashes, bottom-up from leaf to root
}
```

### Generalized Indices

A generalized index (gindex) encodes the path from root to leaf in a binary tree. The root has gindex 1. For any node at gindex `g`, its left child is `2g` and right child is `2g + 1`. A leaf at depth `d` and position `i` has gindex `2^d + i`.

For collection elements, the gindex is composed across tree levels:

```
top_gindex = 2^top_depth + top_leaf_index
collection_gindex = top_gindex << (subtree_depth + 1) | item_index
```

The `+1` accounts for the `mix_in_length` node that sits between the top-level leaf and the subtree root.

For withdrawals, there is an additional nesting level:

```
epoch_gindex = top_gindex << (epoch_tree_depth + 1) | epoch_slot
item_gindex = epoch_gindex << (subtree_depth - 2) | item_slot
```

### Branch Composition

The proof branch concatenates sibling hashes from multiple tree levels:

**Scalar proof:** Top-level tree siblings only (5 elements for depth-5 tree).

**Collection element proof (e.g., validator, deposit):**
1. Subtree siblings (from leaf/node to subtree root)
2. `mix_in_length` sibling: `LE_u64(count)` zero-padded to 32 bytes
3. Top-level tree siblings (from collection leaf to state root)

**Withdrawal proof (three-level):**
1. Per-epoch subtree siblings
2. Per-epoch `mix_in_length` sibling (epoch item count)
3. Epoch tree siblings
4. Epoch count `mix_in_length` sibling
5. Top-level tree siblings

### Proof Granularity

Proofs can target different levels of the tree:

- **Whole-account proof**: The leaf is the per-validator subtree root (internal node 3 levels above field leaves). Shorter branch.
- **Field-level proof**: The leaf is an individual field (e.g., just the balance). Longer branch but proves a single field.

The same applies to deposits and withdrawals — both whole-item and field-level proofs are supported.

## Proof Verification

Verification reconstructs the root from the leaf and branch, then compares against the expected state root:

```rust
fn verify(&self, state_root: &[u8; 32]) -> bool {
    SszTree::verify_proof_gindex(state_root, self.gindex, &self.leaf, &self.branch)
}
```

The algorithm:

1. Start with `hash = leaf`.
2. Walk the gindex from bottom to top. At each level:
   - If the current gindex is even (left child): `hash = SHA256(hash || sibling)`
   - If odd (right child): `hash = SHA256(sibling || hash)`
   - Move up: `gindex /= 2`
3. The final hash must equal the state root, and the gindex must have reached 1 (the root).

The proof length must equal `floor(log2(gindex))` — the depth of the leaf in the tree.

On-chain verification follows the same algorithm. The state root is retrieved from the EIP-4788 system contract by block timestamp, and the proof is verified in Solidity using the SHA256 precompile (`0x02`). No custom precompile is needed — the verification logic is a simple loop of hash computations with left/right ordering determined by the gindex.

## Snapshot and Proof Tree

The live `ssz_tree` is continuously mutated during block execution. Proofs cannot be generated from a moving target, so `capture_state_root()` creates a frozen snapshot:

```rust
pub fn capture_state_root(&mut self, el_block_number: u64) {
    self.state_root = self.ssz_tree.root();
    self.proof_tree = self.ssz_tree.clone();
    self.proof_validator_keys = self.validator_accounts.keys().copied().collect();
    self.proof_el_block_number = el_block_number;
}
```

This is called after `execute_block` in the finalizer. The frozen `proof_tree` is used for all subsequent proof generation (via RPC), while the live `ssz_tree` continues to be mutated by finalization operations. The snapshot includes the sorted validator keys (needed for positional index lookups) and the withdrawal pubkey index (stored inside the `SszStateTree`).

The state root appears on-chain in EL block `proof_el_block_number + 1`.

## RPC API

Two JSON-RPC endpoints on the `SummitProofApi`:

### `getStateRoot`

Returns the current state root and the EL block number it was captured at.

```json
// Request
{"jsonrpc":"2.0","method":"getStateRoot","params":[],"id":1}

// Response
{
  "root": "0x...",
  "el_block_number": 42
}
```

The state root appears on-chain in EL block `el_block_number + 1`.

### `getStateProof`

Takes a list of key strings and returns the state root, EL block number, and one result for each key. Each result echoes the requested key and contains either an `SszProof` or an error for a key that is absent or out of range.

```json
// Request
{"jsonrpc":"2.0","method":"getStateProof","params":[["epoch","validator:0xABCD...","deposit:999999"]],"id":1}

// Response
{
  "root": "0x...",
  "el_block_number": 42,
  "results": [
    {
      "key": "epoch",
      "proof": { "gindex": 32, "leaf": "0x...", "branch": ["0x...", ...] },
      "error": null
    },
    {
      "key": "validator:0xABCD...",
      "proof": { "gindex": 1408, "leaf": "0x...", "branch": ["0x...", ...] },
      "error": null
    },
    {
      "key": "deposit:999999",
      "proof": null,
      "error": "key is absent or out of range"
    }
  ]
}
```

### Key Format

Keys are human-readable strings parsed by `types/src/ssz_tree_key.rs`:

**Scalar fields** — use the field name directly:

| Key | Field |
|-----|-------|
| `epoch` | Current epoch |
| `view` | Current view |
| `latest_height` | Latest finalized block height |
| `head_digest` | Head block digest |
| `epoch_genesis_hash` | Genesis hash for current epoch |
| `validator_minimum_stake` | Minimum validator stake |
| `validator_maximum_stake` | Maximum validator stake |
| `allowed_timestamp_future_ms` | Allowed timestamp future (ms) |
| `treasury_address` | Treasury address |
| `max_deposits_per_epoch` | Max validator deposits per epoch |
| `max_withdrawals_per_epoch` | Max validator withdrawals per epoch |
| `observers_per_validator` | Observer keys authorized per validator |
| `next_withdrawal_index` | Next withdrawal index |
| `forkchoice_head_block_hash` | Forkchoice head hash |
| `forkchoice_safe_block_hash` | Forkchoice safe hash |
| `forkchoice_finalized_block_hash` | Forkchoice finalized hash |

**Validator proofs** — by hex-encoded 32-byte pubkey:

| Key Format | Example | Proves |
|------------|---------|--------|
| `validator:<pubkey>` | `validator:0xABCD...` | Whole account |
| `validator_field:<pubkey>:<field>` | `validator_field:0xABCD...:balance` | Single field |

Validator field names: `consensus_pubkey`, `withdrawal_credentials`, `balance`, `status`, `has_pending_deposit`, `has_pending_withdrawal`, `joining_epoch`, `last_deposit_index`.

**Deposit proofs** — by queue index:

| Key Format | Example | Proves |
|------------|---------|--------|
| `deposit:<index>` | `deposit:0` | Whole deposit |
| `deposit_field:<index>:<field>` | `deposit_field:0:amount` | Single field |

Deposit field names: `node_pubkey`, `consensus_pubkey`, `withdrawal_credentials`, `amount`, `node_signature`, `consensus_signature`, `index`.

**Withdrawal proofs** — by hex-encoded 32-byte pubkey:

| Key Format | Example | Proves |
|------------|---------|--------|
| `withdrawal:<pubkey>` | `withdrawal:0xABCD...` | Whole withdrawal |
| `withdrawal_field:<pubkey>:<field>` | `withdrawal_field:0xABCD...:amount` | Single field |

Withdrawal field names: `index`, `validator_index`, `address`, `amount`, `pubkey`, `balance_deduction`, `epoch`.

**Protocol parameter proofs** — by index:

| Key Format | Example | Proves |
|------------|---------|--------|
| `protocol_param:<index>` | `protocol_param:0` | Whole param |
| `protocol_param_field:<index>:<field>` | `protocol_param_field:0:tag` | Single field |

Protocol param field names: `tag`, `value`.

**Added validator proofs** — by flattened index:

| Key Format | Example | Proves |
|------------|---------|--------|
| `added_validator:<index>` | `added_validator:0` | Whole added validator |
| `added_validator_field:<index>:<field>` | `added_validator_field:0:node_key` | Single field |

Added validator field names: `node_key`, `consensus_key`.

**Removed validator proofs** — by index:

| Key Format | Example | Proves |
|------------|---------|--------|
| `removed_validator:<index>` | `removed_validator:0` | Removed validator pubkey |

## Future Work

### Deferred Tree Updates

Currently, every `ConsensusState` mutation immediately updates the SSZ tree. Since the tree root is only consumed at `capture_state_root()` time (after block execution), intermediate tree states are wasted work.

A deferred approach would accumulate mutations and apply them in a single batch before the root is needed. Two strategies:

1. **Dirty flags per subtree**: Track which subtrees have been modified and rebuild only those at flush time. Simple to implement but still does full rebuilds per subtree.

2. **Operation log**: Record the sequence of mutations (e.g., "popped 5 deposits", "inserted validator at slot 3") and replay them optimally in batch. Enables batch-shift optimizations but adds complexity.

### Batch Queue Pop

The deposit and withdrawal pop operations are the primary candidates for optimization:

- **Deposit pop**: Currently calls `rebuild_deposits()` (full subtree rebuild) on every `pop_deposit()`. During block execution, deposits are popped in a loop up to `validator_onboarding_limit_per_block` times. K consecutive pops trigger K full rebuilds of decreasing size. A single rebuild after all pops would be ~K times cheaper.

- **Withdrawal pop**: Currently rebuilds the affected epoch's subtree on every `pop_withdrawal()`. If a block contains K withdrawals from the same epoch, that's K successive epoch-subtree rebuilds. A batch pop could rebuild the epoch subtree once after all pops.

### Block-Shift Optimization for Deposits

The deposit queue is a `VecDeque` where pops remove from the front, shifting all remaining items. The same `shift_blocks_left` + `rehash_from_position` optimization used for validators could be applied here, avoiding full subtree rebuilds entirely. For K consecutive pops, a single shift left by K positions + partial rehash would be O(D) instead of O(K * D * log D).
