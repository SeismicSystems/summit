# Consensus State Proofs

Summit maintains a Merkle Patricia Trie (MPT) over its consensus state and commits the trie root to each execution layer block header as `parent_beacon_block_root`. During block execution, Reth stores this root in the EIP-4788 system contract, making it available for on-chain verification. Any consensus state field — such as validator balances, epoch number, or withdrawal queue entries — can then be proven on-chain without requiring a trusted oracle.

## Overview

```
┌─────────────────────────┐
│      Summit Node        │
│                         │
│  ConsensusState         │       Engine API          ┌───────────────┐
│  ├─ epoch               │  ─────────────────────▶  │     Reth      │
│  ├─ validator_accounts  │  parent_beacon_block_root │               │
│  ├─ ...                 │  = state_trie.root()      │  EIP-4788     │
│  └─ state_trie ───┐     │                           │  Contract     │
│                   MPT   │                           │  stores root  │
│                    │    │                           │  by timestamp │
└────────────────────│────┘                           └───────┬───────┘
                     │                                        │
                     │                                        │
               ┌─────▼──────┐                          ┌──────▼──────┐
               │ RPC: get   │                          │ On-chain    │
               │ StateProof │                          │ precompile  │
               │ (root +    │                          │ 0x6A        │
               │  proof +   │  ────── proof ──────▶   │ verifies    │
               │  values)   │                          │ MPT proof   │
               └────────────┘                          └─────────────┘
```

The system has three components:

1. **State Trie** — an in-memory MPT over all consensus state fields, maintained by the finalizer
2. **EIP-4788 System Contract** — stores the trie root on-chain, indexed by block timestamp
3. **MPT Verify Precompile (0x6A)** — verifies inclusion and exclusion proofs against a given root

## Consensus State Trie

### Structure

Every field in `ConsensusState` is stored as an individual entry in the trie. This includes scalar fields (epoch, view, latest height) and per-validator fields (balance, status, withdrawal credentials).

Keys are human-readable byte strings like `b"epoch"` or `b"validator_account_balance:<pubkey>"`. Before insertion into the trie, each key is hashed with `keccak256` for uniform distribution across the trie.

Values are encoded using `commonware_codec::Encode` for structured types or big-endian byte encoding for integers.

**Key definitions** (`types/src/state_trie_key.rs`):

**Scalar fields:**

| Key | Description |
|-----|-------------|
| `epoch` | Current epoch number |
| `view` | Current consensus view |
| `latest_height` | Latest finalized block height |
| `head_digest` | Head block digest |
| `epoch_genesis_hash` | Genesis hash for current epoch |
| `validator_minimum_stake` | Minimum validator stake |
| `validator_maximum_stake` | Maximum validator stake |
| `next_withdrawal_index` | Next withdrawal index |
| `forkchoice_head_block_hash` | Forkchoice head hash |
| `forkchoice_safe_block_hash` | Forkchoice safe hash |
| `forkchoice_finalized_block_hash` | Forkchoice finalized hash |

**Validator account fields** (per pubkey):

| Key | Description |
|-----|-------------|
| `validator_account_balance:<pubkey>` | Staked balance |
| `validator_account_status:<pubkey>` | Status (active, pending, exiting) |
| `validator_account_consensus_public_key:<pubkey>` | BLS consensus public key |
| `validator_account_withdrawal_credentials:<pubkey>` | Withdrawal address |
| `validator_account_has_pending_deposit:<pubkey>` | Whether a deposit is pending |
| `validator_account_has_pending_withdrawal:<pubkey>` | Whether a withdrawal is pending |
| `validator_account_joining_epoch:<pubkey>` | Epoch the validator joined |

**Deposit queue fields** (per pubkey):

| Key | Description |
|-----|-------------|
| `deposit_queue_request_consensus_pubkey:<pubkey>` | BLS key in deposit request |
| `deposit_queue_request_withdrawal_credentials:<pubkey>` | Withdrawal address in deposit request |
| `deposit_queue_request_amount:<pubkey>` | Deposit amount |
| `deposit_queue_request_node_signature:<pubkey>` | Node signature on deposit |
| `deposit_queue_request_consensus_signature:<pubkey>` | Consensus signature on deposit |

**Withdrawal queue fields** (per pubkey):

| Key | Description |
|-----|-------------|
| `withdrawal_queue_request_balance_deduction:<pubkey>` | Balance to deduct |
| `withdrawal_queue_request_address:<pubkey>` | Withdrawal destination address |
| `withdrawal_queue_request_amount:<pubkey>` | Withdrawal amount |
| `withdrawal_queue_request_epoch:<pubkey>` | Epoch withdrawal was requested |

**Other fields** (per pubkey):

| Key | Description |
|-----|-------------|
| `added_validators_consensus_key:<pubkey>` | Consensus key of newly added validator |
| `removed_validators:<pubkey>` | Marker for removed validator |
| `protocol_param_changes_param:<variant>` | Pending protocol parameter change |

### Trie Updates

The trie is updated whenever consensus state changes. All mutations to validator accounts go through `set_account()` and `remove_account()` on `ConsensusState`, which update both the accounts map and the trie atomically:

```rust
// types/src/consensus_state.rs
pub fn set_account(&mut self, pubkey: [u8; 32], account: ValidatorAccount) {
    self.insert_validator_trie_entries(&pubkey, &account);
    self.validator_accounts.insert(pubkey, account);
}
```

Each validator field is stored as a separate trie entry. For example, `set_account()` inserts entries for `validator_account_balance:<pubkey>`, `validator_account_status:<pubkey>`, `validator_account_consensus_public_key:<pubkey>`, and so on. This granularity allows proving individual fields without revealing the entire validator record.

Scalar fields (epoch, view, forkchoice hashes, etc.) are updated directly via `state_trie.insert_u64()` or `state_trie.insert_raw()` during block execution and finalization.

### Root Capture and Proof Trie

After each block is executed, the finalizer captures a snapshot of the trie:

```rust
// types/src/consensus_state.rs
pub fn capture_state_root(&mut self, el_block_number: u64) {
    self.state_root = self.state_trie.root();
    self.proof_trie = self.state_trie.clone();
    self.proof_el_block_number = el_block_number;
}
```

This creates two separate copies:
- **`state_trie`** — continues to be mutated as new blocks are processed and finalized
- **`proof_trie`** — frozen snapshot used for proof generation; proofs from this trie will verify against the captured root

The separation is necessary because finalization mutations (epoch transitions, validator set changes) happen after block execution and would invalidate proofs generated against the captured root.

## Publishing the Root On-Chain

### How the Root Reaches the EL

Summit repurposes the `parent_beacon_block_root` field from the Ethereum execution payload to carry the consensus state trie root. In standard Ethereum, this field carries the beacon chain's block root. In Summit, it carries the MPT root of the consensus state.

The flow:

1. **Capture** — After executing block N, the finalizer calls `capture_state_root(N)`, recording the trie root and EL block number
2. **Propose** — When proposing the next block (N+1), the application layer includes `state_root` in the `PayloadAttributes` sent to Reth via the Engine API. Reth places it in the block header as `parent_beacon_block_root`
3. **Validate** — Other validators verify that the proposed block's `parent_beacon_block_root` matches their own computed state root
4. **Store** — When Reth executes the block, its standard EIP-4788 processing calls the system contract at `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`, which stores the root indexed by the block's timestamp

```rust
// application/src/actor.rs — block proposal
engine_client.start_building_block(
    forkchoice,
    timestamp,
    withdrawals,
    withdrawal_credentials,
    Some(aux_data.state_root.into()),  // becomes parent_beacon_block_root
).await;

// application/src/actor.rs — block validation
if block.header.parent_beacon_block_root != aux_data.state_root {
    warn!("parent_beacon_block_root mismatch");
    return false;
}
```

### EIP-4788 System Contract

The system contract at `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02` is a ring buffer that stores the most recent 8191 roots, indexed by timestamp. Reth calls this contract automatically as part of block execution — Summit never interacts with the contract directly.

**Reading a root**: Any contract or off-chain caller can query the stored root by calling the contract with `abi.encode(uint256(timestamp))`, where `timestamp` is the block timestamp at which the root was stored (block N+1's timestamp, since the root captured at block N is published in block N+1).

### TIMESTAMP_MS Modification

Standard Ethereum uses second-level timestamps, but Summit uses millisecond timestamps for finer block granularity. The standard EIP-4788 contract uses the `TIMESTAMP` opcode internally to index its ring buffer, which would cause multiple blocks within the same second to overwrite each other's entries.

To address this, the contract bytecode has been modified to use the `TIMESTAMP_MS` opcode (`0x4B`) instead of `TIMESTAMP` (`0x42`). The `TIMESTAMP_MS` opcode is a Seismic EVM extension that returns the block timestamp in milliseconds directly, matching Summit's native timestamp format.

This change affects two locations in the contract bytecode — both in the "store" path where the contract indexes new entries:

```
Original (TIMESTAMP):    ... 62001fff 42 06 42 81 55 ...
Modified (TIMESTAMP_MS): ... 62001fff 4B 06 4B 81 55 ...
```

The "get" path is unchanged — callers provide the timestamp as a `uint256` argument, so they simply pass the millisecond timestamp directly.

## Proof RPC Endpoints

Summit exposes two RPC endpoints for querying the consensus state trie:

### `getStateRoot`

Returns the current frozen state root and the EL block number at which it was captured.

**Response:**
```json
{
  "root": "0x...",
  "el_block_number": 42
}
```

### `getStateProof`

Given a list of key descriptors, returns the state root, EL block number, proof nodes, and the values for each key (or `null` for keys not present in the trie).

**Request:**
```json
{
  "method": "getStateProof",
  "params": [["epoch", "latest_height", "validator_account_balance:0xabcd..."]]
}
```

**Response:**
```json
{
  "root": "0x...",
  "el_block_number": 42,
  "proof": ["0x...", "0x...", ...],
  "values": ["0x...", "0x...", null]
}
```

**Key descriptor format**: Scalar keys use their name directly (`"epoch"`, `"view"`, `"latest_height"`). Per-validator keys use the format `"field_name:0x<hex_pubkey>"` (e.g., `"validator_account_balance:0xabcd..."`).

The proof is generated from the frozen `proof_trie` snapshot, so it verifies against the root that was published on-chain in EL block `el_block_number + 1`.

## MPT Verify Precompile (0x6A)

The MPT verify precompile at address `0x000000000000000000000000000000000000006A` verifies Merkle Patricia Trie proofs on-chain. It supports both inclusion proofs (key exists with a given value) and exclusion proofs (key does not exist).

### Input Format

```
root                    (32 bytes)
item_count              (4 bytes, big-endian u32)
  For each item:
    hashed_key          (32 bytes, keccak256 of the logical key)
    has_value           (1 byte: 0x01 for inclusion, 0x00 for exclusion)
    If inclusion:
      value_length      (4 bytes, big-endian u32)
      value             (value_length bytes)
proof_count             (4 bytes, big-endian u32)
  For each proof node:
    node_length         (4 bytes, big-endian u32)
    node                (node_length bytes)
```

### Output

Returns a single 32-byte value: `0x00...01` on success, or reverts on failure.

### Gas Cost

```
gas = 3000 + (item_count * 200) + (proof_count * 500)
```

The base cost of 3000 is comparable to `ecrecover` (3000 gas). Each additional item adds 200 gas, and each proof node adds 500 gas.

### Usage

**Direct `eth_call`**: Applications can verify proofs off-chain by calling the precompile with the root and proof data.

**From a smart contract**: Contracts can read the root from the EIP-4788 system contract and then call the precompile:

```solidity
contract MptProofVerifier {
    address constant BEACON_ROOTS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
    address constant MPT_PRECOMPILE = 0x000000000000000000000000000000000000006a;

    function verify(uint256 timestamp, bytes calldata proofData)
        external view returns (bytes32 root)
    {
        // 1. Read state root from the system contract
        (bool ok, bytes memory rootData) = BEACON_ROOTS.staticcall(
            abi.encode(timestamp)
        );
        require(ok && rootData.length == 32, "root lookup failed");
        root = abi.decode(rootData, (bytes32));

        // 2. Verify MPT proof against the root
        (bool ok2, bytes memory result) = MPT_PRECOMPILE.staticcall(
            abi.encodePacked(root, proofData)
        );
        require(
            ok2 && result.length >= 32 && uint8(result[31]) == 1,
            "MPT verification failed"
        );
    }
}
```

This pattern enables fully trustless on-chain verification: the root comes from the system contract (written during block execution), and the proof is verified by the precompile — no trusted oracle required.

## End-to-End Verification Flow

Putting it all together, here is the full flow for proving a consensus state field on-chain:

1. **State capture**: Summit finalizer executes block N, then calls `capture_state_root(N)` to freeze the trie and record the root
2. **Root publication**: Block N+1 is proposed with `parent_beacon_block_root = frozen_root`. Reth executes the block and the EIP-4788 system contract stores the root indexed by block N+1's millisecond timestamp
3. **Proof request**: A client calls `getStateProof(["epoch", "latest_height"])` via Summit RPC. The response includes the frozen root, the EL block number N, proof nodes, and values
4. **On-chain verification**: A smart contract reads the root from the system contract using block N+1's timestamp, then passes the root + proof data to the precompile at `0x6A`
5. **Result**: The precompile returns `0x01` if the proof is valid, proving that the claimed values were part of the consensus state at block N

```
Summit Finalizer                    Reth (EL)                    Smart Contract
     │                                │                               │
     │  execute block N               │                               │
     │  capture_state_root(N)         │                               │
     │  root = trie.root()            │                               │
     │                                │                               │
     │  propose block N+1             │                               │
     │  parent_beacon_block_root=root │                               │
     │  ──────────────────────────▶  │                               │
     │                                │  store root at                │
     │                                │  timestamp(N+1)               │
     │                                │                               │
     │                                │                               │
     │  getStateProof(keys)           │                               │
     │  ◀──────────────────────────  │                               │
     │  returns: root, proof, values  │                               │
     │  ──────────────────────────▶  │                               │
     │                                │                        call verify()
     │                                │                   ◀──────────│
     │                                │  read root from               │
     │                                │  system contract              │
     │                                │  ────────────────▶           │
     │                                │                          verify proof
     │                                │                            via 0x6A
     │                                │                               │
     │                                │                         return success
```
