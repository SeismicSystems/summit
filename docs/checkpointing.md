# Checkpointing

This document describes how checkpoints are created, stored, loaded, and verified in Summit.

## Overview

Checkpoints enable nodes to sync from a recent state rather than replaying the entire chain from genesis. A checkpoint contains a snapshot of the consensus state at the end of an epoch, along with finalized headers that allow verification of the checkpoint's authenticity.

## Checkpoint Creation

Checkpoints are created at the **penultimate block of each epoch** (block `epoch * BLOCKS_PER_EPOCH + BLOCKS_PER_EPOCH - 2`). This timing ensures that:

1. All validator set changes (`added_validators`, `removed_validators`) are finalized before the epoch ends
2. The checkpoint hash can be included in the last block's header for verification

### Creation Flow

1. **Penultimate Block Processing** (`process_execution_requests`):
   - Pending deposit requests are processed from `deposit_queue`
   - New validators are added to `added_validators` for the appropriate activation epoch
   - The `removed_validators` list is populated with validators exiting this epoch

2. **Checkpoint Creation** (`process_block`):
   ```
   if is_penultimate_block_of_epoch(epoch_num_of_blocks, height):
       checkpoint = Checkpoint::new(&state)
       state.pending_checkpoint = Some(checkpoint)
   ```

3. **Last Block of Epoch**:
   - The checkpoint hash is included in the block header's `checkpoint_hash` field
   - Validators sign this block, creating a quorum certificate over the checkpoint

### Checkpoint Contents

A checkpoint contains the serialized `ConsensusState`, which includes:

| Field | Description |
|-------|-------------|
| `epoch` | Current epoch number |
| `view` | Current view number |
| `latest_height` | Height of the last finalized block |
| `head_digest` | Digest of the last finalized block |
| `deposit_queue` | Pending deposit requests |
| `withdrawal_queue` | Scheduled withdrawals by epoch |
| `validator_accounts` | All validator account states |
| `added_validators` | Validators scheduled to join, by activation epoch |
| `removed_validators` | Validators exiting at the current epoch boundary |
| `pending_execution_requests` | Deferred execution requests (e.g., withdrawals from last block) |
| `forkchoice` | Current forkchoice state (head, safe, finalized hashes) |

## Finalized Headers

Finalized headers are stored alongside checkpoints to enable verification. A `FinalizedHeader` contains:

| Field | Description |
|-------|-------------|
| `header` | The block header |
| `certificate` | BLS multi-signature from the validator committee |
| `signers` | Bitmap indicating which validators signed |

### Header Storage

Headers are stored when blocks are finalized:

```
if is_last_block_of_epoch(epoch_num_of_blocks, height):
    finalized_header = FinalizedHeader::new(header, certificate, signers)
    db.put_finalized_header(epoch, finalized_header)
```

Only the last header of each epoch is stored, as it contains:
- The `checkpoint_hash` referencing the checkpoint created at the penultimate block
- The `added_validators` and `removed_validators` for the epoch
- A quorum certificate proving consensus

## Checkpoint Loading

When a node starts, it attempts to load the most recent checkpoint:

### Loading Flow

1. **Find Latest Checkpoint**:
   ```
   latest_epoch = db.get_most_recent_checkpoint_epoch()
   checkpoint = db.get_checkpoint(latest_epoch)
   ```

2. **Restore Consensus State**:
   ```
   state = ConsensusState::try_from(checkpoint)
   ```

3. **Resume from Checkpoint**:
   - Set `sync_height` to `state.latest_height`
   - Set `sync_epoch` to `state.epoch`
   - Begin syncing from the next block

### Database Schema

Checkpoints and headers are stored in separate column families:

| Column Family | Key | Value |
|---------------|-----|-------|
| `checkpoints` | epoch (u64) | Checkpoint bytes |
| `finalized_headers` | epoch (u64) | FinalizedHeader bytes |
| `most_recent_checkpoint` | - | epoch (u64) |
| `most_recent_finalized_header` | - | epoch (u64) |

## Checkpoint Verification

Checkpoint verification allows a node to trustlessly validate a checkpoint received from an untrusted source. This is essential for secure bootstrapping without replaying the entire chain.

### Verification Scheme

To verify a checkpoint for epoch `n`, a verifier needs:

1. **Genesis state**: The initial validator set and their BLS public keys
2. **Finalized headers**: Headers for epochs `0` through `n`
3. **Checkpoint**: The checkpoint for epoch `n`

### Verification Steps

1. **Verify Header Chain**:
   - For each epoch `i` from `0` to `n`:
     - Verify the BLS multi-signature using the known validator set for epoch `i`
     - Extract `added_validators` and `removed_validators` from the header
     - Update the validator set for epoch `i+1`

2. **Verify Checkpoint Hash**:
   - Compute the checkpoint digest
   - Verify it matches `checkpoint_hash` in header `n`

3. **Verify Validator Set Consistency**:
   - The checkpoint's `validator_accounts` should match the accumulated validator set changes

### Header Fields for Verification

Each header contains the validator set changes that take effect at the epoch boundary:

| Field | Description |
|-------|-------------|
| `added_validators` | List of `AddedValidator { node_key, consensus_key }` |
| `removed_validators` | List of validator public keys being removed |
| `checkpoint_hash` | Hash of the checkpoint (only in last block of epoch) |

The `consensus_key` (BLS public key) in `added_validators` allows verifiers to update their known validator set without needing the full checkpoint data for intermediate epochs.

### Withdrawal Deferral

Withdrawal requests for active validators received on the **last block of an epoch** are deferred to the next epoch. This ensures that `removed_validators` in the header accurately reflects all validator exits, since the header is created at the penultimate block.

Deferred requests are stored in `pending_execution_requests` and processed at the start of the next epoch.

### Future Work

Checkpoint verification is not yet implemented. Currently, nodes must either:

- Sync from genesis, or
- Trust the checkpoint source

## Related Configuration

| Parameter | Description |
|-----------|-------------|
| `BLOCKS_PER_EPOCH` | Number of blocks per epoch (determines checkpoint frequency) |
| `VALIDATOR_NUM_WARM_UP_EPOCHS` | Epochs before a new validator becomes active |
| `VALIDATOR_WITHDRAWAL_NUM_EPOCHS` | Epochs before a withdrawal is processed |
