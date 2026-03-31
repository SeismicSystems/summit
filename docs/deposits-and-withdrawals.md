# Deposits and Withdrawals

This document describes the internal state management for deposit and withdrawal requests in Summit.

## Account Flags

Each `ValidatorAccount` has two flags to prevent concurrent requests:

- `has_pending_deposit`: Set when a deposit is queued, cleared when processed
- `has_pending_withdrawal`: Set when a withdrawal is queued, cleared when processed

### Concurrent Request Prevention

| Request Type | Blocked If |
|--------------|------------|
| Deposit | `has_pending_deposit = true` OR `has_pending_withdrawal = true` |
| Withdrawal | `has_pending_deposit = true` OR `has_pending_withdrawal = true` |

## Deposit Flow

Deposits are parsed in `parse_execution_requests` and processed in `process_execution_requests`.

### Deposit Scenarios

| Scenario | When Parsed | When Processed |
|----------|-------------|----------------|
| New validator | Create `Inactive` account, set flag | Set `Joining`, set balance, clear flag |
| Top-up | Set flag | Update balance, clear flag |
| Failed signature | Refund withdrawal (no account) | N/A |

### New Validator Deposit

1. **Parsing**: Signature and stake range validated. Account created with `Inactive` status and `has_pending_deposit = true`. Deposit queued.
2. **Processing**: Status changed to `Joining`, balance set, `joining_epoch` set, flag cleared. Validator added to `added_validators` for future activation.

### Top-up Deposit

1. **Parsing**: Signature validated, `has_pending_deposit = true` set on existing account. Deposit queued.
2. **Processing**: Balance updated if within range, flag cleared. If out of range, refund withdrawal created.

### Failed Signature

If signature verification fails, a refund withdrawal is created immediately. No account is created or modified.

## Withdrawal Flow

Withdrawals are parsed in `parse_execution_requests` and processed when included in a block, unless
they are deferred at an epoch boundary and retried from `pending_execution_requests` in the next
epoch.

### Withdrawal Scenarios

| Scenario | When Parsed | When Processed |
|----------|-------------|----------------|
| User-initiated | Set balance to 0, set flag | Clear flag, remove account if balance is 0 |
| Below min stake | Set balance to 0, set flag | Clear flag, remove account if balance is 0 |
| Above max stake | Subtract excess from balance, set flag | Clear flag |
| Failed deposit refund | Create refund withdrawal (or merge into existing) | No account changes |
| Top-up exceeds range | Create refund withdrawal (or merge into existing) | No account changes |
| New deposit invalid | Create refund withdrawal, remove account | No account changes |

### User-Initiated Withdrawal

1. **Parsing**: `balance` set to 0, `has_pending_withdrawal = true`. The withdrawn amount is tracked as `balance_deduction` on the `PendingWithdrawal` in the queue. Validator added to `removed_validators`.
2. **Processing**: Flag cleared. Account removed if `balance` is zero.

### Stake Bound Violations

When `validator_min_stake` or `validator_max_stake` parameters change:
- **Below min**: Full balance withdrawn, validator removed from committee
- **Above max**: Excess withdrawn as partial withdrawal, validator remains active

### Refund Withdrawals

Refund withdrawals have `balance_deduction = 0` because the deposited funds were never credited to the account. These do not set `has_pending_withdrawal` and do not block future operations.

If the validator already has a pending withdrawal (e.g., a user-initiated exit), the refund is merged into it: the refund amount is added to the existing withdrawal's `amount`, while `balance_deduction` remains unchanged (the refund portion contributes 0). This produces a single withdrawal covering both the original balance and the refunded deposit.

### Invalid Withdrawal Credentials

Withdrawal credentials must be in Eth1 format: `0x01` prefix + 11 zero bytes + 20-byte Ethereum address.

If withdrawal credentials cannot be parsed:
- **New validator deposit**: Deposit is ignored, funds are lost
- **Refund withdrawal**: Refund cannot be created, funds are lost

## Withdrawal Queue and Merging

The `WithdrawalQueue` stores at most one pending withdrawal per validator (keyed by pubkey). Each withdrawal tracks:
- `amount`: the total withdrawal amount (included in the block as an EIP-4895 withdrawal)
- `balance_deduction`: the amount that was moved out of the validator's `balance` when the withdrawal was created. This is used by the RPC `getValidatorBalance` endpoint to include pending withdrawal funds in the reported balance.

When a new withdrawal is pushed for a validator that already has a pending entry, the amounts and balance deductions are merged into the existing entry, keeping the original scheduled epoch. This ensures that refund withdrawals (which bypass the `has_pending_withdrawal` guard) do not create duplicate queue entries.

User-initiated withdrawals are still limited to one at a time via the `has_pending_withdrawal` flag on the account. The merging behavior only applies to system-initiated withdrawals (deposit refunds, stake bounds enforcement) that target a validator with an existing pending withdrawal.

## Withdrawal Deferral at Epoch Boundaries

Withdrawal requests for active validators received on the **last block of an epoch** are deferred to the next epoch. This ensures that `removed_validators` in the finalized header accurately reflects all validator exits, since the header is created at the penultimate block.

Deferred requests are stored in `pending_execution_requests` and processed at the start of the next
epoch. Deferred withdrawals are re-queued individually.

## Invariants

- A validator will join the committee `VALIDATOR_NUM_WARM_UP_EPOCHS` epochs after submitting a valid deposit request. The phase after submitting the deposit request, and before joining the committee is called the `onboarding phase`.
- If a withdrawal request is submitted in epoch `n`, then it is normally handled in epoch `n`, and
  the withdrawal will be processed in epoch `n + VALIDATOR_WITHDRAWAL_NUM_EPOCHS`. Exception:
  requests received on the last block of epoch `n` are deferred to the next epoch before being
  scheduled.
- There are two parameters that govern the staking amount: `validator_min_stake` and `validator_max_stake`. The balance of a validator must always be in range `[validator_min_stake, validator_max_stake]`.
- Any deposit request with resulting balance outside `[validator_min_stake, validator_max_stake]` will be rejected and refunded.
- A validator can only have one pending deposit request at a time. Subsequent deposit requests will be ignored.
- A validator can only have one pending withdrawal entry in the queue at a time. User-initiated withdrawal requests are ignored if one is already pending. System-initiated withdrawals (deposit refunds, stake bounds enforcement) are merged into the existing entry.
- A validator cannot submit a deposit request while a withdrawal request is pending, and vice versa.
- If a withdrawal request is submitted while a validator is in the onboarding phase, then the onboarding phase is aborted, and the withdrawal request will be processed `VALIDATOR_WITHDRAWAL_NUM_EPOCHS` epochs later.
- No partial withdrawals. If a withdrawal request with amount `amount < balance` is submitted, the full `balance` will be withdrawn.
- Exception: If `validator_max_stake` is lowered and a validator's balance exceeds the new maximum, the excess is withdrawn as a partial withdrawal, and the validator remains active.
- If `validator_min_stake` is raised and a validator's balance is below the new minimum, the validator is removed and the full balance is withdrawn.
