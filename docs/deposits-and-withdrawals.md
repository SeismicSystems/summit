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

Withdrawals are parsed in `parse_execution_requests` and processed when included in a block.

### Withdrawal Scenarios

| Scenario | When Parsed | When Processed |
|----------|-------------|----------------|
| User-initiated | Move balance to pending, set flag | Subtract from pending, clear flag |
| Below min stake | Move balance to pending, set flag | Subtract from pending, clear flag |
| Above max stake | Move excess to pending, set flag | Subtract from pending, clear flag |
| Failed deposit refund | Create refund withdrawal | No account changes |
| Top-up exceeds range | Create refund withdrawal | No account changes |
| New deposit invalid | Create refund withdrawal, remove account | No account changes |

### User-Initiated Withdrawal

1. **Parsing**: Balance moved from `balance` to `pending_withdrawal_amount`, `has_pending_withdrawal = true`. Validator added to `removed_validators`.
2. **Processing**: `pending_withdrawal_amount` reduced, flag cleared. Account removed if both `balance` and `pending_withdrawal_amount` are zero.

### Stake Bound Violations

When `validator_min_stake` or `validator_max_stake` parameters change:
- **Below min**: Full balance withdrawn, validator removed from committee
- **Above max**: Excess withdrawn as partial withdrawal, validator remains active

### Refund Withdrawals

Refund withdrawals have `subtract_balance = false` because the deposited funds were never credited to the account. These do not set `has_pending_withdrawal` and do not block future operations.

### Invalid Withdrawal Credentials

Withdrawal credentials must be in Eth1 format: `0x01` prefix + 11 zero bytes + 20-byte Ethereum address.

If withdrawal credentials cannot be parsed:
- **New validator deposit**: Deposit is ignored, funds are lost
- **Refund withdrawal**: Refund cannot be created, funds are lost

## Withdrawal Deferral at Epoch Boundaries

Withdrawal requests for active validators received on the **last block of an epoch** are deferred to the next epoch. This ensures that `removed_validators` in the finalized header accurately reflects all validator exits, since the header is created at the penultimate block.

Deferred requests are stored in `pending_execution_requests` and processed at the start of the next epoch.

## Invariants

- A validator will join the committee `VALIDATOR_NUM_WARM_UP_EPOCHS` epochs after submitting a valid deposit request. The phase after submitting the deposit request, and before joining the committee is called the `onboarding phase`.
- If a withdrawal request is submitted in epoch `n`, then the validator will be removed from the committee at the end of epoch `n`. The withdrawal will be processed in epoch `n + VALIDATOR_WITHDRAWAL_NUM_EPOCHS`.
- There are two parameters that govern the staking amount: `validator_min_stake` and `validator_max_stake`. The balance of a validator must always be in range `[validator_min_stake, validator_max_stake]`.
- Any deposit request with resulting balance outside `[validator_min_stake, validator_max_stake]` will be rejected and refunded.
- A validator can only have one pending deposit request at a time. Subsequent deposit requests will be ignored.
- A validator can only have one pending withdrawal request at a time. Subsequent withdrawal requests will be ignored.
- A validator cannot submit a deposit request while a withdrawal request is pending, and vice versa.
- If a withdrawal request is submitted while a validator is in the onboarding phase, then the onboarding phase is aborted, and the withdrawal request will be processed `VALIDATOR_WITHDRAWAL_NUM_EPOCHS` epochs later.
- No partial withdrawals. If a withdrawal request with amount `amount < balance` is submitted, the full `balance` will be withdrawn.
- Exception: If `validator_max_stake` is lowered and a validator's balance exceeds the new maximum, the excess is withdrawn as a partial withdrawal, and the validator remains active.
- If `validator_min_stake` is raised and a validator's balance is below the new minimum, the validator is removed and the full balance is withdrawn.
