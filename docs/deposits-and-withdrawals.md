# Deposits and Withdrawals

## Deposits
- Deposits follow the EIP-6110, although the contract is slightly modified to support an additional validator key.
- Potential validators have to deposit at least **MINIMUM_STAKE** to join the network.
- If a potential validator makes an initial deposit with *amount* < **MINIMUM_STAKE**, then the validator account is still created, but it won't be set to active.
- Top-up deposits are allowed.
- Once a processed deposit brings an inactive validator's balance to at least **MINIMUM_STAKE**, activation is scheduled **VALIDATOR_NUM_WARM_UP_EPOCHS** later. Deposit processing occurs near epoch end and is subject to **MAX_DEPOSITS_PER_EPOCH**, so activation may be delayed from submission.
- Deposit requests with invalid signatures will be refunded as a withdrawal. K% of the deposited amount (**INVALID_DEPOSIT_TAX**, default 5%) is sent to the treasury address (the zero address by default, which effectively burns it). This prevents invalid deposits from becoming a DDOS vector.
- if the deposit's keys are malformed, it is refunded with the same K% tax applied to invalid signatures.
- If the deposit's consensus (BLS) key does not match the key already on the account (or is already used by another validator), the deposit is refunded with the same K% tax applied to invalid signatures.
- If a deposit lands for an account that no longer exists, then a new account is created.

## Withdrawals
- Withdrawals follow the EIP-7002 spec.
- A withdrawal is accepted only when its source address matches the validator's withdrawal credentials and the validator has not reached **MAX_PENDING_WITHDRAWALS_PER_VALIDATOR**.
- Partial withdrawals are allowed. Active validators retain at least **MINIMUM_STAKE**. Inactive validators have no minimum balance floor, and a withdrawal from a joining validator first cancels its activation.
- For an active validator, amount=0 requests a full exit. The request is rejected if the exit would leave fewer than **MINIMUM_VALIDATOR_COUNT** active validators.
- An accepted full exit processed in epoch E removes the validator at the end of E and schedules its payout for epoch **E + VALIDATOR_WITHDRAWAL_NUM_EPOCHS**. **MAX_WITHDRAWALS_PER_EPOCH** may delay the payout.
- Multiple partial withdrawals may be pending, up to **MAX_PENDING_WITHDRAWALS_PER_VALIDATOR**. At payout, each partial withdrawal is capped again using the current balance and prospective **MINIMUM_STAKE**.
- **MAX_WITHDRAWALS_PER_EPOCH** is a total payout cap. Validator withdrawals take priority over deposit refunds, and overflow remains queued for a later epoch.
- An invalid deposit may create separate refund and treasury withdrawals. Each withdrawal consumes one slot under the payout cap.
- Requests included in the last block of epoch E remain buffered until the penultimate block of E+1. An accepted exit then occurs at the end of E+1, with payout scheduled for epoch **E + 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS**, subject to the withdrawal cap.

## Validator Balance
- All active validators must have a balance of at least **MINIMUM_STAKE**.
- There is no upper limit on validator balance, however, there is no advantage (such as higher chance of becoming a leader) in having a balance that exceeds **MINIMUM_STAKE**.
- The **MINIMUM_STAKE** may be changed via a protocol parameter execution request.
- If **MINIMUM_STAKE** is increased during epoch E, then on the last block of epoch E, the validators with *balance* < **MINIMUM_STAKE** will be removed from the committee. The balance remains in their account and can be withdrawn at any time.
- Exception: if applying the updated **MINIMUM_STAKE** would leave fewer than **MINIMUM_VALIDATOR_COUNT** validators in the committee, then the change is rejected. The previous **MINIMUM_STAKE** remains in effect and no validators are removed.
- Joining validators with *balance* < **MINIMUM_STAKE** will have their activation canceled.
- The epoch's deposits are processed before the updated **MINIMUM_STAKE** is enforced, so a validator's balance already includes any same-epoch deposit when enforcement runs. If a top-up in the same epoch restores a validator to at least **MINIMUM_STAKE**, it stays in the committee.
- A validator still below **MINIMUM_STAKE** after its deposits are applied is removed from the committee and set to inactive. Its balance remains in the account and can be withdrawn at any time.


