# Deposits and Withdrawals

## Deposits
- Deposits follow the EIP-6110, although the contract is slightly modified to support an additional validator key.
- Potential validators have to deposit at least **MINIMUM_STAKE** to join the network.
- If a potential validator makes an initial deposit with *amount* < **MINIMUM_STAKE**, then the validator account is still created, but it won't be set to active.
- Top-up deposits are allowed.
- A potential validator will become active **VALIDATOR_NUM_WARM_UP_EPOCHS** after depositing at least **MINIMUM_STAKE**.
- Deposit requests with invalid signatures will be refunded as a withdrawal. K% of the deposited amount will be burned. This prevents invalid deposits from becoming a DDOS vector.
- if the deposit's keys are malformed, it is refunded with the same K% burn applied to invalid signatures.
- If the deposit's consensus (BLS) key does not match the key already on the account (or is already used by another validator), the deposit is refunded in full with no burn.
- If a deposit lands for an account that no longer exists, then a new account is created.

## Withdrawals
- Withdrawals follow the EIP-7002 spec.
- Partial withdrawals are allowed.
- If a partial withdrawal would leave the validator balance below **MINIMUM_STAKE**, then the withdrawal amount is capped such that the remaining balance is exactly **MINIMUM_STAKE**.
- In order to withdraw a validator's full balance, a withdrawal request with amount=0 has to be submitted. This will initiate a validator exit.
- If a full exit is submitted in epoch E, then the validator will exit the committee at the end of epoch E. The full balance will be payed out on the last block of  epoch **E + VALIDATOR_WITHDRAWAL_NUM_EPOCHS**.
- One exception: if the withdrawal lands on the last block of epoch E, then the request is deferred until the first block of epoch E+1, therefore the validator will remain active for epoch E+1 and exit at the end of epoch E+1. The payout will happen on the last block of epoch **E + 1 + VALIDATOR_WITHDRAWAL_NUM_EPOCHS**.

## Validator Balance
- All active validators must have a balance of at least **MINIMUM_STAKE**.
- There is no upper limit on validator balance, however, there is no advantage (such as higher chance of becoming a leader) in having a balance that exceeds **MINIMUM_STAKE**.
- The **MINIMUM_STAKE** may be changed via a protocol parameter execution request.
- If **MINIMUM_STAKE** is increased during epoch E, then on the last block of epoch E, the validators with *balance* < **MINIMUM_STAKE** will be removed from the committee. The balance remains in their account and can be withdrawn at any time.
- Exception: if applying the updated **MINIMUM_STAKE** would leave fewer than **MINIMUM_VALIDATOR_COUNT** validators in the committee, then the change is rejected. The previous **MINIMUM_STAKE** remains in effect and no validators are removed.
- Joining validators with *balance* < **MINIMUM_STAKE** will have their activation canceled.
- The epoch's deposits are processed before the updated **MINIMUM_STAKE** is enforced, so a validator's balance already includes any same-epoch deposit when enforcement runs. If a top-up in the same epoch restores a validator to at least **MINIMUM_STAKE**, it stays in the committee.
- A validator still below **MINIMUM_STAKE** after its deposits are applied is removed from the committee and set to inactive. Its balance remains in the account and can be withdrawn at any time.


