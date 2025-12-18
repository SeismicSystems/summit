# Staking and participating
Summit is a PoS(Proof of Stake) consensus client. In order to participate in the network a node needs to stake. We leverage a slightly modified version of the ethereum deposit contract.

## Staking Contract
The staking contract is almost the same as ethereum's and the source code of the modified version is available here (https://github.com/SeismicSystems/seismic-contracts/blob/main/src/seismic-std-lib/DepositContract.sol)

The changes that were made were only to accommodate every consensus node needing 2 keys to participate instead of the 1 like on ethereum. A node needs a BL 12-381 key that is aggregeted with other consensus nodes as well as a ED25519 key that is used for authenticated networking messages and is much faster verify. The changes add these keys to the deposit function and as well as to the deposit event. Other than that our validator deposit flow is exactly as it is in Ethereum and for more information on how that works see (https://docs.beaconcha.in/faqs/deposit-process)

## Becoming a validator E2E

1. Deploy the Summit image on TDX VM. This will start seismic-reth and Summit as well as enclave
2. The deposit function requires a signature with the node's keys, and they are only available from within the secure enclave, an rpc endpoint is exposed to received the signed calldata that includes the signature from the node at default port 3030 `/get_deposit_signature?amount=32000000000&address=0x0000000000000000000000000000000000000000` Amount should be the staking amount and address should be your ethereum address you want to be able to withdrawl too. 
3. Send a signed transaction into the network to the deposit contract with the calldata from the previous step along with a value == to the amount needing to be staked(0x00000000219ab540356cBB839Cbe05303d7705Fa same as ethereum)
4. Download the latest checkpoint and load it into the node: WIP
5. Keep your node running and it will start participating in the next epoch

A staking UI that is hosted by the node will be available soon to simplify these steps


## How Summit handles this
When the deposit contract is used to stake the execution layer actually burns the native token and then the balance is accounted for in the consensus layer(Summit). When the deposit contract is used the event that is emmitted is added to the blocks execution_requests field. While proccessing blocks in the finalizer Summit watches for these execution requests (https://github.com/SeismicSystems/summit/blob/main/finalizer/src/actor.rs#L304) and updates its own state accordingly (https://github.com/SeismicSystems/summit/blob/main/finalizer/src/actor.rs#L315). The node will then be added to the participating validator set starting on the next Epoch. This is deterministic and all honest nodes will add validators at the same time and reject blocks that do not include the proper additions based on the execution_requests from the previous blocks.

This section is a WIP


## Withdrawing
Withdrawing deposited funds is in accordance with [EIP-7002](https://eips.ethereum.org/EIPS/eip-7002).
To submit a withdrawal request, a validator must send a transaction to the pre-deployed withdrawal contract.
As defined in EIP-7002, the calldata for this transaction is 56 bytes
- 48 bytes for the validator pubkey
- 8 bytes big-endian uint64 for the amount
Note that the validator pubkey is the ED25519 key (left-padded with zeros), and not the BLS key.
When depositing funds into the staking contract (see above), an Ethereum address was specified (withdrawal_credentials).
A valid withdrawal transaction has to be signed by the private key associated with this Ethereum address.

## Invariants
- A validator will join the committee `VALIDATOR_NUM_WARM_UP_EPOCHS` epochs after submitting a valid deposit request. The phase after submitting the deposit request, and before joining the committee is called the `onboarding phase`.
- If a withdrawal request is submitted in epoch `n`, then the validator will be removed from the committee at the end of epoch `n`. The withdrawal will be processed in epoch `n + VALIDATOR_WITHDRAWAL_NUM_EPOCHS`.
- A validator can only submit one withdrawal request at a time. If another withdrawal request is submitted, while a withdrawal request is pending, then the second withdrawal request will be ignored.
- If a withdrawal request is submitted while a validator is in the onboarding phase, then the onboarding phase is aborted, and the withdrawal request will be processed `VALIDATOR_WITHDRAWAL_NUM_EPOCHS` epochs later.
- No partial withdrawals. If the validator balance is `balance`, and a withdrawal request with amount `amount < balance` is submitted, then the withdrawal request will be processed for the amount of `balance`.
- A validator can only have a balance of `VALIDATOR_MINIMUM_STAKE`. If a deposit request with `amount` is submitted, where `amount != VALIDATOR_MINIMUM_STAKE`, then the deposit request will be skipped, and a withdrawal request will be initiated immediately.
- No top up deposits. If a validator already has a balance of `VALIDATOR_MINIMUM_STAKE`, then it cannot submit another deposit request with amount `VALIDATOR_MINIMUM_STAKE`.