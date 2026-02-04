# Staking and Participating

Summit is a Proof of Stake (PoS) consensus client. In order to participate in the network, a node needs to stake. We leverage a slightly modified version of the Ethereum deposit contract.

## Staking Contract

The staking contract is almost the same as Ethereum's. The source code of the modified version is available [here](https://github.com/SeismicSystems/seismic-contracts/blob/main/src/seismic-std-lib/DepositContract.sol).

The changes were made to accommodate every consensus node having 2 keys to participate instead of 1 like on Ethereum. A node needs a BLS12-381 key that is used for signing consensus messages, as well as an ED25519 key that is used for authenticated networking messages and is much faster to verify. The changes add these keys to the deposit function and the deposit event. Other than that, our validator deposit flow is exactly as it is in Ethereum. For more information on how that works, see the [Beacon Chain deposit process documentation](https://docs.beaconcha.in/faqs/deposit-process).

## Becoming a Validator

1. Deploy the Summit image on a TDX VM. This will start seismic-reth and Summit as well as the enclave.
2. The deposit function requires a signature with the node's keys. Since they are only available from within the secure enclave, an RPC endpoint is exposed to receive the signed calldata that includes the signature from the node at default port 3030:
   ```
   /get_deposit_signature?amount=32000000000&address=0x0000000000000000000000000000000000000000
   ```
   The `amount` should be the staking amount and `address` should be your Ethereum address you want to be able to withdraw to.
3. Send a signed transaction to the deposit contract with the calldata from the previous step, along with a value equal to the amount being staked (contract address: `0x00000000219ab540356cBB839Cbe05303d7705Fa`, same as Ethereum).
4. Download the latest checkpoint and load it into the node.
5. Keep your node running and it will start participating in the next epoch.

## How Summit Handles Deposits

When the deposit contract is used to stake, the execution layer burns the native token and the balance is accounted for in the consensus layer (Summit). When the deposit contract is used, the event that is emitted is added to the block's `execution_requests` field. While processing blocks, the finalizer watches for these execution requests and updates its own state accordingly. After a warm-up period of 2 epochs, the node will be added to the participating validator set. This is deterministic and all honest nodes will add validators at the same time and reject blocks that do not include the proper additions based on the execution requests from previous blocks.

## Withdrawing

Withdrawing deposited funds is in accordance with [EIP-7002](https://eips.ethereum.org/EIPS/eip-7002).

To submit a withdrawal request, a validator must send a transaction to the pre-deployed withdrawal contract. As defined in EIP-7002, the calldata for this transaction is 56 bytes:
- 48 bytes for the validator pubkey
- 8 bytes big-endian uint64 for the amount

Note that the validator pubkey is the ED25519 key (left-padded with zeros), not the BLS key.

When depositing funds into the staking contract (see above), an Ethereum address was specified (`withdrawal_credentials`). A valid withdrawal transaction must be signed by the private key associated with this Ethereum address.

For detailed invariants and internal state management, see [deposits-and-withdrawals.md](deposits-and-withdrawals.md).
