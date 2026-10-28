# Staking and Participating

Summit is a Proof of Stake (PoS) consensus client. In order to participate in the network, a node needs to stake. We leverage a slightly modified version of the Ethereum deposit contract.

## Staking Contract

The staking contract is almost the same as Ethereum's. The source code of the modified version is available [here](https://github.com/SeismicSystems/seismic-contracts/blob/main/src/seismic-std-lib/DepositContract.sol).

The changes were made to accommodate every consensus node having 2 keys to participate instead of 1 like on Ethereum. A node needs a BLS12-381 key that is used for signing consensus messages, as well as an ED25519 key that is used for authenticated networking messages and is much faster to verify. The changes add these keys to the deposit function and the deposit event. Other than that, our validator deposit flow is exactly as it is in Ethereum. For more information on how that works, see the [Beacon Chain deposit process documentation](https://docs.beaconcha.in/faqs/deposit-process).

## Becoming a Validator

1. Provision the Summit validator keys and the network's genesis file on the TDX VM.
2. Start only the localhost deposit-signature RPC server. This does not start the execution client, P2P, consensus, storage, or syncing:
   ```bash
   summit deposit-rpc \
     --genesis-path /path/to/genesis.toml \
     --key-store-path /path/to/keys \
     --port 3031
   ```
3. From a local process on the VM, request the signed deposit data from `127.0.0.1:3031`:
   ```bash
   curl http://127.0.0.1:3031 \
     -H 'Content-Type: application/json' \
     --data '{
       "jsonrpc": "2.0",
       "method": "getDepositSignature",
       "params": [32000000000, "0xYourWithdrawalAddressHere"],
       "id": 1
     }'
   ```
   The `amount` should be the staking amount and `address` should be the Ethereum address you want to be able to withdraw to. **Replace the `address` placeholder with an address you actually control** — withdrawals and exits are only honored from the exact address bound at deposit time, so a stake deposited against an address you cannot sign for is permanently unrecoverable.
4. Stop `summit deposit-rpc`, then send a signed transaction to the deposit contract using the returned deposit data, along with a value equal to the amount being staked (contract address: `0x00000000219ab540356cBB839Cbe05303d7705Fa`, same as Ethereum).
5. Download the latest checkpoint and start the full node with `summit run`.
6. Keep your node running and it will start participating after the validator warm-up period.

## Topping Up

To add to a validator's stake, request deposit data for the top-up amount from the running node's admin RPC (`getDepositSignature` on `127.0.0.1:--admin-rpc-port`), then send it to the deposit contract as in step 4. Every deposit needs its own signature, since the signed message covers the amount.

The account's withdrawal address is fixed by its first deposit, or by genesis for a founder. A top-up doesn't change it, and the address a top-up carries is otherwise ignored, with one exception: a rejected top-up (for example, one whose BLS key doesn't match the account's) is refunded, less the invalid-deposit tax, to the top-up's own address. So top up with the account's withdrawal address. A node running with `--withdrawal-address-path` signs only for its bound address (see below).

## Binding the Withdrawal Address

By default, `getDepositSignature` signs deposit data for whatever address the request carries. With `summit run --withdrawal-address-path <file>`, the node signs for one address only, fixed by its first request (or by genesis for a founder) and never changed. Requests for any other address are refused with error `4004`. `getWithdrawalAddress` returns the bound address.

Note that the node binds the address only; the key is kept in custody of the operator. The node signs deposit data with its validator keys, and anyone can submit that data from any wallet.

**Why.** The first deposit for a validator fixes its withdrawal address for good. Without the binding, anyone who can reach the admin RPC can get deposit data for their own address and deposit first. The operator's own deposit then lands as a top-up on the attacker's account. That's fine when the operator controls every caller of the admin RPC, as on a host they run themselves. On a TEE node, the host is untrusted and controls the guest's network, and other guest processes share its loopback, so firewalls can't keep everyone else out. The binding makes the node itself refuse. If someone else binds first, the operator's request is refused before they fund anything, and they reset the node with new keys. Losing the race costs a reset, never stake.

To change the bound address, reset the node with new keys. Keep the file outside the consensus DB directory, so a resync keeps it. When enabling the flag on an existing validator, make the first request carry the account's withdrawal address.

## How Summit Handles Deposits

When the deposit contract is used to stake, the execution layer burns the native token and the balance is accounted for in the consensus layer (Summit). When the deposit contract is used, the event that is emitted is added to the block's `execution_requests` field. While processing blocks, the finalizer watches for these execution requests and updates its own state accordingly. After a warm-up period of 2 epochs, the node will be added to the participating validator set. This is deterministic and all honest nodes will add validators at the same time and reject blocks that do not include the proper additions based on the execution requests from previous blocks.

## Withdrawing

Withdrawing deposited funds is in accordance with [EIP-7002](https://eips.ethereum.org/EIPS/eip-7002).

To submit a withdrawal request, a validator must send a transaction to the pre-deployed withdrawal contract. As defined in EIP-7002, the calldata for this transaction is 56 bytes:
- 48 bytes for the validator pubkey
- 8 bytes big-endian uint64 for the amount

Note that the validator pubkey is the ED25519 key (left-padded with zeros), not the BLS key.

The big-endian amount above applies only to the calldata you submit to the contract. Per EIP-7002, the predeploy re-encodes the amount to **little-endian** in the `request_data` it emits (`source_address(20) ++ validator_pubkey(48) ++ amount(8)`, 76 bytes), and that little-endian form is what Summit's consensus layer parses. The numeric value is preserved end-to-end; only the encoding differs between the two layers.

When depositing funds into the staking contract (see above), an Ethereum address was specified (`withdrawal_credentials`). A valid withdrawal transaction must be signed by the private key associated with this Ethereum address.

For detailed invariants and internal state management, see [deposits-and-withdrawals.md](deposits-and-withdrawals.md).
