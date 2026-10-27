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

`summit run` also serves `getDepositSignature` on its admin RPC (`127.0.0.1:--admin-rpc-port`, default 3031). By default, it signs deposit data for whatever address a request carries. With `--withdrawal-address-path <file>`, the node binds one withdrawal address for good and signs for no other:

```bash
summit run ... --withdrawal-address-path /path/to/withdrawal/address
```

- **First use binds.** The first `getDepositSignature` writes its address to the file, and every later request must carry the same address. A request for any other address is refused with error `4004`, which names the bound address, and nothing is signed.
- **Founders are bound at startup.** If this node's key is a genesis validator, summit writes that validator's genesis address to the file at startup, before the RPC serves any request. If the file already exists, it must hold that address, or startup fails.
- **Enabling on an existing validator.** The node binds whatever address its first request carries, without checking the validator's account. Make that request carry the account's withdrawal address, or the node is bound to an address that only ever receives refunds of rejected top-ups.
- **Write-once.** The file holds the EIP-55-checksummed address and a newline, and it is never rewritten. To change the address, reset the node with new keys. Keep the file outside the consensus DB directory, so a resync that wipes the DB keeps the binding.
- **Strict addresses.** With the flag set, a request's address must be in its EIP-55 checksummed form (`cast to-check-sum-address` converts one), and the zero address is refused. Anything else is refused with error `3008`, and nothing is bound.
- **Fails closed.** The file's directory must exist. A missing directory, or an unreadable or malformed file, stops startup instead of leaving the node unbound.

`getWithdrawalAddress` on the same listener returns the bound address, or `null` if nothing is bound or the flag is unset. The flag cannot be combined with `--observer`, since observers do not sign deposits, and `summit deposit-rpc` does not support it.

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
