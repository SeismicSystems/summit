# Observer Mode

This document describes how Summit runs a node that follows the chain without voting.

## Overview

An observer is an RPC node. It runs Summit and an execution client, follows consensus, executes every block, and serves RPC, but it never proposes or votes. Operators use observers to serve public RPC without exposing their validator.

Observers exist inside the protocol. Summit's P2P network only admits keys that consensus has authorized, so a node outside the validator set can only connect if the protocol names it. Each validator implicitly authorizes a fixed number of observer identities, derived from its own node key.

## Running an Observer

```bash
summit run --observer <N> --key-store-path <dir> ...
```

`N` is a derivation index, `0 ≤ N < observers_per_validator`. The keystore holds two files:

| File | Content | Used by an observer |
|------|---------|---------------------|
| `node_key.pem` | The **validator's** Ed25519 node key | Yes: the observer derives its P2P identity from it |
| `consensus_key.pem` | A BLS key | No: an observer only verifies certificates |

The keystore format requires both files. The intended setup, which the `observer` e2e binary follows ([`node/src/bin/observer.rs`](../node/src/bin/observer.rs)), copies only the validator's `node_key.pem` and writes a fresh BLS key that is not in the validator set. Nothing enforces this: an observer given its validator's `consensus_key.pem` would ignore it, but would hold it.

In observer mode, the node:

- derives its identity with `ExtPrivateKey::derive_child_signer(&key_store.node_key, namespace, N)` ([`node/src/args.rs`](../node/src/args.rs)), where `namespace` is the chain-bound P2P domain;
- runs the consensus engine with a verifier-only signing scheme (`force_verifier_only`), so it can check certificates but never signs;
- refuses the admin RPC's deposit signing (`RpcError::DisabledInObserverMode`).

## Identity Derivation

Observer keys are derived additively from the validator's Ed25519 key ([`types/src/ext_private_key.rs`](../types/src/ext_private_key.rs)):

```
t           = H(DERIVE_TAG ‖ master_pub ‖ len(namespace) ‖ namespace ‖ "m/seismic/observer/<N>")
child_sk    = master_sk + t
child_pub   = master_pub + t·G
```

Every term in `t` is public, which gives two properties:

- **Anyone can compute an observer's public key** from the validator's public key and the index (`derive_child_public`). This is how every node knows which observer keys to admit without any registration.
- **An observer's private key reveals its validator's.** `master_sk = child_sk − t`. An observer therefore holds the validator's node key in effect, whatever file it was given. This is the node key only (P2P identity and deposit signing), not the BLS key that votes.

## Peer Sets

At each epoch the finalizer registers the next peer set with the P2P oracle ([`finalizer/src/actor.rs`](../finalizer/src/actor.rs)):

- **Primary**: active validators.
- **Secondary**: joining validators, plus the first `observers_per_validator` observer keys of every active or joining validator (`derive_observer_keys`).

Commonware's authenticated P2P only reserves a connection for a key in a tracked peer set, and keeps at most one connection per key. Secondary peers receive the network's data: in Commonware's terms, mechanisms "continue to replicate data to secondary peers (often both gossiping data to them and answering requests from them)." An observer therefore gets blocks and certificates from every validator, and backfills from any of them through the P2P resolver.

`observers_per_validator` is a protocol parameter: set in genesis (default 16, at most 256) and changeable by an `ObserversPerValidator` execution request. It sizes every node's P2P capacity: see [Deposits and Withdrawals](./deposits-and-withdrawals.md) for the formula, which gives 2,177 identities per peer set at the defaults. Authorized observer identities count against it whether or not they are online.

## What an Observer Executes

An observer runs the same finalizer as a validator. The finalizer executes notarized blocks before they finalize (`handle_notarized_block`): on a fork it moves the execution client's head to the notarized block while `safe` and `finalized` stay at the last finalized block. RPC reads against `latest` on an observer can therefore return state from a block that is later abandoned.

## Possible Improvements

- **Observers need only the node key.** The keystore format makes an observer load a BLS key it never uses. Loading only `node_key.pem` in observer mode would remove the BLS file from an observer's setup, and with it the chance that an observer is given its validator's `consensus_key.pem`.
