# Running local network

Easiest way to run a network locally is to use the testnet bin. This will start 4 summit nodes and 4 reth nodes locally and start coming to consensus on a fresh network.

## Prerequisites

1. Make sure you have a `reth` binary installed and in your `PATH` (or point the `SRETH_BIN` env var at a specific binary). The testnet bin passes Seismic-specific flags (e.g. `--seismic.purpose-keys-source`) to the execution client, so a vanilla upstream `reth` will not work - build `seismic-reth`:
   ```bash
   git clone https://github.com/SeismicSystems/seismic-reth.git && cd seismic-reth && cargo build --release
   ```
   Then move the built binary somewhere in your path under the name `reth`:
   ```bash
   mv target/release/seismic-reth ~/.cargo/bin/reth
   ```

## Starting the network

From the repo root:

```bash
cargo run --bin testnet
```

This starts 4 Summit nodes and 4 Reth nodes in that terminal. Each node uses the pregenerated keys in `testnet/node0` .. `testnet/node3`.

Useful flags:

- `--nodes <N>` - number of nodes to run (default: 4)
- `--only-reth` - start only the reth instances, without consensus
- `--log-dir <PATH>` - write per-node logs to a directory
- `--critical-log-dir <PATH>` - write critical error logs to a directory

## Ports

Reth RPC endpoints count **down** from 8545 (`localhost:8545 - node_number`):

| Node | Reth HTTP RPC | Summit RPC | Summit admin RPC | Consensus P2P | Prometheus |
| ---- | ------------- | ---------- | ---------------- | ------------- | ---------- |
| node0 | 8545 | 3030 | 3031 | 26600 | 28600 |
| node1 | 8544 | 3040 | 3041 | 26610 | 28610 |
| node2 | 8543 | 3050 | 3051 | 26620 | 28620 |
| node3 | 8542 | 3060 | 3061 | 26630 | 28630 |

The exact Reth RPC address for each node is also printed on startup (`Node <N> rpc address: ...`).

Quick check that blocks are being produced:

```bash
curl -s -X POST localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Transactions can be submitted through any of the Reth RPC endpoints as usual.

## Resetting

To reset the local testnet data and start fresh, run this from the repo root:

```bash
cd testnet && ./reset.sh && cd ..
```

This removes `node*/data/reth_db`, `node*/db`, and `./stores`. Keys in `testnet/node*` are kept, so the same genesis works after a reset.

## Troubleshooting

- **`reth` not found / immediately exits** - the binary in `PATH` must be `seismic-reth` renamed to `reth`; upstream reth does not understand the Seismic enclave flags.
- **Nodes fail to come to consensus after a previous run** - stale state; run `testnet/reset.sh` and start again.
- **Port already in use** - a previous run did not shut down cleanly; kill leftover `reth`/`testnet` processes before restarting.

---

## Running distributed

To run a fresh network on multiple systems you should install Summit on each server and then run `cargo run --bin summit -- keys generate` and `cargo run --bin summit -- keys show` to get the keys for each node.

You will then recreate the example_genesis.toml file to have the keys and IPs of all your nodes.

After the genesis file is in place you would start your `reth`/`seismic-reth` instance and then start Summit on each host with the matching genesis configuration.
