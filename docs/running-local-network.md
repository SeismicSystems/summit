# Running local network

Easiest way to run a network locally is to use the testnet bin. This will start 4 summit nodes and 4 reth nodes locally and start coming to consensus on a fresh network.

## Steps to do this:

1. First make sure you have a `reth` binary installed and in your `PATH`. For Seismic development, that typically means building `seismic-reth` and placing the resulting binary in your path as `reth`.
   ```bash
   git clone https://github.com/SeismicSystems/seismic-reth.git && cd seismic-reth && cargo build --release
   ```
   - Move the built binary somewhere in your path under the name `reth`
   ```bash
   mv target/release/seismic-reth ~/.cargo/bin/reth
   ```

2. Then `cd` into this repo and run `cargo run --bin testnet` at the repo root. This will start 4 Summit nodes and 4 Reth nodes in that terminal.

3. You can reach the Reth RPC endpoints on the ports printed by the testnet binary. By default they are `localhost:8545`, `localhost:8546`, `localhost:8547`, and `localhost:8548`.

4. To reset the local testnet data and start fresh, run this from the repo root:
   ```bash
   cd testnet && ./reset.sh && cd ..
   ```

---

## Running distributed

To run a fresh network on multiple systems you should install Summit on each server and then run `cargo run -- keys generate` and `cargo run -- keys show` to get the keys for each node.

You will then recreate the example_genesis.toml file to have the keys and IPs of all your nodes.

After the genesis file is in place you would start your `reth`/`seismic-reth` instance and then start Summit on each host with the matching genesis configuration.
