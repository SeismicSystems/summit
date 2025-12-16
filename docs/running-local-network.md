# Running local network

Easiest way to run a network locally is to use the testnet bin. This will start 4 summit nodes and 4 reth nodes locally and start coming to consensus on a fresh network.

## Steps to do this:

1. First make sure you have seismic-reth installed and in your PATH
   ```bash
   git clone https://github.com/SeismicSystems/seismic-reth.git && cd seismic-reth && cargo build --release
   ```
   - move the seismic bin somewhere in your path under the name reth
   ```bash
   mv target/release/seismic-reth ~/.cargo/bin/reth
   ```

2. Then run cd into this repo and run `cargo run --bin testnet` at root of this repo. This will start 4 nodes in that terminal

3. You can reach the reth rpc at localhost:8545 (ports for the other 3 nodes ar 8546, 8547, 8548)

4. To start the network fresh run this from the root of this repo
   ```bash
   cd testnet && ./reset.sh && cd ..
   ```

---

## Running distributed

To run a fresh network on multiple systems you should install summit on each server and then run `cargo run -- keys generate && cargo run -- keys show` to get the keys for each node.

You will then recreate the example_genesis.toml file to have the keys and ips of all your nodes.

After the genesis file is in place you would just start seismic-reth with the `--mock-enclave` flag and then start summit on each and the network should start
