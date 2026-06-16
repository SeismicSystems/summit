use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, Bytes, U256, address, keccak256};
use clap::Parser;
use commonware_runtime::{Clock, Runner as _, Spawner as _, tokio as cw_tokio};
use futures::{FutureExt, pin_mut};
use jsonrpsee::http_client::HttpClientBuilder;
use std::collections::VecDeque;
use std::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    path::PathBuf,
    str::FromStr as _,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit_rpc::{SummitApiClient, SummitProofApiClient};
use summit_types::genesis::Genesis;
use summit_types::reth::Reth;

use tokio::sync::mpsc;
use tracing::Level;

/// Compiled bytecode of SszProofVerifier.sol (solc --via-ir --optimize --bin).
/// Uses generalized indices for unified scalar + collection proof verification.
const SSZ_VERIFIER_BYTECODE: &str = "6080806040523460155761037e908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c63808506aa14610025575f80fd5b3461026b57608036600319011261026b576064359067ffffffffffffffff821161026b573660238301121561026b5781600401359067ffffffffffffffff821161026b576024830192602436918460051b01011161026b575f816020829301906004358252602081526100996040826102db565b5190720f3df6d732807ef1319fb7b8bb8522d0beac025afa3d156102d3573d9067ffffffffffffffff82116102bf57604051916100e0601f8201601f1916602001846102db565b82523d5f602084013e5b806102b4575b1561026f5760208180518101031261026b57602001519060443590602435905f90855b8183106101a75750505060010361016a57810361013557602090604051908152f35b60405162461bcd60e51b815260206004820152600d60248201526c1c1c9bdbd9881a5b9d985b1a59609a1b6044820152606490fd5b60405162461bcd60e51b81526020600482015260156024820152740e0e4dedecc40d8cadccee8d040dad2e6dac2e8c6d605b1b6044820152606490fd5b909192935f6020916001871615821461021b576101c58686866102fd565b35604051908482019283526040820152604081526101e46060826102db565b604051918291518091835e8101838152039060025afa156102105760015f51945b811c93019190610113565b6040513d5f823e3d90fd5b6102268686866102fd565b3590604051908482019283526040820152604081526102466060826102db565b604051918291518091835e8101838152039060025afa156102105760015f5194610205565b5f80fd5b60405162461bcd60e51b815260206004820152601960248201527f626561636f6e20726f6f74206c6f6f6b7570206661696c6564000000000000006044820152606490fd5b5060208151146100f0565b634e487b7160e01b5f52604160045260245ffd5b6060906100ea565b90601f8019910116810190811067ffffffffffffffff8211176102bf57604052565b919081101561030d5760051b0190565b634e487b7160e01b5f52603260045260245ffdfea2646970667358221220a4d0024cbbc25325fd29ae0046edae7ae6f3d95a502a527fc40cb683aa640bad64736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3464313362633133005a";

/// Genesis validator 0 node public key (from example_genesis.toml).
const VALIDATOR0_PUBKEY_HEX: &str =
    "1be3cb06d7cc347602421fb73838534e4b54934e28959de98906d120d0799ef2";

const NUM_NODES: u16 = 4;
const GENESIS_PATH: &str = "./example_genesis.toml";
const E2E_BLOCKS_PER_EPOCH: u64 = 50;

/// EIP-4788 beacon roots contract address.
const BEACON_ROOTS_ADDRESS: Address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

struct NodeRuntime {
    thread: JoinHandle<()>,
    stop_tx: mpsc::UnboundedSender<()>,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    pub log_dir: Option<String>,
    #[arg(long, default_value = "/tmp/summit_ssz_proof_test")]
    pub data_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Clean slate
    let data_dir_path = PathBuf::from(&args.data_dir);
    if data_dir_path.exists() {
        fs::remove_dir_all(&data_dir_path)?;
    }
    if let Some(ref log_dir) = args.log_dir {
        let _ = fs::remove_dir_all(log_dir);
        fs::create_dir_all(log_dir)?;
    }

    let storage_dir = data_dir_path.join("stores");
    let cfg = cw_tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(16)
        .with_storage_directory(storage_dir)
        .with_catch_panics(false);
    let executor = cw_tokio::Runner::new(cfg);

    let mut genesis = Genesis::load_from_file(GENESIS_PATH).expect("Failed to load genesis file");
    genesis.blocks_per_epoch = E2E_BLOCKS_PER_EPOCH;

    // Write modified genesis for nodes to use
    fs::create_dir_all(&data_dir_path).expect("Failed to create data directory");
    let e2e_genesis_path = data_dir_path.join("genesis.toml");
    let genesis_str = toml::to_string_pretty(&genesis).expect("Failed to serialize genesis");
    fs::write(&e2e_genesis_path, genesis_str).expect("Failed to write e2e genesis");
    let e2e_genesis_path_str = e2e_genesis_path.to_str().unwrap().to_string();

    let node_runtimes = executor.start(|context| {
        async move {
            let _critical_log_guard = summit::telemetry::init(Level::INFO, None);

            let mut handles = VecDeque::new();
            let mut node_runtimes: Vec<NodeRuntime> = Vec::new();

            // ---------------------------------------------------------------
            // Start 4 Reth + 4 Summit nodes
            // ---------------------------------------------------------------
            println!("Starting testnet...");
            for x in 0..NUM_NODES {
                println!("******* STARTING RETH FOR NODE {x}");
                let data_dir = format!("{}/node{}/data/reth_db", args.data_dir, x);
                fs::create_dir_all(&data_dir).expect("Failed to create data directory");

                let reth_builder = Reth::new()
                    .instance(x + 1)
                    .keep_stdout()
                    .data_dir(data_dir)
                    .arg("--enclave.mock-server")
                    .arg("--enclave.endpoint-port")
                    .arg(format!("1744{x}"))
                    .arg("--auth-ipc")
                    .arg("--auth-ipc.path")
                    .arg(format!("/tmp/reth_engine_api{x}.ipc"))
                    .arg("--metrics")
                    .arg(format!("0.0.0.0:{}", 9001 + x));

                let mut reth = reth_builder.spawn();
                let stdout = reth.stdout().expect("Failed to get stdout");

                let log_dir = args.log_dir.clone();
                context.clone().spawn(async move |_| {
                    let reader = BufReader::new(stdout);
                    let mut log_file = log_dir.as_ref().map(|dir| {
                        fs::File::create(format!("{}/node{}.log", dir, x))
                            .expect("Failed to create log file")
                    });
                    for line in reader.lines().map_while(Result::ok) {
                        if let Some(ref mut file) = log_file {
                            writeln!(file, "[Node {}] {}", x, line)
                                .expect("Failed to write to log file");
                        }
                    }
                });

                println!("Node {} rpc address: {}", x, reth.http_port());
                handles.push_back(reth);

                let flags = get_node_flags(x.into(), &e2e_genesis_path_str);
                let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
                let data_dir_clone = args.data_dir.clone();
                let thread = std::thread::spawn(move || {
                    let storage_dir =
                        PathBuf::from(&data_dir_clone).join("stores").join(format!("node{}", x));
                    let cfg = cw_tokio::Config::default()
                        .with_tcp_nodelay(Some(true))
                        .with_worker_threads(4)
                        .with_storage_directory(storage_dir)
                        .with_catch_panics(true);
                    let executor = cw_tokio::Runner::new(cfg);
                    executor.start(|node_context| async move {
                        let node_handle = node_context.clone().spawn(|ctx| async move {
                            run_node_local(ctx, flags, None, None).await.unwrap();
                        });
                        let stop_fut = stop_rx.recv().fuse();
                        pin_mut!(stop_fut);
                        futures::select! {
                            _ = stop_fut => {
                                println!("Node {} received stop signal, shutting down runtime...", x);
                                node_context.stop(0, Some(Duration::from_secs(30))).await.unwrap();
                            }
                            _ = node_handle.fuse() => {
                                println!("Node {} handle completed", x);
                            }
                        }
                    });
                });
                node_runtimes.push(NodeRuntime { thread, stop_tx });
            }

            context.sleep(Duration::from_secs(5)).await;

            // ---------------------------------------------------------------
            // Wait for state
            // ---------------------------------------------------------------
            println!("Waiting for state...");
            let summit_rpc_port = get_node_flags(0, &e2e_genesis_path_str).rpc_port;
            loop {
                match get_latest_height(summit_rpc_port).await {
                    Ok(h) if h > 0 => {
                        println!("Summit node 0 at height {h}");
                        break;
                    }
                    Ok(h) => println!("Summit height: {h}, waiting..."),
                    Err(e) => println!("Waiting for Summit RPC... ({e})"),
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // Give the network a few more blocks so the proof trie has been captured
            context.sleep(Duration::from_secs(5)).await;

            // ---------------------------------------------------------------
            // Query getStateProof(["epoch", "latest_height"])
            // ---------------------------------------------------------------
            println!("Querying getStateProof([\"epoch\", \"latest_height\"])...");
            let summit_url = format!("http://localhost:{}", summit_rpc_port);
            let summit_client = HttpClientBuilder::default().build(&summit_url).unwrap();
            let proof_resp = summit_client
                .get_state_proof(vec!["epoch".into(), "latest_height".into()])
                .await
                .expect("getStateProof failed");

            println!("  root: 0x{}", alloy::hex::encode(proof_resp.root));
            println!("  el_block_number: {}", proof_resp.el_block_number);
            println!("  results returned: {}", proof_resp.results.len());
            for (i, result) in proof_resp.results.iter().enumerate() {
                match &result.proof {
                    Some(proof) => println!(
                        "  result[{i}] {}: gindex={}, leaf=0x{}, branch_len={}",
                        result.key,
                        proof.gindex,
                        alloy::hex::encode(proof.leaf),
                        proof.branch.len()
                    ),
                    None => println!(
                        "  result[{i}] {}: missing ({})",
                        result.key,
                        result.error.as_deref().unwrap_or("unknown error")
                    ),
                }
            }

            // Build alloy provider with a funded wallet (for contract deploy)
            let node0_http_port = handles[0].http_port();
            let node0_url = format!("http://localhost:{}", node0_http_port);
            let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer = PrivateKeySigner::from_str(private_key).expect("Failed to create signer");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(node0_url.parse().expect("Invalid URL"));

            // ---------------------------------------------------------------
            // TEST A: Beacon root contract
            // ---------------------------------------------------------------
            println!("\nTEST A: Beacon root contract query");
            let target_block = proof_resp.el_block_number + 1;
            // Wait for the target block to exist
            loop {
                match provider.get_block_number().await {
                    Ok(n) if n >= target_block => break,
                    Ok(n) => println!("  Reth at block {n}, waiting for {target_block}..."),
                    Err(e) => println!("  Reth not ready: {e}"),
                }
                context.sleep(Duration::from_secs(1)).await;
            }

            let block = provider
                .get_block_by_number(target_block.into())
                .await
                .expect("Failed to get block")
                .expect("Block not found");
            let timestamp = block.header.timestamp;
            println!("  Block {target_block} timestamp: {timestamp}");
            let beacon_input = U256::from(timestamp).to_be_bytes::<32>();
            let beacon_tx = TransactionRequest::default()
                .with_to(BEACON_ROOTS_ADDRESS)
                .with_input(Bytes::copy_from_slice(&beacon_input));
            let beacon_result = provider
                .call(beacon_tx)
                .await
                .expect("Beacon root call failed");

            let returned_root: [u8; 32] = beacon_result[..32]
                .try_into()
                .expect("Beacon root response not 32 bytes");
            println!(
                "  Beacon root contract returned: 0x{}",
                alloy::hex::encode(returned_root)
            );
            assert_eq!(
                returned_root, proof_resp.root,
                "Beacon root does not match state proof root"
            );
            println!("  Root matches: YES");

            // ---------------------------------------------------------------
            // TEST B: Deploy SSZ proof verifier and verify scalar proofs
            // ---------------------------------------------------------------
            println!("\nTEST B: On-chain SSZ proof verification (scalar)");

            // Deploy the SszProofVerifier contract
            let bytecode = alloy::hex::decode(SSZ_VERIFIER_BYTECODE)
                .expect("Failed to decode verifier bytecode");
            let deploy_tx = TransactionRequest::default()
                .with_deploy_code(Bytes::from(bytecode))
                .with_gas_limit(3_000_000)
                .with_gas_price(1_000_000_000);
            let pending = provider
                .send_transaction(deploy_tx)
                .await
                .expect("Failed to send deploy tx");
            println!("  Deploy tx sent: {}", pending.tx_hash());
            let receipt = pending
                .get_receipt()
                .await
                .expect("Failed to get deploy receipt");
            let verifier_address = receipt
                .contract_address
                .expect("No contract address in receipt");
            println!("  SszProofVerifier deployed at: {verifier_address}");

            // Verify each proof on-chain using unified verify(uint256,uint256,bytes32,bytes32[])
            let verify_selector = &keccak256(
                "verify(uint256,uint256,bytes32,bytes32[])"
            )[..4];
            for (i, result) in proof_resp.results.iter().enumerate() {
                let proof = result
                    .proof
                    .as_ref()
                    .expect("scalar state proof should be present");
                let calldata = encode_verify(
                    timestamp,
                    proof.gindex,
                    &proof.leaf,
                    &proof.branch,
                    verify_selector,
                );
                let call_tx = TransactionRequest::default()
                    .with_to(verifier_address)
                    .with_input(Bytes::from(calldata));
                let result = provider
                    .call(call_tx)
                    .await
                    .expect("verify call failed");
                let returned_root: [u8; 32] = result[..32]
                    .try_into()
                    .expect("verify response not 32 bytes");
                assert_eq!(
                    returned_root, proof_resp.root,
                    "verify returned wrong root for proof[{i}]"
                );
                println!("  proof[{i}]: verify OK (gindex={})", proof.gindex);
            }

            // ---------------------------------------------------------------
            // TEST C: Query and verify validator (collection) proof on-chain
            // ---------------------------------------------------------------
            println!("\nTEST C: On-chain SSZ proof verification (collection/validator)");

            let validator_key = format!("validator:0x{}", VALIDATOR0_PUBKEY_HEX);
            println!("  Querying proof for {validator_key}...");
            let val_proof_resp = summit_client
                .get_state_proof(vec![validator_key.clone()])
                .await
                .expect("getStateProof (validator) failed");
            println!("  root: 0x{}", alloy::hex::encode(val_proof_resp.root));
            println!("  results returned: {}", val_proof_resp.results.len());
            assert_eq!(
                val_proof_resp.results.len(),
                1,
                "Expected one result for validator"
            );

            // Wait for the target block to exist (might be a newer capture)
            let val_target_block = val_proof_resp.el_block_number + 1;
            loop {
                match provider.get_block_number().await {
                    Ok(n) if n >= val_target_block => break,
                    Ok(n) => println!("  Reth at block {n}, waiting for {val_target_block}..."),
                    Err(e) => println!("  Reth not ready: {e}"),
                }
                context.sleep(Duration::from_secs(1)).await;
            }
            let val_block = provider
                .get_block_by_number(val_target_block.into())
                .await
                .expect("Failed to get block")
                .expect("Block not found");
            let val_timestamp = val_block.header.timestamp;

            let vp = val_proof_resp.results[0]
                .proof
                .as_ref()
                .expect("No proof returned for validator");
            {
                let calldata = encode_verify(
                    val_timestamp,
                    vp.gindex,
                    &vp.leaf,
                    &vp.branch,
                    verify_selector,
                );
                let call_tx = TransactionRequest::default()
                    .with_to(verifier_address)
                    .with_input(Bytes::from(calldata));
                let result = provider
                    .call(call_tx)
                    .await
                    .expect("verify (validator) call failed");
                let returned_root: [u8; 32] = result[..32]
                    .try_into()
                    .expect("verify response not 32 bytes");
                assert_eq!(
                    returned_root, val_proof_resp.root,
                    "verify returned wrong root for validator"
                );
                println!(
                    "  verify OK (gindex={})",
                    vp.gindex
                );
            }

            // ---------------------------------------------------------------
            // TEST D: Verify individual validator balance field proof
            // ---------------------------------------------------------------
            println!("\nTEST D: On-chain validator balance field proof");

            // Query the validator account to get the expected balance
            let validator_node_key = format!("0x{}", VALIDATOR0_PUBKEY_HEX);
            let account_resp = summit_client
                .get_validator_account(validator_node_key)
                .await
                .expect("getValidatorAccount failed");
            println!("  Validator balance: {} gwei", account_resp.balance);

            let balance_key = format!("validator_field:0x{}:balance", VALIDATOR0_PUBKEY_HEX);
            println!("  Querying proof for {balance_key}...");
            let balance_proof_resp = summit_client
                .get_state_proof(vec![balance_key])
                .await
                .expect("getStateProof (balance field) failed");
            println!("  root: 0x{}", alloy::hex::encode(balance_proof_resp.root));
            assert_eq!(
                balance_proof_resp.results.len(),
                1,
                "Expected one result for balance field"
            );

            let bp = balance_proof_resp.results[0]
                .proof
                .as_ref()
                .expect("No proof returned for balance field");
            println!(
                "  gindex={}, leaf=0x{}, branch_len={}",
                bp.gindex,
                alloy::hex::encode(bp.leaf),
                bp.branch.len()
            );

            // Verify the leaf matches the SSZ hash_tree_root of the balance
            use summit_types::ssz_hash::SszHashTreeRoot;
            let expected_balance_leaf = account_resp.balance.hash_tree_root();
            assert_eq!(
                bp.leaf, expected_balance_leaf,
                "balance field leaf does not match expected SSZ encoding"
            );
            println!("  Balance leaf matches SSZ encoding: {} gwei", account_resp.balance);

            // Field proof should be 3 siblings longer than whole-account proof
            println!(
                "  Branch length: {} (account proof was {})",
                bp.branch.len(),
                vp.branch.len()
            );

            // Wait for the target block if needed
            let bal_target_block = balance_proof_resp.el_block_number + 1;
            loop {
                match provider.get_block_number().await {
                    Ok(n) if n >= bal_target_block => break,
                    Ok(n) => println!("  Reth at block {n}, waiting for {bal_target_block}..."),
                    Err(e) => println!("  Reth not ready: {e}"),
                }
                context.sleep(Duration::from_secs(1)).await;
            }
            let bal_block = provider
                .get_block_by_number(bal_target_block.into())
                .await
                .expect("Failed to get block")
                .expect("Block not found");
            let bal_timestamp = bal_block.header.timestamp;

            // Verify on-chain using the standard verify() function
            // (verifyValidatorField has the same signature as verify)
            {
                let calldata = encode_verify(
                    bal_timestamp,
                    bp.gindex,
                    &bp.leaf,
                    &bp.branch,
                    verify_selector,
                );
                let call_tx = TransactionRequest::default()
                    .with_to(verifier_address)
                    .with_input(Bytes::from(calldata));
                let result = provider
                    .call(call_tx)
                    .await
                    .expect("verify (balance field) call failed");
                let returned_root: [u8; 32] = result[..32]
                    .try_into()
                    .expect("verify response not 32 bytes");
                assert_eq!(
                    returned_root, balance_proof_resp.root,
                    "verify returned wrong root for balance field proof"
                );
                println!(
                    "  verify OK: balance={} gwei proven at gindex={}",
                    account_resp.balance, bp.gindex
                );
            }

            // ---------------------------------------------------------------
            // Done
            // ---------------------------------------------------------------
            println!("\nAll tests passed!");

            // Shutdown
            println!("Sending stop signals to all {} nodes...", node_runtimes.len());
            for (idx, node_runtime) in node_runtimes.iter().enumerate() {
                println!("Sending stop signal to node {idx}...");
                let _ = node_runtime.stop_tx.send(());
            }

            Ok::<_, Box<dyn std::error::Error>>(node_runtimes)
        }
    })?;

    // Join all node threads outside async context
    println!("Waiting for all nodes to shut down...");
    for (idx, node_runtime) in node_runtimes.into_iter().enumerate() {
        println!("Waiting for node {idx} to join...");
        match node_runtime.thread.join() {
            Ok(_) => println!("Node {idx} thread joined successfully"),
            Err(e) => println!("Node {idx} thread join failed: {e:?}"),
        }
    }

    println!("All nodes shut down cleanly");
    std::process::exit(0);
}

async fn get_latest_height(rpc_port: u16) -> Result<u64, Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", rpc_port);
    let client = HttpClientBuilder::default().build(&url)?;
    let height = client.get_latest_height().await?;
    Ok(height)
}

/// ABI-encode a call to verify(uint256, uint256, bytes32, bytes32[]).
fn encode_verify(
    timestamp: u64,
    gindex: u64,
    leaf: &[u8; 32],
    branch: &[[u8; 32]],
    selector: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 4 * 32 + branch.len() * 32);
    data.extend_from_slice(selector);
    // timestamp (uint256)
    data.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    // gindex (uint256)
    data.extend_from_slice(&U256::from(gindex).to_be_bytes::<32>());
    // leaf (bytes32)
    data.extend_from_slice(leaf);
    // offset to branch array (4th param, dynamic)
    data.extend_from_slice(&U256::from(4 * 32).to_be_bytes::<32>());
    // branch array: length + elements
    data.extend_from_slice(&U256::from(branch.len()).to_be_bytes::<32>());
    for h in branch {
        data.extend_from_slice(h);
    }
    data
}

fn get_node_flags(node: usize, genesis_path: &str) -> RunFlags {
    let path = format!("testnet/node{node}/");
    RunFlags {
        key_store_path: path.clone(),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        prom_ip: "0.0.0.0".into(),
        rpc_port: (3030 + (node * 10)) as u16,
        admin_rpc_port: (3031 + (node * 10)) as u16,
        rpc_max_request_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        rpc_max_response_body_size: summit_rpc::DEFAULT_RPC_BODY_LIMIT_BYTES,
        rpc_request_timeout_secs: summit_rpc::DEFAULT_RPC_REQUEST_TIMEOUT_SECS,
        rpc_max_batch_size: summit_rpc::DEFAULT_RPC_MAX_BATCH_SIZE,
        worker_threads: Some(2),
        log_level: "debug".into(),
        db_prefix: format!("{node}"),
        genesis_path: genesis_path.into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(feature = "bench")]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: false,
        weak_subjectivity_epoch: None,
        weak_subjectivity_header_digest: None,
        ip: None,
        bootstrappers: None,
        critical_log_dir: None,
        observer: None,
        finalizer_pending_notarized_max: 1000,
    }
}
