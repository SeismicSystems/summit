use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, Bytes, U256, address, keccak256};
use clap::Parser;
use commonware_runtime::{Clock, Metrics as _, Runner as _, Spawner as _, tokio as cw_tokio};
use futures::{FutureExt, pin_mut};
use jsonrpsee::http_client::HttpClientBuilder;
use std::collections::VecDeque;
use std::time::Duration;
use std::{
    fs,
    io::{BufRead as _, BufReader, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr as _,
    thread::JoinHandle,
};
use summit::args::{RunFlags, run_node_local};
use summit_rpc::{SummitApiClient, SummitProofApiClient};
use summit_types::reth::Reth;
use summit_types::ssz_state_tree::SszStateProof;
use tokio::sync::mpsc;
use tracing::Level;

/// Compiled bytecode of SszProofVerifier.sol (solc --bin --optimize).
const SSZ_VERIFIER_BYTECODE: &str = "6080604052348015600e575f5ffd5b5061075e8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80631b361d1314610038578063d07f027b1461005d575b5f5ffd5b61004b610046366004610561565b610070565b60405190815260200160405180910390f35b61004b61006b36600461060b565b610153565b5f5f61007e8a8c8b8b6101be565b90508681146100cc5760405162461bcd60e51b81526020600482015260156024820152741cdd589d1c9959481c1c9bdbd9881a5b9d985b1a59605a1b60448201526064015b60405180910390fd5b5f6100d78888610332565b90506100e28d610414565b92505f6100f1828888886101be565b90508381146101425760405162461bcd60e51b815260206004820152601760248201527f746f702d6c6576656c2070726f6f6620696e76616c696400000000000000000060448201526064016100c3565b5050509a9950505050505050505050565b5f61015d86610414565b90505f61016c858786866101be565b90508181146101b45760405162461bcd60e51b81526020600482015260146024820152731cd8d85b185c881c1c9bdbd9881a5b9d985b1a5960621b60448201526064016100c3565b5095945050505050565b5f84816101ce866001861b610667565b90505f5b84811015610326576101e560028361069a565b5f0361028057600283878784818110610200576102006106ad565b90506020020135604051602001610221929190918252602082015260400190565b60408051601f198184030181529082905261023b916106c1565b602060405180830381855afa158015610256573d5f5f3e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061027991906106d7565b9250610311565b6002868683818110610294576102946106ad565b90506020020135846040516020016102b6929190918252602082015260400190565b60408051601f19818403018152908290526102d0916106c1565b602060405180830381855afa1580156102eb573d5f5f3e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061030e91906106d7565b92505b61031c6002836106ee565b91506001016101d2565b50909695505050505050565b5f8065ff000000ff00600884811b91821664ff000000ff9186901c91821617601090811b67ff000000ff0000009390931666ff000000ff00009290921691909117901c17602081811c63ffffffff1691901b67ffffffff00000000161760c01b9050600284826040516020016103b2929190918252602082015260400190565b60408051601f19818403018152908290526103cc916106c1565b602060405180830381855afa1580156103e7573d5f5f3e3d5ffd5b5050506040513d601f19601f8201168201806040525081019061040a91906106d7565b9150505b92915050565b5f5f5f720f3df6d732807ef1319fb7b8bb8522d0beac026001600160a01b03168460405160200161044791815260200190565b60408051601f1981840301815290829052610461916106c1565b5f60405180830381855afa9150503d805f8114610499576040519150601f19603f3d011682016040523d82523d5f602084013e61049e565b606091505b50915091508180156104b1575080516020145b6104fd5760405162461bcd60e51b815260206004820152601960248201527f626561636f6e20726f6f74206c6f6f6b7570206661696c65640000000000000060448201526064016100c3565b8080602001905181019061051191906106d7565b949350505050565b5f5f83601f840112610529575f5ffd5b50813567ffffffffffffffff811115610540575f5ffd5b6020830191508360208260051b850101111561055a575f5ffd5b9250929050565b5f5f5f5f5f5f5f5f5f5f6101008b8d03121561057b575f5ffd5b8a35995060208b0135985060408b0135975060608b013567ffffffffffffffff8111156105a6575f5ffd5b6105b28d828e01610519565b90985096505060808b0135945060a08b0135935060c08b0135925060e08b013567ffffffffffffffff8111156105e6575f5ffd5b6105f28d828e01610519565b915080935050809150509295989b9194979a5092959850565b5f5f5f5f5f6080868803121561061f575f5ffd5b853594506020860135935060408601359250606086013567ffffffffffffffff81111561064a575f5ffd5b61065688828901610519565b969995985093965092949392505050565b8082018082111561040e57634e487b7160e01b5f52601160045260245ffd5b634e487b7160e01b5f52601260045260245ffd5b5f826106a8576106a8610686565b500690565b634e487b7160e01b5f52603260045260245ffd5b5f82518060208501845e5f920191825250919050565b5f602082840312156106e7575f5ffd5b5051919050565b5f826106fc576106fc610686565b50049056fea2646970667358221220018a63f27dc124efda4c680f863ba5dd3d693d7d45e55e54fe4a5c0c14b74d2f64736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3464313362633133005a";

/// Genesis validator 0 node public key (from example_genesis.toml).
const VALIDATOR0_PUBKEY_HEX: &str =
    "1be3cb06d7cc347602421fb73838534e4b54934e28959de98906d120d0799ef2";

const NUM_NODES: u16 = 4;

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

    let node_runtimes = executor.start(|context| {
        async move {
            let log_level = Level::from_str("info").expect("Invalid log level");
            cw_tokio::telemetry::init(
                context.with_label("metrics"),
                cw_tokio::telemetry::Logging {
                    level: log_level,
                    json: false,
                },
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6969)),
                None,
            );

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

                let flags = get_node_flags(x.into());
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
            let summit_rpc_port = get_node_flags(0).rpc_port;
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
            println!("  proofs returned: {}", proof_resp.proofs.len());
            for (i, proof) in proof_resp.proofs.iter().enumerate() {
                match proof {
                    SszStateProof::Scalar(p) => {
                        println!("  proof[{i}]: Scalar(leaf_index={}, leaf=0x{})",
                            p.leaf_index, alloy::hex::encode(p.leaf_value));
                    }
                    SszStateProof::Collection(p) => {
                        println!("  proof[{i}]: Collection(item_index={}, top_leaf={})",
                            p.item_index, p.top_leaf_index);
                    }
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

            // Verify each scalar proof on-chain
            // verifyScalar(uint256 timestamp, uint256 leafIndex, bytes32 leafValue, bytes32[] branch)
            let verify_scalar_selector = &keccak256(
                "verifyScalar(uint256,uint256,bytes32,bytes32[])"
            )[..4];
            for (i, proof) in proof_resp.proofs.iter().enumerate() {
                if let SszStateProof::Scalar(p) = proof {
                    let calldata = encode_verify_scalar(
                        timestamp,
                        p.leaf_index,
                        &p.leaf_value,
                        &p.branch,
                        verify_scalar_selector,
                    );
                    let call_tx = TransactionRequest::default()
                        .with_to(verifier_address)
                        .with_input(Bytes::from(calldata));
                    let result = provider
                        .call(call_tx)
                        .await
                        .expect("verifyScalar call failed");
                    let returned_root: [u8; 32] = result[..32]
                        .try_into()
                        .expect("verifyScalar response not 32 bytes");
                    assert_eq!(
                        returned_root, proof_resp.root,
                        "verifyScalar returned wrong root for proof[{i}]"
                    );
                    println!("  proof[{i}]: verifyScalar OK (leaf_index={})", p.leaf_index);
                }
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
            println!("  proofs returned: {}", val_proof_resp.proofs.len());
            assert!(
                !val_proof_resp.proofs.is_empty(),
                "No proofs returned for validator"
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

            if let SszStateProof::Collection(cp) = &val_proof_resp.proofs[0] {
                // verifyCollection(uint256,uint256,bytes32,bytes32[],bytes32,uint256,uint256,bytes32[])
                let verify_collection_selector = &keccak256(
                    "verifyCollection(uint256,uint256,bytes32,bytes32[],bytes32,uint256,uint256,bytes32[])"
                )[..4];
                let calldata = encode_verify_collection(
                    val_timestamp,
                    cp,
                    verify_collection_selector,
                );
                let call_tx = TransactionRequest::default()
                    .with_to(verifier_address)
                    .with_input(Bytes::from(calldata));
                let result = provider
                    .call(call_tx)
                    .await
                    .expect("verifyCollection call failed");
                let returned_root: [u8; 32] = result[..32]
                    .try_into()
                    .expect("verifyCollection response not 32 bytes");
                assert_eq!(
                    returned_root, val_proof_resp.root,
                    "verifyCollection returned wrong root"
                );
                println!(
                    "  verifyCollection OK (item_index={}, top_leaf={})",
                    cp.item_index, cp.top_leaf_index
                );
            } else {
                panic!("Expected Collection proof for validator query");
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

/// ABI-encode a call to verifyScalar(uint256, uint256, bytes32, bytes32[]).
fn encode_verify_scalar(
    timestamp: u64,
    leaf_index: usize,
    leaf_value: &[u8; 32],
    branch: &[[u8; 32]],
    selector: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 4 * 32 + branch.len() * 32);
    data.extend_from_slice(selector);
    // timestamp (uint256)
    data.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    // leafIndex (uint256)
    data.extend_from_slice(&U256::from(leaf_index).to_be_bytes::<32>());
    // leafValue (bytes32)
    data.extend_from_slice(leaf_value);
    // offset to branch array (4th param, dynamic)
    data.extend_from_slice(&U256::from(4 * 32).to_be_bytes::<32>());
    // branch array: length + elements
    data.extend_from_slice(&U256::from(branch.len()).to_be_bytes::<32>());
    for h in branch {
        data.extend_from_slice(h);
    }
    data
}

/// ABI-encode a call to verifyCollection(uint256,uint256,bytes32,bytes32[],bytes32,uint256,uint256,bytes32[]).
fn encode_verify_collection(
    timestamp: u64,
    cp: &summit_types::ssz_state_tree::CollectionProof,
    selector: &[u8],
) -> Vec<u8> {
    // 8 params, 2 dynamic (subtreeBranch at index 3, topBranch at index 7)
    let head_size = 8 * 32; // 8 slots of 32 bytes each in the head
    let subtree_branch_offset = head_size;
    let top_branch_offset = subtree_branch_offset + 32 + cp.subtree_branch.len() * 32; // length slot + elements

    let mut data = Vec::with_capacity(
        4 + head_size + 32 + cp.subtree_branch.len() * 32 + 32 + cp.top_branch.len() * 32,
    );
    data.extend_from_slice(selector);
    // timestamp (uint256)
    data.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    // itemIndex (uint256)
    data.extend_from_slice(&U256::from(cp.item_index).to_be_bytes::<32>());
    // leafValue (bytes32)
    data.extend_from_slice(&cp.leaf_value);
    // offset to subtreeBranch (dynamic)
    data.extend_from_slice(&U256::from(subtree_branch_offset).to_be_bytes::<32>());
    // subtreeRoot (bytes32)
    data.extend_from_slice(&cp.subtree_root);
    // collectionLength (uint256)
    data.extend_from_slice(&U256::from(cp.collection_length).to_be_bytes::<32>());
    // topLeafIndex (uint256)
    data.extend_from_slice(&U256::from(cp.top_leaf_index).to_be_bytes::<32>());
    // offset to topBranch (dynamic)
    data.extend_from_slice(&U256::from(top_branch_offset).to_be_bytes::<32>());
    // subtreeBranch array
    data.extend_from_slice(&U256::from(cp.subtree_branch.len()).to_be_bytes::<32>());
    for h in &cp.subtree_branch {
        data.extend_from_slice(h);
    }
    // topBranch array
    data.extend_from_slice(&U256::from(cp.top_branch.len()).to_be_bytes::<32>());
    for h in &cp.top_branch {
        data.extend_from_slice(h);
    }
    data
}

fn get_node_flags(node: usize) -> RunFlags {
    let path = format!("testnet/node{node}/");
    RunFlags {
        archive_mode: false,
        key_store_path: path.clone(),
        store_path: format!("{path}db"),
        port: (26600 + (node * 10)) as u16,
        prom_port: (28600 + (node * 10)) as u16,
        prom_ip: "0.0.0.0".into(),
        rpc_port: (3030 + (node * 10)) as u16,
        worker_threads: 2,
        log_level: "debug".into(),
        db_prefix: format!("{node}-quarts"),
        genesis_path: "./example_genesis.toml".into(),
        engine_ipc_path: format!("/tmp/reth_engine_api{node}.ipc"),
        #[cfg(feature = "bench")]
        bench_block_dir: None,
        checkpoint_path: None,
        checkpoint_or_default: false,
        ip: None,
        bootstrappers: None,
    }
}
