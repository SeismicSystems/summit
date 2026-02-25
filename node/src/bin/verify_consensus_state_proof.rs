use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, Bytes, U256, address, keccak256};
use clap::Parser;
use commonware_codec::DecodeExt;
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
use summit_types::account::{ValidatorAccount, ValidatorStatus};
use summit_types::reth::Reth;
use summit_types::ssz_state_tree::SszStateProof;
use tokio::sync::mpsc;
use tracing::Level;

/// Compiled bytecode of SszProofVerifier.sol (solc --via-ir --optimize --bin).
const SSZ_VERIFIER_BYTECODE: &str = "608080604052346015576109b5908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c80631b361d131461051c5780637e1899e5146100d75763d07f027b1461003a575f80fd5b346100d35760803660031901126100d3576064356001600160401b0381116100d35761006a9036906004016105b4565b90610087610079600435610811565b9283926024356044356106cd565b0361009757602090604051908152f35b60405162461bcd60e51b81526020600482015260146024820152731cd8d85b185c881c1c9bdbd9881a5b9d985b1a5960621b6044820152606490fd5b5f80fd5b346100d3576101e03660031901126100d3576044356001600160401b0381116100d3576101089036906004016105b4565b9060643560c4356001600160401b0381116100d35761012b9036906004016105b4565b909260e4356001600160401b0381116100d357366023820112156100d35780600401356001600160401b0381116100d35736602482840101116100d35761010435906001600160a01b03821682036100d35761012435906001600160401b03821682036100d357610144359160ff831683036100d3576101643580151581036100d357610184359182151583036100d3576101a435966001600160401b03881688036100d3576101c435946001600160401b03861686036100d3576030036104d7575f602091604051838101916024810135835260446fffffffffffffffffffffffffffffffff199101351660408201526040815261022b606082610698565b604051918291518091835e8101838152039060025afa156104b8575f6020916102558251916108f4565b9382146104d0576001945b82146104c35761027a61027460019a6108f4565b966108f4565b97604051908482019283526bffffffffffffffffffffffff199060601b166040820152604081526102ac606082610698565b604051918291518091835e8101838152039060025afa156104b8575f6020918151956040519084820192835260ff60f81b9060f81b166040820152604081526102f6606082610698565b604051918291518091835e8101838152039060025afa156104b8575f602091815196604051908482019260ff60f81b9060f81b16835260ff60f81b9060f81b1660408201526040815261034a606082610698565b604051918291518091835e8101838152039060025afa156104b8575f6020918151946040519084820192835260408201526040815261038a606082610698565b604051918291518091835e8101838152039060025afa156104b8575f602091815194604051908482019283526040820152604081526103ca606082610698565b604051918291518091835e8101838152039060025afa156104b8575f6020918151936040519084820192835260408201526040815261040a606082610698565b604051918291518091835e8101838152039060025afa156104b8575f602091815160405190848201928352604082015260408152610449606082610698565b604051918291518091835e8101838152039060025afa156104b857610492836104896104b0956104836020996104aa966024355f516106cd565b146105e4565b608435906107bd565b9161049e600435610811565b94859360a435906106cd565b14610628565b604051908152f35b6040513d5f823e3d90fd5b61027a610274839a6108f4565b8194610260565b60405162461bcd60e51b815260206004820152601b60248201527f424c53207075626b6579206d75737420626520343820627974657300000000006044820152606490fd5b346100d3576101003660031901126100d3576064356001600160401b0381116100d35761054d9036906004016105b4565b906084359160e435906001600160401b0382116100d3576104aa61059c856105936020976104836105856104b09836906004016105b4565b9790996024356044356106cd565b60a435906107bd565b916105a8600435610811565b94859360c435906106cd565b9181601f840112156100d3578235916001600160401b0383116100d3576020808501948460051b0101116100d357565b156105eb57565b60405162461bcd60e51b81526020600482015260156024820152741cdd589d1c9959481c1c9bdbd9881a5b9d985b1a59605a1b6044820152606490fd5b1561062f57565b60405162461bcd60e51b815260206004820152601760248201527f746f702d6c6576656c2070726f6f6620696e76616c69640000000000000000006044820152606490fd5b91908110156106845760051b0190565b634e487b7160e01b5f52603260045260245ffd5b90601f801991011681019081106001600160401b038211176106b957604052565b634e487b7160e01b5f52604160045260245ffd5b92906001821b9081018091116107a95791905f915b8183106106f0575050505090565b909192935f602091600187161582146107595761070e868686610674565b356040519084820192835260408201526040815261072d606082610698565b604051918291518091835e8101838152039060025afa156104b85760015f51945b811c930191906106e2565b610764868686610674565b359060405190848201928352604082015260408152610784606082610698565b604051918291518091835e8101838152039060025afa156104b85760015f519461074e565b634e487b7160e01b5f52601160045260245ffd5b5f906107d36001600160401b03602094166108f4565b604051908482019283526040820152604081526107f1606082610698565b604051918291518091835e8101838152039060025afa156104b8575f5190565b5f8091604051602081019182526020815261082d604082610698565b5190720f3df6d732807ef1319fb7b8bb8522d0beac025afa3d156108ec573d906001600160401b0382116106b95760405191610873601f8201601f191660200184610698565b82523d5f602084013e5b806108e1575b1561089c576020818051810103126100d3576020015190565b60405162461bcd60e51b815260206004820152601960248201527f626561636f6e20726f6f74206c6f6f6b7570206661696c6564000000000000006044820152606490fd5b506020815114610883565b60609061087d565b65ffffffffffff8160081c9160081b9166ff000000ff000067ff000000ff00000067ffffffffffff000065ff000000ff00861664ff000000ff85161760101b16941691161760101c16176001600160401b03808260201b169160201c161760c01b9056fea2646970667358221220ebf237720b046236505ca9155aafce7ce0ed26df8aba5d7912b1e46cc251663e64736f6c637829302e382e33312d646576656c6f702e323032352e31312e31322b636f6d6d69742e3464313362633133005a";

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
            // TEST D: Verify validator account preimage on-chain
            // ---------------------------------------------------------------
            println!("\nTEST D: On-chain validator account preimage verification");

            // Query the full validator account from the RPC
            let validator_node_key = format!("0x{}", VALIDATOR0_PUBKEY_HEX);
            let account_resp = summit_client
                .get_validator_account(validator_node_key)
                .await
                .expect("getValidatorAccount failed");
            println!("  balance: {}", account_resp.balance);
            println!("  status: {}", account_resp.status);

            // Verify the account fields produce the correct leaf_value from the proof
            use summit_types::ssz_hash::SszHashTreeRoot;
            let bls_pubkey = commonware_cryptography::bls12381::PublicKey::decode(
                &*account_resp.consensus_public_key,
            )
            .expect("Failed to decode BLS pubkey");
            let withdrawal_addr = Address::from_slice(&account_resp.withdrawal_credentials);
            let status_enum = match account_resp.status.as_str() {
                "Active" => ValidatorStatus::Active,
                "Inactive" => ValidatorStatus::Inactive,
                "SubmittedExitRequest" => ValidatorStatus::SubmittedExitRequest,
                "Joining" => ValidatorStatus::Joining,
                other => panic!("Unknown validator status: {other}"),
            };
            let account = ValidatorAccount {
                consensus_public_key: bls_pubkey,
                withdrawal_credentials: withdrawal_addr,
                balance: account_resp.balance,
                status: status_enum,
                has_pending_deposit: account_resp.has_pending_deposit,
                has_pending_withdrawal: account_resp.has_pending_withdrawal,
                joining_epoch: account_resp.joining_epoch,
                last_deposit_index: account_resp.last_deposit_index,
            };
            let account_hash = account.hash_tree_root();

            if let SszStateProof::Collection(cp) = &val_proof_resp.proofs[0] {
                assert_eq!(
                    account_hash, cp.leaf_value,
                    "hash_tree_root(account) does not match proof leaf_value"
                );
                println!(
                    "  Account hash matches proof: 0x{}",
                    alloy::hex::encode(account_hash)
                );

                let status_u8 = match account_resp.status.as_str() {
                    "Active" => 0u8,
                    "Inactive" => 1,
                    "SubmittedExitRequest" => 2,
                    "Joining" => 3,
                    _ => unreachable!(),
                };

                // verifyValidatorAccount(uint256,uint256,bytes32[],bytes32,uint256,uint256,bytes32[],bytes,address,uint64,uint8,bool,bool,uint64,uint64)
                let verify_va_selector = &keccak256(
                    "verifyValidatorAccount(uint256,uint256,bytes32[],bytes32,uint256,uint256,bytes32[],bytes,address,uint64,uint8,bool,bool,uint64,uint64)"
                )[..4];
                let calldata = encode_verify_validator_account(
                    val_timestamp,
                    cp,
                    verify_va_selector,
                    &account_resp.consensus_public_key,
                    withdrawal_addr,
                    account_resp.balance,
                    status_u8,
                    account_resp.has_pending_deposit,
                    account_resp.has_pending_withdrawal,
                    account_resp.joining_epoch,
                    account_resp.last_deposit_index,
                );
                let call_tx = TransactionRequest::default()
                    .with_to(verifier_address)
                    .with_input(Bytes::from(calldata));
                let result = provider
                    .call(call_tx)
                    .await
                    .expect("verifyValidatorAccount call failed");
                let returned_root: [u8; 32] = result[..32]
                    .try_into()
                    .expect("verifyValidatorAccount response not 32 bytes");
                assert_eq!(
                    returned_root, val_proof_resp.root,
                    "verifyValidatorAccount returned wrong root"
                );
                println!(
                    "  verifyValidatorAccount OK (balance={}, status={})",
                    account_resp.balance, account_resp.status
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

/// ABI-encode a call to verifyValidatorAccount(uint256,uint256,bytes32[],bytes32,uint256,uint256,bytes32[],bytes,address,uint64,uint8,bool,bool,uint64,uint64).
#[allow(clippy::too_many_arguments)]
fn encode_verify_validator_account(
    timestamp: u64,
    cp: &summit_types::ssz_state_tree::CollectionProof,
    selector: &[u8],
    consensus_pubkey: &[u8], // 48 bytes
    withdrawal_addr: Address,
    balance: u64,
    status: u8,
    has_pending_deposit: bool,
    has_pending_withdrawal: bool,
    joining_epoch: u64,
    last_deposit_index: u64,
) -> Vec<u8> {
    // 15 params total. Dynamic params: subtreeBranch (index 2), topBranch (index 6), consensusPubkey (index 7)
    let head_size = 15 * 32; // 15 slots in the head

    // Calculate offsets for dynamic data (relative to start of params, not selector)
    // Dynamic params: subtreeBranch at slot 2, topBranch at slot 6, consensusPubkey at slot 7
    // Layout after head:
    //   subtreeBranch data
    //   topBranch data
    //   consensusPubkey data
    let subtree_branch_offset = head_size;
    let subtree_branch_data_size = 32 + cp.subtree_branch.len() * 32;
    let top_branch_offset = subtree_branch_offset + subtree_branch_data_size;
    let top_branch_data_size = 32 + cp.top_branch.len() * 32;
    let consensus_pubkey_offset = top_branch_offset + top_branch_data_size;
    // bytes: length (32) + padded data (ceil(48/32)*32 = 64)
    let consensus_pubkey_data_size = 32 + 64;

    let total_size = 4
        + head_size
        + subtree_branch_data_size
        + top_branch_data_size
        + consensus_pubkey_data_size;

    let mut data = Vec::with_capacity(total_size);
    data.extend_from_slice(selector);

    // Slot 0: timestamp (uint256)
    data.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    // Slot 1: itemIndex (uint256)
    data.extend_from_slice(&U256::from(cp.item_index).to_be_bytes::<32>());
    // Slot 2: offset to subtreeBranch (dynamic)
    data.extend_from_slice(&U256::from(subtree_branch_offset).to_be_bytes::<32>());
    // Slot 3: subtreeRoot (bytes32)
    data.extend_from_slice(&cp.subtree_root);
    // Slot 4: collectionLength (uint256)
    data.extend_from_slice(&U256::from(cp.collection_length).to_be_bytes::<32>());
    // Slot 5: topLeafIndex (uint256)
    data.extend_from_slice(&U256::from(cp.top_leaf_index).to_be_bytes::<32>());
    // Slot 6: offset to topBranch (dynamic)
    data.extend_from_slice(&U256::from(top_branch_offset).to_be_bytes::<32>());
    // Slot 7: offset to consensusPubkey (dynamic bytes)
    data.extend_from_slice(&U256::from(consensus_pubkey_offset).to_be_bytes::<32>());
    // Slot 8: withdrawalCreds (address, left-padded to 32 bytes)
    let mut addr_slot = [0u8; 32];
    addr_slot[12..32].copy_from_slice(withdrawal_addr.as_slice());
    data.extend_from_slice(&addr_slot);
    // Slot 9: balance (uint64)
    data.extend_from_slice(&U256::from(balance).to_be_bytes::<32>());
    // Slot 10: status (uint8)
    data.extend_from_slice(&U256::from(status).to_be_bytes::<32>());
    // Slot 11: hasPendingDeposit (bool)
    data.extend_from_slice(&U256::from(has_pending_deposit as u64).to_be_bytes::<32>());
    // Slot 12: hasPendingWithdrawal (bool)
    data.extend_from_slice(&U256::from(has_pending_withdrawal as u64).to_be_bytes::<32>());
    // Slot 13: joiningEpoch (uint64)
    data.extend_from_slice(&U256::from(joining_epoch).to_be_bytes::<32>());
    // Slot 14: lastDepositIndex (uint64)
    data.extend_from_slice(&U256::from(last_deposit_index).to_be_bytes::<32>());

    // Dynamic data: subtreeBranch
    data.extend_from_slice(&U256::from(cp.subtree_branch.len()).to_be_bytes::<32>());
    for h in &cp.subtree_branch {
        data.extend_from_slice(h);
    }

    // Dynamic data: topBranch
    data.extend_from_slice(&U256::from(cp.top_branch.len()).to_be_bytes::<32>());
    for h in &cp.top_branch {
        data.extend_from_slice(h);
    }

    // Dynamic data: consensusPubkey (bytes)
    data.extend_from_slice(&U256::from(consensus_pubkey.len()).to_be_bytes::<32>());
    let mut padded_pubkey = [0u8; 64]; // ceil(48/32)*32 = 64
    padded_pubkey[..consensus_pubkey.len()].copy_from_slice(consensus_pubkey);
    data.extend_from_slice(&padded_pubkey);

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
