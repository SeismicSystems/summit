mod utils;

use jsonrpsee::http_client::HttpClientBuilder;
use summit_rpc::{
    PathSender, start_rpc_server_for_genesis_with_handle, start_rpc_server_with_handle,
};
use utils::{MockFinalizerState, create_test_finalizer_mailbox, create_test_keystore};

#[tokio::test]
async fn test_health_endpoint() {
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.health().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), "Ok");

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_latest_height() {
    use summit_rpc::SummitApiClient;

    let state = MockFinalizerState {
        latest_height: 42,
        ..Default::default()
    };
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(state);
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_latest_height().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 42);

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_latest_epoch() {
    use summit_rpc::SummitApiClient;

    let state = MockFinalizerState {
        latest_epoch: 10,
        ..Default::default()
    };
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(state);
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_latest_epoch().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 10);

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_validator_balance_not_found() {
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let fake_pubkey = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let response = client.get_validator_balance(fake_pubkey.to_string()).await;

    assert!(
        response.is_err(),
        "Non-existent validator should return error"
    );

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_public_keys() {
    use summit_rpc::SummitGenesisApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_public_keys().await;
    assert!(response.is_ok(), "getPublicKeys should succeed");

    let keys = response.unwrap();
    assert!(!keys.node.is_empty(), "Node public key should not be empty");
    assert!(
        !keys.consensus.is_empty(),
        "Consensus public key should not be empty"
    );

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_send_genesis() {
    use summit_rpc::SummitGenesisApiClient;

    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let genesis_dir = tempfile::tempdir().unwrap();
    let genesis_path = genesis_dir.path().join("genesis.toml");
    let genesis_path_str = genesis_path.to_str().unwrap().to_string();

    let path_sender = PathSender::new(genesis_path_str.clone(), None);

    let (handle, addr) = start_rpc_server_for_genesis_with_handle(path_sender, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let genesis_content = r#"eth_genesis_hash = "0x7a1a4b5e14b0e611bfe79f128bbcf2861dda517d7fc6f98c071c7e5cc349e0b8"
leader_timeout_ms = 2000
notarization_timeout_ms = 4000
nullify_timeout_ms = 4000
activity_timeout_views = 256
skip_timeout_views = 32
max_message_size_bytes = 104857600
namespace = "_SEISMIC_BFT"

[[validators]]
node_public_key = "1be3cb06d7cc347602421fb73838534e4b54934e28959de98906d120d0799ef2"
consensus_public_key = "a6f61154ae7be4fd38cd43cf69adfd4896c57473cacb389702bb83f8adf923eecf4854c745e064c0a2db79db5674332b"
ip_address = "127.0.0.1:26600"
withdrawal_credentials = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

[[validators]]
node_public_key = "32efa16e3cd62292db529e8f4babd27724b13b397edcf2b1dbe48f416ce40f0d"
consensus_public_key = "b82eaa7fbc7f9cf9d60826e5155ca8ccc46e13d87f64f7bcdcaa2972c370766b87635334bfc49b8fba7fb784e763d44e"
ip_address = "127.0.0.1:26610"
withdrawal_credentials = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
"#;
    let response = client.send_genesis(genesis_content.to_string()).await;
    assert!(response.is_ok(), "sendGenesis should succeed");

    let result = response.unwrap();
    assert!(
        result.contains(&genesis_path_str),
        "Response should contain the genesis path"
    );

    let written_content = std::fs::read_to_string(&genesis_path).unwrap();
    assert_eq!(
        written_content, genesis_content,
        "Written genesis content should match input"
    );

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_minimum_stake() {
    use summit_rpc::SummitApiClient;

    let state = MockFinalizerState {
        minimum_stake: 40_000_000_000, // 40 ETH in gwei
        ..Default::default()
    };
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(state);
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_minimum_stake().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 40_000_000_000);

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_maximum_stake() {
    use summit_rpc::SummitApiClient;

    let state = MockFinalizerState {
        maximum_stake: 64_000_000_000, // 64 ETH in gwei
        ..Default::default()
    };
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(state);
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(mailbox, key_store_path, 0)
        .await
        .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_maximum_stake().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 64_000_000_000);

    handle.stop().unwrap();
}
