mod utils;

use jsonrpsee::http_client::HttpClientBuilder;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::AtomicBool;
use summit_rpc::{
    PathSender, start_rpc_server_for_genesis_with_handle, start_rpc_server_pair_with_handle,
    start_rpc_server_with_handle,
};
use utils::{
    MockFinalizerState, create_test_finalized_header, create_test_finalizer_mailbox,
    create_test_keystore,
};

const TEST_GENESIS_HASH: [u8; 32] = [7u8; 32];

/// Derive the observer child transport key for the keystore's node key, the
/// same way `--observer <index>` derives the live P2P signer.
fn derive_observer_node_key(key_store_path: &str, index: u32) -> String {
    use commonware_cryptography::Signer as _;
    use summit_types::{KeyPaths, ext_private_key::ExtPrivateKey};

    let node_key = KeyPaths::new(key_store_path.to_string())
        .read_node_key_from_file()
        .unwrap();
    ExtPrivateKey::derive_child_signer(&node_key, b"_SUMMIT", index)
        .public_key()
        .to_string()
}

#[tokio::test]
async fn test_health_endpoint() {
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
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

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
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

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
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
async fn test_get_finalized_header_digest() {
    use summit_rpc::SummitApiClient;

    let epoch = 3;
    let finalized_header = create_test_finalized_header(epoch);
    let expected_digest = finalized_header.header().get_digest().0;
    let state = MockFinalizerState {
        finalized_headers: [(epoch, Some(finalized_header))].into(),
        ..Default::default()
    };
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(state);
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_finalized_header_digest(epoch).await.unwrap();
    assert_eq!(response.epoch, epoch);
    assert_eq!(response.digest, expected_digest);

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_validator_balance_not_found() {
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
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

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
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
namespace = "_SUMMIT"
validator_minimum_stake = 32000000000
validator_maximum_stake = 32000000000
blocks_per_epoch = 10000
allowed_timestamp_future_ms = 10000

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

/// send_genesis must validate before installing: malformed or empty content is
/// rejected, the target path is left untouched (no partial/garbage file that
/// startup would treat as provisioned), and no temp file is left behind.
#[tokio::test]
async fn test_send_genesis_rejects_invalid_content() {
    use summit_rpc::SummitGenesisApiClient;

    for bad_content in [
        "",
        "this is not valid toml",
        "eth_genesis_hash = \"0xdead\"\n",
    ] {
        let temp_dir = create_test_keystore().unwrap();
        let key_store_path = temp_dir.path().to_str().unwrap().to_string();

        let genesis_dir = tempfile::tempdir().unwrap();
        let genesis_path = genesis_dir.path().join("genesis.toml");
        let genesis_path_str = genesis_path.to_str().unwrap().to_string();

        let path_sender = PathSender::new(genesis_path_str, None);
        let (handle, addr) =
            start_rpc_server_for_genesis_with_handle(path_sender, key_store_path, 0)
                .await
                .unwrap();

        let url = format!("http://{}", addr);
        let client = HttpClientBuilder::default().build(&url).unwrap();

        let response = client.send_genesis(bad_content.to_string()).await;
        assert!(
            response.is_err(),
            "sendGenesis should reject invalid content: {bad_content:?}"
        );

        // The target path must not exist — nothing partial/garbage installed.
        assert!(
            !genesis_path.exists(),
            "target genesis path must not be created on invalid content: {bad_content:?}"
        );
        // No staging temp file left behind.
        assert!(
            !genesis_dir.path().join("genesis.toml.tmp").exists(),
            "temp genesis file must be cleaned up on invalid content: {bad_content:?}"
        );

        handle.stop().unwrap();
    }
}

/// The genesis provisioning RPC installs the chain's authoritative identity
/// (namespace, execution genesis hash, validator committee, peer addresses,
/// initial protocol params) before the node finishes startup. It must bind
/// to loopback so a remote caller cannot install genesis on first boot.
#[tokio::test]
async fn test_genesis_rpc_binds_to_loopback() {
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let genesis_dir = tempfile::tempdir().unwrap();
    let genesis_path = genesis_dir.path().join("genesis.toml");
    let genesis_path_str = genesis_path.to_str().unwrap().to_string();

    let path_sender = PathSender::new(genesis_path_str, None);

    let (handle, addr) = start_rpc_server_for_genesis_with_handle(path_sender, key_store_path, 0)
        .await
        .unwrap();

    assert!(
        addr.ip().is_loopback(),
        "genesis RPC must bind to loopback (got {})",
        addr.ip()
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

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_minimum_stake().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 40_000_000_000);

    handle.stop().unwrap();
}

#[cfg(feature = "permissioned")]
#[tokio::test]
async fn test_pause_rejects_invalid_signature() {
    use jsonrpsee::core::client::Error as ClientError;
    use summit_rpc::SummitPermissionedApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();
    let paused = Arc::new(AtomicBool::new(false));

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        paused.clone(),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bogus_sig = format!("0x{}", "ab".repeat(64));
    let err = client.pause(now, bogus_sig).await.unwrap_err();

    match err {
        ClientError::Call(obj) => assert_eq!(obj.code(), 4002),
        other => panic!("expected 4002 InvalidSignature, got {other:?}"),
    }
    assert!(
        !paused.load(std::sync::atomic::Ordering::Relaxed),
        "pause flag must not flip on a rejected request"
    );

    handle.stop().unwrap();
}

#[cfg(feature = "permissioned")]
#[tokio::test]
async fn test_pause_rejects_stale_timestamp() {
    use jsonrpsee::core::client::Error as ClientError;
    use summit_rpc::SummitPermissionedApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();
    let paused = Arc::new(AtomicBool::new(false));

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        paused.clone(),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let stale_ts = 1; // way outside the 30s window
    let sig = format!("0x{}", "ab".repeat(64));
    let err = client.pause(stale_ts, sig).await.unwrap_err();

    match err {
        ClientError::Call(obj) => assert_eq!(obj.code(), 4001),
        other => panic!("expected 4001 TimestampOutOfWindow, got {other:?}"),
    }
    assert!(!paused.load(std::sync::atomic::Ordering::Relaxed));

    handle.stop().unwrap();
}

#[cfg(feature = "permissioned")]
#[tokio::test]
async fn test_is_paused_open_access() {
    use summit_rpc::SummitPermissionedApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    assert!(!client.is_paused().await.unwrap());

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

    let (handle, addr) = start_rpc_server_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let url = format!("http://{}", addr);
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let response = client.get_maximum_stake().await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), 64_000_000_000);

    handle.stop().unwrap();
}

/// `getDepositSignature` signs caller-supplied deposit data with the node's
/// validator private keys. It must not be reachable on the public RPC
/// listener — only on the localhost-bound admin listener — so a network
/// caller can't preemptively register the node's validator identity with
/// attacker-chosen withdrawal credentials.
#[tokio::test]
async fn test_get_deposit_signature_not_on_public_listener() {
    use jsonrpsee::core::ClientError;
    use jsonrpsee::types::error::ErrorCode;
    use summit_rpc::SummitAdminApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let handles = start_rpc_server_pair_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        0,
        None,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    // The public listener must reject `getDepositSignature` with
    // method-not-found — it isn't part of `SummitApi`/`SummitProofApi`.
    let public_url = format!("http://{}", handles.public_addr);
    let public_client = HttpClientBuilder::default().build(&public_url).unwrap();
    let address = format!("0x{}", "a".repeat(40));
    let public_resp = SummitAdminApiClient::get_deposit_signature(
        &public_client,
        32_000_000_000,
        address.clone(),
    )
    .await;

    match public_resp {
        Err(ClientError::Call(err)) => {
            assert_eq!(
                err.code(),
                ErrorCode::MethodNotFound.code(),
                "expected MethodNotFound on the public RPC listener, got {:?}",
                err
            );
        }
        other => panic!(
            "public RPC listener must not serve getDepositSignature; got {:?}",
            other
        ),
    }

    // The admin listener (loopback) must serve `getDepositSignature`.
    let admin_url = format!("http://{}", handles.admin_addr);
    let admin_client = HttpClientBuilder::default().build(&admin_url).unwrap();
    let admin_resp =
        SummitAdminApiClient::get_deposit_signature(&admin_client, 32_000_000_000, address)
            .await
            .expect("admin listener should serve getDepositSignature");
    assert_eq!(admin_resp.node_signature.len(), 64);
    assert_eq!(admin_resp.consensus_signature.len(), 96);

    // Admin listener must be loopback-bound.
    assert!(
        handles.admin_addr.ip().is_loopback(),
        "admin listener must be bound to loopback; bound to {}",
        handles.admin_addr.ip()
    );

    handles.public_handle.stop().unwrap();
    handles.admin_handle.stop().unwrap();
}

/// An observer node's live P2P identity is a child key derived from the
/// master node key; signing a deposit would bind the master validator
/// identity from a process that doesn't represent it. `getDepositSignature`
/// must therefore be rejected in observer mode, even on the admin listener.
#[tokio::test]
async fn test_get_deposit_signature_disabled_in_observer_mode() {
    use jsonrpsee::core::ClientError;
    use summit_rpc::SummitAdminApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();
    let observer_node_key = derive_observer_node_key(&key_store_path, 0);

    let handles = start_rpc_server_pair_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        0,
        Some(observer_node_key),
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let admin_url = format!("http://{}", handles.admin_addr);
    let admin_client = HttpClientBuilder::default().build(&admin_url).unwrap();
    let address = format!("0x{}", "a".repeat(40));
    let resp =
        SummitAdminApiClient::get_deposit_signature(&admin_client, 32_000_000_000, address).await;

    match resp {
        Err(ClientError::Call(err)) => {
            assert_eq!(
                err.code(),
                4003,
                "expected observer-mode rejection (4003), got {:?}",
                err
            );
        }
        other => panic!(
            "observer node must not serve getDepositSignature; got {:?}",
            other
        ),
    }

    handles.public_handle.stop().unwrap();
    handles.admin_handle.stop().unwrap();
}

/// In observer mode `getPublicKeys` must report the derived child key — the
/// node's live P2P transport identity — rather than the master keystore
/// identity, and must leave the consensus key empty so the response can't be
/// read as speaking for the validator's consensus identity.
#[tokio::test]
async fn test_get_public_keys_reports_observer_key_in_observer_mode() {
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();
    let observer_node_key = derive_observer_node_key(&key_store_path, 3);
    let master_node_key = {
        use summit_types::KeyPaths;
        KeyPaths::new(key_store_path.clone())
            .node_public_key()
            .unwrap()
    };

    let handles = start_rpc_server_pair_with_handle(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0,
        0,
        Some(observer_node_key.clone()),
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let public_url = format!("http://{}", handles.public_addr);
    let public_client = HttpClientBuilder::default().build(&public_url).unwrap();
    let keys = SummitApiClient::get_public_keys(&public_client)
        .await
        .expect("observer node should still serve getPublicKeys");
    assert_eq!(
        keys.node, observer_node_key,
        "observer should report its derived transport key"
    );
    assert_ne!(
        keys.node, master_node_key,
        "observer must not report the master node key"
    );
    assert!(
        keys.consensus.is_empty(),
        "observer must not report a consensus key; got {}",
        keys.consensus
    );

    handles.public_handle.stop().unwrap();
    handles.admin_handle.stop().unwrap();
}
