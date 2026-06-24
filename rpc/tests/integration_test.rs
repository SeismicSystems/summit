mod utils;

use jsonrpsee::http_client::HttpClientBuilder;
#[cfg(feature = "permissioned")]
use std::sync::Arc;
#[cfg(feature = "permissioned")]
use std::sync::atomic::AtomicBool;
use summit_rpc::{
    PathSender, start_rpc_server_for_genesis_with_handle, start_rpc_server_pair_with_handle,
    start_rpc_server_with_handle, start_rpc_server_with_handle_and_batch_limit,
};
use utils::{
    MockFinalizerState, create_gated_proof_mailbox, create_test_finalized_header,
    create_test_finalizer_mailbox, create_test_keystore,
};

const TEST_GENESIS_HASH: [u8; 32] = [7u8; 32];

/// Derives the observer child public key (hex) the way the node does in
/// observer mode, so tests can assert the RPC reports it as the live identity.
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
async fn test_get_state_proof_rejects_too_many_keys() {
    use jsonrpsee::core::client::Error as ClientError;
    use summit_rpc::SummitProofApiClient;

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

    let keys = vec!["epoch".to_string(); 129];
    let err = client.get_state_proof(keys).await.unwrap_err();

    match err {
        ClientError::Call(obj) => assert_eq!(obj.code(), 3005),
        other => panic!("expected 3005 StateProofKeyLimit, got {other:?}"),
    }

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_get_state_proof_rejects_excessive_cost() {
    use jsonrpsee::core::client::Error as ClientError;
    use summit_rpc::SummitProofApiClient;

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

    let validator_key = format!("validator_field:0x{}:balance", "01".repeat(32));
    let keys = vec![validator_key; 65];
    let err = client.get_state_proof(keys).await.unwrap_err();

    match err {
        ClientError::Call(obj) => assert_eq!(obj.code(), 3006),
        other => panic!("expected 3006 StateProofCostLimit, got {other:?}"),
    }

    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_get_state_proof_concurrency_cap_rejects_excess() {
    use futures::StreamExt as _;
    use jsonrpsee::core::client::Error as ClientError;
    use summit_rpc::{MAX_CONCURRENT_STATE_PROOFS, SummitProofApiClient};

    // Gated mock: holds every proof generation open until we release, so we can
    // pin `cap` requests in flight simultaneously and observe the cap engaging.
    let (mailbox, _received, release_tx, _mock) = create_gated_proof_mailbox();
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
    let cap = MAX_CONCURRENT_STATE_PROOFS;
    let extra = 5;

    // Fire cap + extra concurrent proof requests (one cheap scalar key each, well
    // within the per-request limits). The gated mock never responds until we
    // release, so the first `cap` hold their concurrency slots and the remaining
    // `extra` must be rejected with the busy error (3007). No slot is freed before
    // release, so the split is deterministic.
    let (tx, mut rx) = futures::channel::mpsc::unbounded();
    for _ in 0..(cap + extra) {
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = client.get_state_proof(vec!["epoch".to_string()]).await;
            let _ = tx.unbounded_send(res);
        });
    }
    drop(tx);

    let mut busy = 0usize;
    let mut accepted = 0usize;
    let mut release_tx = Some(release_tx);
    while let Some(res) = rx.next().await {
        match res {
            Ok(_) => accepted += 1,
            Err(ClientError::Call(obj)) => {
                assert_eq!(
                    obj.code(),
                    3007,
                    "over-cap request must be rejected as busy"
                );
                busy += 1;
            }
            Err(other) => panic!("unexpected client error: {other:?}"),
        }
        // Once every over-cap request has been rejected, the `cap` accepted ones
        // are confirmed holding their slots in flight; release them to complete.
        if busy == extra {
            if let Some(tx) = release_tx.take() {
                let _ = tx.send(());
            }
        }
    }

    assert_eq!(busy, extra, "exactly the over-cap requests are rejected");
    assert_eq!(
        accepted, cap,
        "exactly the cap is accepted concurrently before release"
    );

    handle.stop().unwrap();
}

// The concurrency permit must be released when the proof task finishes, not
// when the RPC handler future is dropped. Otherwise a caller could connect,
// wait for the proof task to be spawned, disconnect to free the slot while the
// detached proof work keeps running, and repeat to pile up real work under a
// slot count that reads as idle. This drives the handler future directly,
// cancels it after the proof task is spawned, and asserts the slot stays held
// until the gated proof task completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_get_state_proof_permit_outlives_cancelled_request() {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use summit_rpc::{MAX_CONCURRENT_STATE_PROOFS, SummitProofApiServer, SummitRpcServer};

    // Gated mock holds every proof task open, including the permit handed to it,
    // until we release.
    let (mailbox, received, release_tx, _mock) = create_gated_proof_mailbox();
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let server = SummitRpcServer::new(
        key_store_path,
        mailbox,
        TEST_GENESIS_HASH,
        b"_SUMMIT",
        None,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    );

    let cap = MAX_CONCURRENT_STATE_PROOFS;

    // Keep cap - 1 proof requests in flight, held open by the gated mock.
    let mut held = Vec::new();
    for _ in 0..(cap - 1) {
        let server = server.clone();
        held.push(tokio::spawn(async move {
            let _ = server.get_state_proof(vec!["epoch".to_string()]).await;
        }));
    }

    // Start the cap-th request; it acquires the last slot and hands its permit
    // to the (gated) proof task.
    let cancel = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.get_state_proof(vec!["epoch".to_string()]).await;
        })
    };

    // Wait until every request has reached the mock, so all cap slots are
    // acquired and all permits are now owned by the mock's detached tasks.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.load(Ordering::SeqCst) < cap {
        assert!(
            tokio::time::Instant::now() < deadline,
            "proof tasks were never spawned"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Cancel the cap-th request's handler future (the client-disconnect path).
    cancel.abort();
    let _ = cancel.await;

    // The slot must still be held: it belongs to the cancelled request's proof
    // task, which is still gated. A fresh request is rejected as busy and
    // returns immediately. If cancellation had leaked the slot back, the fresh
    // request would instead be accepted and block on the gated mock until the
    // timeout fires.
    let fresh = tokio::time::timeout(
        Duration::from_secs(2),
        server.get_state_proof(vec!["epoch".to_string()]),
    )
    .await;
    match fresh {
        Ok(Err(obj)) => assert_eq!(
            obj.code(),
            3007,
            "cancelled request must keep holding its slot until the proof task completes"
        ),
        Ok(Ok(_)) => {
            panic!("fresh request was accepted: a cancelled request freed its slot early")
        }
        Err(_) => panic!(
            "fresh request blocked on the gated mock: the cancelled request's slot was freed while its proof task is still running"
        ),
    }

    // Release every gated task; permits drop as the tasks complete, freeing
    // slots.
    let _ = release_tx.send(());
    for h in held {
        let _ = h.await;
    }

    // A fresh request now succeeds, proving the permits were released when the
    // proof tasks finished rather than lost.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match server.get_state_proof(vec!["epoch".to_string()]).await {
            Ok(_) => break,
            Err(obj) => {
                assert_eq!(obj.code(), 3007, "unexpected error while draining slots");
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "slots were never freed after the proof tasks completed"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
}

#[tokio::test]
async fn test_oversized_batch_is_rejected() {
    // The server caps JSON-RPC batch size (default DEFAULT_RPC_MAX_BATCH_SIZE).
    // jsonrpsee defaults to unlimited, which lets one request fan out into very
    // many expensive calls; a batch over the limit must be rejected, while a
    // batch within the limit still works.
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::core::params::BatchRequestBuilder;
    use summit_rpc::DEFAULT_RPC_MAX_BATCH_SIZE;

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

    let client = HttpClientBuilder::default()
        .build(format!("http://{addr}"))
        .unwrap();

    // Within the limit: succeeds.
    let mut ok_batch = BatchRequestBuilder::new();
    for _ in 0..10 {
        ok_batch.insert("health", jsonrpsee::rpc_params![]).unwrap();
    }
    assert!(
        client.batch_request::<String>(ok_batch).await.is_ok(),
        "a batch within the limit must be served"
    );

    // Over the limit: rejected.
    let mut big_batch = BatchRequestBuilder::new();
    for _ in 0..(DEFAULT_RPC_MAX_BATCH_SIZE as usize + 1) {
        big_batch
            .insert("health", jsonrpsee::rpc_params![])
            .unwrap();
    }
    assert!(
        client.batch_request::<String>(big_batch).await.is_err(),
        "a batch exceeding the configured limit must be rejected"
    );

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_batch_disabled_rejects_all_batches() {
    // max_batch_size = 0 disables batching entirely: even a single-call batch is
    // rejected, while plain (non-batch) requests still work.
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::core::params::BatchRequestBuilder;
    use summit_rpc::SummitApiClient;

    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle_and_batch_limit(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0, // port
        0, // max_batch_size = 0 -> batching disabled
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let client = HttpClientBuilder::default()
        .build(format!("http://{addr}"))
        .unwrap();

    // A plain (non-batch) request is still served.
    assert!(
        client.health().await.is_ok(),
        "non-batch requests must still work when batching is disabled"
    );

    // Even a single-call batch is rejected.
    let mut batch = BatchRequestBuilder::new();
    batch.insert("health", jsonrpsee::rpc_params![]).unwrap();
    assert!(
        ClientT::batch_request::<String>(&client, batch)
            .await
            .is_err(),
        "any batch must be rejected when max_batch_size = 0"
    );

    handle.stop().unwrap();
}

#[tokio::test]
async fn test_custom_batch_limit_is_honored() {
    // A non-default configured limit is honored independently of
    // DEFAULT_RPC_MAX_BATCH_SIZE: a batch at the limit is served, one over it
    // is rejected.
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::core::params::BatchRequestBuilder;

    let limit: u32 = 3;
    let (mailbox, _finalizer_handle) = create_test_finalizer_mailbox(MockFinalizerState::default());
    let temp_dir = create_test_keystore().unwrap();
    let key_store_path = temp_dir.path().to_str().unwrap().to_string();

    let (handle, addr) = start_rpc_server_with_handle_and_batch_limit(
        mailbox,
        key_store_path,
        TEST_GENESIS_HASH,
        b"_SUMMIT".to_vec(),
        0, // port
        limit,
        #[cfg(feature = "permissioned")]
        Arc::new(AtomicBool::new(false)),
    )
    .await
    .unwrap();

    let client = HttpClientBuilder::default()
        .build(format!("http://{addr}"))
        .unwrap();

    // Exactly at the limit: served.
    let mut at_limit = BatchRequestBuilder::new();
    for _ in 0..limit {
        at_limit.insert("health", jsonrpsee::rpc_params![]).unwrap();
    }
    assert!(
        client.batch_request::<String>(at_limit).await.is_ok(),
        "a batch at the configured limit must be served"
    );

    // One over the limit: rejected.
    let mut over_limit = BatchRequestBuilder::new();
    for _ in 0..(limit + 1) {
        over_limit
            .insert("health", jsonrpsee::rpc_params![])
            .unwrap();
    }
    assert!(
        client.batch_request::<String>(over_limit).await.is_err(),
        "a batch exceeding the configured limit must be rejected"
    );

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

#[tokio::test]
async fn test_websocket_upgrades_are_rejected() {
    // The RPC server is http-only: Summit's API is request/response (no
    // subscriptions). Disabling websocket upgrades closes the idle-connection
    // permit-exhaustion vector (jsonrpsee enables websockets with pings off by
    // default, so idle upgraded connections would hold their max_connections
    // permit indefinitely). HTTP must still work; websocket connects must fail.
    use jsonrpsee::ws_client::WsClientBuilder;
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

    // HTTP still works.
    let http = HttpClientBuilder::default()
        .build(format!("http://{addr}"))
        .unwrap();
    assert_eq!(http.health().await.unwrap(), "Ok");

    // Websocket upgrade is refused, so idle WS connections cannot be opened.
    let ws = WsClientBuilder::default()
        .build(format!("ws://{addr}"))
        .await;
    assert!(
        ws.is_err(),
        "websocket upgrade must be rejected when the server is http-only"
    );

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

/// In observer mode `getDepositSignature` must be rejected even on the admin
/// listener: the observer runs a derived child key, not the master node key,
/// so signing a deposit would bind the master validator identity from a
/// process that doesn't represent it.
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
