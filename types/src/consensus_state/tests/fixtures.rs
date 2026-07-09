//! Golden-vector tests for the client ↔ consensus deposit-request contract.
//!
//! `types/fixtures/deposit_requests.json` freezes deposit requests with
//! valid Ed25519 + BLS signatures in the exact 288-byte EL wire format that
//! [`DepositRequest::try_from_eth_bytes`] parses. The Seismic client SDKs
//! (seismic monorepo, `clients/`) replay the same vectors against the deposit
//! contract and assert the emitted `DepositEvent` reassembles to
//! `expected_request` byte for byte, so an incompatible change to the wire
//! format, the signing message, or the signature domain breaks a test on
//! whichever side changed.
//!
//! The signature domain folds in the EL genesis hash and the Summit
//! namespace, so the vectors are only valid for the (genesis_hash, namespace)
//! pair recorded in the file. The client tests never verify signatures and
//! are unaffected by the domain; only this crate's tests depend on it.
//!
//! To regenerate after an intentional format change:
//!
//! ```text
//! cargo test -p summit-types regenerate_deposit_request_fixtures -- --ignored
//! ```
//!
//! then re-run the client-side fixture tests against the new file.

use super::super::*;
use super::common::{eth1_credentials, make_signed_deposit};
use crate::account::ValidatorStatus;
use crate::execution_request::DepositRequest;
use crate::{Digest, deposit_signature_domain};

use commonware_codec::{DecodeExt, Write};
use commonware_cryptography::{Signer, bls12381, ed25519};
use commonware_formatting::{from_hex, hex};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Mirrors `node/src/test_harness/common.rs::GENESIS_HASH` so the fixtures
/// use the same mock EL genesis as the rest of the repo's tests.
const FIXTURE_GENESIS_HASH: &str =
    "0x683713729fcb72be6f3d8b88c8cda3e10569d73b9640d3bf6f5184d94bd97616";
const FIXTURE_NAMESPACE: &str = "_SUMMIT";

const MIN_STAKE_GWEI: u64 = 32_000_000_000;
const WARM_UP: u64 = 2;
const WITHDRAWAL_EPOCHS: u64 = 2;

#[derive(Serialize, Deserialize)]
struct FixtureFile {
    description: String,
    genesis_hash: String,
    namespace: String,
    vectors: Vec<FixtureVector>,
}

#[derive(Serialize, Deserialize)]
struct FixtureVector {
    name: String,
    comment: String,
    node_private_key: String,
    bls_private_key: String,
    node_pubkey: String,
    consensus_pubkey: String,
    withdrawal_credentials: String,
    amount_gwei: u64,
    node_signature: String,
    consensus_signature: String,
    index: u64,
    expected_request: String,
}

/// Key seeds, amounts, and indices behind each vector. `index` must match the
/// order the deposit contract would assign when the vectors are submitted in
/// file order onto a fresh contract, since the client tests replay them that
/// way.
struct VectorSpec {
    name: &'static str,
    comment: &'static str,
    node_seed: u64,
    bls_seed: u64,
    credential_byte: u8,
    amount_gwei: u64,
    index: u64,
}

const SPECS: &[VectorSpec] = &[
    VectorSpec {
        name: "new_validator_32eth",
        comment: "Fresh validator depositing exactly the minimum stake; \
                  activates after the warm-up.",
        node_seed: 100,
        bls_seed: 100,
        credential_byte: 0xaa,
        amount_gwei: MIN_STAKE_GWEI,
        index: 0,
    },
    VectorSpec {
        name: "new_validator_1eth_below_min",
        comment: "Fresh validator depositing the contract minimum (1 ETH); \
                  stays Inactive below the minimum stake.",
        node_seed: 200,
        bls_seed: 200,
        credential_byte: 0xbb,
        amount_gwei: 1_000_000_000,
        index: 1,
    },
    VectorSpec {
        name: "top_up_31eth_reaches_min",
        comment: "Top-up for the 1 ETH validator with the same keys; lifts \
                  the balance to the minimum stake.",
        node_seed: 200,
        bls_seed: 200,
        credential_byte: 0xbb,
        amount_gwei: 31_000_000_000,
        index: 2,
    },
];

fn codec_bytes<T: Write>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.write(&mut bytes);
    bytes
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex(bytes))
}

fn unhex(value: &str) -> Vec<u8> {
    from_hex(value).expect("valid fixture hex")
}

fn domain_for(genesis_hash: &str, namespace: &str) -> Digest {
    let genesis_hash: [u8; 32] = unhex(genesis_hash)
        .try_into()
        .expect("genesis hash is 32 bytes");
    deposit_signature_domain(genesis_hash, namespace.as_bytes())
}

fn build_fixture_file() -> FixtureFile {
    let domain = domain_for(FIXTURE_GENESIS_HASH, FIXTURE_NAMESPACE);
    let vectors = SPECS
        .iter()
        .map(|spec| {
            let node_priv = ed25519::PrivateKey::from_seed(spec.node_seed);
            let bls_priv = bls12381::PrivateKey::from_seed(spec.bls_seed);
            let deposit = make_signed_deposit(
                &node_priv,
                &bls_priv,
                eth1_credentials(spec.credential_byte),
                spec.amount_gwei,
                spec.index,
                domain,
            );
            let request_bytes = codec_bytes(&deposit);
            assert_eq!(request_bytes.len(), 288, "deposit request wire size");
            FixtureVector {
                name: spec.name.into(),
                comment: spec.comment.into(),
                node_private_key: hex0x(&codec_bytes(&node_priv)),
                bls_private_key: hex0x(&codec_bytes(&bls_priv)),
                node_pubkey: hex0x(deposit.node_pubkey.as_ref()),
                consensus_pubkey: hex0x(&codec_bytes(&deposit.consensus_pubkey)),
                withdrawal_credentials: hex0x(&deposit.withdrawal_credentials),
                amount_gwei: spec.amount_gwei,
                node_signature: hex0x(&deposit.node_signature),
                consensus_signature: hex0x(&deposit.consensus_signature),
                index: spec.index,
                expected_request: hex0x(&request_bytes),
            }
        })
        .collect();
    FixtureFile {
        description: "Deposit-request golden vectors: 288-byte EL wire format \
                      with valid Ed25519 + BLS signatures over as_message(\
                      deposit_signature_domain(genesis_hash, namespace)). \
                      Consumed by summit-types tests and by the Seismic \
                      client SDK tests (seismic monorepo, clients/). \
                      Regenerate with: cargo test -p summit-types \
                      regenerate_deposit_request_fixtures -- --ignored"
            .into(),
        genesis_hash: FIXTURE_GENESIS_HASH.into(),
        namespace: FIXTURE_NAMESPACE.into(),
        vectors,
    }
}

fn fixture_json(file: &FixtureFile) -> String {
    let mut json = serde_json::to_string_pretty(file).expect("fixture serializes");
    json.push('\n');
    json
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/deposit_requests.json")
}

fn load_fixture_file() -> FixtureFile {
    let json = fs::read_to_string(fixture_path()).expect(
        "fixtures/deposit_requests.json is committed; regenerate with \
         cargo test -p summit-types regenerate_deposit_request_fixtures -- --ignored",
    );
    serde_json::from_str(&json).expect("fixture file parses")
}

fn parse_request(vector: &FixtureVector) -> DepositRequest {
    let bytes = unhex(&vector.expected_request);
    DepositRequest::try_from_eth_bytes(&bytes).expect("frozen request parses")
}

/// Writes the fixture file. Run explicitly after an intentional change to the
/// wire format, signing message, or domain derivation:
/// `cargo test -p summit-types regenerate_deposit_request_fixtures -- --ignored`
#[test]
#[ignore]
fn regenerate_deposit_request_fixtures() {
    let path = fixture_path();
    fs::create_dir_all(path.parent().unwrap()).expect("fixtures dir");
    fs::write(&path, fixture_json(&build_fixture_file())).expect("write fixture file");
}

// The committed file must match what the current code generates. A failure
// means the wire format, signing message, or domain derivation changed:
// regenerate the file (see module docs) and re-run the client-side tests.
#[test]
fn committed_fixtures_match_generator() {
    let committed = fs::read_to_string(fixture_path()).expect(
        "fixtures/deposit_requests.json is committed; regenerate with \
         cargo test -p summit-types regenerate_deposit_request_fixtures -- --ignored",
    );
    assert_eq!(
        committed,
        fixture_json(&build_fixture_file()),
        "committed fixtures diverge from the generator; regenerate and \
         re-run the client-side fixture tests"
    );
}

// Every frozen request parses via try_from_eth_bytes into exactly the fields
// recorded in the file, re-encodes to the same wire bytes, and a block-style
// concatenated payload splits back into the same requests.
#[test]
fn frozen_requests_parse_and_round_trip() {
    let file = load_fixture_file();
    let mut payload = Vec::new();
    for vector in &file.vectors {
        let bytes = unhex(&vector.expected_request);
        assert_eq!(bytes.len(), 288, "{}: wire size", vector.name);
        let parsed = DepositRequest::try_from_eth_bytes(&bytes).expect("parses");

        assert_eq!(
            parsed.node_pubkey.as_ref(),
            &unhex(&vector.node_pubkey)[..],
            "{}: node_pubkey",
            vector.name
        );
        assert_eq!(
            codec_bytes(&parsed.consensus_pubkey),
            unhex(&vector.consensus_pubkey),
            "{}: consensus_pubkey",
            vector.name
        );
        assert_eq!(
            &parsed.withdrawal_credentials[..],
            &unhex(&vector.withdrawal_credentials)[..],
            "{}: withdrawal_credentials",
            vector.name
        );
        assert_eq!(parsed.amount, vector.amount_gwei, "{}: amount", vector.name);
        assert_eq!(
            &parsed.node_signature[..],
            &unhex(&vector.node_signature)[..],
            "{}: node_signature",
            vector.name
        );
        assert_eq!(
            &parsed.consensus_signature[..],
            &unhex(&vector.consensus_signature)[..],
            "{}: consensus_signature",
            vector.name
        );
        assert_eq!(parsed.index, vector.index, "{}: index", vector.name);
        assert_eq!(
            codec_bytes(&parsed),
            bytes,
            "{}: re-encode round-trips",
            vector.name
        );
        payload.extend_from_slice(&bytes);
    }

    let requests = DepositRequest::try_from_eth_entry_bytes(&payload).expect("payload splits");
    assert_eq!(requests.len(), file.vectors.len());
    for (request, vector) in requests.iter().zip(&file.vectors) {
        assert_eq!(
            request.index, vector.index,
            "{}: payload order",
            vector.name
        );
    }
}

// The frozen requests pass signature verification and process into the
// expected validator accounts: the 32 ETH deposit activates, the 1 ETH
// deposit stays inactive until its top-up lifts it to the minimum stake.
#[test]
fn frozen_requests_verify_and_process() {
    let file = load_fixture_file();
    let domain = domain_for(&file.genesis_hash, &file.namespace);
    let requests: Vec<DepositRequest> = file.vectors.iter().map(parse_request).collect();

    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN_STAKE_GWEI);
    state.set_max_deposits_per_epoch(16);

    // The new-validator vectors verify against an empty state.
    assert_eq!(state.verify_deposit_request(&requests[0], domain), Ok(()));
    assert_eq!(state.verify_deposit_request(&requests[1], domain), Ok(()));

    for request in &requests {
        state.push_deposit(request.clone());
    }
    state.process_deposits(domain, WARM_UP, WITHDRAWAL_EPOCHS);

    let key0: [u8; 32] = requests[0].node_pubkey.as_ref().try_into().unwrap();
    let account = state.get_account(&key0).expect("32 ETH validator account");
    assert_eq!(account.balance, MIN_STAKE_GWEI);
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.joining_epoch, WARM_UP);
    assert_eq!(account.last_deposit_index, 0);

    let key1: [u8; 32] = requests[1].node_pubkey.as_ref().try_into().unwrap();
    let account = state
        .get_account(&key1)
        .expect("topped-up validator account");
    assert_eq!(account.balance, MIN_STAKE_GWEI);
    assert_eq!(account.status, ValidatorStatus::Joining);
    assert_eq!(account.last_deposit_index, 2);

    // The top-up still verifies now that its account exists (same BLS key).
    assert_eq!(state.verify_deposit_request(&requests[2], domain), Ok(()));
}

// Mutations of the frozen bytes are rejected with the expected reason, and
// the index bytes are provably outside the signed message.
#[test]
fn mutated_frozen_requests_are_rejected() {
    let file = load_fixture_file();
    let domain = domain_for(&file.genesis_hash, &file.namespace);
    let base = unhex(&file.vectors[0].expected_request);
    let state = ConsensusState::default();

    // Wire offsets per try_from_eth_bytes: amount@112, node_signature@120,
    // consensus_signature@184, index@280.
    let mut corrupt_node_sig = base.clone();
    corrupt_node_sig[120] ^= 0x01;
    let request = DepositRequest::try_from_eth_bytes(&corrupt_node_sig).unwrap();
    assert_eq!(
        state.verify_deposit_request(&request, domain),
        Err(DepositRejectionReason::InvalidNodeSignature)
    );

    let mut corrupt_consensus_sig = base.clone();
    corrupt_consensus_sig[184] ^= 0x01;
    let request = DepositRequest::try_from_eth_bytes(&corrupt_consensus_sig).unwrap();
    assert_eq!(
        state.verify_deposit_request(&request, domain),
        Err(DepositRejectionReason::InvalidConsensusSignature)
    );

    // The amount is covered by both signatures; the node signature is checked
    // first, so that is the reported reason.
    let mut corrupt_amount = base.clone();
    corrupt_amount[112] ^= 0x01;
    let request = DepositRequest::try_from_eth_bytes(&corrupt_amount).unwrap();
    assert_eq!(
        state.verify_deposit_request(&request, domain),
        Err(DepositRejectionReason::InvalidNodeSignature)
    );

    // The index is assigned by the deposit contract after signing, so it is
    // deliberately outside the signed message.
    let mut changed_index = base.clone();
    changed_index[280] ^= 0x01;
    let request = DepositRequest::try_from_eth_bytes(&changed_index).unwrap();
    assert_eq!(state.verify_deposit_request(&request, domain), Ok(()));

    assert!(DepositRequest::try_from_eth_bytes(&base[..287]).is_err());
    assert!(DepositRequest::try_from_eth_entry_bytes(&base[..287]).is_err());

    // A deposit signed with vector 0's BLS key under a different node key is
    // a consensus-key theft attempt once vector 0's account exists.
    let mut state = ConsensusState::default();
    state.set_minimum_stake(MIN_STAKE_GWEI);
    state.set_max_deposits_per_epoch(16);
    state.push_deposit(parse_request(&file.vectors[0]));
    state.process_deposits(domain, WARM_UP, WITHDRAWAL_EPOCHS);

    let other_node = ed25519::PrivateKey::from_seed(9999);
    let bls_priv = bls12381::PrivateKey::decode(&unhex(&file.vectors[0].bls_private_key)[..])
        .expect("fixture BLS private key decodes");
    let theft = make_signed_deposit(
        &other_node,
        &bls_priv,
        eth1_credentials(0xcc),
        MIN_STAKE_GWEI,
        3,
        domain,
    );
    assert_eq!(
        state.verify_deposit_request(&theft, domain),
        Err(DepositRejectionReason::KeyMismatch)
    );
}
