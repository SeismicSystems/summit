use super::super::*;

use alloy_primitives::Address;
use commonware_codec::{DecodeExt, Encode, ReadExt};
use commonware_consensus::types::{Epoch, Epocher, Height};
use commonware_cryptography::{Signer, bls12381, ed25519};

use super::common::*;

#[test]
fn test_read_truncated_input_returns_err() {
    // Empty buffer — must not panic.
    let empty: &[u8] = &[];
    assert!(matches!(
        ConsensusState::read(&mut empty.as_ref()),
        Err(Error::EndOfBuffer)
    ));

    // Arbitrary short prefixes: each must return EndOfBuffer (not panic).
    for n in 0..64 {
        let data = vec![0xABu8; n];
        let res = ConsensusState::read(&mut data.as_ref());
        assert!(
            res.is_err(),
            "{n}-byte prefix should not successfully decode",
        );
    }
}

#[test]
fn test_serialization_deserialization_empty() {
    let original_state = ConsensusState::default();

    let mut encoded = original_state.encode();
    let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

    assert_eq!(decoded_state.epoch, original_state.epoch);
    assert_eq!(decoded_state.view, original_state.view);
    assert_eq!(decoded_state.latest_height, original_state.latest_height);
    assert_eq!(
        decoded_state.invalid_deposit_tax,
        original_state.invalid_deposit_tax
    );
    assert_eq!(
        decoded_state.get_next_withdrawal_index(),
        original_state.get_next_withdrawal_index()
    );
    assert_eq!(
        decoded_state.deposit_queue.len(),
        original_state.deposit_queue.len()
    );
    assert_eq!(
        decoded_state.withdrawal_queue,
        original_state.withdrawal_queue
    );
    assert_eq!(
        decoded_state.validator_accounts.len(),
        original_state.validator_accounts.len()
    );
    assert_eq!(
        decoded_state.epoch_genesis_hash,
        original_state.epoch_genesis_hash
    );
    assert_eq!(
        decoded_state.get_minimum_validator_count(),
        DEFAULT_MINIMUM_VALIDATOR_COUNT
    );
    assert_eq!(decoded_state.get_pending_active_validator_exits(), 0);
}

#[test]
fn test_serialization_deserialization_populated() {
    let mut original_state = ConsensusState::new(
        ForkchoiceState::default(),
        0,
        NonZeroU64::new(100).unwrap(),
        10_000,
        Address::ZERO,
        3,
        16,
        0,
        DEFAULT_MINIMUM_VALIDATOR_COUNT,
        0,
        3,
    );

    original_state.set_epoch(7);
    original_state.get_epocher().advance_epoch(Epoch::new(0));
    original_state
        .get_epocher()
        .update_length(NonZeroU64::new(200).unwrap())
        .unwrap();
    original_state.get_epocher().advance_epoch(Epoch::new(7));
    original_state.set_view(123);
    original_state.set_latest_height(42);
    original_state.set_next_withdrawal_index(5);
    original_state.set_epoch_genesis_hash([42u8; 32]);
    original_state.set_invalid_deposit_tax(25);

    let deposit1 = create_test_deposit_request(1, 32000000000);
    let deposit2 = create_test_deposit_request(2, 16000000000);
    original_state.push_deposit(deposit1);
    original_state.push_deposit(deposit2);

    let withdrawal1 = create_test_withdrawal(1, 16000000000, 10);
    let withdrawal2 = create_test_withdrawal(2, 24000000000, 11);
    original_state.push_withdrawal(withdrawal1);
    original_state.push_withdrawal(withdrawal2);

    // Add protocol param changes
    original_state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
        40_000_000_000,
    ));
    original_state
        .push_protocol_param_change(crate::protocol_params::ProtocolParam::EpochLength(500));

    let pubkey1 = [1u8; 32];
    let pubkey2 = [2u8; 32];
    let account1 = create_test_validator_account(1, 32000000000);
    let account2 = create_test_validator_account(2, 64000000000);
    original_state.set_account(pubkey1, account1);
    original_state.set_account(pubkey2, account2);

    // Add validators scheduled for future epochs
    let validator1 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(10).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
    };
    let validator2 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(20).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
    };
    let validator3 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(30).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(30).public_key(),
    };
    let validator4 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(40).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(40).public_key(),
    };

    // Schedule validators for epoch 9 (current epoch + 2)
    original_state.add_validator(9, validator1.clone());
    original_state.add_validator(9, validator2.clone());

    // Schedule validators for epoch 10
    original_state.add_validator(10, validator3.clone());

    // Schedule validators for epoch 11
    original_state.add_validator(11, validator4.clone());

    let mut encoded = original_state.encode();
    let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

    assert_eq!(decoded_state.epoch, original_state.epoch);
    assert_eq!(decoded_state.view, original_state.view);
    assert_eq!(decoded_state.latest_height, original_state.latest_height);
    assert_eq!(
        decoded_state.get_next_withdrawal_index(),
        original_state.get_next_withdrawal_index()
    );
    assert_eq!(
        decoded_state.epoch_genesis_hash,
        original_state.epoch_genesis_hash
    );

    assert_eq!(decoded_state.deposit_queue.len(), 2);
    assert_eq!(decoded_state.deposit_queue[0].amount, 32000000000);
    assert_eq!(decoded_state.deposit_queue[1].amount, 16000000000);

    // Check withdrawal_queue - two distinct scheduled epochs
    assert_eq!(decoded_state.withdrawal_queue.num_epochs(), 2);

    // At epoch 10, only the epoch-10 withdrawal is due (earliest epoch <= 10).
    let epoch10_withdrawals = decoded_state.get_withdrawals_for_epoch(10);
    assert_eq!(epoch10_withdrawals.len(), 1);
    assert_eq!(epoch10_withdrawals[0].inner.index, 1);
    assert_eq!(epoch10_withdrawals[0].inner.amount, 16000000000);

    // By epoch 11 both are due (earliest epoch <= 11), in queue order.
    let epoch11_withdrawals = decoded_state.get_withdrawals_for_epoch(11);
    assert_eq!(epoch11_withdrawals.len(), 2);
    assert_eq!(epoch11_withdrawals[1].inner.index, 2);
    assert_eq!(epoch11_withdrawals[1].inner.amount, 24000000000);

    // Verify protocol_param_changes
    assert_eq!(decoded_state.protocol_param_changes.len(), 2);
    match &decoded_state.protocol_param_changes[0] {
        crate::protocol_params::ProtocolParam::MinimumStake(value) => {
            assert_eq!(*value, 40_000_000_000)
        }
        _ => panic!("Expected MinimumStake variant"),
    }
    match &decoded_state.protocol_param_changes[1] {
        crate::protocol_params::ProtocolParam::EpochLength(value) => {
            assert_eq!(*value, 500)
        }
        _ => panic!("Expected EpochLength variant"),
    }

    assert_eq!(decoded_state.validator_accounts.len(), 2);
    let decoded_account1 = decoded_state.validator_accounts.get(&pubkey1).unwrap();
    assert_eq!(decoded_account1.balance, 32000000000);
    assert_eq!(decoded_account1.last_deposit_index, 1);
    let decoded_account2 = decoded_state.validator_accounts.get(&pubkey2).unwrap();
    assert_eq!(decoded_account2.balance, 64000000000);
    assert_eq!(decoded_account2.last_deposit_index, 2);

    // Verify added_validators
    assert_eq!(decoded_state.added_validators.len(), 3);

    // Check epoch 9 has 2 validators
    let epoch9_validators = decoded_state.get_added_validators(9).unwrap();
    assert_eq!(epoch9_validators.len(), 2);

    // Check epoch 10 has 1 validator
    let epoch10_validators = decoded_state.get_added_validators(10).unwrap();
    assert_eq!(epoch10_validators.len(), 1);

    // Check epoch 11 has 1 validator
    let epoch11_validators = decoded_state.get_added_validators(11).unwrap();
    assert_eq!(epoch11_validators.len(), 1);

    // Check that epoch 8 returns None (no validators scheduled)
    assert!(decoded_state.get_added_validators(8).is_none());

    // Verify epocher round-trips correctly
    let epocher = decoded_state.get_epocher();
    assert_eq!(epocher.current_length(), 200);
    // Epoch 0-1: length 100, epoch 2+: length 200
    assert_eq!(epocher.first(Epoch::new(0)), Some(Height::new(0)));
    assert_eq!(epocher.last(Epoch::new(1)), Some(Height::new(199)));
    assert_eq!(epocher.first(Epoch::new(2)), Some(Height::new(200)));
    assert_eq!(epocher.last(Epoch::new(2)), Some(Height::new(399)));
}

#[test]
fn test_encode_size_accuracy() {
    let mut state = ConsensusState::default();

    state.set_epoch(3);
    state.set_view(456);
    state.set_latest_height(42);
    state.set_next_withdrawal_index(5);

    let deposit = create_test_deposit_request(1, 32000000000);
    state.push_deposit(deposit);

    let withdrawal = create_test_withdrawal(1, 16000000000, 5);
    state.push_withdrawal(withdrawal);

    // Add protocol param changes
    state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
        50_000_000_000,
    ));

    let pubkey = [1u8; 32];
    let account = create_test_validator_account(1, 32000000000);
    state.set_account(pubkey, account);

    // Add validators scheduled for future epochs
    let validator1 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(10).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(10).public_key(),
    };
    let validator2 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(20).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(20).public_key(),
    };
    let validator3 = AddedValidator {
        node_key: ed25519::PrivateKey::from_seed(30).public_key(),
        consensus_key: bls12381::PrivateKey::from_seed(30).public_key(),
    };

    state.add_validator(5, validator1.clone());
    state.add_validator(6, validator2.clone());
    state.add_validator(6, validator3.clone());

    let predicted_size = state.encode_size();
    let actual_encoded = state.encode();
    let actual_size = actual_encoded.len();

    assert_eq!(predicted_size, actual_size);
}

#[test]
fn test_protocol_param_changes_serialization() {
    let mut state = ConsensusState::default();

    // Add various protocol param changes
    state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
        32_000_000_000,
    ));
    state.push_protocol_param_change(crate::protocol_params::ProtocolParam::EpochLength(64));
    state.push_protocol_param_change(crate::protocol_params::ProtocolParam::MinimumStake(
        40_000_000_000,
    ));

    let mut encoded = state.encode();
    let decoded_state = ConsensusState::decode(&mut encoded).expect("Failed to decode");

    assert_eq!(
        decoded_state.protocol_param_changes.len(),
        state.protocol_param_changes.len()
    );
    assert_eq!(decoded_state.protocol_param_changes.len(), 3);

    match &decoded_state.protocol_param_changes[0] {
        crate::protocol_params::ProtocolParam::MinimumStake(value) => {
            assert_eq!(*value, 32_000_000_000)
        }
        _ => panic!("Expected MinimumStake variant"),
    }

    match &decoded_state.protocol_param_changes[1] {
        crate::protocol_params::ProtocolParam::EpochLength(value) => {
            assert_eq!(*value, 64)
        }
        _ => panic!("Expected EpochLength variant"),
    }

    match &decoded_state.protocol_param_changes[2] {
        crate::protocol_params::ProtocolParam::MinimumStake(value) => {
            assert_eq!(*value, 40_000_000_000)
        }
        _ => panic!("Expected MinimumStake variant"),
    }

    // Verify encode_size is correct
    let predicted_size = state.encode_size();
    let actual_size = state.encode().len();
    assert_eq!(predicted_size, actual_size);
}

#[test]
fn test_decode_rejects_out_of_range_max_withdrawals_per_epoch() {
    use crate::protocol_params::{MAX_WITHDRAWALS_PER_EPOCH_MAX, MAX_WITHDRAWALS_PER_EPOCH_MIN};

    // Honest nodes only ever serialize a cap within [MIN, MAX] — genesis and
    // runtime updates both range-check it. A decoded state outside that range
    // can only come from a crafted checkpoint/state artifact or a tampered DB
    // blob. The finalizer trusts this cap as authoritative (a zero cap silently
    // drops every due withdrawal), so decoding must reject it rather than let
    // the node start/restore from it.

    // Valid boundary values must still decode.
    for valid in [MAX_WITHDRAWALS_PER_EPOCH_MIN, MAX_WITHDRAWALS_PER_EPOCH_MAX] {
        let mut state = ConsensusState::default();
        state.max_withdrawals_per_epoch = valid;
        let encoded = state.encode();
        let decoded = ConsensusState::read(&mut encoded.as_ref())
            .unwrap_or_else(|_| panic!("valid max_withdrawals_per_epoch {valid} should decode"));
        assert_eq!(decoded.max_withdrawals_per_epoch, valid);
    }

    // Out-of-range values (0 below MIN, MAX+1 above MAX) must be rejected.
    for invalid in [0, MAX_WITHDRAWALS_PER_EPOCH_MAX + 1] {
        let mut state = ConsensusState::default();
        state.max_withdrawals_per_epoch = invalid;
        let encoded = state.encode();
        assert!(
            ConsensusState::read(&mut encoded.as_ref()).is_err(),
            "max_withdrawals_per_epoch {invalid} should be rejected on decode"
        );
    }
}

#[test]
fn test_decode_rejects_out_of_range_max_pending_withdrawals_per_validator() {
    use crate::protocol_params::{
        MAX_PENDING_WITHDRAWALS_PER_VALIDATOR_MAX, MAX_PENDING_WITHDRAWALS_PER_VALIDATOR_MIN,
    };

    // Genesis and runtime updates bound the per-validator cap to [MIN, MAX];
    // a decoded value outside that range can only come from a crafted or
    // tampered artifact. A zero cap would silently drop every withdrawal
    // request, including full exits, so decode must reject it.
    for valid in [
        MAX_PENDING_WITHDRAWALS_PER_VALIDATOR_MIN,
        MAX_PENDING_WITHDRAWALS_PER_VALIDATOR_MAX,
    ] {
        let mut state = ConsensusState::default();
        state.max_pending_withdrawals_per_validator = valid;
        let encoded = state.encode();
        let decoded = ConsensusState::read(&mut encoded.as_ref()).unwrap_or_else(|_| {
            panic!("valid max_pending_withdrawals_per_validator {valid} should decode")
        });
        assert_eq!(decoded.max_pending_withdrawals_per_validator, valid);
    }

    for invalid in [0, MAX_PENDING_WITHDRAWALS_PER_VALIDATOR_MAX + 1] {
        let mut state = ConsensusState::default();
        state.max_pending_withdrawals_per_validator = invalid;
        let encoded = state.encode();
        assert!(
            ConsensusState::read(&mut encoded.as_ref()).is_err(),
            "max_pending_withdrawals_per_validator {invalid} should be rejected on decode"
        );
    }
}

#[test]
fn test_decode_rejects_out_of_range_max_deposits_per_epoch() {
    // Genesis and runtime updates cap deposits at MAX_MAX_DEPOSITS_PER_EPOCH;
    // a decoded cap above it can only come from a crafted/tampered artifact and
    // would let the penultimate-block selector admit more deposits than policy
    // allows, so decode must reject it.
    use crate::protocol_params::{MAX_MAX_DEPOSITS_PER_EPOCH, MIN_MAX_DEPOSITS_PER_EPOCH};

    for valid in [MIN_MAX_DEPOSITS_PER_EPOCH, MAX_MAX_DEPOSITS_PER_EPOCH] {
        let mut state = ConsensusState::default();
        state.max_deposits_per_epoch = valid;
        let encoded = state.encode();
        let decoded = ConsensusState::read(&mut encoded.as_ref())
            .unwrap_or_else(|_| panic!("valid max_deposits_per_epoch {valid} should decode"));
        assert_eq!(decoded.max_deposits_per_epoch, valid);
    }

    let mut state = ConsensusState::default();
    state.max_deposits_per_epoch = MAX_MAX_DEPOSITS_PER_EPOCH + 1;
    let encoded = state.encode();
    assert!(
        ConsensusState::read(&mut encoded.as_ref()).is_err(),
        "oversized max_deposits_per_epoch should be rejected on decode"
    );
}

#[test]
fn test_decode_rejects_out_of_range_allowed_timestamp_future_ms() {
    // The timestamp tolerance gates block-validity; genesis and runtime updates
    // bound it to [MIN, MAX]. An out-of-range window from a crafted/tampered
    // artifact would put a booting node's clock tolerance outside policy.
    use crate::protocol_params::{
        MAX_ALLOWED_TIMESTAMP_FUTURE_MS, MIN_ALLOWED_TIMESTAMP_FUTURE_MS,
    };

    for valid in [
        MIN_ALLOWED_TIMESTAMP_FUTURE_MS,
        MAX_ALLOWED_TIMESTAMP_FUTURE_MS,
    ] {
        let mut state = ConsensusState::default();
        state.allowed_timestamp_future_ms = valid;
        let encoded = state.encode();
        let decoded = ConsensusState::read(&mut encoded.as_ref())
            .unwrap_or_else(|_| panic!("valid allowed_timestamp_future_ms {valid} should decode"));
        assert_eq!(decoded.allowed_timestamp_future_ms, valid);
    }

    for invalid in [
        MIN_ALLOWED_TIMESTAMP_FUTURE_MS - 1,
        MAX_ALLOWED_TIMESTAMP_FUTURE_MS + 1,
    ] {
        let mut state = ConsensusState::default();
        state.allowed_timestamp_future_ms = invalid;
        let encoded = state.encode();
        assert!(
            ConsensusState::read(&mut encoded.as_ref()).is_err(),
            "allowed_timestamp_future_ms {invalid} should be rejected on decode"
        );
    }
}

#[test]
fn test_decode_rejects_out_of_range_observers_per_validator() {
    // Genesis and runtime updates cap observers at MAX_OBSERVERS_PER_VALIDATOR;
    // a decoded value above it can only come from a crafted/tampered artifact.
    use crate::protocol_params::MAX_OBSERVERS_PER_VALIDATOR;

    for valid in [0u32, MAX_OBSERVERS_PER_VALIDATOR as u32] {
        let mut state = ConsensusState::default();
        state.observers_per_validator = valid;
        let encoded = state.encode();
        let decoded = ConsensusState::read(&mut encoded.as_ref())
            .unwrap_or_else(|_| panic!("valid observers_per_validator {valid} should decode"));
        assert_eq!(decoded.observers_per_validator, valid);
    }

    let mut state = ConsensusState::default();
    state.observers_per_validator = MAX_OBSERVERS_PER_VALIDATOR as u32 + 1;
    let encoded = state.encode();
    assert!(
        ConsensusState::read(&mut encoded.as_ref()).is_err(),
        "oversized observers_per_validator should be rejected on decode"
    );
}
