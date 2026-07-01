use super::super::*;
use super::common::*;
use crate::PublicKey;
use crate::account::ValidatorStatus;
use crate::execution_request::WithdrawalRequest;
use crate::header::AddedValidator;
use crate::protocol_params::ProtocolParam;
use alloy_primitives::Address;
use commonware_codec::DecodeExt;
use commonware_cryptography::{Signer, bls12381, ed25519};

// Add an active validator keyed by a real ed25519 public key (arbitrary [n; 32]
// byte patterns are not all valid curve points). Returns the account key.
fn add_active(state: &mut ConsensusState, seed: u64, balance: u64) -> [u8; 32] {
    let key: [u8; 32] = ed25519::PrivateKey::from_seed(seed)
        .public_key()
        .as_ref()
        .try_into()
        .unwrap();
    state.set_account(key, create_test_validator_account(1, balance));
    key
}

// Add a joining validator (status Joining, activation scheduled for
// `joining_epoch`) keyed by a real ed25519 public key. Returns the account key.
fn add_joining(
    state: &mut ConsensusState,
    seed: u64,
    balance: u64,
    joining_epoch: u64,
) -> [u8; 32] {
    let node_key = ed25519::PrivateKey::from_seed(seed).public_key();
    let consensus_key = bls12381::PrivateKey::from_seed(seed).public_key();
    let key: [u8; 32] = node_key.as_ref().try_into().unwrap();
    let mut account = create_test_validator_account(seed, balance);
    account.status = ValidatorStatus::Joining;
    account.joining_epoch = joining_epoch;
    account.consensus_public_key = consensus_key.clone();
    state.set_account(key, account);
    state.add_validator(
        joining_epoch,
        AddedValidator {
            node_key,
            consensus_key,
        },
    );
    key
}

fn removed(state: &ConsensusState, key: [u8; 32]) -> bool {
    let pk = PublicKey::decode(&key[..]).unwrap();
    state.get_removed_validators().contains(&pk)
}

// A full exit is refused when it would drop the active set below the minimum
// validator count: the validator stays Active and nothing is enqueued.
#[test]
fn exit_floor_blocks_full_exit() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(2);
    state.set_max_withdrawals_per_epoch(10);
    let key = add_active(&mut state, 1, 100);
    add_active(&mut state, 2, 100);

    // Active count is 2; accepting an exit would leave 1 < the floor of 2.
    state.apply_withdrawal_request(
        WithdrawalRequest {
            source_address: Address::from([1u8; 20]),
            validator_pubkey: key,
            amount: 0,
        },
        2,
    );

    assert_eq!(
        state.get_account(&key).unwrap().status,
        ValidatorStatus::Active
    );
    assert!(!removed(&state, key));
    assert!(state.get_withdrawals_for_epoch(2).is_empty());
}

// A pending minimum stake increase is rejected when too few validators would
// remain: the change is dropped and no one is removed.
#[test]
fn enforce_minimum_stake_rejects_when_too_few_retained() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(2);
    // Both validators are below the proposed new minimum of 100.
    add_active(&mut state, 1, 50);
    add_active(&mut state, 2, 50);
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(100)]);
    assert_eq!(state.prospective_minimum_stake(), 100);

    state.enforce_minimum_stake();

    // Retained at >= 100 is 0 < the floor of 2: reject the change, remove no one.
    assert_eq!(state.prospective_minimum_stake(), 32);
    assert!(state.get_removed_validators().is_empty());
}

// A pending minimum stake increase is applied when enough validators remain:
// the change stands and below-minimum validators are staged for removal.
#[test]
fn enforce_minimum_stake_applies_when_enough_retained() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    let key1 = add_active(&mut state, 1, 100);
    let key2 = add_active(&mut state, 2, 100);
    let below = add_active(&mut state, 3, 50);
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);

    state.enforce_minimum_stake();

    // Retained at >= 80 is 2 >= the floor of 1: keep the change, remove only the
    // below-minimum validator.
    assert_eq!(state.prospective_minimum_stake(), 80);
    assert!(removed(&state, below));
    assert!(!removed(&state, key1));
    assert!(!removed(&state, key2));
}

// A joining validator below the raised minimum has its pending activation
// cancelled and reverts to Inactive. It must not be left stuck as Joining (which
// would never re-activate, since its scheduled activation was removed), and it is
// not committee-removed (it never entered the committee).
#[test]
fn enforce_minimum_stake_cancels_joining_validator_to_inactive() {
    let mut state = ConsensusState::default();
    state.set_minimum_stake(32);
    state.set_minimum_validator_count(1);
    // Two active validators stay above the new minimum so the change is applied.
    add_active(&mut state, 1, 100);
    add_active(&mut state, 2, 100);
    // A joining validator (activation scheduled for epoch 2) sits below it.
    let joining = add_joining(&mut state, 3, 50, 2);
    assert!(state.has_added_validators(2));
    state.push_protocol_param_changes([ProtocolParam::MinimumStake(80)]);

    state.enforce_minimum_stake();

    // Activation cancelled, account reverted to Inactive, and not committee-removed.
    assert_eq!(
        state.get_account(&joining).unwrap().status,
        ValidatorStatus::Inactive
    );
    assert!(!state.has_added_validators(2));
    assert!(!removed(&state, joining));
}
