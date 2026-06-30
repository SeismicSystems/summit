use super::super::*;

#[test]
fn protocol_param_batch_accepts_valid_final_stake_interval() {
    let mut state = ConsensusState::default();
    state.push_protocol_param_change(ProtocolParam::MaximumStake(20_000_000_000));
    state.push_protocol_param_change(ProtocolParam::MinimumStake(10_000_000_000));

    let changed = state.apply_protocol_parameter_changes().unwrap();

    assert!(changed);
    assert_eq!(state.get_minimum_stake(), 10_000_000_000);
    assert_eq!(state.get_maximum_stake(), 20_000_000_000);
}

#[test]
fn protocol_param_batch_rejects_inverted_final_stake_interval() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();
    state.push_protocol_param_change(ProtocolParam::MinimumStake(80_000_000_000));

    let err = state.apply_protocol_parameter_changes().unwrap_err();

    assert!(matches!(err, Error::Invalid("ConsensusState", _)));
    assert_eq!(state.get_minimum_stake(), 32_000_000_000);
    assert_eq!(state.get_maximum_stake(), 32_000_000_000);
    assert_eq!(state.ssz_tree().root(), root_before);
    assert_eq!(state.protocol_param_changes.len(), 0);
}

// A grouped batch of protocol param changes flushed
// through push_protocol_param_changes must land in exactly the same state
// (queue contents and ssz root) as pushing each record one at a time. the
// batch path rebuilds the param subtree once instead of once per record.
#[test]
fn test_batch_protocol_param_changes_match_per_record() {
    use crate::protocol_params::ProtocolParam;

    let params = vec![
        ProtocolParam::MinimumStake(16_000_000_000),
        ProtocolParam::MaximumStake(64_000_000_000),
        ProtocolParam::EpochLength(128),
        ProtocolParam::MaxDepositsPerEpoch(8),
    ];

    let mut per_record = ConsensusState::default();
    for param in params.clone() {
        per_record.push_protocol_param_change(param);
    }

    let mut batched = ConsensusState::default();
    batched.push_protocol_param_changes(params.clone());

    assert_eq!(
        batched.protocol_param_changes.len(),
        per_record.protocol_param_changes.len(),
        "batched queue should match per record queue length"
    );
    assert_eq!(
        batched.ssz_tree().root(),
        per_record.ssz_tree().root(),
        "batched ssz root should match per record root"
    );

    // the batch path is equivalent to a full rebuild from the same queue.
    batched.rebuild_ssz_tree();
    assert_eq!(
        batched.ssz_tree().root(),
        per_record.ssz_tree().root(),
        "batched root should match a full rebuild"
    );
}

// an empty batch must be a no op: no queue growth and no root change, so the
// finalizer can call it unconditionally without forcing a needless rebuild.
#[test]
fn test_empty_protocol_param_batch_is_noop() {
    let mut state = ConsensusState::default();
    let root_before = state.ssz_tree().root();
    let len_before = state.protocol_param_changes.len();

    state.push_protocol_param_changes(std::iter::empty());

    assert_eq!(len_before, state.protocol_param_changes.len());
    assert_eq!(
        root_before,
        state.ssz_tree().root(),
        "empty batch should not change the ssz root"
    );
}
