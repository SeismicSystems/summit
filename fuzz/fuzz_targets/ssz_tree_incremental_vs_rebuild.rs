#![no_main]

//! Property-based fuzz target: incremental SSZ tree updates via `ConsensusState`
//! setters *plus* `apply_protocol_parameter_changes` must produce the same root
//! as a full rebuild of the tree from the resulting field values.

use commonware_codec::ReadExt as _;
use libfuzzer_sys::fuzz_target;
use summit_types::{consensus_state::ConsensusState, protocol_params::ProtocolParam};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(mut state) = ConsensusState::read(&mut buf) else {
        return;
    };

    // Mutate a handful of scalar fields; each setter updates the ssz_tree
    // incrementally. Chosen to cover different leaf indices in the top tree.
    state.set_epoch(state.get_epoch().wrapping_add(1));
    state.set_view(state.get_view().wrapping_add(2));
    state.set_latest_height(state.get_latest_height().wrapping_add(3));
    state.set_max_deposits_per_epoch(7);
    state.set_max_withdrawals_per_epoch(42);
    state.set_observers_per_validator(5);

    // Parse any remaining bytes as a sequence of protocol param changes,
    // queue them, then apply. This exercises `apply_protocol_parameter_changes`
    // alongside the scalar setter updates — each applied param runs through
    // an `ssz_tree.set_*` call that must stay in sync with a full rebuild.
    while !buf.is_empty() {
        let Ok(param) = ProtocolParam::read(&mut buf) else {
            break;
        };
        // EpochLength drives the DynamicEpocher, which is not part of the
        // SSZ tree root. It also asserts runtime preconditions that don't
        // hold for arbitrary decoded states — skip it here; the
        // incremental-vs-rebuild property doesn't depend on it.
        if matches!(param, ProtocolParam::EpochLength(_)) {
            continue;
        }
        state.push_protocol_param_change(param);
    }
    let _ = state.apply_protocol_parameter_changes();

    // Snapshot the incremental-update root.
    state.capture_state_root(0);
    let incremental_root = state.get_state_root();

    // Fresh rebuild from the (now mutated) field values.
    state.rebuild_ssz_tree();
    let rebuild_root = state.get_state_root();

    assert_eq!(
        incremental_root, rebuild_root,
        "SszStateTree incremental updates must match full rebuild",
    );
});
