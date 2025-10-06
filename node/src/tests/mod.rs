mod checkpointing;
mod execution_requests;
mod syncer;

use crate::test_harness::common::run_until_height;
use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;

#[test_traced("INFO")]
fn test_20_blocks_and_verify() {
    let link = Link {
        latency: 80.0,
        jitter: 10.0,
        success_rate: 0.98,
    };
    run_until_height(10, 0, link.clone(), 20, true);
}
