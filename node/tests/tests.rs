use summit::test_harness::common::all_online;
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};
use commonware_macros::test_traced;

#[test]
fn test_basic() {
    assert!(true);
}

//#[test_traced]
//fn test_1k() {
//    let link = Link {
//        latency: 80.0,
//        jitter: 10.0,
//        success_rate: 0.98,
//    };
//    all_online(10, 0, link.clone(), 1000);
//}