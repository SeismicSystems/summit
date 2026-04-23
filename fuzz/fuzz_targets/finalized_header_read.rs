#![no_main]

//! Fuzz target for `FinalizedHeader::read_cfg`.
//!
//! FinalizedHeader wraps both a Header and a commonware `Finalization` certificate,
//! so this also exercises the certificate-decode path.

use commonware_codec::{Encode, ReadExt as _};
use libfuzzer_sys::fuzz_target;
use summit_types::FinalizedHeader;
use summit_types::scheme::MultisigScheme;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(value) = FinalizedHeader::<MultisigScheme>::read(&mut buf) else {
        return;
    };

    let encoded = value.encode();
    let mut rebuf: &[u8] = encoded.as_ref();
    let redecoded = FinalizedHeader::<MultisigScheme>::read(&mut rebuf)
        .expect("encoded FinalizedHeader must decode back successfully");

    let re_encoded = redecoded.encode();
    assert_eq!(
        encoded.as_ref(),
        re_encoded.as_ref(),
        "FinalizedHeader encode is not idempotent across a roundtrip",
    );
});
