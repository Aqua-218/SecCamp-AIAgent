#![no_main]

use egress_protocol::response::{CanonicalBrokerResponse, CanonicalResponseChunk};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both response forms are bounded decoders. The fuzz target intentionally
    // keeps the results opaque: acceptance must never panic or retain data
    // beyond the protocol's fixed limits.
    let _ = CanonicalBrokerResponse::decode(data);
    if let Ok(chunk) = CanonicalResponseChunk::decode(data) {
        // A single chunk is valid only when its metadata declares a one-chunk
        // response; otherwise reassembly must fail closed without allocation
        // beyond the protocol's bounded sequence policy.
        let _ = CanonicalBrokerResponse::from_chunks(std::slice::from_ref(&chunk));
    }
});
