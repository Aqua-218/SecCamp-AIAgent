#![no_main]

use egress_protocol::cbor::CanonicalBrokerRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = CanonicalBrokerRequest::decode(data);
});
