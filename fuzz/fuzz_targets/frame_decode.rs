#![no_main]

use egress_protocol::frame::ControlFrame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ControlFrame::decode_complete(data);
});
