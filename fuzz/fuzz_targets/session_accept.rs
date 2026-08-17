#![no_main]

use std::num::NonZeroUsize;

use egress_protocol::session::{
    BrokerEnvelope, BrokerRequestId, BrokerSessionId, SessionReplayGuard,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the public payload-bound ingress with arbitrary identities,
    // sequence values, and payload splits. All failures are expected protocol
    // outcomes; none may panic or mutate state inconsistently.
    let mut session_bytes = [0_u8; 16];
    let session_copy = data.len().min(session_bytes.len());
    session_bytes[..session_copy].copy_from_slice(&data[..session_copy]);

    let mut request_bytes = [0_u8; 16];
    let request_start = session_copy;
    let request_copy = data
        .len()
        .saturating_sub(request_start)
        .min(request_bytes.len());
    request_bytes[..request_copy]
        .copy_from_slice(&data[request_start..request_start + request_copy]);

    let sequence_bytes = data.get(32..).unwrap_or_default();
    let mut sequence_array = [0_u8; 8];
    let sequence_copy = sequence_bytes.len().min(sequence_array.len());
    sequence_array[..sequence_copy].copy_from_slice(&sequence_bytes[..sequence_copy]);
    let sequence = u64::from_be_bytes(sequence_array);

    let payload = data.get(40..).unwrap_or_default();
    let session = BrokerSessionId::new(session_bytes);
    let request = BrokerRequestId::new(request_bytes);
    let envelope = BrokerEnvelope::from_canonical_payload(session, sequence, request, payload);
    let mut guard = SessionReplayGuard::new(
        session,
        NonZeroUsize::new(4).expect("fuzz replay capacity must be non-zero"),
    );
    let _ = guard.accept_payload(envelope, payload);

    // A second payload must either be rejected as a binding mismatch or be
    // independently admitted only when it is represented by a new envelope.
    let alternate_payload = data.get(41..).unwrap_or_default();
    let _ = guard.accept_payload(envelope, alternate_payload);
});
