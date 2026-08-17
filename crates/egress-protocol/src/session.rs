//! Broker session identity, request identity, and replay protection.
//!
//! A transport hashes its canonical request payload, places the result in a
//! [`BrokerEnvelope`], and asks [`SessionReplayGuard`] to accept it before it
//! dispatches any external side effect. This keeps retry/idempotency handling
//! separate from HTTP and provider-specific request construction.

use std::{collections::BTreeMap, error::Error, fmt, num::NonZeroUsize};

use sha2::{Digest, Sha256};

/// Maximum size of one encoded control frame, before allocation or decoding.
pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;

/// A host-issued identifier for one post-restore broker connection.
///
/// The value is intentionally fixed-width rather than an unvalidated string.
/// A snapshot restore must establish a fresh session ID and a fresh
/// [`SessionReplayGuard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrokerSessionId([u8; 16]);

impl BrokerSessionId {
    /// Creates an identifier from exactly 128 host-issued bits.
    #[must_use]
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }

    /// Returns the host-issued bytes without reinterpreting them as text.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A caller-issued 128-bit idempotency identity for one broker request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrokerRequestId([u8; 16]);

impl BrokerRequestId {
    /// Creates an identifier from exactly 128 caller-issued bits.
    #[must_use]
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }

    /// Returns the caller-issued bytes without reinterpreting them as text.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A SHA-256 digest of one canonical broker request payload.
///
/// This is a byte identity, not an authorization decision. The payload must
/// already have a single canonical encoding before it is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PayloadHash([u8; 32]);

impl PayloadHash {
    /// Hashes an already canonical request payload with SHA-256.
    #[must_use]
    pub fn of_canonical_payload(payload: &[u8]) -> Self {
        Self(Sha256::digest(payload).into())
    }

    /// Returns the fixed-width digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Metadata that binds a canonical payload to one ordered broker request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrokerEnvelope {
    session: BrokerSessionId,
    sequence: u64,
    request: BrokerRequestId,
    payload_hash: PayloadHash,
}

impl BrokerEnvelope {
    /// Creates an envelope and derives its payload hash from the exact bytes
    /// that will be sent on the wire.
    ///
    /// This is the preferred constructor for every transport ingress. Keeping
    /// the payload and its digest in one call prevents a caller from hashing
    /// one operation while sending another operation under the same request
    /// identity.
    #[must_use]
    pub fn from_canonical_payload(
        session: BrokerSessionId,
        sequence: u64,
        request: BrokerRequestId,
        payload: &[u8],
    ) -> Self {
        Self::new(
            session,
            sequence,
            request,
            PayloadHash::of_canonical_payload(payload),
        )
    }

    /// Reconstructs an envelope after this crate has validated the payload hash.
    ///
    /// Keeping this constructor crate-private makes it impossible for an
    /// external transport to supply unrelated payload and digest values. Public
    /// callers must use [`Self::from_canonical_payload`].
    #[must_use]
    pub(crate) const fn new(
        session: BrokerSessionId,
        sequence: u64,
        request: BrokerRequestId,
        payload_hash: PayloadHash,
    ) -> Self {
        Self {
            session,
            sequence,
            request,
            payload_hash,
        }
    }

    /// Returns the session in which this envelope is valid.
    #[must_use]
    pub const fn session(&self) -> BrokerSessionId {
        self.session
    }

    /// Returns the strict per-session request sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the request's idempotency identity.
    #[must_use]
    pub const fn request(&self) -> BrokerRequestId {
        self.request
    }

    /// Returns the canonical payload digest bound to the request identity.
    #[must_use]
    pub const fn payload_hash(&self) -> PayloadHash {
        self.payload_hash
    }

    /// Returns whether `payload` is exactly the canonical byte sequence bound
    /// by this envelope.
    #[must_use]
    pub fn binds_canonical_payload(&self, payload: &[u8]) -> bool {
        self.payload_hash == PayloadHash::of_canonical_payload(payload)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedRequest {
    sequence: u64,
    payload_hash: PayloadHash,
}

/// The outcome of validating an envelope before a broker side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeAcceptance {
    /// This is the next previously unseen request and may be dispatched once.
    New,
    /// This exact envelope was already accepted; reuse its retained outcome.
    ///
    /// The caller must not dispatch the external side effect a second time.
    Duplicate,
}

/// Why an envelope cannot be admitted to the current broker session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope belongs to another connection or a pre-restore session.
    WrongSession {
        /// Session ID owned by this guard.
        expected: BrokerSessionId,
        /// Session ID carried by the rejected envelope.
        received: BrokerSessionId,
    },
    /// A new request skipped, repeated, or reordered the required sequence.
    OutOfOrderSequence {
        /// The only sequence number accepted for a new request.
        expected: u64,
        /// The sequence number carried by the rejected envelope.
        received: u64,
    },
    /// The sequence reached `u64::MAX`; accepting another request would wrap.
    SequenceExhausted,
    /// A request ID was reused with different sequence or canonical payload.
    RequestIdentityMismatch {
        /// Request identity that was reused inconsistently.
        request: BrokerRequestId,
    },
    /// The supplied payload did not match the envelope's claimed digest.
    PayloadHashMismatch,
    /// The bounded deduplication table cannot retain another request outcome.
    RequestCapacityExhausted,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSession { .. } => {
                formatter.write_str("broker envelope belongs to another session")
            }
            Self::OutOfOrderSequence { expected, received } => write!(
                formatter,
                "broker envelope sequence {received} is invalid; expected {expected}"
            ),
            Self::SequenceExhausted => formatter.write_str("broker session sequence is exhausted"),
            Self::RequestIdentityMismatch { .. } => {
                formatter.write_str("broker request ID was reused with a different envelope")
            }
            Self::PayloadHashMismatch => {
                formatter.write_str("broker envelope payload does not match its digest")
            }
            Self::RequestCapacityExhausted => {
                formatter.write_str("broker session deduplication capacity is exhausted")
            }
        }
    }
}

impl Error for EnvelopeError {}

/// A bounded, per-connection admission guard for broker requests.
///
/// The guard is intentionally stateful and single-session. Synchronization,
/// response retention, and transport I/O belong to the caller. A caller must
/// retain a completed response for every [`EnvelopeAcceptance::Duplicate`] and
/// must never execute its external side effect for that outcome.
#[derive(Debug)]
pub struct SessionReplayGuard {
    session: BrokerSessionId,
    next_sequence: Option<u64>,
    capacity: NonZeroUsize,
    accepted: BTreeMap<BrokerRequestId, AcceptedRequest>,
}

impl SessionReplayGuard {
    /// Starts an empty session that accepts sequence zero first.
    #[must_use]
    pub const fn new(session: BrokerSessionId, capacity: NonZeroUsize) -> Self {
        Self {
            session,
            next_sequence: Some(0),
            capacity,
            accepted: BTreeMap::new(),
        }
    }

    /// Returns the session ID that this guard owns.
    #[must_use]
    pub const fn session(&self) -> BrokerSessionId {
        self.session
    }

    /// Returns the next sequence number accepted for a new request, if any.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    /// Returns how many accepted request identities are retained.
    #[must_use]
    pub fn accepted_request_count(&self) -> usize {
        self.accepted.len()
    }

    /// Admits one new envelope or identifies an exact retry.
    ///
    /// # Errors
    ///
    /// Returns an error without changing state when the session, order,
    /// request identity, sequence range, or bounded retention limit is wrong.
    pub(crate) fn accept(
        &mut self,
        envelope: BrokerEnvelope,
    ) -> Result<EnvelopeAcceptance, EnvelopeError> {
        if envelope.session != self.session {
            return Err(EnvelopeError::WrongSession {
                expected: self.session,
                received: envelope.session,
            });
        }

        if let Some(accepted) = self.accepted.get(&envelope.request) {
            if accepted.sequence == envelope.sequence
                && accepted.payload_hash == envelope.payload_hash
            {
                return Ok(EnvelopeAcceptance::Duplicate);
            }
            return Err(EnvelopeError::RequestIdentityMismatch {
                request: envelope.request,
            });
        }

        let expected = self.next_sequence.ok_or(EnvelopeError::SequenceExhausted)?;
        if envelope.sequence != expected {
            return Err(EnvelopeError::OutOfOrderSequence {
                expected,
                received: envelope.sequence,
            });
        }
        if self.accepted.len() >= self.capacity.get() {
            return Err(EnvelopeError::RequestCapacityExhausted);
        }

        self.accepted.insert(
            envelope.request,
            AcceptedRequest {
                sequence: envelope.sequence,
                payload_hash: envelope.payload_hash,
            },
        );
        self.next_sequence = envelope.sequence.checked_add(1);
        Ok(EnvelopeAcceptance::New)
    }

    /// Validates the payload binding before admitting an envelope.
    ///
    /// This is the safe public ingress for callers that have both the decoded
    /// envelope and the canonical payload bytes. A mismatch is rejected before
    /// any replay-table or sequence state changes.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::PayloadHashMismatch`] when `payload` is not
    /// the exact byte sequence bound by `envelope`. Otherwise returns the same
    /// session, ordering, identity, capacity, and exhaustion errors as the
    /// internal replay-admission path.
    pub fn accept_payload(
        &mut self,
        envelope: BrokerEnvelope,
        payload: &[u8],
    ) -> Result<EnvelopeAcceptance, EnvelopeError> {
        if envelope.session != self.session {
            return self.accept(envelope);
        }
        if !envelope.binds_canonical_payload(payload) {
            return Err(EnvelopeError::PayloadHashMismatch);
        }
        self.accept(envelope)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::{
        BrokerEnvelope, BrokerRequestId, BrokerSessionId, EnvelopeAcceptance, EnvelopeError,
        PayloadHash, SessionReplayGuard,
    };

    fn session(byte: u8) -> BrokerSessionId {
        BrokerSessionId::new([byte; 16])
    }

    fn request(byte: u8) -> BrokerRequestId {
        BrokerRequestId::new([byte; 16])
    }

    fn envelope(
        session: BrokerSessionId,
        sequence: u64,
        request: BrokerRequestId,
        payload: &[u8],
    ) -> BrokerEnvelope {
        BrokerEnvelope::from_canonical_payload(session, sequence, request, payload)
    }

    #[test]
    fn payload_hash_is_stable_for_the_exact_canonical_bytes() {
        assert_eq!(
            PayloadHash::of_canonical_payload(b"canonical-cbor-payload").as_bytes(),
            &[
                0xfd, 0xbc, 0xd0, 0xa6, 0x95, 0x7f, 0x47, 0x7e, 0xb7, 0xbe, 0xea, 0x66, 0x8a, 0x30,
                0x84, 0x6e, 0x38, 0x98, 0x72, 0xf0, 0x53, 0xc8, 0xa0, 0x39, 0x40, 0xb7, 0x03, 0x2a,
                0xda, 0xfd, 0x73, 0xe9,
            ]
        );
        assert_ne!(
            PayloadHash::of_canonical_payload(b"canonical-cbor-payload"),
            PayloadHash::of_canonical_payload(b"same fields, different bytes")
        );
    }

    #[test]
    fn guard_accepts_the_next_request_once_and_identifies_exact_retries() {
        let current_session = session(1);
        let first = envelope(current_session, 0, request(1), b"first");
        let mut guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(2).expect("test capacity must be non-zero"),
        );

        assert_eq!(guard.accept(first), Ok(EnvelopeAcceptance::New));
        assert_eq!(guard.next_sequence(), Some(1));
        assert_eq!(guard.accept(first), Ok(EnvelopeAcceptance::Duplicate));
        assert_eq!(guard.accepted_request_count(), 1);
    }

    #[test]
    fn payload_ingress_rejects_hash_mismatch_without_consuming_sequence_or_capacity() {
        let current_session = session(9);
        let envelope = envelope(current_session, 0, request(9), b"declared");
        let mut guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(1).expect("test capacity must be non-zero"),
        );

        assert_eq!(
            guard.accept_payload(envelope, b"different"),
            Err(EnvelopeError::PayloadHashMismatch)
        );
        assert_eq!(guard.next_sequence(), Some(0));
        assert_eq!(guard.accepted_request_count(), 0);
        assert_eq!(
            guard.accept_payload(envelope, b"declared"),
            Ok(EnvelopeAcceptance::New)
        );
        assert_eq!(
            guard.accept_payload(envelope, b"declared"),
            Ok(EnvelopeAcceptance::Duplicate)
        );
    }

    #[test]
    fn fresh_restore_session_rejects_every_pre_restore_envelope() {
        let previous_session = session(10);
        let restored_session = session(11);
        let previous = envelope(previous_session, 0, request(10), b"before-restore");
        let mut restored = SessionReplayGuard::new(
            restored_session,
            NonZeroUsize::new(1).expect("test capacity must be non-zero"),
        );

        assert_eq!(
            restored.accept_payload(previous, b"before-restore"),
            Err(EnvelopeError::WrongSession {
                expected: restored_session,
                received: previous_session,
            })
        );
        assert_eq!(restored.next_sequence(), Some(0));
        assert_eq!(restored.accepted_request_count(), 0);
    }

    #[test]
    fn guard_rejects_wrong_session_reordering_and_identity_rebinding() {
        let current_session = session(1);
        let mut guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(3).expect("test capacity must be non-zero"),
        );

        assert_eq!(
            guard.accept(envelope(session(2), 0, request(1), b"first")),
            Err(EnvelopeError::WrongSession {
                expected: current_session,
                received: session(2),
            })
        );
        assert_eq!(
            guard.accept(envelope(current_session, 1, request(1), b"first")),
            Err(EnvelopeError::OutOfOrderSequence {
                expected: 0,
                received: 1,
            })
        );
        assert_eq!(
            guard.accept(envelope(current_session, 0, request(1), b"first")),
            Ok(EnvelopeAcceptance::New)
        );
        assert_eq!(
            guard.accept(envelope(current_session, 1, request(1), b"first")),
            Err(EnvelopeError::RequestIdentityMismatch {
                request: request(1),
            })
        );
        assert_eq!(
            guard.accept(envelope(current_session, 0, request(1), b"changed")),
            Err(EnvelopeError::RequestIdentityMismatch {
                request: request(1),
            })
        );
    }

    #[test]
    fn guard_fails_closed_at_retention_and_sequence_limits() {
        let current_session = session(1);
        let mut capacity_guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(1).expect("test capacity must be non-zero"),
        );
        assert_eq!(
            capacity_guard.accept(envelope(current_session, 0, request(1), b"first")),
            Ok(EnvelopeAcceptance::New)
        );
        assert_eq!(
            capacity_guard.accept(envelope(current_session, 1, request(2), b"second")),
            Err(EnvelopeError::RequestCapacityExhausted)
        );

        let mut final_sequence_guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(2).expect("test capacity must be non-zero"),
        );
        final_sequence_guard.next_sequence = Some(u64::MAX);
        assert_eq!(
            final_sequence_guard.accept_payload(
                envelope(current_session, u64::MAX, request(3), b"last"),
                b"last",
            ),
            Ok(EnvelopeAcceptance::New)
        );
        assert_eq!(final_sequence_guard.next_sequence(), None);
        assert_eq!(
            final_sequence_guard.accept(envelope(current_session, 0, request(4), b"wrapped")),
            Err(EnvelopeError::SequenceExhausted)
        );
    }

    #[test]
    fn capacity_exhaustion_is_terminal_and_does_not_advance_on_retries() {
        let current_session = session(12);
        let mut guard = SessionReplayGuard::new(
            current_session,
            NonZeroUsize::new(1).expect("test capacity must be non-zero"),
        );
        let first = envelope(current_session, 0, request(12), b"first");
        let second = envelope(current_session, 1, request(13), b"second");

        assert_eq!(
            guard.accept_payload(first, b"first"),
            Ok(EnvelopeAcceptance::New)
        );
        assert_eq!(guard.next_sequence(), Some(1));
        assert_eq!(
            guard.accept_payload(second, b"second"),
            Err(EnvelopeError::RequestCapacityExhausted)
        );
        assert_eq!(guard.next_sequence(), Some(1));
        assert_eq!(guard.accepted_request_count(), 1);
        assert_eq!(
            guard.accept_payload(second, b"second"),
            Err(EnvelopeError::RequestCapacityExhausted)
        );
    }
}
