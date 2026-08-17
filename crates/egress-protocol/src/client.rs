//! Allocation-bounded guest-side client for the version-one Broker wire.
//!
//! The client owns the session sequence and request identities, but deliberately
//! does not own a socket implementation.  Any `Read + Write` stream can be
//! supplied by a guest transport adapter (for example an inherited vsock file
//! descriptor).  The wire remains the existing four-byte length prefix followed
//! by canonical CBOR: this module only provides the missing reusable transport
//! boundary around those types.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    io::{self, Read, Write},
    num::NonZeroUsize,
};

use crate::{
    cbor::{CanonicalBrokerRequest, CborError},
    frame::{CONTROL_FRAME_LENGTH_PREFIX_BYTES, ControlFrame, FrameError, ValidatedFrameLength},
    operation::BrokerOperation,
    response::{
        CanonicalBrokerResponse, CanonicalResponseChunk, MAX_EXPANDED_CANONICAL_RESPONSE_BYTES,
        MAX_RESPONSE_CHUNK_BYTES, ResponseCborError, ResponseChunkError,
    },
    session::{BrokerRequestId, BrokerSessionId},
};

/// The maximum number of chunks a bounded expanded response can contain.
///
/// This is deliberately derived from the response wire constants rather than
/// being a second policy value.  It is used before allocating the chunk vector
/// and therefore also bounds adversarial response metadata.
pub const MAX_RESPONSE_CHUNKS: usize =
    MAX_EXPANDED_CANONICAL_RESPONSE_BYTES.div_ceil(MAX_RESPONSE_CHUNK_BYTES);

/// The default number of request identities retained by one client.
///
/// The client is sequential, but retaining identities prevents a caller from
/// accidentally reusing an old request ID after a successful exchange.  The
/// bound keeps that defensive state finite even when a guest is long-lived.
pub const DEFAULT_MAX_REQUESTS: NonZeroUsize =
    NonZeroUsize::new(1024).expect("the default client request limit is non-zero");

/// Resource limits for one guest Broker client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimits {
    max_requests: NonZeroUsize,
}

impl ClientLimits {
    /// Creates limits with a bounded request-identity retention capacity.
    #[must_use]
    pub const fn new(max_requests: NonZeroUsize) -> Self {
        Self { max_requests }
    }

    /// Returns the maximum number of requests this client may issue.
    #[must_use]
    pub const fn max_requests(self) -> NonZeroUsize {
        self.max_requests
    }
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_REQUESTS)
    }
}

/// Identifies the phase of a failed bounded stream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIoOperation {
    /// Writing the four-byte frame length.
    WriteFramePrefix,
    /// Writing the canonical frame payload.
    WriteFramePayload,
    /// Flushing the transport after a complete frame.
    Flush,
    /// Reading the four-byte frame length.
    ReadFramePrefix,
    /// Reading the bounded frame payload.
    ReadFramePayload,
}

impl fmt::Display for ClientIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::WriteFramePrefix => "writing Broker frame prefix",
            Self::WriteFramePayload => "writing Broker frame payload",
            Self::Flush => "flushing Broker frame",
            Self::ReadFramePrefix => "reading Broker frame prefix",
            Self::ReadFramePayload => "reading Broker frame payload",
        };
        formatter.write_str(name)
    }
}

/// Why a guest-side Broker request or response exchange failed.
#[derive(Debug)]
pub enum ClientError {
    /// The request could not be represented by canonical wire-v1 CBOR.
    RequestEncoding(CborError),
    /// A frame length or local frame construction violated the wire bound.
    Frame(FrameError),
    /// The transport returned an operating-system I/O error.
    Io {
        /// Stream phase in which the error occurred.
        operation: ClientIoOperation,
        /// Underlying stream error.
        source: io::Error,
    },
    /// The stream ended before a complete prefix or payload was received.
    TruncatedFrame {
        /// Whether this was a prefix/payload frame boundary is represented by
        /// the expected byte count; the received count is always exact.
        expected: usize,
        /// Bytes received before EOF.
        received: usize,
        /// Stream phase in which EOF occurred.
        operation: ClientIoOperation,
    },
    /// The client has no next sequence number because it reached `u64::MAX`.
    SequenceExhausted,
    /// The generated request identity counter reached its terminal value.
    RequestIdentityExhausted,
    /// The bounded client request allowance has been consumed.
    RequestLimitReached {
        /// Maximum number of request identities retained by this client.
        maximum: usize,
    },
    /// A caller tried to reuse an identity already sent on this client.
    RequestIdentityReuse {
        /// Reused request identity.
        request: BrokerRequestId,
    },
    /// The canonical response carried another request identity.
    ResponseRequestMismatch {
        /// Identity sent in the request.
        expected: BrokerRequestId,
        /// Identity returned by the host.
        received: BrokerRequestId,
    },
    /// Both canonical response forms failed decoding.
    InvalidResponse {
        /// Error from trying the single-response schema.
        response: ResponseCborError,
        /// Error from trying the chunk schema.
        chunk: ResponseChunkError,
    },
    /// A response chunk sequence exceeded the derived bounded count.
    ResponseChunkCountExceeded {
        /// Count advertised by the peer.
        received: usize,
        /// Maximum count derived from the expanded response bound.
        maximum: usize,
    },
    /// A canonical response chunk could not be decoded or reassembled.
    ResponseChunk(ResponseChunkError),
    /// A single canonical response could not be decoded.
    Response(ResponseCborError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestEncoding(error) => {
                write!(formatter, "encoding Broker request failed: {error}")
            }
            Self::Frame(error) => write!(formatter, "Broker frame validation failed: {error}"),
            Self::Io { operation, source } => write!(formatter, "{operation} failed: {source}"),
            Self::TruncatedFrame {
                expected,
                received,
                operation,
            } => write!(
                formatter,
                "{operation} truncated: expected {expected} bytes, received {received}"
            ),
            Self::SequenceExhausted => formatter.write_str("Broker session sequence is exhausted"),
            Self::RequestIdentityExhausted => {
                formatter.write_str("guest Broker request identity sequence is exhausted")
            }
            Self::RequestLimitReached { maximum } => write!(
                formatter,
                "guest Broker client request limit of {maximum} has been reached"
            ),
            Self::RequestIdentityReuse { .. } => {
                formatter.write_str("guest Broker request identity was already used")
            }
            Self::ResponseRequestMismatch { .. } => {
                formatter.write_str("Broker response is bound to a different request")
            }
            Self::InvalidResponse { response, chunk } => write!(
                formatter,
                "Broker response is neither a canonical response ({response}) nor a valid chunk ({chunk})"
            ),
            Self::ResponseChunkCountExceeded { received, maximum } => write!(
                formatter,
                "Broker response advertises {received} chunks; at most {maximum} are allowed"
            ),
            Self::ResponseChunk(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestEncoding(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidResponse { response, .. } => Some(response),
            Self::ResponseChunk(error) => Some(error),
            Self::Response(error) => Some(error),
            Self::TruncatedFrame { .. }
            | Self::SequenceExhausted
            | Self::RequestIdentityExhausted
            | Self::RequestLimitReached { .. }
            | Self::RequestIdentityReuse { .. }
            | Self::ResponseRequestMismatch { .. }
            | Self::ResponseChunkCountExceeded { .. } => None,
        }
    }
}

/// A sequential, bounded guest-side client for the Broker wire v1 protocol.
///
/// The client is intentionally `&mut self` based: one stream has exactly one
/// ordered session sequence, so concurrent writes would create an ambiguous
/// sequence and cannot be made safe by a transport mutex.  A failed write is
/// terminal for that request—the sequence and request identity are consumed
/// before bytes are sent because the peer may have received a partial frame.
#[derive(Debug)]
pub struct GuestBrokerClient<S> {
    stream: S,
    session: BrokerSessionId,
    next_sequence: Option<u64>,
    next_request_nonce: Option<u64>,
    issued_requests: BTreeSet<BrokerRequestId>,
    limits: ClientLimits,
}

impl<S> GuestBrokerClient<S> {
    /// Creates a client with the default bounded request allowance.
    #[must_use]
    pub const fn new(stream: S, session: BrokerSessionId) -> Self {
        Self::with_limits(stream, session, ClientLimits::new(DEFAULT_MAX_REQUESTS))
    }

    /// Creates a client with explicit bounded request-identity retention.
    #[must_use]
    pub const fn with_limits(stream: S, session: BrokerSessionId, limits: ClientLimits) -> Self {
        Self {
            stream,
            session,
            next_sequence: Some(0),
            next_request_nonce: Some(1),
            issued_requests: BTreeSet::new(),
            limits,
        }
    }

    /// Returns the session identity bound into every request.
    #[must_use]
    pub const fn session(&self) -> BrokerSessionId {
        self.session
    }

    /// Returns the next sequence number, or `None` after exhaustion.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    /// Returns how many request identities have been consumed.
    #[must_use]
    pub fn issued_request_count(&self) -> usize {
        self.issued_requests.len()
    }

    /// Returns the immutable client limits.
    #[must_use]
    pub const fn limits(&self) -> ClientLimits {
        self.limits
    }

    /// Borrows the underlying transport for timeout or platform setup.
    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Returns the transport after the client is no longer needed.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> GuestBrokerClient<S>
where
    S: Read + Write,
{
    /// Sends one operation using a monotonically generated request identity.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the request cannot be encoded, the bounded
    /// stream fails, or the host response is malformed or bound to another
    /// request identity.
    pub fn request(
        &mut self,
        operation: BrokerOperation,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        let request = self.next_request_id()?;
        self.request_with_id(request, operation)
    }

    /// Alias for [`Self::request`] for callers that prefer an execution verb.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request`].
    pub fn execute(
        &mut self,
        operation: BrokerOperation,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        self.request(operation)
    }

    /// Sends one operation with a caller-selected request identity.
    ///
    /// This is useful when an application persists an idempotency key outside
    /// the client.  The identity is still retained in the client's bounded
    /// table and cannot be reused on this stream.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] when the identity was already used, the bounded
    /// request allowance is exhausted, the request cannot be encoded, the
    /// stream fails, or the response is invalid.
    pub fn request_with_id(
        &mut self,
        request: BrokerRequestId,
        operation: BrokerOperation,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        if self.issued_requests.len() >= self.limits.max_requests().get() {
            return Err(ClientError::RequestLimitReached {
                maximum: self.limits.max_requests().get(),
            });
        }
        if self.issued_requests.contains(&request) {
            return Err(ClientError::RequestIdentityReuse { request });
        }
        let sequence = self.next_sequence.ok_or(ClientError::SequenceExhausted)?;
        let canonical = CanonicalBrokerRequest::new(self.session, sequence, request, operation);
        let payload = canonical.encode().map_err(ClientError::RequestEncoding)?;
        let frame = ControlFrame::new(payload).map_err(ClientError::Frame)?;

        // Commit the identity and sequence before I/O.  Once a prefix or a
        // payload byte reaches the peer, retrying with the same envelope could
        // duplicate an external effect or make the stream's order ambiguous.
        self.issued_requests.insert(request);
        self.next_sequence = sequence.checked_add(1);
        self.write_frame(&frame)?;
        self.read_response(request)
    }

    /// Alias for [`Self::request_with_id`] for callers that prefer an execution verb.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::request_with_id`].
    pub fn execute_with_id(
        &mut self,
        request: BrokerRequestId,
        operation: BrokerOperation,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        self.request_with_id(request, operation)
    }

    fn next_request_id(&mut self) -> Result<BrokerRequestId, ClientError> {
        let nonce = self
            .next_request_nonce
            .ok_or(ClientError::RequestIdentityExhausted)?;
        let mut bytes = [0_u8; 16];
        // The session prefix keeps identities distinct across sessions while
        // the big-endian nonce is monotonic and easy to audit in a trace.
        bytes[..8].copy_from_slice(&self.session.as_bytes()[..8]);
        bytes[8..].copy_from_slice(&nonce.to_be_bytes());
        self.next_request_nonce = nonce.checked_add(1);
        Ok(BrokerRequestId::new(bytes))
    }

    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ClientError> {
        // Write prefix and payload separately.  This avoids creating a second
        // full-frame Vec and preserves the allocation-before-validation rule.
        let payload = frame.payload();
        let length = u32::try_from(payload.len()).map_err(|_| {
            ClientError::Frame(FrameError::FrameTooLarge {
                length: payload.len(),
            })
        })?;
        self.stream
            .write_all(&length.to_be_bytes())
            .map_err(|source| ClientError::Io {
                operation: ClientIoOperation::WriteFramePrefix,
                source,
            })?;
        self.stream
            .write_all(payload)
            .map_err(|source| ClientError::Io {
                operation: ClientIoOperation::WriteFramePayload,
                source,
            })?;
        self.stream.flush().map_err(|source| ClientError::Io {
            operation: ClientIoOperation::Flush,
            source,
        })
    }

    fn read_frame_payload(&mut self) -> Result<Vec<u8>, ClientError> {
        let mut prefix = [0_u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES];
        self.read_exact_bounded(&mut prefix, ClientIoOperation::ReadFramePrefix)?;
        let length = ValidatedFrameLength::from_network_prefix(prefix)
            .map_err(ClientError::Frame)?
            .as_usize();
        let mut payload = vec![0_u8; length];
        self.read_exact_bounded(&mut payload, ClientIoOperation::ReadFramePayload)?;
        Ok(payload)
    }

    fn read_exact_bounded(
        &mut self,
        buffer: &mut [u8],
        operation: ClientIoOperation,
    ) -> Result<(), ClientError> {
        let mut received = 0_usize;
        while received < buffer.len() {
            match self.stream.read(&mut buffer[received..]) {
                Ok(0) => {
                    return Err(ClientError::TruncatedFrame {
                        expected: buffer.len(),
                        received,
                        operation,
                    });
                }
                Ok(count) => {
                    received = received
                        .checked_add(count)
                        .ok_or(ClientError::TruncatedFrame {
                            expected: buffer.len(),
                            received,
                            operation,
                        })?;
                }
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => return Err(ClientError::Io { operation, source }),
            }
        }
        Ok(())
    }

    fn read_response(
        &mut self,
        request: BrokerRequestId,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        let payload = self.read_frame_payload()?;
        match CanonicalBrokerResponse::decode(&payload) {
            Ok(response) => Self::validate_response(request, response),
            Err(response_error) => match CanonicalResponseChunk::decode(&payload) {
                Ok(first) => self.read_chunked_response(request, first),
                Err(chunk_error) => Err(ClientError::InvalidResponse {
                    response: response_error,
                    chunk: chunk_error,
                }),
            },
        }
    }

    fn read_chunked_response(
        &mut self,
        request: BrokerRequestId,
        first: CanonicalResponseChunk,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        if first.request() != request {
            return Err(ClientError::ResponseRequestMismatch {
                expected: request,
                received: first.request(),
            });
        }
        let count = usize::try_from(first.count()).map_err(|_| {
            ClientError::ResponseChunkCountExceeded {
                received: usize::MAX,
                maximum: MAX_RESPONSE_CHUNKS,
            }
        })?;
        if count > MAX_RESPONSE_CHUNKS {
            return Err(ClientError::ResponseChunkCountExceeded {
                received: count,
                maximum: MAX_RESPONSE_CHUNKS,
            });
        }
        let mut chunks = Vec::with_capacity(count);
        chunks.push(first);
        for _ in 1..count {
            let payload = self.read_frame_payload()?;
            let chunk =
                CanonicalResponseChunk::decode(&payload).map_err(ClientError::ResponseChunk)?;
            if chunk.request() != request {
                return Err(ClientError::ResponseRequestMismatch {
                    expected: request,
                    received: chunk.request(),
                });
            }
            chunks.push(chunk);
        }
        CanonicalBrokerResponse::from_chunks(&chunks).map_err(ClientError::ResponseChunk)
    }

    fn validate_response(
        request: BrokerRequestId,
        response: CanonicalBrokerResponse,
    ) -> Result<CanonicalBrokerResponse, ClientError> {
        if response.request() != request {
            return Err(ClientError::ResponseRequestMismatch {
                expected: request,
                received: response.request(),
            });
        }
        Ok(response)
    }
}

/// Short alias for [`GuestBrokerClient`].
pub type BrokerClient<S> = GuestBrokerClient<S>;

/// Short alias for [`ClientError`].
pub type BrokerClientError = ClientError;

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read, Write},
        num::NonZeroUsize,
    };

    use authority_core::http::{
        CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest,
    };

    use super::{ClientError, ClientLimits, GuestBrokerClient, MAX_RESPONSE_CHUNKS};
    use crate::{
        frame::{ControlFrame, FrameError},
        operation::BrokerOperation,
        response::{
            BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse,
            MAX_RESPONSE_CHUNK_BYTES,
        },
        session::{BrokerRequestId, BrokerSessionId},
    };

    #[derive(Debug)]
    struct Duplex {
        incoming: io::Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }

    impl Duplex {
        fn with_responses(responses: &[Vec<u8>]) -> Self {
            let mut incoming = Vec::new();
            for response in responses {
                let frame = ControlFrame::new(response.clone()).expect("response frame fits");
                incoming.extend_from_slice(&frame.encode());
            }
            Self {
                incoming: io::Cursor::new(incoming),
                outgoing: Vec::new(),
            }
        }

        fn outgoing_frames(&self) -> Vec<crate::frame::ControlFrame> {
            let mut frames = Vec::new();
            let mut cursor = 0;
            while cursor < self.outgoing.len() {
                let prefix: [u8; 4] = self.outgoing[cursor..cursor + 4]
                    .try_into()
                    .expect("test writer emitted a complete prefix");
                let length = u32::from_be_bytes(prefix) as usize;
                let end = cursor + 4 + length;
                frames.push(
                    ControlFrame::decode_complete(&self.outgoing[cursor..end])
                        .expect("test writer emitted a valid frame"),
                );
                cursor = end;
            }
            frames
        }
    }

    impl Read for Duplex {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(bytes)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.outgoing.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn session() -> BrokerSessionId {
        BrokerSessionId::new([0x11; 16])
    }

    fn request(value: u8) -> BrokerRequestId {
        BrokerRequestId::new([value; 16])
    }

    fn operation() -> BrokerOperation {
        BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("broker-client.invalid").expect("host fixture is canonical"),
            CanonicalUrlPath::new("/").expect("path fixture is canonical"),
            1_024,
        ))
    }

    fn rejection(request: BrokerRequestId) -> Vec<u8> {
        CanonicalBrokerResponse::new(
            request,
            BrokerWireOutcome::Rejected(BrokerWireRejection::NotAuthorized),
        )
        .encode()
        .expect("rejection fits one frame")
    }

    fn expanded_response(request: BrokerRequestId) -> CanonicalBrokerResponse {
        CanonicalBrokerResponse::new(
            request,
            BrokerWireOutcome::Public(
                crate::response::PublicWireResponse::new(
                    200,
                    CanonicalHost::new("broker-client.invalid").expect("host fixture is canonical"),
                    CanonicalUrlPath::new("/").expect("path fixture is canonical"),
                    vec![0x5a; MAX_RESPONSE_CHUNK_BYTES],
                )
                .expect("expanded fixture fits the response cap"),
            ),
        )
    }

    #[test]
    fn request_encoding_binds_session_sequence_and_identity_and_is_bounded() {
        let request_id = request(7);
        let mut client =
            GuestBrokerClient::new(Duplex::with_responses(&[rejection(request_id)]), session());
        let response = client
            .request_with_id(request_id, operation())
            .expect("request round trip succeeds");
        assert_eq!(response.request(), request_id);
        assert_eq!(client.next_sequence(), Some(1));
        let frames = client.transport_mut().outgoing_frames();
        assert_eq!(frames.len(), 1);
        let encoded = frames[0].payload();
        let decoded = crate::cbor::CanonicalBrokerRequest::decode(encoded)
            .expect("client emits canonical request");
        assert_eq!(decoded.envelope().session(), session());
        assert_eq!(decoded.envelope().sequence(), 0);
        assert_eq!(decoded.envelope().request(), request_id);
    }

    #[test]
    fn generated_request_ids_are_monotonic_and_reuse_is_rejected() {
        let first = request(1);
        let second = request(2);
        let mut client = GuestBrokerClient::new(
            Duplex::with_responses(&[rejection(first), rejection(second)]),
            session(),
        );
        let first_response = client.request_with_id(first, operation());
        assert!(first_response.is_ok());
        let second_response = client.request_with_id(second, operation());
        assert!(second_response.is_ok());
        assert_eq!(client.next_sequence(), Some(2));
        assert_eq!(client.issued_request_count(), 2);
        assert!(matches!(
            client.request_with_id(first, operation()),
            Err(ClientError::RequestIdentityReuse { request }) if request == first
        ));
    }

    #[test]
    fn response_request_identity_mismatch_is_rejected_before_dispatch_to_caller() {
        let expected = request(3);
        let received = request(4);
        let mut client =
            GuestBrokerClient::new(Duplex::with_responses(&[rejection(received)]), session());
        assert!(matches!(
            client.request_with_id(expected, operation()),
            Err(ClientError::ResponseRequestMismatch { expected: actual, received: returned })
                if actual == expected && returned == received
        ));
    }

    #[test]
    fn chunk_reassembly_rejects_reorder_duplicate_and_digest_corruption() {
        let request_id = request(5);
        let response = expanded_response(request_id);
        let chunks = response.chunks().expect("expanded response has chunks");
        assert_eq!(chunks.len(), 2);
        assert!(chunks.len() <= MAX_RESPONSE_CHUNKS);

        let reordered = [
            chunks[1].encode().expect("chunk encodes"),
            chunks[0].encode().expect("chunk encodes"),
        ];
        let mut client = GuestBrokerClient::new(Duplex::with_responses(&reordered), session());
        assert!(matches!(
            client.request_with_id(request_id, operation()),
            Err(ClientError::ResponseChunk(
                crate::response::ResponseChunkError::ReorderedChunk { .. }
            ))
        ));

        let duplicate = [
            chunks[0].encode().expect("chunk encodes"),
            chunks[0].encode().expect("chunk encodes"),
        ];
        let mut client = GuestBrokerClient::new(Duplex::with_responses(&duplicate), session());
        assert!(matches!(
            client.request_with_id(request_id, operation()),
            Err(ClientError::ResponseChunk(
                crate::response::ResponseChunkError::DuplicateChunk { .. }
            ))
        ));

        let bytes = chunks[1].bytes().to_vec();
        // Keep the chunk metadata and length valid while changing the complete
        // response digest input.  The public type is intentionally immutable,
        // so use its canonical bytes and flip the final payload byte instead.
        let mut encoded = chunks[1].encode().expect("chunk encodes");
        let final_byte = encoded.last_mut().expect("chunk has payload");
        *final_byte ^= 1;
        assert_ne!(bytes.last(), encoded.last());
        let mut client = GuestBrokerClient::new(
            Duplex::with_responses(&[chunks[0].encode().expect("chunk encodes"), encoded]),
            session(),
        );
        assert!(matches!(
            client.request_with_id(request_id, operation()),
            Err(ClientError::ResponseChunk(
                crate::response::ResponseChunkError::DigestMismatch
            ))
        ));
    }

    #[test]
    fn truncated_and_oversized_frames_fail_before_unbounded_allocation() {
        let request_id = request(8);
        let response = expanded_response(request_id);
        let first = response.chunks().expect("expanded response has chunks")[0]
            .encode()
            .expect("chunk encodes");
        let mut truncated = Vec::new();
        let frame = ControlFrame::new(first).expect("first chunk fits").encode();
        truncated.extend_from_slice(&frame[..frame.len() - 1]);
        let mut client = GuestBrokerClient::new(Duplex::with_responses(&[]), session());
        client.transport_mut().incoming = io::Cursor::new(truncated);
        assert!(matches!(
            client.request_with_id(request_id, operation()),
            Err(ClientError::TruncatedFrame { .. })
        ));

        let mut oversized = Duplex::with_responses(&[]);
        oversized.incoming = io::Cursor::new(
            u32::try_from(crate::session::MAX_CONTROL_FRAME_BYTES + 1)
                .expect("test frame length fits u32")
                .to_be_bytes()
                .to_vec(),
        );
        let mut client = GuestBrokerClient::new(oversized, session());
        assert!(matches!(
            client.request_with_id(request(9), operation()),
            Err(ClientError::Frame(FrameError::FrameTooLarge { .. }))
        ));
    }

    #[test]
    fn configured_request_limit_bounds_identity_retention() {
        let id = request(10);
        let limits = ClientLimits::new(NonZeroUsize::new(1).expect("non-zero limit"));
        let mut client = GuestBrokerClient::with_limits(
            Duplex::with_responses(&[rejection(id)]),
            session(),
            limits,
        );
        assert!(client.request_with_id(id, operation()).is_ok());
        assert!(matches!(
            client.request_with_id(request(11), operation()),
            Err(ClientError::RequestLimitReached { maximum: 1 })
        ));
    }
}
