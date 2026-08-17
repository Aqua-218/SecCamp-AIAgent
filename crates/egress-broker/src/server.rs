//! Bounded, peer-bound broker connection serving.
//!
//! A connection is accepted only from the host-selected guest CID. Each
//! accepted request passes through the dispatcher exactly once and receives
//! the sole canonical response representation from `egress-protocol`.

use std::{error::Error, fmt, io, io::Read, io::Write, num::NonZeroUsize};

use egress_protocol::{
    frame::ControlFrame,
    response::{
        BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse, ResponseCborError,
        ResponseChunkError,
    },
};

use authority_core::time::MonotonicTime;

use crate::{
    dispatch::{
        BrokerDispatcher, BrokerEffect, BrokerOutcome, BrokerRejection, BrokerResponse,
        CapabilityExecutor, DispatchContext, DispatchError, PublicDispatchAdapter,
    },
    github::GitHubAdapter,
    transport::{
        DeadlineFramedTransport, DeadlineStream, FramedIo, FramedTransport, PeerBoundListener,
        TransportError, TransportPolicy,
    },
};

/// The result of serving one accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionReport {
    requests_served: usize,
    close_reason: ConnectionCloseReason,
}

/// Why a successfully served broker connection stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionCloseReason {
    /// The host-configured per-connection request bound was reached.
    RequestLimitReached,
    /// Broken byte accounting made further requests unsafe.
    AccountingInvariant,
    /// An external effect committed without its required terminal audit record.
    CommittedButUnrecorded,
}

impl ConnectionReport {
    /// Returns the number of request/response exchanges completed.
    #[must_use]
    pub const fn requests_served(self) -> usize {
        self.requests_served
    }

    /// Returns the typed reason this connection stopped.
    #[must_use]
    pub const fn close_reason(self) -> ConnectionCloseReason {
        self.close_reason
    }

    /// Returns whether a terminal safety invariant forced an early close.
    ///
    /// This compatibility view includes both broken accounting and a committed
    /// effect missing its audit record. Prefer [`Self::close_reason`] when
    /// callers must distinguish those conditions.
    #[must_use]
    pub const fn accounting_invariant_closed(self) -> bool {
        matches!(
            self.close_reason,
            ConnectionCloseReason::AccountingInvariant
                | ConnectionCloseReason::CommittedButUnrecorded
        )
    }
}

/// A dispatcher seam used by the connection loop and deterministic tests.
pub trait RequestDispatcher {
    /// Dispatches one already-bounded frame under immutable host context.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] when canonical decoding or replay admission
    /// rejects the request before a response can be produced.
    fn dispatch_request(
        &mut self,
        frame: &ControlFrame,
        context: &DispatchContext,
    ) -> Result<BrokerResponse, DispatchError>;
}

impl<E, P, G> RequestDispatcher for BrokerDispatcher<E, P, G>
where
    E: CapabilityExecutor,
    P: PublicDispatchAdapter,
    G: GitHubAdapter,
{
    fn dispatch_request(
        &mut self,
        frame: &ControlFrame,
        context: &DispatchContext,
    ) -> Result<BrokerResponse, DispatchError> {
        self.dispatch_control_frame(frame, context)
    }
}

/// Why a broker connection failed before a successful typed close report.
#[derive(Debug)]
pub enum ServerError {
    /// The listener failed to accept a peer.
    Accept(io::Error),
    /// The accepted peer was not the host-selected guest CID.
    UnexpectedPeer {
        /// Host-selected guest CID.
        expected: u32,
        /// CID reported by the accepted socket.
        received: u32,
    },
    /// Bounded frame I/O failed.
    Transport(TransportError),
    /// Canonical decoding, replay admission, or dispatch failed.
    Dispatch(DispatchError),
    /// A typed outcome could not fit the closed response schema.
    Response(ResponseCborError),
    /// A large response could not be represented as canonical bounded chunks.
    ResponseChunk(ResponseChunkError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(error) => write!(formatter, "accepting broker peer failed: {error}"),
            Self::UnexpectedPeer { expected, received } => write!(
                formatter,
                "broker peer CID {received} does not match expected CID {expected}"
            ),
            Self::Transport(error) => error.fmt(formatter),
            Self::Dispatch(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
            Self::ResponseChunk(error) => error.fmt(formatter),
        }
    }
}

impl Error for ServerError {}

/// Accepts and serves one connection from exactly `expected_peer_cid`.
///
/// The stream is dropped on a CID mismatch without reading guest bytes.
///
/// # Errors
///
/// Returns [`ServerError`] for accept, peer identity, framing, dispatch, or
/// canonical response failures.
pub fn serve_expected_peer<L, D, C>(
    listener: &L,
    expected_peer_cid: u32,
    dispatcher: &mut D,
    identity: &DispatchContext,
    clock: &mut C,
    max_requests: NonZeroUsize,
) -> Result<ConnectionReport, ServerError>
where
    L: PeerBoundListener,
    D: RequestDispatcher + ?Sized,
    C: FnMut() -> MonotonicTime,
{
    let (peer_cid, stream) = listener.accept_peer().map_err(ServerError::Accept)?;
    if peer_cid != expected_peer_cid {
        return Err(ServerError::UnexpectedPeer {
            expected: expected_peer_cid,
            received: peer_cid,
        });
    }
    serve_connection(stream, dispatcher, identity, clock, max_requests)
}

/// Accepts and serves one peer with a real socket deadline policy.
///
/// This is the production entry point for streams that implement
/// [`DeadlineStream`]. Generic `Cursor`-style streams cannot call it and thus
/// cannot accidentally claim to enforce timeouts. A failed deadline is a
/// typed [`TransportError::Deadline`] and the stream is dropped immediately;
/// an owner-side shutdown handle can interrupt an already blocked syscall.
///
/// # Errors
///
/// Returns [`ServerError`] for accept, peer identity, policy, framing,
/// dispatch, or canonical response failures.
pub fn serve_expected_peer_with_policy<L, D, C>(
    listener: &L,
    expected_peer_cid: u32,
    policy: TransportPolicy,
    dispatcher: &mut D,
    identity: &DispatchContext,
    clock: &mut C,
    max_requests: NonZeroUsize,
) -> Result<ConnectionReport, ServerError>
where
    L: PeerBoundListener,
    L::Stream: DeadlineStream,
    D: RequestDispatcher + ?Sized,
    C: FnMut() -> MonotonicTime,
{
    let (peer_cid, stream) = listener.accept_peer().map_err(ServerError::Accept)?;
    if peer_cid != expected_peer_cid {
        return Err(ServerError::UnexpectedPeer {
            expected: expected_peer_cid,
            received: peer_cid,
        });
    }
    serve_connection_with_policy(stream, policy, dispatcher, identity, clock, max_requests)
}

/// Serves at most `max_requests` on one already-authenticated connection.
///
/// Any framing, dispatch, encoding, or write error closes the connection by
/// returning ownership of the stream to this function's stack. Terminal safety
/// responses are written once and then force an early successful close so the
/// affected session cannot continue.
///
/// # Errors
///
/// Returns [`ServerError`] on the first failure and never attempts to recover
/// the byte stream after an ambiguous framing or write state.
pub fn serve_connection<S, D, C>(
    stream: S,
    dispatcher: &mut D,
    identity: &DispatchContext,
    clock: &mut C,
    max_requests: NonZeroUsize,
) -> Result<ConnectionReport, ServerError>
where
    S: Read + Write,
    D: RequestDispatcher + ?Sized,
    C: FnMut() -> MonotonicTime,
{
    let transport = FramedTransport::new(stream);
    serve_framed_connection(transport, dispatcher, identity, clock, max_requests)
}

/// Serves one already-authenticated stream with bounded read, write, and
/// absolute connection deadlines.
///
/// The stream must implement [`DeadlineStream`], which is intentionally
/// stricter than [`Read`] + [`Write`]. On a deadline, the function returns a
/// typed [`ServerError::Transport`] and drops the stream, so callers must not
/// retry an ambiguous frame on the same connection. A separate owner-only
/// shutdown handle can interrupt a blocked read or write immediately during
/// cancellation.
///
/// # Errors
///
/// Returns [`ServerError`] on policy application, deadline, framing, dispatch,
/// encoding, or write failure.
pub fn serve_connection_with_policy<S, D, C>(
    stream: S,
    policy: TransportPolicy,
    dispatcher: &mut D,
    identity: &DispatchContext,
    clock: &mut C,
    max_requests: NonZeroUsize,
) -> Result<ConnectionReport, ServerError>
where
    S: DeadlineStream,
    D: RequestDispatcher + ?Sized,
    C: FnMut() -> MonotonicTime,
{
    let transport = DeadlineFramedTransport::new(stream, policy).map_err(ServerError::Transport)?;
    serve_framed_connection(transport, dispatcher, identity, clock, max_requests)
}

fn serve_framed_connection<T, D, C>(
    mut transport: T,
    dispatcher: &mut D,
    identity: &DispatchContext,
    clock: &mut C,
    max_requests: NonZeroUsize,
) -> Result<ConnectionReport, ServerError>
where
    T: FramedIo,
    D: RequestDispatcher + ?Sized,
    C: FnMut() -> MonotonicTime,
{
    for request_index in 0..max_requests.get() {
        let frame = transport.read_frame().map_err(ServerError::Transport)?;
        // Re-read the clock per request. Reusing one instant for the whole
        // connection lets a capability whose validity window closes mid-stream
        // keep authorizing until the connection ends.
        let context = DispatchContext {
            now: clock(),
            ..identity.clone()
        };
        let response = dispatcher
            .dispatch_request(&frame, &context)
            .map_err(ServerError::Dispatch)?;
        // Both cases leave host state the guest must not keep transacting
        // against: broken byte accounting, or an external effect whose terminal
        // audit record is missing and that an operator has to reconcile.
        let close_reason = match &response.outcome {
            BrokerOutcome::Rejected(BrokerRejection::AccountingInvariant) => {
                Some(ConnectionCloseReason::AccountingInvariant)
            }
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded) => {
                Some(ConnectionCloseReason::CommittedButUnrecorded)
            }
            BrokerOutcome::Succeeded(_)
            | BrokerOutcome::Rejected(
                BrokerRejection::NotAuthorized
                | BrokerRejection::Budget
                | BrokerRejection::OperationMismatch
                | BrokerRejection::PublicFetch(_)
                | BrokerRejection::GitHub(_)
                | BrokerRejection::AuditUnavailable,
            ) => None,
        };
        let wire = response_to_wire(response);
        write_wire_response(&mut transport, &wire)?;
        if let Some(close_reason) = close_reason {
            return Ok(ConnectionReport {
                requests_served: request_index + 1,
                close_reason,
            });
        }
    }
    Ok(ConnectionReport {
        requests_served: max_requests.get(),
        close_reason: ConnectionCloseReason::RequestLimitReached,
    })
}

fn write_wire_response<T>(
    transport: &mut T,
    wire: &CanonicalBrokerResponse,
) -> Result<(), ServerError>
where
    T: FramedIo,
{
    match wire.encode() {
        Ok(payload) => write_payload_frame(transport, payload),
        Err(ResponseCborError::PayloadTooLarge { .. }) => {
            for payload in wire
                .encoded_chunk_iter()
                .map_err(ServerError::ResponseChunk)?
            {
                let payload = payload.map_err(ServerError::ResponseChunk)?;
                write_payload_frame(transport, payload)?;
            }
            Ok(())
        }
        Err(error) => Err(ServerError::Response(error)),
    }
}

fn write_payload_frame<T>(transport: &mut T, payload: Vec<u8>) -> Result<(), ServerError>
where
    T: FramedIo,
{
    let response_frame = ControlFrame::new(payload)
        .map_err(|error| ServerError::Transport(TransportError::Frame(error)))?;
    transport
        .write_frame(&response_frame)
        .map_err(ServerError::Transport)
}

fn response_to_wire(response: BrokerResponse) -> CanonicalBrokerResponse {
    let outcome = match response.outcome {
        BrokerOutcome::Succeeded(BrokerEffect::Public(public)) => {
            BrokerWireOutcome::Public(public.into_wire())
        }
        BrokerOutcome::Succeeded(BrokerEffect::GitHub(github)) => {
            BrokerWireOutcome::GitHub(github.into_wire())
        }
        BrokerOutcome::Rejected(rejection) => BrokerWireOutcome::Rejected(match rejection {
            BrokerRejection::NotAuthorized => BrokerWireRejection::NotAuthorized,
            BrokerRejection::Budget => BrokerWireRejection::Budget,
            BrokerRejection::OperationMismatch => BrokerWireRejection::OperationMismatch,
            BrokerRejection::PublicFetch(_) => BrokerWireRejection::PublicFetch,
            BrokerRejection::GitHub(_) => BrokerWireRejection::GitHub,
            BrokerRejection::AccountingInvariant => BrokerWireRejection::AccountingInvariant,
            BrokerRejection::AuditUnavailable => BrokerWireRejection::AuditUnavailable,
            BrokerRejection::CommittedButUnrecorded => BrokerWireRejection::CommittedButUnrecorded,
        }),
    };
    CanonicalBrokerResponse::new(response.request, outcome)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{self, Cursor, Read, Write},
        num::NonZeroUsize,
        sync::{Arc, Mutex},
    };

    use authority_core::{
        capability::{CapId, SubjectId},
        http::{CanonicalHost, CanonicalUrlPath},
        time::MonotonicTime,
    };
    use egress_protocol::{
        frame::ControlFrame,
        response::{
            BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse, CanonicalResponseChunk,
        },
        session::{BrokerRequestId, MAX_CONTROL_FRAME_BYTES},
    };

    use crate::{
        dispatch::{
            BrokerEffect, BrokerOutcome, BrokerRejection, BrokerResponse, DispatchContext,
            DispatchError,
        },
        public_fetch::PublicResponse,
        transport::{DeadlineKind, DeadlineStream, PeerBoundListener},
    };

    use super::{
        ConnectionCloseReason, RequestDispatcher, ServerError, serve_connection,
        serve_expected_peer,
    };

    #[derive(Clone)]
    struct DuplexBuffer {
        input: Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
    }

    struct TimeoutStream;

    impl Read for TimeoutStream {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        }
    }

    impl Write for TimeoutStream {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::TimedOut))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineStream for TimeoutStream {
        fn set_read_timeout(&self, _timeout: std::time::Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: std::time::Duration) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for DuplexBuffer {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for DuplexBuffer {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output
                .lock()
                .expect("output lock must not be poisoned")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeDispatcher {
        outcomes: VecDeque<BrokerResponse>,
        calls: usize,
    }

    impl RequestDispatcher for FakeDispatcher {
        fn dispatch_request(
            &mut self,
            _frame: &ControlFrame,
            _context: &DispatchContext,
        ) -> Result<BrokerResponse, DispatchError> {
            self.calls += 1;
            Ok(self
                .outcomes
                .pop_front()
                .expect("fixture outcome must exist"))
        }
    }

    struct FakeListener {
        cid: u32,
        stream: Mutex<Option<DuplexBuffer>>,
    }

    impl PeerBoundListener for FakeListener {
        type Stream = DuplexBuffer;

        fn accept_peer(&self) -> io::Result<(u32, Self::Stream)> {
            let stream = self
                .stream
                .lock()
                .expect("listener lock must not be poisoned")
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "already accepted"))?;
            Ok((self.cid, stream))
        }
    }

    fn context() -> DispatchContext {
        DispatchContext {
            caller: SubjectId::new("subject"),
            capability: CapId::new("capability"),
            now: MonotonicTime::from_ticks(7),
        }
    }

    fn request_frame(byte: u8) -> Vec<u8> {
        ControlFrame::new(vec![byte])
            .expect("fixture request must fit")
            .encode()
    }

    fn rejection(id: u8, rejection: BrokerRejection) -> BrokerResponse {
        BrokerResponse {
            request: BrokerRequestId::new([id; 16]),
            outcome: BrokerOutcome::Rejected(rejection),
        }
    }

    fn decode_frames(mut encoded: &[u8]) -> Vec<CanonicalBrokerResponse> {
        let mut responses = Vec::new();
        while !encoded.is_empty() {
            let length = u32::from_be_bytes(encoded[..4].try_into().expect("length prefix"));
            let length = usize::try_from(length).expect("frame length must fit");
            responses.push(
                CanonicalBrokerResponse::decode(&encoded[4..4 + length])
                    .expect("response must be canonical"),
            );
            encoded = &encoded[4 + length..];
        }
        responses
    }

    fn decode_frame_payloads(mut encoded: &[u8]) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        while !encoded.is_empty() {
            let length = u32::from_be_bytes(encoded[..4].try_into().expect("length prefix"));
            let length = usize::try_from(length).expect("frame length must fit");
            payloads.push(encoded[4..4 + length].to_vec());
            encoded = &encoded[4 + length..];
        }
        payloads
    }

    // Requirement: a capability whose validity window closes mid-connection stops authorizing there.
    // Category: unit/security. Risk: high.
    #[test]
    fn each_request_on_one_connection_reads_the_clock_again() {
        let mut input = request_frame(1);
        input.extend(request_frame(2));
        let output = Arc::new(Mutex::new(Vec::new()));
        let stream = DuplexBuffer {
            input: Cursor::new(input),
            output,
        };
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([
                rejection(1, BrokerRejection::Budget),
                rejection(2, BrokerRejection::Budget),
            ]),
            calls: 0,
        };
        let mut ticks = 0_u64;

        let report = serve_connection(
            stream,
            &mut dispatcher,
            &context(),
            &mut || {
                ticks += 1;
                MonotonicTime::from_ticks(ticks)
            },
            NonZeroUsize::new(2).expect("bound must be non-zero"),
        )
        .expect("both requests must be served");

        assert_eq!(report.requests_served(), 2);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::RequestLimitReached
        );
        assert_eq!(
            ticks, 2,
            "the clock must be read once per request, not once per connection"
        );
    }

    #[test]
    fn connection_stops_at_the_host_request_bound() {
        let mut input = request_frame(1);
        input.extend(request_frame(2));
        input.extend(request_frame(3));
        let output = Arc::new(Mutex::new(Vec::new()));
        let stream = DuplexBuffer {
            input: Cursor::new(input),
            output: Arc::clone(&output),
        };
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([
                rejection(1, BrokerRejection::Budget),
                rejection(2, BrokerRejection::NotAuthorized),
                rejection(3, BrokerRejection::OperationMismatch),
            ]),
            calls: 0,
        };

        let report = serve_connection(
            stream,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(2).expect("bound must be non-zero"),
        )
        .expect("bounded connection must succeed");

        assert_eq!(report.requests_served(), 2);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::RequestLimitReached
        );
        assert!(!report.accounting_invariant_closed());
        assert_eq!(dispatcher.calls, 2);
        assert_eq!(
            decode_frames(&output.lock().expect("output lock")),
            vec![
                CanonicalBrokerResponse::new(
                    BrokerRequestId::new([1; 16]),
                    BrokerWireOutcome::Rejected(BrokerWireRejection::Budget),
                ),
                CanonicalBrokerResponse::new(
                    BrokerRequestId::new([2; 16]),
                    BrokerWireOutcome::Rejected(BrokerWireRejection::NotAuthorized),
                ),
            ]
        );
    }

    #[test]
    fn accounting_invariant_is_written_once_then_closes_the_connection() {
        let mut input = request_frame(1);
        input.extend(request_frame(2));
        let output = Arc::new(Mutex::new(Vec::new()));
        let stream = DuplexBuffer {
            input: Cursor::new(input),
            output: Arc::clone(&output),
        };
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([
                rejection(1, BrokerRejection::AccountingInvariant),
                rejection(2, BrokerRejection::Budget),
            ]),
            calls: 0,
        };

        let report = serve_connection(
            stream,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(2).expect("bound must be non-zero"),
        )
        .expect("accounting response must be written before close");

        assert_eq!(report.requests_served(), 1);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::AccountingInvariant
        );
        assert!(report.accounting_invariant_closed());
        assert_eq!(dispatcher.calls, 1);
        assert_eq!(decode_frames(&output.lock().expect("output lock")).len(), 1);
    }

    // Requirement: post-effect audit loss has a distinct typed close reason.
    // Category: unit/accounting. Risk: critical.
    #[test]
    fn committed_but_unrecorded_is_written_once_then_reported_distinctly() {
        let mut input = request_frame(1);
        input.extend(request_frame(2));
        let output = Arc::new(Mutex::new(Vec::new()));
        let stream = DuplexBuffer {
            input: Cursor::new(input),
            output: Arc::clone(&output),
        };
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([
                rejection(1, BrokerRejection::CommittedButUnrecorded),
                rejection(2, BrokerRejection::Budget),
            ]),
            calls: 0,
        };

        let report = serve_connection(
            stream,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(2).expect("bound must be non-zero"),
        )
        .expect("committed-but-unrecorded response must be written before close");

        assert_eq!(report.requests_served(), 1);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::CommittedButUnrecorded
        );
        assert!(report.accounting_invariant_closed());
        assert_eq!(dispatcher.calls, 1);
        assert_eq!(decode_frames(&output.lock().expect("output lock")).len(), 1);
    }

    // Requirement: production can erase the concrete dispatcher behind a Box.
    // Category: unit/integration seam. Risk: high.
    #[test]
    fn connection_accepts_boxed_dynamic_dispatcher() {
        let stream = DuplexBuffer {
            input: Cursor::new(request_frame(1)),
            output: Arc::new(Mutex::new(Vec::new())),
        };
        let mut dispatcher: Box<dyn RequestDispatcher> = Box::new(FakeDispatcher {
            outcomes: VecDeque::from([rejection(1, BrokerRejection::Budget)]),
            calls: 0,
        });

        let report = serve_connection(
            stream,
            dispatcher.as_mut(),
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(1).expect("bound must be non-zero"),
        )
        .expect("boxed dispatcher must serve a connection");

        assert_eq!(report.requests_served(), 1);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::RequestLimitReached
        );
    }

    // Requirement: a transport deadline fails closed before dispatch and does
    // not attempt to recover or write a response on an ambiguous stream.
    // Category: timeout/fail-closed. Risk: critical.
    #[test]
    fn deadline_error_closes_connection_before_dispatch() {
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([rejection(1, BrokerRejection::Budget)]),
            calls: 0,
        };
        let policy = super::TransportPolicy::new(
            std::time::Duration::from_millis(10),
            std::time::Duration::from_millis(10),
            std::time::Duration::from_secs(1),
        )
        .expect("test policy must be valid");

        let error = super::serve_connection_with_policy(
            TimeoutStream,
            policy,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(1).expect("request bound must be non-zero"),
        )
        .expect_err("deadline must close the connection");

        assert!(matches!(
            error,
            ServerError::Transport(super::TransportError::Deadline(DeadlineKind::Read))
        ));
        assert_eq!(dispatcher.calls, 0);
    }

    #[test]
    fn expanded_response_is_written_as_reassemblable_bounded_chunks() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let stream = DuplexBuffer {
            input: Cursor::new(request_frame(1)),
            output: Arc::clone(&output),
        };
        let request = BrokerRequestId::new([7; 16]);
        let response = PublicResponse::new(
            200,
            CanonicalHost::new("public.example").expect("fixture host"),
            CanonicalUrlPath::new("/large").expect("fixture path"),
            vec![0x5a; MAX_CONTROL_FRAME_BYTES],
        )
        .expect("expanded response must fit the public cap");
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([BrokerResponse {
                request,
                outcome: BrokerOutcome::Succeeded(BrokerEffect::Public(response)),
            }]),
            calls: 0,
        };

        let report = serve_connection(
            stream,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(1).expect("bound must be non-zero"),
        )
        .expect("large response must be served");

        let payloads = decode_frame_payloads(&output.lock().expect("output lock"));
        assert!(payloads.len() > 1);
        assert!(
            payloads
                .iter()
                .all(|payload| payload.len() <= MAX_CONTROL_FRAME_BYTES)
        );
        let chunks = payloads
            .iter()
            .map(|payload| CanonicalResponseChunk::decode(payload).expect("canonical chunk"))
            .collect::<Vec<_>>();
        let reassembled = CanonicalBrokerResponse::from_chunks(&chunks)
            .expect("complete chunk sequence must reassemble");
        assert_eq!(reassembled.request(), request);
        assert!(
            matches!(reassembled.outcome(), BrokerWireOutcome::Public(public) if public.body().len() == MAX_CONTROL_FRAME_BYTES)
        );
        assert_eq!(report.requests_served(), 1);
        assert_eq!(
            report.close_reason(),
            ConnectionCloseReason::RequestLimitReached
        );
        assert_eq!(dispatcher.calls, 1);
    }

    #[test]
    fn unexpected_peer_is_dropped_before_dispatch() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let listener = FakeListener {
            cid: 99,
            stream: Mutex::new(Some(DuplexBuffer {
                input: Cursor::new(request_frame(1)),
                output: Arc::clone(&output),
            })),
        };
        let mut dispatcher = FakeDispatcher {
            outcomes: VecDeque::from([rejection(1, BrokerRejection::Budget)]),
            calls: 0,
        };

        let error = serve_expected_peer(
            &listener,
            42,
            &mut dispatcher,
            &context(),
            &mut || MonotonicTime::from_ticks(7),
            NonZeroUsize::new(1).expect("bound must be non-zero"),
        )
        .expect_err("unexpected CID must fail closed");

        assert!(matches!(
            error,
            ServerError::UnexpectedPeer {
                expected: 42,
                received: 99
            }
        ));
        assert_eq!(dispatcher.calls, 0);
        assert!(output.lock().expect("output lock").is_empty());
    }
}
