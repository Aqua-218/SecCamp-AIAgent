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
    },
};

use authority_core::time::MonotonicTime;

use crate::{
    dispatch::{
        BrokerDispatcher, BrokerEffect, BrokerOutcome, BrokerRejection, BrokerResponse,
        CapabilityExecutor, DispatchContext, DispatchError, PublicDispatchAdapter,
    },
    github::GitHubAdapter,
    transport::{FramedTransport, PeerBoundListener, TransportError},
};

/// The result of serving one accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionReport {
    requests_served: usize,
    accounting_invariant_closed: bool,
}

impl ConnectionReport {
    /// Returns the number of request/response exchanges completed.
    #[must_use]
    pub const fn requests_served(self) -> usize {
        self.requests_served
    }

    /// Returns whether an accounting invariant forced an early close.
    #[must_use]
    pub const fn accounting_invariant_closed(self) -> bool {
        self.accounting_invariant_closed
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

/// Why a broker connection was closed before its configured request bound.
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
    D: RequestDispatcher,
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

/// Serves at most `max_requests` on one already-authenticated connection.
///
/// Any framing, dispatch, encoding, or write error closes the connection by
/// returning ownership of the stream to this function's stack. An accounting
/// invariant response is written once and then forces an early successful
/// close so the affected session cannot continue.
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
    D: RequestDispatcher,
    C: FnMut() -> MonotonicTime,
{
    let mut transport = FramedTransport::new(stream);
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
        let close_after_response = matches!(
            response.outcome,
            BrokerOutcome::Rejected(
                BrokerRejection::AccountingInvariant | BrokerRejection::CommittedButUnrecorded
            )
        );
        let wire = response_to_wire(response);
        let payload = wire.encode().map_err(ServerError::Response)?;
        let response_frame = ControlFrame::new(payload)
            .map_err(|error| ServerError::Transport(TransportError::Frame(error)))?;
        transport
            .write_frame(&response_frame)
            .map_err(ServerError::Transport)?;
        if close_after_response {
            return Ok(ConnectionReport {
                requests_served: request_index + 1,
                accounting_invariant_closed: true,
            });
        }
    }
    Ok(ConnectionReport {
        requests_served: max_requests.get(),
        accounting_invariant_closed: false,
    })
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
        time::MonotonicTime,
    };
    use egress_protocol::{
        frame::ControlFrame,
        response::{BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse},
        session::BrokerRequestId,
    };

    use crate::{
        dispatch::{
            BrokerOutcome, BrokerRejection, BrokerResponse, DispatchContext, DispatchError,
        },
        transport::PeerBoundListener,
    };

    use super::{RequestDispatcher, ServerError, serve_connection, serve_expected_peer};

    #[derive(Clone)]
    struct DuplexBuffer {
        input: Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
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
        assert!(report.accounting_invariant_closed());
        assert_eq!(dispatcher.calls, 1);
        assert_eq!(decode_frames(&output.lock().expect("output lock")).len(), 1);
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
