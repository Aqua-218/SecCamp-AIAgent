//! `AF_VSOCK` listener abstraction and allocation-safe frame I/O.
//!
//! The listener is intentionally separate from dispatch policy. A stream
//! reader validates the four-byte length prefix before allocating payload
//! memory, and callers then pass the complete `ControlFrame` to
//! `BrokerDispatcher` for canonical CBOR, replay, budget, and authorization.

use std::{
    io::{self, Read, Write},
    net::Shutdown,
    time::{Duration, Instant},
};

use egress_protocol::{
    frame::{CONTROL_FRAME_LENGTH_PREFIX_BYTES, ControlFrame, FrameError, ValidatedFrameLength},
    session::MAX_CONTROL_FRAME_BYTES,
};

const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_PORT_ANY: u32 = u32::MAX;

/// The maximum duration accepted for one Broker transport timeout.
///
/// A timeout is configuration, not peer input. Keeping a finite upper bound
/// prevents an accidental `Duration::MAX` from turning a connection into an
/// effectively unbounded resource reservation.
pub const MAX_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// Default maximum time a peer may spend in one read operation.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum time a peer may spend in one write operation.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum lifetime of one accepted Broker connection.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Validated bounded deadlines for one Broker connection.
///
/// `read_timeout` and `write_timeout` bound individual blocking operations.
/// `connection_timeout` is an absolute lifetime from transport construction;
/// the deadline-aware server path reapplies the remaining time before every
/// frame operation. The plain [`FramedTransport`] constructor intentionally
/// has no timeout claims so deterministic `Cursor` and in-memory streams stay
/// useful in unit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPolicy {
    read: Duration,
    write: Duration,
    connection: Duration,
}

impl TransportPolicy {
    /// Creates a policy after validating every timeout is finite and positive.
    ///
    /// # Errors
    ///
    /// Returns [`TransportConfigError`] when a duration is zero or exceeds
    /// [`MAX_TRANSPORT_TIMEOUT`].
    pub fn new(
        read_timeout: Duration,
        write_timeout: Duration,
        connection_timeout: Duration,
    ) -> Result<Self, TransportConfigError> {
        validate_timeout("read_timeout", read_timeout)?;
        validate_timeout("write_timeout", write_timeout)?;
        validate_timeout("connection_timeout", connection_timeout)?;
        Ok(Self {
            read: read_timeout,
            write: write_timeout,
            connection: connection_timeout,
        })
    }

    /// Returns the per-read blocking bound.
    #[must_use]
    pub const fn read_timeout(self) -> Duration {
        self.read
    }

    /// Returns the per-write blocking bound.
    #[must_use]
    pub const fn write_timeout(self) -> Duration {
        self.write
    }

    /// Returns the absolute connection lifetime bound.
    #[must_use]
    pub const fn connection_timeout(self) -> Duration {
        self.connection
    }

    fn effective_read_timeout(self) -> Duration {
        self.read.min(self.connection)
    }

    fn effective_write_timeout(self) -> Duration {
        self.write.min(self.connection)
    }
}

impl Default for TransportPolicy {
    fn default() -> Self {
        // These constants are validated at compile time by the values above;
        // keep the fallible constructor in one place for custom policies.
        Self {
            read: DEFAULT_READ_TIMEOUT,
            write: DEFAULT_WRITE_TIMEOUT,
            connection: DEFAULT_CONNECTION_TIMEOUT,
        }
    }
}

fn validate_timeout(field: &'static str, timeout: Duration) -> Result<(), TransportConfigError> {
    if timeout.is_zero() {
        return Err(TransportConfigError::Zero { field });
    }
    if timeout > MAX_TRANSPORT_TIMEOUT {
        return Err(TransportConfigError::TooLarge {
            field,
            maximum: MAX_TRANSPORT_TIMEOUT,
        });
    }
    Ok(())
}

/// A transport configuration was invalid before any peer bytes were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConfigError {
    /// A timeout of zero would make every connection fail immediately.
    Zero {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// The timeout exceeds the hard safety bound.
    TooLarge {
        /// Name of the invalid field.
        field: &'static str,
        /// Maximum accepted duration.
        maximum: Duration,
    },
}

impl std::fmt::Display for TransportConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero { field } => write!(formatter, "{field} must be greater than zero"),
            Self::TooLarge { field, maximum } => {
                write!(
                    formatter,
                    "{field} exceeds maximum transport timeout {maximum:?}"
                )
            }
        }
    }
}

impl std::error::Error for TransportConfigError {}

/// Which direction reached a configured transport deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    /// Reading a request frame exceeded its bound.
    Read,
    /// Writing a response frame exceeded its bound.
    Write,
    /// The absolute connection lifetime elapsed before an operation started.
    Connection,
}

impl std::fmt::Display for DeadlineKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Connection => "connection",
        })
    }
}

/// Socket-like stream operations needed to apply real transport deadlines.
///
/// This trait is deliberately separate from [`Read`] and [`Write`]. Generic
/// test streams do not implement it and therefore cannot accidentally claim
/// that a `Cursor` has an enforced timeout. Production socket wrappers, and
/// deterministic test doubles that model timeout behavior, can opt in.
pub trait DeadlineStream: Read + Write {
    /// Applies a read timeout to the underlying socket.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the option cannot be applied.
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()>;

    /// Applies a write timeout to the underlying socket.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error when the option cannot be applied.
    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()>;
}

/// A listener that accepts host/guest byte streams.
pub trait VsockListener {
    /// Stream type returned for one accepted connection.
    type Stream: Read + Write;

    /// Accepts one connection.
    ///
    /// # Errors
    ///
    /// Returns the underlying operating-system error when accepting fails.
    fn accept(&self) -> io::Result<Self::Stream>;
}

/// A listener that reports the authenticated transport peer identity.
pub trait PeerBoundListener {
    /// Stream type returned for one accepted connection.
    type Stream: Read + Write;

    /// Accepts one connection and returns its kernel-reported peer CID.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when accept fails or the peer address
    /// is not an `AF_VSOCK` address.
    fn accept_peer(&self) -> io::Result<(u32, Self::Stream)>;
}

/// A safe wrapper around one accepted `AF_VSOCK` stream.
#[derive(Debug)]
pub struct VsockStream {
    socket: socket2::Socket,
}

impl VsockStream {
    /// Clones only the socket ownership needed by the worker owner to cancel a
    /// connected Broker operation.
    ///
    /// The returned handle cannot read, write, or be converted back into a
    /// stream. Calling [`VsockShutdownHandle::shutdown`] interrupts blocking
    /// frame I/O by applying `SHUT_RDWR` to the shared socket endpoint.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if the socket descriptor cannot be
    /// duplicated.
    pub fn shutdown_handle(&self) -> io::Result<VsockShutdownHandle> {
        self.socket
            .try_clone()
            .map(|socket| VsockShutdownHandle { socket })
    }
}

/// Owner-only cancellation capability for one accepted vsock connection.
///
/// This type deliberately implements neither [`Read`] nor [`Write`]. Holding
/// it grants only the ability to interrupt both directions of the associated
/// stream; it does not duplicate the Broker data plane.
#[derive(Debug)]
pub struct VsockShutdownHandle {
    socket: socket2::Socket,
}

impl VsockShutdownHandle {
    /// Interrupts reads and writes on every descriptor for this socket.
    ///
    /// # Errors
    ///
    /// Returns the operating-system shutdown error.
    pub fn shutdown(&self) -> io::Result<()> {
        self.socket.shutdown(Shutdown::Both)
    }
}

impl Read for VsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.read(buffer)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for VsockStream {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_read_timeout(Some(timeout))
    }

    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_write_timeout(Some(timeout))
    }
}

/// A Linux `AF_VSOCK` stream listener.
#[derive(Debug)]
pub struct AfVsockListener {
    socket: socket2::Socket,
    cid: u32,
    port: u32,
    nonblocking: bool,
    policy: TransportPolicy,
}

impl AfVsockListener {
    /// Binds an `AF_VSOCK` listener to the requested CID and port.
    ///
    /// The CID and port are retained for observability and are not interpreted
    /// as guest-controlled request data.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if `AF_VSOCK` is unavailable or the
    /// address cannot be bound.
    pub fn bind(cid: u32, port: u32, backlog: i32) -> io::Result<Self> {
        Self::bind_with_policy(cid, port, backlog, TransportPolicy::default())
    }

    /// Binds an `AF_VSOCK` listener and applies `policy` to every accepted
    /// stream before returning it to the connection owner.
    ///
    /// # Errors
    ///
    /// Returns [`TransportConfigError`] as an `InvalidInput` error when the
    /// supplied policy is invalid, or an operating-system bind error.
    pub fn bind_with_policy(
        cid: u32,
        port: u32,
        backlog: i32,
        policy: TransportPolicy,
    ) -> io::Result<Self> {
        Self::bind_with_mode(cid, port, backlog, false, policy)
    }

    /// Binds an `AF_VSOCK` listener whose accept path never blocks.
    ///
    /// Owners can poll [`Self::try_accept_peer`] between cancellation checks.
    /// Accepted streams are restored to blocking mode for ordinary framed I/O.
    ///
    /// # Errors
    ///
    /// Returns the same endpoint validation, socket, bind, or listen errors as
    /// [`Self::bind`], plus an error if nonblocking mode cannot be enabled.
    pub fn bind_nonblocking(cid: u32, port: u32, backlog: i32) -> io::Result<Self> {
        Self::bind_nonblocking_with_policy(cid, port, backlog, TransportPolicy::default())
    }

    /// Binds a nonblocking `AF_VSOCK` listener with an explicit transport
    /// policy for accepted streams.
    ///
    /// # Errors
    ///
    /// Returns the same endpoint, policy, socket, bind, and listen errors as
    /// [`Self::bind_with_policy`], plus an error if nonblocking mode cannot be
    /// enabled.
    pub fn bind_nonblocking_with_policy(
        cid: u32,
        port: u32,
        backlog: i32,
        policy: TransportPolicy,
    ) -> io::Result<Self> {
        Self::bind_with_mode(cid, port, backlog, true, policy)
    }

    fn bind_with_mode(
        cid: u32,
        port: u32,
        backlog: i32,
        nonblocking: bool,
        policy: TransportPolicy,
    ) -> io::Result<Self> {
        if cid == VMADDR_CID_ANY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_VSOCK listener CID must be explicit",
            ));
        }
        if port == 0 || port == VMADDR_PORT_ANY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_VSOCK listener port must be a non-zero explicit value",
            ));
        }
        if backlog <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AF_VSOCK listener backlog must be positive",
            ));
        }
        // `TransportPolicy` is normally constructed through `new`, but it is
        // public and `Default` is infallible. Keep this check at the socket
        // boundary so a future constructor cannot accidentally bypass it.
        TransportPolicy::new(
            policy.read_timeout(),
            policy.write_timeout(),
            policy.connection_timeout(),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let socket = socket2::Socket::new(socket2::Domain::VSOCK, socket2::Type::STREAM, None)?;
        let address = socket2::SockAddr::vsock(cid, port);
        socket.bind(&address)?;
        socket.listen(backlog)?;
        socket.set_nonblocking(nonblocking)?;
        Ok(Self {
            socket,
            cid,
            port,
            nonblocking,
            policy,
        })
    }

    /// Returns the bound CID configured by the host.
    #[must_use]
    pub const fn cid(&self) -> u32 {
        self.cid
    }

    /// Returns the bound port configured by the host.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }

    /// Returns whether this listener was created for nonblocking polling.
    #[must_use]
    pub const fn is_nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Attempts one nonblocking accept without allocating a worker thread.
    ///
    /// `Ok(None)` means no connection is ready, allowing the owner to check its
    /// cancellation signal before polling again.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if this listener was created by
    /// [`Self::bind`] rather than [`Self::bind_nonblocking`]. Other errors come
    /// from accepting or validating the peer address.
    pub fn try_accept(&self) -> io::Result<Option<VsockStream>> {
        self.try_accept_peer()
            .map(|accepted| accepted.map(|(_, stream)| stream))
    }

    /// Attempts one nonblocking accept and returns the kernel-reported peer CID.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::try_accept`].
    pub fn try_accept_peer(&self) -> io::Result<Option<(u32, VsockStream)>> {
        if !self.nonblocking {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonblocking accept requires AfVsockListener::bind_nonblocking",
            ));
        }
        classify_nonblocking_accept(self.accept_peer_socket(true))
    }

    fn accept_peer_socket(&self, blocking_stream: bool) -> io::Result<(u32, VsockStream)> {
        let (socket, peer) = self.socket.accept()?;
        if blocking_stream {
            socket.set_nonblocking(false)?;
        }
        let (peer_cid, _peer_port) = peer.as_vsock_address().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "accepted peer did not provide an AF_VSOCK address",
            )
        })?;
        let stream = VsockStream { socket };
        stream
            .set_read_timeout(self.policy.effective_read_timeout())
            .and_then(|()| stream.set_write_timeout(self.policy.effective_write_timeout()))?;
        Ok((peer_cid, stream))
    }
}

impl VsockListener for AfVsockListener {
    type Stream = VsockStream;

    fn accept(&self) -> io::Result<Self::Stream> {
        self.accept_peer().map(|(_, stream)| stream)
    }
}

impl PeerBoundListener for AfVsockListener {
    type Stream = VsockStream;

    fn accept_peer(&self) -> io::Result<(u32, Self::Stream)> {
        self.accept_peer_socket(false)
    }
}

fn classify_nonblocking_accept<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(accepted) => Ok(Some(accepted)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

/// A length-prefixed frame reader/writer for one connection.
pub struct FramedTransport<S> {
    stream: S,
}

impl<S> FramedTransport<S>
where
    S: Read + Write,
{
    /// Wraps one accepted stream.
    #[must_use]
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Reads exactly one bounded frame.
    ///
    /// The payload allocation occurs only after the peer length passes
    /// `egress-protocol`'s one-megabyte limit.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::FrameTooLarge`] before allocating an oversized
    /// payload, or propagates stream truncation/I/O errors.
    pub fn read_frame(&mut self) -> Result<ControlFrame, TransportError> {
        let mut prefix = [0_u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES];
        self.stream
            .read_exact(&mut prefix)
            .map_err(TransportError::Io)?;
        let length = ValidatedFrameLength::from_network_prefix(prefix)
            .map_err(TransportError::Frame)?
            .as_usize();
        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(TransportError::Io)?;
        ControlFrame::new(payload).map_err(TransportError::Frame)
    }

    /// Writes one complete bounded frame.
    ///
    /// # Errors
    ///
    /// Returns a frame error for an oversized payload or an I/O error from the
    /// underlying stream.
    pub fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), TransportError> {
        let encoded = frame.encode();
        if frame.payload().len() > MAX_CONTROL_FRAME_BYTES {
            return Err(TransportError::Frame(FrameError::FrameTooLarge {
                length: frame.payload().len(),
            }));
        }
        self.stream.write_all(&encoded).map_err(TransportError::Io)
    }
}

/// A framed transport with real socket deadline enforcement.
///
/// Unlike [`FramedTransport`], construction requires [`DeadlineStream`]. The
/// policy is applied before any peer bytes are consumed, and the remaining
/// absolute connection budget is applied again before each frame phase. This
/// keeps slowloris reads and blocked writes bounded while leaving generic
/// in-memory test streams free of fake timeout behavior.
pub struct DeadlineFramedTransport<S> {
    stream: S,
    policy: TransportPolicy,
    connection_deadline: Instant,
}

impl<S> DeadlineFramedTransport<S>
where
    S: DeadlineStream,
{
    /// Wraps `stream` and applies the validated deadline policy immediately.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when the underlying socket rejects a
    /// timeout option. No frame bytes are read in that case.
    pub fn new(stream: S, policy: TransportPolicy) -> Result<Self, TransportError> {
        let connection_deadline = Instant::now()
            .checked_add(policy.connection_timeout())
            .ok_or(TransportError::Deadline(DeadlineKind::Connection))?;
        stream
            .set_read_timeout(policy.effective_read_timeout())
            .map_err(TransportError::Io)?;
        stream
            .set_write_timeout(policy.effective_write_timeout())
            .map_err(TransportError::Io)?;
        Ok(Self {
            stream,
            policy,
            connection_deadline,
        })
    }

    fn remaining(&self) -> Result<Duration, TransportError> {
        let remaining = self
            .connection_deadline
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Deadline(DeadlineKind::Connection));
        }
        Ok(remaining)
    }

    fn prepare_read(&self) -> Result<bool, TransportError> {
        let remaining = self.remaining()?;
        let connection_is_tighter = remaining <= self.policy.read_timeout();
        self.stream
            .set_read_timeout(remaining.min(self.policy.read_timeout()))
            .map_err(TransportError::Io)?;
        Ok(connection_is_tighter)
    }

    fn prepare_write(&self) -> Result<bool, TransportError> {
        let remaining = self.remaining()?;
        let connection_is_tighter = remaining <= self.policy.write_timeout();
        self.stream
            .set_write_timeout(remaining.min(self.policy.write_timeout()))
            .map_err(TransportError::Io)?;
        Ok(connection_is_tighter)
    }

    /// Reads exactly one bounded frame under the configured deadlines.
    ///
    /// # Errors
    ///
    /// Returns typed [`DeadlineKind`] failures for idle reads or an expired
    /// connection, and framing/I/O errors for all other failures.
    pub fn read_frame(&mut self) -> Result<ControlFrame, TransportError> {
        let connection_is_tighter = self.prepare_read()?;
        let mut prefix = [0_u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES];
        self.stream
            .read_exact(&mut prefix)
            .map_err(|error| map_deadline_io(error, DeadlineKind::Read, connection_is_tighter))?;
        // A peer may send the prefix promptly and then hold the payload open.
        // Reapply the remaining absolute budget before allocating/reading it.
        let connection_is_tighter = self.prepare_read()?;
        let length = ValidatedFrameLength::from_network_prefix(prefix)
            .map_err(TransportError::Frame)?
            .as_usize();
        let mut payload = vec![0_u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| map_deadline_io(error, DeadlineKind::Read, connection_is_tighter))?;
        ControlFrame::new(payload).map_err(TransportError::Frame)
    }

    /// Writes one complete bounded frame under the configured deadlines.
    ///
    /// # Errors
    ///
    /// Returns typed [`DeadlineKind`] failures for blocked writes or an
    /// expired connection, and framing/I/O errors for all other failures.
    pub fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), TransportError> {
        let encoded = frame.encode();
        if frame.payload().len() > MAX_CONTROL_FRAME_BYTES {
            return Err(TransportError::Frame(FrameError::FrameTooLarge {
                length: frame.payload().len(),
            }));
        }
        let connection_is_tighter = self.prepare_write()?;
        self.stream
            .write_all(&encoded)
            .map_err(|error| map_deadline_io(error, DeadlineKind::Write, connection_is_tighter))
    }
}

fn map_deadline_io(
    error: io::Error,
    operation: DeadlineKind,
    connection_is_tighter: bool,
) -> TransportError {
    if error.kind() == io::ErrorKind::TimedOut {
        if connection_is_tighter {
            TransportError::Deadline(DeadlineKind::Connection)
        } else {
            TransportError::Deadline(operation)
        }
    } else {
        TransportError::Io(error)
    }
}

/// Common framed operations used by the server loop.
pub(crate) trait FramedIo {
    /// Reads one bounded request frame.
    fn read_frame(&mut self) -> Result<ControlFrame, TransportError>;

    /// Writes one bounded response frame.
    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), TransportError>;
}

impl<S> FramedIo for FramedTransport<S>
where
    S: Read + Write,
{
    fn read_frame(&mut self) -> Result<ControlFrame, TransportError> {
        Self::read_frame(self)
    }

    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), TransportError> {
        Self::write_frame(self, frame)
    }
}

impl<S> FramedIo for DeadlineFramedTransport<S>
where
    S: DeadlineStream,
{
    fn read_frame(&mut self) -> Result<ControlFrame, TransportError> {
        Self::read_frame(self)
    }

    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), TransportError> {
        Self::write_frame(self, frame)
    }
}

/// Why one framed transport operation failed.
#[derive(Debug)]
pub enum TransportError {
    /// The underlying stream failed or ended early.
    Io(io::Error),
    /// The frame violated the bounded egress-protocol contract.
    Frame(FrameError),
    /// The transport deadline policy was reached.
    Deadline(DeadlineKind),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "vsock stream I/O failed: {error}"),
            Self::Frame(error) => error.fmt(formatter),
            Self::Deadline(kind) => write!(formatter, "vsock {kind} deadline exceeded"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Read, Write},
        os::unix::net::UnixStream,
        sync::{Arc, Barrier, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use egress_protocol::frame::ControlFrame;

    use super::{
        DeadlineFramedTransport, DeadlineKind, DeadlineStream, FramedTransport, TransportError,
        TransportPolicy, VsockStream, classify_nonblocking_accept,
    };

    struct DeadlineFixture {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        read_times_out: bool,
        write_times_out: bool,
        applied: Arc<Mutex<Vec<(bool, Duration)>>>,
    }

    impl Read for DeadlineFixture {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.read_times_out {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            self.input.read(buffer)
        }
    }

    impl Write for DeadlineFixture {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.write_times_out {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineStream for DeadlineFixture {
        fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
            self.applied
                .lock()
                .expect("deadline fixture lock")
                .push((true, timeout));
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
            self.applied
                .lock()
                .expect("deadline fixture lock")
                .push((false, timeout));
            Ok(())
        }
    }

    // Requirement: WouldBlock is a normal empty poll, while all other accept failures propagate.
    // Category: boundary/cancellation. Risk: critical.
    #[test]
    fn nonblocking_accept_classification_preserves_poll_and_error_semantics() {
        assert_eq!(
            classify_nonblocking_accept::<u32>(Ok(7)).expect("ready accept must succeed"),
            Some(7)
        );
        assert_eq!(
            classify_nonblocking_accept::<u32>(Err(io::Error::from(io::ErrorKind::WouldBlock)))
                .expect("WouldBlock must be an empty poll"),
            None
        );

        let error = classify_nonblocking_accept::<u32>(Err(io::Error::from(
            io::ErrorKind::ConnectionAborted,
        )))
        .expect_err("non-poll errors must propagate");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    // Requirement: a separately owned cancellation handle interrupts connected blocking I/O.
    // Category: concurrency/cancellation. Risk: critical.
    #[test]
    fn shutdown_handle_interrupts_blocking_stream_io() {
        let (socket, peer) = UnixStream::pair().expect("socket pair must be available");
        let stream = VsockStream {
            socket: socket.into(),
        };
        let shutdown = stream
            .shutdown_handle()
            .expect("owner cancellation handle must clone");
        let ready = Arc::new(Barrier::new(2));
        let reader_ready = Arc::clone(&ready);

        let reader = thread::spawn(move || {
            let mut stream = stream;
            let mut byte = [0_u8; 1];
            reader_ready.wait();
            stream.read(&mut byte)
        });
        ready.wait();

        shutdown
            .shutdown()
            .expect("owner cancellation must shut down both directions");
        assert_eq!(
            reader.join().expect("reader thread must not panic").expect(
                "a blocking read interrupted by orderly local shutdown must complete successfully"
            ),
            0
        );
        drop(peer);
    }

    // Requirement: valid frames round-trip through streaming transport.
    // Category: normal/contract. Risk: high.
    #[test]
    fn framed_transport_reads_and_writes_one_bounded_frame() {
        let frame = ControlFrame::new(vec![1, 2, 3]).expect("fixture frame fits");
        let mut transport = FramedTransport::new(Cursor::new(frame.encode()));
        assert_eq!(transport.read_frame().expect("frame must decode"), frame);

        let mut output = Cursor::new(Vec::new());
        let mut writer = FramedTransport::new(&mut output);
        writer.write_frame(&frame).expect("frame must encode");
        assert_eq!(output.into_inner(), frame.encode());
    }

    // Requirement: a peer length above one MiB is rejected before payload allocation.
    // Category: boundary/security/resource exhaustion. Risk: critical.
    #[test]
    fn framed_transport_rejects_oversized_prefix_before_reading_payload() {
        let oversized = u32::try_from(egress_protocol::session::MAX_CONTROL_FRAME_BYTES + 1)
            .expect("fixture size fits in u32")
            .to_be_bytes();
        let mut transport = FramedTransport::new(Cursor::new(oversized));
        assert!(matches!(
            transport.read_frame(),
            Err(TransportError::Frame(
                egress_protocol::frame::FrameError::FrameTooLarge { .. }
            ))
        ));
    }

    // Requirement: timeout configuration rejects immediate and unbounded values.
    // Category: boundary/configuration. Risk: high.
    #[test]
    fn transport_policy_rejects_zero_and_excessive_deadlines() {
        assert!(matches!(
            TransportPolicy::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(super::TransportConfigError::Zero {
                field: "read_timeout"
            })
        ));
        assert!(matches!(
            TransportPolicy::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                super::MAX_TRANSPORT_TIMEOUT + Duration::from_nanos(1),
            ),
            Err(super::TransportConfigError::TooLarge {
                field: "connection_timeout",
                ..
            })
        ));
    }

    // Requirement: a real deadline-capable stream maps an idle read timeout to
    // a typed read failure without changing the frame wire contract.
    // Category: timeout/fail-closed. Risk: critical.
    #[test]
    fn deadline_transport_reports_typed_read_timeout() {
        let policy = TransportPolicy::new(
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .expect("test policy must be valid");
        let applied = Arc::new(Mutex::new(Vec::new()));
        let fixture = DeadlineFixture {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            read_times_out: true,
            write_times_out: false,
            applied: Arc::clone(&applied),
        };
        let mut transport = DeadlineFramedTransport::new(fixture, policy)
            .expect("test deadline options must apply");
        assert!(matches!(
            transport.read_frame(),
            Err(TransportError::Deadline(DeadlineKind::Read))
        ));
        assert_eq!(applied.lock().expect("deadline fixture lock").len(), 3);
    }

    // Requirement: a blocked write is typed and the caller cannot continue
    // using the ambiguous stream through the deadline-aware path.
    // Category: timeout/fail-closed. Risk: critical.
    #[test]
    fn deadline_transport_reports_typed_write_timeout() {
        let policy = TransportPolicy::new(
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .expect("test policy must be valid");
        let applied = Arc::new(Mutex::new(Vec::new()));
        let fixture = DeadlineFixture {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            read_times_out: false,
            write_times_out: true,
            applied: Arc::clone(&applied),
        };
        let mut transport = DeadlineFramedTransport::new(fixture, policy)
            .expect("test deadline options must apply");
        let frame = ControlFrame::new(vec![1, 2, 3]).expect("fixture frame must fit");
        assert!(matches!(
            transport.write_frame(&frame),
            Err(TransportError::Deadline(DeadlineKind::Write))
        ));
        assert_eq!(applied.lock().expect("deadline fixture lock").len(), 3);
    }

    // Requirement: an expired absolute connection budget is distinguished from
    // an idle operation timeout before touching the stream.
    // Category: timeout/fail-closed. Risk: critical.
    #[test]
    fn deadline_transport_reports_expired_connection_before_io() {
        let policy = TransportPolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("test policy must be valid");
        let applied = Arc::new(Mutex::new(Vec::new()));
        let fixture = DeadlineFixture {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
            read_times_out: false,
            write_times_out: false,
            applied: Arc::clone(&applied),
        };
        let mut transport = DeadlineFramedTransport::new(fixture, policy)
            .expect("test deadline options must apply");
        transport.connection_deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test instant subtraction must fit");
        assert!(matches!(
            transport.read_frame(),
            Err(TransportError::Deadline(DeadlineKind::Connection))
        ));
        // Constructor options were applied, but no per-operation reset ran
        // after the connection had expired.
        assert_eq!(applied.lock().expect("deadline fixture lock").len(), 2);
    }

    // Requirement: AF_VSOCK must not bind wildcard or ephemeral endpoint values.
    // Category: boundary/security. Risk: high.
    #[test]
    fn vsock_listener_rejects_wildcard_ephemeral_and_invalid_backlog_values() {
        for (cid, port, backlog) in [
            (u32::MAX, 9000, 16),
            (2, 0, 16),
            (2, u32::MAX, 16),
            (2, 9000, 0),
            (2, 9000, -1),
        ] {
            assert!(
                super::AfVsockListener::bind(cid, port, backlog).is_err(),
                "invalid AF_VSOCK endpoint ({cid}, {port}, {backlog}) must be rejected"
            );
            assert!(
                super::AfVsockListener::bind_nonblocking(cid, port, backlog).is_err(),
                "invalid nonblocking AF_VSOCK endpoint ({cid}, {port}, {backlog}) must be rejected"
            );
        }
    }
}
