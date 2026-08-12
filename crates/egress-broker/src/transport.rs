//! `AF_VSOCK` listener abstraction and allocation-safe frame I/O.
//!
//! The listener is intentionally separate from dispatch policy. A stream
//! reader validates the four-byte length prefix before allocating payload
//! memory, and callers then pass the complete `ControlFrame` to
//! `BrokerDispatcher` for canonical CBOR, replay, budget, and authorization.

use std::{
    io::{self, Read, Write},
    net::Shutdown,
};

use egress_protocol::{
    frame::{CONTROL_FRAME_LENGTH_PREFIX_BYTES, ControlFrame, FrameError, ValidatedFrameLength},
    session::MAX_CONTROL_FRAME_BYTES,
};

const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_PORT_ANY: u32 = u32::MAX;

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

/// A Linux `AF_VSOCK` stream listener.
#[derive(Debug)]
pub struct AfVsockListener {
    socket: socket2::Socket,
    cid: u32,
    port: u32,
    nonblocking: bool,
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
        Self::bind_with_mode(cid, port, backlog, false)
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
        Self::bind_with_mode(cid, port, backlog, true)
    }

    fn bind_with_mode(cid: u32, port: u32, backlog: i32, nonblocking: bool) -> io::Result<Self> {
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
        Ok((peer_cid, VsockStream { socket }))
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

/// Why one framed transport operation failed.
#[derive(Debug)]
pub enum TransportError {
    /// The underlying stream failed or ended early.
    Io(io::Error),
    /// The frame violated the bounded egress-protocol contract.
    Frame(FrameError),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "vsock stream I/O failed: {error}"),
            Self::Frame(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Read},
        os::unix::net::UnixStream,
        sync::{Arc, Barrier},
        thread,
    };

    use egress_protocol::frame::ControlFrame;

    use super::{FramedTransport, TransportError, VsockStream, classify_nonblocking_accept};

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
