//! `AF_VSOCK` listener abstraction and allocation-safe frame I/O.
//!
//! The listener is intentionally separate from dispatch policy. A stream
//! reader validates the four-byte length prefix before allocating payload
//! memory, and callers then pass the complete `ControlFrame` to
//! `BrokerDispatcher` for canonical CBOR, replay, budget, and authorization.

use std::io::{self, Read, Write};

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

/// A safe wrapper around one accepted `AF_VSOCK` stream.
#[derive(Debug)]
pub struct VsockStream {
    socket: socket2::Socket,
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
        Ok(Self { socket, cid, port })
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
}

impl VsockListener for AfVsockListener {
    type Stream = VsockStream;

    fn accept(&self) -> io::Result<Self::Stream> {
        let (socket, _peer) = self.socket.accept()?;
        Ok(VsockStream { socket })
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
    use std::io::Cursor;

    use egress_protocol::frame::ControlFrame;

    use super::{FramedTransport, TransportError};

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
        }
    }
}
