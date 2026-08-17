//! Production control transport that binds a caller before any request byte is read.
//!
//! [ADR 0013](../../../docs/decisions/0013-resolve-caller-identity-from-the-connection.md)
//! requires the supervisor to select the caller from the accepted connection rather than from
//! the `claimed_subject` field a guest writes into a request. This module supplies the two
//! production pieces that requirement needs:
//!
//! - [`SubjectCredentialResolver`] resolves an accepted connection to the subject that owns the
//!   listening socket, and refuses a connection whose peer credential is not the exact credential
//!   the subject was provisioned with.
//! - [`SubjectControlListener`] owns one `SOCK_SEQPACKET` socket per subject, captures
//!   `SO_PEERCRED` at accept time, and returns an [`AcceptedControlConnection`] whose caller is
//!   already bound. Request bytes are only reachable through
//!   [`AcceptedControlConnection::receive_request`], which the caller can reach only after the
//!   binding exists, so a decode failure can never influence which subject a request runs as.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    error::Error,
    fmt, io,
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
    time::Duration,
};

use authority_core::capability::SubjectId;
use rustix::{
    fs::{AtFlags, CWD, Mode, chmodat},
    net::{
        AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType, accept, bind,
        listen, recv, send, socket_with,
        sockopt::{self, socket_peercred},
    },
};

use crate::{
    protocol::{MAX_WIRE_REQUEST_BYTES, WireDecodeError, WireRequest, WireResponse},
    supervisor::{CallerResolver, ConnectionIdentity},
};

/// Exact peer credential one subject's control connections must present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectCredential {
    uid: u32,
    gid: u32,
}

impl SubjectCredential {
    /// Records the user and group a subject's guest process runs as.
    #[must_use]
    pub const fn new(user_id: u32, group_id: u32) -> Self {
        Self {
            uid: user_id,
            gid: group_id,
        }
    }

    /// Returns the required peer user ID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the required peer group ID.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }
}

impl fmt::Display for SubjectCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "uid {} gid {}", self.uid, self.gid)
    }
}

/// Failure while registering one accepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRebindError {
    socket_id: u64,
}

impl fmt::Display for ConnectionRebindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "accepted connection {} is already bound to a subject",
            self.socket_id
        )
    }
}

impl Error for ConnectionRebindError {}

/// Failure while resolving an accepted connection to its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialResolveError {
    /// No accepted connection with this socket identity is registered.
    Unbound {
        /// Supervisor-local accepted socket identity.
        socket_id: u64,
    },
    /// The peer credential is not the credential the subject was provisioned with.
    ForeignCredential {
        /// Supervisor-local accepted socket identity.
        socket_id: u64,
        /// Credential recorded for the subject that owns the listening socket.
        expected: SubjectCredential,
        /// Credential the kernel reported for this connection.
        actual: SubjectCredential,
    },
}

impl fmt::Display for CredentialResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unbound { socket_id } => write!(
                formatter,
                "accepted connection {socket_id} has no subject binding"
            ),
            Self::ForeignCredential {
                socket_id,
                expected,
                actual,
            } => write!(
                formatter,
                "accepted connection {socket_id} presented {actual} but its subject requires {expected}"
            ),
        }
    }
}

impl Error for CredentialResolveError {}

/// Default receive deadline applied to every accepted production control socket.
pub const DEFAULT_CONTROL_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default send deadline applied to every accepted production control socket.
pub const DEFAULT_CONTROL_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum listen backlog accepted by the control listener.
pub const MAX_CONTROL_SOCKET_BACKLOG: i32 = 128;
/// Maximum receive or send timeout accepted by the control listener policy.
pub const MAX_CONTROL_SOCKET_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum number of simultaneously authenticated control connections.
pub const MAX_CONTROL_CONNECTION_BINDINGS: usize = 4_096;

/// Which accepted-socket operation a timeout policy configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlSocketTimeoutKind {
    /// The peer-to-supervisor receive operation.
    Receive,
    /// The supervisor-to-peer send operation.
    Send,
}

/// Receive and send deadlines applied to every accepted control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlSocketTimeouts {
    receive: Duration,
    send: Duration,
}

impl ControlSocketTimeouts {
    /// Creates a timeout policy. Values are validated when a listener is bound.
    #[must_use]
    pub const fn new(receive: Duration, send: Duration) -> Self {
        Self { receive, send }
    }

    /// Creates and validates a timeout policy before a listener is bound.
    pub fn try_new(receive: Duration, send: Duration) -> Result<Self, ControlSocketError> {
        let timeouts = Self::new(receive, send);
        timeouts.validate().map(|()| timeouts)
    }

    /// Returns the bounded peer-to-supervisor receive deadline.
    #[must_use]
    pub const fn receive(self) -> Duration {
        self.receive
    }

    /// Returns the bounded supervisor-to-peer send deadline.
    #[must_use]
    pub const fn send(self) -> Duration {
        self.send
    }

    fn validate(self) -> Result<(), ControlSocketError> {
        validate_timeout(self.receive, ControlSocketTimeoutKind::Receive)?;
        validate_timeout(self.send, ControlSocketTimeoutKind::Send)
    }
}

impl Default for ControlSocketTimeouts {
    fn default() -> Self {
        Self::new(
            DEFAULT_CONTROL_RECEIVE_TIMEOUT,
            DEFAULT_CONTROL_SEND_TIMEOUT,
        )
    }
}

/// Production resolver that binds each accepted connection to exactly one subject.
///
/// A binding is created by the listener that accepted the connection, so the subject is a
/// property of which socket the peer connected to, never of anything the peer sent.
#[derive(Debug, Clone)]
pub struct SubjectCredentialResolver {
    bindings: BTreeMap<u64, (SubjectId, SubjectCredential)>,
    next_socket_id: u64,
}

impl Default for SubjectCredentialResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SubjectCredentialResolver {
    /// Creates an empty binding table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            next_socket_id: 0,
        }
    }

    fn allocate(
        &mut self,
        subject: SubjectId,
        credential: SubjectCredential,
    ) -> Result<u64, ControlSocketError> {
        if self.bindings.len() >= MAX_CONTROL_CONNECTION_BINDINGS {
            return Err(ControlSocketError::BindingCapacityExceeded);
        }
        let socket_id = self.next_socket_id;
        self.next_socket_id = self
            .next_socket_id
            .checked_add(1)
            .ok_or(ControlSocketError::SocketIdExhausted)?;
        self.bind(socket_id, subject, credential)
            .map_err(ControlSocketError::Rebind)?;
        Ok(socket_id)
    }

    /// Binds one accepted connection to the subject that owns its listening socket.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRebindError`] when the socket identity is already bound. Accepted
    /// socket identities are never reused, so a repeat is a defect rather than a race.
    pub fn bind(
        &mut self,
        socket_id: u64,
        subject: SubjectId,
        credential: SubjectCredential,
    ) -> Result<(), ConnectionRebindError> {
        match self.bindings.entry(socket_id) {
            Entry::Occupied(_) => Err(ConnectionRebindError { socket_id }),
            Entry::Vacant(entry) => {
                entry.insert((subject, credential));
                Ok(())
            }
        }
    }

    /// Removes one closed connection and returns the subject it was bound to.
    pub fn release(&mut self, socket_id: u64) -> Option<SubjectId> {
        self.bindings.remove(&socket_id).map(|(subject, _)| subject)
    }

    /// Returns the number of live connection bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Reports whether no connection is currently bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

impl CallerResolver for SubjectCredentialResolver {
    type Error = CredentialResolveError;

    fn resolve(&self, identity: &ConnectionIdentity) -> Result<SubjectId, Self::Error> {
        let socket_id = identity.socket_id();
        let Some((subject, expected)) = self.bindings.get(&socket_id) else {
            return Err(CredentialResolveError::Unbound { socket_id });
        };
        let actual = SubjectCredential::new(identity.peer_uid(), identity.peer_gid());
        if actual != *expected {
            return Err(CredentialResolveError::ForeignCredential {
                socket_id,
                expected: *expected,
                actual,
            });
        }
        Ok(subject.clone())
    }
}

/// Failure on the production control socket.
#[derive(Debug)]
pub enum ControlSocketError {
    /// A socket, bind, listen, accept, credential, or receive operation failed.
    Io(io::Error),
    /// The listening path is not an absolute path the supervisor may own.
    InvalidPath(PathBuf),
    /// The listen backlog is outside the positive hard cap.
    InvalidBacklog {
        /// Caller-supplied backlog.
        requested: i32,
    },
    /// A receive or send timeout is zero or exceeds the hard cap.
    InvalidTimeout {
        /// Operation whose timeout is invalid.
        kind: ControlSocketTimeoutKind,
        /// Caller-supplied timeout.
        requested: Duration,
    },
    /// Accepted socket identities are exhausted for this listener.
    SocketIdExhausted,
    /// The process-wide authenticated connection table reached its hard cap.
    BindingCapacityExceeded,
    /// The accepted connection is already bound, which cannot happen for a fresh identity.
    Rebind(ConnectionRebindError),
    /// One datagram exceeded the bounded wire request size.
    RequestTooLarge {
        /// Bytes the peer sent in a single datagram.
        received: usize,
    },
    /// The peer closed the connection instead of sending a request.
    PeerClosed,
    /// The bounded receive deadline expired without a datagram.
    ReceiveTimeout,
    /// The bounded send deadline expired before the reply was accepted.
    SendTimeout,
    /// The bounded request could not be decoded.
    Decode(WireDecodeError),
    /// The bounded reply could not be encoded.
    Encode(String),
}

impl fmt::Display for ControlSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "control socket operation failed: {error}"),
            Self::InvalidPath(path) => write!(
                formatter,
                "control socket path must be absolute and lexical: {}",
                path.display()
            ),
            Self::InvalidBacklog { requested } => write!(
                formatter,
                "control socket backlog {requested} must be between 1 and {MAX_CONTROL_SOCKET_BACKLOG}"
            ),
            Self::InvalidTimeout { kind, requested } => write!(
                formatter,
                "control socket {kind:?} timeout {requested:?} must be non-zero and at most {MAX_CONTROL_SOCKET_TIMEOUT:?}"
            ),
            Self::SocketIdExhausted => {
                formatter.write_str("control resolver exhausted its accepted socket identities")
            }
            Self::BindingCapacityExceeded => write!(
                formatter,
                "control resolver reached its {MAX_CONTROL_CONNECTION_BINDINGS}-connection cap"
            ),
            Self::Rebind(error) => error.fmt(formatter),
            Self::RequestTooLarge { received } => write!(
                formatter,
                "control request of {received} bytes exceeds the {MAX_WIRE_REQUEST_BYTES} byte bound"
            ),
            Self::PeerClosed => {
                formatter.write_str("control peer closed the connection before sending a request")
            }
            Self::ReceiveTimeout => formatter
                .write_str("control peer did not send a request before the receive deadline"),
            Self::SendTimeout => formatter
                .write_str("control peer did not accept the reply before the send deadline"),
            Self::Decode(error) => error.fmt(formatter),
            Self::Encode(message) => {
                write!(formatter, "control reply could not be encoded: {message}")
            }
        }
    }
}

impl Error for ControlSocketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Rebind(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::InvalidPath(_)
            | Self::InvalidBacklog { .. }
            | Self::InvalidTimeout { .. }
            | Self::SocketIdExhausted
            | Self::BindingCapacityExceeded
            | Self::RequestTooLarge { .. }
            | Self::PeerClosed
            | Self::ReceiveTimeout
            | Self::SendTimeout
            | Self::Encode(_) => None,
        }
    }
}

impl From<rustix::io::Errno> for ControlSocketError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from(error))
    }
}

fn validate_backlog(backlog: i32) -> Result<(), ControlSocketError> {
    if (1..=MAX_CONTROL_SOCKET_BACKLOG).contains(&backlog) {
        Ok(())
    } else {
        Err(ControlSocketError::InvalidBacklog { requested: backlog })
    }
}

fn validate_timeout(
    timeout: Duration,
    kind: ControlSocketTimeoutKind,
) -> Result<(), ControlSocketError> {
    if !timeout.is_zero() && timeout <= MAX_CONTROL_SOCKET_TIMEOUT {
        Ok(())
    } else {
        Err(ControlSocketError::InvalidTimeout {
            kind,
            requested: timeout,
        })
    }
}

fn apply_socket_timeouts(
    socket: &OwnedFd,
    timeouts: ControlSocketTimeouts,
) -> Result<(), ControlSocketError> {
    sockopt::set_socket_timeout(socket, sockopt::Timeout::Recv, Some(timeouts.receive()))?;
    sockopt::set_socket_timeout(socket, sockopt::Timeout::Send, Some(timeouts.send()))?;
    Ok(())
}

fn is_timeout_errno(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK
}

fn receive_error(error: rustix::io::Errno) -> ControlSocketError {
    if is_timeout_errno(error) {
        ControlSocketError::ReceiveTimeout
    } else {
        ControlSocketError::Io(io::Error::from(error))
    }
}

fn send_error(error: rustix::io::Errno) -> ControlSocketError {
    if is_timeout_errno(error) {
        ControlSocketError::SendTimeout
    } else {
        ControlSocketError::Io(io::Error::from(error))
    }
}

/// One `SOCK_SEQPACKET` control socket owned by exactly one subject.
///
/// Every connection accepted here belongs to `subject` by construction, which is what makes
/// "1 connection = 1 subject" a property of the transport instead of a check somebody can forget.
#[derive(Debug)]
pub struct SubjectControlListener {
    socket: OwnedFd,
    path: PathBuf,
    subject: SubjectId,
    credential: SubjectCredential,
    timeouts: ControlSocketTimeouts,
}

impl SubjectControlListener {
    /// Binds an owner-only control socket for one subject and starts listening.
    ///
    /// The socket is created with `SOCK_SEQPACKET` so that one request is exactly one datagram
    /// and a peer cannot merge or split requests across a byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`ControlSocketError`] when the path is not absolute and lexical, or when the
    /// socket cannot be created, bound, restricted to owner-only access, or listened on.
    pub fn bind(
        path: impl Into<PathBuf>,
        subject: SubjectId,
        credential: SubjectCredential,
        backlog: i32,
    ) -> Result<Self, ControlSocketError> {
        Self::bind_with_timeouts(
            path,
            subject,
            credential,
            backlog,
            ControlSocketTimeouts::default(),
        )
    }

    /// Binds an owner-only control socket with explicit accepted-peer deadlines.
    ///
    /// This constructor is useful for deterministic tests and for deployments that need a
    /// shorter or longer bounded peer budget. Production callers should normally use [`Self::bind`]
    /// so the documented defaults remain visible at the call site.
    pub fn bind_with_timeouts(
        path: impl Into<PathBuf>,
        subject: SubjectId,
        credential: SubjectCredential,
        backlog: i32,
        timeouts: ControlSocketTimeouts,
    ) -> Result<Self, ControlSocketError> {
        let path = path.into();
        if !path.is_absolute() || path.components().count() < 2 {
            return Err(ControlSocketError::InvalidPath(path));
        }
        validate_backlog(backlog)?;
        timeouts.validate()?;
        let address = SocketAddrUnix::new(&path)
            .map_err(|_| ControlSocketError::InvalidPath(path.clone()))?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        bind(&socket, &address)?;
        // The node exists only after bind, so its mode is narrowed before anything can connect.
        chmodat(CWD, &path, Mode::RUSR | Mode::WUSR, AtFlags::empty())?;
        listen(&socket, backlog)?;
        Ok(Self {
            socket,
            path,
            subject,
            credential,
            timeouts,
        })
    }

    /// Returns the filesystem path this listener owns.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the only subject connections on this socket may act as.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Accepts one connection and binds its caller before any request byte is readable.
    ///
    /// The peer credential is read from the kernel with `SO_PEERCRED`, so the returned
    /// [`ConnectionIdentity`] never contains a value the peer chose.
    ///
    /// # Errors
    ///
    /// Returns [`ControlSocketError`] when accept or the credential query fails, when this
    /// listener has exhausted its accepted socket identities, or when the fresh identity is
    /// somehow already bound.
    pub fn accept(
        &mut self,
        resolver: &mut SubjectCredentialResolver,
    ) -> Result<AcceptedControlConnection, ControlSocketError> {
        let socket = accept(&self.socket)?;
        let peer = socket_peercred(&socket)?;
        apply_socket_timeouts(&socket, self.timeouts)?;
        let socket_id = resolver.allocate(self.subject.clone(), self.credential)?;
        let identity = ConnectionIdentity::new(
            socket_id,
            peer.pid.as_raw_nonzero().get().unsigned_abs(),
            peer.uid.as_raw(),
            peer.gid.as_raw(),
        );
        Ok(AcceptedControlConnection { identity, socket })
    }
}

/// An accepted connection whose caller is bound before its bytes are readable.
#[derive(Debug)]
pub struct AcceptedControlConnection {
    identity: ConnectionIdentity,
    socket: OwnedFd,
}

impl AcceptedControlConnection {
    /// Returns the authenticated identity to pass to the supervisor.
    #[must_use]
    pub const fn identity(&self) -> ConnectionIdentity {
        self.identity
    }

    /// Receives exactly one bounded request datagram and decodes it.
    ///
    /// A datagram larger than [`MAX_WIRE_REQUEST_BYTES`] is rejected without being decoded, so an
    /// oversized request costs one bounded read rather than an allocation the peer sizes.
    ///
    /// # Errors
    ///
    /// Returns [`ControlSocketError`] when the receive fails, the peer closed the connection, the
    /// datagram exceeds the bounded request size, or the bytes are not a canonical request.
    pub fn receive_request(&self) -> Result<WireRequest, ControlSocketError> {
        // One byte past the bound distinguishes "exactly at the bound" from "truncated".
        let mut buffer = [0_u8; MAX_WIRE_REQUEST_BYTES + 1];
        let received = recv(self.socket.as_fd(), &mut buffer[..], RecvFlags::empty())
            .map_err(receive_error)?
            .0;
        if received == 0 {
            return Err(ControlSocketError::PeerClosed);
        }
        if received > MAX_WIRE_REQUEST_BYTES {
            return Err(ControlSocketError::RequestTooLarge { received });
        }
        WireRequest::decode(&buffer[..received]).map_err(ControlSocketError::Decode)
    }

    /// Sends one bounded reply as a single datagram.
    ///
    /// A guest that never receives a reply cannot tell a refused request from a lost one, so it
    /// retries, and a retried close is exactly the shape that produces stale-handle errors. The
    /// reply carries no identifier, so answering costs nothing in disclosure.
    ///
    /// # Errors
    ///
    /// Returns [`ControlSocketError`] when the reply cannot be encoded or the peer is gone.
    pub fn send_response(&self, response: WireResponse) -> Result<(), ControlSocketError> {
        let encoded = response
            .encode()
            .map_err(|error| ControlSocketError::Encode(error.to_string()))?;
        let sent = send(self.socket.as_fd(), &encoded, SendFlags::empty()).map_err(send_error)?;
        if sent != encoded.len() {
            return Err(ControlSocketError::Io(io::Error::other(
                "control reply was partially sent",
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority_core::handle::HandleId;
    use rustix::net::connect;
    use std::{
        os::fd::OwnedFd,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    fn socket_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "supervisor-control-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        drop(std::fs::remove_file(&path));
        path
    }

    fn self_credential() -> SubjectCredential {
        SubjectCredential::new(
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn connect_and_send(path: &Path, payload: &[u8]) {
        let client = connect_client(path);
        rustix::net::send(&client, payload, rustix::net::SendFlags::empty())
            .expect("test client must send one datagram");
    }

    fn connect_client(path: &Path) -> OwnedFd {
        let address = SocketAddrUnix::new(path).expect("test address must encode");
        let client = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("test client socket must be creatable");
        connect(&client, &address).expect("test client must connect");
        client
    }

    #[test]
    fn accept_binds_the_listening_subject_from_the_kernel_credential() {
        let path = socket_path("accept");
        let subject = SubjectId::new("subject-a");
        let mut listener =
            SubjectControlListener::bind(&path, subject.clone(), self_credential(), 4)
                .expect("listener must bind");
        let mut resolver = SubjectCredentialResolver::new();
        let request = WireRequest::CloseSubject {
            claimed_subject: SubjectId::new("subject-b"),
        };
        let encoded = request.encode().expect("request must encode");
        let client_path = path.clone();
        let client = thread::spawn(move || connect_and_send(&client_path, &encoded));

        let connection = listener.accept(&mut resolver).expect("accept must succeed");
        let identity = connection.identity();
        assert_eq!(identity.socket_id(), 0);
        assert_eq!(identity.peer_uid(), self_credential().uid());
        assert_eq!(identity.peer_gid(), self_credential().gid());
        assert_eq!(
            resolver.resolve(&identity).expect("caller must resolve"),
            subject,
            "the caller is the listening socket's subject, not the request's claim"
        );
        assert_eq!(
            connection
                .receive_request()
                .expect("bounded request must decode"),
            request
        );
        client.join().expect("test client must finish");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn oversized_datagram_is_rejected_without_decoding() {
        let path = socket_path("oversized");
        let mut listener =
            SubjectControlListener::bind(&path, SubjectId::new("subject-a"), self_credential(), 4)
                .expect("listener must bind");
        let mut resolver = SubjectCredentialResolver::new();
        let client_path = path.clone();
        let client =
            thread::spawn(move || connect_and_send(&client_path, &[7; MAX_WIRE_REQUEST_BYTES + 1]));

        let connection = listener.accept(&mut resolver).expect("accept must succeed");
        assert!(matches!(
            connection.receive_request(),
            Err(ControlSocketError::RequestTooLarge {
                received: len
            }) if len == MAX_WIRE_REQUEST_BYTES + 1
        ));
        client.join().expect("test client must finish");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn accepted_socket_identities_are_not_reused_across_connections() {
        let path = socket_path("sequence");
        let mut listener =
            SubjectControlListener::bind(&path, SubjectId::new("subject-a"), self_credential(), 4)
                .expect("listener must bind");
        let mut resolver = SubjectCredentialResolver::new();
        let encoded = WireRequest::CloseHandle {
            claimed_subject: SubjectId::new("subject-a"),
            handle: HandleId::new("handle-1"),
        }
        .encode()
        .expect("request must encode");

        let mut observed = Vec::new();
        for _ in 0_u8..3 {
            let client_path = path.clone();
            let payload = encoded.clone();
            let client = thread::spawn(move || connect_and_send(&client_path, &payload));
            let connection = listener.accept(&mut resolver).expect("accept must succeed");
            observed.push(connection.identity().socket_id());
            client.join().expect("test client must finish");
        }

        assert_eq!(observed, vec![0, 1, 2]);
        assert_eq!(resolver.len(), 3);
        assert_eq!(
            resolver.release(1).as_ref().map(SubjectId::as_str),
            Some("subject-a")
        );
        assert!(matches!(
            resolver.resolve(&ConnectionIdentity::new(
                1,
                1,
                self_credential().uid(),
                self_credential().gid()
            )),
            Err(CredentialResolveError::Unbound { socket_id: 1 })
        ));
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn resolution_fails_closed_for_unbound_and_foreign_credentials() {
        let mut resolver = SubjectCredentialResolver::new();
        let subject = SubjectId::new("subject-a");
        resolver
            .bind(9, subject.clone(), SubjectCredential::new(1000, 1000))
            .expect("first binding must succeed");

        assert!(matches!(
            resolver.bind(9, subject, SubjectCredential::new(1000, 1000)),
            Err(ConnectionRebindError { socket_id: 9 })
        ));
        assert!(matches!(
            resolver.resolve(&ConnectionIdentity::new(10, 4, 1000, 1000)),
            Err(CredentialResolveError::Unbound { socket_id: 10 })
        ));
        assert!(matches!(
            resolver.resolve(&ConnectionIdentity::new(9, 4, 1001, 1000)),
            Err(CredentialResolveError::ForeignCredential { socket_id: 9, .. })
        ));
        assert!(matches!(
            resolver.resolve(&ConnectionIdentity::new(9, 4, 1000, 1001)),
            Err(CredentialResolveError::ForeignCredential { socket_id: 9, .. })
        ));
        assert_eq!(
            resolver
                .resolve(&ConnectionIdentity::new(9, 4, 1000, 1000))
                .expect("exact credential must resolve")
                .as_str(),
            "subject-a"
        );
    }

    #[test]
    fn resolver_rebind_failure_drops_accepted_socket_and_listener_remains_usable() {
        let path = socket_path("rebind-cleanup");
        let mut listener =
            SubjectControlListener::bind(&path, SubjectId::new("subject-a"), self_credential(), 4)
                .expect("listener must bind");
        let mut resolver = SubjectCredentialResolver::new();
        resolver
            .bind(0, SubjectId::new("subject-a"), self_credential())
            .expect("fixture binding must occupy the first identity");

        let first_client = connect_client(&path);
        assert!(matches!(
            listener.accept(&mut resolver),
            Err(ControlSocketError::Rebind(ConnectionRebindError {
                socket_id: 0
            }))
        ));
        drop(first_client);
        assert_eq!(
            resolver.release(0).as_ref().map(SubjectId::as_str),
            Some("subject-a")
        );

        let encoded = WireRequest::CloseSubject {
            claimed_subject: SubjectId::new("subject-a"),
        }
        .encode()
        .expect("request must encode");
        let client_path = path.clone();
        let client = thread::spawn(move || connect_and_send(&client_path, &encoded));
        let connection = listener
            .accept(&mut resolver)
            .expect("listener must remain usable after resolver rejection");
        assert_eq!(connection.identity().socket_id(), 1);
        client.join().expect("test client must finish");
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn listener_rejects_paths_it_cannot_own() {
        for path in ["relative/control.sock", "/"] {
            assert!(matches!(
                SubjectControlListener::bind(
                    PathBuf::from(path),
                    SubjectId::new("subject-a"),
                    self_credential(),
                    4,
                ),
                Err(ControlSocketError::InvalidPath(_))
            ));
        }
    }

    #[test]
    fn listener_rejects_zero_negative_and_excessive_backlogs() {
        let path = socket_path("backlog");
        for backlog in [0, -1, MAX_CONTROL_SOCKET_BACKLOG + 1] {
            assert!(matches!(
                SubjectControlListener::bind(
                    &path,
                    SubjectId::new("subject-a"),
                    self_credential(),
                    backlog,
                ),
                Err(ControlSocketError::InvalidBacklog { requested })
                    if requested == backlog
            ));
            assert!(!path.exists(), "invalid backlog must not create a socket");
        }
    }

    #[test]
    fn listener_rejects_zero_and_excessive_timeouts_before_socket_creation() {
        let path = socket_path("timeout-config");
        for timeouts in [
            ControlSocketTimeouts::new(Duration::ZERO, Duration::from_secs(1)),
            ControlSocketTimeouts::new(
                Duration::from_secs(1),
                MAX_CONTROL_SOCKET_TIMEOUT + Duration::from_nanos(1),
            ),
        ] {
            assert!(matches!(
                SubjectControlListener::bind_with_timeouts(
                    &path,
                    SubjectId::new("subject-a"),
                    self_credential(),
                    4,
                    timeouts,
                ),
                Err(ControlSocketError::InvalidTimeout { .. })
            ));
            assert!(!path.exists(), "invalid timeout must not create a socket");
        }
    }

    #[test]
    fn idle_peer_receive_timeout_is_typed_and_bounded() {
        let path = socket_path("receive-timeout");
        let mut listener = SubjectControlListener::bind_with_timeouts(
            &path,
            SubjectId::new("subject-a"),
            self_credential(),
            4,
            ControlSocketTimeouts::new(Duration::from_millis(1), Duration::from_secs(1)),
        )
        .expect("listener must bind");
        let client = connect_client(&path);
        let mut resolver = SubjectCredentialResolver::new();
        let connection = listener.accept(&mut resolver).expect("accept must succeed");
        assert!(matches!(
            connection.receive_request(),
            Err(ControlSocketError::ReceiveTimeout)
        ));
        drop(client);
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn blocked_peer_send_timeout_is_typed_and_bounded() {
        let path = socket_path("send-timeout");
        let mut listener = SubjectControlListener::bind_with_timeouts(
            &path,
            SubjectId::new("subject-a"),
            self_credential(),
            4,
            ControlSocketTimeouts::new(Duration::from_secs(1), Duration::from_millis(1)),
        )
        .expect("listener must bind");
        let client = connect_client(&path);
        let mut resolver = SubjectCredentialResolver::new();
        let connection = listener.accept(&mut resolver).expect("accept must succeed");

        let filler = [0_u8; 4096];
        let mut socket_send_timed_out = false;
        for _ in 0..4096 {
            match send(connection.socket.as_fd(), &filler, SendFlags::empty()) {
                Ok(_) => {}
                Err(error) if is_timeout_errno(error) => {
                    socket_send_timed_out = true;
                    break;
                }
                Err(error) => panic!("filler send failed unexpectedly: {error}"),
            }
        }
        assert!(socket_send_timed_out, "fixture peer must stop reading");
        assert!(matches!(
            connection.send_response(WireResponse::Refused(
                crate::protocol::RefusalCode::NotPermitted
            )),
            Err(ControlSocketError::SendTimeout)
        ));
        drop(client);
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn bound_socket_is_owner_only() {
        let path = socket_path("mode");
        let listener =
            SubjectControlListener::bind(&path, SubjectId::new("subject-a"), self_credential(), 4)
                .expect("listener must bind");
        let mode = std::os::unix::fs::MetadataExt::mode(
            &std::fs::symlink_metadata(listener.path()).expect("socket node must exist"),
        );
        assert_eq!(mode & 0o777, 0o600);
        drop(std::fs::remove_file(&path));
    }
    #[test]
    fn a_reply_reaches_the_peer_as_one_bounded_datagram() {
        let path = socket_path("reply");
        let mut listener =
            SubjectControlListener::bind(&path, SubjectId::new("subject-a"), self_credential(), 4)
                .expect("listener must bind");
        let mut resolver = SubjectCredentialResolver::new();
        let encoded = WireRequest::CloseSubject {
            claimed_subject: SubjectId::new("subject-a"),
        }
        .encode()
        .expect("request must encode");

        let client_path = path.clone();
        let client = thread::spawn(move || {
            let address = SocketAddrUnix::new(&client_path).expect("test address must encode");
            let client = socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .expect("test client socket must be creatable");
            rustix::net::connect(&client, &address).expect("test client must connect");
            send(&client, &encoded, SendFlags::empty()).expect("test client must send");
            let mut buffer = [0_u8; crate::protocol::MAX_WIRE_RESPONSE_BYTES];
            let received = recv(&client, &mut buffer[..], RecvFlags::empty())
                .expect("test client must receive one reply")
                .0;
            WireResponse::decode(&buffer[..received]).expect("reply must decode")
        });

        let connection = listener.accept(&mut resolver).expect("accept must succeed");
        connection
            .receive_request()
            .expect("bounded request must decode");
        connection
            .send_response(WireResponse::Refused(
                crate::protocol::RefusalCode::NotPermitted,
            ))
            .expect("reply must send");

        assert_eq!(
            client.join().expect("test client must finish"),
            WireResponse::Refused(crate::protocol::RefusalCode::NotPermitted)
        );
        drop(std::fs::remove_file(&path));
    }
}
