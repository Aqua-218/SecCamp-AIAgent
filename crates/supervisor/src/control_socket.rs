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
};

use authority_core::capability::SubjectId;
use rustix::{
    fs::{AtFlags, CWD, Mode, chmodat},
    net::{
        AddressFamily, RecvFlags, SocketAddrUnix, SocketFlags, SocketType, accept, bind, listen,
        recv, socket_with, sockopt::socket_peercred,
    },
};

use crate::{
    protocol::{MAX_WIRE_REQUEST_BYTES, WireDecodeError, WireRequest},
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

/// Production resolver that binds each accepted connection to exactly one subject.
///
/// A binding is created by the listener that accepted the connection, so the subject is a
/// property of which socket the peer connected to, never of anything the peer sent.
#[derive(Debug, Default, Clone)]
pub struct SubjectCredentialResolver {
    bindings: BTreeMap<u64, (SubjectId, SubjectCredential)>,
}

impl SubjectCredentialResolver {
    /// Creates an empty binding table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
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
    /// Accepted socket identities are exhausted for this listener.
    SocketIdExhausted,
    /// The accepted connection is already bound, which cannot happen for a fresh identity.
    Rebind(ConnectionRebindError),
    /// One datagram exceeded the bounded wire request size.
    RequestTooLarge {
        /// Bytes the peer sent in a single datagram.
        received: usize,
    },
    /// The peer closed the connection instead of sending a request.
    PeerClosed,
    /// The bounded request could not be decoded.
    Decode(WireDecodeError),
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
            Self::SocketIdExhausted => {
                formatter.write_str("control listener exhausted its accepted socket identities")
            }
            Self::Rebind(error) => error.fmt(formatter),
            Self::RequestTooLarge { received } => write!(
                formatter,
                "control request of {received} bytes exceeds the {MAX_WIRE_REQUEST_BYTES} byte bound"
            ),
            Self::PeerClosed => {
                formatter.write_str("control peer closed the connection before sending a request")
            }
            Self::Decode(error) => error.fmt(formatter),
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
            | Self::SocketIdExhausted
            | Self::RequestTooLarge { .. }
            | Self::PeerClosed => None,
        }
    }
}

impl From<rustix::io::Errno> for ControlSocketError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from(error))
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
    next_socket_id: u64,
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
        let path = path.into();
        if !path.is_absolute() || path.components().count() < 2 {
            return Err(ControlSocketError::InvalidPath(path));
        }
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
            next_socket_id: 0,
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
        let socket_id = self.next_socket_id;
        self.next_socket_id = self
            .next_socket_id
            .checked_add(1)
            .ok_or(ControlSocketError::SocketIdExhausted)?;
        let identity = ConnectionIdentity::new(
            socket_id,
            peer.pid.as_raw_nonzero().get().unsigned_abs(),
            peer.uid.as_raw(),
            peer.gid.as_raw(),
        );
        resolver
            .bind(socket_id, self.subject.clone(), self.credential)
            .map_err(ControlSocketError::Rebind)?;
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
        let received = recv(self.socket.as_fd(), &mut buffer[..], RecvFlags::empty())?.0;
        if received == 0 {
            return Err(ControlSocketError::PeerClosed);
        }
        if received > MAX_WIRE_REQUEST_BYTES {
            return Err(ControlSocketError::RequestTooLarge { received });
        }
        WireRequest::decode(&buffer[..received]).map_err(ControlSocketError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority_core::handle::HandleId;
    use rustix::net::connect;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        thread,
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
        let address = SocketAddrUnix::new(path).expect("test address must encode");
        let client = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("test client socket must be creatable");
        connect(&client, &address).expect("test client must connect");
        rustix::net::send(&client, payload, rustix::net::SendFlags::empty())
            .expect("test client must send one datagram");
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
}
