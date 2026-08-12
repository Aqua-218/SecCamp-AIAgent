//! Host-side Broker backend for one session-scoped `AF_VSOCK` listener.
//!
//! The backend owns the listener from Broker establishment until the matching
//! close. It deliberately keeps the listener and lease together so a server
//! owner cannot obtain a listener for a different session or Broker identity.

use std::io;

use egress_broker::transport::AfVsockListener;

use crate::{
    BackendError, BrokerBackend as OrchestratorBrokerBackend, BrokerLease, SessionIdentity,
};

const MIN_HOST_CID: u32 = 2;
const MIN_GUEST_CID: u32 = 3;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_PORT_ANY: u32 = u32::MAX;

/// Creates one host-bound listener for a Broker session.
pub trait VsockListenerFactory {
    /// Listener type returned after a successful bind.
    type Listener: Send + Sync + 'static;

    /// Binds a listener to the exact host CID, port, and backlog supplied by
    /// the backend.
    ///
    /// # Errors
    ///
    /// Returns the underlying bind error when the listener cannot be created.
    fn bind(&self, host_cid: u32, port: u32, backlog: i32) -> io::Result<Self::Listener>;
}

/// Production listener factory backed by the egress broker's Linux transport.
#[derive(Debug, Clone, Copy, Default)]
pub struct AfVsockListenerFactory;

impl VsockListenerFactory for AfVsockListenerFactory {
    type Listener = AfVsockListener;

    fn bind(&self, host_cid: u32, port: u32, backlog: i32) -> io::Result<Self::Listener> {
        AfVsockListener::bind(host_cid, port, backlog)
    }
}

/// A Broker backend using the production `AF_VSOCK` listener factory.
pub type ProductionBrokerBackend = BrokerBackend<AfVsockListenerFactory>;

struct ActiveBroker<L> {
    lease: BrokerLease,
    listener: L,
}

/// Establishes one host `AF_VSOCK` listener for an exact Broker lease.
pub struct BrokerBackend<F: VsockListenerFactory = AfVsockListenerFactory> {
    factory: F,
    host_cid: u32,
    expected_guest_cid: u32,
    port: u32,
    backlog: i32,
    active: Option<ActiveBroker<F::Listener>>,
    last_closed: Option<BrokerLease>,
}

impl<F: VsockListenerFactory> BrokerBackend<F> {
    /// Creates a backend with explicit host and guest transport identities.
    ///
    /// The host CID is constrained to explicit host values beginning at 2 so
    /// the commonly used host CID 2 remains valid. Guest CIDs begin at 3;
    /// wildcard CID and port values are rejected before a factory is called.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a CID, port, or backlog violates the
    /// transport boundary.
    pub fn new(
        factory: F,
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
    ) -> Result<Self, BackendError> {
        validate_host_cid(host_cid)?;
        validate_guest_cid(expected_guest_cid)?;
        validate_port(port)?;
        validate_backlog(backlog)?;

        Ok(Self {
            factory,
            host_cid,
            expected_guest_cid,
            port,
            backlog,
            active: None,
            last_closed: None,
        })
    }

    /// Returns the guest CID that the server owner must pass to
    /// `serve_expected_peer`.
    #[must_use]
    pub const fn expected_guest_cid(&self) -> u32 {
        self.expected_guest_cid
    }

    /// Borrows the listener for the exact currently active lease.
    ///
    /// A previously closed lease and every foreign lease are rejected. The
    /// The borrow is tied to this backend, so a successful exact close cannot
    /// leave a separately owned listener alive.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] unless `lease` is the exact active lease.
    pub fn listener_for(&self, lease: &BrokerLease) -> Result<&F::Listener, BackendError> {
        let Some(active) = self.active.as_ref() else {
            return Err(unknown_lease_error("listener lookup"));
        };
        if !active.lease.eq(lease) {
            return Err(unknown_lease_error("listener lookup"));
        }
        Ok(&active.listener)
    }

    /// Borrows the listener for the exact currently active lease.
    ///
    /// This name makes the lease check explicit for callers that pass the
    /// returned listener to the egress broker server.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] unless `lease` is the exact active lease.
    pub fn listener_for_lease(&self, lease: &BrokerLease) -> Result<&F::Listener, BackendError> {
        self.listener_for(lease)
    }

    /// Creates a production backend using `AfVsockListener::bind`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the transport configuration is invalid.
    pub fn new_production(
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
    ) -> Result<Self, BackendError>
    where
        F: From<AfVsockListenerFactory>,
    {
        Self::new(
            AfVsockListenerFactory.into(),
            host_cid,
            expected_guest_cid,
            port,
            backlog,
        )
    }
}

impl BrokerBackend<AfVsockListenerFactory> {
    /// Creates a production backend using `AfVsockListener::bind`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the transport configuration is invalid.
    pub fn production(
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
    ) -> Result<Self, BackendError> {
        Self::new(
            AfVsockListenerFactory,
            host_cid,
            expected_guest_cid,
            port,
            backlog,
        )
    }
}

impl<F: VsockListenerFactory> OrchestratorBrokerBackend for BrokerBackend<F> {
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        if self.active.is_some() {
            return Err(BackendError::new(
                "Broker establishment rejected: one exact lease is already active",
            ));
        }

        let lease = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        if self
            .last_closed
            .as_ref()
            .is_some_and(|closed| closed.eq(&lease))
        {
            return Err(BackendError::new(
                "Broker establishment rejected: the exact lease was already closed",
            ));
        }

        let listener = self
            .factory
            .bind(self.host_cid, self.port, self.backlog)
            .map_err(|error| {
                BackendError::new(format!("host AF_VSOCK listener bind failed: {error}"))
            })?;
        self.active = Some(ActiveBroker {
            lease: lease.clone(),
            listener,
        });
        Ok(lease)
    }

    fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        match self.active.take() {
            Some(active) if active.lease.eq(lease) => {
                self.last_closed = Some(active.lease.clone());
                drop(active);
                Ok(())
            }
            Some(active) => {
                self.active = Some(active);
                Err(unknown_lease_error("close"))
            }
            None if self
                .last_closed
                .as_ref()
                .is_some_and(|closed| closed.eq(lease)) =>
            {
                Ok(())
            }
            None => Err(unknown_lease_error("close")),
        }
    }
}

fn validate_host_cid(host_cid: u32) -> Result<(), BackendError> {
    if !(MIN_HOST_CID..VMADDR_CID_ANY).contains(&host_cid) {
        return Err(BackendError::new(format!(
            "invalid host CID {host_cid}: expected an explicit CID in 2..{}",
            VMADDR_CID_ANY - 1,
        )));
    }
    Ok(())
}

fn validate_guest_cid(expected_guest_cid: u32) -> Result<(), BackendError> {
    if !(MIN_GUEST_CID..VMADDR_CID_ANY).contains(&expected_guest_cid) {
        return Err(BackendError::new(format!(
            "invalid expected guest CID {expected_guest_cid}: expected an explicit CID in 3..{}",
            VMADDR_CID_ANY - 1,
        )));
    }
    Ok(())
}

fn validate_port(port: u32) -> Result<(), BackendError> {
    if port == 0 || port == VMADDR_PORT_ANY {
        return Err(BackendError::new(format!(
            "invalid AF_VSOCK port {port}: expected a non-zero explicit port below {VMADDR_PORT_ANY}",
        )));
    }
    Ok(())
}

fn validate_backlog(backlog: i32) -> Result<(), BackendError> {
    if backlog <= 0 {
        return Err(BackendError::new(format!(
            "invalid AF_VSOCK backlog {backlog}: expected a positive backlog",
        )));
    }
    Ok(())
}

fn unknown_lease_error(operation: &str) -> BackendError {
    BackendError::new(format!(
        "Broker {operation} rejected: lease is not the exact active or previously closed lease",
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use egress_broker::transport::PeerBoundListener;

    use super::{BrokerBackend, VsockListenerFactory};
    use crate::{
        BrokerBackend as OrchestratorBrokerBackend, BrokerLease, BrokerSessionId, CapabilityId,
        RequestId, SessionId, SessionIdentity, SubjectId, VmId, WorkspaceId,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BindCall {
        host_cid: u32,
        port: u32,
        backlog: i32,
    }

    #[derive(Clone)]
    struct FakeFactory {
        calls: Arc<Mutex<Vec<BindCall>>>,
        drops: Arc<AtomicUsize>,
    }

    struct FakeListener {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for FakeListener {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl PeerBoundListener for FakeListener {
        type Stream = Cursor<Vec<u8>>;

        fn accept_peer(&self) -> io::Result<(u32, Self::Stream)> {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "fake listener has no peer",
            ))
        }
    }

    impl VsockListenerFactory for FakeFactory {
        type Listener = FakeListener;

        fn bind(&self, host_cid: u32, port: u32, backlog: i32) -> io::Result<Self::Listener> {
            self.calls
                .lock()
                .expect("fake bind call lock must not be poisoned")
                .push(BindCall {
                    host_cid,
                    port,
                    backlog,
                });
            Ok(FakeListener {
                drops: Arc::clone(&self.drops),
            })
        }
    }

    fn identity(seed: u8) -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([seed; 16]),
            request_id: RequestId::new([seed.wrapping_add(1); 16]),
            vm_id: VmId::new([seed.wrapping_add(2); 16]),
            subject_id: SubjectId::new([seed.wrapping_add(3); 16]),
            workspace_id: WorkspaceId::new([seed.wrapping_add(4); 16]),
            broker_session_id: BrokerSessionId::new([seed.wrapping_add(5); 16]),
            capability_id: CapabilityId::new([seed.wrapping_add(6); 16]),
        }
    }

    fn backend() -> (
        BrokerBackend<FakeFactory>,
        Arc<Mutex<Vec<BindCall>>>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let factory = FakeFactory {
            calls: Arc::clone(&calls),
            drops: Arc::clone(&drops),
        };
        let backend = BrokerBackend::new(factory, 2, 7, 9000, 16)
            .expect("test transport configuration must be valid");
        (backend, calls, drops)
    }

    #[test]
    fn establish_binds_exact_transport_and_identity() {
        let (mut backend, calls, _) = backend();
        let identity = identity(1);

        let lease = backend
            .establish_broker_session(&identity)
            .expect("first Broker establishment must succeed");

        assert_eq!(lease.session_id(), identity.session_id());
        assert_eq!(lease.broker_session_id(), identity.broker_session_id());
        assert_eq!(backend.expected_guest_cid(), 7);
        assert_eq!(
            *calls
                .lock()
                .expect("fake bind call lock must not be poisoned"),
            vec![BindCall {
                host_cid: 2,
                port: 9000,
                backlog: 16,
            }]
        );
        assert!(backend.listener_for(&lease).is_ok());
    }

    #[test]
    fn duplicate_establish_is_rejected_without_another_bind() {
        let (mut backend, calls, _) = backend();
        let first = identity(10);
        backend
            .establish_broker_session(&first)
            .expect("first Broker establishment must succeed");

        assert!(backend.establish_broker_session(&identity(20)).is_err());
        assert_eq!(
            calls
                .lock()
                .expect("fake bind call lock must not be poisoned")
                .len(),
            1
        );
    }

    #[test]
    fn mismatched_close_and_listener_lookup_fail_closed() {
        let (mut backend, _, _) = backend();
        let identity = identity(30);
        let lease = backend
            .establish_broker_session(&identity)
            .expect("Broker establishment must succeed");
        let foreign = BrokerLease::new(SessionId::new([31; 16]), BrokerSessionId::new([32; 16]));

        assert!(backend.listener_for(&foreign).is_err());
        assert!(backend.close_broker_session(&foreign).is_err());
        assert!(backend.listener_for(&lease).is_ok());
    }

    #[test]
    fn exact_close_is_idempotent_but_unknown_close_is_not_success() {
        let (mut backend, _, drops) = backend();
        let lease = backend
            .establish_broker_session(&identity(40))
            .expect("Broker establishment must succeed");

        backend
            .close_broker_session(&lease)
            .expect("exact close must succeed");
        assert!(backend.close_broker_session(&lease).is_ok());
        assert!(backend.listener_for(&lease).is_err());
        assert!(
            backend
                .close_broker_session(&BrokerLease::new(
                    SessionId::new([41; 16]),
                    BrokerSessionId::new([42; 16]),
                ))
                .is_err()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exact_close_drops_the_active_listener() {
        let (mut backend, _, drops) = backend();
        let lease = backend
            .establish_broker_session(&identity(50))
            .expect("Broker establishment must succeed");
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        backend
            .close_broker_session(&lease)
            .expect("exact close must succeed");

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
