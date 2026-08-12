//! Host-owned Broker service lifecycle for one session-scoped `AF_VSOCK` endpoint.
//!
//! A successful lease means that the listener is bound, the session runtime is
//! built, and its worker thread is owned by this backend. The listener and
//! accepted stream are never lent to callers. Closing an exact lease cancels
//! accept, shuts down an accepted stream, and joins the worker before the
//! resource is considered closed.

use std::{
    io::{self, Read, Write},
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use authority_core::time::MonotonicTime;
use egress_broker::{
    dispatch::DispatchContext,
    server::{ConnectionCloseReason, RequestDispatcher, ServerError, serve_connection},
    transport::{AfVsockListener, TransportError, VsockShutdownHandle, VsockStream},
};

use crate::{
    BackendError, BrokerBackend as OrchestratorBrokerBackend, BrokerLease, SessionIdentity,
    session_owner::{BrokerRuntimeStatus, BrokerStatusBackend},
};

const MIN_HOST_CID: u32 = 2;
const MIN_GUEST_CID: u32 = 3;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_PORT_ANY: u32 = u32::MAX;
const DEFAULT_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
const DROP_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Interrupts both directions of one accepted Broker stream.
pub trait BrokerStreamShutdown: Send + 'static {
    /// Shuts down the associated stream.
    ///
    /// Implementations must return promptly. The owner invokes shutdown
    /// synchronously before applying its bounded worker-join deadline.
    ///
    /// # Errors
    ///
    /// Returns the transport error when the stream cannot be interrupted.
    fn shutdown(&self) -> io::Result<()>;
}

impl BrokerStreamShutdown for VsockShutdownHandle {
    fn shutdown(&self) -> io::Result<()> {
        self.shutdown()
    }
}

/// Nonblocking listener operations required by the owned service worker.
pub trait BrokerServiceListener: Send + 'static {
    /// Accepted stream type.
    type Stream: Read + Write + Send + 'static;
    /// Owner-only shutdown capability for an accepted stream.
    type Shutdown: BrokerStreamShutdown;

    /// Attempts to accept one kernel-authenticated peer without blocking.
    ///
    /// `Ok(None)` means no peer is currently pending.
    ///
    /// # Errors
    ///
    /// Returns the underlying accept or peer-address error.
    fn try_accept_peer(&self) -> io::Result<Option<(u32, Self::Stream)>>;

    /// Creates the owner-only cancellation capability for `stream`.
    ///
    /// # Errors
    ///
    /// Returns the underlying descriptor-clone error.
    fn shutdown_handle(stream: &Self::Stream) -> io::Result<Self::Shutdown>;
}

impl BrokerServiceListener for AfVsockListener {
    type Stream = VsockStream;
    type Shutdown = VsockShutdownHandle;

    fn try_accept_peer(&self) -> io::Result<Option<(u32, Self::Stream)>> {
        self.try_accept_peer()
    }

    fn shutdown_handle(stream: &Self::Stream) -> io::Result<Self::Shutdown> {
        stream.shutdown_handle()
    }
}

/// Creates one nonblocking host-bound listener for a Broker service.
pub trait VsockListenerFactory {
    /// Listener type returned after a successful bind.
    type Listener: BrokerServiceListener;

    /// Binds a listener to the exact host CID, port, and backlog supplied by
    /// the backend.
    ///
    /// # Errors
    ///
    /// Returns the underlying bind error when the listener cannot be created.
    fn bind(&self, host_cid: u32, port: u32, backlog: i32) -> io::Result<Self::Listener>;
}

/// Production listener factory backed by a nonblocking Linux `AF_VSOCK` socket.
#[derive(Debug, Clone, Copy, Default)]
pub struct AfVsockListenerFactory;

impl VsockListenerFactory for AfVsockListenerFactory {
    type Listener = AfVsockListener;

    fn bind(&self, host_cid: u32, port: u32, backlog: i32) -> io::Result<Self::Listener> {
        AfVsockListener::bind_nonblocking(host_cid, port, backlog)
    }
}

/// Cooperative cancellation observed by a session Broker runtime.
#[derive(Debug, Clone)]
pub struct BrokerCancellation {
    requested: Arc<AtomicBool>,
}

impl BrokerCancellation {
    fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.requested.store(true, Ordering::Release);
    }

    /// Reports whether the service owner requested cancellation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

/// Typed terminal reason returned by one Broker connection runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerConnectionExit {
    /// The authenticated peer cleanly ended its request stream.
    EndOfStream,
    /// The configured per-connection request maximum was reached.
    RequestLimitReached {
        /// Number of complete request/response exchanges.
        requests_served: usize,
    },
    /// Broken byte accounting forced fail-closed termination.
    AccountingInvariant {
        /// Number of complete request/response exchanges before termination.
        requests_served: usize,
    },
    /// An external effect committed without its terminal audit record.
    CommittedButUnrecorded {
        /// Number of complete request/response exchanges before fail-closed termination.
        requests_served: usize,
    },
    /// Owner cancellation interrupted the connection.
    Cancelled,
    /// Serving failed before a typed normal terminal condition.
    Failed {
        /// Stable operator-facing failure context.
        message: String,
    },
}

/// Runs the policy and protocol loop for one already CID-authenticated stream.
pub trait BrokerRuntime<S>: Send + 'static {
    /// Owns and serves `stream` until a typed terminal condition is reached.
    ///
    /// Implementations must serve synchronously: they must not transfer the
    /// stream to a detached task, and they must return after cancellation plus
    /// stream shutdown. Those requirements let backend close and drop retain
    /// exclusive ownership until the worker has actually terminated.
    fn serve(self, stream: S, cancellation: &BrokerCancellation) -> BrokerConnectionExit;
}

/// Production connection runtime built from the Broker dispatch dependencies.
pub struct BuiltBrokerRuntime<C> {
    dispatcher: Box<dyn RequestDispatcher + Send>,
    identity: DispatchContext,
    clock: C,
    max_requests: NonZeroUsize,
}

impl<C> BuiltBrokerRuntime<C> {
    /// Captures one session's dispatcher, immutable identity, clock, and bound.
    #[must_use]
    pub fn new(
        dispatcher: Box<dyn RequestDispatcher + Send>,
        identity: DispatchContext,
        clock: C,
        max_requests: NonZeroUsize,
    ) -> Self {
        Self {
            dispatcher,
            identity,
            clock,
            max_requests,
        }
    }
}

impl<S, C> BrokerRuntime<S> for BuiltBrokerRuntime<C>
where
    S: Read + Write + Send + 'static,
    C: FnMut() -> MonotonicTime + Send + 'static,
{
    fn serve(mut self, stream: S, cancellation: &BrokerCancellation) -> BrokerConnectionExit {
        match serve_connection(
            stream,
            self.dispatcher.as_mut(),
            &self.identity,
            &mut self.clock,
            self.max_requests,
        ) {
            Ok(report) => {
                successful_connection_exit(report.close_reason(), report.requests_served())
            }
            Err(_) if cancellation.is_cancelled() => BrokerConnectionExit::Cancelled,
            Err(ServerError::Transport(TransportError::Io(error)))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                BrokerConnectionExit::EndOfStream
            }
            Err(error) => BrokerConnectionExit::Failed {
                message: error.to_string(),
            },
        }
    }
}

fn successful_connection_exit(
    close_reason: ConnectionCloseReason,
    requests_served: usize,
) -> BrokerConnectionExit {
    match close_reason {
        ConnectionCloseReason::RequestLimitReached => {
            BrokerConnectionExit::RequestLimitReached { requests_served }
        }
        ConnectionCloseReason::AccountingInvariant => {
            BrokerConnectionExit::AccountingInvariant { requests_served }
        }
        ConnectionCloseReason::CommittedButUnrecorded => {
            BrokerConnectionExit::CommittedButUnrecorded { requests_served }
        }
    }
}

/// Builds the exact runtime state for one fresh Broker session identity.
pub trait BrokerRuntimeFactory<S>: Send + Sync + 'static {
    /// Per-session runtime moved into the owned worker.
    type Runtime: BrokerRuntime<S>;

    /// Builds dispatch, clock, and accounting state for `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the runtime cannot be built completely.
    fn build(&self, identity: &SessionIdentity) -> Result<Self::Runtime, BackendError>;
}

/// Typed terminal reason for the backend-owned Broker worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerWorkerExit {
    /// Close cancelled the worker before any peer was accepted.
    Cancelled,
    /// The authenticated connection reached a runtime terminal condition.
    Connection(BrokerConnectionExit),
    /// Accepting the first peer failed.
    AcceptFailed {
        /// Original transport failure.
        message: String,
    },
    /// The kernel-reported peer CID did not match the host-selected CID.
    UnexpectedPeer {
        /// Host-selected CID.
        expected: u32,
        /// Kernel-reported CID.
        received: u32,
    },
    /// The accepted stream could not produce an owner-only shutdown handle.
    ShutdownHandleFailed {
        /// Original descriptor-clone failure.
        message: String,
    },
    /// The runtime panicked; the worker caught the unwind and failed closed.
    Panicked,
    /// The worker ended without publishing its typed terminal reason.
    ExitChannelLost,
}

/// Parent-observable state of one exact Broker lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerWorkerStatus {
    /// The worker has not published a terminal reason.
    Running,
    /// The worker has terminated with the enclosed typed reason.
    Exited(BrokerWorkerExit),
}

/// A Broker backend using the production `AF_VSOCK` listener factory.
pub type ProductionBrokerBackend<R> = BrokerBackend<AfVsockListenerFactory, R>;

type StreamShutdownSlot<F> =
    Arc<Mutex<Option<<<F as VsockListenerFactory>::Listener as BrokerServiceListener>::Shutdown>>>;

struct ActiveBroker<F>
where
    F: VsockListenerFactory,
{
    lease: BrokerLease,
    cancellation: BrokerCancellation,
    stream_shutdown: StreamShutdownSlot<F>,
    exit_receiver: Receiver<BrokerWorkerExit>,
    worker: Option<JoinHandle<()>>,
    exit: Option<BrokerWorkerExit>,
    drop_join_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropJoinAction {
    Join,
    Wait(Duration),
    FailStop,
}

fn drop_join_action(worker_finished: bool, elapsed: Duration, timeout: Duration) -> DropJoinAction {
    if worker_finished {
        return DropJoinAction::Join;
    }
    let remaining = timeout.saturating_sub(elapsed);
    if remaining.is_zero() {
        DropJoinAction::FailStop
    } else {
        DropJoinAction::Wait(remaining.min(DROP_JOIN_POLL_INTERVAL))
    }
}

impl<F> ActiveBroker<F>
where
    F: VsockListenerFactory,
{
    fn request_cancel(&self) -> Option<String> {
        self.cancellation.cancel();
        if let Some(worker) = self.worker.as_ref() {
            worker.thread().unpark();
        }
        let shutdown = self
            .stream_shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shutdown
            .as_ref()
            .and_then(|handle| handle.shutdown().err())
            .map(|error| error.to_string())
    }

    fn publish_received_exit(&mut self, exit: BrokerWorkerExit) {
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            self.exit = Some(BrokerWorkerExit::Panicked);
            return;
        }
        self.exit = Some(exit);
    }

    fn refresh_exit(&mut self) {
        if self.exit.is_some() {
            return;
        }
        match self.exit_receiver.try_recv() {
            Ok(exit) => self.publish_received_exit(exit),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.exit = Some(self.disconnected_exit());
            }
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        self.refresh_exit();
        if self.exit.is_some() {
            return true;
        }
        match self.exit_receiver.recv_timeout(timeout) {
            Ok(exit) => self.publish_received_exit(exit),
            Err(RecvTimeoutError::Timeout) => return false,
            Err(RecvTimeoutError::Disconnected) => {
                self.exit = Some(self.disconnected_exit());
            }
        }
        true
    }

    fn disconnected_exit(&mut self) -> BrokerWorkerExit {
        let Some(worker) = self.worker.take() else {
            return BrokerWorkerExit::ExitChannelLost;
        };
        if worker.join().is_err() {
            BrokerWorkerExit::Panicked
        } else {
            BrokerWorkerExit::ExitChannelLost
        }
    }

    fn wait_for_drop_progress(&mut self, timeout: Duration) {
        if self.exit.is_some() {
            thread::park_timeout(timeout);
            return;
        }
        match self.exit_receiver.recv_timeout(timeout) {
            Ok(exit) => self.exit = Some(exit),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => thread::park_timeout(timeout),
        }
    }
}

impl<F> Drop for ActiveBroker<F>
where
    F: VsockListenerFactory,
{
    fn drop(&mut self) {
        if self.worker.is_none() {
            return;
        }

        // Destructors must not unwind, especially while an outer panic is
        // already in flight. Cancellation is set before stream shutdown, so a
        // panicking shutdown implementation can be contained while the owner
        // still waits for the worker. Forgetting the panic payload also avoids
        // running a hostile payload destructor from this destructor.
        if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| self.request_cancel())) {
            std::mem::forget(payload);
        }

        let started = Instant::now();
        loop {
            let worker_finished = self.worker.as_ref().is_some_and(JoinHandle::is_finished);
            match drop_join_action(worker_finished, started.elapsed(), self.drop_join_timeout) {
                DropJoinAction::Join => {
                    if let Some(worker) = self.worker.take() {
                        let _ = worker.join();
                    }
                    return;
                }
                DropJoinAction::Wait(timeout) => self.wait_for_drop_progress(timeout),
                // A live worker cannot be detached safely: it still owns a
                // session-scoped listener/runtime. Abort is the explicit
                // fail-stop boundary once bounded cancellation is exhausted.
                DropJoinAction::FailStop => std::process::abort(),
            }
        }
    }
}

struct ClosedBroker {
    lease: BrokerLease,
    exit: BrokerWorkerExit,
}

/// Owns one complete Broker service and its exact lifecycle lease.
pub struct BrokerBackend<F, R>
where
    F: VsockListenerFactory,
    R: BrokerRuntimeFactory<
        <<F as VsockListenerFactory>::Listener as BrokerServiceListener>::Stream,
    >,
{
    listener_factory: F,
    runtime_factory: R,
    host_cid: u32,
    expected_guest_cid: u32,
    port: u32,
    backlog: i32,
    accept_poll_interval: Duration,
    join_timeout: Duration,
    active: Option<ActiveBroker<F>>,
    last_closed: Option<ClosedBroker>,
}

impl<F, R> BrokerBackend<F, R>
where
    F: VsockListenerFactory,
    R: BrokerRuntimeFactory<
        <<F as VsockListenerFactory>::Listener as BrokerServiceListener>::Stream,
    >,
{
    /// Creates a backend with bounded default accept polling and join timing.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when transport configuration is invalid.
    pub fn new(
        listener_factory: F,
        runtime_factory: R,
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
    ) -> Result<Self, BackendError> {
        Self::with_timeouts(
            listener_factory,
            runtime_factory,
            host_cid,
            expected_guest_cid,
            port,
            backlog,
            DEFAULT_ACCEPT_POLL_INTERVAL,
            DEFAULT_JOIN_TIMEOUT,
        )
    }

    /// Creates a backend with explicit cancellation-poll and close-join bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when transport configuration or either timeout
    /// is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn with_timeouts(
        listener_factory: F,
        runtime_factory: R,
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
        accept_poll_interval: Duration,
        join_timeout: Duration,
    ) -> Result<Self, BackendError> {
        validate_host_cid(host_cid)?;
        validate_guest_cid(expected_guest_cid)?;
        validate_port(port)?;
        validate_backlog(backlog)?;
        validate_duration("accept poll interval", accept_poll_interval)?;
        validate_duration("worker join timeout", join_timeout)?;

        Ok(Self {
            listener_factory,
            runtime_factory,
            host_cid,
            expected_guest_cid,
            port,
            backlog,
            accept_poll_interval,
            join_timeout,
            active: None,
            last_closed: None,
        })
    }

    /// Returns the kernel-authenticated guest CID required by the worker.
    #[must_use]
    pub const fn expected_guest_cid(&self) -> u32 {
        self.expected_guest_cid
    }

    /// Polls the exact active or most recently closed lease without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] for every foreign or stale lease.
    pub fn poll_broker_status(
        &mut self,
        lease: &BrokerLease,
    ) -> Result<BrokerWorkerStatus, BackendError> {
        if let Some(active) = self.active.as_mut() {
            if !active.lease.eq(lease) {
                return Err(unknown_lease_error("status poll"));
            }
            active.refresh_exit();
            return Ok(match active.exit.as_ref() {
                Some(exit) => BrokerWorkerStatus::Exited(exit.clone()),
                None => BrokerWorkerStatus::Running,
            });
        }
        match self.last_closed.as_ref() {
            Some(closed) if closed.lease.eq(lease) => {
                Ok(BrokerWorkerStatus::Exited(closed.exit.clone()))
            }
            _ => Err(unknown_lease_error("status poll")),
        }
    }

    fn establish(&mut self, identity: &SessionIdentity) -> Result<BrokerLease, BackendError> {
        if self.active.is_some() {
            return Err(BackendError::new(
                "Broker establishment rejected: one exact lease is already active",
            ));
        }

        let lease = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        if self
            .last_closed
            .as_ref()
            .is_some_and(|closed| closed.lease.eq(&lease))
        {
            return Err(BackendError::new(
                "Broker establishment rejected: the exact lease was already closed",
            ));
        }

        let listener = self
            .listener_factory
            .bind(self.host_cid, self.port, self.backlog)
            .map_err(|error| {
                BackendError::new(format!("host AF_VSOCK listener bind failed: {error}"))
            })?;
        let runtime = self.runtime_factory.build(identity)?;
        let cancellation = BrokerCancellation::new();
        let stream_shutdown = Arc::new(Mutex::new(None));
        let (exit_sender, exit_receiver) = mpsc::sync_channel(1);
        let worker_cancellation = cancellation.clone();
        let worker_shutdown = Arc::clone(&stream_shutdown);
        let expected_guest_cid = self.expected_guest_cid;
        let accept_poll_interval = self.accept_poll_interval;
        let worker = thread::Builder::new()
            .name("session-egress-broker".to_owned())
            .spawn(move || {
                let exit = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_worker(
                        &listener,
                        runtime,
                        expected_guest_cid,
                        &worker_cancellation,
                        &worker_shutdown,
                        accept_poll_interval,
                    )
                }))
                .unwrap_or(BrokerWorkerExit::Panicked);
                let _ = exit_sender.send(exit);
            })
            .map_err(|error| BackendError::new(format!("Broker worker spawn failed: {error}")))?;

        self.active = Some(ActiveBroker {
            lease: lease.clone(),
            cancellation,
            stream_shutdown,
            exit_receiver,
            worker: Some(worker),
            exit: None,
            drop_join_timeout: self.join_timeout,
        });
        Ok(lease)
    }

    fn close(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        let Some(mut active) = self.active.take() else {
            return match self.last_closed.as_ref() {
                Some(closed) if closed.lease.eq(lease) => Ok(()),
                _ => Err(unknown_lease_error("close")),
            };
        };
        if !active.lease.eq(lease) {
            self.active = Some(active);
            return Err(unknown_lease_error("close"));
        }

        let shutdown_error = active.request_cancel();
        if !active.wait_for_exit(self.join_timeout) {
            self.active = Some(active);
            let shutdown_context = shutdown_error
                .map(|message| format!("; stream shutdown also failed: {message}"))
                .unwrap_or_default();
            return Err(BackendError::new(format!(
                "Broker close timed out after {:?}; worker ownership retained for retry{shutdown_context}",
                self.join_timeout,
            )));
        }

        let exit = active
            .exit
            .take()
            .unwrap_or(BrokerWorkerExit::ExitChannelLost);
        self.last_closed = Some(ClosedBroker {
            lease: active.lease.clone(),
            exit,
        });
        Ok(())
    }
}

impl<R> BrokerBackend<AfVsockListenerFactory, R>
where
    R: BrokerRuntimeFactory<VsockStream>,
{
    /// Creates a production transport backend with a caller-supplied runtime factory.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when transport configuration is invalid.
    pub fn production(
        runtime_factory: R,
        host_cid: u32,
        expected_guest_cid: u32,
        port: u32,
        backlog: i32,
    ) -> Result<Self, BackendError> {
        Self::new(
            AfVsockListenerFactory,
            runtime_factory,
            host_cid,
            expected_guest_cid,
            port,
            backlog,
        )
    }
}

impl<F, R> OrchestratorBrokerBackend for BrokerBackend<F, R>
where
    F: VsockListenerFactory,
    R: BrokerRuntimeFactory<
        <<F as VsockListenerFactory>::Listener as BrokerServiceListener>::Stream,
    >,
{
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        self.establish(identity)
    }

    fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        self.close(lease)
    }

    fn ensure_broker_session_running(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        match BrokerBackend::poll_broker_status(self, lease)? {
            BrokerWorkerStatus::Running => Ok(()),
            BrokerWorkerStatus::Exited(exit) => Err(BackendError::new(format!(
                "Broker worker exited before workload release: {exit:?}",
            ))),
        }
    }
}

impl<F, R> BrokerStatusBackend for BrokerBackend<F, R>
where
    F: VsockListenerFactory,
    R: BrokerRuntimeFactory<
        <<F as VsockListenerFactory>::Listener as BrokerServiceListener>::Stream,
    >,
{
    fn poll_broker_status(
        &mut self,
        lease: &BrokerLease,
    ) -> Result<BrokerRuntimeStatus, BackendError> {
        BrokerBackend::poll_broker_status(self, lease).map(|status| match status {
            BrokerWorkerStatus::Running => BrokerRuntimeStatus::Running,
            BrokerWorkerStatus::Exited(_) => BrokerRuntimeStatus::Exited,
        })
    }
}

fn run_worker<L, R>(
    listener: &L,
    runtime: R,
    expected_guest_cid: u32,
    cancellation: &BrokerCancellation,
    stream_shutdown: &Arc<Mutex<Option<L::Shutdown>>>,
    accept_poll_interval: Duration,
) -> BrokerWorkerExit
where
    L: BrokerServiceListener,
    R: BrokerRuntime<L::Stream>,
{
    let (peer_cid, stream) = loop {
        if cancellation.is_cancelled() {
            return BrokerWorkerExit::Cancelled;
        }
        match listener.try_accept_peer() {
            Ok(Some(accepted)) => break accepted,
            Ok(None) => thread::park_timeout(accept_poll_interval),
            Err(error) => {
                return BrokerWorkerExit::AcceptFailed {
                    message: error.to_string(),
                };
            }
        }
    };

    if peer_cid != expected_guest_cid {
        return BrokerWorkerExit::UnexpectedPeer {
            expected: expected_guest_cid,
            received: peer_cid,
        };
    }
    let shutdown = match L::shutdown_handle(&stream) {
        Ok(shutdown) => shutdown,
        Err(error) => {
            return BrokerWorkerExit::ShutdownHandleFailed {
                message: error.to_string(),
            };
        }
    };
    stream_shutdown
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(shutdown);
    if cancellation.is_cancelled() {
        return BrokerWorkerExit::Cancelled;
    }
    BrokerWorkerExit::Connection(runtime.serve(stream, cancellation))
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

fn validate_duration(name: &str, duration: Duration) -> Result<(), BackendError> {
    if duration.is_zero() {
        return Err(BackendError::new(format!(
            "invalid Broker {name}: expected a positive duration",
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
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use egress_broker::server::ConnectionCloseReason;

    use super::{
        BrokerBackend, BrokerCancellation, BrokerConnectionExit, BrokerRuntime,
        BrokerRuntimeFactory, BrokerServiceListener, BrokerStreamShutdown, BrokerWorkerExit,
        BrokerWorkerStatus, DROP_JOIN_POLL_INTERVAL, DropJoinAction, VsockListenerFactory,
        drop_join_action, successful_connection_exit,
    };
    use crate::{
        BackendError, BrokerBackend as OrchestratorBrokerBackend, BrokerLease, BrokerSessionId,
        CapabilityId, RequestId, SessionId, SessionIdentity, SubjectId, VmId, WorkspaceId,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BindCall {
        host_cid: u32,
        port: u32,
        backlog: i32,
    }

    #[derive(Clone)]
    struct FakeListenerFactory {
        calls: Arc<Mutex<Vec<BindCall>>>,
        peer_cid: u32,
        accepted: Arc<AtomicBool>,
        shutdowns: Arc<AtomicUsize>,
    }

    struct FakeListener {
        peer_cid: u32,
        accepted: Arc<AtomicBool>,
        shutdowns: Arc<AtomicUsize>,
    }

    struct FakeStream {
        bytes: Cursor<Vec<u8>>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl io::Read for FakeStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.bytes.read(buffer)
        }
    }

    impl io::Write for FakeStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeShutdown(Arc<AtomicUsize>);

    impl BrokerStreamShutdown for FakeShutdown {
        fn shutdown(&self) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl BrokerServiceListener for FakeListener {
        type Stream = FakeStream;
        type Shutdown = FakeShutdown;

        fn try_accept_peer(&self) -> io::Result<Option<(u32, Self::Stream)>> {
            if self.accepted.swap(true, Ordering::SeqCst) {
                return Ok(None);
            }
            Ok(Some((
                self.peer_cid,
                FakeStream {
                    bytes: Cursor::new(Vec::new()),
                    shutdowns: Arc::clone(&self.shutdowns),
                },
            )))
        }

        fn shutdown_handle(stream: &Self::Stream) -> io::Result<Self::Shutdown> {
            Ok(FakeShutdown(Arc::clone(&stream.shutdowns)))
        }
    }

    impl VsockListenerFactory for FakeListenerFactory {
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
                peer_cid: self.peer_cid,
                accepted: Arc::clone(&self.accepted),
                shutdowns: Arc::clone(&self.shutdowns),
            })
        }
    }

    #[derive(Clone)]
    struct RuntimeFactory {
        builds: Arc<AtomicUsize>,
        behavior: RuntimeBehavior,
    }

    #[derive(Clone)]
    enum RuntimeBehavior {
        Exit(BrokerConnectionExit),
        Block(Arc<(Mutex<BlockState>, Condvar)>),
        Panic,
    }

    #[derive(Default)]
    struct BlockState {
        entered: bool,
        released: bool,
    }

    struct TestRuntime(RuntimeBehavior);

    impl BrokerRuntime<FakeStream> for TestRuntime {
        fn serve(
            self,
            _stream: FakeStream,
            cancellation: &BrokerCancellation,
        ) -> BrokerConnectionExit {
            match self.0 {
                RuntimeBehavior::Exit(exit) => exit,
                RuntimeBehavior::Block(gate) => {
                    let (state, condvar) = &*gate;
                    let mut state = state.lock().expect("gate lock must not be poisoned");
                    state.entered = true;
                    condvar.notify_all();
                    while !state.released {
                        state = condvar
                            .wait_timeout(state, Duration::from_millis(2))
                            .expect("gate wait must not be poisoned")
                            .0;
                        if cancellation.is_cancelled() && state.released {
                            break;
                        }
                    }
                    BrokerConnectionExit::Cancelled
                }
                RuntimeBehavior::Panic => panic!("scripted Broker runtime panic"),
            }
        }
    }

    impl BrokerRuntimeFactory<FakeStream> for RuntimeFactory {
        type Runtime = TestRuntime;

        fn build(&self, _identity: &SessionIdentity) -> Result<Self::Runtime, BackendError> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            Ok(TestRuntime(self.behavior.clone()))
        }
    }

    type TestBackend = BrokerBackend<FakeListenerFactory, RuntimeFactory>;
    type BackendFixture = (
        TestBackend,
        Arc<Mutex<Vec<BindCall>>>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    );

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

    fn backend(behavior: RuntimeBehavior, join_timeout: Duration) -> BackendFixture {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let builds = Arc::new(AtomicUsize::new(0));
        let listener_factory = FakeListenerFactory {
            calls: Arc::clone(&calls),
            peer_cid: 7,
            accepted: Arc::new(AtomicBool::new(false)),
            shutdowns: Arc::clone(&shutdowns),
        };
        let runtime_factory = RuntimeFactory {
            builds: Arc::clone(&builds),
            behavior,
        };
        let backend = BrokerBackend::with_timeouts(
            listener_factory,
            runtime_factory,
            2,
            7,
            9000,
            16,
            Duration::from_millis(1),
            join_timeout,
        )
        .expect("test transport configuration must be valid");
        (backend, calls, builds, shutdowns)
    }

    fn wait_for_exit(backend: &mut TestBackend, lease: &BrokerLease) -> BrokerWorkerExit {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match backend
                .poll_broker_status(lease)
                .expect("exact lease status poll must succeed")
            {
                BrokerWorkerStatus::Running if Instant::now() < deadline => thread::yield_now(),
                BrokerWorkerStatus::Running => panic!("Broker worker did not exit before deadline"),
                BrokerWorkerStatus::Exited(exit) => return exit,
            }
        }
    }

    fn wait_until_runtime_entered(gate: &Arc<(Mutex<BlockState>, Condvar)>) {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (state, condvar) = &**gate;
        let mut state = state.lock().expect("gate lock must not be poisoned");
        while !state.entered {
            let now = Instant::now();
            assert!(
                now < deadline,
                "Broker runtime did not start before deadline"
            );
            state = condvar
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .expect("gate wait must not be poisoned")
                .0;
        }
    }

    fn release_runtime(gate: &Arc<(Mutex<BlockState>, Condvar)>) {
        let (state, condvar) = &**gate;
        state
            .lock()
            .expect("gate lock must not be poisoned")
            .released = true;
        condvar.notify_all();
    }

    #[test]
    fn establish_binds_builds_spawns_then_returns_exact_lease() {
        let (mut backend, calls, builds, _) = backend(
            RuntimeBehavior::Exit(BrokerConnectionExit::RequestLimitReached { requests_served: 8 }),
            Duration::from_secs(1),
        );
        let session = identity(1);

        let lease = backend
            .establish_broker_session(&session)
            .expect("first Broker establishment must succeed");

        assert_eq!(lease.session_id(), session.session_id());
        assert_eq!(lease.broker_session_id(), session.broker_session_id());
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(
            *calls.lock().expect("bind log must not be poisoned"),
            vec![BindCall {
                host_cid: 2,
                port: 9000,
                backlog: 16,
            }]
        );
        assert_eq!(
            wait_for_exit(&mut backend, &lease),
            BrokerWorkerExit::Connection(BrokerConnectionExit::RequestLimitReached {
                requests_served: 8,
            })
        );
    }

    #[test]
    fn production_report_mapping_preserves_max_accounting_and_cbu_reasons() {
        assert_eq!(
            successful_connection_exit(ConnectionCloseReason::RequestLimitReached, 9),
            BrokerConnectionExit::RequestLimitReached { requests_served: 9 }
        );
        assert_eq!(
            successful_connection_exit(ConnectionCloseReason::AccountingInvariant, 4),
            BrokerConnectionExit::AccountingInvariant { requests_served: 4 }
        );
        assert_eq!(
            successful_connection_exit(ConnectionCloseReason::CommittedButUnrecorded, 2),
            BrokerConnectionExit::CommittedButUnrecorded { requests_served: 2 }
        );
    }

    #[test]
    fn drop_join_decision_joins_only_a_known_finished_worker() {
        let timeout = Duration::from_millis(5);

        assert_eq!(
            drop_join_action(true, Duration::ZERO, timeout),
            DropJoinAction::Join
        );
        assert_eq!(
            drop_join_action(true, timeout, timeout),
            DropJoinAction::Join
        );
    }

    #[test]
    fn drop_join_decision_waits_boundedly_then_requires_fail_stop() {
        let timeout = Duration::from_millis(5);

        assert_eq!(
            drop_join_action(false, Duration::ZERO, timeout),
            DropJoinAction::Wait(DROP_JOIN_POLL_INTERVAL)
        );
        assert_eq!(
            drop_join_action(false, Duration::from_micros(4_500), timeout),
            DropJoinAction::Wait(Duration::from_micros(500))
        );
        assert_eq!(
            drop_join_action(false, timeout, timeout),
            DropJoinAction::FailStop
        );
        assert_eq!(
            drop_join_action(false, timeout + Duration::from_millis(1), timeout),
            DropJoinAction::FailStop
        );
    }

    #[test]
    fn exact_close_shuts_down_and_preserves_typed_exit_for_idempotent_poll() {
        let gate = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
        let (mut backend, _, _, shutdowns) = backend(
            RuntimeBehavior::Block(Arc::clone(&gate)),
            Duration::from_secs(1),
        );
        let lease = backend
            .establish_broker_session(&identity(10))
            .expect("Broker establishment must succeed");
        let deadline = Instant::now() + Duration::from_secs(1);
        while shutdowns.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            if let Some(active) = backend.active.as_ref()
                && active
                    .stream_shutdown
                    .lock()
                    .expect("shutdown slot must not be poisoned")
                    .is_some()
            {
                break;
            }
            thread::yield_now();
        }
        release_runtime(&gate);

        backend
            .close_broker_session(&lease)
            .expect("exact close must join the worker");

        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert!(backend.close_broker_session(&lease).is_ok());
        assert_eq!(
            backend
                .poll_broker_status(&lease)
                .expect("closed exact lease remains observable"),
            BrokerWorkerStatus::Exited(BrokerWorkerExit::Connection(
                BrokerConnectionExit::Cancelled
            ))
        );
    }

    #[test]
    fn close_timeout_retains_worker_for_exact_retry() {
        let gate = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
        let (mut backend, _, _, _) = backend(
            RuntimeBehavior::Block(Arc::clone(&gate)),
            Duration::from_millis(5),
        );
        let lease = backend
            .establish_broker_session(&identity(20))
            .expect("Broker establishment must succeed");
        wait_until_runtime_entered(&gate);

        let error = backend
            .close_broker_session(&lease)
            .expect_err("uncooperative worker must time out");
        assert!(error.message().contains("ownership retained for retry"));
        assert!(backend.active.is_some());

        release_runtime(&gate);
        backend
            .close_broker_session(&lease)
            .expect("same exact lease must be retryable");
        assert!(backend.active.is_none());
    }

    #[test]
    fn worker_panic_is_caught_as_typed_exit() {
        let (mut backend, _, _, _) = backend(RuntimeBehavior::Panic, Duration::from_secs(1));
        let lease = backend
            .establish_broker_session(&identity(30))
            .expect("Broker establishment must succeed");

        assert_eq!(
            wait_for_exit(&mut backend, &lease),
            BrokerWorkerExit::Panicked
        );
        backend
            .close_broker_session(&lease)
            .expect("caught panic leaves a joinable worker");
    }

    #[test]
    fn workload_release_check_requires_the_exact_worker_to_be_running() {
        let gate = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
        let (mut backend, _, _, _) = backend(
            RuntimeBehavior::Block(Arc::clone(&gate)),
            Duration::from_secs(1),
        );
        let lease = backend
            .establish_broker_session(&identity(35))
            .expect("Broker establishment must succeed");
        wait_until_runtime_entered(&gate);

        backend
            .ensure_broker_session_running(&lease)
            .expect("an observed running exact worker permits workload release");
        release_runtime(&gate);
        assert_eq!(
            wait_for_exit(&mut backend, &lease),
            BrokerWorkerExit::Connection(BrokerConnectionExit::Cancelled)
        );
        assert!(backend.ensure_broker_session_running(&lease).is_err());
        backend
            .close_broker_session(&lease)
            .expect("test cleanup must succeed");
    }

    #[test]
    fn foreign_close_and_status_poll_do_not_disturb_exact_owner() {
        let (mut backend, _, _, _) = backend(
            RuntimeBehavior::Exit(BrokerConnectionExit::EndOfStream),
            Duration::from_secs(1),
        );
        let lease = backend
            .establish_broker_session(&identity(40))
            .expect("Broker establishment must succeed");
        let foreign = BrokerLease::new(SessionId::new([41; 16]), BrokerSessionId::new([42; 16]));

        assert!(backend.poll_broker_status(&foreign).is_err());
        assert!(backend.close_broker_session(&foreign).is_err());
        assert!(backend.poll_broker_status(&lease).is_ok());
    }

    #[test]
    fn duplicate_establish_is_rejected_without_another_bind_or_build() {
        let gate = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
        let (mut backend, calls, builds, _) = backend(
            RuntimeBehavior::Block(Arc::clone(&gate)),
            Duration::from_secs(1),
        );
        let lease = backend
            .establish_broker_session(&identity(50))
            .expect("first Broker establishment must succeed");

        assert!(backend.establish_broker_session(&identity(51)).is_err());
        assert_eq!(
            calls.lock().expect("bind log must not be poisoned").len(),
            1
        );
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        release_runtime(&gate);
        backend
            .close_broker_session(&lease)
            .expect("test cleanup must succeed");
    }
}
