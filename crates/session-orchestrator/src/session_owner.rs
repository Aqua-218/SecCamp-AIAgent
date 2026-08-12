//! Synchronous production ownership for one complete session lifecycle.
//!
//! `SessionOwner` keeps the orchestrator and every resource backend in one
//! non-cloneable value. Callers drive health checks explicitly through
//! [`SessionOwner::poll`]; this module never spawns a worker that could outlive
//! the owner or retain a backend after shutdown begins.

use std::{error::Error, fmt};

use crate::{
    BackendError, BrokerBackend, BrokerLease, CapabilityBackend, CapabilityRevocationBackend,
    CryptographicRandom, IdentityLedger, LifecycleState, SessionInfo, SessionOrchestrator,
    SnapshotDescriptor, StartError, StopError, VmBackend, WorkloadBackend, WorkspaceBackend,
    WorkspaceTemplateId,
};

/// Broker liveness observed for the exact lease owned by the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrokerRuntimeStatus {
    /// The Broker worker serving the lease is still running.
    Running,
    /// The Broker worker serving the lease terminated.
    Exited,
}

/// A lease-bound health boundary implemented by a production Broker adapter.
pub trait BrokerStatusBackend: BrokerBackend {
    /// Polls the worker that owns exactly `lease`.
    ///
    /// Implementations must reject stale, closed, and foreign leases instead
    /// of reporting the status of another worker.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the exact worker cannot be identified or
    /// its status cannot be observed safely.
    fn poll_broker_status(
        &mut self,
        lease: &BrokerLease,
    ) -> Result<BrokerRuntimeStatus, BackendError>;
}

/// Host control sampled by one synchronous owner poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerPollRequest {
    /// Continue the session if its exact Broker worker is healthy.
    Continue,
    /// Begin externally requested shutdown without another health poll.
    Stop,
}

/// The event that caused the owner to begin terminal cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShutdownReason {
    /// The host explicitly requested shutdown.
    ExternalRequest,
    /// The exact Broker worker exited while the session was running.
    BrokerExited,
    /// Broker health could not be established and the owner failed closed.
    BrokerStatusUnavailable,
    /// Startup rollback retained cleanup work for an explicit retry.
    StartupRollback,
}

/// The stable result of one owner poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerPollOutcome {
    /// The session and its exact Broker worker remain active.
    Running(SessionInfo),
    /// All resources reached terminal cleanup for the reported reason.
    Closed(ShutdownReason),
}

/// A health or cleanup failure observed by the session owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerPollError {
    /// The owner has no running or retryable session to poll.
    InvalidState(LifecycleState),
    /// Broker health was unavailable; cleanup was attempted before returning.
    BrokerStatus {
        /// Exact-lease status failure.
        error: BackendError,
        /// Cleanup failure retained in `Stopping`, if cleanup did not finish.
        cleanup_error: Option<StopError>,
    },
    /// Shutdown began for `reason`, but cleanup remains retryable.
    Cleanup {
        /// Stable reason retained across cleanup retries.
        reason: ShutdownReason,
        /// Ordered cleanup failures from this retry pass.
        error: StopError,
    },
}

impl OwnerPollError {
    /// Returns the cleanup reason when shutdown has begun.
    #[must_use]
    pub const fn shutdown_reason(&self) -> Option<ShutdownReason> {
        match self {
            Self::InvalidState(_) => None,
            Self::BrokerStatus { .. } => Some(ShutdownReason::BrokerStatusUnavailable),
            Self::Cleanup { reason, .. } => Some(*reason),
        }
    }

    /// Returns the retained cleanup error, if cleanup remains incomplete.
    #[must_use]
    pub const fn cleanup_error(&self) -> Option<&StopError> {
        match self {
            Self::InvalidState(_) => None,
            Self::BrokerStatus { cleanup_error, .. } => cleanup_error.as_ref(),
            Self::Cleanup { error, .. } => Some(error),
        }
    }
}

impl fmt::Display for OwnerPollError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(state) => {
                write!(formatter, "cannot poll session owner in {state} state")
            }
            Self::BrokerStatus {
                error,
                cleanup_error: None,
            } => write!(
                formatter,
                "exact Broker status failed and fail-closed cleanup completed: {error}"
            ),
            Self::BrokerStatus {
                error,
                cleanup_error: Some(cleanup_error),
            } => write!(
                formatter,
                "exact Broker status failed and fail-closed cleanup remains incomplete: {error}; {cleanup_error}"
            ),
            Self::Cleanup { reason, error } => {
                write!(
                    formatter,
                    "session cleanup for {reason:?} remains incomplete: {error}"
                )
            }
        }
    }
}

impl Error for OwnerPollError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidState(_) => None,
            Self::BrokerStatus { error, .. } => Some(error),
            Self::Cleanup { error, .. } => Some(error),
        }
    }
}

/// Backends exclusively retained for the lifetime of a [`SessionOwner`].
pub struct SessionBackends<W, B, V, C, Work> {
    workspace: W,
    broker: B,
    vm: V,
    capability: C,
    workload: Work,
}

impl<W, B, V, C, Work> SessionBackends<W, B, V, C, Work> {
    /// Bundles the five lifecycle backends without exposing independent
    /// mutable ownership after a session owner is constructed.
    #[must_use]
    pub const fn new(workspace: W, broker: B, vm: V, capability: C, workload: Work) -> Self {
        Self {
            workspace,
            broker,
            vm,
            capability,
            workload,
        }
    }
}

/// Exclusive synchronous owner of an orchestrator and all session backends.
pub struct SessionOwner<R, L, W, B, V, C, Work>
where
    R: CryptographicRandom,
    L: IdentityLedger,
    W: WorkspaceBackend,
    B: BrokerStatusBackend,
    V: VmBackend,
    C: CapabilityRevocationBackend,
    Work: WorkloadBackend,
{
    orchestrator: SessionOrchestrator<R, L>,
    backends: SessionBackends<W, B, V, C, Work>,
    shutdown_reason: Option<ShutdownReason>,
}

impl<R, L, W, B, V, C, Work> SessionOwner<R, L, W, B, V, C, Work>
where
    R: CryptographicRandom,
    L: IdentityLedger,
    W: WorkspaceBackend,
    B: BrokerStatusBackend,
    V: VmBackend,
    C: CapabilityRevocationBackend,
    Work: WorkloadBackend,
{
    /// Takes exclusive ownership of a complete lifecycle stack.
    #[must_use]
    pub const fn new(
        orchestrator: SessionOrchestrator<R, L>,
        backends: SessionBackends<W, B, V, C, Work>,
    ) -> Self {
        Self {
            orchestrator,
            backends,
            shutdown_reason: None,
        }
    }

    /// Returns the underlying orchestrator lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.orchestrator.state()
    }

    /// Returns the running session summary, if startup committed.
    #[must_use]
    pub fn active_session(&self) -> Option<SessionInfo> {
        self.orchestrator.active_session()
    }

    /// Returns the shutdown reason retained across cleanup retries.
    #[must_use]
    pub const fn shutdown_reason(&self) -> Option<ShutdownReason> {
        self.shutdown_reason
    }

    /// Starts one session while all mutable backends remain exclusively owned.
    ///
    /// A failed startup whose rollback is incomplete records
    /// [`ShutdownReason::StartupRollback`] so later polls retry cleanup without
    /// attempting to observe a partially started Broker worker.
    ///
    /// # Errors
    ///
    /// Returns [`StartError`] with the orchestrator's stage and rollback report.
    pub fn start<G>(
        &mut self,
        snapshot: &SnapshotDescriptor,
        workspace_template: &WorkspaceTemplateId,
        grant: &G,
    ) -> Result<SessionInfo, StartError>
    where
        C: CapabilityBackend<G>,
    {
        if matches!(
            self.orchestrator.state(),
            LifecycleState::Ready | LifecycleState::Closed
        ) {
            self.shutdown_reason = None;
        }
        let result = self.orchestrator.start_session(
            snapshot,
            workspace_template,
            grant,
            &mut self.backends.workspace,
            &mut self.backends.broker,
            &mut self.backends.vm,
            &mut self.backends.capability,
            &mut self.backends.workload,
        );
        if result.is_err()
            && self.orchestrator.state() == LifecycleState::Stopping
            && self.shutdown_reason.is_none()
        {
            self.shutdown_reason = Some(ShutdownReason::StartupRollback);
        }
        result
    }

    /// Polls an external stop request and the exact active Broker lease.
    ///
    /// External stop takes precedence and does not perform another health poll.
    /// An observed exit starts cleanup immediately. A status error also starts
    /// cleanup before it is returned, because an unverified worker must not be
    /// treated as live. If cleanup fails, the owner remains in `Stopping` and a
    /// later call retries only unfinished stages.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerPollError`] for an invalid lifecycle state, unavailable
    /// exact-lease status, or retryable cleanup failure.
    pub fn poll(&mut self, request: OwnerPollRequest) -> Result<OwnerPollOutcome, OwnerPollError> {
        match self.orchestrator.state() {
            LifecycleState::Running => self.poll_running(request),
            LifecycleState::Stopping => {
                let reason = self
                    .shutdown_reason
                    .unwrap_or(ShutdownReason::StartupRollback);
                self.finish_shutdown(reason)
            }
            LifecycleState::Closed => self
                .shutdown_reason
                .map(OwnerPollOutcome::Closed)
                .ok_or(OwnerPollError::InvalidState(LifecycleState::Closed)),
            state => Err(OwnerPollError::InvalidState(state)),
        }
    }

    /// Requests host-initiated shutdown through the same cleanup path as poll.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerPollError`] when no session can be stopped or cleanup
    /// remains incomplete.
    pub fn stop(&mut self) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.poll(OwnerPollRequest::Stop)
    }

    fn poll_running(
        &mut self,
        request: OwnerPollRequest,
    ) -> Result<OwnerPollOutcome, OwnerPollError> {
        if request == OwnerPollRequest::Stop {
            return self.finish_shutdown(ShutdownReason::ExternalRequest);
        }

        let Some(lease) = self.orchestrator.active_broker_lease().cloned() else {
            return self.fail_closed_status(BackendError::new(
                "running session has no exact Broker lease to poll",
            ));
        };
        match self.backends.broker.poll_broker_status(&lease) {
            Ok(BrokerRuntimeStatus::Running) => {
                let Some(info) = self.orchestrator.active_session() else {
                    return self.fail_closed_status(BackendError::new(
                        "running lifecycle has no active session summary",
                    ));
                };
                Ok(OwnerPollOutcome::Running(info))
            }
            Ok(BrokerRuntimeStatus::Exited) => self.finish_shutdown(ShutdownReason::BrokerExited),
            Err(error) => self.fail_closed_status(error),
        }
    }

    fn fail_closed_status(
        &mut self,
        error: BackendError,
    ) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.shutdown_reason = Some(ShutdownReason::BrokerStatusUnavailable);
        let cleanup_error = self.stop_active().err();
        Err(OwnerPollError::BrokerStatus {
            error,
            cleanup_error,
        })
    }

    fn finish_shutdown(
        &mut self,
        reason: ShutdownReason,
    ) -> Result<OwnerPollOutcome, OwnerPollError> {
        self.shutdown_reason = Some(reason);
        self.stop_active()
            .map(|()| OwnerPollOutcome::Closed(reason))
            .map_err(|error| OwnerPollError::Cleanup { reason, error })
    }

    fn stop_active(&mut self) -> Result<(), StopError> {
        self.orchestrator.stop_session(
            &mut self.backends.workspace,
            &mut self.backends.broker,
            &mut self.backends.vm,
            &mut self.backends.capability,
        )
    }
}

impl<R, L, W, B, V, C, Work> Drop for SessionOwner<R, L, W, B, V, C, Work>
where
    R: CryptographicRandom,
    L: IdentityLedger,
    W: WorkspaceBackend,
    B: BrokerStatusBackend,
    V: VmBackend,
    C: CapabilityRevocationBackend,
    Work: WorkloadBackend,
{
    fn drop(&mut self) {
        if matches!(
            self.orchestrator.state(),
            LifecycleState::Running | LifecycleState::Stopping
        ) {
            let _ = self.stop_active();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::{
        CapabilityLease, EntropyError, ID_BYTES, InMemoryIdentityLedger, SessionId,
        SessionIdentity, VmLease, WorkloadLease, WorkspaceLease,
    };

    type Events = Arc<Mutex<Vec<&'static str>>>;

    #[derive(Default)]
    struct TestRandom(u8);

    impl CryptographicRandom for TestRandom {
        fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError> {
            self.0 = self.0.wrapping_add(1);
            Ok([self.0; ID_BYTES])
        }
    }

    struct TestWorkspace {
        events: Events,
    }

    impl WorkspaceBackend for TestWorkspace {
        fn clone_workspace(
            &mut self,
            identity: &SessionIdentity,
            _template: &WorkspaceTemplateId,
        ) -> Result<WorkspaceLease, BackendError> {
            record(&self.events, "clone");
            Ok(WorkspaceLease::new(
                identity.session_id(),
                identity.workspace_id(),
            ))
        }

        fn isolate_workspace(&mut self, _lease: &WorkspaceLease) -> Result<(), BackendError> {
            record(&self.events, "isolate");
            Ok(())
        }
    }

    struct TestBroker {
        events: Events,
        active: Option<BrokerLease>,
        statuses: VecDeque<Result<BrokerRuntimeStatus, BackendError>>,
    }

    impl BrokerBackend for TestBroker {
        fn establish_broker_session(
            &mut self,
            identity: &SessionIdentity,
        ) -> Result<BrokerLease, BackendError> {
            record(&self.events, "establish");
            let lease = BrokerLease::new(identity.session_id(), identity.broker_session_id());
            self.active = Some(lease.clone());
            Ok(lease)
        }

        fn ensure_broker_session_running(
            &mut self,
            lease: &BrokerLease,
        ) -> Result<(), BackendError> {
            if self.active.as_ref() == Some(lease) {
                Ok(())
            } else {
                Err(BackendError::new(
                    "test rejected an inexact Broker health check",
                ))
            }
        }

        fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
            record(&self.events, "close");
            if self.active.as_ref() != Some(lease) {
                return Err(BackendError::new("test rejected an inexact Broker close"));
            }
            self.active = None;
            Ok(())
        }
    }

    impl BrokerStatusBackend for TestBroker {
        fn poll_broker_status(
            &mut self,
            lease: &BrokerLease,
        ) -> Result<BrokerRuntimeStatus, BackendError> {
            record(&self.events, "poll");
            if self.active.as_ref() != Some(lease) {
                return Err(BackendError::new("test rejected an inexact Broker poll"));
            }
            self.statuses
                .pop_front()
                .unwrap_or(Ok(BrokerRuntimeStatus::Running))
        }
    }

    struct TestVm {
        events: Events,
        kill_failures: VecDeque<bool>,
    }

    impl VmBackend for TestVm {
        fn start_vm(
            &mut self,
            _snapshot: &SnapshotDescriptor,
            identity: &SessionIdentity,
            workspace: &WorkspaceLease,
            broker: &BrokerLease,
        ) -> Result<VmLease, BackendError> {
            record(&self.events, "start-vm");
            Ok(VmLease::new(
                identity.session_id(),
                identity.vm_id(),
                workspace.workspace_id(),
                broker.broker_session_id(),
            ))
        }

        fn kill_vm(&mut self, _lease: &VmLease) -> Result<(), BackendError> {
            record(&self.events, "kill");
            if self.kill_failures.pop_front().unwrap_or(false) {
                return Err(BackendError::new("test VM kill failed"));
            }
            Ok(())
        }
    }

    struct TestCapability {
        events: Events,
    }

    impl CapabilityRevocationBackend for TestCapability {
        fn revoke_root_capability(&mut self, _lease: &CapabilityLease) -> Result<(), BackendError> {
            record(&self.events, "revoke");
            Ok(())
        }
    }

    impl CapabilityBackend<()> for TestCapability {
        fn inject_root_capability(
            &mut self,
            identity: &SessionIdentity,
            _grant: &(),
        ) -> Result<CapabilityLease, BackendError> {
            record(&self.events, "inject");
            Ok(CapabilityLease::new(
                identity.session_id(),
                identity.subject_id(),
                identity.capability_id(),
            ))
        }
    }

    struct TestWorkload {
        events: Events,
        release_failures: VecDeque<bool>,
    }

    impl WorkloadBackend for TestWorkload {
        fn release_workload(
            &mut self,
            identity: &SessionIdentity,
            vm: &VmLease,
            capability: &CapabilityLease,
        ) -> Result<WorkloadLease, BackendError> {
            record(&self.events, "release");
            if self.release_failures.pop_front().unwrap_or(false) {
                return Err(BackendError::new("test workload release failed"));
            }
            Ok(WorkloadLease::new(
                identity.session_id(),
                vm.vm_id(),
                capability.subject_id(),
                capability.capability_id(),
            ))
        }
    }

    type TestOwner = SessionOwner<
        TestRandom,
        InMemoryIdentityLedger,
        TestWorkspace,
        TestBroker,
        TestVm,
        TestCapability,
        TestWorkload,
    >;

    fn record(events: &Events, event: &'static str) {
        events
            .lock()
            .expect("test event lock must not be poisoned")
            .push(event);
    }

    fn owner(
        statuses: impl IntoIterator<Item = Result<BrokerRuntimeStatus, BackendError>>,
        kill_failures: impl IntoIterator<Item = bool>,
        release_failures: impl IntoIterator<Item = bool>,
    ) -> (TestOwner, Events) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let backends = SessionBackends::new(
            TestWorkspace {
                events: Arc::clone(&events),
            },
            TestBroker {
                events: Arc::clone(&events),
                active: None,
                statuses: statuses.into_iter().collect(),
            },
            TestVm {
                events: Arc::clone(&events),
                kill_failures: kill_failures.into_iter().collect(),
            },
            TestCapability {
                events: Arc::clone(&events),
            },
            TestWorkload {
                events: Arc::clone(&events),
                release_failures: release_failures.into_iter().collect(),
            },
        );
        (
            SessionOwner::new(SessionOrchestrator::new(TestRandom::default()), backends),
            events,
        )
    }

    fn start(owner: &mut TestOwner) -> SessionInfo {
        owner
            .start(
                &SnapshotDescriptor::clean(crate::SnapshotId::new([0x91; ID_BYTES])),
                &WorkspaceTemplateId::new("template"),
                &(),
            )
            .expect("test session startup must succeed")
    }

    #[test]
    fn broker_exit_stops_exact_owned_session_in_dependency_order() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Exited)], [], []);
        let info = start(&mut owner);

        assert_eq!(
            owner.poll(OwnerPollRequest::Continue),
            Ok(OwnerPollOutcome::Closed(ShutdownReason::BrokerExited))
        );
        assert_eq!(owner.state(), LifecycleState::Closed);
        assert_eq!(owner.active_session(), None);
        assert_eq!(owner.shutdown_reason(), Some(ShutdownReason::BrokerExited));
        assert_eq!(info.identity().session_id(), SessionId::new([1; ID_BYTES]));
        assert_eq!(
            events
                .lock()
                .expect("test event lock must not be poisoned")
                .as_slice(),
            [
                "clone",
                "establish",
                "start-vm",
                "inject",
                "release",
                "poll",
                "revoke",
                "kill",
                "close",
                "isolate",
            ]
        );
    }

    #[test]
    fn healthy_exact_broker_poll_keeps_owned_session_running() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Running)], [], []);
        let info = start(&mut owner);

        assert_eq!(
            owner.poll(OwnerPollRequest::Continue),
            Ok(OwnerPollOutcome::Running(info))
        );
        assert_eq!(owner.state(), LifecycleState::Running);
        assert_eq!(owner.active_session(), Some(info));
        assert_eq!(
            events
                .lock()
                .expect("test event lock must not be poisoned")
                .as_slice(),
            [
                "clone",
                "establish",
                "start-vm",
                "inject",
                "release",
                "poll"
            ]
        );

        owner.stop().expect("test cleanup must succeed");
    }

    #[test]
    fn cleanup_failure_stays_stopping_and_poll_retries_only_unfinished_work() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Exited)], [true, false], []);
        start(&mut owner);

        let error = owner
            .poll(OwnerPollRequest::Continue)
            .expect_err("first cleanup pass must retain the failed VM kill");
        assert_eq!(error.shutdown_reason(), Some(ShutdownReason::BrokerExited));
        assert!(error.cleanup_error().is_some());
        assert_eq!(owner.state(), LifecycleState::Stopping);

        assert_eq!(
            owner.poll(OwnerPollRequest::Continue),
            Ok(OwnerPollOutcome::Closed(ShutdownReason::BrokerExited))
        );
        assert_eq!(
            events
                .lock()
                .expect("test event lock must not be poisoned")
                .as_slice(),
            [
                "clone",
                "establish",
                "start-vm",
                "inject",
                "release",
                "poll",
                "revoke",
                "kill",
                "close",
                "kill",
                "isolate",
            ]
        );
    }

    #[test]
    fn failed_start_cleanup_is_retried_without_polling_partial_broker_state() {
        let (mut owner, events) = owner([], [true, false], [true]);

        let error = owner
            .start(
                &SnapshotDescriptor::clean(crate::SnapshotId::new([0x92; ID_BYTES])),
                &WorkspaceTemplateId::new("template"),
                &(),
            )
            .expect_err("workload release and first VM cleanup must fail");

        assert_eq!(error.stage(), crate::StartStage::WorkloadRelease);
        assert_eq!(error.rollback_failures().len(), 1);
        assert_eq!(owner.state(), LifecycleState::Stopping);
        assert_eq!(
            owner.shutdown_reason(),
            Some(ShutdownReason::StartupRollback)
        );
        assert_eq!(
            owner.poll(OwnerPollRequest::Continue),
            Ok(OwnerPollOutcome::Closed(ShutdownReason::StartupRollback))
        );
        let events = events.lock().expect("test event lock must not be poisoned");
        assert!(!events.contains(&"poll"));
        assert_eq!(events.iter().filter(|event| **event == "kill").count(), 2);
        assert_eq!(events.last(), Some(&"isolate"));
    }

    #[test]
    fn external_stop_preempts_status_poll() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Running)], [], []);
        start(&mut owner);

        assert_eq!(
            owner.stop(),
            Ok(OwnerPollOutcome::Closed(ShutdownReason::ExternalRequest))
        );
        assert!(
            !events
                .lock()
                .expect("test event lock must not be poisoned")
                .contains(&"poll")
        );
    }

    #[test]
    fn status_failure_fails_closed_before_returning_error() {
        let (mut owner, events) =
            owner([Err(BackendError::new("test status unavailable"))], [], []);
        start(&mut owner);

        let error = owner
            .poll(OwnerPollRequest::Continue)
            .expect_err("unverified Broker status must be reported");

        assert_eq!(
            error.shutdown_reason(),
            Some(ShutdownReason::BrokerStatusUnavailable)
        );
        assert_eq!(error.cleanup_error(), None);
        assert_eq!(owner.state(), LifecycleState::Closed);
        assert_eq!(
            events
                .lock()
                .expect("test event lock must not be poisoned")
                .last(),
            Some(&"isolate")
        );
    }

    #[test]
    fn drop_synchronously_attempts_cleanup_without_a_detached_worker() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Running)], [], []);
        start(&mut owner);

        drop(owner);

        assert_eq!(
            events
                .lock()
                .expect("test event lock must not be poisoned")
                .as_slice(),
            [
                "clone",
                "establish",
                "start-vm",
                "inject",
                "release",
                "revoke",
                "kill",
                "close",
                "isolate",
            ]
        );
    }

    #[test]
    fn drop_retries_one_stopping_cleanup_pass_synchronously() {
        let (mut owner, events) = owner([Ok(BrokerRuntimeStatus::Exited)], [true, false], []);
        start(&mut owner);
        owner
            .poll(OwnerPollRequest::Continue)
            .expect_err("first VM kill must leave cleanup retryable");

        drop(owner);

        let events = events.lock().expect("test event lock must not be poisoned");
        assert_eq!(events.iter().filter(|event| **event == "kill").count(), 2);
        assert_eq!(events.last(), Some(&"isolate"));
    }
}
