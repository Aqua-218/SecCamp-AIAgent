//! Fixed-operation systemd boundary for production one-session workers.
//!
//! The controller never accepts a program, unit name, argument, path, or systemd property from a
//! client. A durably allocated 128-bit session ID is encoded into one of two fixed template names;
//! the service manager is expected to authorize only those templates for the unprivileged control
//! account.

use firecracker_runtime::{
    CommandRunner, CommandSpec, PinnedArtifact, RealCommandRunner, RuntimeError,
};

use crate::control_plane::{
    ControlSessionId, ControlWorker, ControlWorkerError, ControlWorkerFactory, ControlWorkerStatus,
    PrincipalId,
};

const WORKER_TEMPLATE: &str = "host-sessiond@";
const RECOVERY_TEMPLATE: &str = "host-sessiond-recover@";

/// Closed service-manager state used by the worker adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedUnitState {
    /// The worker is active or still starting/stopping under systemd ownership.
    Owned,
    /// The unit is inactive and systemd owns no worker process.
    Inactive,
}

/// Fixed lifecycle operations required from a service manager.
pub trait FixedServiceManager: Clone {
    /// Starts the exact worker template instance and waits for successful service admission.
    ///
    /// # Errors
    ///
    /// Returns a closed worker error unless systemd owns the exact admitted unit.
    fn start_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError>;
    /// Observes the exact worker template instance.
    ///
    /// # Errors
    ///
    /// Returns a closed worker error when exact unit state cannot be established.
    fn worker_state(&self, session: ControlSessionId)
    -> Result<FixedUnitState, ControlWorkerError>;
    /// Stops the exact worker template and waits for systemd's stop transaction.
    ///
    /// # Errors
    ///
    /// Returns a closed worker error while the exact unit is not proven inactive.
    fn stop_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError>;
    /// Runs the exact recovery-only template for one session namespace.
    ///
    /// # Errors
    ///
    /// Returns a closed worker error unless recovery succeeds and the worker remains inactive.
    fn recover_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError>;
}

/// Production manager that executes only a pinned `systemctl` and two fixed template names.
#[derive(Clone)]
pub struct PinnedSystemdManager {
    systemctl: PinnedArtifact,
}

impl PinnedSystemdManager {
    /// Creates a manager around one digest-pinned `systemctl` executable.
    #[must_use]
    pub const fn new(systemctl: PinnedArtifact) -> Self {
        Self { systemctl }
    }

    fn run(&self, operation: &str, unit: String) -> Result<Vec<u8>, RuntimeError> {
        let mut runner = RealCommandRunner::new();
        runner
            .run(&CommandSpec::pinned(
                &self.systemctl,
                [
                    "--no-ask-password".to_owned(),
                    "--no-pager".to_owned(),
                    operation.to_owned(),
                    unit,
                ],
            ))
            .map(|output| output.stdout)
    }

    fn state(&self, session: ControlSessionId) -> Result<FixedUnitState, ControlWorkerError> {
        let unit = worker_unit(session);
        let mut runner = RealCommandRunner::new();
        let output = runner
            .run(&CommandSpec::pinned(
                &self.systemctl,
                [
                    "--no-ask-password".to_owned(),
                    "--no-pager".to_owned(),
                    "show".to_owned(),
                    "--property=LoadState".to_owned(),
                    "--property=ActiveState".to_owned(),
                    "--value".to_owned(),
                    unit,
                ],
            ))
            .map_err(|_| ControlWorkerError::StatusUnavailable)?;
        let value = std::str::from_utf8(&output.stdout)
            .map_err(|_| ControlWorkerError::StatusUnavailable)?;
        let states = value.lines().collect::<Vec<_>>();
        if states.len() != 2 || states[0] != "loaded" {
            return Err(ControlWorkerError::StatusUnavailable);
        }
        match states[1] {
            "active" | "activating" | "deactivating" | "reloading" => Ok(FixedUnitState::Owned),
            "inactive" | "failed" => Ok(FixedUnitState::Inactive),
            _ => Err(ControlWorkerError::StatusUnavailable),
        }
    }
}

impl FixedServiceManager for PinnedSystemdManager {
    fn start_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
        self.run("start", worker_unit(session))
            .map_err(|_| ControlWorkerError::StartupFailed)?;
        match self.state(session)? {
            FixedUnitState::Owned => Ok(()),
            FixedUnitState::Inactive => Err(ControlWorkerError::StartupFailed),
        }
    }

    fn worker_state(
        &self,
        session: ControlSessionId,
    ) -> Result<FixedUnitState, ControlWorkerError> {
        self.state(session)
    }

    fn stop_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
        self.run("stop", worker_unit(session))
            .map_err(|_| ControlWorkerError::CleanupIncomplete)?;
        match self.state(session) {
            Ok(FixedUnitState::Inactive) => Ok(()),
            _ => Err(ControlWorkerError::CleanupIncomplete),
        }
    }

    fn recover_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
        self.run("start", recovery_unit(session))
            .map_err(|_| ControlWorkerError::CleanupIncomplete)?;
        match self.state(session) {
            Ok(FixedUnitState::Inactive) => Ok(()),
            _ => Err(ControlWorkerError::CleanupIncomplete),
        }
    }
}

/// Factory that transfers each controller reservation to one fixed systemd worker instance.
pub struct SystemdWorkerFactory<M> {
    manager: M,
}

impl<M> SystemdWorkerFactory<M> {
    /// Creates a factory around a fixed-operation service manager.
    #[must_use]
    pub const fn new(manager: M) -> Self {
        Self { manager }
    }
}

/// One exact systemd-owned worker.
pub struct SystemdWorker<M> {
    manager: M,
    session: ControlSessionId,
}

impl<M: FixedServiceManager> ControlWorker for SystemdWorker<M> {
    fn poll(&mut self) -> Result<ControlWorkerStatus, ControlWorkerError> {
        match self.manager.worker_state(self.session)? {
            FixedUnitState::Owned => Ok(ControlWorkerStatus::Running),
            FixedUnitState::Inactive => Ok(ControlWorkerStatus::Closed),
        }
    }

    fn stop(&mut self) -> Result<(), ControlWorkerError> {
        self.manager.stop_worker(self.session)?;
        self.manager.recover_worker(self.session)
    }
}

impl<M: FixedServiceManager> ControlWorkerFactory for SystemdWorkerFactory<M> {
    type Worker = SystemdWorker<M>;

    fn spawn(
        &mut self,
        _principal: PrincipalId,
        session: ControlSessionId,
    ) -> Result<Self::Worker, ControlWorkerError> {
        self.manager.start_worker(session)?;
        Ok(SystemdWorker {
            manager: self.manager.clone(),
            session,
        })
    }

    fn recover(
        &mut self,
        _principal: PrincipalId,
        session: ControlSessionId,
    ) -> Result<(), ControlWorkerError> {
        self.manager.stop_worker(session)?;
        self.manager.recover_worker(session)
    }
}

fn worker_unit(session: ControlSessionId) -> String {
    format!("{WORKER_TEMPLATE}{session}.service")
}

fn recovery_unit(session: ControlSessionId) -> String {
    format!("{RECOVERY_TEMPLATE}{session}.service")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct FakeManager {
        events: Arc<Mutex<Vec<String>>>,
        state: Arc<Mutex<FixedUnitState>>,
    }

    impl FixedServiceManager for FakeManager {
        fn start_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
            self.events.lock().unwrap().push(format!("start:{session}"));
            *self.state.lock().unwrap() = FixedUnitState::Owned;
            Ok(())
        }

        fn worker_state(
            &self,
            session: ControlSessionId,
        ) -> Result<FixedUnitState, ControlWorkerError> {
            self.events.lock().unwrap().push(format!("poll:{session}"));
            Ok(*self.state.lock().unwrap())
        }

        fn stop_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
            self.events.lock().unwrap().push(format!("stop:{session}"));
            *self.state.lock().unwrap() = FixedUnitState::Inactive;
            Ok(())
        }

        fn recover_worker(&self, session: ControlSessionId) -> Result<(), ControlWorkerError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("recover:{session}"));
            Ok(())
        }
    }

    #[test]
    fn factory_uses_only_the_exact_session_for_start_poll_stop_and_recovery() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(FixedUnitState::Inactive));
        let manager = FakeManager {
            events: Arc::clone(&events),
            state,
        };
        let mut factory = SystemdWorkerFactory::new(manager);
        let principal = PrincipalId::new([1; 16]);
        let session = ControlSessionId::new([0xab; 16]);
        let mut worker = factory.spawn(principal, session).unwrap();
        assert_eq!(worker.poll().unwrap(), ControlWorkerStatus::Running);
        worker.stop().unwrap();
        factory.recover(principal, session).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                format!("start:{session}"),
                format!("poll:{session}"),
                format!("stop:{session}"),
                format!("recover:{session}"),
                format!("stop:{session}"),
                format!("recover:{session}"),
            ]
        );
    }

    #[test]
    fn template_names_are_closed_and_canonical() {
        let session = ControlSessionId::new([0xcd; 16]);
        assert_eq!(
            worker_unit(session),
            "host-sessiond@cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.service"
        );
        assert_eq!(
            recovery_unit(session),
            "host-sessiond-recover@cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.service"
        );
    }
}
