//! Shared workspace composition for the session orchestrator and Firecracker runtime.
//!
//! The orchestrator owns workspace creation and deletion. The runtime receives a
//! view over the same filesystem that can verify artifacts and claim the exact
//! workspace already prepared by the orchestrator. Keeping both views over one
//! mutex-protected state prevents the runtime from copying the workspace again.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use firecracker_runtime::{FileSystem, RuntimeError};

use crate::{BackendError, SessionIdentity, WorkspaceBackend, WorkspaceLease, WorkspaceTemplateId};

/// The orchestrator-side adapter and runtime-side filesystem view for one workspace root.
pub type FirecrackerWorkspaceAdapters<F> =
    (FirecrackerWorkspaceBackend<F>, FirecrackerFileSystem<F>);

/// Shared state used by both sides of the workspace composition.
struct SharedWorkspaceState<F> {
    filesystem: F,
    prepared: HashMap<crate::WorkspaceId, PreparedWorkspace>,
}

/// The exact binding retained after the orchestrator prepares a workspace.
struct PreparedWorkspace {
    session_id: crate::SessionId,
    workspace_id: crate::WorkspaceId,
    source: PathBuf,
    destination: PathBuf,
    runtime_claimed: bool,
    runtime_released: bool,
    orchestrator_released: bool,
}

/// A [`WorkspaceBackend`] backed by a shared [`FileSystem`] composition.
pub struct FirecrackerWorkspaceBackend<F> {
    state: Arc<Mutex<SharedWorkspaceState<F>>>,
    configured_template: WorkspaceTemplateId,
    source: PathBuf,
    clone_root: PathBuf,
}

/// A [`FileSystem`] view for Firecracker that claims prepared workspaces without copying them.
pub struct FirecrackerFileSystem<F> {
    state: Arc<Mutex<SharedWorkspaceState<F>>>,
}

/// Compatibility name for the runtime-side adapter.
pub type FirecrackerWorkspaceFileSystem<F> = FirecrackerFileSystem<F>;

/// Factory that composes one configured workspace template with one filesystem instance.
pub struct FirecrackerWorkspaceBackendFactory<F> {
    state: Arc<Mutex<SharedWorkspaceState<F>>>,
    configured_template: WorkspaceTemplateId,
    source: PathBuf,
    clone_root: PathBuf,
}

/// Short name for [`FirecrackerWorkspaceBackendFactory`].
pub type FirecrackerWorkspaceFactory<F> = FirecrackerWorkspaceBackendFactory<F>;

impl<F> FirecrackerWorkspaceBackendFactory<F> {
    /// Creates a factory around one filesystem, source path, clone root, and template identity.
    #[must_use]
    pub fn new(
        filesystem: F,
        configured_template: WorkspaceTemplateId,
        source: impl Into<PathBuf>,
        clone_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedWorkspaceState {
                filesystem,
                prepared: HashMap::new(),
            })),
            configured_template,
            source: source.into(),
            clone_root: clone_root.into(),
        }
    }

    /// Returns separate orchestrator and runtime handles over the same shared state.
    #[must_use]
    pub fn into_handles(self) -> FirecrackerWorkspaceAdapters<F> {
        let state = self.state;
        (
            FirecrackerWorkspaceBackend {
                state: Arc::clone(&state),
                configured_template: self.configured_template,
                source: self.source,
                clone_root: self.clone_root,
            },
            FirecrackerFileSystem { state },
        )
    }
}

/// Creates the orchestrator and runtime adapters over one filesystem instance.
///
/// The configured template is the only template accepted by the returned
/// [`WorkspaceBackend`]. `source` is the exact source path passed to the
/// underlying filesystem, and every destination is `clone_root` followed by
/// the lowercase 32-hexadecimal workspace identity.
#[must_use]
pub fn new_firecracker_workspace_adapters<F>(
    filesystem: F,
    configured_template: WorkspaceTemplateId,
    source: impl Into<PathBuf>,
    clone_root: impl Into<PathBuf>,
) -> FirecrackerWorkspaceAdapters<F> {
    FirecrackerWorkspaceBackendFactory::new(filesystem, configured_template, source, clone_root)
        .into_handles()
}

/// Creates separate workspace backend and runtime filesystem handles.
#[must_use]
pub fn new_firecracker_workspace_backends<F>(
    filesystem: F,
    configured_template: WorkspaceTemplateId,
    source: impl Into<PathBuf>,
    clone_root: impl Into<PathBuf>,
) -> FirecrackerWorkspaceAdapters<F> {
    new_firecracker_workspace_adapters(filesystem, configured_template, source, clone_root)
}

impl<F> WorkspaceBackend for FirecrackerWorkspaceBackend<F>
where
    F: FileSystem,
{
    fn clone_workspace(
        &mut self,
        identity: &SessionIdentity,
        template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError> {
        if template != &self.configured_template {
            return Err(BackendError::new(format!(
                "workspace template mismatch: configured '{}', received '{}'",
                self.configured_template.as_str(),
                template.as_str()
            )));
        }

        let workspace_id = identity.workspace_id();
        let destination = self.clone_root.join(workspace_id.to_string());
        let mut state = self.state.lock().map_err(|_| {
            BackendError::new("workspace state mutex is poisoned; refusing workspace operation")
        })?;

        if state.prepared.contains_key(&workspace_id) {
            return Err(BackendError::new(format!(
                "workspace identity is already prepared: {workspace_id}"
            )));
        }

        state
            .filesystem
            .clone_workspace(&self.source, &destination)
            .map_err(|error| {
                BackendError::new(format!(
                    "failed to prepare workspace {} at {}: {error}",
                    workspace_id,
                    destination.display()
                ))
            })?;

        state.prepared.insert(
            workspace_id,
            PreparedWorkspace {
                session_id: identity.session_id(),
                workspace_id,
                source: self.source.clone(),
                destination,
                runtime_claimed: false,
                runtime_released: false,
                orchestrator_released: false,
            },
        );

        Ok(WorkspaceLease::new(
            identity.session_id(),
            identity.workspace_id(),
        ))
    }

    fn isolate_workspace(&mut self, lease: &WorkspaceLease) -> Result<(), BackendError> {
        let mut state = self.state.lock().map_err(|_| {
            BackendError::new("workspace state mutex is poisoned; refusing workspace operation")
        })?;

        let workspace_id = lease.workspace_id();
        let (destination, already_released, runtime_still_owns) = {
            let record = state.prepared.get(&workspace_id).ok_or_else(|| {
                BackendError::new(format!(
                    "cannot isolate unknown workspace lease: {workspace_id}"
                ))
            })?;
            if record.session_id != lease.session_id() || record.workspace_id != workspace_id {
                return Err(BackendError::new(format!(
                    "workspace lease ownership mismatch for {workspace_id}"
                )));
            }
            (
                record.destination.clone(),
                record.orchestrator_released,
                record.runtime_claimed && !record.runtime_released,
            )
        };

        if already_released {
            return Ok(());
        }
        if runtime_still_owns {
            return Err(BackendError::new(format!(
                "cannot isolate workspace {workspace_id} before Runtime releases it"
            )));
        }

        state
            .filesystem
            .remove_workspace(&destination)
            .map_err(|error| {
                BackendError::new(format!(
                    "failed to isolate workspace {} at {}: {error}",
                    workspace_id,
                    destination.display()
                ))
            })?;

        let Some(record) = state.prepared.get_mut(&workspace_id) else {
            return Err(BackendError::new(format!(
                "workspace record disappeared while isolating {workspace_id}"
            )));
        };
        record.orchestrator_released = true;
        Ok(())
    }
}

impl<F> FileSystem for FirecrackerFileSystem<F>
where
    F: FileSystem,
{
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        state.filesystem.read(path)
    }

    fn clone_workspace(&mut self, source: &Path, destination: &Path) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = state
            .prepared
            .values()
            .find(|record| record.source == source && record.destination == destination)
            .map(|record| record.workspace_id)
            .ok_or_else(|| {
                runtime_workspace_error(
                    "clone_workspace received a source/destination pair that was not prepared by the orchestrator",
                )
            })?;

        let Some(record) = state.prepared.get_mut(&workspace_id) else {
            return Err(runtime_workspace_error(
                "workspace record disappeared while claiming the prepared workspace",
            ));
        };
        if record.orchestrator_released {
            return Err(runtime_workspace_error(
                "clone_workspace received a workspace already released by the orchestrator",
            ));
        }
        if record.runtime_claimed {
            return Err(runtime_workspace_error(
                "clone_workspace attempted to claim one prepared workspace twice",
            ));
        }

        record.runtime_claimed = true;
        Ok(())
    }

    fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = state
            .prepared
            .values()
            .find(|record| record.destination == path)
            .map(|record| record.workspace_id)
            .ok_or_else(|| {
                runtime_workspace_error(
                    "remove_workspace received a path that was not prepared by the orchestrator",
                )
            })?;

        let Some(record) = state.prepared.get_mut(&workspace_id) else {
            return Err(runtime_workspace_error(
                "workspace record disappeared while releasing the runtime claim",
            ));
        };
        if !record.runtime_claimed {
            return Err(runtime_workspace_error(
                "remove_workspace received a workspace that Runtime did not claim",
            ));
        }
        if record.runtime_released {
            return Ok(());
        }

        // The orchestrator owns physical deletion. Runtime cleanup only records
        // that the Runtime side released its claim, so it cannot delete a path
        // still needed by the orchestrator's rollback state.
        record.runtime_released = true;
        Ok(())
    }
}

fn poisoned_runtime_error() -> RuntimeError {
    RuntimeError::InvalidState {
        expected: "healthy shared workspace state".to_owned(),
        actual: "workspace state mutex is poisoned".to_owned(),
    }
}

fn runtime_workspace_error(message: &str) -> RuntimeError {
    RuntimeError::InvalidState {
        expected: "an exact prepared workspace binding".to_owned(),
        actual: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BrokerSessionId, CapabilityId, ID_BYTES, RequestId, SessionId, SubjectId, VmId, WorkspaceId,
    };
    use std::{collections::VecDeque, sync::Mutex};

    #[derive(Debug, Default)]
    struct FakeState {
        clones: Vec<(PathBuf, PathBuf)>,
        reads: Vec<PathBuf>,
        removals: Vec<PathBuf>,
        remove_failures: VecDeque<bool>,
    }

    #[derive(Clone, Debug)]
    struct FakeFileSystem {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeFileSystem {
        fn new(state: Arc<Mutex<FakeState>>) -> Self {
            Self { state }
        }
    }

    impl FileSystem for FakeFileSystem {
        fn read(&mut self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .reads
                .push(path.to_owned());
            Ok(b"artifact".to_vec())
        }

        fn clone_workspace(
            &mut self,
            source: &Path,
            destination: &Path,
        ) -> Result<(), RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .clones
                .push((source.to_owned(), destination.to_owned()));
            Ok(())
        }

        fn remove_workspace(&mut self, path: &Path) -> Result<(), RuntimeError> {
            let mut state = self.state.lock().expect("fake state must not be poisoned");
            state.removals.push(path.to_owned());
            if state.remove_failures.pop_front().unwrap_or(false) {
                return Err(RuntimeError::Io("injected removal failure".to_owned()));
            }
            Ok(())
        }
    }

    fn identity(session_byte: u8, workspace_byte: u8) -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([session_byte; ID_BYTES]),
            request_id: RequestId::new([0x20; ID_BYTES]),
            vm_id: VmId::new([0x30; ID_BYTES]),
            subject_id: SubjectId::new([0x40; ID_BYTES]),
            workspace_id: WorkspaceId::new([workspace_byte; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0x60; ID_BYTES]),
            capability_id: CapabilityId::new([0x70; ID_BYTES]),
        }
    }

    fn adapters(state: Arc<Mutex<FakeState>>) -> FirecrackerWorkspaceAdapters<FakeFileSystem> {
        new_firecracker_workspace_adapters(
            FakeFileSystem::new(state),
            WorkspaceTemplateId::new("template-a"),
            "/workspace/source",
            "/workspace/clones",
        )
    }

    #[test]
    fn derives_exact_lowercase_workspace_path_and_does_not_clone_twice() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let (mut backend, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let session = identity(0x11, 0xab);
        let template = WorkspaceTemplateId::new("template-a");

        let lease = backend
            .clone_workspace(&session, &template)
            .expect("orchestrator clone must succeed");
        runtime_filesystem
            .clone_workspace(
                Path::new("/workspace/source"),
                Path::new("/workspace/clones/abababababababababababababababab"),
            )
            .expect("runtime must claim the prepared clone");

        let recorded = state.lock().expect("fake state must not be poisoned");
        assert_eq!(recorded.clones.len(), 1);
        assert_eq!(
            recorded.clones[0],
            (
                PathBuf::from("/workspace/source"),
                PathBuf::from("/workspace/clones/abababababababababababababababab")
            )
        );
        drop(recorded);

        assert!(
            runtime_filesystem
                .clone_workspace(
                    Path::new("/workspace/source"),
                    Path::new("/workspace/clones/abababababababababababababababab"),
                )
                .is_err()
        );
        assert_eq!(
            lease,
            WorkspaceLease::new(session.session_id(), session.workspace_id())
        );
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .clones
                .len(),
            1
        );
    }

    #[test]
    fn rejects_mismatched_template_and_foreign_lease_without_side_effects() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let (mut backend, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let session = identity(0x11, 0xab);

        assert!(
            backend
                .clone_workspace(&session, &WorkspaceTemplateId::new("template-b"))
                .is_err()
        );
        let lease = backend
            .clone_workspace(&session, &WorkspaceTemplateId::new("template-a"))
            .expect("orchestrator clone must succeed");
        let foreign_lease =
            WorkspaceLease::new(SessionId::new([0x99; ID_BYTES]), lease.workspace_id());

        assert!(backend.isolate_workspace(&foreign_lease).is_err());
        assert!(
            runtime_filesystem
                .clone_workspace(
                    Path::new("/workspace/source"),
                    Path::new("/workspace/other")
                )
                .is_err()
        );

        let recorded = state.lock().expect("fake state must not be poisoned");
        assert_eq!(recorded.clones.len(), 1);
        assert!(recorded.removals.is_empty());
    }

    #[test]
    fn runtime_removal_is_non_destructive_and_orchestrator_removal_is_retry_safe() {
        let state = Arc::new(Mutex::new(FakeState {
            remove_failures: VecDeque::from([true, false]),
            ..FakeState::default()
        }));
        let (mut backend, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let session = identity(0x11, 0xab);
        let lease = backend
            .clone_workspace(&session, &WorkspaceTemplateId::new("template-a"))
            .expect("orchestrator clone must succeed");
        runtime_filesystem
            .clone_workspace(
                Path::new("/workspace/source"),
                Path::new("/workspace/clones/abababababababababababababababab"),
            )
            .expect("runtime must claim the prepared clone");

        runtime_filesystem
            .remove_workspace(Path::new(
                "/workspace/clones/abababababababababababababababab",
            ))
            .expect("runtime release must only mark the record");
        assert!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .removals
                .is_empty()
        );

        assert!(backend.isolate_workspace(&lease).is_err());
        assert!(backend.isolate_workspace(&lease).is_ok());
        assert!(backend.isolate_workspace(&lease).is_ok());
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .removals
                .len(),
            2
        );
    }
}
