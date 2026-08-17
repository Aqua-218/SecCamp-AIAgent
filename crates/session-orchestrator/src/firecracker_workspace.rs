//! Shared workspace composition for the session orchestrator and Firecracker runtime.
//!
//! The orchestrator owns workspace creation and deletion. The runtime receives a
//! view over the same filesystem that can verify artifacts and claim the exact
//! workspace already prepared by the orchestrator. Keeping both views over one
//! mutex-protected state prevents the runtime from copying the workspace again.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use firecracker_runtime::{FileSystem, RuntimeError, Sha256Digest};

use crate::{BackendError, SessionIdentity, WorkspaceBackend, WorkspaceLease, WorkspaceTemplateId};

/// The orchestrator-side adapter and runtime-side filesystem view for one workspace root.
pub type FirecrackerWorkspaceAdapters<F> =
    (FirecrackerWorkspaceBackend<F>, FirecrackerFileSystem<F>);

/// Shared state used by both sides of the workspace composition.
struct SharedWorkspaceState<F> {
    filesystem: F,
    prepared: HashMap<crate::WorkspaceId, PreparedWorkspace>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceImageState {
    NotCreated,
    Created,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceBlockDeviceState {
    NeverBound,
    Bound,
    Released,
}

/// The exact binding retained after the orchestrator prepares a workspace.
struct PreparedWorkspace {
    session_id: crate::SessionId,
    workspace_id: crate::WorkspaceId,
    source: PathBuf,
    session_jail_root: PathBuf,
    destination: PathBuf,
    runtime_claimed: bool,
    runtime_image: WorkspaceImageState,
    runtime_block_device: WorkspaceBlockDeviceState,
    runtime_released: bool,
    orchestrator_released: bool,
}

/// A [`WorkspaceBackend`] backed by a shared [`FileSystem`] composition.
pub struct FirecrackerWorkspaceBackend<F> {
    state: Arc<Mutex<SharedWorkspaceState<F>>>,
    configured_template: WorkspaceTemplateId,
    source: PathBuf,
    jail_root: PathBuf,
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
    jail_root: PathBuf,
}

/// Short name for [`FirecrackerWorkspaceBackendFactory`].
pub type FirecrackerWorkspaceFactory<F> = FirecrackerWorkspaceBackendFactory<F>;

fn workspace_id_for_block_device<F>(
    state: &SharedWorkspaceState<F>,
    source: &Path,
    jailed_device: &Path,
) -> Result<crate::WorkspaceId, RuntimeError> {
    let record = state
        .prepared
        .values()
        .find(|record| {
            record.runtime_claimed
                && !record.runtime_released
                && !record.orchestrator_released
                && record.session_jail_root.join("dev/rootfs") == jailed_device
        })
        .ok_or_else(|| {
            runtime_workspace_error(
                "block-device operation is not bound to the active session jail",
            )
        })?;
    let expected_mapper_suffix = format!("-{}", record.workspace_id);
    let mapper_is_session_bound = source.parent() == Some(Path::new("/dev/mapper"))
        && source
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(&expected_mapper_suffix));
    if !mapper_is_session_bound {
        return Err(runtime_workspace_error(
            "block-device mapper is not bound to the active workspace identity",
        ));
    }
    Ok(record.workspace_id)
}

impl<F> FirecrackerWorkspaceBackendFactory<F> {
    /// Creates a factory around one filesystem, source path, Firecracker jail root, and template
    /// identity.
    ///
    /// For workspace identity `id`, the session jail is `<jail_root>/<id>/root` and the exact
    /// runtime clone is `<jail_root>/<id>/root/workspace/<id>`.
    #[must_use]
    pub fn new(
        filesystem: F,
        configured_template: WorkspaceTemplateId,
        source: impl Into<PathBuf>,
        jail_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedWorkspaceState {
                filesystem,
                prepared: HashMap::new(),
            })),
            configured_template,
            source: source.into(),
            jail_root: jail_root.into(),
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
                jail_root: self.jail_root,
            },
            FirecrackerFileSystem { state },
        )
    }
}

/// Creates the orchestrator and runtime adapters over one filesystem instance.
///
/// The configured template is the only template accepted by the returned
/// [`WorkspaceBackend`]. `source` is the exact source path passed to the
/// underlying filesystem. `jail_root` is the Firecracker executable-specific directory beneath
/// the jailer's chroot base. Every destination is derived as
/// `<jail_root>/<workspace_id>/root/workspace/<workspace_id>`.
#[must_use]
pub fn new_firecracker_workspace_adapters<F>(
    filesystem: F,
    configured_template: WorkspaceTemplateId,
    source: impl Into<PathBuf>,
    jail_root: impl Into<PathBuf>,
) -> FirecrackerWorkspaceAdapters<F> {
    FirecrackerWorkspaceBackendFactory::new(filesystem, configured_template, source, jail_root)
        .into_handles()
}

/// Creates separate workspace backend and runtime filesystem handles.
#[must_use]
pub fn new_firecracker_workspace_backends<F>(
    filesystem: F,
    configured_template: WorkspaceTemplateId,
    source: impl Into<PathBuf>,
    jail_root: impl Into<PathBuf>,
) -> FirecrackerWorkspaceAdapters<F> {
    new_firecracker_workspace_adapters(filesystem, configured_template, source, jail_root)
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

        validate_jail_root(&self.jail_root).map_err(|error| {
            BackendError::new(format!("invalid Firecracker workspace jail root: {error}"))
        })?;
        let workspace_id = identity.workspace_id();
        let session_jail_root = self.jail_root.join(workspace_id.to_string()).join("root");
        let destination = session_jail_root
            .join("workspace")
            .join(workspace_id.to_string());
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
                session_jail_root,
                destination,
                runtime_claimed: false,
                runtime_image: WorkspaceImageState::NotCreated,
                runtime_block_device: WorkspaceBlockDeviceState::NeverBound,
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

    fn digest(&mut self, path: &Path) -> Result<Sha256Digest, RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        state.filesystem.digest(path)
    }

    fn bind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = workspace_id_for_block_device(&state, source, jailed_device)?;
        let record = state.prepared.get(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared while binding its block device")
        })?;
        if record.runtime_image != WorkspaceImageState::Created {
            return Err(runtime_workspace_error(
                "block-device binding requires the claimed workspace image",
            ));
        }
        if record.runtime_block_device != WorkspaceBlockDeviceState::NeverBound {
            return Err(runtime_workspace_error(
                "block-device binding was already consumed by this Runtime claim",
            ));
        }
        state.filesystem.bind_block_device(source, jailed_device)?;
        let record = state.prepared.get_mut(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared after binding its block device")
        })?;
        record.runtime_block_device = WorkspaceBlockDeviceState::Bound;
        Ok(())
    }

    fn unbind_block_device(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = workspace_id_for_block_device(&state, source, jailed_device)?;
        let record = state.prepared.get(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared while unbinding its block device")
        })?;
        if record.runtime_block_device != WorkspaceBlockDeviceState::Bound {
            return Err(runtime_workspace_error(
                "block-device unbinding requires the exact live Runtime binding",
            ));
        }
        state
            .filesystem
            .unbind_block_device(source, jailed_device)?;
        let record = state.prepared.get_mut(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared after unbinding its block device")
        })?;
        record.runtime_block_device = WorkspaceBlockDeviceState::Released;
        Ok(())
    }

    fn verify_block_device_binding(
        &mut self,
        source: &Path,
        jailed_device: &Path,
    ) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = workspace_id_for_block_device(&state, source, jailed_device)?;
        let record = state.prepared.get(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared while verifying its block device")
        })?;
        if record.runtime_block_device != WorkspaceBlockDeviceState::Bound {
            return Err(runtime_workspace_error(
                "block-device verification requires the exact live Runtime binding",
            ));
        }
        state
            .filesystem
            .verify_block_device_binding(source, jailed_device)
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

    fn create_workspace_image(
        &mut self,
        workspace: &Path,
        image: &Path,
        size_bytes: u64,
    ) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().map_err(|_| poisoned_runtime_error())?;
        let workspace_id = state
            .prepared
            .values()
            .find(|record| record.destination == workspace)
            .map(|record| record.workspace_id)
            .ok_or_else(|| {
                runtime_workspace_error(
                    "workspace image is not bound to a prepared workspace destination",
                )
            })?;
        let record = state.prepared.get(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared while preparing its block image")
        })?;
        let expected_image = record.destination.with_extension("ext4");
        if !record.runtime_claimed || record.runtime_released || record.orchestrator_released {
            return Err(runtime_workspace_error(
                "workspace image requires a live Runtime claim",
            ));
        }
        if record.runtime_image == WorkspaceImageState::Created {
            return Err(runtime_workspace_error(
                "workspace image was already created for this Runtime claim",
            ));
        }
        if image != expected_image {
            return Err(runtime_workspace_error(
                "workspace image path is not the exact session-owned sibling",
            ));
        }
        state
            .filesystem
            .create_workspace_image(workspace, image, size_bytes)?;
        let record = state.prepared.get_mut(&workspace_id).ok_or_else(|| {
            runtime_workspace_error("workspace record disappeared after creating its block image")
        })?;
        record.runtime_image = WorkspaceImageState::Created;
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
        if record.runtime_block_device == WorkspaceBlockDeviceState::Bound {
            return Err(runtime_workspace_error(
                "remove_workspace cannot release a live block-device binding",
            ));
        }

        // The orchestrator owns physical deletion. Runtime cleanup only records
        // that the Runtime side released its claim, so it cannot delete a path
        // still needed by the orchestrator's rollback state.
        record.runtime_released = true;
        Ok(())
    }
}

fn validate_jail_root(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("jail root must be absolute");
    }
    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => has_normal_component = true,
            Component::ParentDir | Component::CurDir | Component::Prefix(_) => {
                return Err(
                    "jail root must contain only an absolute root and normal path components",
                );
            }
        }
    }
    if !has_normal_component {
        return Err("jail root cannot be the host root");
    }
    Ok(())
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
        images: Vec<(PathBuf, PathBuf, u64)>,
        reads: Vec<PathBuf>,
        digests: Vec<PathBuf>,
        block_device_binds: Vec<(PathBuf, PathBuf)>,
        block_bindings: Vec<(PathBuf, PathBuf)>,
        block_device_unbinds: Vec<(PathBuf, PathBuf)>,
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
            let mut state = self.state.lock().expect("fake state must not be poisoned");
            state.reads.push(path.to_owned());
            if path == Path::new("/jailer/snapshots/memory") {
                return Err(RuntimeError::InvalidConfig(
                    "pinned artifact exceeds 64 MiB test read bound".to_owned(),
                ));
            }
            Ok(b"artifact".to_vec())
        }

        fn digest(&mut self, path: &Path) -> Result<Sha256Digest, RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .digests
                .push(path.to_owned());
            Ok(Sha256Digest::from_bytes([0xa5; 32]))
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

        fn create_workspace_image(
            &mut self,
            workspace: &Path,
            image: &Path,
            size_bytes: u64,
        ) -> Result<(), RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .images
                .push((workspace.to_owned(), image.to_owned(), size_bytes));
            Ok(())
        }

        fn bind_block_device(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .block_device_binds
                .push((source.to_owned(), jailed_device.to_owned()));
            Ok(())
        }

        fn unbind_block_device(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .block_device_unbinds
                .push((source.to_owned(), jailed_device.to_owned()));
            Ok(())
        }

        fn verify_block_device_binding(
            &mut self,
            source: &Path,
            jailed_device: &Path,
        ) -> Result<(), RuntimeError> {
            self.state
                .lock()
                .expect("fake state must not be poisoned")
                .block_bindings
                .push((source.to_owned(), jailed_device.to_owned()));
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
            "/srv/jailer/firecracker",
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
                Path::new(
                    "/srv/jailer/firecracker/abababababababababababababababab/root/workspace/abababababababababababababababab",
                ),
            )
            .expect("runtime must claim the prepared clone");

        let recorded = state.lock().expect("fake state must not be poisoned");
        assert_eq!(recorded.clones.len(), 1);
        assert_eq!(
            recorded.clones[0],
            (
                PathBuf::from("/workspace/source"),
                PathBuf::from(
                    "/srv/jailer/firecracker/abababababababababababababababab/root/workspace/abababababababababababababababab"
                )
            )
        );
        drop(recorded);

        assert!(
            runtime_filesystem
                .clone_workspace(
                    Path::new("/workspace/source"),
                    Path::new(
                        "/srv/jailer/firecracker/abababababababababababababababab/root/workspace/abababababababababababababababab",
                    ),
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
    fn over_64_mib_snapshot_digest_forwards_without_using_bounded_read() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let (_, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let snapshot_memory = Path::new("/jailer/snapshots/memory");

        let digest = runtime_filesystem
            .digest(snapshot_memory)
            .expect("snapshot digest must use the underlying bounded streaming digest");

        assert_eq!(digest, Sha256Digest::from_bytes([0xa5; 32]));
        let state = state.lock().expect("fake state must not be poisoned");
        assert_eq!(state.digests, [snapshot_memory.to_owned()]);
        assert!(
            state.reads.is_empty(),
            "snapshot digest must not fall back to the bounded read path"
        );
    }

    #[test]
    fn workspace_image_is_forwarded_once_only_for_the_claimed_session_sibling() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let (mut backend, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let session = identity(0x11, 0xab);
        let workspace_id = session.workspace_id().to_string();
        let workspace = PathBuf::from(format!(
            "/srv/jailer/firecracker/{workspace_id}/root/workspace/{workspace_id}"
        ));
        let image = workspace.with_extension("ext4");
        backend
            .clone_workspace(&session, &WorkspaceTemplateId::new("template-a"))
            .expect("orchestrator clone must succeed");
        runtime_filesystem
            .clone_workspace(Path::new("/workspace/source"), &workspace)
            .expect("runtime must claim the prepared clone");

        assert!(
            runtime_filesystem
                .create_workspace_image(
                    &workspace,
                    &workspace.with_extension("foreign"),
                    64 * 1024 * 1024
                )
                .is_err()
        );
        runtime_filesystem
            .create_workspace_image(&workspace, &image, 64 * 1024 * 1024)
            .expect("exact image must be forwarded once");
        assert!(
            runtime_filesystem
                .create_workspace_image(&workspace, &image, 64 * 1024 * 1024)
                .is_err()
        );
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .images,
            [(workspace, image, 64 * 1024 * 1024)]
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
    fn rejects_unsafe_jail_roots_before_clone_side_effects() {
        for jail_root in [
            "relative/jailer/firecracker",
            "/",
            "//",
            "/srv/jailer/../escape",
        ] {
            let state = Arc::new(Mutex::new(FakeState::default()));
            let (mut backend, _) = new_firecracker_workspace_adapters(
                FakeFileSystem::new(Arc::clone(&state)),
                WorkspaceTemplateId::new("template-a"),
                "/workspace/source",
                jail_root,
            );

            assert!(
                backend
                    .clone_workspace(
                        &identity(0x11, 0xab),
                        &WorkspaceTemplateId::new("template-a"),
                    )
                    .is_err(),
                "unsafe jail root must fail closed: {jail_root}"
            );
            assert!(
                state
                    .lock()
                    .expect("fake state must not be poisoned")
                    .clones
                    .is_empty()
            );
        }
    }

    // The scenario is one uninterrupted lifecycle: splitting it into helpers would hide the
    // ordering this test exists to pin down.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn block_device_lifecycle_is_session_bound_and_forwarded_exactly() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let (mut backend, mut runtime_filesystem) = adapters(Arc::clone(&state));
        let session = identity(0x11, 0xab);
        let workspace_id = session.workspace_id().to_string();
        let destination = PathBuf::from(format!(
            "/srv/jailer/firecracker/{workspace_id}/root/workspace/{workspace_id}"
        ));
        backend
            .clone_workspace(&session, &WorkspaceTemplateId::new("template-a"))
            .expect("orchestrator clone must succeed");
        runtime_filesystem
            .clone_workspace(Path::new("/workspace/source"), &destination)
            .expect("runtime must claim the exact prepared clone");

        let mapper = PathBuf::from(format!("/dev/mapper/rootfs-verity-{workspace_id}"));
        let jailed_device = PathBuf::from(format!(
            "/srv/jailer/firecracker/{workspace_id}/root/dev/rootfs"
        ));
        let foreign_id = identity(0x22, 0xcd).workspace_id().to_string();
        let foreign_device = PathBuf::from(format!(
            "/srv/jailer/firecracker/{foreign_id}/root/dev/rootfs"
        ));

        assert!(
            runtime_filesystem
                .bind_block_device(&mapper, &foreign_device)
                .is_err()
        );
        assert!(
            runtime_filesystem
                .bind_block_device(
                    Path::new("/dev/mapper/rootfs-verity-foreign"),
                    &jailed_device
                )
                .is_err()
        );
        assert!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .block_device_binds
                .is_empty(),
            "cross-session bind operations must not reach the production filesystem boundary"
        );

        assert!(
            runtime_filesystem
                .verify_block_device_binding(&mapper, &jailed_device)
                .is_err(),
            "verification must not accept an unbound target"
        );
        runtime_filesystem
            .create_workspace_image(
                &destination,
                &destination.with_extension("ext4"),
                64 * 1024 * 1024,
            )
            .expect("exact workspace image must precede the block binding");
        runtime_filesystem
            .bind_block_device(&mapper, &jailed_device)
            .expect("the exact session block device must be delegated once");
        assert!(
            runtime_filesystem
                .bind_block_device(&mapper, &jailed_device)
                .is_err(),
            "one Runtime claim cannot bind its device twice"
        );

        runtime_filesystem
            .verify_block_device_binding(&mapper, &jailed_device)
            .expect("the exact session block binding must be delegated");
        runtime_filesystem
            .unbind_block_device(&mapper, &jailed_device)
            .expect("the exact session block device must be released once");
        assert!(
            runtime_filesystem
                .verify_block_device_binding(&mapper, &jailed_device)
                .is_err(),
            "verification must reject an already released target"
        );
        assert!(
            runtime_filesystem
                .unbind_block_device(&mapper, &jailed_device)
                .is_err(),
            "one Runtime claim cannot release its device twice"
        );
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .block_device_binds,
            [(mapper.clone(), jailed_device.clone())]
        );
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .block_bindings,
            [(mapper.clone(), jailed_device.clone())]
        );
        assert_eq!(
            state
                .lock()
                .expect("fake state must not be poisoned")
                .block_device_unbinds,
            [(mapper, jailed_device)]
        );
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
                Path::new(
                    "/srv/jailer/firecracker/abababababababababababababababab/root/workspace/abababababababababababababababab",
                ),
            )
            .expect("runtime must claim the prepared clone");

        runtime_filesystem
            .remove_workspace(Path::new(
                "/srv/jailer/firecracker/abababababababababababababababab/root/workspace/abababababababababababababababab",
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
