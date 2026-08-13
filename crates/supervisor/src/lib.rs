//! Fail-closed subject supervision and transport-bound request dispatch.
//!
//! The crate owns the orchestration boundary between a transport connection,
//! an [`authority_core::kernel::CapabilityKernel`]-compatible authority
//! implementation, and an OS-specific resource implementation. It deliberately
//! keeps operating-system handles opaque so a production adapter can provide
//! namespace, cgroup, mount, and descriptor operations without changing the
//! lifecycle state machine.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

#[cfg(target_os = "linux")]
mod capfs_resources;
#[cfg(target_os = "linux")]
mod control_socket;
#[cfg(target_os = "linux")]
mod linux_host;
mod protocol;
mod supervisor;

#[cfg(target_os = "linux")]
pub use linux_host::{
    LinuxHostConfig, LinuxHostError, LinuxHostResources, WORKLOAD_CONTROL_SOCKET_ENV,
    WORKLOAD_MOUNTPOINT_ENV, WORKLOAD_SUBJECT_ENV,
};

#[cfg(target_os = "linux")]
pub use control_socket::{
    AcceptedControlConnection, ConnectionRebindError, ControlSocketError, CredentialResolveError,
    SubjectControlListener, SubjectCredential, SubjectCredentialResolver,
};

#[cfg(target_os = "linux")]
pub use capfs_resources::{
    CapfsBuildError, CapfsHostResources, CapfsMountPlan, CapfsPlanError, CapfsResourceError,
    CapfsRuntimeConfig, CapfsRuntimeManager, CapfsRuntimeResources, CapfsSupervisor,
    CapfsSupervisorError, CapfsUnmountStrategy,
};

pub use protocol::{
    MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES, RefusalCode, WireDecodeError, WireEncodeError,
    WireRequest, WireResponse,
};
pub use supervisor::{
    AuthorityKernel, CallerBindingError, CallerResolver, CgroupHandle, CleanupFailure, CleanupStep,
    ConnectionIdentity, ControlFdHandle, DispatchResponse, MountHandle, OperationFailure,
    ResourceAcquisition, ResourceError, ResourceFailure, ResourceMutation, RuntimeResources,
    SetupStep, StaticCallerResolver, SubjectLifecycle, Supervisor, SupervisorError, WorkloadHandle,
};
