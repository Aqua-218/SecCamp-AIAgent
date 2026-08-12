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

mod protocol;
mod supervisor;

pub use protocol::{MAX_WIRE_REQUEST_BYTES, WireDecodeError, WireEncodeError, WireRequest};
pub use supervisor::{
    AuthorityKernel, CallerBindingError, CallerResolver, CgroupHandle, CleanupFailure, CleanupStep,
    ConnectionIdentity, ControlFdHandle, DispatchResponse, MountHandle, OperationFailure,
    ResourceAcquisition, ResourceError, ResourceFailure, ResourceMutation, RuntimeResources,
    SetupStep, StaticCallerResolver, SubjectLifecycle, Supervisor, SupervisorError, WorkloadHandle,
};
