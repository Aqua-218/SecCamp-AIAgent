//! Capability-enforcing filesystem state and adapter boundaries.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod backing;
pub mod namespace;
pub mod node;
#[cfg(target_os = "linux")]
pub mod read_only;
#[cfg(target_os = "linux")]
mod runtime;

/// Capability-enforcing FUSE adapter.
///
/// This is the preferred public module name. The older `read_only` module is
/// retained while downstream callers migrate from the initial read-only slice.
#[cfg(target_os = "linux")]
pub mod filesystem {
    pub use crate::read_only::*;
}
