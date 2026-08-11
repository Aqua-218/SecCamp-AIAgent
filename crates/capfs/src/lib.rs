//! Capability-enforcing filesystem state and adapter boundaries.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod backing;
pub mod namespace;
