//! Typed, replay-safe control envelopes for the Host Egress Broker.
//!
//! This crate deliberately contains no socket, CBOR, HTTP, credential, or
//! provider-client implementation. It defines the bounded session envelope
//! that a vsock transport must validate before dispatching a typed request.

#![forbid(unsafe_code)]

pub mod budget;
pub mod frame;
pub mod session;
