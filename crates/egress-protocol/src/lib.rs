//! Typed, replay-safe control envelopes for the Host Egress Broker.
//!
//! This crate deliberately contains no socket, HTTP, credential, or
//! provider-client implementation. It defines the bounded session envelope,
//! canonical-CBOR request schema, and typed operation boundary that a vsock
//! transport must validate before dispatching a request.

#![forbid(unsafe_code)]

pub mod budget;
pub mod cbor;
pub mod client;
pub mod frame;
pub mod operation;
pub mod response;
pub mod session;
