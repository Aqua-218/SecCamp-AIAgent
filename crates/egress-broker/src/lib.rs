//! Host-side egress broker for bounded guest requests.
//!
//! The crate deliberately exposes typed operations only. A caller must pass
//! through the length-bounded frame reader, canonical CBOR decoder, session
//! replay guard, session budget, and capability kernel before an adapter can
//! perform an external effect.

#![forbid(unsafe_code)]

pub mod dispatch;
pub mod durable;
pub mod github;
pub mod ip_policy;
pub mod public_fetch;
pub mod server;
pub mod transport;
