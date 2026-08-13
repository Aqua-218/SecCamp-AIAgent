//! Fixed guest workload that verifies the host Broker's `AF_VSOCK` boundary.
//!
//! This is a test artifact, not a general Broker client. It sends one closed,
//! deliberately unauthorized request to the host-selected port and requires
//! the canonical detail-free rejection response. No host, credential, URL,
//! command, or payload is accepted from the host.

#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    env,
    fs::File,
    io::{Read, Write},
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
};

use authority_core::http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest};
use egress_protocol::{
    cbor::CanonicalBrokerRequest,
    frame::{CONTROL_FRAME_LENGTH_PREFIX_BYTES, ControlFrame, ValidatedFrameLength},
    operation::BrokerOperation,
    response::{BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse},
    session::{BrokerRequestId, BrokerSessionId},
};
use socket2::{Domain, SockAddr, Socket, Type};

const VMADDR_CID_HOST: u32 = 2;
const RESPONSE_TIMEOUT_SECONDS: u64 = 5;
const PROBE_SESSION: BrokerSessionId = BrokerSessionId::new([7; 16]);
const PROBE_REQUEST: BrokerRequestId = BrokerRequestId::new([8; 16]);
const EGRESS_BROKER_FD_ENV: &str = "EGRESS_BROKER_FD";
const EGRESS_BROKER_SESSION_ENV: &str = "EGRESS_BROKER_SESSION_ID";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport {
    Inherited,
    DirectVsock(u32),
}

fn main() -> std::process::ExitCode {
    let mut stage = 1;
    match run(&mut stage) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("guest-broker-probe: {error}");
            std::process::ExitCode::from(stage)
        }
    }
}

fn run(stage: &mut u8) -> Result<(), String> {
    *stage = 2;
    let transport = parse_transport(env::args().skip(1))?;
    *stage = 3;
    let session = match transport {
        Transport::Inherited => broker_session_from_environment()?,
        Transport::DirectVsock(_) => PROBE_SESSION,
    };
    *stage = 4;
    let request = CanonicalBrokerRequest::new(
        session,
        0,
        PROBE_REQUEST,
        BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("broker-probe.invalid")
                .map_err(|error| format!("constructing fixed probe host: {error}"))?,
            CanonicalUrlPath::new("/")
                .map_err(|error| format!("constructing fixed probe path: {error}"))?,
            1_024,
        )),
    );
    let frame = ControlFrame::new(
        request
            .encode()
            .map_err(|error| format!("encoding fixed probe request: {error}"))?,
    )
    .map_err(|error| format!("framing fixed probe request: {error}"))?;

    *stage = 6;
    let mut channel = File::from(open_transport(transport)?);
    *stage = 7;
    channel
        .write_all(&frame.encode())
        .map_err(|error| format!("writing fixed probe frame: {error}"))?;

    *stage = 8;
    let response = read_response(&mut channel)?;
    *stage = 9;
    if response.request() != PROBE_REQUEST {
        return Err("host response did not bind the fixed probe request".to_owned());
    }
    if response.outcome() != &BrokerWireOutcome::Rejected(BrokerWireRejection::NotAuthorized) {
        return Err(
            "host did not return the expected detail-free authorization rejection".to_owned(),
        );
    }
    Ok(())
}

fn parse_transport(mut arguments: impl Iterator<Item = String>) -> Result<Transport, String> {
    let Some(flag) = arguments.next() else {
        return Ok(Transport::Inherited);
    };
    if flag != "--port" {
        return Err(usage());
    }
    let port = arguments
        .next()
        .ok_or_else(usage)?
        .parse::<u32>()
        .map_err(|_| usage())?;
    if port == 0 || port == u32::MAX || arguments.next().is_some() {
        return Err(usage());
    }
    Ok(Transport::DirectVsock(port))
}

fn open_transport(transport: Transport) -> Result<OwnedFd, String> {
    match transport {
        Transport::DirectVsock(port) => {
            let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)
                .map_err(|error| format!("creating AF_VSOCK stream: {error}"))?;
            socket
                .connect(&SockAddr::vsock(VMADDR_CID_HOST, port))
                .map_err(|error| format!("connecting to host AF_VSOCK port {port}: {error}"))?;
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(
                    RESPONSE_TIMEOUT_SECONDS,
                )))
                .map_err(|error| format!("setting direct Broker read timeout: {error}"))?;
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(
                    RESPONSE_TIMEOUT_SECONDS,
                )))
                .map_err(|error| format!("setting direct Broker write timeout: {error}"))?;
            // SAFETY: `into_raw_fd` transfers this socket's unique descriptor ownership.
            Ok(unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) })
        }
        Transport::Inherited => {
            let descriptor = env::var(EGRESS_BROKER_FD_ENV)
                .map_err(|_| format!("required {EGRESS_BROKER_FD_ENV} is absent"))?
                .parse::<i32>()
                .map_err(|_| format!("{EGRESS_BROKER_FD_ENV} must be a decimal descriptor"))?;
            if descriptor < 3 {
                return Err(format!(
                    "{EGRESS_BROKER_FD_ENV} must name a nonstandard descriptor"
                ));
            }
            // SAFETY: `workload-isolation-launcher` owns this environment value, preserves only
            // its validated connected AF_VSOCK stream across isolation, and closes every other
            // nonstandard descriptor. This process receives its own descriptor table entry, so
            // taking ownership closes only the workload's endpoint.
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            Ok(descriptor)
        }
    }
}

fn broker_session_from_environment() -> Result<BrokerSessionId, String> {
    let identity = env::var(EGRESS_BROKER_SESSION_ENV)
        .map_err(|_| format!("required {EGRESS_BROKER_SESSION_ENV} is absent"))?;
    if identity.len() != 32
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{EGRESS_BROKER_SESSION_ENV} must be 32 lower hexadecimal bytes"
        ));
    }
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&identity[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{EGRESS_BROKER_SESSION_ENV} contains a non-hex byte"))?;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(format!(
            "{EGRESS_BROKER_SESSION_ENV} must not be all zeroes"
        ));
    }
    Ok(BrokerSessionId::new(bytes))
}

fn read_response(channel: &mut File) -> Result<CanonicalBrokerResponse, String> {
    let mut prefix = [0_u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES];
    channel
        .read_exact(&mut prefix)
        .map_err(|error| format!("reading response frame prefix: {error}"))?;
    let length = ValidatedFrameLength::from_network_prefix(prefix)
        .map_err(|error| format!("validating response frame length: {error}"))?
        .as_usize();
    let mut payload = vec![0_u8; length];
    channel
        .read_exact(&mut payload)
        .map_err(|error| format!("reading response frame payload: {error}"))?;
    CanonicalBrokerResponse::decode(&payload)
        .map_err(|error| format!("decoding canonical host response: {error}"))
}

fn usage() -> String {
    format!(
        "usage: guest-broker-probe [--port <1..{}>] (without --port requires the inherited Broker channel)",
        u32::MAX - 1
    )
}

#[cfg(test)]
mod tests {
    use super::{Transport, parse_transport};

    #[test]
    fn accepts_one_explicit_non_wildcard_port() {
        assert_eq!(
            parse_transport(["--port".to_owned(), "18081".to_owned()].into_iter()),
            Ok(Transport::DirectVsock(18081))
        );
    }

    #[test]
    fn uses_the_inherited_broker_channel_without_arguments() {
        assert_eq!(
            parse_transport(std::iter::empty()),
            Ok(Transport::Inherited)
        );
    }

    #[test]
    fn rejects_missing_ambiguous_or_extra_arguments() {
        for arguments in [
            vec!["--port".to_owned(), "0".to_owned()],
            vec!["--port".to_owned(), u32::MAX.to_string()],
            vec!["--port".to_owned(), "18081".to_owned(), "extra".to_owned()],
            vec!["--host".to_owned(), "18081".to_owned()],
        ] {
            assert!(parse_transport(arguments.into_iter()).is_err());
        }
    }
}
