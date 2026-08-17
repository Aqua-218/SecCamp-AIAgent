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
    io::{self, Write},
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
};

use authority_core::http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest};
use egress_protocol::{
    client::GuestBrokerClient,
    operation::BrokerOperation,
    response::{BrokerWireOutcome, BrokerWireRejection},
    session::{BrokerRequestId, BrokerSessionId},
};
use socket2::{Domain, SockAddr, Socket, Type};

const VMADDR_CID_HOST: u32 = 2;
const RESPONSE_TIMEOUT_SECONDS: u64 = 5;
const PROBE_SESSION: BrokerSessionId = BrokerSessionId::new([7; 16]);
const PROBE_REQUEST: BrokerRequestId = BrokerRequestId::new([8; 16]);
const EGRESS_BROKER_FD_ENV: &str = "EGRESS_BROKER_FD";
const EGRESS_BROKER_SESSION_ENV: &str = "EGRESS_BROKER_SESSION_ID";
const SUPERVISOR_READINESS_ENV: &str = "GUEST_SUPERVISOR_READINESS";
const SUPERVISOR_READINESS_REQUIRED: &str = "1";
const SUPERVISOR_READY_MARKER: &[u8; 25] = b"guest-supervisor-ready/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport {
    Inherited,
    DirectVsock(u32),
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("guest-broker-probe: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    signal_supervisor_readiness(
        env::var(SUPERVISOR_READINESS_ENV).ok().as_deref(),
        &mut io::stdout().lock(),
    )?;
    let transport = parse_transport(env::args().skip(1))?;
    let session = match transport {
        Transport::Inherited => broker_session_from_environment()?,
        Transport::DirectVsock(_) => PROBE_SESSION,
    };
    let operation = BrokerOperation::PublicFetch(HttpFetchRequest::new(
        HttpFetchMethod::Get,
        CanonicalHost::new("broker-probe.invalid")
            .map_err(|error| format!("constructing fixed probe host: {error}"))?,
        CanonicalUrlPath::new("/")
            .map_err(|error| format!("constructing fixed probe path: {error}"))?,
        1_024,
    ));
    let channel = File::from(open_transport(transport)?);
    let mut client = GuestBrokerClient::new(channel, session);
    let response = client
        .execute_with_id(PROBE_REQUEST, operation)
        .map_err(|error| format!("executing fixed probe request: {error}"))?;
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

fn signal_supervisor_readiness(
    requirement: Option<&str>,
    output: &mut impl Write,
) -> Result<(), String> {
    match requirement {
        None => Ok(()),
        Some(SUPERVISOR_READINESS_REQUIRED) => output
            .write_all(SUPERVISOR_READY_MARKER)
            .and_then(|()| output.flush())
            .map_err(|error| format!("signalling guest supervisor readiness: {error}")),
        Some(_) => Err(format!(
            "{SUPERVISOR_READINESS_ENV} must be exactly {SUPERVISOR_READINESS_REQUIRED} when present"
        )),
    }
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

fn usage() -> String {
    format!(
        "usage: guest-broker-probe [--port <1..{}>] (without --port requires the inherited Broker channel)",
        u32::MAX - 1
    )
}

#[cfg(test)]
mod tests {
    use super::{SUPERVISOR_READY_MARKER, Transport, parse_transport, signal_supervisor_readiness};

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

    #[test]
    fn signals_the_exact_guest_supervisor_readiness_marker_when_required() {
        let mut output = Vec::new();
        signal_supervisor_readiness(Some("1"), &mut output)
            .expect("the exact readiness requirement must be accepted");
        assert_eq!(output, SUPERVISOR_READY_MARKER);
    }

    #[test]
    fn leaves_normal_probe_output_untouched_without_the_readiness_contract() {
        let mut output = Vec::new();
        signal_supervisor_readiness(None, &mut output)
            .expect("an absent readiness requirement must remain compatible");
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_ambiguous_readiness_requirements_without_writing() {
        for requirement in ["", "true", "01", "2"] {
            let mut output = Vec::new();
            assert!(signal_supervisor_readiness(Some(requirement), &mut output).is_err());
            assert!(output.is_empty());
        }
    }
}
