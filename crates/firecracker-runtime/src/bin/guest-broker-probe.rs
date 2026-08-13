//! Fixed guest workload that verifies the host Broker's `AF_VSOCK` boundary.
//!
//! This is a test artifact, not a general Broker client. It sends one closed,
//! deliberately unauthorized request to the host-selected port and requires
//! the canonical detail-free rejection response. No host, credential, URL,
//! command, or payload is accepted from the host.

#![forbid(unsafe_code)]

use std::{
    env,
    io::{Read, Write},
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
    let port = parse_port(env::args().skip(1))?;
    let request = CanonicalBrokerRequest::new(
        PROBE_SESSION,
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

    let mut socket = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|error| format!("creating AF_VSOCK stream: {error}"))?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(
            RESPONSE_TIMEOUT_SECONDS,
        )))
        .map_err(|error| format!("setting read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(
            RESPONSE_TIMEOUT_SECONDS,
        )))
        .map_err(|error| format!("setting write timeout: {error}"))?;
    socket
        .connect(&SockAddr::vsock(VMADDR_CID_HOST, port))
        .map_err(|error| format!("connecting to host AF_VSOCK port {port}: {error}"))?;
    socket
        .write_all(&frame.encode())
        .map_err(|error| format!("writing fixed probe frame: {error}"))?;

    let response = read_response(&mut socket)?;
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

fn parse_port(mut arguments: impl Iterator<Item = String>) -> Result<u32, String> {
    if arguments.next().as_deref() != Some("--port") {
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
    Ok(port)
}

fn read_response(socket: &mut Socket) -> Result<CanonicalBrokerResponse, String> {
    let mut prefix = [0_u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES];
    socket
        .read_exact(&mut prefix)
        .map_err(|error| format!("reading response frame prefix: {error}"))?;
    let length = ValidatedFrameLength::from_network_prefix(prefix)
        .map_err(|error| format!("validating response frame length: {error}"))?
        .as_usize();
    let mut payload = vec![0_u8; length];
    socket
        .read_exact(&mut payload)
        .map_err(|error| format!("reading response frame payload: {error}"))?;
    CanonicalBrokerResponse::decode(&payload)
        .map_err(|error| format!("decoding canonical host response: {error}"))
}

fn usage() -> String {
    format!("usage: guest-broker-probe --port <1..{}>", u32::MAX - 1)
}

#[cfg(test)]
mod tests {
    use super::parse_port;

    #[test]
    fn accepts_one_explicit_non_wildcard_port() {
        assert_eq!(
            parse_port(["--port".to_owned(), "18081".to_owned()].into_iter()),
            Ok(18081)
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
            assert!(parse_port(arguments.into_iter()).is_err());
        }
    }
}
