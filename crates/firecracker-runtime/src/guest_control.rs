//! Canonical, replay-resistant control messages used between the host runtime and guest.
//!
//! The protocol is deliberately small: a request carries the per-restoration challenge and all
//! regenerated identities; the guest must return the byte-for-byte canonical acknowledgement.
//! Strict parsing prevents a different JSON spelling from becoming a second accepted protocol.

use std::{
    fmt::{Display, Formatter},
    io::{self, Read, Write},
};

use crate::{IdentityBundle, IdentityId};

/// Guest operation selected by the HTTP path exposed over Firecracker vsock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestControlAction {
    /// Store the identities while retaining the workload gate.
    InjectIdentity,
    /// Release the workload gate after an identity injection.
    StartWorkload,
}

impl GuestControlAction {
    /// HTTP path used by the host runtime.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::InjectIdentity => "/actions/inject-identity",
            Self::StartWorkload => "/actions/start-workload",
        }
    }

    /// Parses an accepted guest-control HTTP path.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        match path {
            "/actions/inject-identity" => Some(Self::InjectIdentity),
            "/actions/start-workload" => Some(Self::StartWorkload),
            _ => None,
        }
    }

    const fn acknowledgement(self) -> &'static str {
        match self {
            Self::InjectIdentity => "identity-injected",
            Self::StartWorkload => "workload-started",
        }
    }
}

/// An identity-bound request received by the guest control endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestControlRequest {
    challenge: IdentityId,
    identities: IdentityBundle,
}

impl GuestControlRequest {
    /// Validates a request assembled by trusted host code.
    ///
    /// The challenge must be independent of every identity. This makes a captured request from a
    /// previous restored VM unusable after its identity bundle changes.
    ///
    /// # Errors
    ///
    /// Returns [`GuestControlError::ChallengeReused`] when the challenge is part of the bundle.
    pub fn new(
        challenge: IdentityId,
        identities: IdentityBundle,
    ) -> Result<Self, GuestControlError> {
        if identities_match(challenge, &identities) {
            return Err(GuestControlError::ChallengeReused);
        }
        Ok(Self {
            challenge,
            identities,
        })
    }

    /// Parses only the single canonical request spelling emitted by [`Self::canonical_body`].
    ///
    /// # Errors
    ///
    /// Returns a parse, identity-validation, or canonical-encoding error for any other body.
    pub fn parse_canonical(body: &str) -> Result<Self, GuestControlError> {
        let fields = parse_fields(body)?;
        let request = Self::new(fields.challenge, fields.into_bundle()?)?;
        if body != request.canonical_body() {
            return Err(GuestControlError::NonCanonicalBody);
        }
        Ok(request)
    }

    /// Returns the challenge for session binding.
    #[must_use]
    pub const fn challenge(&self) -> IdentityId {
        self.challenge
    }

    /// Returns the regenerated identity bundle.
    #[must_use]
    pub const fn identities(&self) -> &IdentityBundle {
        &self.identities
    }

    /// Stable JSON encoding sent over the vsock endpoint.
    #[must_use]
    pub fn canonical_body(&self) -> String {
        encode_request(self.challenge, &self.identities)
    }

    /// Stable acknowledgement encoding expected from the guest.
    #[must_use]
    pub fn canonical_acknowledgement(&self, action: GuestControlAction) -> String {
        encode_acknowledgement(action.acknowledgement(), self.challenge, &self.identities)
    }
}

/// Guest-side lifecycle state for the identity-gated workload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum GuestControlState {
    /// The guest has not accepted an identity bundle.
    #[default]
    AwaitingIdentity,
    /// The guest has accepted the bundle but workload execution stays closed.
    IdentityInjected(GuestControlRequest),
    /// The guest released workload execution for the accepted bundle.
    WorkloadStarted(GuestControlRequest),
}

/// Maximum accepted HTTP header size on the guest-control endpoint.
pub const MAX_GUEST_CONTROL_HEADER_BYTES: usize = 4 * 1024;
/// Maximum accepted JSON body size on the guest-control endpoint.
pub const MAX_GUEST_CONTROL_BODY_BYTES: usize = 1024;

/// Result of a successfully applied guest-control HTTP operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestControlOutcome {
    /// The guest stored the independent identity bundle.
    IdentityInjected,
    /// The guest may release its configured workload gate.
    WorkloadStarted,
}

impl From<GuestControlAction> for GuestControlOutcome {
    fn from(action: GuestControlAction) -> Self {
        match action {
            GuestControlAction::InjectIdentity => Self::IdentityInjected,
            GuestControlAction::StartWorkload => Self::WorkloadStarted,
        }
    }
}

/// Bounded HTTP response returned by [`GuestControlServer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestControlHttpResponse {
    status: u16,
    body: String,
    outcome: Option<GuestControlOutcome>,
}

impl GuestControlHttpResponse {
    /// Returns the HTTP status selected for the request.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the canonical acknowledgement body for a successful request.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns the state transition that was committed by this request.
    #[must_use]
    pub const fn outcome(&self) -> Option<GuestControlOutcome> {
        self.outcome
    }
}

/// One non-concurrent guest-control HTTP endpoint.
///
/// An endpoint is intentionally per guest VM. It does not expose a mutable subject or a workload
/// path in the wire protocol: the image's init owns both, and only acts on
/// [`GuestControlOutcome::WorkloadStarted`] after a valid identity-bound transition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GuestControlServer {
    state: GuestControlState,
}

impl GuestControlServer {
    /// Creates a closed guest-control endpoint awaiting an identity bundle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: GuestControlState::AwaitingIdentity,
        }
    }

    /// Returns the endpoint's current workload-gate state.
    #[must_use]
    pub const fn state(&self) -> &GuestControlState {
        &self.state
    }

    /// Handles a bounded HTTP request after its framing has been parsed.
    #[must_use]
    pub fn handle(&mut self, method: &str, path: &str, body: &[u8]) -> GuestControlHttpResponse {
        if method != "PUT" {
            return response(405, String::new(), None);
        }
        let Some(action) = GuestControlAction::from_path(path) else {
            return response(404, String::new(), None);
        };
        let Ok(body) = std::str::from_utf8(body) else {
            return response(400, String::new(), None);
        };
        let Ok(request) = GuestControlRequest::parse_canonical(body) else {
            return response(400, String::new(), None);
        };
        match self.state.apply(action, request) {
            Ok(acknowledgement) => response(200, acknowledgement, Some(action.into())),
            Err(GuestControlError::IdentityNotInjected | GuestControlError::IdentityMismatch) => {
                response(409, String::new(), None)
            }
            Err(
                GuestControlError::MalformedBody
                | GuestControlError::NonCanonicalBody
                | GuestControlError::InvalidIdentity(_)
                | GuestControlError::ChallengeReused,
            ) => response(400, String::new(), None),
        }
    }

    /// Reads, applies, and writes exactly one bounded HTTP/1.1 request.
    ///
    /// # Errors
    ///
    /// Returns [`GuestControlIoError`] for a transport error or a malformed HTTP envelope. A
    /// decoded but rejected control request instead receives an ordinary fail-closed response.
    pub fn serve_once<S: Read + Write>(
        &mut self,
        stream: &mut S,
    ) -> Result<GuestControlHttpResponse, GuestControlIoError> {
        self.serve_once_with(stream, || Ok(()))
    }

    /// Reads, applies, and writes one request, starting the fixed workload before its success ACK.
    ///
    /// The callback is invoked only for a committed `start-workload` transition. It may be called
    /// again after the host loses an acknowledgement, so callers must make it idempotent for this
    /// guest image. A callback failure is reported as `503` and never acknowledges workload start.
    ///
    /// # Errors
    ///
    /// Returns [`GuestControlIoError`] for a transport or malformed HTTP envelope. A workload
    /// callback failure is returned to the peer as `503 Service Unavailable` instead.
    pub fn serve_once_with<S: Read + Write, F>(
        &mut self,
        stream: &mut S,
        start_workload: F,
    ) -> Result<GuestControlHttpResponse, GuestControlIoError>
    where
        F: FnOnce() -> io::Result<()>,
    {
        let request = read_http_request(stream)?;
        let mut result = self.handle(&request.method, &request.path, &request.body);
        if result.outcome == Some(GuestControlOutcome::WorkloadStarted) && start_workload().is_err()
        {
            result = response(503, String::new(), None);
        }
        write_http_response(stream, &result)?;
        Ok(result)
    }
}

fn response(
    status: u16,
    body: String,
    outcome: Option<GuestControlOutcome>,
) -> GuestControlHttpResponse {
    GuestControlHttpResponse {
        status,
        body,
        outcome,
    }
}

struct GuestControlHttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request<S: Read>(
    stream: &mut S,
) -> Result<GuestControlHttpRequest, GuestControlIoError> {
    let mut header = Vec::with_capacity(512);
    loop {
        if header.len() == MAX_GUEST_CONTROL_HEADER_BYTES {
            return Err(GuestControlIoError::HeaderTooLarge);
        }
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(GuestControlIoError::Io)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = std::str::from_utf8(&header).map_err(|_| GuestControlIoError::MalformedHttp)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(GuestControlIoError::MalformedHttp)?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts
        .next()
        .ok_or(GuestControlIoError::MalformedHttp)?;
    let path = request_parts
        .next()
        .ok_or(GuestControlIoError::MalformedHttp)?;
    if request_parts.next() != Some("HTTP/1.1") || request_parts.next().is_some() {
        return Err(GuestControlIoError::MalformedHttp);
    }
    if method.is_empty() || path.is_empty() || !path.starts_with('/') {
        return Err(GuestControlIoError::MalformedHttp);
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(GuestControlIoError::MalformedHttp)?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(GuestControlIoError::MalformedHttp);
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(GuestControlIoError::MalformedHttp);
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| GuestControlIoError::MalformedHttp)?;
            if length > MAX_GUEST_CONTROL_BODY_BYTES {
                return Err(GuestControlIoError::BodyTooLarge);
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(GuestControlIoError::MalformedHttp);
        }
    }
    let length = content_length.ok_or(GuestControlIoError::MalformedHttp)?;
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(GuestControlIoError::Io)?;
    Ok(GuestControlHttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        body,
    })
}

fn write_http_response<S: Write>(
    stream: &mut S,
    response: &GuestControlHttpResponse,
) -> Result<(), GuestControlIoError> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => return Err(GuestControlIoError::MalformedHttp),
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(response.body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(GuestControlIoError::Io)
}

/// I/O or HTTP framing failure at the guest-control endpoint.
#[derive(Debug)]
pub enum GuestControlIoError {
    /// The transport could not make progress.
    Io(io::Error),
    /// The endpoint refused an oversized request header before allocating it.
    HeaderTooLarge,
    /// The endpoint refused an oversized body before allocating it.
    BodyTooLarge,
    /// The request was not the one-request HTTP/1.1 envelope this endpoint accepts.
    MalformedHttp,
}

impl Display for GuestControlIoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "guest-control I/O failed: {error}"),
            Self::HeaderTooLarge => {
                write!(formatter, "guest-control HTTP header exceeds its bound")
            }
            Self::BodyTooLarge => write!(formatter, "guest-control HTTP body exceeds its bound"),
            Self::MalformedHttp => write!(formatter, "guest-control HTTP request is malformed"),
        }
    }
}

impl std::error::Error for GuestControlIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::HeaderTooLarge | Self::BodyTooLarge | Self::MalformedHttp => None,
        }
    }
}

impl GuestControlState {
    /// Applies a parsed request, enforcing inject-before-start and safe retries.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-order operation or a request that differs from the
    /// identity bundle already accepted by this guest.
    pub fn apply(
        &mut self,
        action: GuestControlAction,
        request: GuestControlRequest,
    ) -> Result<String, GuestControlError> {
        match action {
            GuestControlAction::InjectIdentity => match self {
                Self::AwaitingIdentity => {
                    let acknowledgement = request.canonical_acknowledgement(action);
                    *self = Self::IdentityInjected(request);
                    Ok(acknowledgement)
                }
                Self::IdentityInjected(existing) | Self::WorkloadStarted(existing)
                    if existing == &request =>
                {
                    Ok(request.canonical_acknowledgement(action))
                }
                Self::IdentityInjected(_) | Self::WorkloadStarted(_) => {
                    Err(GuestControlError::IdentityMismatch)
                }
            },
            GuestControlAction::StartWorkload => match self {
                Self::AwaitingIdentity => Err(GuestControlError::IdentityNotInjected),
                Self::IdentityInjected(existing) if existing == &request => {
                    let acknowledgement = request.canonical_acknowledgement(action);
                    *self = Self::WorkloadStarted(request);
                    Ok(acknowledgement)
                }
                Self::WorkloadStarted(existing) if existing == &request => {
                    Ok(request.canonical_acknowledgement(action))
                }
                Self::IdentityInjected(_) | Self::WorkloadStarted(_) => {
                    Err(GuestControlError::IdentityMismatch)
                }
            },
        }
    }
}

/// Invalid input or an unsafe guest-control transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestControlError {
    /// Body does not have the required fixed JSON shape.
    MalformedBody,
    /// Body parses but does not exactly use the one allowed encoding.
    NonCanonicalBody,
    /// One field was not a valid identity.
    InvalidIdentity(String),
    /// Challenge duplicated an identity from its bundle.
    ChallengeReused,
    /// Workload execution was requested before identity injection.
    IdentityNotInjected,
    /// A request tried to replace the injected identity bundle.
    IdentityMismatch,
}

impl Display for GuestControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedBody => write!(formatter, "malformed guest-control body"),
            Self::NonCanonicalBody => write!(formatter, "guest-control body is not canonical"),
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid guest-control identity: {message}")
            }
            Self::ChallengeReused => {
                write!(formatter, "guest-control challenge duplicates an identity")
            }
            Self::IdentityNotInjected => {
                write!(formatter, "workload requested before identity injection")
            }
            Self::IdentityMismatch => {
                write!(
                    formatter,
                    "guest-control identities do not match the accepted bundle"
                )
            }
        }
    }
}

impl std::error::Error for GuestControlError {}

struct Fields {
    challenge: IdentityId,
    vm_id: IdentityId,
    session_id: IdentityId,
    request_id: IdentityId,
    subject_id: IdentityId,
    capability_id: IdentityId,
}

impl Fields {
    fn into_bundle(self) -> Result<IdentityBundle, GuestControlError> {
        IdentityBundle::new(
            self.vm_id,
            self.session_id,
            self.request_id,
            self.subject_id,
            self.capability_id,
        )
        .map_err(|error| GuestControlError::InvalidIdentity(error.to_string()))
    }
}

fn parse_fields(body: &str) -> Result<Fields, GuestControlError> {
    let rest = body
        .strip_prefix("{\"challenge\":\"")
        .ok_or(GuestControlError::MalformedBody)?;
    let (challenge, rest) = take_identity(rest, "\",\"vm_id\":\"")?;
    let (vm_id, rest) = take_identity(rest, "\",\"session_id\":\"")?;
    let (session_id, rest) = take_identity(rest, "\",\"request_id\":\"")?;
    let (request_id, rest) = take_identity(rest, "\",\"subject_id\":\"")?;
    let (subject_id, rest) = take_identity(rest, "\",\"capability_id\":\"")?;
    let (capability_id, rest) = take_identity(rest, "\"}")?;
    if !rest.is_empty() {
        return Err(GuestControlError::MalformedBody);
    }
    Ok(Fields {
        challenge,
        vm_id,
        session_id,
        request_id,
        subject_id,
        capability_id,
    })
}

fn take_identity<'a>(
    value: &'a str,
    suffix: &str,
) -> Result<(IdentityId, &'a str), GuestControlError> {
    let Some(hex) = value.get(..32) else {
        return Err(GuestControlError::MalformedBody);
    };
    let rest = value.get(32..).ok_or(GuestControlError::MalformedBody)?;
    let rest = rest
        .strip_prefix(suffix)
        .ok_or(GuestControlError::MalformedBody)?;
    let identity = IdentityId::from_hex(hex)
        .map_err(|error| GuestControlError::InvalidIdentity(error.to_string()))?;
    Ok((identity, rest))
}

fn identities_match(challenge: IdentityId, identities: &IdentityBundle) -> bool {
    [
        identities.vm_id,
        identities.session_id,
        identities.request_id,
        identities.subject_id,
        identities.capability_id,
    ]
    .contains(&challenge)
}

fn encode_request(challenge: IdentityId, identities: &IdentityBundle) -> String {
    format!(
        "{{\"challenge\":\"{}\",\"vm_id\":\"{}\",\"session_id\":\"{}\",\"request_id\":\"{}\",\"subject_id\":\"{}\",\"capability_id\":\"{}\"}}",
        challenge.to_hex(),
        identities.vm_id.to_hex(),
        identities.session_id.to_hex(),
        identities.request_id.to_hex(),
        identities.subject_id.to_hex(),
        identities.capability_id.to_hex(),
    )
}

fn encode_acknowledgement(
    acknowledgement: &str,
    challenge: IdentityId,
    identities: &IdentityBundle,
) -> String {
    format!(
        "{{\"ack\":\"{}\",\"challenge\":\"{}\",\"vm_id\":\"{}\",\"session_id\":\"{}\",\"request_id\":\"{}\",\"subject_id\":\"{}\",\"capability_id\":\"{}\"}}",
        acknowledgement,
        challenge.to_hex(),
        identities.vm_id.to_hex(),
        identities.session_id.to_hex(),
        identities.request_id.to_hex(),
        identities.subject_id.to_hex(),
        identities.capability_id.to_hex(),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn request(seed: u8) -> GuestControlRequest {
        let identity = |offset| {
            let mut value = [0_u8; 16];
            value[15] = seed.wrapping_add(offset);
            IdentityId(value)
        };
        GuestControlRequest::new(
            identity(1),
            IdentityBundle::new(
                identity(2),
                identity(3),
                identity(4),
                identity(5),
                identity(6),
            )
            .expect("distinct test identities"),
        )
        .expect("independent test challenge")
    }

    #[test]
    fn canonical_body_round_trips_and_rejects_noncanonical_spelling() {
        let request = request(170);
        let body = request.canonical_body();
        assert_eq!(
            GuestControlRequest::parse_canonical(&body),
            Ok(request.clone())
        );
        let challenge = request.challenge().to_hex();
        let uppercase = body.replacen(&challenge, &challenge.to_uppercase(), 1);
        assert_eq!(
            GuestControlRequest::parse_canonical(&uppercase),
            Err(GuestControlError::NonCanonicalBody)
        );
        assert_eq!(
            GuestControlRequest::parse_canonical("{}"),
            Err(GuestControlError::MalformedBody)
        );
    }

    #[test]
    fn request_rejects_challenge_reused_as_identity() {
        let request = request(30);
        assert_eq!(
            GuestControlRequest::new(request.identities().vm_id, request.identities().clone()),
            Err(GuestControlError::ChallengeReused)
        );
    }

    #[test]
    fn workload_gate_enforces_order_and_supports_exact_retries() {
        let request = request(40);
        let mut state = GuestControlState::default();
        assert_eq!(
            state.apply(GuestControlAction::StartWorkload, request.clone()),
            Err(GuestControlError::IdentityNotInjected)
        );
        assert_eq!(
            state.apply(GuestControlAction::InjectIdentity, request.clone()),
            Ok(request.canonical_acknowledgement(GuestControlAction::InjectIdentity))
        );
        assert_eq!(
            state.apply(GuestControlAction::InjectIdentity, request.clone()),
            Ok(request.canonical_acknowledgement(GuestControlAction::InjectIdentity))
        );
        assert_eq!(
            state.apply(GuestControlAction::StartWorkload, request.clone()),
            Ok(request.canonical_acknowledgement(GuestControlAction::StartWorkload))
        );
    }

    #[test]
    fn replay_from_another_restoration_is_rejected() {
        let first = request(50);
        let second = request(60);
        let mut state = GuestControlState::default();
        state
            .apply(GuestControlAction::InjectIdentity, first)
            .expect("first injection");
        assert_eq!(
            state.apply(GuestControlAction::StartWorkload, second),
            Err(GuestControlError::IdentityMismatch)
        );
    }

    fn http_request(method: &str, path: &str, body: &str) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: guest\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn server_only_releases_the_gate_for_a_canonical_injected_identity() {
        let request = request(70);
        let mut server = GuestControlServer::new();
        let premature = server.handle(
            "PUT",
            GuestControlAction::StartWorkload.path(),
            request.canonical_body().as_bytes(),
        );
        assert_eq!(premature.status(), 409);
        assert_eq!(premature.outcome(), None);

        let injected = server.handle(
            "PUT",
            GuestControlAction::InjectIdentity.path(),
            request.canonical_body().as_bytes(),
        );
        assert_eq!(injected.status(), 200);
        assert_eq!(
            injected.body(),
            request.canonical_acknowledgement(GuestControlAction::InjectIdentity)
        );
        assert_eq!(
            injected.outcome(),
            Some(GuestControlOutcome::IdentityInjected)
        );

        let started = server.handle(
            "PUT",
            GuestControlAction::StartWorkload.path(),
            request.canonical_body().as_bytes(),
        );
        assert_eq!(started.status(), 200);
        assert_eq!(
            started.body(),
            request.canonical_acknowledgement(GuestControlAction::StartWorkload)
        );
        assert_eq!(
            started.outcome(),
            Some(GuestControlOutcome::WorkloadStarted)
        );
    }

    #[test]
    fn server_rejects_noncanonical_or_unknown_requests_without_transition() {
        let request = request(170);
        let body = request.canonical_body();
        let challenge = request.challenge().to_hex();
        let noncanonical = body.replacen(&challenge, &challenge.to_uppercase(), 1);
        let mut server = GuestControlServer::new();
        assert_eq!(
            server
                .handle(
                    "PUT",
                    GuestControlAction::InjectIdentity.path(),
                    noncanonical.as_bytes(),
                )
                .status(),
            400
        );
        assert_eq!(
            server
                .handle(
                    "POST",
                    GuestControlAction::InjectIdentity.path(),
                    body.as_bytes()
                )
                .status(),
            405
        );
        assert_eq!(server.state(), &GuestControlState::AwaitingIdentity);
    }

    #[test]
    fn http_server_has_bounded_framing_and_returns_exact_acknowledgement() {
        let request = request(80);
        let body = request.canonical_body();
        let input = http_request("PUT", GuestControlAction::InjectIdentity.path(), &body);
        let input_length = input.len();
        let mut stream = Cursor::new(input);
        let mut server = GuestControlServer::new();
        let response = server
            .serve_once(&mut stream)
            .expect("well-formed one-request HTTP stream");
        assert_eq!(response.status(), 200);
        let bytes = stream.into_inner();
        let output = String::from_utf8(bytes[input_length..].to_vec())
            .expect("in-memory HTTP bytes must remain UTF-8");
        assert!(output.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(output.ends_with(response.body()));
        assert_eq!(
            response.body(),
            request.canonical_acknowledgement(GuestControlAction::InjectIdentity)
        );

        let too_large = format!(
            "PUT /actions/inject-identity HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_GUEST_CONTROL_BODY_BYTES + 1
        );
        let mut stream = Cursor::new(too_large.into_bytes());
        assert!(matches!(
            GuestControlServer::new().serve_once(&mut stream),
            Err(GuestControlIoError::BodyTooLarge)
        ));
    }

    #[test]
    fn http_server_rejects_ambiguous_or_non_decimal_framing_without_transition() {
        let request = request(85);
        let body = request.canonical_body();
        let duplicate_length = format!(
            "PUT /actions/inject-identity HTTP/1.1\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
            body.len()
        );
        let transfer_encoding = format!(
            "PUT /actions/inject-identity HTTP/1.1\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n{body}",
            body.len()
        );
        let signed_length = format!(
            "PUT /actions/inject-identity HTTP/1.1\r\nContent-Length: +{}\r\n\r\n{body}",
            body.len()
        );
        for input in [duplicate_length, transfer_encoding, signed_length] {
            let mut stream = Cursor::new(input.into_bytes());
            assert!(matches!(
                GuestControlServer::new().serve_once(&mut stream),
                Err(GuestControlIoError::MalformedHttp)
            ));
        }

        let mut stream = Cursor::new(vec![b'a'; MAX_GUEST_CONTROL_HEADER_BYTES + 1]);
        assert!(matches!(
            GuestControlServer::new().serve_once(&mut stream),
            Err(GuestControlIoError::HeaderTooLarge)
        ));
    }

    #[test]
    fn workload_start_is_not_acknowledged_when_the_image_cannot_start_it() {
        let request = request(90);
        let body = request.canonical_body();
        let mut server = GuestControlServer::new();
        assert_eq!(
            server
                .handle(
                    "PUT",
                    GuestControlAction::InjectIdentity.path(),
                    body.as_bytes(),
                )
                .status(),
            200
        );
        let input = http_request("PUT", GuestControlAction::StartWorkload.path(), &body);
        let mut stream = Cursor::new(input);
        let response = server
            .serve_once_with(&mut stream, || {
                Err(io::Error::other("workload unavailable"))
            })
            .expect("a rejected workload still receives an HTTP response");
        assert_eq!(response.status(), 503);
        assert_eq!(response.outcome(), None);
        assert!(response.body().is_empty());
    }
}
