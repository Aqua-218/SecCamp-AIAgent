//! Canonical, replay-resistant control messages used between the host runtime and guest.
//!
//! The protocol is deliberately small: a request carries the per-restoration challenge and all
//! regenerated identities; the guest must return the byte-for-byte canonical acknowledgement.
//! Strict parsing prevents a different JSON spelling from becoming a second accepted protocol.

use std::fmt::{Display, Formatter};

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
}
