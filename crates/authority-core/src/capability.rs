//! Capability envelopes, typed authority requests, and delegation decisions.

use std::fmt;

use crate::{
    file::{FileAuthority, FileRequest, file_body_below, file_matches},
    time::{MonotonicTime, TimeWindow},
};

/// An opaque, session-unique capability identity assigned by the host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapId(String);

impl CapId {
    /// Creates a capability identity from its host-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying host-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An opaque identity for the subject that holds a capability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId(String);

impl SubjectId {
    /// Creates a subject identity from its host-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying host-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An opaque identity for the host component that issued a capability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerId(String);

impl IssuerId {
    /// Creates an issuer identity from its host-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying host-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Identity and issuance data carried by a capability envelope.
///
/// This metadata does not contribute to authority-set containment. The state
/// machine that issues a child must separately validate the parent link,
/// holder, issuer, and `delegable` flag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityMetadata {
    id: CapId,
    subject: SubjectId,
    issuer: IssuerId,
    parent: Option<CapId>,
    delegable: bool,
}

impl CapabilityMetadata {
    /// Creates metadata for a capability without a parent or delegation right.
    #[must_use]
    pub const fn new(id: CapId, subject: SubjectId, issuer: IssuerId) -> Self {
        Self {
            id,
            subject,
            issuer,
            parent: None,
            delegable: false,
        }
    }

    /// Records the capability from which this capability was derived.
    #[must_use]
    pub fn with_parent(mut self, parent: CapId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets whether the state machine may derive a child from this capability.
    #[must_use]
    pub const fn with_delegable(mut self, delegable: bool) -> Self {
        self.delegable = delegable;
        self
    }

    /// Returns this capability's identity.
    #[must_use]
    pub const fn id(&self) -> &CapId {
        &self.id
    }

    /// Returns the subject that holds this capability.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the component that issued this capability.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// Returns the recorded parent capability, if any.
    #[must_use]
    pub const fn parent(&self) -> Option<&CapId> {
        self.parent.as_ref()
    }

    /// Returns whether the state machine may derive a child from this capability.
    #[must_use]
    pub const fn is_delegable(&self) -> bool {
        self.delegable
    }
}

/// A typed authority body carried by a capability.
///
/// Each new authority family must add its corresponding request variant and
/// explicit matching and containment rules. There is no untyped fallback.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthorityBody {
    /// Repository filesystem authority.
    File(FileAuthority),
}

/// A typed operation checked against an [`AuthorityBody`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthorityRequest {
    /// Repository filesystem request.
    File(FileRequest),
}

/// An immutable capability envelope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Capability {
    metadata: CapabilityMetadata,
    validity: TimeWindow,
    authority: AuthorityBody,
}

impl Capability {
    /// Creates a capability from independently validated envelope fields.
    #[must_use]
    pub const fn new(
        metadata: CapabilityMetadata,
        validity: TimeWindow,
        authority: AuthorityBody,
    ) -> Self {
        Self {
            metadata,
            validity,
            authority,
        }
    }

    /// Returns the identity and issuance metadata.
    #[must_use]
    pub const fn metadata(&self) -> &CapabilityMetadata {
        &self.metadata
    }

    /// Returns the half-open validity window.
    #[must_use]
    pub const fn validity(&self) -> TimeWindow {
        self.validity
    }

    /// Returns the typed authority body.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityBody {
        &self.authority
    }
}

/// An operation and the monotonic time at which it is authorized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityRequest {
    time: MonotonicTime,
    authority: AuthorityRequest,
}

impl CapabilityRequest {
    /// Creates a time-stamped authority request.
    #[must_use]
    pub const fn new(time: MonotonicTime, authority: AuthorityRequest) -> Self {
        Self { time, authority }
    }

    /// Returns the authorization time.
    #[must_use]
    pub const fn time(&self) -> MonotonicTime {
        self.time
    }

    /// Returns the typed operation being requested.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityRequest {
        &self.authority
    }
}

/// A non-empty group of requests that must authorize one external operation.
///
/// Some operations have more than one independently meaningful authority
/// boundary. For example, opening a file for both reading and writing needs
/// `ReadData` and `WriteData`; a no-replace rename needs authorization for its
/// source and destination paths. This type keeps every required request
/// together so the concurrent kernel can check and audit them as one effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityRequestSet {
    first: CapabilityRequest,
    additional: Vec<CapabilityRequest>,
}

impl CapabilityRequestSet {
    /// Creates a one-request set for an ordinary single-boundary operation.
    #[must_use]
    pub const fn one(request: CapabilityRequest) -> Self {
        Self {
            first: request,
            additional: Vec::new(),
        }
    }

    /// Creates a set containing `first` and every additional required request.
    #[must_use]
    pub fn new(
        first: CapabilityRequest,
        additional: impl IntoIterator<Item = CapabilityRequest>,
    ) -> Self {
        Self {
            first,
            additional: additional.into_iter().collect(),
        }
    }

    /// Returns the first request, retained for single-request compatibility.
    #[must_use]
    pub const fn first(&self) -> &CapabilityRequest {
        &self.first
    }

    /// Returns the requests after [`Self::first`].
    #[must_use]
    pub fn additional(&self) -> &[CapabilityRequest] {
        self.additional.as_slice()
    }

    /// Returns every request in the set in stable audit order.
    #[must_use]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &CapabilityRequest> {
        std::iter::once(&self.first).chain(self.additional.iter())
    }
}

/// Returns whether a typed authority body permits a typed request.
#[must_use]
pub fn authority_matches(authority: &AuthorityBody, request: &AuthorityRequest) -> bool {
    match (authority, request) {
        (AuthorityBody::File(authority), AuthorityRequest::File(request)) => {
            file_matches(authority, request)
        }
    }
}

/// Returns whether every request permitted by `child` is permitted by `parent`.
#[must_use]
pub fn authority_body_below(child: &AuthorityBody, parent: &AuthorityBody) -> bool {
    match (child, parent) {
        (AuthorityBody::File(child), AuthorityBody::File(parent)) => file_body_below(child, parent),
    }
}

/// Returns whether `capability` permits `request` at the supplied time.
#[must_use]
pub fn capability_matches(capability: &Capability, request: &CapabilityRequest) -> bool {
    capability.validity.contains(request.time)
        && authority_matches(&capability.authority, &request.authority)
}

/// Returns whether the child's authority set is contained by the parent's.
///
/// This pure relation compares the validity window and typed authority body.
/// Issuance policy such as parent identity, subject assignment, and the
/// parent's `delegable` flag belongs to the state-machine `derive` transition.
#[must_use]
pub fn weaker_than(child: &Capability, parent: &Capability) -> bool {
    child.validity.is_subset_of(parent.validity)
        && authority_body_below(&child.authority, &parent.authority)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityBody, AuthorityRequest, CapId, Capability, CapabilityMetadata, CapabilityRequest,
        IssuerId, SubjectId, capability_matches, weaker_than,
    };
    use crate::{
        file::{FileAuthority, FileEffect, FileEffects, FileRequest},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        time::{MonotonicTime, TimeWindow},
    };

    fn time(ticks: u64) -> MonotonicTime {
        MonotonicTime::from_ticks(ticks)
    }

    fn window(not_before: u64, expires_at: u64) -> TimeWindow {
        TimeWindow::new(time(not_before), time(expires_at))
            .expect("test bounds must form a non-empty time window")
    }

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must contain valid segments")
    }

    fn metadata(label: &str) -> CapabilityMetadata {
        CapabilityMetadata::new(
            CapId::new(format!("cap-{label}")),
            SubjectId::new(format!("subject-{label}")),
            IssuerId::new(format!("issuer-{label}")),
        )
    }

    fn file_capability(
        label: &str,
        validity: TimeWindow,
        effects: FileEffects,
        path: PathPattern,
    ) -> Capability {
        Capability::new(
            metadata(label),
            validity,
            AuthorityBody::File(FileAuthority::new(RepoId::new("workspace"), effects, path)),
        )
    }

    fn file_request(time: u64, effect: FileEffect, path: CanonicalPath) -> CapabilityRequest {
        CapabilityRequest::new(
            MonotonicTime::from_ticks(time),
            AuthorityRequest::File(FileRequest::new(RepoId::new("workspace"), effect, path)),
        )
    }

    #[test]
    fn capability_metadata_preserves_typed_issuance_fields() {
        let metadata = metadata("child")
            .with_parent(CapId::new("cap-parent"))
            .with_delegable(true);

        assert_eq!(metadata.id().as_str(), "cap-child");
        assert_eq!(metadata.subject().as_str(), "subject-child");
        assert_eq!(metadata.issuer().as_str(), "issuer-child");
        assert_eq!(metadata.parent().map(CapId::as_str), Some("cap-parent"));
        assert!(metadata.is_delegable());
    }

    #[test]
    fn capability_matching_requires_time_and_authority() {
        let capability = file_capability(
            "source-reader",
            window(10, 20),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(path(&["src"])),
        );

        assert!(capability_matches(
            &capability,
            &file_request(10, FileEffect::ReadData, path(&["src", "main.rs"])),
        ));
        assert!(!capability_matches(
            &capability,
            &file_request(20, FileEffect::ReadData, path(&["src", "main.rs"])),
        ));
        assert!(!capability_matches(
            &capability,
            &file_request(15, FileEffect::WriteData, path(&["src", "main.rs"])),
        ));
        assert!(!capability_matches(
            &capability,
            &file_request(15, FileEffect::ReadData, path(&["docs", "design.md"])),
        ));
    }

    #[test]
    fn weaker_than_accepts_narrower_time_and_file_authority() {
        let parent = file_capability(
            "parent",
            window(10, 30),
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Prefix(path(&["src"])),
        );
        let child = file_capability(
            "child",
            window(15, 20),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Exact(path(&["src", "main.rs"])),
        );

        assert!(weaker_than(&parent, &parent));
        assert!(weaker_than(&child, &child));
        assert!(weaker_than(&child, &parent));
        assert_ne!(child.metadata().id(), parent.metadata().id());
        assert_ne!(child.metadata().subject(), parent.metadata().subject());
    }

    #[test]
    fn weaker_than_rejects_time_or_file_authority_expansion() {
        let parent = file_capability(
            "parent",
            window(10, 30),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(path(&["src"])),
        );
        let early_child = file_capability(
            "early",
            window(9, 20),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Exact(path(&["src", "main.rs"])),
        );
        let broad_effect_child = file_capability(
            "writer",
            window(15, 20),
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Exact(path(&["src", "main.rs"])),
        );
        let broad_path_child = file_capability(
            "root-reader",
            window(15, 20),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(CanonicalPath::root()),
        );

        assert!(!weaker_than(&early_child, &parent));
        assert!(!weaker_than(&broad_effect_child, &parent));
        assert!(!weaker_than(&broad_path_child, &parent));
    }

    #[test]
    fn weaker_than_is_transitive_for_file_capabilities() {
        let root = file_capability(
            "root",
            window(10, 60),
            FileEffects::from_effects([
                FileEffect::ReadData,
                FileEffect::WriteData,
                FileEffect::Rename,
            ]),
            PathPattern::Prefix(path(&["src"])),
        );
        let child = file_capability(
            "child",
            window(20, 50),
            FileEffects::from_effects([FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Prefix(path(&["src", "parser"])),
        );
        let leaf = file_capability(
            "leaf",
            window(30, 40),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Exact(path(&["src", "parser", "lexer.rs"])),
        );

        assert!(weaker_than(&leaf, &child));
        assert!(weaker_than(&child, &root));
        assert!(weaker_than(&leaf, &root));
    }
}
