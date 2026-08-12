//! The closed request universe accepted by the Host Egress Broker.
//!
//! Transport code may carry opaque frames, but the dispatcher must decode them
//! into this enum before it can select an external client. There is no variant
//! for arbitrary URLs, headers, HTTP methods, request bodies, or credentials.

use authority_core::{
    capability::{AuthorityRequest, CapabilityRequest},
    github::GitHubRequest,
    http::{HttpFetchMethod, HttpFetchRequest},
    time::MonotonicTime,
};

/// One external-effect family the Broker may dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrokerOperationKind {
    /// An unauthenticated public HTTP GET or HEAD request.
    PublicFetch,
    /// One named operation performed through the GitHub provider adapter.
    GitHub,
}

/// A broker request decoded into one closed, typed external operation.
///
/// The caller must obtain this request from a canonical transport payload and
/// arrange its capability authorization before dispatch. The Broker must still
/// apply its host-side session envelope, replay guard, and session budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrokerOperation {
    /// A public, unauthenticated GET or HEAD fetch.
    PublicFetch(HttpFetchRequest),
    /// A GitHub request limited to the authority-core operation enum.
    GitHub(GitHubRequest),
}

impl BrokerOperation {
    /// Returns this request's closed external-effect family.
    #[must_use]
    pub const fn kind(&self) -> BrokerOperationKind {
        match self {
            Self::PublicFetch(_) => BrokerOperationKind::PublicFetch,
            Self::GitHub(_) => BrokerOperationKind::GitHub,
        }
    }

    /// Returns the exact public-fetch request, if this is one.
    #[must_use]
    pub const fn as_public_fetch(&self) -> Option<&HttpFetchRequest> {
        match self {
            Self::PublicFetch(request) => Some(request),
            Self::GitHub(_) => None,
        }
    }

    /// Returns the exact GitHub request, if this is one.
    #[must_use]
    pub const fn as_github(&self) -> Option<&GitHubRequest> {
        match self {
            Self::PublicFetch(_) => None,
            Self::GitHub(request) => Some(request),
        }
    }

    /// Returns the public-response byte reservation requested by this operation.
    ///
    /// GitHub provider responses use a separate host policy rather than an
    /// authority-controlled response cap, so this returns `None` for them.
    #[must_use]
    pub const fn public_response_byte_limit(&self) -> Option<u64> {
        match self {
            Self::PublicFetch(request) => Some(request.max_response_bytes()),
            Self::GitHub(_) => None,
        }
    }

    /// Rebuilds this operation as the matching authority-core request variant.
    ///
    /// This is the only operation-to-authority conversion in this crate. A
    /// Broker adapter can therefore hand the exact closed operation it decoded
    /// to `CapabilityKernel` without independently choosing an authority tag.
    #[must_use]
    pub fn authority_request(&self) -> AuthorityRequest {
        match self {
            Self::PublicFetch(request) => AuthorityRequest::HttpFetch(request.clone()),
            Self::GitHub(request) => AuthorityRequest::GitHub(request.clone()),
        }
    }

    /// Rebuilds this operation as a capability request at `time`.
    ///
    /// The Broker adapter still owns caller and capability identity, final
    /// authorization, replay handling, budget reservation, and the external
    /// effect's linearization point.
    #[must_use]
    pub fn capability_request_at(&self, time: MonotonicTime) -> CapabilityRequest {
        CapabilityRequest::new(time, self.authority_request())
    }
}

/// Returns whether a public operation is one of the closed safe methods.
///
/// This redundancy keeps the transport/dispatcher boundary explicit even
/// though [`HttpFetchMethod`] itself is a closed enum today.
#[must_use]
pub const fn is_safe_public_fetch_method(method: HttpFetchMethod) -> bool {
    matches!(method, HttpFetchMethod::Get | HttpFetchMethod::Head)
}

#[cfg(test)]
mod tests {
    use authority_core::{
        capability::AuthorityRequest,
        github::{BranchName, GitHubOperation, GitHubRequest, InstallationId},
        http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest},
        repository::RepoId,
        time::MonotonicTime,
    };

    use super::{BrokerOperation, BrokerOperationKind, is_safe_public_fetch_method};

    fn public_fetch() -> HttpFetchRequest {
        HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("docs.example").expect("test host must be valid"),
            CanonicalUrlPath::new("/guide").expect("test URL path must be valid"),
            1_024,
        )
    }

    fn branch(value: &str) -> BranchName {
        BranchName::new(value).expect("test branch must be valid")
    }

    fn github_request() -> GitHubRequest {
        GitHubRequest::new(
            InstallationId::new("installation-a"),
            RepoId::new("github.example/acme/workspace"),
            GitHubOperation::CreatePullRequest,
            branch("main"),
            branch("agents/fix"),
        )
    }

    #[test]
    fn operation_union_exposes_only_its_matching_typed_request() {
        let fetch = BrokerOperation::PublicFetch(public_fetch());
        let github = BrokerOperation::GitHub(github_request());

        assert_eq!(fetch.kind(), BrokerOperationKind::PublicFetch);
        assert!(fetch.as_public_fetch().is_some());
        assert!(fetch.as_github().is_none());
        assert_eq!(fetch.public_response_byte_limit(), Some(1_024));

        assert_eq!(github.kind(), BrokerOperationKind::GitHub);
        assert!(github.as_public_fetch().is_none());
        assert!(github.as_github().is_some());
        assert_eq!(github.public_response_byte_limit(), None);
    }

    #[test]
    fn public_fetch_method_universe_contains_only_get_and_head() {
        assert!(is_safe_public_fetch_method(HttpFetchMethod::Get));
        assert!(is_safe_public_fetch_method(HttpFetchMethod::Head));
    }

    #[test]
    fn authority_conversion_preserves_the_exact_closed_operation_variant() {
        let fetch = BrokerOperation::PublicFetch(public_fetch());
        let github = BrokerOperation::GitHub(github_request());
        let time = MonotonicTime::from_ticks(42);

        assert_eq!(
            fetch.authority_request(),
            AuthorityRequest::HttpFetch(public_fetch())
        );
        assert_eq!(
            github.authority_request(),
            AuthorityRequest::GitHub(github_request())
        );
        assert_eq!(fetch.capability_request_at(time).time(), time);
        assert_eq!(
            fetch.capability_request_at(time).authority(),
            &fetch.authority_request()
        );
    }
}
