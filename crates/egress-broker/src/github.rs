//! Typed GitHub provider adapters.
//!
//! The guest can select only the two operations already represented by
//! `egress-protocol`. Credentials are selected by an opaque host-side handle;
//! no token, arbitrary URL, arbitrary headers, or arbitrary JSON body appears
//! in any broker operation. Branch publishing requires a host-supplied
//! expected-old/new object pair and always uses a non-force update.

use std::{collections::BTreeMap, error::Error, fmt, io::Read, time::Duration};

use authority_core::github::{
    GitHubAuthority, GitHubOperation, GitHubRequest, InstallationId, github_matches,
};
use egress_protocol::session::BrokerRequestId;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use reqwest::blocking::{Client, Response};
use serde_json::Value;

/// Hard upper bound for any provider response retained by the broker.
pub const MAX_GITHUB_RESPONSE_BYTES: u64 = 1024 * 1024;

/// A validated Git object ID used by the publish precondition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitObjectId(String);

impl GitObjectId {
    /// Creates a SHA-1 or SHA-256 hexadecimal object ID.
    ///
    /// # Errors
    ///
    /// Rejects any non-hex or non-standard object ID length.
    pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidGitObjectId> {
        let value = value.as_ref();
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InvalidGitObjectId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Returns the normalized lowercase object ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why an object ID cannot be used as a GitHub precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidGitObjectId;

impl fmt::Display for InvalidGitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Git object ID must be 40 or 64 hexadecimal characters")
    }
}

impl Error for InvalidGitObjectId {}

/// Host-provided input required for non-overwriting branch publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBranchPlan {
    new_object: GitObjectId,
    expected_old_object: GitObjectId,
}

impl PublishBranchPlan {
    /// Creates a branch plan with an explicit expected-old-object check.
    #[must_use]
    pub const fn new(new_object: GitObjectId, expected_old_object: GitObjectId) -> Self {
        Self {
            new_object,
            expected_old_object,
        }
    }

    /// Returns the object the branch is allowed to become.
    #[must_use]
    pub const fn new_object(&self) -> &GitObjectId {
        &self.new_object
    }

    /// Returns the exact remote object that must currently be present.
    #[must_use]
    pub const fn expected_old_object(&self) -> &GitObjectId {
        &self.expected_old_object
    }
}

/// A host-selected opaque credential identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialHandle(u64);

impl CredentialHandle {
    /// Creates an opaque host handle. The value is never a token or secret.
    #[must_use]
    pub const fn from_host_id(value: u64) -> Self {
        Self(value)
    }
}

/// Host-side credential selection without exposing token material.
pub trait CredentialProvider: Send + Sync {
    /// Selects the credential handle for an exact installation identity.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when no host credential is bound to the
    /// requested installation.
    fn credential_for(
        &self,
        installation: &InstallationId,
    ) -> Result<CredentialHandle, CredentialError>;
}

/// A deterministic credential selector for a configured installation.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    installation: InstallationId,
    handle: CredentialHandle,
}

impl StaticCredentialProvider {
    /// Binds one opaque handle to one host-assigned installation.
    #[must_use]
    pub const fn new(installation: InstallationId, handle: CredentialHandle) -> Self {
        Self {
            installation,
            handle,
        }
    }
}

impl CredentialProvider for StaticCredentialProvider {
    fn credential_for(
        &self,
        installation: &InstallationId,
    ) -> Result<CredentialHandle, CredentialError> {
        if &self.installation == installation {
            Ok(self.handle)
        } else {
            Err(CredentialError::Unavailable)
        }
    }
}

/// A host-side source of expected-old-object confirmations.
pub trait PublishPlanProvider: Send + Sync {
    /// Returns the plan for one exact request identity.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubAdapterError::MissingPublishPrecondition`] when the
    /// host has not supplied an expected-old-object confirmation.
    fn plan_for(
        &self,
        request_id: BrokerRequestId,
        request: &GitHubRequest,
    ) -> Result<PublishBranchPlan, GitHubAdapterError>;
}

/// A deterministic plan provider suitable for a host-owned dispatch table.
#[derive(Debug, Clone)]
pub struct StaticPublishPlanProvider {
    plans: BTreeMap<BrokerRequestId, PublishBranchPlan>,
}

impl StaticPublishPlanProvider {
    /// Creates a provider from request-bound host plans.
    #[must_use]
    pub fn new(plans: impl IntoIterator<Item = (BrokerRequestId, PublishBranchPlan)>) -> Self {
        Self {
            plans: plans.into_iter().collect(),
        }
    }
}

impl PublishPlanProvider for StaticPublishPlanProvider {
    fn plan_for(
        &self,
        request_id: BrokerRequestId,
        _request: &GitHubRequest,
    ) -> Result<PublishBranchPlan, GitHubAdapterError> {
        self.plans
            .get(&request_id)
            .cloned()
            .ok_or(GitHubAdapterError::MissingPublishPrecondition)
    }
}

/// A typed request sent to a provider for branch publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBranchInput {
    request: GitHubRequest,
    plan: PublishBranchPlan,
}

impl PublishBranchInput {
    /// Returns the original authorized operation.
    #[must_use]
    pub const fn request(&self) -> &GitHubRequest {
        &self.request
    }

    /// Returns the host-confirmed object transition.
    #[must_use]
    pub const fn plan(&self) -> &PublishBranchPlan {
        &self.plan
    }
}

/// A typed request sent to a provider for pull-request creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePullRequestInput {
    request: GitHubRequest,
}

impl CreatePullRequestInput {
    /// Returns the original authorized operation.
    #[must_use]
    pub const fn request(&self) -> &GitHubRequest {
        &self.request
    }
}

/// Typed result of a GitHub provider call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubResponse {
    /// Number of provider response bytes accounted to the session budget.
    pub response_bytes: u64,
    /// Operation completed by the provider.
    pub operation: GitHubOperation,
    /// Created pull-request number, when applicable.
    pub number: Option<u64>,
    /// Published object, when applicable.
    pub object: Option<GitObjectId>,
    disposition: GitHubCommitDisposition,
}

impl GitHubResponse {
    /// Creates a provider response for a mutation known to have committed.
    #[must_use]
    pub const fn committed(
        response_bytes: u64,
        operation: GitHubOperation,
        number: Option<u64>,
        object: Option<GitObjectId>,
    ) -> Self {
        Self {
            response_bytes,
            operation,
            number,
            object,
            disposition: GitHubCommitDisposition::Committed,
        }
    }

    /// Converts opaque commit-unknown evidence into an internal effect marker.
    pub(crate) const fn commit_unknown(unknown: GitHubCommitUnknown) -> Self {
        Self {
            response_bytes: unknown.response_bytes,
            operation: unknown.operation,
            number: None,
            object: None,
            disposition: GitHubCommitDisposition::Unknown,
        }
    }

    /// Returns whether this response marks an effect with unknown commit state.
    pub(crate) const fn is_commit_unknown(&self) -> bool {
        matches!(self.disposition, GitHubCommitDisposition::Unknown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitHubCommitDisposition {
    Committed,
    Unknown,
}

/// Opaque evidence that a GitHub mutation may have reached its commit point.
///
/// Only this module can create the evidence. The dispatcher can consume it to
/// record a committed effect without exposing a constructor that lets an
/// arbitrary adapter manufacture a successful-looking unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitHubCommitUnknown {
    operation: GitHubOperation,
    response_bytes: u64,
}

impl GitHubCommitUnknown {
    const fn new(operation: GitHubOperation, response_bytes: u64) -> Self {
        Self {
            operation,
            response_bytes,
        }
    }
}

/// Typed provider boundary. There is no raw request method.
pub trait GitHubProvider: Send {
    /// Performs the fixed branch publication operation.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubProviderError`] for typed provider, response, rate-limit,
    /// or transport failures.
    fn publish_branch(
        &mut self,
        input: &PublishBranchInput,
        credential: CredentialHandle,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError>;
    /// Performs the fixed pull-request creation operation.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubProviderError`] for typed provider, response, rate-limit,
    /// or transport failures.
    fn create_pull_request(
        &mut self,
        input: &CreatePullRequestInput,
        credential: CredentialHandle,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError>;
}

/// A typed adapter joining authority, opaque credentials, plans, and provider.
pub struct TypedGitHubAdapter<P, C, O> {
    provider: P,
    credentials: C,
    plans: O,
}

impl<P, C, O> TypedGitHubAdapter<P, C, O>
where
    P: GitHubProvider,
    C: CredentialProvider,
    O: PublishPlanProvider,
{
    /// Creates an adapter with host-owned provider dependencies.
    #[must_use]
    pub const fn new(provider: P, credentials: C, plans: O) -> Self {
        Self {
            provider,
            credentials,
            plans,
        }
    }
}

/// The dispatcher-facing GitHub adapter seam.
pub trait GitHubAdapter: Send {
    /// Executes one already-typed GitHub request.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubAdapterError`] when authority, credential, precondition,
    /// provider, or response validation rejects the operation.
    fn execute(
        &mut self,
        request_id: BrokerRequestId,
        request: &GitHubRequest,
        authority: &GitHubAuthority,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubAdapterError>;
}

impl<P, C, O> GitHubAdapter for TypedGitHubAdapter<P, C, O>
where
    P: GitHubProvider,
    C: CredentialProvider,
    O: PublishPlanProvider,
{
    fn execute(
        &mut self,
        request_id: BrokerRequestId,
        request: &GitHubRequest,
        authority: &GitHubAuthority,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubAdapterError> {
        if !github_matches(authority, request) {
            return Err(GitHubAdapterError::NotAuthorized);
        }
        let credential = self
            .credentials
            .credential_for(request.installation())
            .map_err(|_| GitHubAdapterError::CredentialUnavailable)?;
        match request.operation() {
            GitHubOperation::PublishBranch => {
                let plan = self.plans.plan_for(request_id, request)?;
                let input = PublishBranchInput {
                    request: request.clone(),
                    plan,
                };
                finish_provider_mutation(
                    self.provider
                        .publish_branch(&input, credential, max_response_bytes),
                    request.operation(),
                    max_response_bytes,
                    Some(input.plan.new_object()),
                )
            }
            GitHubOperation::CreatePullRequest => {
                let input = CreatePullRequestInput {
                    request: request.clone(),
                };
                finish_provider_mutation(
                    self.provider
                        .create_pull_request(&input, credential, max_response_bytes),
                    request.operation(),
                    max_response_bytes,
                    None,
                )
            }
        }
    }
}

fn finish_provider_mutation(
    result: Result<GitHubResponse, GitHubProviderError>,
    operation: GitHubOperation,
    max_response_bytes: u64,
    expected_object: Option<&GitObjectId>,
) -> Result<GitHubResponse, GitHubAdapterError> {
    let response = match result {
        Ok(response) => response,
        Err(GitHubProviderError::CommitUnknown) => {
            return Err(GitHubAdapterError::CommitUnknown(GitHubCommitUnknown::new(
                operation,
                max_response_bytes,
            )));
        }
        Err(error) => return Err(GitHubAdapterError::from_provider_before_commit(error)),
    };
    if validate_provider_response(&response, operation, max_response_bytes, expected_object)
        .is_err()
    {
        // A provider that returns `Ok` has already crossed its mutation
        // boundary. Invalid typed fields cannot safely turn that effect into a
        // pre-commit denial because a retry could execute it a second time.
        return Err(GitHubAdapterError::CommitUnknown(GitHubCommitUnknown::new(
            operation,
            max_response_bytes,
        )));
    }
    Ok(response)
}

fn validate_provider_response(
    response: &GitHubResponse,
    operation: GitHubOperation,
    max_response_bytes: u64,
    expected_object: Option<&GitObjectId>,
) -> Result<(), GitHubAdapterError> {
    if response.is_commit_unknown()
        || response.operation != operation
        || response.response_bytes > max_response_bytes
    {
        return Err(GitHubAdapterError::InvalidProviderResponse);
    }
    match operation {
        GitHubOperation::PublishBranch
            if response.number.is_some() || response.object != expected_object.cloned() =>
        {
            Err(GitHubAdapterError::InvalidProviderResponse)
        }
        GitHubOperation::CreatePullRequest
            if response.number.is_none() || response.object.is_some() =>
        {
            Err(GitHubAdapterError::InvalidProviderResponse)
        }
        _ => Ok(()),
    }
}

/// Why the host could not select or use credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// No credential is configured for the exact installation.
    Unavailable,
}

/// Typed provider rate-limit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitInfo {
    /// Remaining calls reported by the provider.
    pub remaining: Option<u64>,
    /// Unix reset time reported by the provider.
    pub reset_unix_seconds: Option<u64>,
    /// Retry-after seconds, when the provider supplied it.
    pub retry_after_seconds: Option<u64>,
}

/// Typed provider failures with no raw response passthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitHubProviderError {
    /// Authentication was rejected.
    Unauthorized,
    /// Credential lacks the requested operation.
    Forbidden,
    /// Repository or ref was not found.
    NotFound,
    /// The expected-old-object check failed.
    Conflict,
    /// Provider rate limit was reached.
    RateLimited(RateLimitInfo),
    /// Provider returned another server error.
    Server {
        /// HTTP status returned by the provider.
        status: u16,
    },
    /// TLS, timeout, or connection failure.
    Transport,
    /// Provider response failed its fixed schema validation.
    InvalidResponse,
    /// A mutation was sent but its terminal provider result could not be proven.
    CommitUnknown,
}

/// Typed adapter failures retained in broker outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubAdapterError {
    /// The request did not match the selected authority.
    NotAuthorized,
    /// No expected-old-object plan was supplied for `PublishBranch`.
    MissingPublishPrecondition,
    /// No credential was available for the installation.
    CredentialUnavailable,
    /// Provider rejected the operation.
    ProviderRejected,
    /// Provider rejected authentication.
    ProviderUnauthorized,
    /// Provider denied the installation permission.
    ProviderForbidden,
    /// Provider could not find the repository or ref.
    ProviderNotFound,
    /// Provider reported an expected-old-object or branch conflict.
    ProviderConflict,
    /// Provider returned a typed server status.
    ProviderServer {
        /// HTTP status returned by the provider.
        status: u16,
    },
    /// Provider rate limit with typed retry metadata.
    RateLimited(RateLimitInfo),
    /// Provider returned an invalid or unsupported response.
    InvalidProviderResponse,
    /// Provider transport failed.
    ProviderTransport,
    /// A mutation may have committed and must be recorded terminally.
    CommitUnknown(GitHubCommitUnknown),
}

impl GitHubAdapterError {
    fn from_provider_before_commit(error: GitHubProviderError) -> Self {
        match error {
            GitHubProviderError::RateLimited(info) => Self::RateLimited(info),
            GitHubProviderError::InvalidResponse => Self::InvalidProviderResponse,
            GitHubProviderError::Transport => Self::ProviderTransport,
            GitHubProviderError::Unauthorized => Self::ProviderUnauthorized,
            GitHubProviderError::Forbidden => Self::ProviderForbidden,
            GitHubProviderError::NotFound => Self::ProviderNotFound,
            GitHubProviderError::Conflict => Self::ProviderConflict,
            GitHubProviderError::Server { status } => Self::ProviderServer { status },
            GitHubProviderError::CommitUnknown => {
                unreachable!("commit-unknown errors require request context")
            }
        }
    }
}

impl fmt::Display for GitHubAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotAuthorized => "GitHub request is outside the selected authority",
            Self::MissingPublishPrecondition => {
                "PublishBranch requires a host expected-old-object plan"
            }
            Self::CredentialUnavailable => {
                "no host credential is available for the GitHub installation"
            }
            Self::ProviderRejected => "GitHub provider rejected the typed operation",
            Self::ProviderUnauthorized => "GitHub provider rejected the host credential",
            Self::ProviderForbidden => "GitHub provider denied the requested operation",
            Self::ProviderNotFound => "GitHub provider could not find the repository or ref",
            Self::ProviderConflict => "GitHub provider reported a ref conflict",
            Self::ProviderServer { status: _ } => "GitHub provider returned a server status",
            Self::RateLimited(_) => "GitHub provider rate limit was reached",
            Self::InvalidProviderResponse => "GitHub provider returned an invalid typed response",
            Self::ProviderTransport => "GitHub provider transport failed",
            Self::CommitUnknown(_) => {
                "GitHub mutation may have committed without a valid provider response"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for GitHubAdapterError {}

/// A production provider using Reqwest's rustls backend and fixed GitHub routes.
pub struct RustlsGitHubProvider {
    client: Client,
    token: String,
}

impl fmt::Debug for RustlsGitHubProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustlsGitHubProvider")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl RustlsGitHubProvider {
    /// Builds the fixed GitHub provider from the host-only environment secret.
    ///
    /// The token is read inside the host adapter and is never part of a guest
    /// request, response, debug representation, or provider error.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubProviderError::Transport`] if the rustls client cannot
    /// be constructed or the host-only variable is absent.
    pub fn from_environment() -> Result<Self, GitHubProviderError> {
        let token =
            std::env::var("EGRESS_GITHUB_TOKEN").map_err(|_| GitHubProviderError::Transport)?;
        if token.is_empty()
            || token.len() > 4096
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(GitHubProviderError::Transport);
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("host-egress-broker")
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| GitHubProviderError::Transport)?;
        Ok(Self { client, token })
    }

    fn send_publish(
        &self,
        input: &PublishBranchInput,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError> {
        let route = repository_route(input.request.repository().as_str())
            .ok_or(GitHubProviderError::InvalidResponse)?;
        let branch = branch_route(input.request.head());
        if branch.len() > 255 {
            return Err(GitHubProviderError::InvalidResponse);
        }
        let response_limit = max_response_bytes.min(MAX_GITHUB_RESPONSE_BYTES);
        let repository = self
            .client
            .get(format!("https://api.github.com/repos/{route}"))
            .bearer_auth(&self.token)
            .send()
            .map_err(|_| GitHubProviderError::Transport)?;
        let repository_bytes = response_bytes(repository, response_limit)?;
        let repository_id = parse_repository_node_id(&repository_bytes)?;
        let repository_response_bytes = u64::try_from(repository_bytes.len())
            .map_err(|_| GitHubProviderError::InvalidResponse)?;
        let remaining = response_limit
            .checked_sub(repository_response_bytes)
            .ok_or(GitHubProviderError::InvalidResponse)?;
        if remaining == 0 {
            return Err(GitHubProviderError::InvalidResponse);
        }
        let update = self
            .client
            .post("https://api.github.com/graphql")
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "query": "mutation UpdateRefs($repositoryId: ID!, $refUpdates: [RefUpdate!]!) { updateRefs(input: { repositoryId: $repositoryId, refUpdates: $refUpdates }) { clientMutationId } }",
                "variables": {
                    "repositoryId": repository_id,
                    "refUpdates": [{
                        "name": format!("refs/heads/{}", input.request.head()),
                        "beforeOid": input.plan.expected_old_object().as_str(),
                        "afterOid": input.plan.new_object().as_str(),
                        "force": false,
                    }],
                },
            }))
            .send()
            .map_err(|_| GitHubProviderError::CommitUnknown)?;
        let update_bytes = mutation_response_bytes(update, remaining)?;
        parse_update_refs_response(&update_bytes)?;
        let update_response_bytes =
            u64::try_from(update_bytes.len()).map_err(|_| GitHubProviderError::CommitUnknown)?;
        let total_response_bytes = repository_response_bytes
            .checked_add(update_response_bytes)
            .ok_or(GitHubProviderError::CommitUnknown)?;
        Ok(GitHubResponse::committed(
            total_response_bytes,
            GitHubOperation::PublishBranch,
            None,
            Some(input.plan.new_object().clone()),
        ))
    }

    fn send_pull_request(
        &self,
        input: &CreatePullRequestInput,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError> {
        let route = repository_route(input.request.repository().as_str())
            .ok_or(GitHubProviderError::InvalidResponse)?;
        let url = format!("https://api.github.com/repos/{route}/pulls");
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({
                "title": "Automated pull request",
                "base": input.request.base().to_string(),
                "head": input.request.head().to_string(),
            }))
            .send()
            .map_err(|_| GitHubProviderError::CommitUnknown)?;
        let bytes =
            mutation_response_bytes(response, max_response_bytes.min(MAX_GITHUB_RESPONSE_BYTES))?;
        let number = parse_pull_request_number(&bytes)?;
        Ok(GitHubResponse::committed(
            u64::try_from(bytes.len()).map_err(|_| GitHubProviderError::CommitUnknown)?,
            GitHubOperation::CreatePullRequest,
            Some(number),
            None,
        ))
    }
}

impl GitHubProvider for RustlsGitHubProvider {
    fn publish_branch(
        &mut self,
        input: &PublishBranchInput,
        _credential: CredentialHandle,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError> {
        self.send_publish(input, max_response_bytes)
    }

    fn create_pull_request(
        &mut self,
        input: &CreatePullRequestInput,
        _credential: CredentialHandle,
        max_response_bytes: u64,
    ) -> Result<GitHubResponse, GitHubProviderError> {
        self.send_pull_request(input, max_response_bytes)
    }
}

/// A host credential selector for the one environment-backed provider.
#[derive(Debug, Clone)]
pub struct EnvironmentCredentialProvider {
    installation: InstallationId,
    handle: CredentialHandle,
}

impl EnvironmentCredentialProvider {
    /// Binds the host-only environment token to one exact installation.
    #[must_use]
    pub const fn new(installation: InstallationId, handle: CredentialHandle) -> Self {
        Self {
            installation,
            handle,
        }
    }
}

impl CredentialProvider for EnvironmentCredentialProvider {
    fn credential_for(
        &self,
        installation: &InstallationId,
    ) -> Result<CredentialHandle, CredentialError> {
        if installation == &self.installation {
            Ok(self.handle)
        } else {
            Err(CredentialError::Unavailable)
        }
    }
}

fn parse_repository_node_id(bytes: &[u8]) -> Result<String, GitHubProviderError> {
    let json: Value =
        serde_json::from_slice(bytes).map_err(|_| GitHubProviderError::InvalidResponse)?;
    let node_id = json
        .get("node_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.bytes().all(|byte| !byte.is_ascii_control())
        })
        .ok_or(GitHubProviderError::InvalidResponse)?;
    Ok(node_id.to_owned())
}

fn parse_update_refs_response(bytes: &[u8]) -> Result<(), GitHubProviderError> {
    let json: Value =
        serde_json::from_slice(bytes).map_err(|_| GitHubProviderError::CommitUnknown)?;
    if json
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        let expected_old_conflict =
            json.get("errors")
                .and_then(Value::as_array)
                .is_some_and(|errors| {
                    errors.iter().any(|error| {
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .is_some_and(|message| {
                                message.contains("beforeoid")
                                    || message.contains("expected")
                                    || message.contains("point to")
                            })
                    })
                });
        return Err(if expected_old_conflict {
            GitHubProviderError::Conflict
        } else {
            GitHubProviderError::CommitUnknown
        });
    }
    let update_refs = json
        .get("data")
        .and_then(|data| data.get("updateRefs"))
        .ok_or(GitHubProviderError::CommitUnknown)?;
    if !update_refs.is_object() {
        return Err(GitHubProviderError::CommitUnknown);
    }
    Ok(())
}

fn parse_pull_request_number(bytes: &[u8]) -> Result<u64, GitHubProviderError> {
    let json: Value =
        serde_json::from_slice(bytes).map_err(|_| GitHubProviderError::CommitUnknown)?;
    json.get("number")
        .and_then(Value::as_u64)
        .filter(|number| *number != 0)
        .ok_or(GitHubProviderError::CommitUnknown)
}

fn response_bytes(mut response: Response, limit: u64) -> Result<Vec<u8>, GitHubProviderError> {
    let status = response.status().as_u16();
    let rate_limit = rate_limit_info(&response);
    if !(200..300).contains(&status) {
        return Err(provider_error_from_status(status, rate_limit));
    }
    read_response_body(&mut response, limit)
}

fn mutation_response_bytes(
    mut response: Response,
    limit: u64,
) -> Result<Vec<u8>, GitHubProviderError> {
    let status = response.status().as_u16();
    let rate_limit = rate_limit_info(&response);
    if !(200..300).contains(&status) {
        return match provider_error_from_status(status, rate_limit) {
            GitHubProviderError::Server { .. } => Err(GitHubProviderError::CommitUnknown),
            error => Err(error),
        };
    }
    mutation_body_result(read_response_body(&mut response, limit))
}

fn mutation_body_result<T>(
    result: Result<T, GitHubProviderError>,
) -> Result<T, GitHubProviderError> {
    result.map_err(|_| GitHubProviderError::CommitUnknown)
}

fn read_response_body(response: &mut Response, limit: u64) -> Result<Vec<u8>, GitHubProviderError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|_| GitHubProviderError::Transport)?;
        if read == 0 {
            break;
        }
        let next = bytes.len().saturating_add(read);
        if u64::try_from(next).map_or(true, |length| length > limit) {
            return Err(GitHubProviderError::InvalidResponse);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

fn rate_limit_info(response: &Response) -> RateLimitInfo {
    RateLimitInfo {
        remaining: header_u64(response, "x-ratelimit-remaining"),
        reset_unix_seconds: header_u64(response, "x-ratelimit-reset"),
        retry_after_seconds: header_u64(response, "retry-after"),
    }
}

fn header_u64(response: &Response, name: &str) -> Option<u64> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn provider_error_from_status(status: u16, rate_limit: RateLimitInfo) -> GitHubProviderError {
    match status {
        401 => GitHubProviderError::Unauthorized,
        403 if rate_limit.remaining == Some(0) => GitHubProviderError::RateLimited(rate_limit),
        403 => GitHubProviderError::Forbidden,
        404 => GitHubProviderError::NotFound,
        409 => GitHubProviderError::Conflict,
        429 => GitHubProviderError::RateLimited(rate_limit),
        status if status >= 500 => GitHubProviderError::Server { status },
        _ => GitHubProviderError::InvalidResponse,
    }
}

fn repository_route(repository: &str) -> Option<String> {
    let mut parts = repository.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || owner == "."
        || owner == ".."
        || name == "."
        || name == ".."
        || owner.len() > 100
        || name.len() > 100
        || !owner.bytes().all(is_safe_repo_byte)
        || !name.bytes().all(is_safe_repo_byte)
    {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

fn branch_route(branch: &authority_core::github::BranchName) -> String {
    branch
        .as_segments()
        .iter()
        .map(|segment| percent_encode(segment.as_bytes(), NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

const fn is_safe_repo_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use authority_core::github::{
        BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
        GitHubRequest, InstallationId,
    };
    use authority_core::repository::RepoId;
    use egress_protocol::session::BrokerRequestId;

    use super::{
        CredentialHandle, GitHubAdapter, GitHubAdapterError, GitHubProvider, GitHubProviderError,
        GitHubResponse, GitObjectId, MAX_GITHUB_RESPONSE_BYTES, PublishBranchPlan,
        StaticCredentialProvider, StaticPublishPlanProvider, TypedGitHubAdapter,
    };

    fn request(operation: GitHubOperation) -> GitHubRequest {
        GitHubRequest::new(
            InstallationId::new("install-a"),
            RepoId::new("owner/repo"),
            operation,
            BranchName::new("main").expect("fixture branch is valid"),
            BranchName::new("agents/fix").expect("fixture branch is valid"),
        )
    }

    fn authority(operation: GitHubOperation) -> GitHubAuthority {
        GitHubAuthority::new(
            InstallationId::new("install-a"),
            RepoId::new("owner/repo"),
            GitHubOperations::only(operation),
            BranchPattern::Exact(BranchName::new("main").expect("fixture branch is valid")),
            BranchPattern::Prefix(BranchName::new("agents").expect("fixture branch is valid")),
        )
    }

    struct MockProvider {
        calls: Arc<Mutex<u32>>,
        error: Option<GitHubProviderError>,
    }
    impl GitHubProvider for MockProvider {
        fn publish_branch(
            &mut self,
            input: &super::PublishBranchInput,
            _credential: CredentialHandle,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubProviderError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            assert_eq!(
                input.plan().expected_old_object().as_str(),
                "0000000000000000000000000000000000000000"
            );
            self.error.map_or_else(
                || {
                    Ok(GitHubResponse::committed(
                        2,
                        GitHubOperation::PublishBranch,
                        None,
                        Some(input.plan().new_object().clone()),
                    ))
                },
                Err,
            )
        }
        fn create_pull_request(
            &mut self,
            _input: &super::CreatePullRequestInput,
            _credential: CredentialHandle,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubProviderError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            self.error.map_or_else(
                || {
                    Ok(GitHubResponse::committed(
                        2,
                        GitHubOperation::CreatePullRequest,
                        Some(9),
                        None,
                    ))
                },
                Err,
            )
        }
    }

    fn adapter(
        error: Option<GitHubProviderError>,
    ) -> (
        TypedGitHubAdapter<MockProvider, StaticCredentialProvider, StaticPublishPlanProvider>,
        Arc<Mutex<u32>>,
    ) {
        let calls = Arc::new(Mutex::new(0));
        let provider = MockProvider {
            calls: calls.clone(),
            error,
        };
        let old = GitObjectId::new("0000000000000000000000000000000000000000")
            .expect("fixture object is valid");
        let new = GitObjectId::new("1111111111111111111111111111111111111111")
            .expect("fixture object is valid");
        let plan = PublishBranchPlan::new(new, old);
        let request_id = BrokerRequestId::new([7; 16]);
        (
            TypedGitHubAdapter::new(
                provider,
                StaticCredentialProvider::new(
                    InstallationId::new("install-a"),
                    CredentialHandle::from_host_id(1),
                ),
                StaticPublishPlanProvider::new([(request_id, plan)]),
            ),
            calls,
        )
    }

    // Requirement: PublishBranch requires exact expected-old-object data and uses only opaque credentials.
    // Category: security/normal. Risk: critical.
    #[test]
    fn typed_publish_branch_uses_plan_and_opaque_credential() {
        let (mut adapter, calls) = adapter(None);
        let response = adapter
            .execute(
                BrokerRequestId::new([7; 16]),
                &request(GitHubOperation::PublishBranch),
                &authority(GitHubOperation::PublishBranch),
                MAX_GITHUB_RESPONSE_BYTES,
            )
            .expect("typed publish should succeed");
        assert_eq!(response.operation, GitHubOperation::PublishBranch);
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 1);
    }

    // Requirement: provider rate-limit failures remain typed and contain no raw response/body.
    // Category: error/security. Risk: high.
    #[test]
    fn typed_provider_rate_limit_is_preserved() {
        let (mut adapter, _) = adapter(Some(GitHubProviderError::RateLimited(
            super::RateLimitInfo {
                remaining: Some(0),
                reset_unix_seconds: Some(123),
                retry_after_seconds: Some(10),
            },
        )));
        assert_eq!(
            adapter.execute(
                BrokerRequestId::new([7; 16]),
                &request(GitHubOperation::PublishBranch),
                &authority(GitHubOperation::PublishBranch),
                MAX_GITHUB_RESPONSE_BYTES,
            ),
            Err(GitHubAdapterError::RateLimited(super::RateLimitInfo {
                remaining: Some(0),
                reset_unix_seconds: Some(123),
                retry_after_seconds: Some(10)
            }))
        );
    }

    // Requirement: a provider result must obey the operation and response-byte contract.
    // Category: contract/security/resource. Risk: high.
    #[test]
    fn provider_response_over_budget_is_rejected_at_the_typed_boundary() {
        let (mut adapter, calls) = adapter(None);
        assert!(matches!(
            adapter.execute(
                BrokerRequestId::new([7; 16]),
                &request(GitHubOperation::PublishBranch),
                &authority(GitHubOperation::PublishBranch),
                1,
            ),
            Err(GitHubAdapterError::CommitUnknown(_))
        ));
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 1);
    }

    // Requirement: failures after a mutation send cannot authorize a second mutation attempt.
    // Category: state transition/security. Risk: critical.
    #[test]
    fn provider_commit_unknown_is_preserved_as_opaque_adapter_evidence() {
        let (mut adapter, calls) = adapter(Some(GitHubProviderError::CommitUnknown));

        assert!(matches!(
            adapter.execute(
                BrokerRequestId::new([7; 16]),
                &request(GitHubOperation::CreatePullRequest),
                &authority(GitHubOperation::CreatePullRequest),
                MAX_GITHUB_RESPONSE_BYTES,
            ),
            Err(GitHubAdapterError::CommitUnknown(_))
        ));
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 1);
    }

    // Requirement: failed reads and malformed 2xx bodies after a mutation send are commit-unknown.
    // Category: fault injection/security. Risk: critical.
    #[test]
    fn failed_and_malformed_post_send_responses_are_commit_unknown() {
        assert_eq!(
            super::mutation_body_result::<Vec<u8>>(Err(GitHubProviderError::Transport)),
            Err(GitHubProviderError::CommitUnknown)
        );
        assert_eq!(
            super::parse_pull_request_number(br#"{"number":"not-a-number"}"#),
            Err(GitHubProviderError::CommitUnknown)
        );
        assert_eq!(
            super::parse_update_refs_response(br#"{"data":{"updateRefs":null}}"#),
            Err(GitHubProviderError::CommitUnknown)
        );
    }

    // Requirement: missing host precondition rejects before provider invocation.
    // Category: negative/security. Risk: critical.
    #[test]
    fn publish_branch_without_expected_old_object_is_rejected() {
        let calls = Arc::new(Mutex::new(0));
        let provider = MockProvider {
            calls: calls.clone(),
            error: None,
        };
        let mut adapter = TypedGitHubAdapter::new(
            provider,
            StaticCredentialProvider::new(
                InstallationId::new("install-a"),
                CredentialHandle::from_host_id(1),
            ),
            StaticPublishPlanProvider::new([]),
        );
        assert_eq!(
            adapter.execute(
                BrokerRequestId::new([7; 16]),
                &request(GitHubOperation::PublishBranch),
                &authority(GitHubOperation::PublishBranch),
                MAX_GITHUB_RESPONSE_BYTES,
            ),
            Err(GitHubAdapterError::MissingPublishPrecondition)
        );
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 0);
    }

    // Requirement: typed branch names cannot change the fixed GitHub URL route.
    // Category: security/input validation. Risk: high.
    #[test]
    fn branch_route_encodes_reserved_path_bytes() {
        let branch = BranchName::new("feature#hash").expect("fixture branch is valid");
        assert_eq!(super::branch_route(&branch), "feature%23hash");
    }

    // Requirement: provider JSON errors are classified without returning raw provider content.
    // Category: contract/error/security. Risk: high.
    #[test]
    fn graphql_expected_old_conflict_is_typed_and_malformed_success_is_commit_unknown() {
        assert_eq!(
            super::parse_update_refs_response(
                br#"{"errors":[{"message":"Expected ref beforeOid to point to the supplied value"}]}"#,
            ),
            Err(GitHubProviderError::Conflict)
        );
        assert_eq!(
            super::parse_update_refs_response(br#"{"data":{"updateRefs":null}}"#),
            Err(GitHubProviderError::CommitUnknown)
        );
    }
}
