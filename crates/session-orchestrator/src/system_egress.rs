//! Concrete host egress adapters for a production session.
//!
//! The guest never receives DNS, TLS, or credential configuration. This module creates the
//! bounded public HTTPS adapter and, only when explicitly configured, the GitHub adapter that
//! reads its token inside the host process.

use std::time::Instant;

use authority_core::{github::InstallationId, time::MonotonicTime};
use egress_broker::{
    github::{
        CredentialHandle, EnvironmentCredentialProvider, GitHubAdapter, GitHubAdapterError,
        RustlsGitHubProvider, StaticPublishPlanProvider, TypedGitHubAdapter,
    },
    ip_policy::IpPolicy,
    public_fetch::{FetchPolicy, PublicFetcher, RustlsHttpsConnector, SystemResolver},
};
use egress_protocol::session::BrokerRequestId;

use crate::{
    BackendError,
    production_runtime::{PerSessionEgressFactory, PreparedEgressSession, SessionEgressRequest},
};

/// GitHub credential configuration retained exclusively by the host egress factory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GitHubEgressConfig {
    /// Rejects every GitHub request without reading any credential environment variable.
    #[default]
    Disabled,
    /// Binds the host's `EGRESS_GITHUB_TOKEN` to one exact GitHub installation.
    Environment {
        /// Installation whose requests may use the host-only token.
        installation: InstallationId,
        /// Opaque host bookkeeping identity; this is never a credential value.
        credential_handle: CredentialHandle,
    },
}

impl GitHubEgressConfig {
    /// Configures the environment-backed host token for exactly one installation.
    #[must_use]
    pub const fn environment(
        installation: InstallationId,
        credential_handle: CredentialHandle,
    ) -> Self {
        Self::Environment {
            installation,
            credential_handle,
        }
    }
}

/// Standard concrete egress factory for a host daemon.
///
/// Public HTTPS always uses the strict built-in SSRF deny policy, a rustls connector, no proxy,
/// and the broker's bounded fetch policy. GitHub remains disabled until an operator identifies an
/// installation and intentionally supplies `EGRESS_GITHUB_TOKEN` to the daemon process.
#[derive(Debug, Clone, Default)]
pub struct SystemEgressFactory {
    github: GitHubEgressConfig,
}

impl SystemEgressFactory {
    /// Creates a factory with explicit GitHub credential policy.
    #[must_use]
    pub const fn new(github: GitHubEgressConfig) -> Self {
        Self { github }
    }

    /// Creates a public-HTTPS-only factory with GitHub disabled.
    #[must_use]
    pub const fn public_https_only() -> Self {
        Self::new(GitHubEgressConfig::Disabled)
    }
}

impl PerSessionEgressFactory for SystemEgressFactory {
    fn prepare(
        &self,
        request: &SessionEgressRequest,
    ) -> Result<PreparedEgressSession, BackendError> {
        let public = PublicFetcher::new(
            SystemResolver,
            RustlsHttpsConnector::default(),
            IpPolicy::default(),
            FetchPolicy::default(),
        );
        let clock_origin = Instant::now();
        match &self.github {
            GitHubEgressConfig::Disabled => Ok(PreparedEgressSession::new(
                request,
                public,
                DisabledGitHubAdapter,
                move || elapsed_ticks(clock_origin),
            )),
            GitHubEgressConfig::Environment {
                installation,
                credential_handle,
            } => {
                let provider = RustlsGitHubProvider::from_environment().map_err(|_| {
                    BackendError::new(
                        "environment-backed GitHub egress requires a valid EGRESS_GITHUB_TOKEN",
                    )
                })?;
                let github = TypedGitHubAdapter::new(
                    provider,
                    EnvironmentCredentialProvider::new(installation.clone(), *credential_handle),
                    StaticPublishPlanProvider::new([]),
                );
                Ok(PreparedEgressSession::new(
                    request,
                    public,
                    github,
                    move || elapsed_ticks(clock_origin),
                ))
            }
        }
    }
}

fn elapsed_ticks(origin: Instant) -> MonotonicTime {
    MonotonicTime::from_ticks(u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX))
}

struct DisabledGitHubAdapter;

impl GitHubAdapter for DisabledGitHubAdapter {
    fn execute(
        &mut self,
        _request_id: BrokerRequestId,
        _request: &authority_core::github::GitHubRequest,
        _authority: &authority_core::github::GitHubAuthority,
        _max_response_bytes: u64,
    ) -> Result<egress_broker::github::GitHubResponse, GitHubAdapterError> {
        Err(GitHubAdapterError::NotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BrokerSessionId, CapabilityId, ID_BYTES, RequestId, SessionId, SubjectId, VmId,
        WorkspaceId,
        production_runtime::{PerSessionEgressFactory, SessionEgressRequest},
    };

    use super::SystemEgressFactory;

    #[test]
    fn public_https_only_prepares_without_a_github_secret() {
        let request = SessionEgressRequest::new(crate::SessionIdentity {
            session_id: SessionId::new([0x11; ID_BYTES]),
            request_id: RequestId::new([0x12; ID_BYTES]),
            vm_id: VmId::new([0x13; ID_BYTES]),
            subject_id: SubjectId::new([0x14; ID_BYTES]),
            workspace_id: WorkspaceId::new([0x15; ID_BYTES]),
            capability_id: CapabilityId::new([0x16; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0x17; ID_BYTES]),
        });

        SystemEgressFactory::public_https_only()
            .prepare(&request)
            .expect("public HTTPS egress must not require a GitHub credential");
    }
}
