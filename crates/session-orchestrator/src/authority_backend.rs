//! Authority Core integration for the session capability backend.
//!
//! The adapter is deliberately narrower than the generic orchestration trait:
//! the grant supplies only authority policy, while session and capability
//! identities always come from the trusted fixed-width [`SessionIdentity`].

use std::{collections::BTreeMap, sync::Arc};

use authority_core::{
    capability::{AuthorityBody, CapId, SubjectId as AuthoritySubjectId},
    kernel::{CapabilityKernel, CapabilityKernelError},
    policy::AuthorityPolicyDigest,
    state::{CapabilityGrant, StaticAuthorityEnvelope, Subject},
    time::TimeWindow,
};

use crate::{
    BackendError, CapabilityBackend, CapabilityLease, CapabilityRevocationBackend, ID_BYTES,
    SessionId, SessionIdentity,
};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Authority policy for one session root capability.
///
/// The subject and capability identities are intentionally absent. They are
/// derived from [`SessionIdentity`] by [`AuthorityCoreBackend`] so callers
/// cannot substitute textual identities from a request or grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorityRootGrant {
    validity: TimeWindow,
    authority: AuthorityBody,
    broker_authority: Option<AuthorityBody>,
    delegable: bool,
}

impl AuthorityRootGrant {
    /// Creates a non-delegable root grant from a validity window and typed authority.
    #[must_use]
    pub const fn new(validity: TimeWindow, authority: AuthorityBody) -> Self {
        Self {
            validity,
            authority,
            broker_authority: None,
            delegable: false,
        }
    }

    /// Sets whether the issued root may derive child capabilities.
    #[must_use]
    pub const fn with_delegable(mut self, delegable: bool) -> Self {
        self.delegable = delegable;
        self
    }

    /// Assigns a separate typed authority to the host Broker's non-guest root.
    ///
    /// The guest root remains the only capability injected into the guest supervisor. The Broker
    /// root stays host-owned, allowing file and egress authorities to be revoked together without
    /// exposing the egress authority as a guest descriptor or control message.
    #[must_use]
    pub fn with_broker_authority(mut self, broker_authority: AuthorityBody) -> Self {
        self.broker_authority = Some(broker_authority);
        self
    }

    /// Returns the root capability's validity window.
    #[must_use]
    pub const fn validity(&self) -> TimeWindow {
        self.validity
    }

    /// Returns the root capability's typed authority body.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityBody {
        &self.authority
    }

    /// Returns the authority bound to the host Broker root.
    ///
    /// Without an explicit Broker authority, the guest root authority is reused. That preserves
    /// the original single-family policy while still using two distinct Authority Core roots.
    #[must_use]
    pub fn broker_authority(&self) -> &AuthorityBody {
        self.broker_authority.as_ref().unwrap_or(&self.authority)
    }

    /// Returns whether the root capability may derive child capabilities.
    #[must_use]
    pub const fn is_delegable(&self) -> bool {
        self.delegable
    }

    /// Returns the versioned digest that a guest must independently derive
    /// from its immutable root policy before the workload gate is released.
    #[must_use]
    pub fn policy_digest(&self) -> AuthorityPolicyDigest {
        AuthorityPolicyDigest::for_root(self.validity, &self.authority, self.delegable)
    }

    fn envelope(&self) -> StaticAuthorityEnvelope {
        StaticAuthorityEnvelope::new(self.validity, self.authority.clone())
    }

    fn capability_grant(&self, subject: AuthoritySubjectId) -> CapabilityGrant {
        CapabilityGrant::new(subject, self.validity, self.authority.clone())
            .with_delegable(self.delegable)
    }

    fn broker_envelope(&self) -> StaticAuthorityEnvelope {
        StaticAuthorityEnvelope::new(self.validity, self.broker_authority().clone())
    }

    fn broker_capability_grant(&self, subject: AuthoritySubjectId) -> CapabilityGrant {
        CapabilityGrant::new(subject, self.validity, self.broker_authority().clone())
            .with_delegable(self.delegable)
    }
}

/// Descriptive alias for callers that refer to the policy as a specification.
pub type AuthorityRootSpec = AuthorityRootGrant;

/// Authority identities supplied to one session's Broker worker.
///
/// These values are derived only from the host-allocated [`SessionIdentity`]
/// and can be moved directly into an egress Broker dispatch context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorityBrokerBinding {
    /// Authority Core subject authenticated for the Broker connection.
    pub caller: AuthoritySubjectId,
    /// Root capability selected for final Broker authorization.
    pub capability: CapId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingStatus {
    Active,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootBinding {
    lease: CapabilityLease,
    guest_subject: AuthoritySubjectId,
    guest_capability: CapId,
    broker_subject: AuthoritySubjectId,
    broker_capability: CapId,
    status: BindingStatus,
}

/// Production `CapabilityBackend` adapter backed by Authority Core.
///
/// The kernel is shared with the host adapters that authorize effects. Root
/// bindings remain owned here until subject closure succeeds, allowing a
/// failed cleanup step to be retried without losing the exact identity tuple.
#[derive(Debug)]
pub struct AuthorityCoreBackend {
    kernel: Arc<CapabilityKernel>,
    bindings: BTreeMap<SessionId, RootBinding>,
}

impl AuthorityCoreBackend {
    /// Creates an adapter that owns a shared reference to an initialized kernel.
    #[must_use]
    pub fn new(kernel: Arc<CapabilityKernel>) -> Self {
        Self {
            kernel,
            bindings: BTreeMap::new(),
        }
    }

    /// Returns the shared kernel used for issuance, authorization, and revocation.
    #[must_use]
    pub fn kernel(&self) -> &Arc<CapabilityKernel> {
        &self.kernel
    }

    /// Returns an owned reference to the exact kernel shared with this backend.
    ///
    /// A production Broker worker can move this value into its dispatcher;
    /// issuance, Broker authorization, and revocation then use one serialized
    /// Authority Core state instance.
    #[must_use]
    pub fn broker_executor(&self) -> Arc<CapabilityKernel> {
        Arc::clone(&self.kernel)
    }

    /// Derives the exact Authority Core identities for one host Broker worker.
    ///
    /// This is the sole conversion point from orchestrator subject and
    /// capability identities into their Authority Core representations.
    #[must_use]
    pub fn broker_binding(&self, identity: &SessionIdentity) -> AuthorityBrokerBinding {
        let broker = to_lower_hex(identity.broker_session_id().as_bytes());
        AuthorityBrokerBinding {
            caller: AuthoritySubjectId::new(format!("broker-{broker}")),
            capability: CapId::new(format!("broker-{broker}")),
        }
    }

    fn guest_binding(identity: &SessionIdentity) -> AuthorityBrokerBinding {
        AuthorityBrokerBinding {
            caller: AuthoritySubjectId::new(to_lower_hex(identity.subject_id().as_bytes())),
            capability: CapId::new(to_lower_hex(identity.capability_id().as_bytes())),
        }
    }
}

/// Short name for [`AuthorityCoreBackend`].
pub type AuthorityBackend = AuthorityCoreBackend;

impl CapabilityBackend<AuthorityRootGrant> for AuthorityCoreBackend {
    fn inject_root_capability(
        &mut self,
        identity: &SessionIdentity,
        grant: &AuthorityRootGrant,
    ) -> Result<CapabilityLease, BackendError> {
        let session_id = identity.session_id();
        if self.bindings.contains_key(&session_id) {
            return Err(BackendError::new(format!(
                "a root capability binding already exists for session `{session_id}`"
            )));
        }

        let guest = Self::guest_binding(identity);
        let broker = self.broker_binding(identity);
        let lease = CapabilityLease::new_bound(
            identity.session_id(),
            identity.subject_id(),
            identity.capability_id(),
            grant.policy_digest(),
        );

        self.register_and_issue(
            &guest,
            grant.envelope(),
            grant.capability_grant(guest.caller.clone()),
        )?;
        if let Err(error) = self.register_and_issue(
            &broker,
            grant.broker_envelope(),
            grant.broker_capability_grant(broker.caller.clone()),
        ) {
            let cleanup = self.close_issued(&guest.caller, &guest.capability);
            return Err(BackendError::new(format!(
                "failed to issue host Broker root after guest root was issued: {error}; guest root cleanup was {cleanup}"
            )));
        }

        self.bindings.insert(
            session_id,
            RootBinding {
                lease: lease.clone(),
                guest_subject: guest.caller,
                guest_capability: guest.capability,
                broker_subject: broker.caller,
                broker_capability: broker.capability,
                status: BindingStatus::Active,
            },
        );
        Ok(lease)
    }
}

impl CapabilityRevocationBackend for AuthorityCoreBackend {
    fn revoke_root_capability(&mut self, lease: &CapabilityLease) -> Result<(), BackendError> {
        let binding = self
            .bindings
            .get(&lease.session_id())
            .cloned()
            .ok_or_else(|| {
                BackendError::new(format!(
                    "unknown root capability lease for session `{}`",
                    lease.session_id()
                ))
            })?;

        if binding.lease != *lease {
            return Err(BackendError::new(format!(
                "root capability lease for session `{}` does not match its registered subject and capability",
                lease.session_id()
            )));
        }

        self.revoke_and_close(
            &binding.broker_subject,
            &binding.broker_capability,
            binding.status,
        )?;
        self.revoke_and_close(
            &binding.guest_subject,
            &binding.guest_capability,
            binding.status,
        )?;

        if let Some(binding) = self.bindings.get_mut(&lease.session_id()) {
            binding.status = BindingStatus::Closed;
        }
        Ok(())
    }
}

impl AuthorityCoreBackend {
    fn register_and_issue(
        &self,
        binding: &AuthorityBrokerBinding,
        envelope: StaticAuthorityEnvelope,
        grant: CapabilityGrant,
    ) -> Result<(), BackendError> {
        self.kernel
            .register_subject(Subject::new(binding.caller.clone(), envelope))
            .map_err(|error| {
                BackendError::new(format!(
                    "failed to register Authority Core subject `{}`: {error}",
                    binding.caller
                ))
            })?;
        let issued = match self
            .kernel
            .issue_root_with_id(binding.capability.clone(), grant)
        {
            Ok(capability) => capability,
            Err(error) => {
                return Err(self.issue_failure(&binding.caller, &error.to_string(), None));
            }
        };
        if issued != binding.capability {
            let issue_error = format!(
                "Authority Core returned capability ID `{issued}` instead of requested `{}`",
                binding.capability
            );
            return Err(self.issue_failure(&binding.caller, &issue_error, Some(&issued)));
        }
        Ok(())
    }

    fn revoke_and_close(
        &self,
        subject: &AuthoritySubjectId,
        capability: &CapId,
        status: BindingStatus,
    ) -> Result<(), BackendError> {
        self.kernel
            .revoke_held_by(subject, capability)
            .map_err(|error| revoke_error(subject, capability, status, "revoke", &error))?;
        self.kernel.begin_subject_close(subject).map_err(|error| {
            revoke_error(subject, capability, status, "begin subject close", &error)
        })?;
        self.kernel.finish_subject_close(subject).map_err(|error| {
            revoke_error(subject, capability, status, "finish subject close", &error)
        })?;
        Ok(())
    }

    fn close_issued(&self, subject: &AuthoritySubjectId, capability: &CapId) -> String {
        let revoke = self.kernel.revoke_held_by(subject, capability);
        let begin = self.kernel.begin_subject_close(subject);
        let finish = self.kernel.finish_subject_close(subject);
        format!(
            "revoke {}, begin {}, finish {}",
            close_result_detail(&revoke),
            close_result_detail(&begin),
            close_result_detail(&finish)
        )
    }

    fn issue_failure(
        &self,
        subject: &AuthoritySubjectId,
        issue_error: &str,
        issued: Option<&CapId>,
    ) -> BackendError {
        let revoke_detail = match issued {
            None => "not required".to_owned(),
            Some(capability) => match self.kernel.revoke_held_by(subject, capability) {
                Ok(status) => format!("attempted ({status:?})"),
                Err(error) => format!("failed ({error})"),
            },
        };
        let begin_result = self.kernel.begin_subject_close(subject);
        let finish_result = self.kernel.finish_subject_close(subject);

        BackendError::new(format!(
            "root capability issuance failed for subject `{subject}`: {issue_error}; cleanup was attempted (revoke: {revoke_detail}, begin subject close: {}, finish subject close: {})",
            close_result_detail(&begin_result),
            close_result_detail(&finish_result),
        ))
    }
}

fn revoke_error(
    subject: &AuthoritySubjectId,
    capability: &CapId,
    status: BindingStatus,
    operation: &str,
    error: &CapabilityKernelError,
) -> BackendError {
    BackendError::new(format!(
        "failed to {operation} root capability `{capability}` for subject `{subject}` while binding was {status:?}: {error}"
    ))
}

fn close_result_detail<T: std::fmt::Debug>(result: &Result<T, CapabilityKernelError>) -> String {
    match result {
        Ok(status) => format!("succeeded ({status:?})"),
        Err(error) => format!("failed ({error})"),
    }
}

fn to_lower_hex(bytes: [u8; ID_BYTES]) -> String {
    let mut encoded = String::with_capacity(ID_BYTES * 2);
    for byte in bytes {
        encoded.push(char::from(HEX_DIGITS[(byte >> 4) as usize]));
        encoded.push(char::from(HEX_DIGITS[(byte & 0x0f) as usize]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use authority_core::{
        capability::{AuthorityRequest, CapabilityRequest, IssuerId},
        file::{FileAuthority, FileEffect, FileEffects, FileRequest},
        http::{
            CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
            HttpFetchRequest, UrlPathPattern,
        },
        kernel::CapabilityKernel,
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityState, SubjectStatus},
        time::{MonotonicTime, TimeWindow},
    };

    use super::*;
    use crate::{
        BrokerSessionId, CapabilityId, RequestId, SessionId, SubjectId, VmId, WorkspaceId,
    };

    fn time(ticks: u64) -> MonotonicTime {
        MonotonicTime::from_ticks(ticks)
    }

    fn window(not_before: u64, expires_at: u64) -> TimeWindow {
        TimeWindow::new(time(not_before), time(expires_at))
            .expect("test bounds must form a non-empty window")
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ]),
            request_id: RequestId::new([0x20; ID_BYTES]),
            vm_id: VmId::new([0x30; ID_BYTES]),
            subject_id: SubjectId::new([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            workspace_id: WorkspaceId::new([0x40; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0x50; ID_BYTES]),
            capability_id: CapabilityId::new([
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
                0xfe, 0xff,
            ]),
        }
    }

    fn authority() -> AuthorityBody {
        AuthorityBody::File(FileAuthority::new(
            RepoId::new("workspace"),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Prefix(CanonicalPath::new(["src"]).expect("test path must be valid")),
        ))
    }

    fn grant() -> AuthorityRootGrant {
        AuthorityRootGrant::new(window(0, 100), authority()).with_delegable(true)
    }

    fn backend() -> AuthorityCoreBackend {
        let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
            "test-issuer",
        ))));
        AuthorityCoreBackend::new(kernel)
    }

    fn request() -> CapabilityRequest {
        CapabilityRequest::new(
            time(10),
            AuthorityRequest::File(FileRequest::new(
                RepoId::new("workspace"),
                FileEffect::ReadData,
                CanonicalPath::new(["src", "main.rs"]).expect("test path must be valid"),
            )),
        )
    }

    fn broker_authority() -> AuthorityBody {
        AuthorityBody::HttpFetch(HttpFetchAuthority::new(
            HttpFetchMethods::only(HttpFetchMethod::Get),
            CanonicalHost::new("api.example.test").expect("test host must be canonical"),
            UrlPathPattern::Prefix(CanonicalUrlPath::root()),
            1_024,
        ))
    }

    fn broker_request() -> CapabilityRequest {
        CapabilityRequest::new(
            time(10),
            AuthorityRequest::HttpFetch(HttpFetchRequest::new(
                HttpFetchMethod::Get,
                CanonicalHost::new("api.example.test").expect("test host must be canonical"),
                CanonicalUrlPath::new("/v1/status").expect("test path must be canonical"),
                1_024,
            )),
        )
    }

    #[test]
    fn policy_digest_binds_only_the_guest_root_policy_axes() {
        let base = grant();
        let broker_changed = base.clone().with_broker_authority(broker_authority());
        assert_eq!(base.policy_digest(), broker_changed.policy_digest());

        let authority_changed = AuthorityRootGrant::new(
            base.validity(),
            AuthorityBody::File(FileAuthority::new(
                RepoId::new("workspace"),
                FileEffects::only(FileEffect::WriteData),
                PathPattern::Prefix(CanonicalPath::new(["src"]).expect("test path must be valid")),
            )),
        )
        .with_delegable(true);
        assert_ne!(base.policy_digest(), authority_changed.policy_digest());

        let nondelegable = AuthorityRootGrant::new(base.validity(), base.authority().clone());
        assert_ne!(base.policy_digest(), nondelegable.policy_digest());
    }

    #[test]
    fn root_injection_uses_exact_lowercase_authority_ids_and_grant() {
        let mut backend = backend();
        let identity = identity();
        let lease = backend
            .inject_root_capability(&identity, &grant())
            .expect("root capability injection must succeed");

        assert_eq!(
            lease.subject_id().to_string(),
            "000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            lease.capability_id().to_string(),
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        assert_eq!(lease.policy_digest(), Some(grant().policy_digest()));

        let AuthorityBrokerBinding {
            caller: subject,
            capability,
        } = backend.broker_binding(&identity);
        backend
            .kernel()
            .with_active_capability(&subject, &capability, time(10), |issued| {
                assert_eq!(issued.metadata().subject().as_str(), subject.as_str());
                assert_eq!(issued.metadata().id().as_str(), capability.as_str());
                assert_eq!(issued.validity(), grant().validity());
                assert_eq!(issued.authority(), grant().authority());
                assert!(issued.metadata().is_delegable());
                Ok::<_, Infallible>(())
            })
            .expect("the issued root must use the exact authority IDs");
    }

    #[test]
    fn issued_root_authorizes_request_inside_grant() {
        let mut backend = backend();
        let identity = identity();
        backend
            .inject_root_capability(&identity, &grant())
            .expect("root capability injection must succeed");

        let binding = backend.broker_binding(&identity);
        backend
            .kernel()
            .authorize_and_execute_classified(
                &binding.caller,
                &binding.capability,
                &request(),
                |_| authority_core::kernel::EffectExecution::<(), Infallible>::Committed {
                    value: (),
                    receipt: None,
                },
            )
            .expect("a request inside the root grant must authorize");
    }

    #[test]
    fn host_broker_uses_a_separate_typed_root_from_the_guest_capability() {
        let mut backend = backend();
        let identity = identity();
        let grant = grant().with_broker_authority(broker_authority());
        backend
            .inject_root_capability(&identity, &grant)
            .expect("guest and Broker roots must issue together");

        let guest = AuthorityCoreBackend::guest_binding(&identity);
        backend
            .kernel()
            .authorize_and_execute_classified(&guest.caller, &guest.capability, &request(), |_| {
                authority_core::kernel::EffectExecution::<(), Infallible>::Committed {
                    value: (),
                    receipt: None,
                }
            })
            .expect("guest file root must retain its original authority");

        let broker = backend.broker_binding(&identity);
        backend
            .kernel()
            .authorize_and_execute_classified(
                &broker.caller,
                &broker.capability,
                &broker_request(),
                |_| authority_core::kernel::EffectExecution::<(), Infallible>::Committed {
                    value: (),
                    receipt: None,
                },
            )
            .expect("host Broker root must authorize its separate typed request");
    }

    #[test]
    fn broker_binding_and_executor_preserve_the_exact_production_identity() {
        let backend = backend();
        let identity = identity();

        let binding = backend.broker_binding(&identity);
        let executor = backend.broker_executor();

        assert_eq!(
            binding.caller.as_str(),
            "broker-50505050505050505050505050505050"
        );
        assert_eq!(
            binding.capability.as_str(),
            "broker-50505050505050505050505050505050"
        );
        assert!(Arc::ptr_eq(&executor, backend.kernel()));
    }

    #[test]
    fn revoke_is_idempotent_and_closes_subject() {
        let mut backend = backend();
        let identity = identity();
        let lease = backend
            .inject_root_capability(&identity, &grant())
            .expect("root capability injection must succeed");

        backend
            .revoke_root_capability(&lease)
            .expect("first revoke must close the subject");
        backend
            .revoke_root_capability(&lease)
            .expect("repeating the exact revoke must be idempotent");
        assert_eq!(
            backend
                .kernel()
                .subject_status(&backend.broker_binding(&identity).caller)
                .expect("subject status lookup must succeed"),
            Some(SubjectStatus::Closed)
        );
        assert_eq!(
            backend
                .kernel()
                .subject_status(&AuthorityCoreBackend::guest_binding(&identity).caller)
                .expect("guest subject status lookup must succeed"),
            Some(SubjectStatus::Closed)
        );
    }

    #[test]
    fn mismatched_lease_is_rejected_before_revoke() {
        let mut backend = backend();
        let identity = identity();
        let lease = backend
            .inject_root_capability(&identity, &grant())
            .expect("root capability injection must succeed");
        let mismatched = CapabilityLease::new(
            lease.session_id(),
            lease.subject_id(),
            CapabilityId::new([0xee; ID_BYTES]),
        );

        assert!(backend.revoke_root_capability(&mismatched).is_err());
        assert_eq!(
            backend
                .kernel()
                .subject_status(&backend.broker_binding(&identity).caller)
                .expect("subject status lookup must succeed"),
            Some(SubjectStatus::Running)
        );
        backend
            .revoke_root_capability(&lease)
            .expect("the exact lease must still revoke successfully");
    }
}
