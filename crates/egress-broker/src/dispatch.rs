//! Session-bound transport dispatch.
//!
//! This module is the only path from an encoded frame to an adapter. It
//! decodes exactly one `ControlFrame`, decodes canonical CBOR, admits the
//! envelope to the per-session replay guard, reserves the session budget, and
//! performs the external effect under the capability kernel's final
//! authorization guard. Completed outcomes are cached before they are
//! returned, so an exact retry never calls an adapter again.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::{Read, Write},
    num::NonZeroUsize,
};

use authority_core::{
    capability::{AuthorityBody, CapId, Capability, CapabilityRequest, SubjectId},
    kernel::{CapabilityKernel, EffectCommitError},
    time::MonotonicTime,
};
use egress_protocol::{
    budget::{SessionBudget, SessionBudgetError, SessionBudgetLimits},
    cbor::{CanonicalBrokerRequest, CborError},
    frame::{ControlFrame, FrameError},
    operation::BrokerOperation,
    session::{
        BrokerRequestId, BrokerSessionId, EnvelopeAcceptance, EnvelopeError, SessionReplayGuard,
    },
};

use crate::{
    github::{GitHubAdapter, GitHubAdapterError, GitHubResponse},
    public_fetch::{FetchError, PublicResponse},
    transport::{FramedTransport, TransportError},
};

/// The capability and subject identity attached by the guest supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchContext {
    /// Authenticated subject that owns the capability.
    pub caller: SubjectId,
    /// Capability identity selected by the supervisor.
    pub capability: CapId,
    /// Monotonic time used by the final capability check.
    pub now: MonotonicTime,
}

/// A successful typed adapter effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerEffect {
    /// Public HTTP response with a bounded body.
    Public(PublicResponse),
    /// GitHub operation result with no credential material.
    GitHub(GitHubResponse),
}

impl BrokerEffect {
    fn response_bytes(&self) -> u64 {
        match self {
            Self::Public(response) => u64::try_from(response.body.len()).unwrap_or(u64::MAX),
            Self::GitHub(response) => response.response_bytes,
        }
    }
}

/// A typed reason retained for a rejected request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerRejection {
    /// The capability was inactive, mismatched, or revoked.
    NotAuthorized,
    /// The session budget rejected this request.
    Budget,
    /// The selected operation did not match its capability family.
    OperationMismatch,
    /// The public adapter rejected network policy or response limits.
    PublicFetch(FetchError),
    /// The GitHub adapter rejected provider policy or its typed response.
    GitHub(GitHubAdapterError),
    /// Session accounting failed after the effect completed; the session must be closed.
    AccountingInvariant,
}

/// A response retained for exact retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerResponse {
    /// Request identity to which this response belongs.
    pub request: BrokerRequestId,
    /// The first dispatch outcome, never recomputed for a retry.
    pub outcome: BrokerOutcome,
}

/// The observable result of one accepted request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerOutcome {
    /// External effect completed.
    Succeeded(BrokerEffect),
    /// External effect was not reported as successful.
    Rejected(BrokerRejection),
}

/// Why the transport could not produce a response for a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// The frame prefix/payload was not safely bounded or complete.
    Frame(FrameError),
    /// The canonical CBOR schema rejected the payload.
    Cbor(CborError),
    /// Session envelope admission failed before an outcome could be cached.
    Envelope(EnvelopeError),
    /// A new request had no cached outcome for an exact duplicate.
    MissingCachedOutcome(BrokerRequestId),
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => error.fmt(formatter),
            Self::Cbor(error) => error.fmt(formatter),
            Self::Envelope(error) => error.fmt(formatter),
            Self::MissingCachedOutcome(_) => {
                formatter.write_str("exact retry has no retained broker outcome")
            }
        }
    }
}

impl Error for DispatchError {}

/// Error returned when frame I/O and typed dispatch are combined.
#[derive(Debug)]
pub enum TransportDispatchError {
    /// The stream could not provide a complete bounded frame.
    Transport(TransportError),
    /// The complete frame failed typed dispatch.
    Dispatch(DispatchError),
}

impl fmt::Display for TransportDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Dispatch(error) => error.fmt(formatter),
        }
    }
}

impl Error for TransportDispatchError {}

/// The capability-kernel operation boundary used by the dispatcher.
pub trait CapabilityExecutor {
    /// Performs final authorization and runs `effect` while it is linearized.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError`] when authorization, kernel state, or the
    /// typed adapter effect fails.
    fn execute(
        &self,
        context: &DispatchContext,
        request: &CapabilityRequest,
        effect: &mut dyn FnMut(&Capability) -> Result<BrokerEffect, AdapterError>,
    ) -> Result<BrokerEffect, ExecutorError>;
}

/// The only adapter errors that can cross the capability executor callback.
#[derive(Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// Public fetch policy or transport failed.
    Public(FetchError),
    /// GitHub provider policy or transport failed.
    GitHub(GitHubAdapterError),
    /// A decoded operation had no matching authority family.
    OperationMismatch,
}

/// Why a capability executor did not commit the callback.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecutorError {
    /// Capability or subject was not authorized at the final check.
    NotAuthorized,
    /// The kernel state lock could not be trusted.
    LockPoisoned,
    /// The adapter failed before its effect linearization point.
    Adapter(AdapterError),
}

impl CapabilityExecutor for CapabilityKernel {
    fn execute(
        &self,
        context: &DispatchContext,
        request: &CapabilityRequest,
        effect: &mut dyn FnMut(&Capability) -> Result<BrokerEffect, AdapterError>,
    ) -> Result<BrokerEffect, ExecutorError> {
        self.authorize_and_commit(
            &context.caller,
            &context.capability,
            request,
            |capability| effect(capability),
        )
        .map_err(|error| match error {
            EffectCommitError::NotAuthorized => ExecutorError::NotAuthorized,
            EffectCommitError::LockPoisoned => ExecutorError::LockPoisoned,
            EffectCommitError::Effect(error) => ExecutorError::Adapter(error),
            EffectCommitError::Audit(_) | EffectCommitError::CommittedButAudit(_) => {
                ExecutorError::LockPoisoned
            }
        })
    }
}

/// A replay-safe, budgeted dispatcher for one broker session.
pub struct BrokerDispatcher<E, P, G> {
    executor: E,
    public_fetch: P,
    github: G,
    replay: SessionReplayGuard,
    budget: SessionBudget,
    github_response_cap: u64,
    outcomes: BTreeMap<BrokerRequestId, CachedOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedOutcome {
    Final(BrokerResponse),
    RetryableBudget(BrokerOperation),
}

impl<E, P, G> BrokerDispatcher<E, P, G>
where
    E: CapabilityExecutor,
    P: PublicDispatchAdapter,
    G: GitHubAdapter,
{
    /// Creates a dispatcher with bounded replay retention and session budget.
    #[must_use]
    pub fn new(
        executor: E,
        public_fetch: P,
        github: G,
        session: BrokerSessionId,
        replay_capacity: NonZeroUsize,
        budget_limits: SessionBudgetLimits,
        github_response_cap: u64,
    ) -> Self {
        Self {
            executor,
            public_fetch,
            github,
            replay: SessionReplayGuard::new(session, replay_capacity),
            budget: SessionBudget::new(budget_limits),
            github_response_cap: github_response_cap.min(crate::github::MAX_GITHUB_RESPONSE_BYTES),
            outcomes: BTreeMap::new(),
        }
    }

    /// Dispatches one complete length-prefixed frame.
    ///
    /// Frame and canonical-CBOR failures happen before an envelope exists and
    /// therefore return [`DispatchError`]. Every error after a new envelope is
    /// admitted becomes a cached [`BrokerOutcome::Rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] when framing, canonical decoding, or session
    /// replay admission fails before a cacheable outcome exists.
    pub fn dispatch_frame(
        &mut self,
        encoded_frame: &[u8],
        context: &DispatchContext,
    ) -> Result<BrokerResponse, DispatchError> {
        let frame = ControlFrame::decode_complete(encoded_frame).map_err(DispatchError::Frame)?;
        let request =
            CanonicalBrokerRequest::decode(frame.payload()).map_err(DispatchError::Cbor)?;
        let envelope = request.envelope();
        match self
            .replay
            .accept(envelope)
            .map_err(DispatchError::Envelope)?
        {
            EnvelopeAcceptance::Duplicate => {
                match self.outcomes.get(&envelope.request()).cloned() {
                    Some(CachedOutcome::Final(response)) => Ok(response),
                    Some(CachedOutcome::RetryableBudget(operation)) => {
                        let (response, cached) =
                            self.dispatch_new(envelope.request(), &operation, context);
                        // The same write-back as the `New` arm below. Storing
                        // only when `dispatch_new` returns `Some` would leave
                        // the entry `RetryableBudget` forever, so every later
                        // exact retry would re-enter the adapter.
                        self.outcomes.insert(
                            envelope.request(),
                            cached.unwrap_or_else(|| CachedOutcome::Final(response.clone())),
                        );
                        Ok(response)
                    }
                    None => Err(DispatchError::MissingCachedOutcome(envelope.request())),
                }
            }
            EnvelopeAcceptance::New => {
                let (response, cached) =
                    self.dispatch_new(envelope.request(), request.operation(), context);
                self.outcomes.insert(
                    envelope.request(),
                    cached.unwrap_or_else(|| CachedOutcome::Final(response.clone())),
                );
                Ok(response)
            }
        }
    }

    /// Reads one framed stream request and dispatches it through every guard.
    ///
    /// The response is returned to the caller so the connection owner can
    /// encode the project's response envelope without giving the broker a
    /// second, unbounded wire format.
    ///
    /// # Errors
    ///
    /// Returns [`TransportDispatchError`] when reading the bounded frame or
    /// dispatching its typed request fails.
    pub fn dispatch_transport<S>(
        &mut self,
        transport: &mut FramedTransport<S>,
        context: &DispatchContext,
    ) -> Result<BrokerResponse, TransportDispatchError>
    where
        S: Read + Write,
    {
        let frame = transport
            .read_frame()
            .map_err(TransportDispatchError::Transport)?;
        self.dispatch_frame(&frame.encode(), context)
            .map_err(TransportDispatchError::Dispatch)
    }

    /// Returns a copy of current budget usage for host metrics and tests.
    #[must_use]
    pub fn budget_usage(&self) -> egress_protocol::budget::SessionBudgetUsage {
        self.budget.usage()
    }

    fn dispatch_new(
        &mut self,
        request_id: BrokerRequestId,
        operation: &BrokerOperation,
        context: &DispatchContext,
    ) -> (BrokerResponse, Option<CachedOutcome>) {
        let response_cap = operation
            .public_response_byte_limit()
            .unwrap_or(self.github_response_cap);
        if let Err(error) = self.budget.start(request_id, response_cap) {
            let response = Self::rejected(request_id, BrokerRejection::Budget);
            let cached = if is_retryable_budget_error(error, self.budget.usage()) {
                Some(CachedOutcome::RetryableBudget(operation.clone()))
            } else {
                Some(CachedOutcome::Final(response.clone()))
            };
            return (response, cached);
        }
        let capability_request = operation.capability_request_at(context.now);
        let public_fetch = &self.public_fetch;
        let github = &mut self.github;
        let github_response_cap = self.github_response_cap;
        let mut effect = |capability: &Capability| {
            dispatch_adapter(
                public_fetch,
                github,
                operation,
                capability,
                request_id,
                github_response_cap,
            )
        };
        let result = self
            .executor
            .execute(context, &capability_request, &mut effect);
        match result {
            Ok(effect) => {
                if self
                    .budget
                    .complete(request_id, effect.response_bytes())
                    .is_err()
                {
                    let _ = self.budget.abort(request_id);
                    (
                        Self::rejected(request_id, BrokerRejection::AccountingInvariant),
                        None,
                    )
                } else {
                    (
                        BrokerResponse {
                            request: request_id,
                            outcome: BrokerOutcome::Succeeded(effect),
                        },
                        None,
                    )
                }
            }
            Err(error) => {
                let _ = self.budget.abort(request_id);
                (
                    Self::rejected(
                        request_id,
                        match error {
                            ExecutorError::NotAuthorized | ExecutorError::LockPoisoned => {
                                BrokerRejection::NotAuthorized
                            }
                            ExecutorError::Adapter(AdapterError::Public(error)) => {
                                BrokerRejection::PublicFetch(error)
                            }
                            ExecutorError::Adapter(AdapterError::GitHub(error)) => {
                                BrokerRejection::GitHub(error)
                            }
                            ExecutorError::Adapter(AdapterError::OperationMismatch) => {
                                BrokerRejection::OperationMismatch
                            }
                        },
                    ),
                    None,
                )
            }
        }
    }

    fn rejected(request: BrokerRequestId, rejection: BrokerRejection) -> BrokerResponse {
        BrokerResponse {
            request,
            outcome: BrokerOutcome::Rejected(rejection),
        }
    }
}

fn dispatch_adapter<P, G>(
    public_fetch: &P,
    github: &mut G,
    operation: &BrokerOperation,
    capability: &Capability,
    request_id: BrokerRequestId,
    github_response_cap: u64,
) -> Result<BrokerEffect, AdapterError>
where
    P: PublicDispatchAdapter,
    G: GitHubAdapter,
{
    match (operation, capability.authority()) {
        (BrokerOperation::PublicFetch(request), AuthorityBody::HttpFetch(authority)) => {
            public_fetch
                .fetch(request, authority)
                .map(BrokerEffect::Public)
                .map_err(AdapterError::Public)
        }
        (BrokerOperation::GitHub(request), AuthorityBody::GitHub(authority)) => github
            .execute(request_id, request, authority, github_response_cap)
            .map(BrokerEffect::GitHub)
            .map_err(AdapterError::GitHub),
        _ => Err(AdapterError::OperationMismatch),
    }
}

fn is_retryable_budget_error(
    error: SessionBudgetError,
    usage: egress_protocol::budget::SessionBudgetUsage,
) -> bool {
    match error {
        SessionBudgetError::ConcurrentRequestLimitReached => true,
        SessionBudgetError::ResponseBytesExhausted { .. } => usage.reserved_response_bytes() != 0,
        SessionBudgetError::RequestCountExhausted
        | SessionBudgetError::ReservationAlreadyActive { .. }
        | SessionBudgetError::UnknownReservation { .. }
        | SessionBudgetError::ResponseExceedsReservation { .. }
        | SessionBudgetError::AccountingInvariantBroken => false,
    }
}

/// The public-fetch adapter seam used by the dispatcher.
pub trait PublicDispatchAdapter {
    /// Executes a typed public request under the already-selected authority.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError`] when network policy, connection, redirect, or
    /// response limits reject the request.
    fn fetch(
        &self,
        request: &authority_core::http::HttpFetchRequest,
        authority: &authority_core::http::HttpFetchAuthority,
    ) -> Result<PublicResponse, FetchError>;
}

impl<R, C> PublicDispatchAdapter for crate::public_fetch::PublicFetcher<R, C>
where
    R: crate::public_fetch::Resolver,
    C: crate::public_fetch::HttpsConnector,
{
    fn fetch(
        &self,
        request: &authority_core::http::HttpFetchRequest,
        authority: &authority_core::http::HttpFetchAuthority,
    ) -> Result<PublicResponse, FetchError> {
        crate::public_fetch::PublicFetcher::fetch(self, request, authority)
    }
}

/// Returns the fixed response cap used for provider responses in tests/hosts.
#[must_use]
pub const fn default_github_response_cap() -> u64 {
    1024 * 1024
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::{IpAddr, Ipv4Addr},
        num::{NonZeroU64, NonZeroUsize},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use authority_core::{
        capability::{AuthorityBody, CapId, IssuerId, SubjectId},
        github::{GitHubAuthority, GitHubOperation, GitHubRequest},
        http::{
            CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
            HttpFetchRequest, UrlPathPattern,
        },
        kernel::CapabilityKernel,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use egress_protocol::{
        budget::SessionBudgetLimits,
        cbor::{CanonicalBrokerRequest, CborError},
        frame::ControlFrame,
        operation::BrokerOperation,
        session::{BrokerRequestId, BrokerSessionId, EnvelopeError},
    };

    use super::{
        BrokerDispatcher, BrokerEffect, BrokerOutcome, BrokerRejection, DispatchContext,
        DispatchError, default_github_response_cap,
    };
    use crate::{
        github::{GitHubAdapter, GitHubAdapterError, GitHubResponse},
        ip_policy::IpPolicy,
        public_fetch::{
            ConnectorError, ConnectorResponse, FetchPolicy, FetchTarget, HttpsConnector,
            PublicFetcher, Resolver,
        },
        transport::FramedTransport,
    };

    #[derive(Clone)]
    struct ResolverFixture;
    impl Resolver for ResolverFixture {
        fn resolve(
            &self,
            _host: &CanonicalHost,
        ) -> Result<Vec<IpAddr>, crate::public_fetch::ResolveError> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        }
    }
    struct ConnectorFixture;
    impl HttpsConnector for ConnectorFixture {
        fn send(
            &self,
            _target: &FetchTarget,
            _address: std::net::SocketAddr,
            _method: HttpFetchMethod,
            _timeout: Duration,
        ) -> Result<ConnectorResponse, ConnectorError> {
            Ok(ConnectorResponse {
                status: 200,
                location: None,
                body: Box::new(Cursor::new(b"ok".to_vec())),
            })
        }
    }
    struct MockGithub {
        calls: Arc<Mutex<u32>>,
        failure: bool,
    }
    impl GitHubAdapter for MockGithub {
        fn execute(
            &mut self,
            _request_id: BrokerRequestId,
            _request: &GitHubRequest,
            _authority: &GitHubAuthority,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubAdapterError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            if self.failure {
                Err(GitHubAdapterError::ProviderRejected)
            } else {
                Ok(GitHubResponse {
                    response_bytes: 3,
                    operation: GitHubOperation::CreatePullRequest,
                    number: Some(7),
                    object: None,
                })
            }
        }
    }

    fn kernel_and_capability() -> (CapabilityKernel, SubjectId, CapId) {
        let subject = SubjectId::new("guest");
        let operation = AuthorityBody::HttpFetch(HttpFetchAuthority::new(
            HttpFetchMethods::only(HttpFetchMethod::Get),
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            UrlPathPattern::Prefix(CanonicalUrlPath::new("/").expect("fixture path is valid")),
            32,
        ));
        let envelope = StaticAuthorityEnvelope::new(
            TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
                .expect("fixture window is valid"),
            operation.clone(),
        );
        let kernel = CapabilityKernel::new(CapabilityState::new(IssuerId::new("broker")));
        kernel
            .register_subject(Subject::new(subject.clone(), envelope))
            .expect("fixture subject registration succeeds");
        let capability = kernel
            .issue_root(CapabilityGrant::new(
                subject.clone(),
                TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
                    .expect("fixture window is valid"),
                operation,
            ))
            .expect("fixture capability issuance succeeds");
        (kernel, subject, CapId::new(capability.as_str()))
    }

    fn frame(
        session: BrokerSessionId,
        sequence: u64,
        id: u8,
        operation: BrokerOperation,
    ) -> Vec<u8> {
        ControlFrame::new(
            CanonicalBrokerRequest::new(
                session,
                sequence,
                BrokerRequestId::new([id; 16]),
                operation,
            )
            .encode()
            .expect("fixture request fits"),
        )
        .expect("fixture frame fits")
        .encode()
    }

    fn public_operation() -> BrokerOperation {
        BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
            32,
        ))
    }

    fn dispatcher_with_response_budget(
        kernel: CapabilityKernel,
        max_response_bytes: u64,
    ) -> BrokerDispatcher<
        CapabilityKernel,
        PublicFetcher<ResolverFixture, ConnectorFixture>,
        MockGithub,
    > {
        let calls = Arc::new(Mutex::new(0));
        let github = MockGithub {
            calls,
            failure: false,
        };
        BrokerDispatcher::new(
            kernel,
            PublicFetcher::new(
                ResolverFixture,
                ConnectorFixture,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            github,
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                max_response_bytes,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
            default_github_response_cap(),
        )
    }

    fn dispatcher(
        kernel: CapabilityKernel,
    ) -> BrokerDispatcher<
        CapabilityKernel,
        PublicFetcher<ResolverFixture, ConnectorFixture>,
        MockGithub,
    > {
        dispatcher_with_response_budget(kernel, 128)
    }

    // Requirement: a frame cannot bypass canonical decode, replay, budget, or capability authorization.
    // Category: integration/security. Risk: critical.
    #[test]
    fn dispatcher_runs_public_request_and_returns_cached_exact_retry() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 4, public_operation());
        let mut transport = FramedTransport::new(Cursor::new(encoded.clone()));
        let first = dispatcher
            .dispatch_transport(&mut transport, &context)
            .expect("first frame should dispatch");
        let second = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("exact retry should use cache");
        assert_eq!(first, second);
        assert!(matches!(
            first.outcome,
            BrokerOutcome::Succeeded(BrokerEffect::Public(_))
        ));
        assert_eq!(dispatcher.budget_usage().started_requests(), 1);
    }

    // Requirement: canonical CBOR rejection happens before replay, budget, or adapter access.
    // Category: protocol/security. Risk: critical.
    #[test]
    fn dispatcher_rejects_noncanonical_cbor_before_session_admission() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = ControlFrame::new(vec![0x00])
            .expect("malformed fixture frame still fits")
            .encode();
        assert!(matches!(
            dispatcher.dispatch_frame(&encoded, &context),
            Err(DispatchError::Cbor(CborError::UnexpectedMajorType { .. }))
        ));
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
    }

    // Requirement: an unauthorized operation is rejected and does not reach its adapter.
    // Category: authorization/negative. Risk: critical.
    #[test]
    fn dispatcher_caches_capability_rejection_without_external_effect() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let operation = BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("other.example").expect("fixture host is valid"),
            CanonicalUrlPath::new("/").expect("fixture path is valid"),
            32,
        ));
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 5, operation);
        let response = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("rejection is a cached response");
        assert_eq!(
            response.outcome,
            BrokerOutcome::Rejected(BrokerRejection::NotAuthorized)
        );
        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("retry uses rejection cache"),
            response
        );
    }

    // Requirement: a session ID cannot be rebound to a different connection.
    // Category: session/security. Risk: critical.
    #[test]
    fn dispatcher_rejects_session_rebinding_before_budget_or_adapter() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([9; 16]), 0, 6, public_operation());
        assert!(matches!(
            dispatcher.dispatch_frame(&encoded, &context),
            Err(DispatchError::Envelope(EnvelopeError::WrongSession { .. }))
        ));
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
    }

    // Requirement: a request ID cannot be rebound to a different canonical operation.
    // Category: session/security. Risk: critical.
    #[test]
    fn dispatcher_rejects_request_id_rebinding_after_first_acceptance() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let first = frame(BrokerSessionId::new([1; 16]), 0, 7, public_operation());
        dispatcher
            .dispatch_frame(&first, &context)
            .expect("first request should dispatch");
        let rebound = frame(
            BrokerSessionId::new([1; 16]),
            1,
            7,
            BrokerOperation::PublicFetch(HttpFetchRequest::new(
                HttpFetchMethod::Get,
                CanonicalHost::new("public.example").expect("fixture host is valid"),
                CanonicalUrlPath::new("/other").expect("fixture path is valid"),
                32,
            )),
        );
        assert!(matches!(
            dispatcher.dispatch_frame(&rebound, &context),
            Err(DispatchError::Envelope(
                EnvelopeError::RequestIdentityMismatch { .. }
            ))
        ));
    }

    // Requirement: the session response budget rejects requests before external I/O.
    // Category: resource/security. Risk: high.
    #[test]
    fn dispatcher_caches_budget_rejection_before_adapter() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher_with_response_budget(kernel, 16);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 8, public_operation());
        let first = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("budget rejection should be a cached response");
        assert_eq!(
            first.outcome,
            BrokerOutcome::Rejected(BrokerRejection::Budget)
        );
        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("budget rejection retry should be cached"),
            first
        );
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
    }

    // Requirement: a transient budget denial must be retryable after the blocking reservation ends.
    // Category: state transition/security/resource. Risk: high.
    #[test]
    fn dispatcher_retries_transient_budget_denial_without_double_charging() {
        let (kernel, subject, capability) = kernel_and_capability();
        let mut dispatcher = dispatcher(kernel);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let blocker = BrokerRequestId::new([200; 16]);
        dispatcher
            .budget
            .start(blocker, 32)
            .expect("test blocker should reserve the concurrency slot");
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 9, public_operation());

        let first = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("transient budget denial should be an outcome");
        assert_eq!(
            first.outcome,
            BrokerOutcome::Rejected(BrokerRejection::Budget)
        );
        assert_eq!(dispatcher.budget_usage().started_requests(), 1);

        dispatcher
            .budget
            .abort(blocker)
            .expect("test blocker should release its reservation");
        let second = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("exact retry should re-evaluate the released budget");
        assert!(matches!(
            second.outcome,
            BrokerOutcome::Succeeded(BrokerEffect::Public(_))
        ));
        assert_eq!(dispatcher.budget_usage().started_requests(), 2);

        // The retry that resolved the transient denial must replace the cached
        // `RetryableBudget` entry. Otherwise every later exact retry re-enters
        // the adapter, which for `CreatePullRequest` is one pull request each.
        let third = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("a settled retry should be served from the cache");
        assert_eq!(third.outcome, second.outcome);
        assert_eq!(
            dispatcher.budget_usage().started_requests(),
            2,
            "a settled outcome must not start another request"
        );
    }
}
