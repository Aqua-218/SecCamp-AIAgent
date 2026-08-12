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
    path::Path,
    sync::Arc,
};

use authority_core::{
    capability::{AuthorityBody, CapId, Capability, CapabilityRequest, SubjectId},
    kernel::{CapabilityKernel, EffectCommitError, EffectExecution},
    time::MonotonicTime,
};
use egress_protocol::{
    budget::{SessionBudget, SessionBudgetError, SessionBudgetLimits},
    cbor::{CanonicalBrokerRequest, CborError},
    frame::{ControlFrame, FrameError},
    operation::BrokerOperation,
    response::{
        BrokerWireOutcome, BrokerWireRejection, CanonicalBrokerResponse, MAX_PUBLIC_WIRE_BODY_BYTES,
    },
    session::{
        BrokerRequestId, BrokerSessionId, EnvelopeAcceptance, EnvelopeError, PayloadHash,
        SessionReplayGuard,
    },
};

use crate::{
    durable::{
        BudgetSettlement, DurableAcceptance, DurableBrokerWal, DurableRequestPhase,
        DurableSessionConfig, DurableWalError,
    },
    github::{GitHubAdapter, GitHubAdapterError, GitHubResponse, GitObjectId},
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
            Self::Public(response) => u64::try_from(response.body().len()).unwrap_or(u64::MAX),
            Self::GitHub(response) => response.response_bytes(),
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
    /// The attempt could not be journaled, so no external effect was attempted.
    AuditUnavailable,
    /// The external effect committed but its terminal audit record was not
    /// persisted. The effect may exist at the provider and must be reconciled.
    CommittedButUnrecorded,
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
    /// Durable replay state could not be trusted; the dispatcher is sealed.
    DurableUnavailable,
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
            Self::DurableUnavailable => {
                formatter.write_str("durable broker state is unavailable; dispatcher is sealed")
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
        effect: &mut dyn FnMut(&Capability) -> EffectExecution<BrokerEffect, AdapterError>,
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
    /// The attempt could not be journaled; the executor was never called.
    AuditUnavailable,
    /// The executor reported success but the terminal receipt was not
    /// persisted. The external effect may already exist.
    CommittedButUnrecorded,
    /// The adapter failed before its effect linearization point.
    Adapter(AdapterError),
}

impl CapabilityExecutor for CapabilityKernel {
    fn execute(
        &self,
        context: &DispatchContext,
        request: &CapabilityRequest,
        effect: &mut dyn FnMut(&Capability) -> EffectExecution<BrokerEffect, AdapterError>,
    ) -> Result<BrokerEffect, ExecutorError> {
        self.authorize_and_execute_classified(
            &context.caller,
            &context.capability,
            request,
            |capability| effect(capability),
        )
        .map_err(|error| match error {
            EffectCommitError::NotAuthorized => ExecutorError::NotAuthorized,
            EffectCommitError::LockPoisoned => ExecutorError::LockPoisoned,
            EffectCommitError::Effect(error) => ExecutorError::Adapter(error),
            EffectCommitError::Audit(_) => ExecutorError::AuditUnavailable,
            EffectCommitError::CommittedButAudit(_) => ExecutorError::CommittedButUnrecorded,
            EffectCommitError::CommitUnknown | EffectCommitError::CommitUnknownAndAudit(_) => {
                ExecutorError::CommittedButUnrecorded
            }
        })
    }
}

impl CapabilityExecutor for Arc<CapabilityKernel> {
    fn execute(
        &self,
        context: &DispatchContext,
        request: &CapabilityRequest,
        effect: &mut dyn FnMut(&Capability) -> EffectExecution<BrokerEffect, AdapterError>,
    ) -> Result<BrokerEffect, ExecutorError> {
        <CapabilityKernel as CapabilityExecutor>::execute(self, context, request, effect)
    }
}

/// A replay-safe, budgeted dispatcher for one broker session.
pub struct BrokerDispatcher<E, P, G> {
    executor: E,
    public_fetch: P,
    github: G,
    replay: Option<SessionReplayGuard>,
    budget: SessionBudget,
    github_response_cap: u64,
    outcomes: BTreeMap<BrokerRequestId, CachedOutcome>,
    durable: Option<DurableBrokerWal>,
    sealed: bool,
    session: BrokerSessionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedOutcome {
    AcceptedPending { response_cap: u64 },
    Final(BrokerResponse),
    RetryableBudget,
}

impl<E, P, G> BrokerDispatcher<E, P, G>
where
    E: CapabilityExecutor,
    P: PublicDispatchAdapter,
    G: GitHubAdapter,
{
    /// Creates a non-durable dispatcher for tests and development harnesses.
    ///
    /// Production callers requiring process-crash replay safety must use
    /// [`Self::new_durable`] or [`Self::open_durable`].
    #[must_use]
    pub fn new_in_memory(
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
            replay: Some(SessionReplayGuard::new(session, replay_capacity)),
            budget: SessionBudget::new(budget_limits),
            github_response_cap: github_response_cap.min(crate::github::MAX_GITHUB_RESPONSE_BYTES),
            outcomes: BTreeMap::new(),
            durable: None,
            sealed: false,
            session,
        }
    }

    /// Creates a fresh process-crash-safe dispatcher and exclusively owns its WAL.
    ///
    /// The session record and containing directory are synced before this
    /// constructor returns. The WAL path must not already exist.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] when the WAL cannot be created and synced.
    pub fn new_durable(
        executor: E,
        public_fetch: P,
        github: G,
        config: DurableSessionConfig,
        github_response_cap: u64,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, DurableWalError> {
        let wal = DurableBrokerWal::create(wal_path, config)?;
        Ok(Self {
            executor,
            public_fetch,
            github,
            replay: None,
            budget: SessionBudget::new(config.budget_limits()),
            github_response_cap: github_response_cap.min(crate::github::MAX_GITHUB_RESPONSE_BYTES),
            outcomes: BTreeMap::new(),
            durable: Some(wal),
            sealed: false,
            session: config.session(),
        })
    }

    /// Reopens and fully recovers a process-crash-safe dispatcher.
    ///
    /// Final canonical responses, accepted-pending crash markers, retryable
    /// budget phases, counters, and active reservations are reconstructed
    /// before any new frame can be dispatched.
    ///
    /// # Errors
    ///
    /// Returns [`DurableWalError`] for lock contention, corruption, an
    /// unexpected session/configuration, or an unreconstructable outcome.
    pub fn open_durable(
        executor: E,
        public_fetch: P,
        github: G,
        config: DurableSessionConfig,
        github_response_cap: u64,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, DurableWalError> {
        let wal = DurableBrokerWal::open(wal_path, config)?;
        let view = wal.read_only_view()?;
        let budget = view.restore_budget()?;
        let mut outcomes = BTreeMap::new();
        for request in view.requests() {
            let cached = match request.phase() {
                DurableRequestPhase::AcceptedPending => CachedOutcome::AcceptedPending {
                    response_cap: request.response_cap(),
                },
                DurableRequestPhase::RetryableBudget => CachedOutcome::RetryableBudget,
                DurableRequestPhase::Final(canonical) => {
                    CachedOutcome::Final(broker_response_from_wire(canonical.response())?)
                }
            };
            outcomes.insert(request.request(), cached);
        }
        Ok(Self {
            executor,
            public_fetch,
            github,
            replay: None,
            budget,
            github_response_cap: github_response_cap.min(crate::github::MAX_GITHUB_RESPONSE_BYTES),
            outcomes,
            durable: Some(wal),
            sealed: false,
            session: config.session(),
        })
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
        self.dispatch_control_frame(&frame, context)
    }

    /// Dispatches a frame the transport already bounded and validated.
    ///
    /// Callers that hold a [`ControlFrame`] use this rather than re-encoding it
    /// for [`Self::dispatch_frame`]: that round trip copies up to 1 MiB twice
    /// and routes the production path through `decode_complete`, which is meant
    /// for buffered inputs and does not reproduce the transport's
    /// check-before-allocate order.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] when canonical decoding or session replay
    /// admission fails before a cacheable outcome exists.
    pub fn dispatch_control_frame(
        &mut self,
        frame: &ControlFrame,
        context: &DispatchContext,
    ) -> Result<BrokerResponse, DispatchError> {
        if self.sealed {
            return Err(DispatchError::DurableUnavailable);
        }
        let request =
            CanonicalBrokerRequest::decode(frame.payload()).map_err(DispatchError::Cbor)?;
        let envelope = request.envelope();
        let request_id = envelope.request();
        let response_cap = self.operation_response_cap(request.operation());
        let had_retained_outcome = self.outcomes.contains_key(&request_id);
        let acceptance = self.admit(envelope, response_cap, had_retained_outcome)?;
        if acceptance == EnvelopeAcceptance::New && self.durable.is_some() {
            self.outcomes
                .insert(request_id, CachedOutcome::AcceptedPending { response_cap });
        } else if acceptance == EnvelopeAcceptance::New && had_retained_outcome {
            // A pending cache entry can predate replay admission when the
            // original call was interrupted between the two transitions.
            // Conservatively terminate it without running an external effect.
            return self.recover_accepted_pending(request_id, response_cap);
        }
        match acceptance {
            EnvelopeAcceptance::Duplicate => match self.outcomes.get(&request_id).cloned() {
                Some(CachedOutcome::AcceptedPending { response_cap }) => {
                    self.recover_accepted_pending(request_id, response_cap)
                }
                Some(CachedOutcome::Final(response)) => Ok(response),
                Some(CachedOutcome::RetryableBudget) => {
                    let (response, cached) = self.dispatch_new(
                        request_id,
                        request.operation(),
                        envelope.payload_hash(),
                        context,
                        true,
                    )?;
                    self.outcomes.insert(
                        request_id,
                        cached.unwrap_or_else(|| CachedOutcome::Final(response.clone())),
                    );
                    Ok(response)
                }
                None => Err(DispatchError::MissingCachedOutcome(request_id)),
            },
            EnvelopeAcceptance::New => {
                let (response, cached) = self.dispatch_new(
                    request_id,
                    request.operation(),
                    envelope.payload_hash(),
                    context,
                    false,
                )?;
                self.outcomes.insert(
                    request_id,
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
        self.dispatch_control_frame(&frame, context)
            .map_err(TransportDispatchError::Dispatch)
    }

    /// Returns a copy of current budget usage for host metrics and tests.
    #[must_use]
    pub fn budget_usage(&self) -> egress_protocol::budget::SessionBudgetUsage {
        self.budget.usage()
    }

    fn admit(
        &mut self,
        envelope: egress_protocol::session::BrokerEnvelope,
        response_cap: u64,
        had_retained_outcome: bool,
    ) -> Result<EnvelopeAcceptance, DispatchError> {
        if let Some(wal) = self.durable.as_mut() {
            if envelope.session() != self.session {
                return Err(DispatchError::Envelope(EnvelopeError::WrongSession {
                    expected: self.session,
                    received: envelope.session(),
                }));
            }
            return match wal.accept(envelope, response_cap) {
                Ok(DurableAcceptance::New) => Ok(EnvelopeAcceptance::New),
                Ok(DurableAcceptance::ExactDuplicate(_)) => Ok(EnvelopeAcceptance::Duplicate),
                Err(DurableWalError::OutOfOrderSequence { expected, received }) => {
                    Err(DispatchError::Envelope(EnvelopeError::OutOfOrderSequence {
                        expected,
                        received,
                    }))
                }
                Err(DurableWalError::RequestIdentityMismatch { request }) => Err(
                    DispatchError::Envelope(EnvelopeError::RequestIdentityMismatch { request }),
                ),
                Err(DurableWalError::RequestCapacityExhausted) => Err(DispatchError::Envelope(
                    EnvelopeError::RequestCapacityExhausted,
                )),
                Err(DurableWalError::SequenceExhausted) => {
                    Err(DispatchError::Envelope(EnvelopeError::SequenceExhausted))
                }
                Err(_) => {
                    self.sealed = true;
                    Err(DispatchError::DurableUnavailable)
                }
            };
        }
        if !had_retained_outcome {
            self.outcomes.insert(
                envelope.request(),
                CachedOutcome::AcceptedPending { response_cap },
            );
        }
        let Some(replay) = self.replay.as_mut() else {
            self.sealed = true;
            return Err(DispatchError::DurableUnavailable);
        };
        match replay.accept(envelope) {
            Ok(acceptance) => Ok(acceptance),
            Err(error) => {
                if !had_retained_outcome {
                    self.outcomes.remove(&envelope.request());
                }
                Err(DispatchError::Envelope(error))
            }
        }
    }

    fn dispatch_new(
        &mut self,
        request_id: BrokerRequestId,
        operation: &BrokerOperation,
        payload_hash: PayloadHash,
        context: &DispatchContext,
        resuming_retryable_budget: bool,
    ) -> Result<(BrokerResponse, Option<CachedOutcome>), DispatchError> {
        if operation
            .public_response_byte_limit()
            .is_some_and(|limit| limit > MAX_PUBLIC_WIRE_BODY_BYTES)
        {
            let response = Self::rejected(
                request_id,
                BrokerRejection::PublicFetch(FetchError::OperationRejected),
            );
            self.finalize_durable(&response, BudgetSettlement::NotStarted)?;
            return Ok((response, None));
        }
        let response_cap = self.operation_response_cap(operation);
        let budget_start = if let Some(wal) = self.durable.as_mut() {
            match wal.reserve(request_id) {
                Ok(()) => match self.budget.start(request_id, response_cap) {
                    Ok(_) => Ok(()),
                    Err(_) => return Err(self.seal_durable()),
                },
                Err(DurableWalError::Budget(error)) => Err(error),
                Err(_) => return Err(self.seal_durable()),
            }
        } else {
            self.budget.start(request_id, response_cap).map(|_| ())
        };
        if let Err(error) = budget_start {
            let response = Self::rejected(request_id, BrokerRejection::Budget);
            let cached = if is_retryable_budget_error(error, self.budget.usage()) {
                if !resuming_retryable_budget
                    && let Some(wal) = self.durable.as_mut()
                    && wal.mark_retryable_budget(request_id).is_err()
                {
                    return Err(self.seal_durable());
                }
                Some(CachedOutcome::RetryableBudget)
            } else {
                self.finalize_durable(&response, BudgetSettlement::NotStarted)?;
                Some(CachedOutcome::Final(response.clone()))
            };
            return Ok((response, cached));
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
                payload_hash,
                github_response_cap,
            )
        };
        let result = self
            .executor
            .execute(context, &capability_request, &mut effect);
        match result {
            Ok(effect) => {
                let response_bytes = effect.response_bytes();
                let response = BrokerResponse {
                    request: request_id,
                    outcome: BrokerOutcome::Succeeded(effect),
                };
                self.finalize_durable(&response, BudgetSettlement::Complete { response_bytes })?;
                if self.budget.complete(request_id, response_bytes).is_err() {
                    if self.durable.is_some() {
                        self.sealed = true;
                        Err(DispatchError::DurableUnavailable)
                    } else {
                        let _ = self.budget.abort(request_id);
                        Ok((
                            Self::rejected(request_id, BrokerRejection::AccountingInvariant),
                            None,
                        ))
                    }
                } else {
                    Ok((response, None))
                }
            }
            Err(ExecutorError::CommittedButUnrecorded) => {
                self.settle_committed_but_unrecorded(request_id, response_cap)
            }
            Err(error) => {
                let response = Self::rejected(request_id, rejection_from_executor(error));
                self.finalize_durable(&response, BudgetSettlement::Abort)?;
                let _ = self.budget.abort(request_id);
                Ok((response, None))
            }
        }
    }

    fn operation_response_cap(&self, operation: &BrokerOperation) -> u64 {
        operation
            .public_response_byte_limit()
            .unwrap_or(self.github_response_cap)
    }

    fn recover_accepted_pending(
        &mut self,
        request_id: BrokerRequestId,
        response_cap: u64,
    ) -> Result<BrokerResponse, DispatchError> {
        // Admission survived without a retained completion, so the external
        // linearization point may have been crossed. Settle any live budget
        // reservation at its full cap and never invoke the adapter again.
        if self.durable.is_none() {
            let response = Self::rejected(request_id, BrokerRejection::CommittedButUnrecorded);
            if self.budget.complete(request_id, response_cap).is_err() {
                let _ = self.budget.abort(request_id);
            }
            self.outcomes
                .insert(request_id, CachedOutcome::Final(response.clone()));
            return Ok(response);
        }
        let active = if let Some(wal) = self.durable.as_ref() {
            match wal.read_only_view() {
                Ok(view) => view
                    .request(request_id)
                    .is_some_and(|request| request.active_reservation().is_some()),
                Err(_) => return Err(self.seal_durable()),
            }
        } else {
            true
        };
        let response = Self::rejected(request_id, BrokerRejection::CommittedButUnrecorded);
        let settlement = if active {
            BudgetSettlement::Complete {
                response_bytes: response_cap,
            }
        } else {
            BudgetSettlement::NotStarted
        };
        self.finalize_durable(&response, settlement)?;
        if active && self.budget.complete(request_id, response_cap).is_err() {
            self.sealed = true;
            return Err(DispatchError::DurableUnavailable);
        }
        self.outcomes
            .insert(request_id, CachedOutcome::Final(response.clone()));
        Ok(response)
    }

    fn settle_committed_but_unrecorded(
        &mut self,
        request_id: BrokerRequestId,
        response_cap: u64,
    ) -> Result<(BrokerResponse, Option<CachedOutcome>), DispatchError> {
        // The external effect may exist at the provider. Charging any live
        // reservation at its complete cap keeps the session honest and
        // prevents those bytes from being spent twice.
        let response = Self::rejected(request_id, BrokerRejection::CommittedButUnrecorded);
        self.finalize_durable(
            &response,
            BudgetSettlement::Complete {
                response_bytes: response_cap,
            },
        )?;
        if self.budget.complete(request_id, response_cap).is_err() {
            if self.durable.is_some() {
                self.sealed = true;
                return Err(DispatchError::DurableUnavailable);
            }
            let _ = self.budget.abort(request_id);
        }
        Ok((response, None))
    }

    fn finalize_durable(
        &mut self,
        response: &BrokerResponse,
        settlement: BudgetSettlement,
    ) -> Result<(), DispatchError> {
        let Some(wal) = self.durable.as_mut() else {
            return Ok(());
        };
        let canonical = broker_response_to_wire(response);
        if wal
            .finalize(response.request, &canonical, settlement)
            .is_err()
        {
            return Err(self.seal_durable());
        }
        Ok(())
    }

    fn seal_durable(&mut self) -> DispatchError {
        self.sealed = true;
        DispatchError::DurableUnavailable
    }

    fn rejected(request: BrokerRequestId, rejection: BrokerRejection) -> BrokerResponse {
        BrokerResponse {
            request,
            outcome: BrokerOutcome::Rejected(rejection),
        }
    }
}

fn broker_response_to_wire(response: &BrokerResponse) -> CanonicalBrokerResponse {
    let outcome = match response.outcome.clone() {
        BrokerOutcome::Succeeded(BrokerEffect::Public(public)) => {
            BrokerWireOutcome::Public(public.into_wire())
        }
        BrokerOutcome::Succeeded(BrokerEffect::GitHub(github)) => {
            BrokerWireOutcome::GitHub(github.into_wire())
        }
        BrokerOutcome::Rejected(rejection) => BrokerWireOutcome::Rejected(match rejection {
            BrokerRejection::NotAuthorized => BrokerWireRejection::NotAuthorized,
            BrokerRejection::Budget => BrokerWireRejection::Budget,
            BrokerRejection::OperationMismatch => BrokerWireRejection::OperationMismatch,
            BrokerRejection::PublicFetch(_) => BrokerWireRejection::PublicFetch,
            BrokerRejection::GitHub(_) => BrokerWireRejection::GitHub,
            BrokerRejection::AccountingInvariant => BrokerWireRejection::AccountingInvariant,
            BrokerRejection::AuditUnavailable => BrokerWireRejection::AuditUnavailable,
            BrokerRejection::CommittedButUnrecorded => BrokerWireRejection::CommittedButUnrecorded,
        }),
    };
    CanonicalBrokerResponse::new(response.request, outcome)
}

fn rejection_from_executor(error: ExecutorError) -> BrokerRejection {
    match error {
        ExecutorError::NotAuthorized => BrokerRejection::NotAuthorized,
        ExecutorError::LockPoisoned | ExecutorError::AuditUnavailable => {
            BrokerRejection::AuditUnavailable
        }
        ExecutorError::CommittedButUnrecorded => {
            unreachable!("committed-but-unrecorded is handled before rejection mapping")
        }
        ExecutorError::Adapter(AdapterError::Public(error)) => BrokerRejection::PublicFetch(error),
        ExecutorError::Adapter(AdapterError::GitHub(error)) => BrokerRejection::GitHub(error),
        ExecutorError::Adapter(AdapterError::OperationMismatch) => {
            BrokerRejection::OperationMismatch
        }
    }
}

fn broker_response_from_wire(
    response: &CanonicalBrokerResponse,
) -> Result<BrokerResponse, DurableWalError> {
    let outcome = match response.outcome() {
        BrokerWireOutcome::Public(public) => BrokerOutcome::Succeeded(BrokerEffect::Public(
            PublicResponse::new(
                public.status(),
                public.host().clone(),
                public.path().clone(),
                public.body().to_vec(),
            )
            .map_err(|_| {
                DurableWalError::InvalidRecord(
                    "durable public response cannot be reconstructed".to_owned(),
                )
            })?,
        )),
        BrokerWireOutcome::GitHub(github) => {
            let object = github
                .object_id()
                .map(GitObjectId::new)
                .transpose()
                .map_err(|_| {
                    DurableWalError::InvalidRecord(
                        "durable GitHub object identity is invalid".to_owned(),
                    )
                })?;
            let response = GitHubResponse::committed(
                github.response_bytes(),
                github.operation(),
                github.pull_request_number(),
                object,
            )
            .map_err(|_| {
                DurableWalError::InvalidRecord(
                    "durable GitHub response cannot be reconstructed".to_owned(),
                )
            })?;
            BrokerOutcome::Succeeded(BrokerEffect::GitHub(response))
        }
        BrokerWireOutcome::Rejected(rejection) => BrokerOutcome::Rejected(match rejection {
            BrokerWireRejection::NotAuthorized => BrokerRejection::NotAuthorized,
            BrokerWireRejection::Budget => BrokerRejection::Budget,
            BrokerWireRejection::OperationMismatch => BrokerRejection::OperationMismatch,
            BrokerWireRejection::PublicFetch => {
                BrokerRejection::PublicFetch(FetchError::OperationRejected)
            }
            BrokerWireRejection::GitHub => {
                BrokerRejection::GitHub(GitHubAdapterError::ProviderRejected)
            }
            BrokerWireRejection::AccountingInvariant => BrokerRejection::AccountingInvariant,
            BrokerWireRejection::AuditUnavailable => BrokerRejection::AuditUnavailable,
            BrokerWireRejection::CommittedButUnrecorded => BrokerRejection::CommittedButUnrecorded,
        }),
    };
    Ok(BrokerResponse {
        request: response.request(),
        outcome,
    })
}

fn dispatch_adapter<P, G>(
    public_fetch: &P,
    github: &mut G,
    operation: &BrokerOperation,
    capability: &Capability,
    request_id: BrokerRequestId,
    payload_hash: PayloadHash,
    github_response_cap: u64,
) -> EffectExecution<BrokerEffect, AdapterError>
where
    P: PublicDispatchAdapter,
    G: GitHubAdapter,
{
    match (operation, capability.authority()) {
        (BrokerOperation::PublicFetch(request), AuthorityBody::HttpFetch(authority)) => {
            match public_fetch.fetch(request, authority) {
                Ok(response) if response.validate_dispatch(request, authority) => {
                    EffectExecution::Committed {
                        value: BrokerEffect::Public(response),
                        receipt: None,
                    }
                }
                Ok(_) => EffectExecution::FailedBeforeCommit(AdapterError::Public(
                    FetchError::InvalidResponse,
                )),
                Err(error) => EffectExecution::FailedBeforeCommit(AdapterError::Public(error)),
            }
        }
        (BrokerOperation::GitHub(request), AuthorityBody::GitHub(authority)) => {
            match github
                .execute(request_id, request, authority, github_response_cap)
                .and_then(|response| {
                    response.validate_dispatch_binding(request_id, request, github_response_cap)
                }) {
                Ok(response) => EffectExecution::Committed {
                    value: BrokerEffect::GitHub(response),
                    receipt: None,
                },
                Err(GitHubAdapterError::CommitUnknown(_)) => {
                    let mut evidence = Vec::with_capacity(1 + 16 + 32);
                    evidence.push(1);
                    evidence.extend_from_slice(request_id.as_bytes());
                    evidence.extend_from_slice(payload_hash.as_bytes());
                    EffectExecution::CommitUnknown { evidence }
                }
                Err(error) => EffectExecution::FailedBeforeCommit(AdapterError::GitHub(error)),
            }
        }
        _ => EffectExecution::FailedBeforeCommit(AdapterError::OperationMismatch),
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
        fs,
        io::Cursor,
        net::{IpAddr, Ipv4Addr},
        num::{NonZeroU64, NonZeroUsize},
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use authority_core::{
        capability::{AuthorityBody, CapId, Capability, CapabilityRequest, IssuerId, SubjectId},
        github::{
            BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
            GitHubRequest, InstallationId,
        },
        http::{
            CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
            HttpFetchRequest, UrlPathPattern,
        },
        kernel::{CapabilityKernel, EffectExecution},
        repository::RepoId,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use egress_protocol::{
        budget::SessionBudgetLimits,
        cbor::{CanonicalBrokerRequest, CborError},
        frame::ControlFrame,
        operation::BrokerOperation,
        response::MAX_PUBLIC_WIRE_BODY_BYTES,
        session::{BrokerRequestId, BrokerSessionId, EnvelopeError},
    };

    use super::{
        AdapterError, BrokerDispatcher, BrokerEffect, BrokerOutcome, BrokerRejection,
        CachedOutcome, CapabilityExecutor, DispatchContext, DispatchError, ExecutorError,
        PublicDispatchAdapter, broker_response_to_wire, default_github_response_cap,
    };
    use crate::{
        durable::{DurableBrokerWal, DurableRequestPhase, DurableSessionConfig},
        github::{
            CreatePullRequestInput, CredentialHandle, GitHubAdapter, GitHubAdapterError,
            GitHubProvider, GitHubProviderError, GitHubResponse, PublishBranchInput,
            StaticCredentialProvider, StaticPublishPlanProvider, TypedGitHubAdapter,
        },
        ip_policy::IpPolicy,
        public_fetch::{
            ConnectorError, ConnectorResponse, FetchError, FetchPolicy, FetchTarget,
            HttpsConnector, PublicFetcher, PublicResponse, Resolver,
        },
        transport::FramedTransport,
    };

    static NEXT_WAL_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestWalPath(PathBuf);

    impl TestWalPath {
        fn new(name: &str) -> Self {
            let nonce = NEXT_WAL_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "egress-dispatch-{}-{name}-{nonce}.wal",
                std::process::id()
            )))
        }
    }

    impl Drop for TestWalPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

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
            request_id: BrokerRequestId,
            request: &GitHubRequest,
            _authority: &GitHubAuthority,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubAdapterError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            if self.failure {
                Err(GitHubAdapterError::ProviderRejected)
            } else {
                GitHubResponse::committed(3, GitHubOperation::CreatePullRequest, Some(7), None)
                    .map(|response| response.bind(request_id, request))
                    .map_err(|_| GitHubAdapterError::InvalidProviderResponse)
            }
        }
    }

    struct UnboundGithub {
        calls: Arc<Mutex<u32>>,
    }

    impl GitHubAdapter for UnboundGithub {
        fn execute(
            &mut self,
            _request_id: BrokerRequestId,
            _request: &GitHubRequest,
            _authority: &GitHubAuthority,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubAdapterError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            GitHubResponse::committed(3, GitHubOperation::CreatePullRequest, Some(7), None)
                .map_err(|_| GitHubAdapterError::InvalidProviderResponse)
        }
    }

    fn kernel_and_capability() -> (CapabilityKernel, SubjectId, CapId) {
        kernel_and_capability_with_public_limit(32)
    }

    fn kernel_and_capability_with_public_limit(
        max_response_bytes: u64,
    ) -> (CapabilityKernel, SubjectId, CapId) {
        let subject = SubjectId::new("guest");
        let operation = AuthorityBody::HttpFetch(HttpFetchAuthority::new(
            HttpFetchMethods::only(HttpFetchMethod::Get),
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            UrlPathPattern::Prefix(CanonicalUrlPath::new("/").expect("fixture path is valid")),
            max_response_bytes,
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

    fn github_kernel_and_capability() -> (CapabilityKernel, SubjectId, CapId) {
        let subject = SubjectId::new("guest");
        let operation = AuthorityBody::GitHub(GitHubAuthority::new(
            InstallationId::new("install-a"),
            RepoId::new("owner/repo"),
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Exact(BranchName::new("main").expect("fixture branch is valid")),
            BranchPattern::Prefix(BranchName::new("agents").expect("fixture branch is valid")),
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
        public_operation_with_limit(32)
    }

    fn public_operation_with_limit(max_response_bytes: u64) -> BrokerOperation {
        BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
            max_response_bytes,
        ))
    }

    fn github_operation() -> BrokerOperation {
        BrokerOperation::GitHub(GitHubRequest::new(
            InstallationId::new("install-a"),
            RepoId::new("owner/repo"),
            GitHubOperation::CreatePullRequest,
            BranchName::new("main").expect("fixture branch is valid"),
            BranchName::new("agents/fix").expect("fixture branch is valid"),
        ))
    }

    struct CommitUnknownProvider {
        calls: Arc<Mutex<u32>>,
    }

    impl GitHubProvider for CommitUnknownProvider {
        fn publish_branch(
            &mut self,
            _input: &PublishBranchInput,
            _credential: CredentialHandle,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubProviderError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            Err(GitHubProviderError::CommitUnknown)
        }

        fn create_pull_request(
            &mut self,
            _input: &CreatePullRequestInput,
            _credential: CredentialHandle,
            _max_response_bytes: u64,
        ) -> Result<GitHubResponse, GitHubProviderError> {
            *self.calls.lock().expect("call mutex is not poisoned") += 1;
            Err(GitHubProviderError::CommitUnknown)
        }
    }

    /// Reports a fixed executor failure so the post-executor budget and
    /// rejection handling can be exercised without a real kernel state.
    struct FailingExecutor(fn() -> ExecutorError);
    impl CapabilityExecutor for FailingExecutor {
        fn execute(
            &self,
            _context: &DispatchContext,
            _request: &CapabilityRequest,
            _effect: &mut dyn FnMut(&Capability) -> EffectExecution<BrokerEffect, AdapterError>,
        ) -> Result<BrokerEffect, ExecutorError> {
            Err((self.0)())
        }
    }

    struct PanickingExecutor {
        calls: Arc<AtomicU32>,
    }

    impl CapabilityExecutor for PanickingExecutor {
        fn execute(
            &self,
            _context: &DispatchContext,
            _request: &CapabilityRequest,
            _effect: &mut dyn FnMut(&Capability) -> EffectExecution<BrokerEffect, AdapterError>,
        ) -> Result<BrokerEffect, ExecutorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("injected executor panic");
        }
    }

    struct PanickingPublicAdapter {
        calls: Arc<AtomicU32>,
    }

    impl PublicDispatchAdapter for PanickingPublicAdapter {
        fn fetch(
            &self,
            _request: &HttpFetchRequest,
            _authority: &HttpFetchAuthority,
        ) -> Result<PublicResponse, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("injected public adapter panic");
        }
    }

    struct FixedBodyPublicAdapter {
        calls: Arc<AtomicU32>,
        body_bytes: usize,
    }

    impl PublicDispatchAdapter for FixedBodyPublicAdapter {
        fn fetch(
            &self,
            _request: &HttpFetchRequest,
            _authority: &HttpFetchAuthority,
        ) -> Result<PublicResponse, FetchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            PublicResponse::new(
                200,
                CanonicalHost::new("public.example").expect("fixture host is valid"),
                CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
                vec![0x5a; self.body_bytes],
            )
        }
    }

    fn dispatcher_with_executor(
        executor: FailingExecutor,
    ) -> BrokerDispatcher<
        FailingExecutor,
        PublicFetcher<ResolverFixture, ConnectorFixture>,
        MockGithub,
    > {
        BrokerDispatcher::new_in_memory(
            executor,
            PublicFetcher::new(
                ResolverFixture,
                ConnectorFixture,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                128,
                NonZeroUsize::new(2).expect("fixture concurrency limit is non-zero"),
            ),
            default_github_response_cap(),
        )
    }

    fn dispatcher_with_panicking_executor(
        calls: Arc<AtomicU32>,
    ) -> BrokerDispatcher<
        PanickingExecutor,
        PublicFetcher<ResolverFixture, ConnectorFixture>,
        MockGithub,
    > {
        BrokerDispatcher::new_in_memory(
            PanickingExecutor { calls },
            PublicFetcher::new(
                ResolverFixture,
                ConnectorFixture,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                128,
                NonZeroUsize::new(2).expect("fixture concurrency limit is non-zero"),
            ),
            default_github_response_cap(),
        )
    }

    // Requirement: an effect that crossed its linearization point is never reported as a denial.
    // Category: unit/security. Risk: high.
    #[test]
    fn committed_but_unrecorded_is_distinct_and_keeps_the_reserved_bytes_charged() {
        let mut dispatcher =
            dispatcher_with_executor(FailingExecutor(|| ExecutorError::CommittedButUnrecorded));
        let context = DispatchContext {
            caller: SubjectId::new("subject"),
            capability: CapId::new("capability"),
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 9, public_operation());

        let response = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("a committed-but-unrecorded effect is an outcome, not a dispatch error");

        assert_eq!(
            response.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded),
            "an effect that may exist at the provider must not be reported as NotAuthorized"
        );
        let usage = dispatcher.budget_usage();
        assert_eq!(
            usage.reserved_response_bytes(),
            0,
            "the reservation settles"
        );
        assert_ne!(
            usage.committed_response_bytes(),
            0,
            "bytes for a committed effect must stay charged to the session"
        );
    }

    // Requirement: a post-send GitHub ambiguity is committed in the kernel but never returned as success.
    // Category: integration/security/idempotency. Risk: critical.
    #[test]
    fn github_commit_unknown_is_terminal_charged_and_exact_retry_does_not_reexecute() {
        let (kernel, subject, capability) = github_kernel_and_capability();
        let calls = Arc::new(Mutex::new(0));
        let github = TypedGitHubAdapter::new(
            CommitUnknownProvider {
                calls: calls.clone(),
            },
            StaticCredentialProvider::new(
                InstallationId::new("install-a"),
                CredentialHandle::from_host_id(1),
            ),
            StaticPublishPlanProvider::new([]),
        );
        let github_response_cap = 64;
        let mut dispatcher = BrokerDispatcher::new_in_memory(
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
                128,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
            github_response_cap,
        );
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 10, github_operation());

        let first = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("commit-unknown is a retained terminal response");
        assert_eq!(
            first.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 1);
        assert_eq!(
            dispatcher.budget_usage().committed_response_bytes(),
            github_response_cap,
            "an uncertain mutation charges its complete reservation"
        );
        assert_eq!(
            dispatcher
                .executor
                .effect_records()
                .expect("kernel audit should remain readable")
                .len(),
            0,
            "an unknown provider result must never be recorded as committed"
        );
        let attempts = dispatcher
            .executor
            .attempt_records()
            .expect("kernel audit should remain readable");
        assert_eq!(attempts.len(), 1);
        assert_eq!(
            attempts[0].outcome(),
            authority_core::audit::AttemptOutcome::CommitUnknown
        );

        let retry = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("exact retry should return the retained terminal response");
        assert_eq!(retry, first);
        assert_eq!(
            *calls.lock().expect("call mutex is not poisoned"),
            1,
            "an exact retry must not send the GitHub mutation again"
        );
        assert_eq!(dispatcher.budget_usage().started_requests(), 1);
    }

    // Requirement: a dispatcher extension cannot report success without binding the result to
    // the complete request that crossed the provider mutation boundary.
    // Category: integration/security/accounting. Risk: critical.
    #[test]
    fn unbound_github_adapter_success_is_terminal_and_charged_at_the_full_cap() {
        let (kernel, subject, capability) = github_kernel_and_capability();
        let calls = Arc::new(Mutex::new(0));
        let github_response_cap = 64;
        let mut dispatcher = BrokerDispatcher::new_in_memory(
            kernel,
            PublicFetcher::new(
                ResolverFixture,
                ConnectorFixture,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            UnboundGithub {
                calls: calls.clone(),
            },
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                128,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
            github_response_cap,
        );
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 11, github_operation());

        let first = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("an unbound post-mutation response must fail closed");
        assert_eq!(
            first.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(*calls.lock().expect("call mutex is not poisoned"), 1);
        assert_eq!(
            dispatcher.budget_usage().committed_response_bytes(),
            github_response_cap
        );

        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("the exact retry must return the retained terminal outcome"),
            first
        );
        assert_eq!(
            *calls.lock().expect("call mutex is not poisoned"),
            1,
            "binding rejection must never reopen the provider mutation"
        );
    }

    // Requirement: an unjournalable attempt is not indistinguishable from an authorization denial.
    // Category: unit/security. Risk: high.
    #[test]
    fn audit_failure_is_reported_separately_from_authorization_denial() {
        for error in [ExecutorError::AuditUnavailable, ExecutorError::LockPoisoned] {
            let make: fn() -> ExecutorError = match error {
                ExecutorError::AuditUnavailable => || ExecutorError::AuditUnavailable,
                _ => || ExecutorError::LockPoisoned,
            };
            let mut dispatcher = dispatcher_with_executor(FailingExecutor(make));
            let context = DispatchContext {
                caller: SubjectId::new("subject"),
                capability: CapId::new("capability"),
                now: MonotonicTime::from_ticks(1),
            };
            let encoded = frame(BrokerSessionId::new([1; 16]), 0, 9, public_operation());

            let response = dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("an audit failure is an outcome, not a dispatch error");

            assert_eq!(
                response.outcome,
                BrokerOutcome::Rejected(BrokerRejection::AuditUnavailable)
            );
            assert_eq!(
                dispatcher.budget_usage().committed_response_bytes(),
                0,
                "no effect ran, so nothing is charged"
            );
        }
    }

    // Requirement: an executor panic after replay admission cannot reopen the external effect.
    // Category: state transition/security/idempotency. Risk: critical.
    #[test]
    fn dispatcher_recovers_executor_panic_as_terminal_commit_unknown() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut dispatcher = dispatcher_with_panicking_executor(calls.clone());
        let context = DispatchContext {
            caller: SubjectId::new("subject"),
            capability: CapId::new("capability"),
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 13, public_operation());

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = dispatcher.dispatch_frame(&encoded, &context);
        }));
        assert!(panic.is_err(), "the injected executor panic must propagate");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(dispatcher.budget_usage().active_requests(), 1);

        let recovered = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("an exact retry should recover the retained pending state");
        assert_eq!(
            recovered.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(dispatcher.budget_usage().active_requests(), 0);
        assert_eq!(dispatcher.budget_usage().committed_response_bytes(), 32);

        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("the recovered outcome should remain terminal"),
            recovered
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // Requirement: a panic inside an authorized adapter cannot duplicate its unknown effect.
    // Category: integration/security/idempotency. Risk: critical.
    #[test]
    fn dispatcher_recovers_adapter_panic_without_reinvoking_adapter() {
        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(AtomicU32::new(0));
        let mut dispatcher = BrokerDispatcher::new_in_memory(
            kernel,
            PanickingPublicAdapter {
                calls: calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                128,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
            default_github_response_cap(),
        );
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 14, public_operation());

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = dispatcher.dispatch_frame(&encoded, &context);
        }));
        assert!(panic.is_err(), "the injected adapter panic must propagate");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let recovered = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("an exact retry should fail closed from the pending state");
        assert_eq!(
            recovered.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(dispatcher.budget_usage().active_requests(), 0);
        assert_eq!(dispatcher.budget_usage().committed_response_bytes(), 32);
    }

    // Requirement: interruption before replay mutation still cannot turn retry into new work.
    // Category: state transition/security/idempotency. Risk: critical.
    #[test]
    fn dispatcher_fails_closed_after_pre_admission_interruption() {
        let calls = Arc::new(AtomicU32::new(0));
        let mut dispatcher = dispatcher_with_panicking_executor(calls.clone());
        let context = DispatchContext {
            caller: SubjectId::new("subject"),
            capability: CapId::new("capability"),
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 15, public_operation());
        let control = ControlFrame::decode_complete(&encoded).expect("fixture frame is valid");
        let request = CanonicalBrokerRequest::decode(control.payload())
            .expect("fixture request is canonical");
        let request_id = request.envelope().request();
        let response_cap = dispatcher.operation_response_cap(request.operation());

        // This is the only state retained if the caller is interrupted after
        // the pre-admission cache write but before `replay.accept`.
        dispatcher
            .outcomes
            .insert(request_id, CachedOutcome::AcceptedPending { response_cap });

        let recovered = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("the resumed request should terminate without execution");
        assert_eq!(
            recovered.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("the exact retry should use the terminal cache"),
            recovered
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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
        BrokerDispatcher::new_in_memory(
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

    fn durable_config(max_response_bytes: u64) -> DurableSessionConfig {
        DurableSessionConfig::new(
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                max_response_bytes,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
        )
    }

    // Requirement: a completed effect survives process restart with one exact wire result.
    // Category: integration/crash-recovery/idempotency. Risk: critical.
    #[test]
    fn durable_restart_returns_exact_terminal_without_adapter_reexecution() {
        let path = TestWalPath::new("terminal");
        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(Mutex::new(0));
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 21, public_operation());
        let first = {
            let mut dispatcher = BrokerDispatcher::new_durable(
                kernel,
                PublicFetcher::new(
                    ResolverFixture,
                    ConnectorFixture,
                    IpPolicy::default(),
                    FetchPolicy::default(),
                ),
                MockGithub {
                    calls: calls.clone(),
                    failure: false,
                },
                durable_config(128),
                default_github_response_cap(),
                &path.0,
            )
            .expect("create durable dispatcher");
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("first request should dispatch")
        };
        let expected_wire = broker_response_to_wire(&first)
            .encode()
            .expect("response must have canonical wire bytes");

        let (kernel, subject, capability) = kernel_and_capability();
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: Arc::new(AtomicU32::new(0)),
            },
            MockGithub {
                calls,
                failure: false,
            },
            durable_config(128),
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen durable dispatcher");
        let retry = reopened
            .dispatch_frame(
                &encoded,
                &DispatchContext {
                    caller: subject,
                    capability,
                    now: MonotonicTime::from_ticks(1),
                },
            )
            .expect("exact retry should use durable terminal state");
        assert_eq!(retry, first);
        assert_eq!(
            broker_response_to_wire(&retry)
                .encode()
                .expect("retry must have canonical wire bytes"),
            expected_wire
        );
        assert_eq!(reopened.budget_usage().started_requests(), 1);
        assert_eq!(reopened.budget_usage().committed_response_bytes(), 2);
    }

    // Requirement: an accepted crash marker survives restart and forbids execution.
    // Category: integration/crash-recovery/idempotency. Risk: critical.
    #[test]
    fn durable_restart_seals_prebudget_pending_without_charge_or_execution() {
        let path = TestWalPath::new("pending");
        let config = durable_config(128);
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 22, public_operation());
        let control = ControlFrame::decode_complete(&encoded).expect("fixture frame is valid");
        let request = CanonicalBrokerRequest::decode(control.payload()).expect("canonical request");
        {
            let mut wal = DurableBrokerWal::create(&path.0, config).expect("create WAL");
            wal.accept(request.envelope(), 32)
                .expect("persist accepted-pending marker");
        }

        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(AtomicU32::new(0));
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen durable dispatcher");
        let terminal = reopened
            .dispatch_frame(
                &encoded,
                &DispatchContext {
                    caller: subject,
                    capability,
                    now: MonotonicTime::from_ticks(1),
                },
            )
            .expect("pending marker should recover terminally");
        assert_eq!(
            terminal.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopened.budget_usage().started_requests(), 0);
        assert_eq!(reopened.budget_usage().committed_response_bytes(), 0);
        drop(reopened);

        let (kernel, subject, capability) = kernel_and_capability();
        let mut retry_process = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen finalized recovery");
        assert_eq!(
            retry_process
                .dispatch_frame(
                    &encoded,
                    &DispatchContext {
                        caller: subject,
                        capability,
                        now: MonotonicTime::from_ticks(1),
                    }
                )
                .expect("retry should use recovered final"),
            terminal
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    // Requirement: a post-budget crash marker is terminal and conservatively full-charged.
    // Category: integration/crash-recovery/accounting. Risk: critical.
    #[test]
    fn durable_restart_seals_reserved_pending_at_full_cap_without_execution() {
        let path = TestWalPath::new("reserved-pending");
        let config = durable_config(128);
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 23, public_operation());
        let control = ControlFrame::decode_complete(&encoded).expect("fixture frame is valid");
        let request = CanonicalBrokerRequest::decode(control.payload()).expect("canonical request");
        {
            let mut wal = DurableBrokerWal::create(&path.0, config).expect("create WAL");
            wal.accept(request.envelope(), 32)
                .expect("persist accepted-pending marker");
            wal.reserve(request.envelope().request())
                .expect("persist active reservation");
        }

        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(AtomicU32::new(0));
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen durable dispatcher");
        let terminal = reopened
            .dispatch_frame(
                &encoded,
                &DispatchContext {
                    caller: subject,
                    capability,
                    now: MonotonicTime::from_ticks(1),
                },
            )
            .expect("active pending marker should recover terminally");
        assert_eq!(
            terminal.outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopened.budget_usage().started_requests(), 1);
        assert_eq!(reopened.budget_usage().active_requests(), 0);
        assert_eq!(reopened.budget_usage().committed_response_bytes(), 32);
    }

    // Requirement: a durable transient budget phase may only retry the exact re-decoded request.
    // Category: integration/crash-recovery/idempotency. Risk: high.
    #[test]
    fn durable_retryable_budget_rebinds_the_redecoded_operation_after_restart() {
        let path = TestWalPath::new("retryable-budget");
        let config = durable_config(128);
        let encoded = frame(BrokerSessionId::new([1; 16]), 0, 24, public_operation());
        let control = ControlFrame::decode_complete(&encoded).expect("fixture frame is valid");
        let request = CanonicalBrokerRequest::decode(control.payload()).expect("canonical request");
        {
            let mut wal = DurableBrokerWal::create(&path.0, config).expect("create WAL");
            wal.accept(request.envelope(), 32).expect("accept request");
            wal.mark_retryable_budget(request.envelope().request())
                .expect("persist retryable budget phase");
        }

        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(AtomicU32::new(0));
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            FixedBodyPublicAdapter {
                calls: calls.clone(),
                body_bytes: 2,
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen retryable request");
        let completed = reopened
            .dispatch_frame(
                &encoded,
                &DispatchContext {
                    caller: subject,
                    capability,
                    now: MonotonicTime::from_ticks(1),
                },
            )
            .expect("exact retry should re-evaluate available budget");
        assert!(matches!(completed.outcome, BrokerOutcome::Succeeded(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(reopened.budget_usage().started_requests(), 1);
        assert_eq!(reopened.budget_usage().committed_response_bytes(), 2);
    }

    // Requirement: repeated transient durable denials remain retryable and never seal the WAL.
    // Category: integration/crash-recovery/accounting. Risk: high.
    #[test]
    fn durable_retryable_budget_can_be_denied_repeatedly_then_succeed() {
        let path = TestWalPath::new("repeated-retryable-budget");
        let config = durable_config(128);
        let active_encoded = frame(BrokerSessionId::new([1; 16]), 0, 26, public_operation());
        let retry_encoded = frame(BrokerSessionId::new([1; 16]), 1, 27, public_operation());
        let active_control =
            ControlFrame::decode_complete(&active_encoded).expect("active frame is valid");
        let active_request =
            CanonicalBrokerRequest::decode(active_control.payload()).expect("active request");
        let retry_control =
            ControlFrame::decode_complete(&retry_encoded).expect("retry frame is valid");
        let retry_request =
            CanonicalBrokerRequest::decode(retry_control.payload()).expect("retry request");
        {
            let mut wal = DurableBrokerWal::create(&path.0, config).expect("create WAL");
            wal.accept(active_request.envelope(), 32)
                .expect("accept active request");
            wal.reserve(active_request.envelope().request())
                .expect("reserve active request");
            wal.accept(retry_request.envelope(), 32)
                .expect("accept retryable request");
            wal.mark_retryable_budget(retry_request.envelope().request())
                .expect("persist retryable phase");
        }

        let (kernel, subject, capability) = kernel_and_capability();
        let calls = Arc::new(AtomicU32::new(0));
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            FixedBodyPublicAdapter {
                calls: calls.clone(),
                body_bytes: 2,
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen durable dispatcher");
        for _ in 0..2 {
            assert_eq!(
                reopened
                    .dispatch_frame(&retry_encoded, &context)
                    .expect("transient denial remains an outcome")
                    .outcome,
                BrokerOutcome::Rejected(BrokerRejection::Budget)
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            reopened
                .dispatch_frame(&active_encoded, &context)
                .expect("active crash marker must settle")
                .outcome,
            BrokerOutcome::Rejected(BrokerRejection::CommittedButUnrecorded)
        );
        assert!(matches!(
            reopened
                .dispatch_frame(&retry_encoded, &context)
                .expect("retry should run after capacity is released")
                .outcome,
            BrokerOutcome::Succeeded(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(reopened.budget_usage().started_requests(), 2);
        assert_eq!(reopened.budget_usage().committed_response_bytes(), 34);
    }

    // Requirement: the largest public response survives as one exact canonical chunk sequence.
    // Category: integration/boundary/crash-recovery. Risk: critical.
    #[test]
    fn durable_max_public_response_reopens_with_exact_chunk_payloads() {
        let path = TestWalPath::new("maximum-chunked-response");
        let maximum = usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("public response cap fits this platform");
        let config = durable_config(MAX_PUBLIC_WIRE_BODY_BYTES);
        let (kernel, subject, capability) =
            kernel_and_capability_with_public_limit(MAX_PUBLIC_WIRE_BODY_BYTES);
        let calls = Arc::new(AtomicU32::new(0));
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(
            BrokerSessionId::new([1; 16]),
            0,
            25,
            public_operation_with_limit(MAX_PUBLIC_WIRE_BODY_BYTES),
        );
        let expected_wire_payloads = {
            let mut dispatcher = BrokerDispatcher::new_durable(
                kernel,
                FixedBodyPublicAdapter {
                    calls: calls.clone(),
                    body_bytes: maximum,
                },
                MockGithub {
                    calls: Arc::new(Mutex::new(0)),
                    failure: false,
                },
                config,
                default_github_response_cap(),
                &path.0,
            )
            .expect("create durable dispatcher");
            let response = dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("maximum response should dispatch");
            let wal = dispatcher.durable.as_ref().expect("durable WAL exists");
            let view = wal.read_only_view().expect("read durable view");
            let request = view
                .request(response.request)
                .expect("terminal request is retained");
            let DurableRequestPhase::Final(canonical) = request.phase() else {
                panic!("maximum response must be terminal");
            };
            assert!(canonical.wire_payloads().len() > 1);
            canonical.wire_payloads().to_vec()
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (kernel, subject, capability) =
            kernel_and_capability_with_public_limit(MAX_PUBLIC_WIRE_BODY_BYTES);
        let reopened_calls = Arc::new(AtomicU32::new(0));
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: reopened_calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen maximum response");
        let retry = reopened
            .dispatch_frame(
                &encoded,
                &DispatchContext {
                    caller: subject,
                    capability,
                    now: MonotonicTime::from_ticks(1),
                },
            )
            .expect("retry should use durable terminal");
        assert_eq!(reopened_calls.load(Ordering::SeqCst), 0);
        let reopened_wire_payloads = reopened
            .durable
            .as_ref()
            .expect("durable WAL exists")
            .read_only_view()
            .expect("read reopened view")
            .request(retry.request)
            .and_then(|request| match request.phase() {
                DurableRequestPhase::Final(canonical) => Some(canonical.wire_payloads().to_vec()),
                _ => None,
            })
            .expect("reopened final response exists");
        assert_eq!(reopened_wire_payloads, expected_wire_payloads);
        assert_eq!(
            reopened.budget_usage().committed_response_bytes(),
            MAX_PUBLIC_WIRE_BODY_BYTES
        );
    }

    // Requirement: max+1 is a small durable terminal rejection before any adapter/effect.
    // Category: integration/boundary/crash-recovery. Risk: critical.
    #[test]
    fn durable_public_response_cap_max_plus_one_reopens_as_exact_rejection() {
        let path = TestWalPath::new("maximum-plus-one");
        let oversized = MAX_PUBLIC_WIRE_BODY_BYTES + 1;
        let config = durable_config(oversized);
        let (kernel, subject, capability) = kernel_and_capability_with_public_limit(oversized);
        let calls = Arc::new(AtomicU32::new(0));
        let encoded = frame(
            BrokerSessionId::new([1; 16]),
            0,
            28,
            public_operation_with_limit(oversized),
        );
        let terminal = {
            let mut dispatcher = BrokerDispatcher::new_durable(
                kernel,
                FixedBodyPublicAdapter {
                    calls: calls.clone(),
                    body_bytes: 0,
                },
                MockGithub {
                    calls: Arc::new(Mutex::new(0)),
                    failure: false,
                },
                config,
                default_github_response_cap(),
                &path.0,
            )
            .expect("create durable dispatcher");
            let response = dispatcher
                .dispatch_frame(
                    &encoded,
                    &DispatchContext {
                        caller: subject,
                        capability,
                        now: MonotonicTime::from_ticks(1),
                    },
                )
                .expect("oversized admission is a terminal response");
            assert_eq!(dispatcher.budget_usage().started_requests(), 0);
            response
        };
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            terminal.outcome,
            BrokerOutcome::Rejected(BrokerRejection::PublicFetch(FetchError::OperationRejected))
        );

        let (kernel, subject, capability) = kernel_and_capability_with_public_limit(oversized);
        let mut reopened = BrokerDispatcher::open_durable(
            kernel,
            PanickingPublicAdapter {
                calls: calls.clone(),
            },
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            config,
            default_github_response_cap(),
            &path.0,
        )
        .expect("reopen durable dispatcher");
        assert_eq!(
            reopened
                .dispatch_frame(
                    &encoded,
                    &DispatchContext {
                        caller: subject,
                        capability,
                        now: MonotonicTime::from_ticks(1),
                    }
                )
                .expect("retry should return durable rejection"),
            terminal
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(reopened.budget_usage().started_requests(), 0);
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

    // Requirement: production workers can share the authority backend's exact kernel instance.
    // Category: integration/authorization. Risk: critical.
    #[test]
    fn arc_kernel_executor_delegates_to_the_shared_kernel() {
        let (kernel, subject, capability) = kernel_and_capability();
        let kernel = Arc::new(kernel);
        let mut dispatcher = BrokerDispatcher::new_in_memory(
            Arc::clone(&kernel),
            PublicFetcher::new(
                ResolverFixture,
                ConnectorFixture,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            MockGithub {
                calls: Arc::new(Mutex::new(0)),
                failure: false,
            },
            BrokerSessionId::new([1; 16]),
            NonZeroUsize::new(8).expect("fixture capacity is non-zero"),
            SessionBudgetLimits::new(
                NonZeroU64::new(4).expect("fixture request limit is non-zero"),
                128,
                NonZeroUsize::new(1).expect("fixture concurrency limit is non-zero"),
            ),
            default_github_response_cap(),
        );
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };

        let response = dispatcher
            .dispatch_frame(
                &frame(BrokerSessionId::new([1; 16]), 0, 16, public_operation()),
                &context,
            )
            .expect("the shared kernel must authorize the bound request");

        assert!(matches!(
            response.outcome,
            BrokerOutcome::Succeeded(BrokerEffect::Public(_))
        ));
        assert_eq!(
            kernel
                .effect_records()
                .expect("the shared kernel audit must remain readable")
                .len(),
            1,
            "dispatch must record the effect in the exact shared kernel"
        );
    }

    // Requirement: the largest encodable public response cap is admitted before adapter execution.
    // Category: boundary/resource. Risk: critical.
    #[test]
    fn dispatcher_admits_exact_public_wire_body_limit() {
        let (kernel, subject, capability) =
            kernel_and_capability_with_public_limit(MAX_PUBLIC_WIRE_BODY_BYTES);
        let mut dispatcher = dispatcher_with_response_budget(kernel, MAX_PUBLIC_WIRE_BODY_BYTES);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(
            BrokerSessionId::new([1; 16]),
            0,
            11,
            public_operation_with_limit(MAX_PUBLIC_WIRE_BODY_BYTES),
        );

        let response = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("the exact wire body limit should be admitted");

        assert!(matches!(
            response.outcome,
            BrokerOutcome::Succeeded(BrokerEffect::Public(_))
        ));
        assert_eq!(dispatcher.budget_usage().started_requests(), 1);
    }

    // Requirement: an unencodable public response cap is rejected and cached before any effect.
    // Category: boundary/security/resource. Risk: critical.
    #[test]
    fn dispatcher_rejects_public_wire_body_limit_plus_one_before_effect() {
        let oversized = MAX_PUBLIC_WIRE_BODY_BYTES + 1;
        let (kernel, subject, capability) = kernel_and_capability_with_public_limit(oversized);
        let mut dispatcher = dispatcher_with_response_budget(kernel, oversized);
        let context = DispatchContext {
            caller: subject,
            capability,
            now: MonotonicTime::from_ticks(1),
        };
        let encoded = frame(
            BrokerSessionId::new([1; 16]),
            0,
            12,
            public_operation_with_limit(oversized),
        );

        let first = dispatcher
            .dispatch_frame(&encoded, &context)
            .expect("wire admission rejection should be a cacheable outcome");
        assert_eq!(
            first.outcome,
            BrokerOutcome::Rejected(BrokerRejection::PublicFetch(FetchError::OperationRejected))
        );
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
        assert!(
            dispatcher
                .executor
                .effect_records()
                .expect("kernel audit should remain readable")
                .is_empty(),
            "wire admission must reject before kernel effect execution"
        );
        assert_eq!(
            dispatcher
                .dispatch_frame(&encoded, &context)
                .expect("exact retry should use the admission rejection cache"),
            first
        );
        assert_eq!(dispatcher.budget_usage().started_requests(), 0);
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
