//! Emits proof-free runtime observations from the public Rust state-machine APIs.

use std::{
    collections::VecDeque,
    convert::Infallible,
    env, fs,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use authority_core::{
    audit::{AttemptId, AttemptOutcome},
    capability::{AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId},
    durable_audit::{DurableAuditLog, DurableAuditView},
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    kernel::{CapabilityKernel, CapabilityKernelError, EffectCommitError, EffectExecution},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        CapabilityGrant, CapabilityState, CapabilityStateError, RevocationStatus,
        StaticAuthorityEnvelope, Subject,
    },
    time::{MonotonicTime, TimeWindow},
};
use egress_broker::durable::{
    BudgetSettlement, DurableAcceptance, DurableBrokerWal, DurableBudgetSnapshot,
    DurableRequestPhase, DurableSessionConfig,
};
use egress_protocol::{
    budget::SessionBudgetLimits,
    response::{
        BrokerWireOutcome, CanonicalBrokerResponse, CanonicalResponseChunk, PublicWireResponse,
    },
    session::{BrokerEnvelope, BrokerRequestId, BrokerSessionId},
};
use session_orchestrator::{
    BackendError, BrokerBackend, BrokerLease, CapabilityBackend, CapabilityLease,
    CapabilityRevocationBackend, CryptographicRandom, EntropyError, ID_BYTES,
    InMemoryIdentityLedger, LifecycleState, SessionIdentity, SessionOrchestrator,
    SnapshotDescriptor, SnapshotId, VmBackend, VmLease, WorkloadBackend, WorkloadLease,
    WorkspaceBackend, WorkspaceLease, WorkspaceTemplateId,
    session_owner::{
        BrokerRuntimeStatus, BrokerStatusBackend, OwnerPollOutcome, OwnerPollRequest,
        SessionBackends, SessionOwner, ShutdownReason,
    },
};

const CORPUS_HEADER: &str = "# authority-runtime-corpus-v1";
const RESPONSE_CAP: u64 = 1_100_000;
const AUTHORITY_OBSERVATION_TIME: MonotonicTime = MonotonicTime::from_ticks(1);

fn checked<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> Result<T, String> {
    result.map_err(|error| format!("{context}: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn active_flag(
    kernel: &CapabilityKernel,
    caller: &SubjectId,
    capability: &CapId,
) -> Result<u8, String> {
    match kernel.with_active_capability(caller, capability, AUTHORITY_OBSERVATION_TIME, |_| {
        Ok::<_, Infallible>(())
    }) {
        Ok(()) => Ok(1),
        Err(authority_core::kernel::CapabilityInspectionError::NotActive) => Ok(0),
        Err(error) => Err(format!("inspect authority snapshot: {error}")),
    }
}

struct AuthorityFixture {
    audit: TemporaryWal,
    kernel: CapabilityKernel,
    subject: SubjectId,
    foreign: SubjectId,
    capability: CapId,
}

fn authority_fixture() -> Result<AuthorityFixture, String> {
    let audit = TemporaryWal::new("authority-audit")?;
    let subject = SubjectId::new("runtime-subject");
    let foreign = SubjectId::new("foreign-subject");
    let capability = CapId::new("runtime-capability");
    let validity = checked(
        TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10)),
        "construct authority validity window",
    )?;
    let authority = AuthorityBody::File(FileAuthority::new(
        RepoId::new("runtime-repository"),
        FileEffects::only(FileEffect::ReadData),
        PathPattern::Prefix(CanonicalPath::root()),
    ));
    let durable_audit = checked(
        DurableAuditLog::create(&audit.path),
        "create authority durable audit",
    )?;
    let kernel = checked(
        CapabilityKernel::try_new_with_durable_audit(
            CapabilityState::new(IssuerId::new("runtime-corpus")),
            durable_audit,
        ),
        "attach authority durable audit",
    )?;
    checked(
        kernel.register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(validity, authority.clone()),
        )),
        "register runtime corpus subject",
    )?;
    checked(
        kernel.issue_root_with_id(
            capability.clone(),
            CapabilityGrant::new(subject.clone(), validity, authority),
        ),
        "issue runtime corpus capability",
    )?;
    Ok(AuthorityFixture {
        audit,
        kernel,
        subject,
        foreign,
        capability,
    })
}

struct AuthorityCheckpoint {
    row: String,
    epoch: u64,
    active: u8,
    next_attempt: u64,
    effect_count: usize,
}

fn execute_commit_unknown(
    fixture: &AuthorityFixture,
    request: &CapabilityRequest,
) -> Result<(AttemptId, Vec<u8>), String> {
    let classified: Result<(), EffectCommitError<&'static str>> = fixture
        .kernel
        .authorize_and_execute_classified(&fixture.subject, &fixture.capability, request, |_| {
            EffectExecution::CommitUnknown {
                evidence: b"runtime-corpus-provider-timeout".to_vec(),
            }
        });
    match classified {
        Err(EffectCommitError::CommitUnknown {
            attempt_id,
            evidence,
        }) if evidence.as_slice() == b"runtime-corpus-provider-timeout" => {
            Ok((attempt_id, evidence))
        }
        other => Err(format!(
            "classified ambiguous execution returned {other:?}, expected bound CommitUnknown"
        )),
    }
}

fn commit_unknown_row(fixture: &AuthorityFixture) -> Result<AuthorityCheckpoint, String> {
    let request = CapabilityRequest::new(
        AUTHORITY_OBSERVATION_TIME,
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("runtime-repository"),
            FileEffect::ReadData,
            CanonicalPath::root(),
        )),
    );
    let before_epoch = checked(
        fixture.kernel.authorization_epoch(),
        "read pre-attempt epoch",
    )?
    .as_u64();
    let before_active = active_flag(&fixture.kernel, &fixture.subject, &fixture.capability)?;
    let before_unknown_view = checked(
        DurableAuditView::open(&fixture.audit.path),
        "read pre-attempt durable audit",
    )?;
    let before_next_attempt = before_unknown_view
        .next_attempt_sequence()
        .ok_or_else(|| "authority attempt sequence was unexpectedly exhausted".to_owned())?;
    let before_effect_count =
        checked(fixture.kernel.effect_records(), "read pre-attempt effects")?.len();
    let (returned_attempt_id, returned_evidence) = execute_commit_unknown(fixture, &request)?;
    let after_epoch = checked(
        fixture.kernel.authorization_epoch(),
        "read post-attempt epoch",
    )?
    .as_u64();
    let after_active = active_flag(&fixture.kernel, &fixture.subject, &fixture.capability)?;
    let after_unknown_view = checked(
        DurableAuditView::open(&fixture.audit.path),
        "read post-attempt durable audit",
    )?;
    let after_next_attempt = after_unknown_view
        .next_attempt_sequence()
        .ok_or_else(|| "authority attempt sequence exhausted after one attempt".to_owned())?;
    let durable_attempt = after_unknown_view
        .attempts()
        .last()
        .ok_or_else(|| "classified execution produced no durable attempt".to_owned())?;
    let unknown_evidence = durable_attempt
        .commit_unknown_evidence()
        .ok_or_else(|| "classified CommitUnknown attempt retained no evidence".to_owned())?;
    if durable_attempt.outcome() != AttemptOutcome::CommitUnknown {
        return Err(format!(
            "classified ambiguous attempt retained {:?}, expected CommitUnknown",
            durable_attempt.outcome()
        ));
    }
    if returned_attempt_id != durable_attempt.attempt_id()
        || returned_attempt_id != unknown_evidence.attempt_id()
        || returned_evidence.as_slice() != unknown_evidence.token()
    {
        return Err("returned, durable, and evidence CommitUnknown identities disagree".to_owned());
    }
    let after_effect_count =
        checked(fixture.kernel.effect_records(), "read post-attempt effects")?.len();
    let in_memory_attempts = checked(fixture.kernel.attempt_records(), "read classified attempts")?;
    let in_memory_attempt = in_memory_attempts
        .last()
        .ok_or_else(|| "classified execution produced no in-memory attempt".to_owned())?;
    if in_memory_attempt.id() != durable_attempt.attempt_id()
        || in_memory_attempt.outcome() != AttemptOutcome::CommitUnknown
    {
        return Err("in-memory and durable CommitUnknown attempts disagree".to_owned());
    }
    let row = format!(
        "authority\tcommit-unknown\t1\t{}\t{}\t{}\tcommit-unknown\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\tcommit-unknown\t{}\t{}",
        fixture.subject.as_str(),
        fixture.subject.as_str(),
        fixture.capability.as_str(),
        before_epoch,
        after_epoch,
        before_active,
        after_active,
        before_next_attempt,
        after_next_attempt,
        durable_attempt.attempt_id().as_u64(),
        unknown_evidence.attempt_id().as_u64(),
        unknown_evidence.token().len(),
        before_effect_count,
        after_effect_count,
    );
    Ok(AuthorityCheckpoint {
        row,
        epoch: after_epoch,
        active: after_active,
        next_attempt: after_next_attempt,
        effect_count: after_effect_count,
    })
}

fn authority_rows() -> Result<Vec<String>, String> {
    let fixture = authority_fixture()?;
    let checkpoint = commit_unknown_row(&fixture)?;
    let foreign_outcome = match fixture
        .kernel
        .revoke_held_by(&fixture.foreign, &fixture.capability)
    {
        Err(CapabilityKernelError::StateTransition(CapabilityStateError::CapabilityNotHeld {
            ..
        })) => "capability-not-held",
        Ok(status) => return Err(format!("foreign revoke unexpectedly succeeded: {status:?}")),
        Err(error) => return Err(format!("foreign revoke returned wrong error: {error}")),
    };
    let after_foreign = checked(
        fixture.kernel.authorization_epoch(),
        "read rejected-revoke epoch",
    )?
    .as_u64();
    let after_foreign_active = active_flag(&fixture.kernel, &fixture.subject, &fixture.capability)?;
    let owned_outcome = checked(
        fixture
            .kernel
            .revoke_held_by(&fixture.subject, &fixture.capability),
        "revoke caller-held capability",
    )?;
    if owned_outcome != RevocationStatus::NewlyRevoked {
        return Err(format!(
            "first caller-held revoke returned {owned_outcome:?}, expected NewlyRevoked"
        ));
    }
    let after_owned = checked(
        fixture.kernel.authorization_epoch(),
        "read committed-revoke epoch",
    )?
    .as_u64();
    let after_owned_active = active_flag(&fixture.kernel, &fixture.subject, &fixture.capability)?;

    Ok(vec![
        checkpoint.row,
        format!(
            "authority\trevoke-foreign\t1\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t-\t-\t0\tnone\t{}\t{}",
            fixture.foreign.as_str(),
            fixture.subject.as_str(),
            fixture.capability.as_str(),
            foreign_outcome,
            checkpoint.epoch,
            after_foreign,
            checkpoint.active,
            after_foreign_active,
            checkpoint.next_attempt,
            checkpoint.next_attempt,
            checkpoint.effect_count,
            checkpoint.effect_count,
        ),
        format!(
            "authority\trevoke-owned\t1\t{}\t{}\t{}\tnewly-revoked\t{}\t{}\t{}\t{}\t{}\t{}\t-\t-\t0\tnone\t{}\t{}",
            fixture.subject.as_str(),
            fixture.subject.as_str(),
            fixture.capability.as_str(),
            after_foreign,
            after_owned,
            after_foreign_active,
            after_owned_active,
            checkpoint.next_attempt,
            checkpoint.next_attempt,
            checkpoint.effect_count,
            checkpoint.effect_count,
        ),
    ])
}

struct TemporaryWal {
    path: PathBuf,
}

impl TemporaryWal {
    fn new(label: &str) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
            .as_nanos();
        Ok(Self {
            path: env::temp_dir().join(format!(
                "authority-runtime-corpus-{label}-{}-{nonce}.wal",
                process::id()
            )),
        })
    }
}

impl Drop for TemporaryWal {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn digest_prefix(bytes: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn chunked_response(request: BrokerRequestId) -> Result<CanonicalBrokerResponse, String> {
    let body_length = usize::try_from(RESPONSE_CAP)
        .map_err(|error| format!("response cap does not fit this platform: {error}"))?;
    Ok(CanonicalBrokerResponse::new(
        request,
        BrokerWireOutcome::Public(checked(
            PublicWireResponse::new(
                200,
                checked(
                    authority_core::http::CanonicalHost::new("runtime.example"),
                    "construct canonical response host",
                )?,
                checked(
                    authority_core::http::CanonicalUrlPath::new("/corpus"),
                    "construct canonical response path",
                )?,
                vec![0x5a; body_length],
            ),
            "construct chunked canonical response",
        )?),
    ))
}

struct BrokerObservation {
    envelope: BrokerEnvelope,
    accepted_budget: DurableBudgetSnapshot,
    reservation: u64,
    reserved_budget: DurableBudgetSnapshot,
    final_budget: DurableBudgetSnapshot,
    chunks: Vec<CanonicalResponseChunk>,
}

fn render_broker_rows(observation: &BrokerObservation) -> Result<Vec<String>, String> {
    let first = observation
        .chunks
        .first()
        .ok_or_else(|| "canonical response produced no chunks".to_owned())?;
    let digest = digest_prefix(first.digest().as_bytes());
    let request_hex = hex(observation.envelope.request().as_bytes());
    let payload_hash = hex(observation.envelope.payload_hash().as_bytes());
    let mut rows = vec![
        format!(
            "broker\taccepted-pending\t1\t0\t{request_hex}\t{payload_hash}\t{RESPONSE_CAP}\taccepted-pending\t-\t{}\t{}\t{}\t{}",
            observation.accepted_budget.started_requests(),
            observation.accepted_budget.committed_response_bytes(),
            observation.accepted_budget.reserved_response_bytes(),
            observation.accepted_budget.active_reservations().len()
        ),
        format!(
            "broker\tbudget-reserved\t1\t0\t{request_hex}\t{payload_hash}\t{RESPONSE_CAP}\taccepted-pending\t{}\t{}\t{}\t{}\t{}",
            observation.reservation,
            observation.reserved_budget.started_requests(),
            observation.reserved_budget.committed_response_bytes(),
            observation.reserved_budget.reserved_response_bytes(),
            observation.reserved_budget.active_reservations().len()
        ),
        format!(
            "broker\tterminal\t1\t0\t{request_hex}\t{payload_hash}\t{RESPONSE_CAP}\tfinal\t-\t{}\t{}\t{}\t{}\t{digest}\t{}\t{}",
            observation.final_budget.started_requests(),
            observation.final_budget.committed_response_bytes(),
            observation.final_budget.reserved_response_bytes(),
            observation.final_budget.active_reservations().len(),
            observation.chunks.len(),
            first.total_length()
        ),
    ];
    for chunk in &observation.chunks {
        rows.push(format!(
            "chunk\tterminal-public\t1\t{request_hex}\t{}\t{}\t{}\t{digest}\t{}",
            chunk.index(),
            chunk.count(),
            chunk.total_length(),
            chunk.bytes().len()
        ));
    }
    rows.push(format!(
        "broker\texact-retry\t1\t0\t{request_hex}\t{payload_hash}\t{RESPONSE_CAP}\tfinal\t{digest}"
    ));
    Ok(rows)
}

fn broker_rows() -> Result<Vec<String>, String> {
    let temporary = TemporaryWal::new("broker")?;
    let session = BrokerSessionId::new([0x31; 16]);
    let request = BrokerRequestId::new([0x32; 16]);
    let envelope =
        BrokerEnvelope::from_canonical_payload(session, 0, request, b"runtime-corpus-public-fetch");
    let limits = SessionBudgetLimits::new(
        NonZeroU64::new(2).ok_or_else(|| "request limit must be non-zero".to_owned())?,
        2_500_000,
        NonZeroUsize::new(1).ok_or_else(|| "concurrency limit must be non-zero".to_owned())?,
    );
    let config = DurableSessionConfig::new(
        session,
        NonZeroUsize::new(4).ok_or_else(|| "replay capacity must be non-zero".to_owned())?,
        limits,
    );
    let mut wal = checked(
        DurableBrokerWal::create(&temporary.path, config),
        "create durable Broker WAL",
    )?;
    if !matches!(
        checked(wal.accept(envelope, RESPONSE_CAP), "durably accept request")?,
        DurableAcceptance::New
    ) {
        return Err("fresh durable request was not reported as New".to_owned());
    }
    let accepted = checked(wal.read_only_view(), "observe accepted-pending state")?;
    let accepted_request = accepted
        .request(request)
        .ok_or_else(|| "accepted request missing from durable view".to_owned())?;
    if !matches!(
        accepted_request.phase(),
        DurableRequestPhase::AcceptedPending
    ) {
        return Err("new request did not enter AcceptedPending".to_owned());
    }
    let accepted_budget = accepted.budget();

    checked(wal.reserve(request), "durably reserve Broker budget")?;
    let reserved = checked(wal.read_only_view(), "observe reserved Broker budget")?;
    let reserved_request = reserved
        .request(request)
        .ok_or_else(|| "reserved request missing from durable view".to_owned())?;
    let reservation = reserved_request
        .active_reservation()
        .ok_or_else(|| "durable reservation was not visible".to_owned())?;
    let reserved_budget = reserved.budget();

    let response = chunked_response(request)?;
    let chunks = checked(response.chunks(), "construct canonical response chunks")?;
    if chunks.len() < 2 {
        return Err("runtime corpus response did not cross the chunk boundary".to_owned());
    }
    checked(
        wal.finalize(
            request,
            &response,
            BudgetSettlement::Complete {
                response_bytes: RESPONSE_CAP,
            },
        ),
        "durably finalize Broker response",
    )?;
    let final_view = checked(wal.read_only_view(), "observe terminal Broker state")?;
    let final_request = final_view
        .request(request)
        .ok_or_else(|| "terminal request missing from durable view".to_owned())?;
    let DurableRequestPhase::Final(canonical) = final_request.phase() else {
        return Err("finalized request did not enter Final".to_owned());
    };
    if canonical.wire_payloads().len() != chunks.len() {
        return Err("durable chunk payload count differs from canonical manifest".to_owned());
    }
    let final_budget = final_view.budget();
    let duplicate = checked(
        wal.accept(envelope, RESPONSE_CAP),
        "read exact durable duplicate",
    )?;
    let DurableAcceptance::ExactDuplicate(recovered) = duplicate else {
        return Err("terminal retry was not reported as ExactDuplicate".to_owned());
    };
    let DurableRequestPhase::Final(recovered_response) = recovered.phase() else {
        return Err("exact duplicate did not retain Final phase".to_owned());
    };
    if recovered_response.wire_payloads() != canonical.wire_payloads() {
        return Err("exact duplicate changed canonical wire payloads".to_owned());
    }
    render_broker_rows(&BrokerObservation {
        envelope,
        accepted_budget,
        reservation,
        reserved_budget,
        final_budget,
        chunks,
    })
}

type Events = Arc<Mutex<Vec<&'static str>>>;

#[derive(Default)]
struct FixedRandom(u8);

impl CryptographicRandom for FixedRandom {
    fn random_128(&mut self) -> Result<[u8; ID_BYTES], EntropyError> {
        self.0 = self.0.wrapping_add(1);
        Ok([self.0; ID_BYTES])
    }
}

fn record(events: &Events, event: &'static str) -> Result<(), BackendError> {
    events
        .lock()
        .map_err(|_| BackendError::new("runtime corpus event log is poisoned"))?
        .push(event);
    Ok(())
}

struct CorpusWorkspace(Events);

impl WorkspaceBackend for CorpusWorkspace {
    fn clone_workspace(
        &mut self,
        identity: &SessionIdentity,
        _template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError> {
        record(&self.0, "clone")?;
        Ok(WorkspaceLease::new(
            identity.session_id(),
            identity.workspace_id(),
        ))
    }

    fn isolate_workspace(&mut self, _lease: &WorkspaceLease) -> Result<(), BackendError> {
        record(&self.0, "isolate")
    }
}

struct CorpusBroker {
    events: Events,
    active: Option<BrokerLease>,
    statuses: VecDeque<BrokerRuntimeStatus>,
}

impl BrokerBackend for CorpusBroker {
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        record(&self.events, "establish")?;
        let lease = BrokerLease::new(identity.session_id(), identity.broker_session_id());
        self.active = Some(lease.clone());
        record(&self.events, "worker-running")?;
        Ok(lease)
    }

    fn ensure_broker_session_running(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        record(&self.events, "worker-gate")?;
        if self.active.as_ref() == Some(lease) {
            Ok(())
        } else {
            Err(BackendError::new(
                "runtime corpus observed a foreign Broker lease",
            ))
        }
    }

    fn close_broker_session(&mut self, lease: &BrokerLease) -> Result<(), BackendError> {
        record(&self.events, "close")?;
        if self.active.as_ref() != Some(lease) {
            return Err(BackendError::new(
                "runtime corpus cannot close a foreign Broker lease",
            ));
        }
        self.active = None;
        Ok(())
    }
}

impl BrokerStatusBackend for CorpusBroker {
    fn poll_broker_status(
        &mut self,
        lease: &BrokerLease,
    ) -> Result<BrokerRuntimeStatus, BackendError> {
        record(&self.events, "poll")?;
        if self.active.as_ref() != Some(lease) {
            return Err(BackendError::new(
                "runtime corpus cannot poll a foreign Broker lease",
            ));
        }
        self.statuses
            .pop_front()
            .ok_or_else(|| BackendError::new("runtime corpus has no Broker status observation"))
    }
}

struct CorpusVm(Events);

impl VmBackend for CorpusVm {
    fn start_vm(
        &mut self,
        _snapshot: &SnapshotDescriptor,
        identity: &SessionIdentity,
        workspace: &WorkspaceLease,
        broker: &BrokerLease,
    ) -> Result<VmLease, BackendError> {
        record(&self.0, "start-paused-vm")?;
        Ok(VmLease::new(
            identity.session_id(),
            identity.vm_id(),
            workspace.workspace_id(),
            broker.broker_session_id(),
        ))
    }

    fn kill_vm(&mut self, _lease: &VmLease) -> Result<(), BackendError> {
        record(&self.0, "kill")
    }
}

struct CorpusCapability(Events);

impl CapabilityRevocationBackend for CorpusCapability {
    fn revoke_root_capability(&mut self, _lease: &CapabilityLease) -> Result<(), BackendError> {
        record(&self.0, "revoke")
    }
}

impl CapabilityBackend<()> for CorpusCapability {
    fn inject_root_capability(
        &mut self,
        identity: &SessionIdentity,
        _grant: &(),
    ) -> Result<CapabilityLease, BackendError> {
        record(&self.0, "inject")?;
        Ok(CapabilityLease::new(
            identity.session_id(),
            identity.subject_id(),
            identity.capability_id(),
        ))
    }
}

struct CorpusWorkload(Events);

impl WorkloadBackend for CorpusWorkload {
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
        record(&self.0, "release")?;
        Ok(WorkloadLease::new(
            identity.session_id(),
            vm.vm_id(),
            capability.subject_id(),
            capability.capability_id(),
        ))
    }
}

fn orchestrator_rows() -> Result<Vec<String>, String> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let backends = SessionBackends::new(
        CorpusWorkspace(Arc::clone(&events)),
        CorpusBroker {
            events: Arc::clone(&events),
            active: None,
            statuses: [BrokerRuntimeStatus::Running, BrokerRuntimeStatus::Exited]
                .into_iter()
                .collect(),
        },
        CorpusVm(Arc::clone(&events)),
        CorpusCapability(Arc::clone(&events)),
        CorpusWorkload(Arc::clone(&events)),
    );
    let mut owner = SessionOwner::new(
        SessionOrchestrator::<FixedRandom, InMemoryIdentityLedger>::new(FixedRandom::default()),
        backends,
    );
    let info = checked(
        owner.start(
            &SnapshotDescriptor::clean(SnapshotId::new([0x41; ID_BYTES])),
            &WorkspaceTemplateId::new("runtime-template"),
            &(),
        ),
        "start owned runtime corpus session",
    )?;
    if owner.state() != LifecycleState::Running {
        return Err(format!(
            "startup ended in {}, expected running",
            owner.state()
        ));
    }
    let healthy = checked(
        owner.poll(OwnerPollRequest::Continue),
        "poll healthy owned Broker worker",
    )?;
    if healthy != OwnerPollOutcome::Running(info) {
        return Err(format!("healthy owner poll returned {healthy:?}"));
    }
    let closed = checked(
        owner.poll(OwnerPollRequest::Continue),
        "poll exited owned Broker worker",
    )?;
    if closed != OwnerPollOutcome::Closed(ShutdownReason::BrokerExited)
        || owner.state() != LifecycleState::Closed
    {
        return Err(format!(
            "exited owner poll returned {closed:?} in {}",
            owner.state()
        ));
    }
    let event_names = events
        .lock()
        .map_err(|_| "runtime corpus event log is poisoned".to_owned())?
        .join(",");
    Ok(vec![format!(
        "orchestrator\towned-exit\t1\t{}\t{}\tclosed\tbroker-exited\t{event_names}",
        info.identity().session_id(),
        info.identity().broker_session_id()
    )])
}

fn run() -> Result<(), String> {
    println!("{CORPUS_HEADER}");
    for row in authority_rows()?
        .into_iter()
        .chain(broker_rows()?)
        .chain(orchestrator_rows()?)
    {
        println!("{row}");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("runtime corpus failed: {error}");
        process::exit(1);
    }
}
