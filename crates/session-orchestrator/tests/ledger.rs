//! Durable identity-ledger contract tests.

use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use session_orchestrator::{
    BackendError, BrokerBackend, BrokerLease, CapabilityBackend, CapabilityLease,
    CapabilityRevocationBackend, CryptographicRandom, DurableIdentityLedger, EntropyError,
    IdentityKind, IdentityLedger, LedgerError, MAX_LEDGER_RECORDS, SessionIdentity,
    SessionOrchestrator, SnapshotDescriptor, SnapshotId, StartFailure, VmBackend, VmLease,
    WorkloadBackend, WorkloadLease, WorkspaceBackend, WorkspaceLease, WorkspaceTemplateId,
};

#[cfg(unix)]
use std::os::unix::fs::symlink;

const LEDGER_V2_HEADER_BYTES: usize = 64;
const LEDGER_V2_DATA_OFFSET: usize = LEDGER_V2_HEADER_BYTES * 2;
const LEDGER_RECORD_BYTES: usize = 32;
const EXACT_CAPACITY_CHUNK: usize = 4_096;
const CHILD_PATH: &str = "SESSION_ORCHESTRATOR_LEDGER_CHILD_PATH";
const CHILD_READY: &str = "SESSION_ORCHESTRATOR_LEDGER_CHILD_READY";
const CHILD_RELEASE: &str = "SESSION_ORCHESTRATOR_LEDGER_CHILD_RELEASE";

fn ledger_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "session-orchestrator-{test_name}-{}-{nonce}.ledger",
        std::process::id()
    ))
}

fn remove(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let _ = fs::remove_file(lock);
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !value
}

fn v2_header(slot: usize, generation: u64, record_count: u64) -> [u8; LEDGER_V2_HEADER_BYTES] {
    let mut header = [0_u8; LEDGER_V2_HEADER_BYTES];
    header[..8].copy_from_slice(b"SORLEDG2");
    header[8] = 2;
    header[9] = u8::try_from(LEDGER_V2_HEADER_BYTES).expect("header width fits in a byte");
    header[12..20].copy_from_slice(&generation.to_le_bytes());
    header[20..28].copy_from_slice(&record_count.to_le_bytes());
    let data_length = LEDGER_V2_DATA_OFFSET as u64 + record_count * LEDGER_RECORD_BYTES as u64;
    header[28..36].copy_from_slice(&data_length.to_le_bytes());
    header[36] = u8::try_from(slot).expect("header slot fits in a byte");
    let header_checksum = checksum(&header[..60]);
    header[60..].copy_from_slice(&header_checksum.to_le_bytes());
    header
}

fn record(kind: IdentityKind, identity: [u8; 16], sequence: u64) -> [u8; LEDGER_RECORD_BYTES] {
    let mut record = [0_u8; LEDGER_RECORD_BYTES];
    record[0] = 1;
    record[1] = match kind {
        IdentityKind::Vm => 1,
        IdentityKind::Session => 2,
        IdentityKind::Subject => 3,
        IdentityKind::Workspace => 4,
        IdentityKind::Capability => 5,
        IdentityKind::Request => 6,
        IdentityKind::BrokerSession => 7,
    };
    record[4..12].copy_from_slice(&sequence.to_le_bytes());
    record[12..28].copy_from_slice(&identity);
    let record_checksum = checksum(&record[..28]);
    record[28..].copy_from_slice(&record_checksum.to_le_bytes());
    record
}

fn committed_record_count(path: &Path) -> u64 {
    let bytes = fs::read(path).expect("ledger bytes must be readable");
    [0, LEDGER_V2_HEADER_BYTES]
        .into_iter()
        .map(|offset| u64::from_le_bytes(bytes[offset + 20..offset + 28].try_into().unwrap()))
        .max()
        .expect("the v2 ledger has two commit headers")
}

fn indexed_identity(index: usize) -> [u8; 16] {
    let mut identity = [0_u8; 16];
    identity[..8].copy_from_slice(&(index as u64).to_le_bytes());
    identity
}

fn spawn_lock_holder(path: &Path, ready: &Path, release: &Path) -> Child {
    Command::new(std::env::current_exe().expect("test executable must exist"))
        .args(["--exact", "ledger_lock_child", "--nocapture"])
        .env(CHILD_PATH, path)
        .env(CHILD_READY, ready)
        .env(CHILD_RELEASE, release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ledger lock child must start")
}

fn wait_for_ready(child: &mut Child, ready: &Path) -> bool {
    for _ in 0..500 {
        if ready.exists() {
            return true;
        }
        if child
            .try_wait()
            .expect("child status must be readable")
            .is_some()
        {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

#[derive(Debug)]
struct DeterministicRandom {
    next: u8,
}

impl CryptographicRandom for DeterministicRandom {
    fn random_128(&mut self) -> Result<[u8; 16], EntropyError> {
        let value = [self.next; 16];
        self.next = self.next.wrapping_add(1);
        Ok(value)
    }
}

#[derive(Debug)]
struct ZeroThenRandom {
    return_zero: bool,
    next: u8,
}

impl CryptographicRandom for ZeroThenRandom {
    fn random_128(&mut self) -> Result<[u8; 16], EntropyError> {
        if self.return_zero {
            self.return_zero = false;
            return Ok([0_u8; 16]);
        }
        let value = [self.next; 16];
        self.next = self.next.wrapping_add(1);
        Ok(value)
    }
}

#[derive(Debug, Default)]
struct AlwaysZeroRandom;

impl CryptographicRandom for AlwaysZeroRandom {
    fn random_128(&mut self) -> Result<[u8; 16], EntropyError> {
        Ok([0_u8; 16])
    }
}

struct DurableProbeWorkspace {
    path: PathBuf,
}

impl WorkspaceBackend for DurableProbeWorkspace {
    fn clone_workspace(
        &mut self,
        identity: &SessionIdentity,
        _template: &WorkspaceTemplateId,
    ) -> Result<WorkspaceLease, BackendError> {
        assert_eq!(
            committed_record_count(&self.path),
            7,
            "all session identities must be durable before the first backend effect"
        );
        Ok(WorkspaceLease::new(
            identity.session_id(),
            identity.workspace_id(),
        ))
    }

    fn isolate_workspace(&mut self, _lease: &WorkspaceLease) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Default)]
struct DurableProbeBroker;

impl BrokerBackend for DurableProbeBroker {
    fn establish_broker_session(
        &mut self,
        identity: &SessionIdentity,
    ) -> Result<BrokerLease, BackendError> {
        Ok(BrokerLease::new(
            identity.session_id(),
            identity.broker_session_id(),
        ))
    }

    fn ensure_broker_session_running(&mut self, _lease: &BrokerLease) -> Result<(), BackendError> {
        Ok(())
    }

    fn close_broker_session(&mut self, _lease: &BrokerLease) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Default)]
struct DurableProbeVm;

impl VmBackend for DurableProbeVm {
    fn start_vm(
        &mut self,
        _snapshot: &SnapshotDescriptor,
        identity: &SessionIdentity,
        workspace: &WorkspaceLease,
        broker: &BrokerLease,
    ) -> Result<VmLease, BackendError> {
        Ok(VmLease::new(
            identity.session_id(),
            identity.vm_id(),
            workspace.workspace_id(),
            broker.broker_session_id(),
        ))
    }

    fn kill_vm(&mut self, _lease: &VmLease) -> Result<(), BackendError> {
        Ok(())
    }
}

#[derive(Default)]
struct DurableProbeCapability;

impl CapabilityRevocationBackend for DurableProbeCapability {
    fn revoke_root_capability(&mut self, _lease: &CapabilityLease) -> Result<(), BackendError> {
        Ok(())
    }
}

impl CapabilityBackend<()> for DurableProbeCapability {
    fn inject_root_capability(
        &mut self,
        identity: &SessionIdentity,
        _grant: &(),
    ) -> Result<CapabilityLease, BackendError> {
        Ok(CapabilityLease::new(
            identity.session_id(),
            identity.subject_id(),
            identity.capability_id(),
        ))
    }
}

#[derive(Default)]
struct DurableProbeWorkload;

impl WorkloadBackend for DurableProbeWorkload {
    fn release_workload(
        &mut self,
        identity: &SessionIdentity,
        vm: &VmLease,
        capability: &CapabilityLease,
    ) -> Result<WorkloadLease, BackendError> {
        Ok(WorkloadLease::new(
            identity.session_id(),
            vm.vm_id(),
            capability.subject_id(),
            capability.capability_id(),
        ))
    }
}

#[test]
fn ledger_lock_child() {
    let Some(path) = std::env::var_os(CHILD_PATH).map(PathBuf::from) else {
        return;
    };
    let ready =
        PathBuf::from(std::env::var_os(CHILD_READY).expect("child ready path must be provided"));
    let release = PathBuf::from(
        std::env::var_os(CHILD_RELEASE).expect("child release path must be provided"),
    );
    let ledger = DurableIdentityLedger::open(path).expect("child must own durable ledger");
    fs::write(&ready, b"ready").expect("child must publish readiness");
    for _ in 0..1_000 {
        if release.exists() {
            drop(ledger);
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("parent did not release durable ledger child");
}

#[test]
fn durable_ledger_recovers_all_committed_records_after_reopen() {
    let path = ledger_path("recovery");
    let first = [0x11; 16];
    let second = [0x22; 16];
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve_batch(&[(IdentityKind::Session, first), (IdentityKind::Vm, second)])
            .expect("batch must sync");
        assert_eq!(ledger.committed_count(), 2);
    }
    let ledger = DurableIdentityLedger::open(&path).expect("ledger must recover");
    assert!(ledger.contains(first));
    assert!(ledger.contains(second));
    assert_eq!(ledger.committed_count(), 2);
    drop(ledger);
    remove(&path);
}

#[test]
fn corrupt_record_is_rejected() {
    let path = ledger_path("corrupt");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("test ledger must be writable");
    file.seek(SeekFrom::Start(0)).expect("seek must work");
    file.write_all(b"X").expect("test corruption must write");
    file.sync_data().expect("test corruption must sync");
    let error = DurableIdentityLedger::open(&path).expect_err("corrupt header must fail");
    assert!(matches!(error, LedgerError::Corrupt { .. }));
    remove(&path);
}

#[test]
fn truncated_record_is_rejected() {
    let path = ledger_path("truncated");
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve(IdentityKind::Session, [0x44; 16])
            .expect("record must be committed");
    }
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("test ledger must be writable");
    let length = file.metadata().expect("metadata must work").len();
    file.set_len(length - 1).expect("test truncation must work");
    file.sync_data().expect("test truncation must sync");
    let error = DurableIdentityLedger::open(&path).expect_err("truncated header must fail");
    assert!(matches!(error, LedgerError::Truncated { .. }));
    remove(&path);
}

#[test]
fn duplicate_remains_rejected_after_reopen() {
    let path = ledger_path("duplicate");
    let identity = [0x33; 16];
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve(IdentityKind::Capability, identity)
            .expect("first reservation must sync");
    }
    let mut reopened = DurableIdentityLedger::open(&path).expect("ledger must recover");
    let error = reopened
        .reserve(IdentityKind::Request, identity)
        .expect_err("duplicate must remain rejected");
    assert!(matches!(error, LedgerError::Duplicate { .. }));
    drop(reopened);
    remove(&path);
}

#[test]
fn second_owner_is_rejected_while_first_owner_is_alive() {
    let path = ledger_path("lock");
    let first = DurableIdentityLedger::open(&path).expect("first owner must open");
    let error = DurableIdentityLedger::open(&path).expect_err("second owner must be rejected");
    assert!(matches!(error, LedgerError::Locked { .. }));
    drop(first);
    remove(&path);
}

#[test]
fn new_durable_commits_all_identity_domains_before_start_effects() {
    let path = ledger_path("orchestrator");
    let mut orchestrator =
        SessionOrchestrator::<DeterministicRandom, DurableIdentityLedger>::new_durable(
            DeterministicRandom { next: 1 },
            &path,
        )
        .expect("durable orchestrator must open its ledger");
    let mut workspace = DurableProbeWorkspace { path: path.clone() };
    let mut broker = DurableProbeBroker;
    let mut vm = DurableProbeVm;
    let mut capability = DurableProbeCapability;
    let mut workload = DurableProbeWorkload;
    let info = orchestrator
        .start_session(
            &SnapshotDescriptor::clean(SnapshotId::new([0xa0; 16])),
            &WorkspaceTemplateId::new("durable-test-template"),
            &(),
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("durable orchestrator startup must commit");
    assert_eq!(info.identity().session_id().as_bytes(), [1; 16]);
    assert_eq!(committed_record_count(&path), 7);

    orchestrator
        .stop_session(&mut workspace, &mut broker, &mut vm, &mut capability)
        .expect("durable orchestrator stop must commit");
    drop(orchestrator);
    let reopened = DurableIdentityLedger::open(&path).expect("durable ledger must reopen");
    assert_eq!(reopened.committed_count(), 7);
    drop(reopened);
    remove(&path);
}

#[test]
fn new_durable_retries_an_all_zero_identity_before_backend_effects() {
    let path = ledger_path("orchestrator-zero-retry");
    let mut orchestrator =
        SessionOrchestrator::<ZeroThenRandom, DurableIdentityLedger>::new_durable(
            ZeroThenRandom {
                return_zero: true,
                next: 1,
            },
            &path,
        )
        .expect("durable orchestrator must open its ledger");
    let mut workspace = DurableProbeWorkspace { path: path.clone() };
    let mut broker = DurableProbeBroker;
    let mut vm = DurableProbeVm;
    let mut capability = DurableProbeCapability;
    let mut workload = DurableProbeWorkload;
    let info = orchestrator
        .start_session(
            &SnapshotDescriptor::clean(SnapshotId::new([0xa1; 16])),
            &WorkspaceTemplateId::new("durable-zero-retry-template"),
            &(),
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect("one all-zero draw must be retried before committing identities");
    assert_eq!(info.identity().session_id().as_bytes(), [1; 16]);
    assert_eq!(committed_record_count(&path), 7);
    drop(orchestrator);
    remove(&path);
}

#[test]
fn new_durable_rejects_persistent_all_zero_identity_without_reserving() {
    let path = ledger_path("orchestrator-zero-fail");
    let mut orchestrator =
        SessionOrchestrator::<AlwaysZeroRandom, DurableIdentityLedger>::new_durable(
            AlwaysZeroRandom,
            &path,
        )
        .expect("durable orchestrator must open its ledger");
    let mut workspace = DurableProbeWorkspace { path: path.clone() };
    let mut broker = DurableProbeBroker;
    let mut vm = DurableProbeVm;
    let mut capability = DurableProbeCapability;
    let mut workload = DurableProbeWorkload;
    let error = orchestrator
        .start_session(
            &SnapshotDescriptor::clean(SnapshotId::new([0xa2; 16])),
            &WorkspaceTemplateId::new("durable-zero-fail-template"),
            &(),
            &mut workspace,
            &mut broker,
            &mut vm,
            &mut capability,
            &mut workload,
        )
        .expect_err("persistent all-zero identity source must fail closed");
    assert!(matches!(
        error.failure(),
        StartFailure::Entropy(error) if error.message().contains("all-zero")
    ));
    drop(orchestrator);
    let reopened =
        DurableIdentityLedger::open(&path).expect("failed allocation must leave ledger usable");
    assert_eq!(reopened.committed_count(), 0);
    drop(reopened);
    remove(&path);
}

#[test]
fn cross_process_contention_releases_the_same_stable_lock() {
    let path = ledger_path("cross-process");
    let ready = path.with_extension("ready");
    let release = path.with_extension("release");
    let mut child = spawn_lock_holder(&path, &ready, &release);
    assert!(
        wait_for_ready(&mut child, &ready),
        "child must acquire the ledger"
    );
    let error = DurableIdentityLedger::open(&path)
        .expect_err("a second process must not bypass the kernel lock");
    assert!(matches!(error, LedgerError::Locked { .. }));
    fs::write(&release, b"release").expect("parent must release child");
    let output = child.wait_with_output().expect("child must finish");
    assert!(
        output.status.success(),
        "child failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let reopened =
        DurableIdentityLedger::open(&path).expect("the released stable lock must be reusable");
    drop(reopened);
    remove(&path);
    let _ = fs::remove_file(ready);
    let _ = fs::remove_file(release);
}

#[test]
fn stale_lock_is_recoverable_after_owner_process_is_killed() {
    let path = ledger_path("stale-lock");
    let ready = path.with_extension("ready");
    let release = path.with_extension("release");
    let mut child = spawn_lock_holder(&path, &ready, &release);
    assert!(
        wait_for_ready(&mut child, &ready),
        "child must acquire the ledger"
    );
    child
        .kill()
        .expect("parent must be able to terminate the owner");
    let output = child
        .wait_with_output()
        .expect("killed child must be reaped");
    assert!(
        !output.status.success(),
        "the lock holder must have been killed"
    );

    let mut reopened = DurableIdentityLedger::open(&path)
        .expect("kernel must release a stale lock after owner death");
    reopened
        .reserve(IdentityKind::Session, [0x5a; 16])
        .expect("recovered owner must still be able to reserve");
    drop(reopened);
    remove(&path);
    let _ = fs::remove_file(ready);
    let _ = fs::remove_file(release);
}

#[test]
fn crash_after_record_sync_is_recovered_as_uncommitted_tail() {
    let path = ledger_path("crash-tail");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let staged = record(IdentityKind::Session, [0x6a; 16], 0);
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("ledger must be writable for the crash simulation");
    file.write_all(&staged)
        .and_then(|()| file.sync_all())
        .expect("staged record must become visible before the simulated crash");
    let reopened = DurableIdentityLedger::open(&path)
        .expect("a valid staged tail must be discarded on reopen");
    assert_eq!(reopened.committed_count(), 0);
    assert!(!reopened.contains([0x6a; 16]));
    drop(reopened);
    assert_eq!(
        fs::metadata(&path)
            .expect("ledger metadata must exist")
            .len(),
        LEDGER_V2_DATA_OFFSET as u64
    );
    remove(&path);
}

#[test]
fn rename_and_length_changes_poison_the_live_owner() {
    let path = ledger_path("rename-poison");
    let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
    let displaced = path.with_extension("displaced");
    fs::rename(&path, &displaced).expect("ledger path must be displaced");
    fs::copy(&displaced, &path).expect("replacement ledger must be installed");
    assert!(matches!(
        ledger.reserve(IdentityKind::Session, [0x70; 16]),
        Err(LedgerError::PathIdentityChanged { .. })
    ));
    assert!(matches!(
        ledger.reserve(IdentityKind::Session, [0x71; 16]),
        Err(LedgerError::Unavailable { .. })
    ));
    drop(ledger);
    remove(&path);
    let _ = fs::remove_file(displaced);

    let path = ledger_path("length-poison");
    let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
    OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&[0xaa]).and_then(|()| file.sync_all()))
        .expect("test must append an uncommitted byte");
    assert!(matches!(
        ledger.reserve(IdentityKind::Session, [0x72; 16]),
        Err(LedgerError::LengthChanged { .. })
    ));
    assert!(matches!(
        ledger.reserve(IdentityKind::Session, [0x73; 16]),
        Err(LedgerError::Unavailable { .. })
    ));
    drop(ledger);
    remove(&path);
}

#[test]
fn capacity_is_bounded_at_request_header_and_file_edges() {
    let path = ledger_path("request-capacity");
    let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
    let identities = (0..=MAX_LEDGER_RECORDS)
        .map(|index| (IdentityKind::Session, indexed_identity(index)))
        .collect::<Vec<_>>();
    assert!(matches!(
        ledger.reserve_batch(&identities),
        Err(LedgerError::CapacityExceeded {
            records,
            max_records
        }) if records == MAX_LEDGER_RECORDS as u64 + 1
            && max_records == MAX_LEDGER_RECORDS as u64
    ));
    drop(ledger);
    remove(&path);

    let path = ledger_path("header-capacity");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("ledger must be writable");
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&v2_header(0, 0, MAX_LEDGER_RECORDS as u64 + 1)))
        .and_then(|()| file.seek(SeekFrom::Start(LEDGER_V2_HEADER_BYTES as u64)))
        .and_then(|_| file.write_all(&v2_header(1, 0, MAX_LEDGER_RECORDS as u64 + 1)))
        .and_then(|()| file.sync_all())
        .expect("test header must be durable");
    assert!(matches!(
        DurableIdentityLedger::open(&path),
        Err(LedgerError::CapacityExceeded {
            records,
            max_records
        }) if records == MAX_LEDGER_RECORDS as u64 + 1
            && max_records == MAX_LEDGER_RECORDS as u64
    ));
    remove(&path);

    let path = ledger_path("file-capacity");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("ledger must be writable");
    file.set_len((LEDGER_V2_DATA_OFFSET + MAX_LEDGER_RECORDS * LEDGER_RECORD_BYTES + 1) as u64)
        .expect("test must create an over-capacity sparse file");
    file.sync_all().expect("test capacity must be durable");
    assert!(matches!(
        DurableIdentityLedger::open(&path),
        Err(LedgerError::CapacityExceeded { .. })
    ));
    remove(&path);
}

#[test]
fn capacity_accepts_exact_limit_and_rejects_the_next_record() {
    let path = ledger_path("exact-capacity");
    let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
    for start in (0..MAX_LEDGER_RECORDS).step_by(EXACT_CAPACITY_CHUNK) {
        let end = (start + EXACT_CAPACITY_CHUNK).min(MAX_LEDGER_RECORDS);
        let batch = (start..end)
            .map(|index| (IdentityKind::Session, indexed_identity(index + 1)))
            .collect::<Vec<_>>();
        ledger
            .reserve_batch(&batch)
            .expect("each chunk up to the exact record limit must commit");
    }
    assert_eq!(ledger.committed_count(), MAX_LEDGER_RECORDS);
    assert_eq!(
        fs::metadata(&path)
            .expect("full ledger metadata must be readable")
            .len(),
        (LEDGER_V2_DATA_OFFSET + MAX_LEDGER_RECORDS * LEDGER_RECORD_BYTES) as u64
    );
    assert!(matches!(
        ledger.reserve(IdentityKind::Session, indexed_identity(MAX_LEDGER_RECORDS + 1)),
        Err(LedgerError::CapacityExceeded {
            records,
            max_records
        }) if records == MAX_LEDGER_RECORDS as u64 + 1
            && max_records == MAX_LEDGER_RECORDS as u64
    ));
    drop(ledger);

    let reopened = DurableIdentityLedger::open(&path).expect("exact-limit ledger must reopen");
    assert_eq!(reopened.committed_count(), MAX_LEDGER_RECORDS);
    assert!(reopened.contains(indexed_identity(MAX_LEDGER_RECORDS)));
    drop(reopened);
    remove(&path);
}

#[test]
fn malformed_header_and_symlink_errors_fail_closed() {
    let path = ledger_path("unsupported");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("ledger must be writable");
    file.seek(SeekFrom::Start(8))
        .and_then(|_| file.write_all(&[0x7f]))
        .and_then(|()| file.seek(SeekFrom::Start((LEDGER_V2_HEADER_BYTES + 8) as u64)))
        .and_then(|_| file.write_all(&[0x7f]))
        .and_then(|()| file.sync_all())
        .expect("test version mutation must be durable");
    assert!(matches!(
        DurableIdentityLedger::open(&path),
        Err(LedgerError::UnsupportedVersion { version: 0x7f })
    ));
    remove(&path);

    #[cfg(unix)]
    {
        let path = ledger_path("symlink");
        let target = ledger_path("symlink-target");
        fs::write(&target, b"not-a-ledger").expect("symlink target must exist");
        symlink(&target, &path).expect("ledger symlink must be created");
        assert!(matches!(
            DurableIdentityLedger::open(&path),
            Err(LedgerError::Symlink { .. })
        ));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(target);
    }
}

#[test]
fn malformed_staged_records_fail_closed_before_tail_truncation() {
    for (name, mutation) in [
        (
            "unknown-kind",
            (|record: &mut [u8; LEDGER_RECORD_BYTES]| record[1] = 0)
                as fn(&mut [u8; LEDGER_RECORD_BYTES]),
        ),
        (
            "non-contiguous-sequence",
            (|record: &mut [u8; LEDGER_RECORD_BYTES]| {
                record[4..12].copy_from_slice(&1_u64.to_le_bytes());
            }) as fn(&mut [u8; LEDGER_RECORD_BYTES]),
        ),
        (
            "reserved-byte",
            (|record: &mut [u8; LEDGER_RECORD_BYTES]| record[2] = 1)
                as fn(&mut [u8; LEDGER_RECORD_BYTES]),
        ),
    ] {
        let path = ledger_path(name);
        {
            let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
            drop(ledger);
        }
        let mut staged = record(IdentityKind::Session, [0x7a; 16], 0);
        mutation(&mut staged);
        let record_checksum = checksum(&staged[..28]);
        staged[28..].copy_from_slice(&record_checksum.to_le_bytes());
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("ledger must be writable");
        file.write_all(&staged)
            .and_then(|()| file.sync_all())
            .expect("malformed staged record must be durable");
        assert!(matches!(
            DurableIdentityLedger::open(&path),
            Err(LedgerError::Corrupt { .. })
        ));
        remove(&path);
    }
}

#[cfg(target_os = "linux")]
fn create_fifo(path: &Path) {
    let output = Command::new("mkfifo")
        .args(["-m", "0600"])
        .arg(path)
        .output()
        .expect("mkfifo must be available for the non-regular-file fixture");
    assert!(
        output.status.success(),
        "mkfifo failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_regular_ledger_path_is_rejected() {
    let path = ledger_path("not-regular");
    create_fifo(&path);
    let error = DurableIdentityLedger::open(&path).expect_err("FIFO ledger path must fail closed");
    assert!(matches!(
        error,
        LedgerError::NotRegularFile { path: rejected } if rejected == path
    ));
    remove(&path);
}

#[cfg(target_os = "linux")]
#[test]
fn os_entropy_reads_fresh_kernel_randomness() {
    let mut entropy = session_orchestrator::OsEntropy;
    let first = entropy
        .random_128()
        .expect("/dev/urandom must provide one identity");
    let second = entropy
        .random_128()
        .expect("/dev/urandom must provide a second identity");
    assert!(first.iter().any(|byte| *byte != 0));
    assert!(second.iter().any(|byte| *byte != 0));
    assert_ne!(first, second, "independent kernel draws must not repeat");
}

#[test]
fn record_count_limit_is_explicitly_bounded() {
    assert_eq!(MAX_LEDGER_RECORDS, 1_048_576);
}
