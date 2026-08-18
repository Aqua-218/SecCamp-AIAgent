//! One-session production host daemon.
//!
//! The daemon accepts only explicit, pinned configuration. It builds the production ownership
//! graph, starts one immutable guest image, polls the exact Broker worker, and drains cleanup when
//! an operator creates its configured stop file. Guest identity and capability policy are never
//! accepted over the guest control transport.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    env, fs,
    io::{self, Seek, SeekFrom, Write},
    num::{NonZeroU64, NonZeroUsize},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::{
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
#[cfg(unix)]
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, sendto, socket_with,
};

use authority_core::{
    capability::{AuthorityBody, IssuerId},
    file::{FileAuthority, FileEffect, FileEffects},
    github::{
        BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
        InstallationId,
    },
    http::{
        CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
        UrlPathPattern,
    },
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    time::{MonotonicTime, TimeWindow},
};
use egress_broker::github::CredentialHandle;
use firecracker_runtime::{
    CgroupConfig, CgroupVersion, DmVerityConfig, HostIsolationConfig, JailerConfig,
    NamespaceConfig, PinnedArtifact, RuntimeConfig, SeccompConfig, Sha256Digest, VsockConfig,
    WorkspaceConfig, WorkspaceImageConfig, recovery::RecoveryTools,
};
use session_orchestrator::{
    SessionIdentity, SnapshotId, WorkspaceTemplateId,
    authority_backend::AuthorityRootGrant,
    filesystem_factory::{FilesystemFirecrackerFactory, GuestArtifactTemplate, SnapshotTemplate},
    production_runtime::{
        AuthorityAuditMode, ProductionBrokerEndpoint, ProductionBrokerLimits,
        ProductionDurabilityConfig, ProductionFirecrackerConfig, ProductionGuestControlEndpoint,
        ProductionSessionConfig, ProductionSessionRuntimeBuilder,
    },
    session_owner::{OwnerPollOutcome, OwnerPollRequest},
    system_egress::{
        GitHubEgressConfig, SystemEgressFactory, load_publish_plan_manifest,
        validate_publish_plans_for_authority,
    },
};

const TEMPLATE_CLONE_ID: &str = "template";
const MAX_SHUTDOWN_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;
const REQUIRED_SECCOMP_DENIES: [&str; 6] = [
    "bpf",
    "mount",
    "perf_event_open",
    "ptrace",
    "setns",
    "unshare",
];

fn main() -> ExitCode {
    if env::args().skip(1).any(|argument| argument == "--help") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-sessiond: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = DaemonConfig::parse(effective_arguments()?)?;
    let signals = install_signal_handlers()?;
    let status = StatusReporter::new(config.status_file.clone())?;
    status.emit("starting", "starting", None, None);
    let factory = FilesystemFirecrackerFactory::with_guest_artifacts(
        config.snapshot_id,
        config.runtime.clone(),
        GuestArtifactTemplate::new(config.kernel_source, config.seccomp_source),
        SnapshotTemplate::new(
            config.snapshot_state,
            config.snapshot_memory,
            config.grant.policy_digest(),
        ),
    );
    let egress = SystemEgressFactory::new(config.github_egress);
    let mut runtime =
        match ProductionSessionRuntimeBuilder::new(config.production, factory, egress).build() {
            Ok(runtime) => runtime,
            Err(error) => {
                status.emit("failed", "starting", None, Some("runtime-build-failed"));
                return Err(format!("building production session runtime: {error}"));
            }
        };
    if config.recover_only {
        status.emit("recovered", "closed", None, Some("recovery-only"));
        return Ok(());
    }
    let started = match runtime.start(&config.grant) {
        Ok(started) => started,
        Err(error) => {
            status.emit("failed", "starting", None, Some("session-start-failed"));
            eprintln!("host-sessiond: session start failed before cleanup: {error}");
            return Err(format!("starting production session: {error}"));
        }
    };
    let identity = started.identity();
    status.emit("ready", "running", Some(identity), None);
    notify_systemd_ready()?;
    run_session_loop(
        &mut runtime,
        &config.stop_file,
        config.poll_interval,
        config.shutdown_timeout,
        &signals,
        &status,
        identity,
    )
}

fn effective_arguments() -> Result<Vec<String>, String> {
    let direct = env::args().skip(1).collect::<Vec<_>>();
    systemd_arguments(direct, |variable| env::var(variable).ok())
}

#[allow(clippy::too_many_lines)] // Closed environment-to-argument mapping lists every production field.
fn systemd_arguments(
    direct: Vec<String>,
    mut environment: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    if direct.first().map(String::as_str) != Some("--systemd-instance") {
        return Ok(direct);
    }
    if direct.len() != 4 || direct.get(2).map(String::as_str) != Some("--mode") {
        return Err(
            "systemd worker mode requires exactly --systemd-instance ID --mode run|recover"
                .to_owned(),
        );
    }
    let instance = direct[1].clone();
    let mode = direct[3].clone();
    ControlInstance::parse(&instance)?;
    if !matches!(mode.as_str(), "run" | "recover") {
        return Err("systemd worker --mode must be run or recover".to_owned());
    }
    let mappings = [
        ("firecracker", "HOST_SESSIOND_FIRECRACKER"),
        ("firecracker-sha256", "HOST_SESSIOND_FIRECRACKER_SHA256"),
        ("jailer", "HOST_SESSIOND_JAILER"),
        ("jailer-sha256", "HOST_SESSIOND_JAILER_SHA256"),
        ("kernel-source", "HOST_SESSIOND_KERNEL_SOURCE"),
        ("kernel-source-sha256", "HOST_SESSIOND_KERNEL_SOURCE_SHA256"),
        ("rootfs", "HOST_SESSIOND_ROOTFS"),
        ("rootfs-sha256", "HOST_SESSIOND_ROOTFS_SHA256"),
        ("verity-hash", "HOST_SESSIOND_VERITY_HASH"),
        ("verity-hash-sha256", "HOST_SESSIOND_VERITY_HASH_SHA256"),
        (
            "rootfs-verity-root-hash",
            "HOST_SESSIOND_ROOTFS_VERITY_ROOT_HASH",
        ),
        ("workspace-formatter", "HOST_SESSIOND_WORKSPACE_FORMATTER"),
        (
            "workspace-formatter-sha256",
            "HOST_SESSIOND_WORKSPACE_FORMATTER_SHA256",
        ),
        ("workspace-source", "HOST_SESSIOND_WORKSPACE_SOURCE"),
        ("seccomp-compiler", "HOST_SESSIOND_SECCOMP_COMPILER"),
        (
            "seccomp-compiler-sha256",
            "HOST_SESSIOND_SECCOMP_COMPILER_SHA256",
        ),
        ("seccomp-source", "HOST_SESSIOND_SECCOMP_SOURCE"),
        (
            "seccomp-source-sha256",
            "HOST_SESSIOND_SECCOMP_SOURCE_SHA256",
        ),
        (
            "seccomp-policy-source",
            "HOST_SESSIOND_SECCOMP_POLICY_SOURCE",
        ),
        (
            "seccomp-policy-source-sha256",
            "HOST_SESSIOND_SECCOMP_POLICY_SOURCE_SHA256",
        ),
        ("snapshot-id", "HOST_SESSIOND_SNAPSHOT_ID"),
        ("snapshot-state", "HOST_SESSIOND_SNAPSHOT_STATE"),
        (
            "snapshot-state-sha256",
            "HOST_SESSIOND_SNAPSHOT_STATE_SHA256",
        ),
        ("snapshot-memory", "HOST_SESSIOND_SNAPSHOT_MEMORY"),
        (
            "snapshot-memory-sha256",
            "HOST_SESSIOND_SNAPSHOT_MEMORY_SHA256",
        ),
        ("veritysetup", "HOST_SESSIOND_VERITYSETUP"),
        ("veritysetup-sha256", "HOST_SESSIOND_VERITYSETUP_SHA256"),
        ("dmsetup", "HOST_SESSIOND_DMSETUP"),
        ("dmsetup-sha256", "HOST_SESSIOND_DMSETUP_SHA256"),
        ("jailer-chroot-base", "HOST_SESSIOND_JAILER_CHROOT_BASE"),
        ("cgroup-parent", "HOST_SESSIOND_CGROUP_PARENT"),
        ("jailer-uid", "HOST_SESSIOND_JAILER_UID"),
        ("jailer-gid", "HOST_SESSIOND_JAILER_GID"),
        ("verity-mapper-prefix", "HOST_SESSIOND_VERITY_MAPPER_PREFIX"),
        (
            "workspace-image-bytes",
            "HOST_SESSIOND_WORKSPACE_IMAGE_BYTES",
        ),
        ("memory-max-bytes", "HOST_SESSIOND_MEMORY_MAX_BYTES"),
        ("cpu-quota-micros", "HOST_SESSIOND_CPU_QUOTA_MICROS"),
        ("cpu-period-micros", "HOST_SESSIOND_CPU_PERIOD_MICROS"),
        ("guest-cid", "HOST_SESSIOND_GUEST_CID"),
        ("vcpu-count", "HOST_SESSIOND_VCPU_COUNT"),
        ("memory-mib", "HOST_SESSIOND_MEMORY_MIB"),
        ("boot-args", "HOST_SESSIOND_BOOT_ARGS"),
        ("issuer", "HOST_SESSIOND_ISSUER"),
        ("workspace-template", "HOST_SESSIOND_WORKSPACE_TEMPLATE"),
        ("identity-ledger", "HOST_SESSIOND_IDENTITY_LEDGER_ROOT"),
        ("recovery-journal", "HOST_SESSIOND_RECOVERY_JOURNAL_ROOT"),
        ("authority-audit", "HOST_SESSIOND_AUTHORITY_AUDIT_ROOT"),
        ("authority-audit-mode", "HOST_SESSIOND_AUTHORITY_AUDIT_MODE"),
        ("broker-wal-root", "HOST_SESSIOND_BROKER_WAL_BASE"),
        ("broker-host-cid", "HOST_SESSIOND_BROKER_HOST_CID"),
        ("broker-port", "HOST_SESSIOND_BROKER_PORT"),
        ("broker-backlog", "HOST_SESSIOND_BROKER_BACKLOG"),
        ("guest-control-port", "HOST_SESSIOND_GUEST_CONTROL_PORT"),
        (
            "broker-replay-capacity",
            "HOST_SESSIOND_BROKER_REPLAY_CAPACITY",
        ),
        (
            "broker-budget-requests",
            "HOST_SESSIOND_BROKER_BUDGET_REQUESTS",
        ),
        (
            "broker-budget-response-bytes",
            "HOST_SESSIOND_BROKER_BUDGET_RESPONSE_BYTES",
        ),
        (
            "broker-budget-concurrent",
            "HOST_SESSIOND_BROKER_BUDGET_CONCURRENT",
        ),
        (
            "github-response-cap-bytes",
            "HOST_SESSIOND_GITHUB_RESPONSE_CAP_BYTES",
        ),
        (
            "broker-max-connection-requests",
            "HOST_SESSIOND_BROKER_MAX_CONNECTION_REQUESTS",
        ),
        ("repository", "HOST_SESSIOND_REPOSITORY"),
        ("file-effects", "HOST_SESSIOND_FILE_EFFECTS"),
        ("path-prefix", "HOST_SESSIOND_PATH_PREFIX"),
        ("stop-file", "HOST_SESSIOND_STOP_ROOT"),
        ("poll-millis", "HOST_SESSIOND_POLL_MILLIS"),
        (
            "shutdown-timeout-millis",
            "HOST_SESSIOND_SHUTDOWN_TIMEOUT_MILLIS",
        ),
        ("status-file", "HOST_SESSIOND_STATUS_ROOT"),
    ];
    let mut arguments = Vec::with_capacity(mappings.len() * 2 + 6);
    arguments.extend(["--control-session-id".to_owned(), instance]);
    arguments.extend(["--mode".to_owned(), mode]);
    for (flag, variable) in mappings {
        let value = environment(variable)
            .ok_or_else(|| format!("systemd worker environment is missing {variable}"))?;
        if value.is_empty() || value.contains('\0') {
            return Err(format!("systemd worker environment has invalid {variable}"));
        }
        arguments.extend([format!("--{flag}"), value]);
    }
    arguments.extend(["--egress-authority".to_owned(), "none".to_owned()]);
    Ok(arguments)
}

fn run_session_loop(
    runtime: &mut session_orchestrator::production_runtime::ProductionSessionRuntime,
    stop_file: &Path,
    poll_interval: Duration,
    shutdown_timeout: Duration,
    signals: &ShutdownSignals,
    status: &StatusReporter,
    identity: SessionIdentity,
) -> Result<(), String> {
    loop {
        if let Some(request) = signals.requested() {
            eprintln!(
                "host-sessiond: {} received; draining cleanup",
                request.label()
            );
            return drain_stop(runtime, poll_interval, shutdown_timeout, status, request);
        }
        match stop_file_present(stop_file) {
            Ok(true) => {
                eprintln!(
                    "host-sessiond: stop file observed at {}; draining cleanup",
                    stop_file.display()
                );
                return drain_stop(
                    runtime,
                    poll_interval,
                    shutdown_timeout,
                    status,
                    ShutdownRequest::StopFile,
                );
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!(
                    "host-sessiond: stop file state is unavailable at {}; failing closed",
                    stop_file.display()
                );
                let cleanup = drain_stop(
                    runtime,
                    poll_interval,
                    shutdown_timeout,
                    status,
                    ShutdownRequest::StopFileUnavailable,
                );
                return match cleanup {
                    Ok(()) => Err(format!("observing configured stop file: {error}")),
                    Err(cleanup_error) => Err(format!(
                        "observing configured stop file: {error}; cleanup also failed: {cleanup_error}"
                    )),
                };
            }
        }
        match runtime.poll(OwnerPollRequest::Continue) {
            Ok(OwnerPollOutcome::Running(_)) => {
                thread::sleep(poll_interval.min(Duration::from_millis(250)));
            }
            Ok(OwnerPollOutcome::Closed(reason)) => {
                status.emit(
                    "closed",
                    "closed",
                    Some(identity),
                    Some(shutdown_reason_label(reason)),
                );
                return Ok(());
            }
            Err(error) if runtime.state() == session_orchestrator::LifecycleState::Closed => {
                eprintln!("host-sessiond: terminal poll error after cleanup: {error}");
                status.emit(
                    "closed",
                    "closed",
                    Some(identity),
                    Some("poll-terminal-error"),
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("host-sessiond: poll failed closed; retrying retained cleanup: {error}");
                status.emit(
                    "poll-error",
                    runtime.state().to_string().as_str(),
                    Some(identity),
                    Some("poll-retryable"),
                );
                thread::sleep(poll_interval.min(Duration::from_millis(250)));
            }
        }
    }
}

#[cfg(unix)]
fn notify_systemd_ready() -> Result<(), String> {
    let Some(raw) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err("NOTIFY_SOCKET is malformed".to_owned());
    }
    let address = if let Some(name) = bytes.strip_prefix(b"@") {
        if name.is_empty() {
            return Err("NOTIFY_SOCKET abstract name is empty".to_owned());
        }
        SocketAddrUnix::new_abstract_name(name)
    } else {
        let path = Path::new(&raw);
        if !path.is_absolute() {
            return Err("NOTIFY_SOCKET path is not absolute".to_owned());
        }
        SocketAddrUnix::new(path)
    }
    .map_err(|error| format!("parse NOTIFY_SOCKET: {error}"))?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| format!("create systemd notify socket: {error}"))?;
    let message = b"READY=1\nSTATUS=one session is ready";
    let written = sendto(&socket, message, SendFlags::empty(), &address)
        .map_err(|error| format!("notify systemd readiness: {error}"))?;
    if written != message.len() {
        return Err("systemd readiness datagram was truncated".to_owned());
    }
    Ok(())
}

#[cfg(not(unix))]
fn notify_systemd_ready() -> Result<(), String> {
    Ok(())
}

fn drain_stop(
    runtime: &mut session_orchestrator::production_runtime::ProductionSessionRuntime,
    interval: Duration,
    timeout: Duration,
    status: &StatusReporter,
    request: ShutdownRequest,
) -> Result<(), String> {
    let identity = runtime
        .active_session()
        .map(session_orchestrator::SessionInfo::identity);
    status.emit("stopping", "stopping", identity, Some(request.label()));
    let deadline = Instant::now() + timeout;
    loop {
        match runtime.stop() {
            Ok(OwnerPollOutcome::Closed(reason)) => {
                status.emit(
                    "closed",
                    "closed",
                    identity,
                    Some(shutdown_reason_label(reason)),
                );
                return Ok(());
            }
            Ok(OwnerPollOutcome::Running(_)) => {
                status.emit("failed", "running", identity, Some("stop-left-running"));
                return Err("stop request unexpectedly left the session running".to_owned());
            }
            Err(error) if runtime.state() == session_orchestrator::LifecycleState::Closed => {
                eprintln!("host-sessiond: terminal stop error after cleanup: {error}");
                status.emit("closed", "closed", identity, Some("stop-terminal-error"));
                return Ok(());
            }
            Err(error) => {
                eprintln!("host-sessiond: cleanup remains retryable: {error}");
                if Instant::now() >= deadline {
                    status.emit("failed", "stopping", identity, Some("shutdown-timeout"));
                    return Err(format!(
                        "shutdown exceeded configured timeout of {} ms",
                        timeout.as_millis()
                    ));
                }
                status.emit(
                    "cleanup-retry",
                    "stopping",
                    identity,
                    Some("cleanup-retryable"),
                );
                thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownRequest {
    StopFile,
    StopFileUnavailable,
    Sigterm,
    Sigint,
}

impl ShutdownRequest {
    const fn label(self) -> &'static str {
        match self {
            Self::StopFile => "stop-file",
            Self::StopFileUnavailable => "stop-file-unavailable",
            Self::Sigterm => "sigterm",
            Self::Sigint => "sigint",
        }
    }
}

fn stop_file_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

const fn shutdown_reason_label(
    reason: session_orchestrator::session_owner::ShutdownReason,
) -> &'static str {
    match reason {
        session_orchestrator::session_owner::ShutdownReason::ExternalRequest => "external-request",
        session_orchestrator::session_owner::ShutdownReason::BrokerExited => "broker-exited",
        session_orchestrator::session_owner::ShutdownReason::BrokerStatusUnavailable => {
            "broker-status-unavailable"
        }
        session_orchestrator::session_owner::ShutdownReason::StartupRollback => "startup-rollback",
    }
}

#[derive(Clone)]
struct ShutdownSignals {
    #[cfg(unix)]
    term: Arc<AtomicBool>,
    #[cfg(unix)]
    interrupt: Arc<AtomicBool>,
}

#[cfg(unix)]
fn install_signal_handlers() -> Result<ShutdownSignals, String> {
    let term = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))
        .map_err(|error| format!("registering SIGTERM handler: {error}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupt))
        .map_err(|error| format!("registering SIGINT handler: {error}"))?;
    Ok(ShutdownSignals { term, interrupt })
}

#[cfg(not(unix))]
fn install_signal_handlers() -> Result<ShutdownSignals, String> {
    Ok(ShutdownSignals)
}

impl ShutdownSignals {
    fn requested(&self) -> Option<ShutdownRequest> {
        #[cfg(unix)]
        {
            if self.term.load(Ordering::Relaxed) {
                return Some(ShutdownRequest::Sigterm);
            }
            if self.interrupt.load(Ordering::Relaxed) {
                return Some(ShutdownRequest::Sigint);
            }
        }
        None
    }
}

struct StatusReporter {
    status_path: Option<PathBuf>,
    status_file: Option<RefCell<fs::File>>,
}

impl StatusReporter {
    fn new(status_path: Option<PathBuf>) -> Result<Self, String> {
        let status_file = status_path
            .as_deref()
            .map(open_status_file)
            .transpose()?
            .map(RefCell::new);
        Ok(Self {
            status_path,
            status_file,
        })
    }

    fn emit(
        &self,
        event: &'static str,
        state: &str,
        identity: Option<session_orchestrator::SessionIdentity>,
        reason: Option<&'static str>,
    ) {
        let line = status_line(event, state, identity, reason);
        let _ = writeln!(io::stdout().lock(), "{line}");
        if let (Some(path), Some(file)) = (self.status_path.as_deref(), self.status_file.as_ref())
            && let Err(error) = write_status_file(&mut file.borrow_mut(), &line)
        {
            eprintln!(
                "host-sessiond: could not update status file {}: {error}",
                path.display()
            );
        }
    }
}

fn status_line(
    event: &'static str,
    state: &str,
    identity: Option<session_orchestrator::SessionIdentity>,
    reason: Option<&'static str>,
) -> String {
    use std::fmt::Write as _;

    let mut line = format!(
        r#"{{"schema":"host-sessiond/v1","event":"{}","state":"{}""#,
        json_string(event),
        json_string(state),
    );
    if let Some(identity) = identity {
        // These are opaque, random lifecycle identifiers. Credentials, paths, authority bodies,
        // and backend error text are deliberately excluded from the machine-readable record.
        let _ = write!(
            line,
            r#","session_id":"{}","workspace_id":"{}","subject_id":"{}","capability_id":"{}""#,
            identity.session_id(),
            identity.workspace_id(),
            identity.subject_id(),
            identity.capability_id(),
        );
    }
    if let Some(reason) = reason {
        let _ = write!(line, r#","reason":"{}""#, json_string(reason));
    }
    line.push('}');
    line
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(unix)]
fn open_status_file(path: &Path) -> Result<fs::File, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "status file has no parent directory".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect status directory {}: {error}", parent.display()))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "status parent must be a secure, service-owned directory: {}",
            parent.display()
        ));
    }
    let descriptor = openat2(
        CWD,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR | Mode::RGRP,
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("securely open status file {}: {error}", path.display()))?;
    let file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect opened status file {}: {error}", path.display()))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "status file must be a singly-linked, service-owned regular file: {}",
            path.display()
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o640))
        .map_err(|error| format!("set status file permissions {}: {error}", path.display()))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_status_file(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .map_err(|error| format!("open status file {}: {error}", path.display()))
}

fn write_status_file(file: &mut fs::File, line: &str) -> Result<(), String> {
    file.set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|error| format!("truncate status file: {error}"))?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write status file: {error}"))
}

struct DaemonConfig {
    production: ProductionSessionConfig,
    runtime: RuntimeConfig,
    snapshot_id: SnapshotId,
    kernel_source: PinnedArtifact,
    seccomp_source: PinnedArtifact,
    snapshot_state: PinnedArtifact,
    snapshot_memory: PinnedArtifact,
    github_egress: GitHubEgressConfig,
    grant: AuthorityRootGrant,
    stop_file: PathBuf,
    poll_interval: Duration,
    shutdown_timeout: Duration,
    status_file: Option<PathBuf>,
    recover_only: bool,
}

impl DaemonConfig {
    #[allow(clippy::too_many_lines)] // Every required deployment boundary is parsed explicitly.
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut arguments = Arguments::parse(arguments)?;
        let control_session = arguments
            .optional("control-session-id")?
            .map(|value| ControlInstance::parse(&value))
            .transpose()?;
        let recover_only = match arguments.optional("mode")?.as_deref().unwrap_or("run") {
            "run" => false,
            "recover" => true,
            value => return Err(format!("--mode must be run or recover, got {value:?}")),
        };
        let firecracker = arguments.pinned("firecracker")?;
        let jailer = arguments.pinned("jailer")?;
        let kernel_source = arguments.pinned("kernel-source")?;
        let rootfs = arguments.pinned("rootfs")?;
        let verity_hash = arguments.pinned("verity-hash")?;
        let formatter = arguments.pinned("workspace-formatter")?;
        let seccomp_compiler = arguments.pinned("seccomp-compiler")?;
        let seccomp_source = arguments.pinned("seccomp-source")?;
        let seccomp_policy_source = arguments.pinned("seccomp-policy-source")?;
        let snapshot_state = arguments.pinned("snapshot-state")?;
        let snapshot_memory = arguments.pinned("snapshot-memory")?;
        let veritysetup = arguments.pinned("veritysetup")?;
        let dmsetup = arguments.pinned("dmsetup")?;
        let chroot_base = scoped_jailer_directory(
            &arguments.absolute_path("jailer-chroot-base")?,
            control_session,
        );
        let workspace_source = arguments.absolute_path("workspace-source")?;
        let cgroup_parent = scoped_cgroup_parent(
            &parse_cgroup_parent(&arguments.required("cgroup-parent")?)?,
            control_session,
        );
        if control_session.is_some() {
            verify_own_systemd_cgroup(&cgroup_parent)?;
        }
        let firecracker_name = firecracker
            .path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "--firecracker path must have a filename".to_owned())?;
        let template_root = chroot_base
            .join(firecracker_name)
            .join(TEMPLATE_CLONE_ID)
            .join("root");
        // A systemd worker path contains both the controller session ID and the runtime workspace
        // ID. Compact in-jail names keep the host-visible endpoint within Linux sockaddr_un even
        // for a maximum-width u32 guest port; direct single-session mode retains descriptive names.
        let (api_socket, vsock_uds_path) = if control_session.is_some() {
            (template_root.join("a"), template_root.join("v"))
        } else {
            (
                template_root.join("run/firecracker.sock"),
                template_root.join("run/vsock.sock"),
            )
        };
        let guest_cid = arguments.number("guest-cid")?;
        let runtime = RuntimeConfig {
            firecracker,
            kernel: PinnedArtifact::new(
                template_root.join("artifacts/kernel"),
                kernel_source.digest,
            ),
            rootfs: rootfs.clone(),
            verity_hash: verity_hash.clone(),
            veritysetup: veritysetup.clone(),
            dm_verity: DmVerityConfig {
                data_device: rootfs.path.clone(),
                hash_device: verity_hash.path.clone(),
                mapper_name: scoped_mapper_prefix(
                    &arguments.required("verity-mapper-prefix")?,
                    control_session,
                )?,
                root_hash: arguments.digest("rootfs-verity-root-hash")?,
                jailed_device_path: template_root.join("dev/rootfs"),
            },
            workspace: WorkspaceConfig {
                source: workspace_source,
                clone_root: template_root.join("workspace"),
                clone_id: TEMPLATE_CLONE_ID.to_owned(),
                image: WorkspaceImageConfig {
                    formatter,
                    size_bytes: arguments.number("workspace-image-bytes")?,
                },
            },
            jailer,
            jailer_config: JailerConfig {
                uid: arguments.number("jailer-uid")?,
                gid: arguments.number("jailer-gid")?,
                chroot_base_dir: chroot_base,
                cgroup_version: CgroupVersion::V2,
            },
            api_socket,
            isolation: HostIsolationConfig {
                namespaces: NamespaceConfig {
                    user: false,
                    pid: true,
                    mount: true,
                    network: false,
                    ipc: false,
                    uts: false,
                },
                cgroup: CgroupConfig {
                    path: Path::new("/sys/fs/cgroup")
                        .join(cgroup_parent)
                        .join(TEMPLATE_CLONE_ID),
                    memory_max_bytes: arguments.number("memory-max-bytes")?,
                    cpu_quota_micros: arguments.number("cpu-quota-micros")?,
                    cpu_period_micros: arguments.number("cpu-period-micros")?,
                },
                seccomp: SeccompConfig {
                    compiler: seccomp_compiler,
                    filter: PinnedArtifact::new(
                        template_root.join("artifacts/seccomp"),
                        seccomp_source.digest,
                    ),
                    policy: seccomp_policy_source.clone(),
                    blocked_syscalls: REQUIRED_SECCOMP_DENIES
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                },
            },
            vsock: VsockConfig {
                guest_cid,
                uds_path: vsock_uds_path,
            },
            network_devices: Vec::new(),
            vcpu_count: arguments.number("vcpu-count")?,
            memory_mib: arguments.number("memory-mib")?,
            boot_args: arguments.required("boot-args")?,
        };
        let snapshot_id = arguments.snapshot_id("snapshot-id")?;
        let repository = arguments.required("repository")?;
        let effects = arguments.required("file-effects")?;
        let path_prefix = arguments.required("path-prefix")?;
        let authority = file_authority(repository, &effects, &path_prefix)?;
        let validity = TimeWindow::new(
            MonotonicTime::from_ticks(0),
            MonotonicTime::from_ticks(u64::MAX),
        )
        .map_err(|error| format!("creating fixed guest-compatible validity window: {error}"))?;
        let (broker_authority, github_egress) =
            parse_egress_profile(&mut arguments, authority.repository().clone())?;
        let mut grant = AuthorityRootGrant::new(validity, AuthorityBody::File(authority));
        if let Some(broker_authority) = broker_authority {
            grant = grant.with_broker_authority(broker_authority);
        }
        let audit_path = scoped_file(
            &arguments.absolute_path("authority-audit")?,
            control_session,
            "authority-audit",
        );
        let audit_mode = match arguments.required("authority-audit-mode")?.as_str() {
            "create" => AuthorityAuditMode::CreateNew(audit_path.clone()),
            "open" => AuthorityAuditMode::OpenExisting(audit_path.clone()),
            "auto" => match fs::symlink_metadata(&audit_path) {
                Ok(_) => AuthorityAuditMode::OpenExisting(audit_path.clone()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    AuthorityAuditMode::CreateNew(audit_path.clone())
                }
                Err(error) => {
                    return Err(format!(
                        "cannot inspect --authority-audit {} for auto mode: {error}",
                        audit_path.display()
                    ));
                }
            },
            value => {
                return Err(format!(
                    "--authority-audit-mode must be create, open, or auto, got {value:?}"
                ));
            }
        };
        let broker_limits = ProductionBrokerLimits::new(
            arguments.nonzero_usize("broker-replay-capacity")?,
            arguments.nonzero_u64("broker-budget-requests")?,
            arguments.number("broker-budget-response-bytes")?,
            arguments.nonzero_usize("broker-budget-concurrent")?,
            arguments.number("github-response-cap-bytes")?,
            arguments.nonzero_usize("broker-max-connection-requests")?,
        );
        let identity_ledger_path = scoped_file(
            &arguments.absolute_path("identity-ledger")?,
            control_session,
            "identity-ledger",
        );
        let recovery_journal_path = scoped_file(
            &arguments.absolute_path("recovery-journal")?,
            control_session,
            "recovery-journal",
        );
        let broker_wal_root = scoped_file(
            &arguments.absolute_path("broker-wal-root")?,
            control_session,
            "broker-wal",
        );
        let broker_port = arguments.number("broker-port")?;
        let production = ProductionSessionConfig::new(
            ProductionDurabilityConfig::new(
                identity_ledger_path.clone(),
                recovery_journal_path.clone(),
                audit_mode,
                broker_wal_root.clone(),
            ),
            IssuerId::new(arguments.required("issuer")?),
            ProductionFirecrackerConfig::new(
                runtime.clone(),
                RecoveryTools::new(veritysetup, dmsetup),
            ),
            WorkspaceTemplateId::new(arguments.required("workspace-template")?),
            ProductionBrokerEndpoint::new(
                arguments.number("broker-host-cid")?,
                guest_cid,
                broker_port,
                arguments.number("broker-backlog")?,
            ),
            ProductionGuestControlEndpoint::new(arguments.number("guest-control-port")?),
            broker_limits,
        );
        let stop_file = scoped_file(
            &arguments.absolute_path("stop-file")?,
            control_session,
            "stop",
        );
        match fs::symlink_metadata(&stop_file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(format!(
                    "--stop-file must be absent when the daemon starts: {}",
                    stop_file.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect --stop-file {}: {error}",
                    stop_file.display()
                ));
            }
        }
        let poll_interval = Duration::from_millis(arguments.nonzero_u64("poll-millis")?.get());
        let shutdown_timeout =
            validate_shutdown_timeout(arguments.nonzero_u64("shutdown-timeout-millis")?.get())?;
        let status_file = arguments
            .optional("status-file")?
            .map(|value| {
                let path = scoped_file(&PathBuf::from(value), control_session, "status");
                validate_absolute_path("status-file", &path)?;
                Ok::<PathBuf, String>(path)
            })
            .transpose()?;
        if let Some(status_file) = status_file.as_deref() {
            validate_status_file_separation(
                status_file,
                &[
                    &identity_ledger_path,
                    &recovery_journal_path,
                    &audit_path,
                    &stop_file,
                    &runtime.firecracker.path,
                    &runtime.kernel.path,
                    &runtime.rootfs.path,
                    &runtime.verity_hash.path,
                    &runtime.veritysetup.path,
                    &runtime.workspace.image.formatter.path,
                    &runtime.jailer.path,
                    &runtime.isolation.seccomp.compiler.path,
                    &runtime.isolation.seccomp.filter.path,
                    &runtime.isolation.seccomp.policy.path,
                    &kernel_source.path,
                    &seccomp_source.path,
                    &snapshot_state.path,
                    &snapshot_memory.path,
                ],
                &[
                    &broker_wal_root,
                    &runtime.jailer_config.chroot_base_dir,
                    &runtime.workspace.source,
                    &runtime.workspace.clone_root,
                ],
            )?;
        }
        arguments.finish()?;
        Ok(Self {
            production,
            runtime,
            snapshot_id,
            kernel_source,
            seccomp_source,
            snapshot_state,
            snapshot_memory,
            github_egress,
            grant,
            stop_file,
            poll_interval,
            shutdown_timeout,
            status_file,
            recover_only,
        })
    }
}

fn validate_status_file_separation(
    status_file: &Path,
    protected_files: &[&PathBuf],
    protected_roots: &[&PathBuf],
) -> Result<(), String> {
    if protected_files
        .iter()
        .any(|path| status_file == path.as_path())
        || protected_roots
            .iter()
            .any(|root| status_file == root.as_path() || status_file.starts_with(root))
    {
        return Err(format!(
            "--status-file must be disjoint from every durable, runtime, workspace, and artifact path: {}",
            status_file.display()
        ));
    }
    Ok(())
}

fn validate_shutdown_timeout(milliseconds: u64) -> Result<Duration, String> {
    if milliseconds > MAX_SHUTDOWN_TIMEOUT_MILLIS {
        return Err(format!(
            "--shutdown-timeout-millis must be at most {MAX_SHUTDOWN_TIMEOUT_MILLIS}"
        ));
    }
    Ok(Duration::from_millis(milliseconds))
}

struct Arguments {
    values: BTreeMap<String, String>,
}

impl Arguments {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut iterator = arguments.into_iter();
        while let Some(flag) = iterator.next() {
            if !flag.starts_with("--") || flag.len() == 2 {
                return Err(format!("expected a --flag, got {flag:?}; {}", usage()));
            }
            let value = iterator
                .next()
                .ok_or_else(|| format!("missing value for {flag}; {}", usage()))?;
            let key = flag.trim_start_matches("--").to_owned();
            if values.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate command-line flag --{key}"));
            }
        }
        Ok(Self { values })
    }

    fn required(&mut self, name: &str) -> Result<String, String> {
        self.values
            .remove(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing required --{name}"))
    }

    fn optional(&mut self, name: &str) -> Result<Option<String>, String> {
        match self.values.remove(name) {
            Some(value) if value.is_empty() => Err(format!("--{name} cannot be empty")),
            Some(value) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    fn number<T>(&mut self, name: &str) -> Result<T, String>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        parse_number(&format!("--{name}"), &self.required(name)?)
    }

    fn nonzero_u64(&mut self, name: &str) -> Result<NonZeroU64, String> {
        NonZeroU64::new(self.number(name)?).ok_or_else(|| format!("--{name} must be non-zero"))
    }

    fn nonzero_usize(&mut self, name: &str) -> Result<NonZeroUsize, String> {
        NonZeroUsize::new(self.number(name)?).ok_or_else(|| format!("--{name} must be non-zero"))
    }

    fn absolute_path(&mut self, name: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(self.required(name)?);
        validate_absolute_path(name, &path)?;
        Ok(path)
    }

    fn digest(&mut self, name: &str) -> Result<Sha256Digest, String> {
        Sha256Digest::from_hex(&self.required(name)?)
            .map_err(|error| format!("invalid --{name}: {error}"))
    }

    fn pinned(&mut self, name: &str) -> Result<PinnedArtifact, String> {
        Ok(PinnedArtifact::new(
            self.absolute_path(name)?,
            self.digest(&format!("{name}-sha256"))?,
        ))
    }

    fn snapshot_id(&mut self, name: &str) -> Result<SnapshotId, String> {
        Ok(SnapshotId::new(parse_hex_16(
            &format!("--{name}"),
            &self.required(name)?,
        )?))
    }

    fn finish(self) -> Result<(), String> {
        if self.values.is_empty() {
            Ok(())
        } else {
            let unexpected = self.values.keys().cloned().collect::<Vec<_>>().join(", ");
            Err(format!("unknown command-line flag(s): {unexpected}"))
        }
    }
}

fn parse_number<T>(label: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} must be an unsigned decimal integer"));
    }
    value
        .parse()
        .map_err(|error| format!("invalid {label}: {error}"))
}

fn parse_hex_16(label: &str, value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be exactly 32 hexadecimal characters"));
    }
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| format!("{label} contains a non-hexadecimal byte"))?;
    }
    Ok(bytes)
}

fn validate_absolute_path(label: &str, path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "--{label} must be an absolute non-root path with only normal components: {}",
            path.display()
        ));
    }
    Ok(())
}

fn parse_cgroup_parent(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.split('/').any(|component| {
            component.is_empty()
                || component.starts_with('.')
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@')
                })
        })
    {
        return Err("--cgroup-parent must be safe relative cgroup components".to_owned());
    }
    Ok(PathBuf::from(value))
}

#[derive(Clone, Copy)]
struct ControlInstance([u8; 16]);

impl ControlInstance {
    fn parse(value: &str) -> Result<Self, String> {
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "--control-session-id must use exactly 32 lower-case hexadecimal characters"
                    .to_owned(),
            );
        }
        let bytes = parse_hex_16("--control-session-id", value)?;
        if bytes == [0; 16] {
            return Err("--control-session-id cannot be all zeroes".to_owned());
        }
        Ok(Self(bytes))
    }

    fn name(self) -> String {
        let mut name = String::with_capacity(32);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        name
    }
}

fn scoped_jailer_directory(base: &Path, instance: Option<ControlInstance>) -> PathBuf {
    instance.map_or_else(|| base.to_owned(), |instance| base.join(instance.name()))
}

fn scoped_file(base: &Path, instance: Option<ControlInstance>, leaf: &str) -> PathBuf {
    instance.map_or_else(
        || base.to_owned(),
        |instance| base.join(instance.name()).join(leaf),
    )
}

fn scoped_cgroup_parent(base: &Path, instance: Option<ControlInstance>) -> PathBuf {
    instance.map_or_else(
        || base.to_owned(),
        |instance| base.join(format!("host-sessiond@{}.service", instance.name())),
    )
}

fn verify_own_systemd_cgroup(expected: &Path) -> Result<(), String> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("read own cgroup membership: {error}"))?;
    let expected = format!("0::/{}", expected.display());
    if cgroup
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        != [expected]
    {
        return Err("systemd worker is not running in its exact delegated cgroup".to_owned());
    }
    Ok(())
}

fn scoped_mapper_prefix(base: &str, instance: Option<ControlInstance>) -> Result<String, String> {
    let value = instance.map_or_else(
        || base.to_owned(),
        |instance| format!("{base}-{}", instance.name()),
    );
    if value.len() > 127 {
        return Err("session-scoped --verity-mapper-prefix exceeds 127 bytes".to_owned());
    }
    Ok(value)
}

fn file_authority(
    repository: String,
    effects: &str,
    path_prefix: &str,
) -> Result<FileAuthority, String> {
    if repository.is_empty()
        || repository.len() > 128
        || !repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("--repository must be a 1-128 byte safe identifier".to_owned());
    }
    Ok(FileAuthority::new(
        RepoId::new(repository),
        parse_file_effects(effects)?,
        parse_path_prefix(path_prefix)?,
    ))
}

fn parse_file_effects(value: &str) -> Result<FileEffects, String> {
    if value.is_empty() || value.starts_with(',') || value.ends_with(',') || value.contains(",,") {
        return Err("--file-effects must be a non-empty canonical comma list".to_owned());
    }
    let mut previous = None;
    let mut parsed = Vec::new();
    for name in value.split(',') {
        let (index, effect) = match name {
            "read-data" => (0, FileEffect::ReadData),
            "list-directory" => (1, FileEffect::ListDirectory),
            "write-data" => (2, FileEffect::WriteData),
            "truncate" => (3, FileEffect::Truncate),
            "create-file" => (4, FileEffect::CreateFile),
            "create-directory" => (5, FileEffect::CreateDirectory),
            "remove-file" => (6, FileEffect::RemoveFile),
            "remove-directory" => (7, FileEffect::RemoveDirectory),
            "rename" => (8, FileEffect::Rename),
            "set-metadata" => (9, FileEffect::SetMetadata),
            "read-link" => (10, FileEffect::ReadLink),
            "create-symlink" => (11, FileEffect::CreateSymlink),
            "create-hard-link" => (12, FileEffect::CreateHardLink),
            _ => return Err("--file-effects contains a non-canonical effect".to_owned()),
        };
        if previous.is_some_and(|previous| index <= previous) {
            return Err("--file-effects must be ordered with no duplicates".to_owned());
        }
        previous = Some(index);
        parsed.push(effect);
    }
    Ok(FileEffects::from_effects(parsed))
}

fn parse_path_prefix(value: &str) -> Result<PathPattern, String> {
    if value == "/" {
        return Ok(PathPattern::Prefix(CanonicalPath::root()));
    }
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err("--path-prefix must be / or canonical safe relative segments".to_owned());
    }
    CanonicalPath::new(value.split('/'))
        .map(PathPattern::Prefix)
        .map_err(|error| format!("invalid --path-prefix: {error}"))
}

/// Parses the sole external authority family that may be attached to this session's Broker.
///
/// File authority always remains in the guest capability channel. The Broker gets a distinct
/// typed root only for an explicitly selected external profile, so a guest cannot turn a
/// workspace capability into ambient network or GitHub access.
fn parse_egress_profile(
    arguments: &mut Arguments,
    repository: RepoId,
) -> Result<(Option<AuthorityBody>, GitHubEgressConfig), String> {
    match arguments.required("egress-authority")?.as_str() {
        "none" => {
            reject_egress_flags(arguments)?;
            Ok((None, GitHubEgressConfig::Disabled))
        }
        "public" => {
            reject_github_flags(arguments)?;
            let methods = parse_http_methods(&arguments.required("public-methods")?)?;
            let host = CanonicalHost::new(arguments.required("public-host")?)
                .map_err(|error| format!("invalid --public-host: {error}"))?;
            let path = CanonicalUrlPath::new(arguments.required("public-path-prefix")?)
                .map_err(|error| format!("invalid --public-path-prefix: {error}"))?;
            let max_response_bytes = arguments.nonzero_u64("public-max-response-bytes")?.get();
            Ok((
                Some(AuthorityBody::HttpFetch(HttpFetchAuthority::new(
                    methods,
                    host,
                    UrlPathPattern::Prefix(path),
                    max_response_bytes,
                ))),
                GitHubEgressConfig::Disabled,
            ))
        }
        "github" => {
            reject_public_flags(arguments)?;
            let installation = InstallationId::new(arguments.required("github-installation")?);
            let credential_handle =
                CredentialHandle::from_host_id(arguments.number("github-credential-handle")?);
            let operations = parse_github_operations(&arguments.required("github-operations")?)?;
            let base = parse_branch_pattern(
                "--github-base-branch-pattern",
                &arguments.required("github-base-branch-pattern")?,
            )?;
            let head = parse_branch_pattern(
                "--github-head-branch-pattern",
                &arguments.required("github-head-branch-pattern")?,
            )?;
            let authority =
                GitHubAuthority::new(installation.clone(), repository, operations, base, head);
            let publish_plans_path = arguments
                .optional("github-publish-plans")?
                .map(PathBuf::from);
            if let Some(path) = publish_plans_path.as_deref() {
                validate_absolute_path("github-publish-plans", path)?;
            }
            let publish_plans = if authority
                .operations()
                .contains(GitHubOperation::PublishBranch)
            {
                let path = publish_plans_path.ok_or_else(|| {
                    "--github-publish-plans is required when GitHub operations include publish-branch"
                        .to_owned()
                })?;
                let plans = load_publish_plan_manifest(path)
                    .map_err(|error| format!("loading --github-publish-plans: {error}"))?;
                validate_publish_plans_for_authority(&authority, plans)
                    .map_err(|error| format!("validating --github-publish-plans: {error}"))?
            } else {
                if publish_plans_path.is_some() {
                    return Err(
                        "--github-publish-plans requires publish-branch in --github-operations"
                            .to_owned(),
                    );
                }
                Vec::new()
            };
            Ok((
                Some(AuthorityBody::GitHub(authority)),
                GitHubEgressConfig::environment_with_plans(
                    installation,
                    credential_handle,
                    publish_plans,
                ),
            ))
        }
        value => Err(format!(
            "--egress-authority must be none, public, or github, got {value:?}"
        )),
    }
}

fn reject_egress_flags(arguments: &mut Arguments) -> Result<(), String> {
    reject_public_flags(arguments)?;
    reject_github_flags(arguments)
}

fn reject_public_flags(arguments: &mut Arguments) -> Result<(), String> {
    reject_absent(
        arguments,
        [
            "public-methods",
            "public-host",
            "public-path-prefix",
            "public-max-response-bytes",
        ],
    )
}

fn reject_github_flags(arguments: &mut Arguments) -> Result<(), String> {
    reject_absent(
        arguments,
        [
            "github-installation",
            "github-credential-handle",
            "github-operations",
            "github-base-branch-pattern",
            "github-head-branch-pattern",
            "github-publish-plans",
        ],
    )
}

fn reject_absent<'a>(
    arguments: &mut Arguments,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    for name in names {
        if arguments.optional(name)?.is_some() {
            return Err(format!(
                "--{name} is incompatible with this --egress-authority"
            ));
        }
    }
    Ok(())
}

fn parse_http_methods(value: &str) -> Result<HttpFetchMethods, String> {
    if value.is_empty() || value.starts_with(',') || value.ends_with(',') || value.contains(",,") {
        return Err("--public-methods must be a non-empty canonical comma list".to_owned());
    }
    let mut previous = None;
    let mut parsed = Vec::new();
    for method in value.split(',') {
        let (index, method) = match method {
            "get" => (0, HttpFetchMethod::Get),
            "head" => (1, HttpFetchMethod::Head),
            _ => return Err("--public-methods contains a non-canonical method".to_owned()),
        };
        if previous.is_some_and(|previous| index <= previous) {
            return Err("--public-methods must be ordered with no duplicates".to_owned());
        }
        previous = Some(index);
        parsed.push(method);
    }
    Ok(HttpFetchMethods::from_methods(parsed))
}

fn parse_github_operations(value: &str) -> Result<GitHubOperations, String> {
    if value.is_empty() || value.starts_with(',') || value.ends_with(',') || value.contains(",,") {
        return Err("--github-operations must be a non-empty canonical comma list".to_owned());
    }
    let mut previous = None;
    let mut parsed = Vec::new();
    for operation in value.split(',') {
        let (index, operation) = match operation {
            "publish-branch" => (0, GitHubOperation::PublishBranch),
            "create-pull-request" => (1, GitHubOperation::CreatePullRequest),
            _ => return Err("--github-operations contains a non-canonical operation".to_owned()),
        };
        if previous.is_some_and(|previous| index <= previous) {
            return Err("--github-operations must be ordered with no duplicates".to_owned());
        }
        previous = Some(index);
        parsed.push(operation);
    }
    Ok(GitHubOperations::from_operations(parsed))
}

fn parse_branch_pattern(label: &str, value: &str) -> Result<BranchPattern, String> {
    let (kind, branch) = value
        .split_once(':')
        .ok_or_else(|| format!("{label} must be exact:BRANCH or prefix:BRANCH"))?;
    let branch = BranchName::new(branch).map_err(|error| format!("invalid {label}: {error}"))?;
    match kind {
        "exact" => Ok(BranchPattern::Exact(branch)),
        "prefix" => Ok(BranchPattern::Prefix(branch)),
        _ => Err(format!("{label} must be exact:BRANCH or prefix:BRANCH")),
    }
}

fn usage() -> &'static str {
    "usage: host-sessiond \\
  --firecracker PATH --firecracker-sha256 SHA256 --jailer PATH --jailer-sha256 SHA256 \\
  --kernel-source PATH --kernel-source-sha256 SHA256 --rootfs PATH --rootfs-sha256 SHA256 \\
  --verity-hash PATH --verity-hash-sha256 SHA256 --rootfs-verity-root-hash SHA256 \\
  --workspace-formatter PATH --workspace-formatter-sha256 SHA256 --workspace-source PATH \\
  --seccomp-compiler PATH --seccomp-compiler-sha256 SHA256 \\
  --seccomp-source PATH --seccomp-source-sha256 SHA256 \\
  --seccomp-policy-source PATH --seccomp-policy-source-sha256 SHA256 --snapshot-id HEX32 \\
  --snapshot-state PATH --snapshot-state-sha256 SHA256 --snapshot-memory PATH --snapshot-memory-sha256 SHA256 \\
  --veritysetup PATH --veritysetup-sha256 SHA256 --dmsetup PATH --dmsetup-sha256 SHA256 \\
  --jailer-chroot-base PATH --cgroup-parent RELATIVE --jailer-uid UID --jailer-gid GID \\
  --verity-mapper-prefix NAME --workspace-image-bytes BYTES --memory-max-bytes BYTES \\
  --cpu-quota-micros MICROS --cpu-period-micros MICROS --guest-cid CID --vcpu-count COUNT \\
  --memory-mib MIB --boot-args ARGS --issuer ID --workspace-template ID \\
  --identity-ledger PATH --recovery-journal PATH --authority-audit PATH --authority-audit-mode create|open|auto \\
  --broker-wal-root PATH --broker-host-cid CID --broker-port PORT --broker-backlog COUNT \\
  --guest-control-port PORT --broker-replay-capacity COUNT --broker-budget-requests COUNT \\
  --broker-budget-response-bytes BYTES --broker-budget-concurrent COUNT --github-response-cap-bytes BYTES \\
  --broker-max-connection-requests COUNT --repository ID --file-effects CANONICAL-LIST \\
  --path-prefix /|PATH --egress-authority none|public|github --stop-file PATH --poll-millis MILLIS \\
  --shutdown-timeout-millis MILLIS [--status-file PATH] \\
  [--public-methods get[,head] --public-host DNS --public-path-prefix /PATH --public-max-response-bytes BYTES] \\
  [--github-installation ID --github-credential-handle INTEGER --github-operations CANONICAL-LIST \\
   --github-base-branch-pattern exact:BRANCH|prefix:BRANCH \\
  --github-head-branch-pattern exact:BRANCH|prefix:BRANCH \\
  --github-publish-plans PATH]\n\nThe stop file must be absent at startup. SIGTERM and SIGINT, or the stop file, request a dependency-ordered shutdown. Cleanup retries only until --shutdown-timeout-millis; a timeout exits non-zero and leaves the durable recovery records for the next start. Readiness and lifecycle records are JSON lines on stdout and, when --status-file is set, in an owner-readable status file. They contain opaque lifecycle IDs only; credentials, authority bodies, paths, and backend error text are never written to the status record. Select exactly one egress profile: `none` issues no external authority, `public` issues a host/path/method-limited HTTPS authority, and `github` issues a typed GitHub authority. A GitHub `publish-branch` authority also requires an owner-readable `--github-publish-plans` manifest; `create-pull-request` alone does not. GitHub tokens are read from the systemd credential `github-token` when available, with EGRESS_GITHUB_TOKEN retained as the explicit non-systemd fallback."
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::ffi::OsStrExt,
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{
        Arguments, ControlInstance, MAX_SHUTDOWN_TIMEOUT_MILLIS, ShutdownRequest, file_authority,
        json_string, parse_branch_pattern, parse_cgroup_parent, parse_egress_profile,
        parse_file_effects, parse_github_operations, parse_hex_16, parse_http_methods,
        parse_path_prefix, scoped_file, scoped_jailer_directory, status_line, stop_file_present,
        systemd_arguments, validate_absolute_path, validate_shutdown_timeout,
    };
    use authority_core::{capability::AuthorityBody, repository::RepoId};
    use firecracker_runtime::firecracker_guest_port_path;
    use session_orchestrator::system_egress::GitHubEgressConfig;

    fn arguments(values: &[&str]) -> Arguments {
        Arguments::parse(values.iter().map(|value| (*value).to_owned()))
            .expect("test arguments must have complete flag/value pairs")
    }

    fn argument_value<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
        arguments
            .windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].as_str())
    }

    #[test]
    fn systemd_workers_use_snapshot_compatible_vsock_values_from_the_environment() {
        let arguments = systemd_arguments(
            vec![
                "--systemd-instance".to_owned(),
                "00112233445566778899aabbccddeeff".to_owned(),
                "--mode".to_owned(),
                "run".to_owned(),
            ],
            |variable| {
                Some(match variable {
                    "HOST_SESSIOND_GUEST_CID" => "42".to_owned(),
                    "HOST_SESSIOND_BROKER_PORT" => "5001".to_owned(),
                    _ => "fixture".to_owned(),
                })
            },
        )
        .expect("complete systemd worker environment must map to daemon arguments");

        assert_eq!(argument_value(&arguments, "--guest-cid"), Some("42"));
        assert_eq!(argument_value(&arguments, "--broker-port"), Some("5001"));
        assert_eq!(
            argument_value(&arguments, "--control-session-id"),
            Some("00112233445566778899aabbccddeeff")
        );
    }

    #[test]
    fn systemd_worker_jailer_and_durability_paths_are_disjoint() {
        let instance = ControlInstance::parse("00112233445566778899aabbccddeeff")
            .expect("canonical instance must parse");
        let jail_base = Path::new("/var/lib/host-jails");
        let durability_base = Path::new("/var/lib/host-sessiond/instances");

        assert_eq!(
            scoped_jailer_directory(jail_base, Some(instance)),
            jail_base.join("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            scoped_file(durability_base, Some(instance), "identity-ledger"),
            durability_base.join("00112233445566778899aabbccddeeff/identity-ledger")
        );

        let maximum_port_path = firecracker_guest_port_path(
            jail_base
                .join("00112233445566778899aabbccddeeff")
                .join("fc/ffeeddccbbaa99887766554433221100/root/v"),
            u32::MAX - 1,
        )
        .expect("canonical systemd vsock endpoint must derive");
        assert!(
            maximum_port_path.as_os_str().as_bytes().len() < 108,
            "the maximum systemd guest-port endpoint must fit sockaddr_un"
        );
    }

    #[test]
    fn policy_parser_matches_the_guest_image_contract() {
        assert!(parse_file_effects("read-data,list-directory,write-data").is_ok());
        assert!(parse_file_effects("write-data,read-data").is_err());
        assert!(parse_file_effects("read-data,read-data").is_err());
        assert!(parse_path_prefix("src/generated").is_ok());
        assert!(parse_path_prefix("src/../escape").is_err());
        assert!(parse_hex_16("snapshot", "0123456789abcdef0123456789abcdef").is_ok());
        assert!(parse_hex_16("snapshot", "invalid").is_err());
    }

    #[test]
    fn egress_policy_lists_are_closed_and_canonical() {
        assert!(parse_http_methods("get,head").is_ok());
        assert!(parse_http_methods("head,get").is_err());
        assert!(parse_http_methods("get,get").is_err());
        assert!(parse_github_operations("publish-branch,create-pull-request").is_ok());
        assert!(parse_github_operations("create-pull-request,publish-branch").is_err());
        assert!(parse_branch_pattern("--branch", "exact:main").is_ok());
        assert!(parse_branch_pattern("--branch", "prefix:agent/work").is_ok());
        assert!(parse_branch_pattern("--branch", "all:main").is_err());
        assert!(parse_branch_pattern("--branch", "prefix:refs/heads/main").is_err());
    }

    #[test]
    fn primitive_arguments_are_bounded_closed_and_consumed_once() {
        let digest = "01".repeat(32);
        let mut parsed = arguments(&[
            "--count",
            "7",
            "--nonzero",
            "9",
            "--path",
            "/var/lib/agent/state",
            "--artifact",
            "/opt/agent/artifact",
            "--artifact-sha256",
            &digest,
            "--snapshot",
            "0123456789abcdef0123456789abcdef",
        ]);
        assert_eq!(parsed.number::<u64>("count").expect("decimal count"), 7);
        assert_eq!(
            parsed
                .nonzero_usize("nonzero")
                .expect("positive nonzero count")
                .get(),
            9
        );
        assert_eq!(
            parsed.absolute_path("path").expect("safe absolute path"),
            std::path::Path::new("/var/lib/agent/state")
        );
        let artifact = parsed.pinned("artifact").expect("pinned artifact");
        assert_eq!(artifact.path, std::path::Path::new("/opt/agent/artifact"));
        assert_eq!(
            parsed.snapshot_id("snapshot").expect("snapshot identity"),
            session_orchestrator::SnapshotId::new([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])
        );
        assert!(
            parsed
                .optional("absent")
                .expect("absent is valid")
                .is_none()
        );
        assert!(parsed.finish().is_ok());

        assert!(Arguments::parse(["positional".to_owned()]).is_err());
        assert!(Arguments::parse(["--dangling".to_owned()]).is_err());
        assert!(
            Arguments::parse([
                "--same".to_owned(),
                "one".to_owned(),
                "--same".to_owned(),
                "two".to_owned(),
            ])
            .is_err()
        );
        assert!(arguments(&["--empty", ""]).optional("empty").is_err());
        assert!(
            arguments(&["--count", "1x"])
                .number::<u64>("count")
                .is_err()
        );
        assert!(arguments(&["--count", "0"]).nonzero_u64("count").is_err());
        assert!(arguments(&["--extra", "value"]).finish().is_err());
        assert!(validate_absolute_path("path", std::path::Path::new("/")).is_err());
        assert!(validate_absolute_path("path", std::path::Path::new("relative")).is_err());
        assert!(parse_cgroup_parent("agent/sessions").is_ok());
        assert!(parse_cgroup_parent("../sessions").is_err());
        assert!(file_authority("bad/repository".to_owned(), "read-data", "/").is_err());
    }

    #[test]
    fn shutdown_timeout_is_positive_and_bounded() {
        assert!(
            arguments(&["--timeout", "1"])
                .nonzero_u64("timeout")
                .is_ok()
        );
        assert!(
            arguments(&["--timeout", "0"])
                .nonzero_u64("timeout")
                .is_err()
        );
        assert!(validate_shutdown_timeout(MAX_SHUTDOWN_TIMEOUT_MILLIS).is_ok());
        assert!(validate_shutdown_timeout(MAX_SHUTDOWN_TIMEOUT_MILLIS + 1).is_err());
    }

    #[test]
    fn stop_file_observation_distinguishes_absence_from_io_failure() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "host-sessiond-stop-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("create stop-file fixture");
        let stop = directory.join("stop");
        assert!(!stop_file_present(&stop).expect("an absent stop file is observable"));
        fs::write(&stop, b"stop").expect("create stop file");
        assert!(stop_file_present(&stop).expect("a present stop file is observable"));

        let not_a_directory = directory.join("not-a-directory");
        fs::write(&not_a_directory, b"block traversal").expect("create traversal blocker");
        assert!(stop_file_present(&not_a_directory.join("stop")).is_err());
        fs::remove_dir_all(directory).expect("remove stop-file fixture");
    }

    #[test]
    fn egress_profiles_issue_only_the_selected_authority_family() {
        let mut public = arguments(&[
            "--egress-authority",
            "public",
            "--public-methods",
            "get,head",
            "--public-host",
            "example.com",
            "--public-path-prefix",
            "/api",
            "--public-max-response-bytes",
            "4096",
        ]);
        let (authority, github) =
            parse_egress_profile(&mut public, RepoId::new("workspace")).expect("public profile");
        assert!(matches!(authority, Some(AuthorityBody::HttpFetch(_))));
        assert_eq!(github, GitHubEgressConfig::Disabled);
        assert!(public.finish().is_ok());

        let mut github = arguments(&[
            "--egress-authority",
            "github",
            "--github-installation",
            "installation-a",
            "--github-credential-handle",
            "7",
            "--github-operations",
            "create-pull-request",
            "--github-base-branch-pattern",
            "exact:main",
            "--github-head-branch-pattern",
            "prefix:agent/work",
        ]);
        let (authority, github_config) =
            parse_egress_profile(&mut github, RepoId::new("workspace")).expect("GitHub profile");
        assert!(matches!(authority, Some(AuthorityBody::GitHub(_))));
        assert!(matches!(
            github_config,
            GitHubEgressConfig::Environment { .. }
        ));
        assert!(github.finish().is_ok());

        let mut disabled_with_public_flag =
            arguments(&["--egress-authority", "none", "--public-host", "example.com"]);
        assert!(
            parse_egress_profile(&mut disabled_with_public_flag, RepoId::new("workspace")).is_err()
        );
        let mut unknown = arguments(&[("--egress-authority"), "raw-network"]);
        assert!(parse_egress_profile(&mut unknown, RepoId::new("workspace")).is_err());
    }

    #[test]
    fn publish_branch_profile_requires_a_host_plan_manifest() {
        let mut github = arguments(&[
            "--egress-authority",
            "github",
            "--github-installation",
            "installation-a",
            "--github-credential-handle",
            "7",
            "--github-operations",
            "publish-branch",
            "--github-base-branch-pattern",
            "exact:main",
            "--github-head-branch-pattern",
            "prefix:agent",
        ]);
        let error = parse_egress_profile(&mut github, RepoId::new("workspace"))
            .expect_err("publish-branch must not start without a plan manifest");
        assert!(error.contains("github-publish-plans"));
    }

    #[test]
    fn publish_branch_profile_loads_matching_host_plan_manifest() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "host-sessiond-parser-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("create plan directory");
        let path = directory.join("plans.tsv");
        let contents = format!(
            "host-publish-plan-v1\t00112233445566778899aabbccddeeff\tinstallation-a\tworkspace\tpublish-branch\tmain\tagent/work\t{}\t{}\n",
            "a".repeat(40),
            "b".repeat(40),
        );
        fs::write(&path, contents).expect("write plan manifest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("protect plan directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("protect plan manifest");
        }
        let path_value = path.display().to_string();
        let mut github = arguments(&[
            "--egress-authority",
            "github",
            "--github-installation",
            "installation-a",
            "--github-credential-handle",
            "7",
            "--github-operations",
            "publish-branch,create-pull-request",
            "--github-base-branch-pattern",
            "exact:main",
            "--github-head-branch-pattern",
            "prefix:agent",
            "--github-publish-plans",
            &path_value,
        ]);
        let (_, config) = parse_egress_profile(&mut github, RepoId::new("workspace"))
            .expect("matching publish manifest");
        match config {
            GitHubEgressConfig::Environment { publish_plans, .. } => {
                assert_eq!(publish_plans.len(), 1);
            }
            GitHubEgressConfig::Disabled => panic!("GitHub profile must be enabled"),
        }
        assert!(github.finish().is_ok());
        fs::remove_dir_all(directory).expect("remove test plan directory");
    }

    #[test]
    fn create_pull_request_profile_keeps_plan_manifest_optional() {
        let mut github = arguments(&[
            "--egress-authority",
            "github",
            "--github-installation",
            "installation-a",
            "--github-credential-handle",
            "7",
            "--github-operations",
            "create-pull-request",
            "--github-base-branch-pattern",
            "exact:main",
            "--github-head-branch-pattern",
            "prefix:agent",
        ]);
        let (authority, config) = parse_egress_profile(&mut github, RepoId::new("workspace"))
            .expect("create-pull-request-only profile");
        assert!(matches!(authority, Some(AuthorityBody::GitHub(_))));
        assert!(matches!(config, GitHubEgressConfig::Environment { .. }));
        assert!(github.finish().is_ok());
    }

    #[test]
    fn shutdown_requests_have_stable_machine_names() {
        assert_eq!(ShutdownRequest::StopFile.label(), "stop-file");
        assert_eq!(ShutdownRequest::Sigterm.label(), "sigterm");
        assert_eq!(ShutdownRequest::Sigint.label(), "sigint");
    }

    #[test]
    fn status_records_are_structured_and_do_not_include_error_text_or_secrets() {
        let line = status_line("poll-error", "stopping", None, Some("cleanup-retryable"));
        assert_eq!(
            line,
            r#"{"schema":"host-sessiond/v1","event":"poll-error","state":"stopping","reason":"cleanup-retryable"}"#
        );
        assert!(!line.contains("EGRESS_GITHUB_TOKEN"));
        assert!(!line.contains("authority"));
        assert!(!line.contains("/var/"));
    }

    #[test]
    fn status_json_escapes_untrusted_state_text() {
        assert_eq!(json_string("line\nquote\""), "line\\nquote\\\"");
        let line = status_line("event", "state\"\n", None, None);
        assert!(line.contains(r#""state":"state\"\n""#));
    }
}
