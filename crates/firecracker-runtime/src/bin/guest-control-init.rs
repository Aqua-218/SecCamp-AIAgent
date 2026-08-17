//! PID 1 guest-control service for a Firecracker image without a network device.
//!
//! This binary intentionally accepts exactly two host-originated vsock operations: inject a
//! session-bound identity bundle, then release one image-configured workload. It neither accepts
//! a command from the host nor exposes a network listener inside the guest.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsString,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use firecracker_runtime::guest_control::{
    GuestControlOutcome, GuestControlRequest, GuestControlServer,
};
use socket2::{Domain, SockAddr, Socket, Type};

const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_CID_HOST: u32 = 2;
const LISTEN_BACKLOG: i32 = 4;
const GUEST_CHALLENGE_ENV: &str = "GUEST_IDENTITY_CHALLENGE";
const GUEST_VM_ID_ENV: &str = "GUEST_IDENTITY_VM_ID";
const GUEST_SESSION_ID_ENV: &str = "GUEST_IDENTITY_SESSION_ID";
const GUEST_REQUEST_ID_ENV: &str = "GUEST_IDENTITY_REQUEST_ID";
const GUEST_SUBJECT_ID_ENV: &str = "GUEST_IDENTITY_SUBJECT_ID";
const GUEST_CAPABILITY_ID_ENV: &str = "GUEST_IDENTITY_CAPABILITY_ID";
const GUEST_POLICY_DIGEST_ENV: &str = "GUEST_AUTHORITY_POLICY_DIGEST";
const GUEST_POLICY_ENCODING_VERSION_ENV: &str = "GUEST_AUTHORITY_POLICY_ENCODING_VERSION";
const SUPERVISOR_READINESS_ENV: &str = "GUEST_SUPERVISOR_READINESS";
const SUPERVISOR_READINESS_REQUIRED: &str = "1";
const SUPERVISOR_READY_MARKER: &[u8; 25] = b"guest-supervisor-ready/v1";
const SUPERVISOR_ERROR_PREFIX: &[u8; 26] = b"guest-supervisor-error/v1:";
const MAX_SUPERVISOR_ERROR_BYTES: usize = 768;
// The supervisor performs real proc/cgroup/workspace mounts, starts kernel FUSE, and launches the
// isolated workload before acknowledging readiness.  Keep this bounded but large enough for a
// cold production guest rather than treating ordinary device startup as a five-second failure.
const SUPERVISOR_READY_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug)]
struct Config {
    port: u32,
    workload: PathBuf,
    workload_arguments: Vec<OsString>,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("guest-control-init: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().collect::<Vec<_>>();
    let config = parse_config(arguments.into_iter().skip(1))?;
    let listener = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|error| format!("creating AF_VSOCK listener: {error}"))?;
    listener
        .bind(&SockAddr::vsock(VMADDR_CID_ANY, config.port))
        .map_err(|error| format!("binding AF_VSOCK port {}: {error}", config.port))?;
    listener
        .listen(LISTEN_BACKLOG)
        .map_err(|error| format!("listening on AF_VSOCK port {}: {error}", config.port))?;

    let mut server = GuestControlServer::new();
    let mut workload = None;
    loop {
        let (mut stream, peer) = listener
            .accept()
            .map_err(|error| format!("accepting AF_VSOCK connection: {error}"))?;
        let Some((peer_cid, _peer_port)) = peer.as_vsock_address() else {
            continue;
        };
        if peer_cid != VMADDR_CID_HOST {
            continue;
        }
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|error| format!("setting guest-control read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|error| format!("setting guest-control write timeout: {error}"))?;
        let response = server
            .serve_once_with_identity(&mut stream, |request| {
                start_workload(&config, &mut workload, request)
            })
            .map_err(|error| format!("serving guest-control request: {error}"))?;
        if response.outcome() == Some(GuestControlOutcome::WorkloadStarted) {
            reap_workload(&mut workload)?;
        }
    }
}

fn parse_config(arguments: impl IntoIterator<Item = OsString>) -> Result<Config, String> {
    let mut arguments = arguments.into_iter();
    let first = arguments.next();
    let first = if first.as_deref() == Some(std::ffi::OsStr::new("--")) {
        arguments.next()
    } else {
        first
    };
    if first.as_deref() != Some(std::ffi::OsStr::new("--port")) {
        return Err(usage());
    }
    let port = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?
        .parse::<u32>()
        .map_err(|_| usage())?;
    if port == 0 || port == u32::MAX {
        return Err("guest-control port must be explicit, non-zero, and non-wildcard".to_owned());
    }
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--workload")) {
        return Err(usage());
    }
    let workload = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if !is_absolute_lexical_path(&workload) {
        return Err(format!(
            "guest workload path must be absolute and lexical: {}",
            workload.display()
        ));
    }
    let first_workload_argument = arguments.next();
    let mut workload_arguments = Vec::new();
    if first_workload_argument.as_deref() != Some(std::ffi::OsStr::new("--")) {
        workload_arguments.extend(first_workload_argument);
    }
    workload_arguments.extend(arguments);
    Ok(Config {
        port,
        workload,
        workload_arguments,
    })
}

fn usage() -> String {
    format!(
        "usage: guest-control-init --port <1..{}> --workload <absolute-path> [workload args]",
        u32::MAX - 1
    )
}

fn is_absolute_lexical_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn start_workload(
    config: &Config,
    workload: &mut Option<Child>,
    request: &GuestControlRequest,
) -> io::Result<()> {
    if let Some(existing) = workload.as_mut() {
        if existing.try_wait()?.is_none() {
            return Ok(());
        }
        *workload = None;
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "configured guest supervisor exited before the start request was acknowledged",
        ));
    }

    let (mut readiness, supervisor_output) = Socket::pair(Domain::UNIX, Type::STREAM, None)?;
    readiness.set_read_timeout(Some(SUPERVISOR_READY_TIMEOUT))?;
    // `Stdio::from(OwnedFd)` transfers this endpoint to exactly the child that
    // `spawn` returns. The parent retains only `readiness`; no pathname or
    // process-global fd can satisfy the handshake.
    supervisor_output.set_cloexec(false)?;
    let supervisor_output = std::os::fd::OwnedFd::from(supervisor_output);
    let child = Command::new(&config.workload)
        .args(&config.workload_arguments)
        .env_clear()
        .envs(workload_environment(request))
        .env(SUPERVISOR_READINESS_ENV, SUPERVISOR_READINESS_REQUIRED)
        .stdin(Stdio::null())
        .stdout(Stdio::from(supervisor_output))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            eprintln!(
                "guest-control-init: starting image-configured workload {}: {error}",
                config.workload.display()
            );
            error
        })?;

    let mut child = child;
    if let Err(error) = wait_for_supervisor_readiness(&mut readiness, &mut child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if child.try_wait()?.is_some() {
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "configured guest supervisor exited immediately after readiness",
        ));
    }
    *workload = Some(child);
    Ok(())
}

fn wait_for_supervisor_readiness(readiness: &mut Socket, child: &mut Child) -> io::Result<()> {
    wait_for_supervisor_readiness_with_timeout(readiness, child, SUPERVISOR_READY_TIMEOUT)
}

fn wait_for_supervisor_readiness_with_timeout(
    readiness: &mut Socket,
    child: &mut Child,
    timeout: Duration,
) -> io::Result<()> {
    readiness.set_read_timeout(Some(timeout))?;
    let mut marker = [0_u8; SUPERVISOR_READY_MARKER.len()];
    let mut received = 0_usize;
    while received < marker.len() {
        match readiness.read(&mut marker[received..]) {
            Ok(0) if received != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest supervisor closed a partial readiness marker",
                ));
            }
            Ok(0) => {
                let status = child.try_wait()?.map_or_else(
                    || "without an observable exit status".to_owned(),
                    |status| format!("with status {status}"),
                );
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("guest supervisor exited before readiness {status}"),
                ));
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("guest supervisor exited before readiness ({status})"),
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "guest supervisor did not signal readiness within {} milliseconds",
                        timeout.as_millis()
                    ),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    if marker == *SUPERVISOR_READY_MARKER {
        return Ok(());
    }
    if marker == SUPERVISOR_ERROR_PREFIX[..marker.len()] {
        let mut payload = Vec::with_capacity(MAX_SUPERVISOR_ERROR_BYTES + 1);
        readiness
            .take((MAX_SUPERVISOR_ERROR_BYTES + 1) as u64)
            .read_to_end(&mut payload)?;
        if payload.first() != Some(&b':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest supervisor sent a malformed startup-failure record",
            ));
        }
        let diagnostic = payload[1..]
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '?'
                }
            })
            .collect::<String>();
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("guest supervisor startup failure: {diagnostic}"),
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "guest supervisor sent a malformed or foreign readiness marker",
    ))
}

fn workload_environment(request: &GuestControlRequest) -> Vec<(OsString, String)> {
    let identities = request.identities();
    let mut environment = vec![
        (
            OsString::from(GUEST_CHALLENGE_ENV),
            request.challenge().to_hex(),
        ),
        (OsString::from(GUEST_VM_ID_ENV), identities.vm_id.to_hex()),
        (
            OsString::from(GUEST_SESSION_ID_ENV),
            identities.session_id.to_hex(),
        ),
        (
            OsString::from(GUEST_REQUEST_ID_ENV),
            identities.request_id.to_hex(),
        ),
        (
            OsString::from(GUEST_SUBJECT_ID_ENV),
            identities.subject_id.to_hex(),
        ),
        (
            OsString::from(GUEST_CAPABILITY_ID_ENV),
            identities.capability_id.to_hex(),
        ),
    ];
    if let (Some(version), Some(digest)) =
        (request.policy_encoding_version(), request.policy_digest())
    {
        environment.push((
            OsString::from(GUEST_POLICY_ENCODING_VERSION_ENV),
            version.to_string(),
        ));
        environment.push((OsString::from(GUEST_POLICY_DIGEST_ENV), digest.to_hex()));
    }
    environment
}

fn reap_workload(workload: &mut Option<Child>) -> Result<(), String> {
    let Some(child) = workload.as_mut() else {
        return Ok(());
    };
    if child
        .try_wait()
        .map_err(|error| format!("observing guest workload: {error}"))?
        .is_some()
    {
        *workload = None;
        return Err("configured guest workload exited immediately after start".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use firecracker_runtime::{IdentityBundle, IdentityId};

    fn child_writing_readiness(payload: &'static str, hold_open: bool) -> (Socket, Child) {
        let (readiness, child_output) =
            Socket::pair(Domain::UNIX, Type::STREAM, None).expect("test socket pair");
        child_output
            .set_cloexec(false)
            .expect("test child endpoint must be inherited");
        let output = std::os::fd::OwnedFd::from(child_output);
        let command = if hold_open {
            "printf '%s' \"$READY_PAYLOAD\"; sleep 1".to_owned()
        } else {
            "printf '%s' \"$READY_PAYLOAD\"".to_owned()
        };
        let child = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("READY_PAYLOAD", payload)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output))
            .stderr(Stdio::null())
            .spawn()
            .expect("test readiness child must spawn");
        (readiness, child)
    }

    #[test]
    fn accepts_exact_supervisor_readiness_after_child_setup() {
        let (mut readiness, mut child) = child_writing_readiness(
            std::str::from_utf8(SUPERVISOR_READY_MARKER).expect("marker is UTF-8"),
            true,
        );
        wait_for_supervisor_readiness_with_timeout(
            &mut readiness,
            &mut child,
            Duration::from_secs(1),
        )
        .expect("exact readiness marker must be accepted");
        child.kill().expect("test child must be stoppable");
        child.wait().expect("test child must be reaped");
    }

    #[test]
    fn rejects_immediate_supervisor_exit_before_readiness() {
        let (mut readiness, mut child) = child_writing_readiness("", false);
        let error = wait_for_supervisor_readiness_with_timeout(
            &mut readiness,
            &mut child,
            Duration::from_secs(1),
        )
        .expect_err("an exited supervisor must not satisfy readiness");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        child.wait().expect("test child must be reaped");
    }

    #[test]
    fn rejects_missing_supervisor_readiness_at_the_deadline() {
        let (mut readiness, mut child) = child_writing_readiness("", true);
        let error = wait_for_supervisor_readiness_with_timeout(
            &mut readiness,
            &mut child,
            Duration::from_millis(20),
        )
        .expect_err("a silent supervisor must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        child.kill().expect("silent test child must be stoppable");
        child.wait().expect("test child must be reaped");
    }

    #[test]
    fn rejects_malformed_or_foreign_supervisor_readiness() {
        let (mut readiness, mut child) = child_writing_readiness("foreign-ready", true);
        let error = wait_for_supervisor_readiness_with_timeout(
            &mut readiness,
            &mut child,
            Duration::from_secs(1),
        )
        .expect_err("a foreign marker must not satisfy readiness");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        child
            .kill()
            .expect("malformed test child must be stoppable");
        child.wait().expect("test child must be reaped");
    }

    #[test]
    fn reports_a_bounded_supervisor_startup_failure_without_accepting_readiness() {
        let (mut readiness, mut child) =
            child_writing_readiness("guest-supervisor-error/v1:mounting procfs: EPERM", false);
        let error = wait_for_supervisor_readiness_with_timeout(
            &mut readiness,
            &mut child,
            Duration::from_secs(1),
        )
        .expect_err("a startup failure record must not satisfy readiness");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            error.to_string(),
            "guest supervisor startup failure: mounting procfs: EPERM"
        );
        child.wait().expect("test child must be reaped");
    }

    #[test]
    fn start_workload_ack_path_waits_for_the_exact_child_readiness_channel() {
        let identity = |byte| {
            IdentityId::from_hex(&format!("{byte:02x}").repeat(16))
                .expect("test identity must be valid")
        };
        let request = GuestControlRequest::new(
            identity(1),
            IdentityBundle::new(
                identity(2),
                identity(3),
                identity(4),
                identity(5),
                identity(6),
            )
            .expect("distinct test identities must form a bundle"),
        )
        .expect("challenge must not be inside the bundle");
        let marker = std::str::from_utf8(SUPERVISOR_READY_MARKER).expect("marker is UTF-8");
        let config = Config {
            port: 18080,
            workload: PathBuf::from("/bin/sh"),
            workload_arguments: vec![
                OsString::from("-c"),
                OsString::from(format!("printf '%s' '{marker}'; sleep 1")),
            ],
        };
        let mut workload = None;
        start_workload(&config, &mut workload, &request)
            .expect("start must wait for and receive child readiness");
        let child = workload.as_mut().expect("successful start retains child");
        assert!(
            child
                .try_wait()
                .expect("child status must be readable")
                .is_none()
        );
        child.kill().expect("test workload must be stoppable");
        child.wait().expect("test workload must be reaped");
    }

    #[test]
    fn accepts_the_kernel_init_argument_delimiter() {
        let parsed = parse_config([
            OsString::from("--"),
            OsString::from("--port"),
            OsString::from("18080"),
            OsString::from("--workload"),
            OsString::from("/usr/local/libexec/guest-workload"),
            OsString::from("sleep"),
            OsString::from("600"),
        ])
        .expect("kernel-delimited guest init configuration must parse");
        assert_eq!(parsed.port, 18080);
        assert_eq!(
            parsed.workload,
            PathBuf::from("/usr/local/libexec/guest-workload")
        );
        assert_eq!(
            parsed.workload_arguments,
            [OsString::from("sleep"), OsString::from("600")]
        );
    }

    #[test]
    fn refuses_host_relative_or_ambiguous_workload_paths() {
        let error = parse_config([
            OsString::from("--port"),
            OsString::from("18080"),
            OsString::from("--workload"),
            OsString::from("/usr/local/../guest-workload"),
            OsString::from("--"),
        ])
        .expect_err("workload path must not contain a parent traversal");
        assert!(error.contains("absolute and lexical"));
    }

    #[test]
    fn workload_environment_contains_only_the_canonical_identity_bundle() {
        let identity = |byte| {
            IdentityId::from_hex(&format!("{byte:02x}").repeat(16))
                .expect("test identity must be valid")
        };
        let request = GuestControlRequest::new(
            identity(1),
            IdentityBundle::new(
                identity(2),
                identity(3),
                identity(4),
                identity(5),
                identity(6),
            )
            .expect("distinct test identities must form a bundle"),
        )
        .expect("challenge must not be inside the bundle");
        let environment = workload_environment(&request);
        assert_eq!(environment.len(), 6);
        assert_eq!(
            environment[0],
            (OsString::from(GUEST_CHALLENGE_ENV), "01".repeat(16))
        );
        assert_eq!(
            environment[4],
            (OsString::from(GUEST_SUBJECT_ID_ENV), "05".repeat(16))
        );
        assert_eq!(
            environment[5],
            (OsString::from(GUEST_CAPABILITY_ID_ENV), "06".repeat(16))
        );
    }

    #[test]
    fn bound_workload_environment_carries_the_exact_policy_binding() {
        let identity = |byte| {
            IdentityId::from_hex(&format!("{byte:02x}").repeat(16))
                .expect("test identity must be valid")
        };
        let digest = authority_core::policy::AuthorityPolicyDigest::from_hex(&"a5".repeat(32))
            .expect("test digest must be valid");
        let request = GuestControlRequest::new_bound(
            identity(1),
            IdentityBundle::new(
                identity(2),
                identity(3),
                identity(4),
                identity(5),
                identity(6),
            )
            .expect("distinct test identities must form a bundle"),
            digest,
        )
        .expect("challenge must not be inside the bundle");

        let environment = workload_environment(&request);
        assert_eq!(environment.len(), 8);
        assert_eq!(
            environment[6],
            (
                OsString::from(GUEST_POLICY_ENCODING_VERSION_ENV),
                authority_core::policy::ROOT_POLICY_ENCODING_VERSION.to_string(),
            )
        );
        assert_eq!(
            environment[7],
            (OsString::from(GUEST_POLICY_DIGEST_ENV), digest.to_hex())
        );
    }
}
