//! Single-purpose launcher for a workload that must enter the runtime isolation boundary.
//!
//! The launcher is intentionally expendable: `RuntimeIsolation` changes namespaces in its
//! calling process before it forks the isolated PID-namespace child.  A long-lived supervisor
//! must therefore execute this binary instead of calling the isolation API in-process.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::Shutdown,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
    os::unix::{ffi::OsStringExt, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

use runtime_isolation::{
    BindMountConfig, CgroupConfig, ChildExit, ChildStartupStatus, ControlChannelConfig,
    EgressChannelConfig, ExecStatusChannelConfig, IdentityMap, IsolationConfig, LandlockConfig,
    LinuxBackend, RootfsConfig, RuntimeIsolation, SeccompPolicy, SpawnOutcome, TmpfsConfig,
};
use rustix::{
    io::{FdFlags, fcntl_getfd, fcntl_setfd},
    net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with},
};

const LANDLOCK_ABI: u32 = 3;
const ISOLATION_READY: &[u8; 8] = b"isolated";
const EXEC_STATUS_TIMEOUT: Duration = Duration::from_secs(10);
const EXEC_FAILED: [u8; 1] = [1];
const EGRESS_BROKER_FD_ENV: &str = "EGRESS_BROKER_FD";
const EGRESS_BROKER_SESSION_ENV: &str = "EGRESS_BROKER_SESSION_ID";

#[derive(Debug)]
struct LauncherConfig {
    isolation: IsolationConfig,
    control_socket: PathBuf,
    egress_broker_fd: i32,
    egress_broker_session: String,
    workload_directory: PathBuf,
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("workload-isolation-launcher: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = parse_config(env::args_os().skip(1))?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut start_gate_input = stdin.lock();
    let mut start_gate_output = stdout.lock();
    wait_for_start_gate(&mut start_gate_input, &mut start_gate_output)?;
    let control_channel = connect_control_channel(&config.control_socket)?;
    let control_channel_fd = control_channel.as_raw_fd();
    preserve_for_workload(&control_channel, "supervisor control channel")?;
    let (mut exec_status_reader, mut exec_status_writer) = UnixStream::pair()
        .map_err(|error| format!("creating workload exec-status channel: {error}"))?;
    exec_status_reader
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("restricting workload exec-status reader: {error}"))?;
    exec_status_writer
        .shutdown(Shutdown::Read)
        .map_err(|error| format!("restricting workload exec-status writer: {error}"))?;
    exec_status_reader
        .set_read_timeout(Some(EXEC_STATUS_TIMEOUT))
        .map_err(|error| format!("bounding workload exec-status wait: {error}"))?;
    require_close_on_exec(&exec_status_writer, "workload exec-status channel")?;
    let exec_status_fd = exec_status_writer.as_raw_fd();
    let isolation = config
        .isolation
        .clone()
        .with_control_channel(
            ControlChannelConfig::new(control_channel_fd)
                .map_err(|error| format!("configuring supervisor control channel: {error}"))?,
        )
        .with_egress_channel(
            EgressChannelConfig::new(config.egress_broker_fd)
                .map_err(|error| format!("configuring egress Broker channel: {error}"))?,
        )
        .with_exec_status_channel(
            ExecStatusChannelConfig::new(exec_status_fd)
                .map_err(|error| format!("configuring workload exec-status channel: {error}"))?,
        );
    let mut backend = LinuxBackend::new();
    match RuntimeIsolation::spawn_isolated(&mut backend, &isolation, move |_| {
        execute_workload(
            &config,
            control_channel_fd,
            config.egress_broker_fd,
            &mut exec_status_writer,
        )
    }) {
        Ok(SpawnOutcome::Parent(mut child)) => {
            match child
                .wait_for_startup()
                .map_err(|error| format!("waiting for isolated workload startup: {error}"))?
            {
                ChildStartupStatus::Ready(_) => {
                    wait_for_exec(&mut exec_status_reader)?;
                    if let Some(exit) = child.try_wait().map_err(|error| {
                        format!("checking workload immediately after exec: {error}")
                    })? {
                        return Err(format!(
                            "isolated workload exited before its exec acknowledgement was delivered: {exit:?}"
                        ));
                    }
                    start_gate_output
                        .write_all(ISOLATION_READY)
                        .and_then(|()| start_gate_output.flush())
                        .map_err(|error| {
                            format!("confirming executed workload startup to parent: {error}")
                        })?;
                }
                ChildStartupStatus::Failed(failure) => {
                    return Err(format!(
                        "isolated workload setup failed at {:?}: {} (errno {:?}, rollback failures {}, termination required {})",
                        failure.step(),
                        failure.detail(),
                        failure.errno(),
                        failure.rollback_failure_count(),
                        failure.termination_required()
                    ));
                }
            }
            match child
                .wait()
                .map_err(|error| format!("reaping isolated workload: {error}"))?
            {
                ChildExit::Exited(0) => Ok(()),
                ChildExit::Exited(status) => {
                    Err(format!("isolated workload exited with status {status}"))
                }
                ChildExit::Signaled(signal) => Err(format!(
                    "isolated workload was terminated by signal {signal}"
                )),
            }
        }
        Ok(SpawnOutcome::Child(result)) => result,
        Err(error) => Err(format!("starting isolated workload: {error}")),
    }
}

fn connect_control_channel(path: &Path) -> Result<OwnedFd, String> {
    let address = SocketAddrUnix::new(path).map_err(|_| {
        format!(
            "encoding supervisor control socket path {} as Unix address",
            path.display()
        )
    })?;
    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| format!("creating supervisor control channel: {error}"))?;
    connect(&descriptor, &address).map_err(|error| {
        format!(
            "connecting to supervisor control socket {}: {error}",
            path.display()
        )
    })?;
    Ok(descriptor)
}

fn preserve_for_workload(descriptor: impl AsFd, label: &str) -> Result<(), String> {
    let descriptor_flags = fcntl_getfd(&descriptor)
        .map_err(|error| format!("reading {label} descriptor flags: {error}"))?;
    fcntl_setfd(&descriptor, descriptor_flags & !FdFlags::CLOEXEC)
        .map_err(|error| format!("preserving {label} descriptor: {error}"))
}

fn require_close_on_exec(descriptor: impl AsFd, label: &str) -> Result<(), String> {
    let descriptor_flags = fcntl_getfd(&descriptor)
        .map_err(|error| format!("reading {label} descriptor flags: {error}"))?;
    fcntl_setfd(&descriptor, descriptor_flags | FdFlags::CLOEXEC)
        .map_err(|error| format!("making {label} close on exec: {error}"))
}

fn wait_for_start_gate(input: &mut impl Read, output: &mut impl Write) -> Result<(), String> {
    output
        .write_all(b"ready")
        .and_then(|()| output.flush())
        .map_err(|error| format!("announcing workload start-gate readiness: {error}"))?;
    let mut release = [0_u8; 1];
    input
        .read_exact(&mut release)
        .map_err(|error| format!("waiting for workload start-gate release: {error}"))?;
    if release == [1] {
        Ok(())
    } else {
        Err("parent refused workload start-gate release".to_owned())
    }
}

fn wait_for_exec(reader: &mut impl Read) -> Result<(), String> {
    let mut marker = [0_u8; 1];
    loop {
        match reader.read(&mut marker) {
            Ok(0) => return Ok(()),
            Ok(_) if marker == EXEC_FAILED => {
                return Err("isolated workload reported that execve failed".to_owned());
            }
            Ok(_) => return Err("isolated workload sent an invalid exec-status marker".to_owned()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(format!(
                    "waiting for the isolated workload to reach execve: {error}"
                ));
            }
        }
    }
}

fn execute_workload(
    config: &LauncherConfig,
    control_channel_fd: i32,
    egress_broker_fd: i32,
    exec_status: &mut impl Write,
) -> Result<(), String> {
    let error = Command::new(&config.program)
        .args(&config.arguments)
        .env_clear()
        .envs(config.environment.iter().cloned())
        .env("SUPERVISOR_CONTROL_FD", control_channel_fd.to_string())
        .env(EGRESS_BROKER_FD_ENV, egress_broker_fd.to_string())
        .env(EGRESS_BROKER_SESSION_ENV, &config.egress_broker_session)
        .current_dir(&config.workload_directory)
        // Standard descriptors were replaced with close-on-exec `/dev/null` placeholders before
        // this transaction. Do not reopen `/dev/null` here: the device tree is intentionally
        // hidden before the workload is execed.
        .exec();
    let detail = format!(
        "execing configured workload {} after isolation: {error}",
        config.program.display()
    );
    exec_status
        .write_all(&EXEC_FAILED)
        .and_then(|()| exec_status.flush())
        .map_err(|status_error| {
            format!("{detail}; reporting exec failure to launcher also failed: {status_error}")
        })?;
    Err(detail)
}

#[allow(clippy::similar_names, clippy::too_many_lines)]
fn parse_config(arguments: impl IntoIterator<Item = OsString>) -> Result<LauncherConfig, String> {
    let mut arguments = arguments.into_iter().peekable();
    let rootfs_source = required_path(&mut arguments, "--rootfs-source")?;
    let rootfs_mount_target = required_path(&mut arguments, "--rootfs-mount-target")?;
    let old_root = required_path(&mut arguments, "--old-root")?;
    let workspace_source = required_path(&mut arguments, "--workspace-source")?;
    let workspace_target = required_path(&mut arguments, "--workspace-target")?;
    let tmpfs_target = required_path(&mut arguments, "--tmpfs-target")?;
    let tmpfs_size_bytes = required_u64(&mut arguments, "--tmpfs-size-bytes")?;
    let cgroup_root = required_path(&mut arguments, "--cgroup-root")?;
    let cgroup_name = required_string(&mut arguments, "--cgroup-name")?;
    let memory_max_bytes = required_u64(&mut arguments, "--memory-max-bytes")?;
    let pids_max = required_u64(&mut arguments, "--pids-max")?;
    let host_uid = required_u32(&mut arguments, "--host-uid")?;
    let host_gid = required_u32(&mut arguments, "--host-gid")?;
    let control_socket = required_path(&mut arguments, "--control-socket")?;
    let egress_broker_fd = required_descriptor(&mut arguments, "--egress-broker-fd")?;
    let egress_broker_session = required_identity(&mut arguments, "--egress-broker-session")?;

    let mut read_only_paths = Vec::new();
    let mut writable_paths = Vec::new();
    let mut environment = Vec::new();
    while let Some(argument) = arguments.peek() {
        match argument.as_os_str() {
            value if value == OsStr::new("--landlock-read-only") => {
                arguments.next();
                read_only_paths.push(next_path(&mut arguments, "--landlock-read-only")?);
            }
            value if value == OsStr::new("--landlock-writable") => {
                arguments.next();
                writable_paths.push(next_path(&mut arguments, "--landlock-writable")?);
            }
            value if value == OsStr::new("--env") => {
                arguments.next();
                environment.push(next_environment(&mut arguments)?);
            }
            value if value == OsStr::new("--program") => break,
            _ => return Err(usage()),
        }
    }

    expect_flag(&mut arguments, "--program")?;
    let program = next_path(&mut arguments, "--program")?;
    expect_flag(&mut arguments, "--")?;
    let workload_arguments = arguments.collect::<Vec<_>>();

    if read_only_paths.is_empty() || writable_paths.is_empty() {
        return Err(
            "at least one read-only and one writable Landlock path are required".to_owned(),
        );
    }

    let isolation = IsolationConfig::new(
        RootfsConfig::new(rootfs_source, rootfs_mount_target, old_root),
        BindMountConfig::new(workspace_source, workspace_target.clone()),
        TmpfsConfig::new(tmpfs_target, tmpfs_size_bytes),
        CgroupConfig::new(cgroup_root, cgroup_name, memory_max_bytes, pids_max),
        LandlockConfig::new(LANDLOCK_ABI, read_only_paths, writable_paths),
        SeccompPolicy::default(),
        IdentityMap::new(host_uid, host_gid),
    );
    isolation
        .validate()
        .map_err(|error| format!("validating isolation configuration: {error}"))?;

    Ok(LauncherConfig {
        isolation,
        control_socket,
        egress_broker_fd,
        egress_broker_session,
        workload_directory: workspace_target,
        program,
        arguments: workload_arguments,
        environment,
    })
}

fn required_descriptor<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<i32, String>
where
    I: Iterator<Item = OsString>,
{
    expect_flag(arguments, flag)?;
    let value = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?;
    let descriptor = value.parse::<i32>().map_err(|_| usage())?;
    if descriptor < 3 {
        return Err(format!("{flag} must be a nonstandard file descriptor"));
    }
    Ok(descriptor)
}

fn required_identity<I>(
    arguments: &mut std::iter::Peekable<I>,
    flag: &str,
) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    expect_flag(arguments, flag)?;
    let identity = arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())?;
    if identity.len() != 32
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !identity.bytes().any(|byte| byte != b'0')
    {
        return Err(format!(
            "{flag} must be a non-zero lower hexadecimal identity"
        ));
    }
    Ok(identity)
}

fn required_path<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<PathBuf, String>
where
    I: Iterator<Item = OsString>,
{
    expect_flag(arguments, flag)?;
    next_path(arguments, flag)
}

fn required_string<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    expect_flag(arguments, flag)?;
    arguments
        .next()
        .ok_or_else(usage)?
        .into_string()
        .map_err(|_| usage())
}

fn required_u64<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<u64, String>
where
    I: Iterator<Item = OsString>,
{
    required_string(arguments, flag)?
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be an unsigned decimal integer"))
}

fn required_u32<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<u32, String>
where
    I: Iterator<Item = OsString>,
{
    required_string(arguments, flag)?
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be an unsigned decimal integer"))
}

fn expect_flag<I>(arguments: &mut std::iter::Peekable<I>, expected: &str) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    if arguments.next().as_deref() == Some(OsStr::new(expected)) {
        Ok(())
    } else {
        Err(usage())
    }
}

fn next_path<I>(arguments: &mut std::iter::Peekable<I>, flag: &str) -> Result<PathBuf, String>
where
    I: Iterator<Item = OsString>,
{
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if is_absolute_lexical_path(&path) {
        Ok(path)
    } else {
        Err(format!("{flag} must be an absolute lexical path"))
    }
}

fn next_environment<I>(
    arguments: &mut std::iter::Peekable<I>,
) -> Result<(OsString, OsString), String>
where
    I: Iterator<Item = OsString>,
{
    let value = arguments.next().ok_or_else(usage)?;
    let encoded = value.as_encoded_bytes();
    let Some(separator) = encoded.iter().position(|byte| *byte == b'=') else {
        return Err("--env must use NAME=VALUE with a non-empty name".to_owned());
    };
    let (name, value) = (&encoded[..separator], &encoded[separator + 1..]);
    if name.is_empty() || name.contains(&0) || value.contains(&0) {
        return Err("--env must not contain an empty name or NUL byte".to_owned());
    }
    Ok((
        OsString::from_vec(name.to_vec()),
        OsString::from_vec(value.to_vec()),
    ))
}

fn is_absolute_lexical_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn usage() -> String {
    "usage: workload-isolation-launcher --rootfs-source <absolute-path> --rootfs-mount-target <absolute-path> --old-root <absolute-path> --workspace-source <absolute-path> --workspace-target <absolute-path> --tmpfs-target <absolute-path> --tmpfs-size-bytes <u64> --cgroup-root <absolute-path> --cgroup-name <safe-name> --memory-max-bytes <u64> --pids-max <u64> --host-uid <u32> --host-gid <u32> --control-socket <absolute-path> --egress-broker-fd <fd> --egress-broker-session <identity> --landlock-read-only <absolute-path>... --landlock-writable <absolute-path>... [--env NAME=VALUE]... --program <absolute-path> -- [arguments...]".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<OsString> {
        [
            "--rootfs-source",
            "/",
            "--rootfs-mount-target",
            "/mnt/rootfs",
            "--old-root",
            "/mnt/rootfs/.old-root",
            "--workspace-source",
            "/mnt/capfs",
            "--workspace-target",
            "/workspace",
            "--tmpfs-target",
            "/tmp",
            "--tmpfs-size-bytes",
            "1048576",
            "--cgroup-root",
            "/sys/fs/cgroup",
            "--cgroup-name",
            "subject-a",
            "--memory-max-bytes",
            "1048576",
            "--pids-max",
            "8",
            "--host-uid",
            "1000",
            "--host-gid",
            "1000",
            "--control-socket",
            "/run/supervisor/subject-a.sock",
            "--egress-broker-fd",
            "19",
            "--egress-broker-session",
            "00112233445566778899aabbccddeeff",
            "--landlock-read-only",
            "/",
            "--landlock-writable",
            "/workspace",
            "--env",
            "CAPFS_MOUNTPOINT=/workspace",
            "--program",
            "/usr/local/libexec/guest-workload",
            "--",
            "--fixed-argument",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parses_a_complete_fixed_workload_policy() {
        let config = parse_config(arguments()).expect("fixed policy must parse");
        assert_eq!(
            config.program,
            PathBuf::from("/usr/local/libexec/guest-workload")
        );
        assert_eq!(config.arguments, [OsString::from("--fixed-argument")]);
        assert_eq!(config.egress_broker_fd, 19);
        assert_eq!(
            config.egress_broker_session,
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            config.environment,
            [(
                OsString::from("CAPFS_MOUNTPOINT"),
                OsString::from("/workspace")
            )]
        );
    }

    #[test]
    fn rejects_relative_program_paths() {
        let mut arguments = arguments();
        let index = arguments
            .iter()
            .position(|argument| argument == "--program")
            .expect("test arguments contain program")
            + 1;
        arguments[index] = OsString::from("guest-workload");
        let error = parse_config(arguments).expect_err("relative program must be refused");
        assert!(error.contains("--program must be an absolute lexical path"));
    }

    #[test]
    fn rejects_missing_writable_landlock_path() {
        let mut arguments = arguments();
        let index = arguments
            .iter()
            .position(|argument| argument == "--landlock-writable")
            .expect("test arguments contain writable Landlock path");
        arguments.drain(index..=index + 1);
        let error = parse_config(arguments).expect_err("writable policy must be required");
        assert!(error.contains("writable Landlock path"));
    }

    #[test]
    fn rejects_noncanonical_broker_session_identity() {
        let mut arguments = arguments();
        let index = arguments
            .iter()
            .position(|argument| argument == "--egress-broker-session")
            .expect("test arguments contain Broker session")
            + 1;
        arguments[index] = OsString::from("00112233445566778899AABBCCDDEEFF");
        let error = parse_config(arguments).expect_err("upper-case identity must be refused");
        assert!(error.contains("non-zero lower hexadecimal identity"));
    }

    #[test]
    fn start_gate_uses_exact_inherited_streams() {
        let mut input = io::Cursor::new(vec![1]);
        let mut output = Vec::new();
        wait_for_start_gate(&mut input, &mut output).expect("release marker must open the gate");
        assert_eq!(output, b"ready");

        let mut refused = io::Cursor::new(vec![0]);
        assert!(wait_for_start_gate(&mut refused, &mut Vec::new()).is_err());
    }

    #[test]
    fn exec_status_accepts_only_close_without_a_failure_marker() {
        assert!(wait_for_exec(&mut io::Cursor::new(Vec::<u8>::new())).is_ok());
        assert!(wait_for_exec(&mut io::Cursor::new(EXEC_FAILED)).is_err());
        assert!(wait_for_exec(&mut io::Cursor::new([7])).is_err());
    }
}
