//! PID 1 guest-control service for a Firecracker image without a network device.
//!
//! This binary intentionally accepts exactly two host-originated vsock operations: inject a
//! session-bound identity bundle, then release one image-configured workload. It neither accepts
//! a command from the host nor exposes a network listener inside the guest.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsString,
    io,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
};

use firecracker_runtime::guest_control::{GuestControlOutcome, GuestControlServer};
use socket2::{Domain, SockAddr, Socket, Type};

const VMADDR_CID_ANY: u32 = u32::MAX;
const VMADDR_CID_HOST: u32 = 2;
const LISTEN_BACKLOG: i32 = 4;

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
            .serve_once_with(&mut stream, || start_workload(&config, &mut workload))
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

fn start_workload(config: &Config, workload: &mut Option<Child>) -> io::Result<()> {
    if workload.is_some() {
        return Ok(());
    }
    let child = Command::new(&config.workload)
        .args(&config.workload_arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    *workload = Some(child);
    Ok(())
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
}
