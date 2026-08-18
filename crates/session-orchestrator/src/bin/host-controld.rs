//! Unprivileged authenticated multi-session controller.
//!
//! Clients can request only start/stop over a bounded local protocol. The caller principal is
//! derived from kernel `SO_PEERCRED`; program names, unit names, paths, service properties and
//! worker configuration never cross this socket.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixListener},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use firecracker_runtime::{PinnedArtifact, Sha256Digest};
use rustix::{
    fs::{CWD, Gid, Mode, OFlags, ResolveFlags, chown, openat2},
    net::sockopt::socket_peercred,
};
use session_orchestrator::{
    OsEntropy,
    control_plane::{
        ControlAuthenticator, ControlLimits, ControlRequestId, ControlSessionId, ControlTag,
        MultiSessionController, PrincipalId, StartSessionRequest, StopSessionRequest,
    },
    control_transport::principal_for_uid,
    systemd_worker::{PinnedSystemdManager, SystemdWorkerFactory},
};
use zeroize::Zeroize;

const START_REQUEST_BYTES: usize = 50;
const STOP_REQUEST_BYTES: usize = 66;
const MAX_REQUEST_BYTES: usize = STOP_REQUEST_BYTES;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(20);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-controld: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    let mut key = read_control_key(&config.key_file, config.client_gid)?;
    let authenticator = ControlAuthenticator::new(key);
    key.zeroize();
    let manager = PinnedSystemdManager::new(config.systemctl);
    let factory = SystemdWorkerFactory::new(manager);
    let mut controller = MultiSessionController::open(
        &config.journal,
        config.limits,
        authenticator,
        factory,
        OsEntropy,
    )
    .map_err(|error| format!("open controller: {error}"))?;
    let listener = bind_control_socket(&config.socket, config.client_gid)?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("make control socket nonblocking: {error}"))?;
    let shutdown = install_shutdown_handlers()?;

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
                stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
                let response = match decode_request(&mut stream) {
                    Ok(Request::Start {
                        principal,
                        request,
                        tag,
                    }) => controller
                        .start(StartSessionRequest::new(principal, request, tag))
                        .map(Response::Started)
                        .unwrap_or(Response::Denied),
                    Ok(Request::Stop {
                        principal,
                        request,
                        session,
                        tag,
                    }) => controller
                        .stop(StopSessionRequest::new(principal, request, session, tag))
                        .map(|()| Response::Stopped)
                        .unwrap_or(Response::Denied),
                    Err(()) => Response::Denied,
                };
                let _ = write_response(&mut stream, response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Err(error) = controller.poll_all() {
                    eprintln!("host-controld: worker poll failed closed: {error}");
                }
                thread::sleep(config.poll_interval.min(ACCEPT_POLL));
            }
            Err(error) => return Err(format!("accept control connection: {error}")),
        }
    }

    controller
        .shutdown_all()
        .map_err(|error| format!("shutdown workers: {error}"))
}

struct Config {
    socket: PathBuf,
    journal: PathBuf,
    key_file: PathBuf,
    systemctl: PinnedArtifact,
    limits: ControlLimits,
    poll_interval: Duration,
    client_gid: u32,
}

impl Config {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut arguments = arguments.into_iter();
        while let Some(flag) = arguments.next() {
            let name = flag
                .strip_prefix("--")
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("invalid flag {flag:?}"))?;
            let value = arguments
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("missing value for --{name}"))?;
            if values.insert(name.to_owned(), value).is_some() {
                return Err(format!("duplicate --{name}"));
            }
        }
        let socket = absolute_path(take(&mut values, "socket")?, "socket")?;
        let journal = absolute_path(take(&mut values, "journal")?, "journal")?;
        let key_file = absolute_path(take(&mut values, "key-file")?, "key-file")?;
        let systemctl_path = absolute_path(take(&mut values, "systemctl")?, "systemctl")?;
        let systemctl_digest = Sha256Digest::from_hex(&take(&mut values, "systemctl-sha256")?)
            .map_err(|error| format!("invalid --systemctl-sha256: {error}"))?;
        let max_sessions = number(&take(&mut values, "max-sessions")?, "max-sessions")?;
        let max_per_principal = number(
            &take(&mut values, "max-sessions-per-principal")?,
            "max-sessions-per-principal",
        )?;
        let poll_millis: u64 = number(&take(&mut values, "poll-millis")?, "poll-millis")?;
        let client_gid = number(&take(&mut values, "client-gid")?, "client-gid")?;
        if poll_millis == 0 || poll_millis > 60_000 {
            return Err("--poll-millis must be in 1..=60000".to_owned());
        }
        if !values.is_empty() {
            return Err(format!(
                "unknown flags: {}",
                values.keys().cloned().collect::<Vec<_>>().join(",")
            ));
        }
        Ok(Self {
            socket,
            journal,
            key_file,
            systemctl: PinnedArtifact::new(systemctl_path, systemctl_digest),
            limits: ControlLimits::new(max_sessions, max_per_principal)
                .map_err(|error| error.to_string())?,
            poll_interval: Duration::from_millis(poll_millis),
            client_gid,
        })
    }
}

fn take(values: &mut BTreeMap<String, String>, name: &str) -> Result<String, String> {
    values
        .remove(name)
        .ok_or_else(|| format!("missing --{name}"))
}

fn number<T: std::str::FromStr>(value: &str, name: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| format!("invalid --{name}: {error}"))
}

fn absolute_path(value: String, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(format!(
            "--{label} must be an absolute canonical non-root path"
        ));
    }
    Ok(path)
}

fn read_control_key(path: &Path, client_gid: u32) -> Result<[u8; 32], String> {
    let descriptor = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("open control key {}: {error}", path.display()))?;
    let mut file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect control key {}: {error}", path.display()))?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != client_gid
        || metadata.mode() & 0o777 != 0o440
        || metadata.len() != 32
    {
        return Err(
            "control key must be one service-owned, client-group-readable 0440 32-byte file"
                .to_owned(),
        );
    }
    let mut key = [0_u8; 32];
    file.read_exact(&mut key)
        .map_err(|error| format!("read control key: {error}"))?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).map_err(|error| error.to_string())? != 0 {
        key.zeroize();
        return Err("control key grew while being read".to_owned());
    }
    Ok(key)
}

fn bind_control_socket(path: &Path, client_gid: u32) -> Result<UnixListener, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "control socket has no parent".to_owned())?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect socket parent {}: {error}", parent.display()))?;
    let uid = rustix::process::geteuid().as_raw();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != client_gid
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "control socket parent must be service-owned and not group/world writable".to_owned(),
        );
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("bind control socket {}: {error}", path.display()))?;
    chown(path, None, Some(Gid::from_raw(client_gid)))
        .map_err(|error| format!("assign control socket client group: {error}"))?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o660))
        .map_err(|error| format!("restrict control socket: {error}"))?;
    Ok(listener)
}

enum Request {
    Start {
        principal: PrincipalId,
        request: ControlRequestId,
        tag: ControlTag,
    },
    Stop {
        principal: PrincipalId,
        request: ControlRequestId,
        session: ControlSessionId,
        tag: ControlTag,
    },
}

fn decode_request(stream: &mut std::os::unix::net::UnixStream) -> Result<Request, ()> {
    let credentials = socket_peercred(&*stream).map_err(|_| ())?;
    let principal = principal_for_uid(credentials.uid.as_raw());
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).map_err(|_| ())?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_REQUEST_BYTES || !matches!(length, START_REQUEST_BYTES | STOP_REQUEST_BYTES) {
        return Err(());
    }
    let mut body = [0_u8; MAX_REQUEST_BYTES];
    stream.read_exact(&mut body[..length]).map_err(|_| ())?;
    if body[0] != 1 {
        return Err(());
    }
    let request = ControlRequestId::new(body[2..18].try_into().map_err(|_| ())?);
    let tag = ControlTag::new(body[18..50].try_into().map_err(|_| ())?);
    match (body[1], length) {
        (1, START_REQUEST_BYTES) => Ok(Request::Start {
            principal,
            request,
            tag,
        }),
        (2, STOP_REQUEST_BYTES) => Ok(Request::Stop {
            principal,
            request,
            tag,
            session: ControlSessionId::new(body[50..66].try_into().map_err(|_| ())?),
        }),
        _ => Err(()),
    }
}

#[derive(Clone, Copy)]
enum Response {
    Started(ControlSessionId),
    Stopped,
    Denied,
}

fn write_response(
    stream: &mut std::os::unix::net::UnixStream,
    response: Response,
) -> std::io::Result<()> {
    let mut body = Vec::with_capacity(18);
    body.push(1);
    match response {
        Response::Started(session) => {
            body.push(1);
            body.extend_from_slice(&session.as_bytes());
        }
        Response::Stopped => body.push(2),
        Response::Denied => body.push(0),
    }
    stream.write_all(&(u16::try_from(body.len()).unwrap()).to_be_bytes())?;
    stream.write_all(&body)
}

fn install_shutdown_handlers() -> Result<Arc<AtomicBool>, String> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .map_err(|error| format!("register SIGTERM: {error}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .map_err(|error| format!("register SIGINT: {error}"))?;
    Ok(shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_is_stable_and_bound_to_the_kernel_uid() {
        assert_eq!(principal_for_uid(1000), principal_for_uid(1000));
        assert_ne!(principal_for_uid(1000), principal_for_uid(1001));
        assert_ne!(principal_for_uid(0), PrincipalId::new([0; 16]));
    }

    #[test]
    fn configuration_rejects_relative_paths_zero_poll_and_unknown_flags() {
        let base = [
            "--socket",
            "/run/host-controld/control.sock",
            "--journal",
            "/var/lib/host-controld/control.journal",
            "--key-file",
            "/etc/host-controld/key",
            "--systemctl",
            "/usr/bin/systemctl",
            "--systemctl-sha256",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--max-sessions",
            "8",
            "--max-sessions-per-principal",
            "2",
            "--poll-millis",
            "20",
            "--client-gid",
            "2000",
        ];
        assert!(Config::parse(base.map(str::to_owned)).is_ok());
        let mut relative = base.map(str::to_owned);
        relative[1] = "relative".to_owned();
        assert!(Config::parse(relative).is_err());
        let mut zero = base.map(str::to_owned);
        zero[15] = "0".to_owned();
        assert!(Config::parse(zero).is_err());
    }
}
