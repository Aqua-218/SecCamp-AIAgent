//! Minimal authenticated client for the local `host-controld` socket.

use std::{
    env, fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
use session_orchestrator::{
    CryptographicRandom, OsEntropy,
    control_plane::{ControlAuthenticator, ControlRequestId, ControlSessionId},
    control_transport::{
        ControlResponse, decode_response, encode_start, encode_stop, principal_for_uid,
    },
};
use zeroize::Zeroize;

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 18;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-control: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (socket, key_file, client_gid, command) = parse_arguments(env::args().skip(1))?;
    let mut key = read_client_key(&key_file, client_gid)?;
    let authenticator = ControlAuthenticator::new(key);
    key.zeroize();
    let principal = principal_for_uid(rustix::process::geteuid().as_raw());
    let request_id = ControlRequestId::new(
        OsEntropy
            .random_128()
            .map_err(|error| format!("generate request identity: {error}"))?,
    );
    let frame = match command {
        Command::Start => encode_start(authenticator.sign_start(principal, request_id)),
        Command::Stop(session) => {
            encode_stop(authenticator.sign_stop(principal, request_id, session))
        }
    };
    let mut stream = UnixStream::connect(&socket)
        .map_err(|error| format!("connect {}: {error}", socket.display()))?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    stream
        .write_all(&frame)
        .map_err(|error| format!("write control request: {error}"))?;
    let mut length = [0_u8; 2];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("read response length: {error}"))?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_RESPONSE_BYTES {
        return Err("controller returned an invalid response length".to_owned());
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("read response: {error}"))?;
    match decode_response(&body) {
        Some(ControlResponse::Started(session)) if matches!(command, Command::Start) => {
            println!("{session}");
            Ok(())
        }
        Some(ControlResponse::Stopped) if matches!(command, Command::Stop(_)) => Ok(()),
        Some(ControlResponse::Denied) => Err("request denied".to_owned()),
        _ => Err("controller returned a non-canonical response".to_owned()),
    }
}

#[derive(Clone, Copy)]
enum Command {
    Start,
    Stop(ControlSessionId),
}

fn parse_arguments(
    arguments: impl IntoIterator<Item = String>,
) -> Result<(PathBuf, PathBuf, u32, Command), String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() < 7
        || arguments[0] != "--socket"
        || arguments[2] != "--key-file"
        || arguments[4] != "--client-gid"
    {
        return Err(usage().to_owned());
    }
    let socket = absolute_path(&arguments[1], "socket")?;
    let key = absolute_path(&arguments[3], "key-file")?;
    let gid = arguments[5]
        .parse()
        .map_err(|error| format!("invalid --client-gid: {error}"))?;
    let command = match arguments[6].as_str() {
        "start" if arguments.len() == 7 => Command::Start,
        "stop" if arguments.len() == 8 => Command::Stop(parse_session(&arguments[7])?),
        _ => return Err(usage().to_owned()),
    };
    Ok((socket, key, gid, command))
}

fn absolute_path(value: &str, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!(
            "--{label} must be an absolute canonical non-root path"
        ));
    }
    Ok(path)
}

fn parse_session(value: &str) -> Result<ControlSessionId, String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("session must be exactly 32 lower-case hexadecimal characters".to_owned());
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "session contains invalid hexadecimal".to_owned())?;
    }
    if bytes == [0; 16] {
        return Err("session cannot be all zeroes".to_owned());
    }
    Ok(ControlSessionId::new(bytes))
}

fn read_client_key(path: &Path, client_gid: u32) -> Result<[u8; 32], String> {
    let descriptor = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("open control key {}: {error}", path.display()))?;
    let mut file = fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.gid() != client_gid
        || metadata.mode() & 0o777 != 0o440
        || metadata.len() != 32
    {
        return Err("control key is not the exact client-group-readable 0440 file".to_owned());
    }
    let mut key = [0_u8; 32];
    file.read_exact(&mut key)
        .map_err(|error| format!("read control key: {error}"))?;
    Ok(key)
}

const fn usage() -> &'static str {
    "usage: host-control --socket PATH --key-file PATH --client-gid GID start|stop [SESSION]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_parser_accepts_only_nonzero_canonical_lower_hex() {
        assert!(parse_session("01010101010101010101010101010101").is_ok());
        assert!(parse_session("00000000000000000000000000000000").is_err());
        assert!(parse_session("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(parse_session("01").is_err());
    }

    #[test]
    fn command_grammar_is_closed() {
        let base = [
            "--socket",
            "/run/host-controld/control.sock",
            "--key-file",
            "/etc/host-controld/control.key",
            "--client-gid",
            "2000",
            "start",
        ];
        assert!(parse_arguments(base.map(str::to_owned)).is_ok());
        let mut extra = base.map(str::to_owned).to_vec();
        extra.push("extra".to_owned());
        assert!(parse_arguments(extra).is_err());
    }
}
