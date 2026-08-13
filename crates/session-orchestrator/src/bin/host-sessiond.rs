//! One-session production host daemon.
//!
//! The daemon accepts only explicit, pinned configuration. It builds the production ownership
//! graph, starts one immutable guest image, polls the exact Broker worker, and drains cleanup when
//! an operator creates its configured stop file. Guest identity and capability policy are never
//! accepted over the guest control transport.

use std::{
    collections::BTreeMap,
    env, fs,
    num::{NonZeroU64, NonZeroUsize},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    thread,
    time::Duration,
};

use authority_core::{
    capability::{AuthorityBody, IssuerId},
    file::{FileAuthority, FileEffect, FileEffects},
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
    SnapshotId, WorkspaceTemplateId,
    authority_backend::AuthorityRootGrant,
    filesystem_factory::{FilesystemFirecrackerFactory, GuestArtifactTemplate, SnapshotTemplate},
    production_runtime::{
        AuthorityAuditMode, ProductionBrokerEndpoint, ProductionBrokerLimits,
        ProductionDurabilityConfig, ProductionFirecrackerConfig, ProductionGuestControlEndpoint,
        ProductionSessionConfig, ProductionSessionRuntimeBuilder,
    },
    session_owner::{OwnerPollOutcome, OwnerPollRequest},
    system_egress::{GitHubEgressConfig, SystemEgressFactory},
};

const TEMPLATE_CLONE_ID: &str = "template";
const REQUIRED_SECCOMP_DENIES: [&str; 8] = [
    "bpf",
    "connect",
    "mount",
    "perf_event_open",
    "ptrace",
    "setns",
    "socket",
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
    let config = DaemonConfig::parse(env::args().skip(1))?;
    let factory = FilesystemFirecrackerFactory::with_guest_artifacts(
        config.snapshot_id,
        config.runtime.clone(),
        GuestArtifactTemplate::new(config.kernel_source, config.seccomp_source),
        SnapshotTemplate::new(config.snapshot_state, config.snapshot_memory),
    );
    let egress = SystemEgressFactory::new(config.github_egress);
    let mut runtime = ProductionSessionRuntimeBuilder::new(config.production, factory, egress)
        .build()
        .map_err(|error| format!("building production session runtime: {error}"))?;
    let started = runtime
        .start(&config.grant)
        .map_err(|error| format!("starting production session: {error}"))?;
    let identity = started.identity();
    println!(
        "host-sessiond: started session={} workspace={} subject={} capability={}",
        identity.session_id(),
        identity.workspace_id(),
        identity.subject_id(),
        identity.capability_id()
    );

    loop {
        if config.stop_file.exists() {
            eprintln!(
                "host-sessiond: stop file observed at {}; draining cleanup",
                config.stop_file.display()
            );
            return drain_stop(&mut runtime, config.poll_interval);
        }
        match runtime.poll(OwnerPollRequest::Continue) {
            Ok(OwnerPollOutcome::Running(_)) => thread::sleep(config.poll_interval),
            Ok(OwnerPollOutcome::Closed(reason)) => {
                println!("host-sessiond: session closed after {reason:?}");
                return Ok(());
            }
            Err(error) if runtime.state() == session_orchestrator::LifecycleState::Closed => {
                eprintln!("host-sessiond: terminal poll error after cleanup: {error}");
                return Ok(());
            }
            Err(error) => {
                eprintln!("host-sessiond: poll failed closed; retrying retained cleanup: {error}");
                thread::sleep(config.poll_interval);
            }
        }
    }
}

fn drain_stop(
    runtime: &mut session_orchestrator::production_runtime::ProductionSessionRuntime,
    interval: Duration,
) -> Result<(), String> {
    loop {
        match runtime.stop() {
            Ok(OwnerPollOutcome::Closed(reason)) => {
                println!("host-sessiond: session closed after {reason:?}");
                return Ok(());
            }
            Ok(OwnerPollOutcome::Running(_)) => {
                return Err("stop request unexpectedly left the session running".to_owned());
            }
            Err(error) if runtime.state() == session_orchestrator::LifecycleState::Closed => {
                eprintln!("host-sessiond: terminal stop error after cleanup: {error}");
                return Ok(());
            }
            Err(error) => {
                eprintln!("host-sessiond: cleanup remains retryable: {error}");
                thread::sleep(interval);
            }
        }
    }
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
}

impl DaemonConfig {
    #[allow(clippy::too_many_lines)] // Every required deployment boundary is parsed explicitly.
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut arguments = Arguments::parse(arguments)?;
        let firecracker = arguments.pinned("firecracker")?;
        let jailer = arguments.pinned("jailer")?;
        let kernel_source = arguments.pinned("kernel-source")?;
        let rootfs = arguments.pinned("rootfs")?;
        let verity_hash = arguments.pinned("verity-hash")?;
        let formatter = arguments.pinned("workspace-formatter")?;
        let seccomp_source = arguments.pinned("seccomp-source")?;
        let snapshot_state = arguments.pinned("snapshot-state")?;
        let snapshot_memory = arguments.pinned("snapshot-memory")?;
        let veritysetup = arguments.pinned("veritysetup")?;
        let dmsetup = arguments.pinned("dmsetup")?;
        let chroot_base = arguments.absolute_path("jailer-chroot-base")?;
        let workspace_source = arguments.absolute_path("workspace-source")?;
        let cgroup_parent = parse_cgroup_parent(&arguments.required("cgroup-parent")?)?;
        let firecracker_name = firecracker
            .path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "--firecracker path must have a filename".to_owned())?;
        let template_root = chroot_base
            .join(firecracker_name)
            .join(TEMPLATE_CLONE_ID)
            .join("root");
        let guest_cid = arguments.number("guest-cid")?;
        let runtime = RuntimeConfig {
            firecracker,
            kernel: PinnedArtifact::new(
                template_root.join("artifacts/kernel"),
                kernel_source.digest,
            ),
            rootfs: rootfs.clone(),
            verity_hash: verity_hash.clone(),
            dm_verity: DmVerityConfig {
                data_device: rootfs.path.clone(),
                hash_device: verity_hash.path.clone(),
                mapper_name: arguments.required("verity-mapper-prefix")?,
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
            api_socket: template_root.join("run/firecracker.sock"),
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
                    filter: PinnedArtifact::new(
                        template_root.join("artifacts/seccomp"),
                        seccomp_source.digest,
                    ),
                    blocked_syscalls: REQUIRED_SECCOMP_DENIES
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                },
            },
            vsock: VsockConfig {
                guest_cid,
                uds_path: template_root.join("run/vsock.sock"),
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
        let grant = AuthorityRootGrant::new(validity, AuthorityBody::File(authority));
        let audit_path = arguments.absolute_path("authority-audit")?;
        let audit_mode = match arguments.required("authority-audit-mode")?.as_str() {
            "create" => AuthorityAuditMode::CreateNew(audit_path),
            "open" => AuthorityAuditMode::OpenExisting(audit_path),
            value => {
                return Err(format!(
                    "--authority-audit-mode must be create or open, got {value:?}"
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
        let production = ProductionSessionConfig::new(
            ProductionDurabilityConfig::new(
                arguments.absolute_path("identity-ledger")?,
                arguments.absolute_path("recovery-journal")?,
                audit_mode,
                arguments.absolute_path("broker-wal-root")?,
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
                arguments.number("broker-port")?,
                arguments.number("broker-backlog")?,
            ),
            ProductionGuestControlEndpoint::new(arguments.number("guest-control-port")?),
            broker_limits,
        );
        let github_egress = match (
            arguments.optional("github-installation")?,
            arguments.optional("github-credential-handle")?,
        ) {
            (None, None) => GitHubEgressConfig::Disabled,
            (Some(installation), Some(handle)) => GitHubEgressConfig::environment(
                authority_core::github::InstallationId::new(installation),
                CredentialHandle::from_host_id(parse_number(
                    "--github-credential-handle",
                    &handle,
                )?),
            ),
            _ => {
                return Err(
                    "--github-installation and --github-credential-handle must be configured together"
                        .to_owned(),
                );
            }
        };
        let stop_file = arguments.absolute_path("stop-file")?;
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
        })
    }
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
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err("--cgroup-parent must be safe relative cgroup components".to_owned());
    }
    Ok(PathBuf::from(value))
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

fn usage() -> &'static str {
    "usage: host-sessiond \\
  --firecracker PATH --firecracker-sha256 SHA256 --jailer PATH --jailer-sha256 SHA256 \\
  --kernel-source PATH --kernel-source-sha256 SHA256 --rootfs PATH --rootfs-sha256 SHA256 \\
  --verity-hash PATH --verity-hash-sha256 SHA256 --rootfs-verity-root-hash SHA256 \\
  --workspace-formatter PATH --workspace-formatter-sha256 SHA256 --workspace-source PATH \\
  --seccomp-source PATH --seccomp-source-sha256 SHA256 --snapshot-id HEX32 \\
  --snapshot-state PATH --snapshot-state-sha256 SHA256 --snapshot-memory PATH --snapshot-memory-sha256 SHA256 \\
  --veritysetup PATH --veritysetup-sha256 SHA256 --dmsetup PATH --dmsetup-sha256 SHA256 \\
  --jailer-chroot-base PATH --cgroup-parent RELATIVE --jailer-uid UID --jailer-gid GID \\
  --verity-mapper-prefix NAME --workspace-image-bytes BYTES --memory-max-bytes BYTES \\
  --cpu-quota-micros MICROS --cpu-period-micros MICROS --guest-cid CID --vcpu-count COUNT \\
  --memory-mib MIB --boot-args ARGS --issuer ID --workspace-template ID \\
  --identity-ledger PATH --recovery-journal PATH --authority-audit PATH --authority-audit-mode create|open \\
  --broker-wal-root PATH --broker-host-cid CID --broker-port PORT --broker-backlog COUNT \\
  --guest-control-port PORT --broker-replay-capacity COUNT --broker-budget-requests COUNT \\
  --broker-budget-response-bytes BYTES --broker-budget-concurrent COUNT --github-response-cap-bytes BYTES \\
  --broker-max-connection-requests COUNT --repository ID --file-effects CANONICAL-LIST \\
  --path-prefix /|PATH --stop-file PATH --poll-millis MILLIS \\
  [--github-installation ID --github-credential-handle INTEGER]\n\nThe stop file must be absent at startup. Create it to request a retrying, dependency-ordered shutdown.\nGitHub egress is disabled unless both optional GitHub flags are supplied; the token is read only from EGRESS_GITHUB_TOKEN."
}

#[cfg(test)]
mod tests {
    use super::{parse_file_effects, parse_hex_16, parse_path_prefix};

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
}
