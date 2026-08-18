//! Opt-in production `Runtime::launch` lifecycle verification.
//!
//! This test deliberately uses the real command runner, filesystem adapter, jailer, Firecracker
//! API socket, dm-verity mapping, and cgroup-v2 hierarchy.  It is not a direct Firecracker API
//! smoke test: the only API calls are made by `Runtime::launch` after the real host resources
//! have passed their ownership gates.

use firecracker_runtime::{
    ApiClient, ApiRequest, ApiResponse, CgroupConfig, CgroupVersion, DmVerityConfig,
    HostIsolationConfig, JailerConfig, NamespaceConfig, PinnedArtifact, RealCommandRunner,
    RealFileSystem, Runtime, RuntimeConfig, RuntimeError, RuntimeState, SeccompConfig,
    SystemIdentitySource, VsockConfig, WorkspaceConfig, WorkspaceImageConfig, sha256,
};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const GUEST_MEMORY_MIB: u32 = 128;
const GUEST_CID: u32 = 42;
const API_TIMEOUT: Duration = Duration::from_secs(5);
const CGROUP_MEMORY_MAX: u64 = 512 * 1024 * 1024;
const CGROUP_CPU_QUOTA: u64 = 100_000;
const CGROUP_CPU_PERIOD: u64 = 100_000;

struct UnusedApi;

impl ApiClient for UnusedApi {
    fn request(&mut self, _request: &ApiRequest) -> Result<ApiResponse, RuntimeError> {
        Err(RuntimeError::Api(
            "the real lifecycle gate must not use the guest API client during launch".to_owned(),
        ))
    }
}

fn required_path(variable: &str) -> PathBuf {
    let value = std::env::var_os(variable).unwrap_or_else(|| panic!("{variable} must be set"));
    let path = PathBuf::from(value);
    let metadata = fs::symlink_metadata(&path)
        .unwrap_or_else(|error| panic!("{variable} is not accessible: {error}"));
    assert!(path.is_absolute(), "{variable} must be absolute");
    assert!(
        !metadata.file_type().is_symlink(),
        "{variable} must not be a symlink"
    );
    assert!(metadata.is_file(), "{variable} must be a regular file");
    path
}

fn required_root_hash() -> firecracker_runtime::Sha256Digest {
    let value = std::env::var("REAL_FIRECRACKER_ROOT_HASH")
        .expect("REAL_FIRECRACKER_ROOT_HASH must be set");
    firecracker_runtime::Sha256Digest::from_hex(value.trim())
        .expect("REAL_FIRECRACKER_ROOT_HASH must be a 64-character hex digest")
}

fn required_lifecycle_name(variable: &str) -> String {
    let value = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} must be set"));
    assert!(!value.is_empty(), "{variable} must not be empty");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "{variable} must contain only ASCII letters, digits, '_' or '-'",
    );
    value
}

fn required_lifecycle_cgroup_parent() -> PathBuf {
    const PREFIX: &str = "/sys/fs/cgroup/firecracker-runtime-lifecycle-";
    let value = std::env::var("REAL_RUNTIME_LIFECYCLE_CGROUP_PARENT")
        .expect("REAL_RUNTIME_LIFECYCLE_CGROUP_PARENT must be set");
    assert!(
        value.starts_with(PREFIX),
        "cgroup parent must be wrapper-owned"
    );
    let suffix = &value[PREFIX.len()..];
    assert!(
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-'),
        "cgroup parent suffix must contain only digits and '-'"
    );
    PathBuf::from(value)
}

fn copy_pinned(source: &Path, destination: &Path) -> PinnedArtifact {
    fs::copy(source, destination).unwrap_or_else(|error| {
        panic!(
            "cannot copy pinned artifact {} -> {}: {error}",
            source.display(),
            destination.display()
        )
    });
    let bytes = fs::read(destination).expect("copied pinned artifact must be readable");
    PinnedArtifact::new(destination, sha256(&bytes))
}

fn read_cgroup_tasks(path: &Path) -> Vec<u32> {
    let contents = fs::read_to_string(path.join("cgroup.procs"))
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    contents
        .lines()
        .map(|line| line.parse::<u32>().expect("cgroup task must be decimal"))
        .collect()
}

fn wait_for_cgroup_task(path: &Path) -> u32 {
    let deadline = Instant::now() + API_TIMEOUT;
    loop {
        let tasks = read_cgroup_tasks(path);
        if let Some(pid) = tasks.into_iter().next() {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "real jailer did not place Firecracker in {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn proc_status_field(pid: u32, field: &str) -> String {
    let contents = fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|error| panic!("cannot read /proc/{pid}/status: {error}"));
    contents
        .lines()
        .find_map(|line| line.strip_prefix(field).map(str::trim))
        .unwrap_or_else(|| panic!("/proc/{pid}/status omitted {field}"))
        .to_owned()
}

fn proc_cgroup_path(pid: u32) -> String {
    let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_else(|error| panic!("cannot read /proc/{pid}/cgroup: {error}"));
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_else(|| panic!("/proc/{pid}/cgroup omitted the cgroup-v2 entry"))
        .to_owned()
}

fn digest_proc_executable(pid: u32) -> firecracker_runtime::Sha256Digest {
    let mut file = File::open(format!("/proc/{pid}/exe"))
        .unwrap_or_else(|error| panic!("cannot open /proc/{pid}/exe: {error}"));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("/proc executable must be readable");
    sha256(&bytes)
}

fn namespace_link(pid: u32, name: &str) -> PathBuf {
    fs::read_link(format!("/proc/{pid}/ns/{name}"))
        .unwrap_or_else(|error| panic!("cannot inspect {name} namespace for {pid}: {error}"))
}

#[allow(clippy::too_many_lines)] // Profile construction enumerates every production launch artifact.
fn configure_test_profile() -> (tempfile::TempDir, RuntimeConfig, PathBuf) {
    let firecracker = required_path("REAL_FIRECRACKER_BIN");
    let jailer = required_path("REAL_FIRECRACKER_JAILER");
    let kernel = required_path("REAL_FIRECRACKER_KERNEL");
    let rootfs = required_path("REAL_FIRECRACKER_ROOTFS");
    let verity_hash = required_path("REAL_FIRECRACKER_VERITY_HASH");
    let veritysetup = required_path("REAL_VERITYSETUP");
    let formatter = required_path("REAL_WORKSPACE_FORMATTER");
    let seccomp = required_path("REAL_FIRECRACKER_SECCOMP");
    let seccomp_policy = required_path("REAL_FIRECRACKER_SECCOMP_POLICY");
    let seccomp_compiler = required_path("REAL_FIRECRACKER_SECCOMP_COMPILER");
    let root_hash = required_root_hash();
    let clone_id = required_lifecycle_name("REAL_RUNTIME_LIFECYCLE_CLONE_ID");
    let mapper_name = required_lifecycle_name("REAL_RUNTIME_LIFECYCLE_MAPPER_NAME");

    let directory = tempfile::tempdir().expect("real lifecycle staging directory must exist");
    let jailer_base = directory.path().join("jailer");
    let cgroup_parent = required_lifecycle_cgroup_parent();
    let jail_root = jailer_base.join("firecracker").join(&clone_id).join("root");
    fs::create_dir_all(jail_root.join("dev"))
        .expect("jail /dev directory must be creatable before bind setup");
    fs::create_dir_all(jail_root.join("run"))
        .expect("jail /run directory must be creatable before API setup");
    fs::create_dir_all(jail_root.join("workspace"))
        .expect("jail workspace parent must be creatable before cloning");
    fs::create_dir_all(jail_root.join("artifacts"))
        .expect("jail artifact directory must be creatable");
    for directory in [
        jail_root.as_path(),
        jail_root.join("dev").as_path(),
        jail_root.join("run").as_path(),
        jail_root.join("workspace").as_path(),
        jail_root.join("artifacts").as_path(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .expect("jail directories must be traversable by the jailed Firecracker user");
    }

    let jail_kernel = copy_pinned(&kernel, &jail_root.join("artifacts/kernel"));
    let jail_seccomp = copy_pinned(&seccomp, &jail_root.join("artifacts/seccomp"));
    for artifact in [
        jail_root.join("artifacts/kernel"),
        jail_root.join("artifacts/seccomp"),
    ] {
        fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))
            .expect("jailed artifacts must be readable by the jailed Firecracker user");
    }
    let source = directory.path().join("source");
    fs::create_dir(&source).expect("workspace source must be creatable");
    let mut source_file = File::create(source.join("launch-marker"))
        .expect("workspace source marker must be creatable");
    source_file
        .write_all(b"real-runtime-launch/v1\n")
        .expect("workspace source marker must be writable");
    source_file
        .sync_all()
        .expect("workspace source marker must sync");

    fs::create_dir(&cgroup_parent).unwrap_or_else(|error| {
        panic!(
            "cannot create cgroup parent {}: {error}",
            cgroup_parent.display()
        )
    });
    let cgroup = cgroup_parent.join(&clone_id);

    let workspace = WorkspaceConfig {
        source,
        clone_root: jail_root.join("workspace"),
        clone_id: clone_id.clone(),
        image: WorkspaceImageConfig {
            formatter: PinnedArtifact::new(&formatter, sha256(&fs::read(&formatter).unwrap())),
            size_bytes: 16 * 1024 * 1024,
        },
    };
    let config = RuntimeConfig {
        firecracker: PinnedArtifact::new(&firecracker, sha256(&fs::read(&firecracker).unwrap())),
        kernel: jail_kernel,
        rootfs: PinnedArtifact::new(&rootfs, sha256(&fs::read(&rootfs).unwrap())),
        verity_hash: PinnedArtifact::new(
            &verity_hash,
            sha256(&fs::read(&verity_hash).unwrap()),
        ),
        veritysetup: PinnedArtifact::new(
            &veritysetup,
            sha256(&fs::read(&veritysetup).unwrap()),
        ),
        dm_verity: DmVerityConfig {
            data_device: rootfs.clone(),
            hash_device: verity_hash.clone(),
            mapper_name,
            root_hash,
            jailed_device_path: jail_root.join("dev/rootfs"),
        },
        workspace,
        jailer: PinnedArtifact::new(&jailer, sha256(&fs::read(&jailer).unwrap())),
        jailer_config: JailerConfig {
            uid: 65_534,
            gid: 65_534,
            chroot_base_dir: jailer_base,
            cgroup_version: CgroupVersion::V2,
        },
        api_socket: jail_root.join("run/api.sock"),
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
                path: cgroup.clone(),
                memory_max_bytes: CGROUP_MEMORY_MAX,
                cpu_quota_micros: CGROUP_CPU_QUOTA,
                cpu_period_micros: CGROUP_CPU_PERIOD,
            },
            seccomp: SeccompConfig {
                compiler: PinnedArtifact::new(
                    &seccomp_compiler,
                    sha256(&fs::read(&seccomp_compiler).unwrap()),
                ),
                filter: jail_seccomp,
                policy: PinnedArtifact::new(
                    &seccomp_policy,
                    sha256(&fs::read(&seccomp_policy).unwrap()),
                ),
                blocked_syscalls: [
                    "bpf",
                    "mount",
                    "perf_event_open",
                    "ptrace",
                    "setns",
                    "unshare",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            },
        },
        vsock: VsockConfig {
            guest_cid: GUEST_CID,
            uds_path: jail_root.join("run/vsock.sock"),
        },
        network_devices: Vec::new(),
        vcpu_count: 1,
        memory_mib: GUEST_MEMORY_MIB,
        boot_args: "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rootfstype=squashfs ro init=/usr/local/libexec/guest-control-init".to_owned(),
    };
    (directory, config, cgroup_parent)
}

#[test]
#[ignore = "requires root, /dev/kvm, cgroup-v2, dm-verity, and pinned Firecracker artifacts"]
#[allow(clippy::too_many_lines)] // The gate observes launch, isolation, and every shutdown residue.
fn real_runtime_launches_and_cleans_real_jailer_lifecycle() {
    assert_eq!(std::env::var("REAL_RUNTIME_LIFECYCLE").as_deref(), Ok("1"));
    let (_directory, config, cgroup_parent) = configure_test_profile();
    config
        .validate()
        .expect("real profile must validate before side effects");

    let expected_cgroup = config.isolation.cgroup.path.clone();
    let expected_mapper = PathBuf::from("/dev/mapper").join(&config.dm_verity.mapper_name);
    let expected_jail_root = config
        .jailer_config
        .chroot_base_dir
        .join("firecracker")
        .join(&config.workspace.clone_id)
        .join("root");
    let expected_firecracker_digest = config.firecracker.digest;
    let own_pid_namespace = namespace_link(std::process::id(), "pid");
    let own_mount_namespace = namespace_link(std::process::id(), "mnt");

    let api = firecracker_runtime::UnixApiClient::new(&config.api_socket)
        .expect("real Firecracker API socket path must be valid")
        .with_timeout(API_TIMEOUT)
        .expect("real Firecracker API timeout must be valid");
    let mut runtime = Runtime::new(
        RealCommandRunner::new(),
        RealFileSystem::default(),
        api,
        UnusedApi,
        SystemIdentitySource,
    );

    let mut instance = runtime
        .launch(&config)
        .unwrap_or_else(|error| panic!("production Runtime::launch failed: {error}"));
    assert_eq!(instance.state(), RuntimeState::WorkloadStopped);

    let firecracker_pid = wait_for_cgroup_task(&expected_cgroup);
    assert_eq!(
        digest_proc_executable(firecracker_pid),
        expected_firecracker_digest
    );
    assert_eq!(
        proc_cgroup_path(firecracker_pid),
        format!(
            "/{}",
            expected_cgroup
                .strip_prefix("/sys/fs/cgroup")
                .unwrap()
                .display()
        )
    );
    assert_eq!(proc_status_field(firecracker_pid, "Seccomp:"), "2");
    assert_eq!(
        proc_status_field(firecracker_pid, "Uid:"),
        "65534\t65534\t65534\t65534"
    );
    assert_ne!(namespace_link(firecracker_pid, "pid"), own_pid_namespace);
    assert_ne!(namespace_link(firecracker_pid, "mnt"), own_mount_namespace);
    assert_eq!(
        fs::read_to_string(expected_cgroup.join("memory.max"))
            .unwrap()
            .trim(),
        CGROUP_MEMORY_MAX.to_string()
    );
    assert_eq!(
        fs::read_to_string(expected_cgroup.join("cpu.max"))
            .unwrap()
            .trim(),
        format!("{CGROUP_CPU_QUOTA} {CGROUP_CPU_PERIOD}")
    );
    assert!(
        expected_mapper.exists(),
        "dm-verity mapper must remain active while VM is live"
    );
    assert!(
        expected_jail_root.exists(),
        "jailer root must exist while VM is live"
    );
    assert!(
        config.workspace.clone_path().exists(),
        "workspace clone must remain while VM is live"
    );
    assert!(
        config.workspace.image_path().exists(),
        "workspace image must remain while VM is live"
    );

    runtime
        .shutdown(&mut instance, &config)
        .unwrap_or_else(|error| panic!("production Runtime::shutdown failed: {error}"));
    assert_eq!(instance.state(), RuntimeState::Stopped);
    assert!(
        !expected_mapper.exists(),
        "dm-verity mapper must be closed after shutdown"
    );
    assert!(
        !config.dm_verity.jailed_device_path.exists(),
        "jail bind target must be removed after shutdown"
    );
    assert!(
        !config.workspace.clone_path().exists(),
        "workspace clone must be removed after shutdown"
    );
    assert!(
        !config.workspace.image_path().exists(),
        "workspace image must be removed after shutdown"
    );
    assert!(
        !expected_cgroup.exists(),
        "owned cgroup leaf must be removed after shutdown"
    );
    assert!(
        !expected_jail_root.exists(),
        "jailer root must be removed after shutdown"
    );

    fs::remove_dir(&cgroup_parent)
        .unwrap_or_else(|error| panic!("cgroup parent residue could not be removed: {error}"));
    assert!(
        !cgroup_parent.exists(),
        "cgroup parent must be empty after shutdown"
    );
}
