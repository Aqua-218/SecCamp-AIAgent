//! Real-syscall verification of the isolation transaction.
//!
//! Every other `runtime-isolation` test drives a recording mock that never enters the kernel.
//! This target applies the 13 steps through [`LinuxBackend`] on the running host and then asks
//! the isolated child what the kernel actually enforces against it.
//!
//! The transaction cannot run inside the libtest harness: `LinuxBackend` refuses a
//! multi-threaded launcher, and the isolated child becomes PID 1 of a fresh namespace set.
//! This target therefore uses `harness = false` and re-executes itself as a single-threaded
//! probe, selected by `RUNTIME_ISOLATION_PROBE_ROLE`.
//!
//! Hosts without the required privileges do not silently pass: the run reports the missing
//! prerequisite from the same [`CapabilityReport`] the backend would refuse to start with.

#![allow(missing_docs)]

use std::{
    env,
    ffi::CString,
    fs,
    io::Error,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};

use runtime_isolation::{
    BindMountConfig, CapabilityReport, CgroupConfig, ChildExit, ChildStartupStatus, IdentityMap,
    IsolationBackend, IsolationConfig, IsolationStep, LandlockConfig, LinuxBackend, RootfsConfig,
    RuntimeIsolation, SeccompPolicy, SpawnOutcome, TmpfsConfig,
};

/// Selects the probe role in a re-executed copy of this target.
const ROLE_ENV: &str = "RUNTIME_ISOLATION_PROBE_ROLE";
/// Carries the staging directory to the probe.
const BASE_ENV: &str = "RUNTIME_ISOLATION_PROBE_BASE";
/// Carries the host cgroup name to the probe.
const CGROUP_ENV: &str = "RUNTIME_ISOLATION_PROBE_CGROUP";

/// The scenario that must complete all 13 steps.
const ROLE_ENFORCE: &str = "enforce";
/// The scenario that must fail inside the child at `Landlock`.
const ROLE_LANDLOCK_FAILURE: &str = "landlock-failure";

/// A nonstandard descriptor deliberately left inheritable to prove the sweep closes it.
const MARKER_FD: i32 = 100;
/// The delegated cgroup v2 hierarchy the probe creates its constrained cgroup under.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// A Landlock read-only path that cannot resolve, used to fail step 10 deterministically.
const ABSENT_LANDLOCK_PATH: &str = "/runtime-isolation-probe-absent";

fn main() {
    match env::var(ROLE_ENV) {
        Ok(role) => run_probe(&role),
        Err(_) => run_verification(),
    }
}

// ---------------------------------------------------------------------------
// Verification role: prepares staging, re-executes the probe, checks the kernel
// ---------------------------------------------------------------------------

fn run_verification() {
    let mut backend = LinuxBackend::new();
    let report = backend.detect_capabilities(&detection_config());
    if !report.is_sufficient(&detection_config()) {
        assert!(
            !report.reasons.is_empty(),
            "an insufficient capability report must explain the missing prerequisite"
        );
        eprintln!(
            "privileged runtime isolation verification unavailable: {}",
            report.reasons.join("; ")
        );
        return;
    }
    assert_capability_report(&report);

    verify_enforced_boundary();
    verify_failed_step_reports_and_releases_the_host_cgroup();
    println!("privileged runtime isolation verification: 2 scenarios passed");
}

fn assert_capability_report(report: &CapabilityReport) {
    assert!(report.namespaces_available);
    assert!(report.cgroup_v2_available);
    assert!(report.seccomp_available);
    assert!(report.landlock_abi.is_some_and(|abi| abi >= 3));
}

/// Applies all 13 steps and asserts what the kernel denies the isolated child.
fn verify_enforced_boundary() {
    let scenario = Scenario::start(ROLE_ENFORCE);

    let parent = scenario.parent_report();
    assert_eq!(
        field(&parent, "startup"),
        "ready",
        "the launcher must observe a completed 13-step startup: {parent:?}"
    );
    assert_eq!(field(&parent, "exit"), "exited:0", "report: {parent:?}");

    let child = scenario.child_report();
    assert_eq!(
        field(&child, "pid"),
        "1",
        "the workload must be PID 1 of its own PID namespace"
    );
    assert_eq!(
        field(&child, "inherited_fd"),
        errno_name(libc::EBADF),
        "the descriptor sweep must close an inheritable nonstandard descriptor"
    );
    assert_eq!(
        field(&child, "socket"),
        errno_name(libc::EPERM),
        "seccomp must deny socket creation with EPERM"
    );
    assert_eq!(
        field(&child, "unshare"),
        errno_name(libc::EPERM),
        "seccomp must deny namespace creation with EPERM"
    );
    assert_eq!(
        field(&child, "dev_null"),
        errno_name(libc::ENOENT),
        "the masked device tree must not expose /dev/null"
    );
    // The tmpfs is writable at the mount level, so only Landlock can refuse this write. It is
    // the one probe that isolates the ruleset from every other restriction in the boundary.
    assert_eq!(
        field(&child, "tmpfs_write"),
        errno_name(libc::EACCES),
        "Landlock must deny writes outside the workspace"
    );
    // The rootfs is refused one layer earlier: the kernel rejects the write against the
    // read-only mount before any LSM hook runs.
    assert_eq!(
        field(&child, "rootfs_write"),
        errno_name(libc::EROFS),
        "the pivoted rootfs must be mounted read-only"
    );
    assert_eq!(
        field(&child, "workspace_write"),
        "0",
        "the workspace must remain writable inside the boundary"
    );
    assert_eq!(
        field(&child, "capeff"),
        "0000000000000000",
        "every effective capability must be dropped"
    );
    assert_eq!(field(&child, "nonewprivs"), "1");
    assert_eq!(
        field(&child, "seccomp"),
        "2",
        "the workload must run under a seccomp filter"
    );

    scenario.assert_cgroup_released();
}

/// Fails step 10 inside the child and asserts the launcher reports it and frees host state.
fn verify_failed_step_reports_and_releases_the_host_cgroup() {
    let scenario = Scenario::start(ROLE_LANDLOCK_FAILURE);

    let parent = scenario.parent_report();
    assert_eq!(
        field(&parent, "startup"),
        "failed",
        "an unsatisfiable Landlock policy must not report a started workload: {parent:?}"
    );
    assert_eq!(
        field(&parent, "failed_step"),
        format!("{:?}", IsolationStep::Landlock),
        "the launcher must learn which step refused the workload"
    );
    assert_eq!(
        field(&parent, "termination_required"),
        "true",
        "an irreversible root pivot must force termination instead of a retry"
    );
    assert!(
        !scenario
            .base
            .join("workspace")
            .join("child-report")
            .exists(),
        "a workload that never completed isolation must not have run"
    );

    scenario.assert_cgroup_released();
}

struct Scenario {
    role: &'static str,
    base: PathBuf,
    cgroup_name: String,
}

impl Scenario {
    fn start(role: &'static str) -> Self {
        let scenario = Self {
            role,
            base: env::temp_dir().join(format!(
                "runtime-isolation-probe-{role}-{}",
                std::process::id()
            )),
            cgroup_name: format!("runtime-isolation-probe-{role}-{}", std::process::id()),
        };
        scenario.stage();
        scenario.execute();
        scenario
    }

    /// Builds the tree the probe turns into a read-only rootfs.
    ///
    /// Every mount target is created here, while the tree is still writable: the backend only
    /// calls `create_dir_all`, which cannot add a directory to a read-only rootfs.
    fn stage(&self) {
        let _ = fs::remove_dir_all(&self.base);
        let rootfs = self.base.join("rootfs");
        for directory in [
            rootfs.join("workspace"),
            rootfs.join("tmp"),
            rootfs.join("proc"),
            rootfs.join("dev"),
            rootfs.join("etc"),
            rootfs.join(".old-root"),
            self.base.join("workspace"),
            self.base.join("mount"),
        ] {
            fs::create_dir_all(&directory)
                .unwrap_or_else(|error| panic!("staging {}: {error}", directory.display()));
        }
        fs::write(rootfs.join("etc").join("marker"), b"read-only\n")
            .expect("staging a file inside the read-only rootfs");
    }

    fn execute(&self) {
        let probe = env::current_exe().expect("locating this verification target");
        let output = Command::new(probe)
            .env(ROLE_ENV, self.role)
            .env(BASE_ENV, &self.base)
            .env(CGROUP_ENV, &self.cgroup_name)
            .output()
            .expect("re-executing this target as a single-threaded isolation probe");
        assert!(
            output.status.success(),
            "isolation probe failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn parent_report(&self) -> Vec<String> {
        read_report(&self.base.join("parent-report"))
    }

    fn child_report(&self) -> Vec<String> {
        read_report(&self.base.join("workspace").join("child-report"))
    }

    /// The launcher owns the constrained cgroup and must remove it once the child is reaped.
    fn assert_cgroup_released(&self) {
        let cgroup = Path::new(CGROUP_ROOT).join(&self.cgroup_name);
        assert!(
            !cgroup.exists(),
            "the launcher must remove its constrained cgroup: {}",
            cgroup.display()
        );
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
        let _ = fs::remove_dir(Path::new(CGROUP_ROOT).join(&self.cgroup_name));
    }
}

fn read_report(path: &Path) -> Vec<String> {
    let report = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading probe report {}: {error}", path.display()));
    report.lines().map(str::to_owned).collect()
}

fn field(report: &[String], name: &str) -> String {
    let prefix = format!("{name}=");
    report
        .iter()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("probe report has no {name} field: {report:?}"))
        .to_owned()
}

// ---------------------------------------------------------------------------
// Probe role: performs the real transaction
// ---------------------------------------------------------------------------

fn run_probe(role: &str) {
    let base = PathBuf::from(env::var(BASE_ENV).expect("probe staging directory"));
    let cgroup_name = env::var(CGROUP_ENV).expect("probe cgroup name");
    prepare_private_readonly_rootfs(&base.join("rootfs"));
    retain_inheritable_marker_descriptor(&base);

    let config = probe_config(&base, &cgroup_name, role);
    let mut backend = LinuxBackend::new();
    match RuntimeIsolation::spawn_isolated(&mut backend, &config, |_receipt| report_from_child()) {
        Ok(SpawnOutcome::Child(())) => {}
        Ok(SpawnOutcome::Parent(mut child)) => {
            let mut lines = Vec::new();
            let mut failed = false;
            match child.wait_for_startup() {
                Ok(ChildStartupStatus::Ready(ready)) => {
                    lines.push("startup=ready".to_owned());
                    lines.push(format!("pid_namespace={}", ready.pid_namespace().inode()));
                }
                Ok(ChildStartupStatus::Failed(failure)) => {
                    failed = true;
                    lines.push("startup=failed".to_owned());
                    lines.push(format!("failed_step={:?}", failure.step()));
                    lines.push(format!("failed_errno={:?}", failure.errno()));
                    lines.push(format!("failed_detail={}", failure.detail()));
                    lines.push(format!(
                        "termination_required={}",
                        failure.termination_required()
                    ));
                    lines.push(format!(
                        "rollback_failures={}",
                        failure.rollback_failure_count()
                    ));
                }
                Err(error) => {
                    failed = true;
                    lines.push("startup=error".to_owned());
                    lines.push(format!("startup_error={error}"));
                }
            }
            let exit = if failed {
                child.terminate()
            } else {
                child.wait()
            };
            lines.push(match exit {
                Ok(ChildExit::Exited(status)) => format!("exit=exited:{status}"),
                Ok(ChildExit::Signaled(signal)) => format!("exit=signaled:{signal}"),
                Err(error) => format!("exit=error:{error}"),
            });
            fs::write(base.join("parent-report"), lines.join("\n"))
                .expect("writing the launcher report");
        }
        Err(error) => {
            // Only the launcher can still reach its staging directory; the isolated child has
            // already pivoted away from it and must simply exit.
            if std::process::id() != 1 {
                let _ = fs::write(
                    base.join("parent-report"),
                    format!("startup=error\nstartup_error={error}\nexit=error:unstarted"),
                );
            }
            std::process::exit(1);
        }
    }
}

fn probe_config(base: &Path, cgroup_name: &str, role: &str) -> IsolationConfig {
    let mut read_only_paths = vec![PathBuf::from("/")];
    if role == ROLE_LANDLOCK_FAILURE {
        read_only_paths.push(PathBuf::from(ABSENT_LANDLOCK_PATH));
    }
    let config = IsolationConfig::new(
        RootfsConfig::new(
            base.join("rootfs"),
            base.join("mount"),
            base.join("mount").join(".old-root"),
        ),
        BindMountConfig::new(base.join("workspace"), "/workspace"),
        TmpfsConfig::new("/tmp", 8 * 1024 * 1024),
        CgroupConfig::new(CGROUP_ROOT, cgroup_name, 64 * 1024 * 1024, 64),
        LandlockConfig::new(3, read_only_paths, ["/workspace"]),
        SeccompPolicy::default(),
        IdentityMap::new(0, 0),
    );
    config
        .validate()
        .expect("the probe policy must satisfy the crate's own validation");
    config
}

/// Asks the kernel what it refuses, from inside the completed boundary.
///
/// Only allowlisted syscalls may appear here: the seccomp filter is already installed, so a
/// denied call inside this function would be reported as a boundary failure rather than a probe
/// bug. Every observation is buffered before the report is opened, because the report itself
/// proves the workspace is writable.
fn report_from_child() {
    let mut lines = vec![
        format!("pid={}", std::process::id()),
        format!("inherited_fd={}", errno_name(errno_of_fstat(MARKER_FD))),
        format!("socket={}", errno_name(errno_of_denied_socket())),
        format!("unshare={}", errno_name(errno_of_denied_unshare())),
        format!(
            "dev_null={}",
            errno_name(errno_of_open("/dev/null", libc::O_RDONLY))
        ),
        format!(
            "tmpfs_write={}",
            errno_name(errno_of_open("/tmp/escape", libc::O_CREAT | libc::O_WRONLY))
        ),
        format!(
            "rootfs_write={}",
            errno_name(errno_of_open("/etc/escape", libc::O_CREAT | libc::O_WRONLY))
        ),
        format!(
            "workspace_write={}",
            errno_name(errno_of_open(
                "/workspace/probe-write",
                libc::O_CREAT | libc::O_WRONLY
            ))
        ),
    ];
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for (field, label) in [
        ("CapEff:", "capeff"),
        ("NoNewPrivs:", "nonewprivs"),
        ("Seccomp:", "seccomp"),
    ] {
        lines.push(format!("{label}={}", status_field(&status, field)));
    }
    fs::write("/workspace/child-report", lines.join("\n"))
        .expect("the workspace must accept the isolated workload's report");
}

fn status_field(status: &str, field: &str) -> String {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map_or_else(|| "absent".to_owned(), |value| value.trim().to_owned())
}

// ---------------------------------------------------------------------------
// Probe setup and kernel observations
// ---------------------------------------------------------------------------

/// Gives the probe a private mount namespace holding a read-only rootfs.
///
/// The backend refuses a writable rootfs source, and doing this in the probe's own namespace
/// keeps the host mount table unchanged no matter how the scenario ends.
fn prepare_private_readonly_rootfs(rootfs: &Path) {
    // SAFETY: unshare takes only scalar flags.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        0,
        "probe requires a private mount namespace: {}",
        Error::last_os_error()
    );
    mount_or_panic(None, Path::new("/"), libc::MS_REC | libc::MS_PRIVATE);
    mount_or_panic(Some(rootfs), rootfs, libc::MS_BIND);
    mount_or_panic(
        None,
        rootfs,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
    );
}

fn mount_or_panic(source: Option<&Path>, target: &Path, flags: libc::c_ulong) {
    let source = source.map(c_path);
    let target = c_path(target);
    let source_pointer = source
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    // SAFETY: both paths stay alive for the call, and the filesystem type and data are unused
    // for the bind, remount, and propagation changes issued here.
    let result = unsafe {
        libc::mount(
            source_pointer,
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    assert_eq!(
        result,
        0,
        "probe mount of {target:?} with flags {flags:#x} failed: {}",
        Error::last_os_error()
    );
}

/// Leaves a nonstandard descriptor open without close-on-exec, for the sweep to close.
fn retain_inheritable_marker_descriptor(base: &Path) {
    let path = base.join("inherited-marker");
    fs::write(&path, b"marker\n").expect("staging the inheritable marker file");
    let path = c_path(&path);
    // SAFETY: the path stays alive for the call and no mode is needed without O_CREAT.
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    assert!(
        descriptor >= 0,
        "opening the inheritable marker: {}",
        Error::last_os_error()
    );
    // SAFETY: `descriptor` is open, and dup2 returns a descriptor without close-on-exec.
    let duplicated = unsafe { libc::dup2(descriptor, MARKER_FD) };
    assert_eq!(
        duplicated,
        MARKER_FD,
        "reserving the marker descriptor: {}",
        Error::last_os_error()
    );
    // SAFETY: the original descriptor was returned by a successful open and is now duplicated.
    unsafe { libc::close(descriptor) };
}

fn errno_of_open(path: &str, flags: libc::c_int) -> i32 {
    let path = CString::new(path).expect("probe paths contain no NUL byte");
    // SAFETY: the path stays alive for the call and a mode accompanies O_CREAT.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags, 0o600 as libc::c_uint) };
    if descriptor >= 0 {
        // SAFETY: the descriptor was returned by a successful open.
        unsafe { libc::close(descriptor) };
        return 0;
    }
    last_errno()
}

fn errno_of_fstat(descriptor: libc::c_int) -> i32 {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `metadata` is writable for the whole call.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } == 0 {
        return 0;
    }
    last_errno()
}

fn errno_of_denied_socket() -> i32 {
    // SAFETY: socket takes only scalar arguments.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if descriptor >= 0 {
        // SAFETY: the descriptor was returned by a successful socket call.
        unsafe { libc::close(descriptor) };
        return 0;
    }
    last_errno()
}

fn errno_of_denied_unshare() -> i32 {
    // SAFETY: unshare takes only scalar flags.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
        return 0;
    }
    last_errno()
}

fn last_errno() -> i32 {
    Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Reports errno by name so a failing assertion names the boundary, not a number.
fn errno_name(errno: i32) -> String {
    match errno {
        0 => "0".to_owned(),
        libc::EPERM => "EPERM".to_owned(),
        libc::EACCES => "EACCES".to_owned(),
        libc::EBADF => "EBADF".to_owned(),
        libc::ENOENT => "ENOENT".to_owned(),
        libc::EROFS => "EROFS".to_owned(),
        other => format!("errno:{other}"),
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("probe paths contain no NUL byte")
}

fn detection_config() -> IsolationConfig {
    IsolationConfig::new(
        RootfsConfig::new("/var/lib/luna/rootfs", "/mnt/luna", "/mnt/luna/.old-root"),
        BindMountConfig::new("/run/luna/capfs", "/workspace"),
        TmpfsConfig::new("/tmp", 8 * 1024 * 1024),
        CgroupConfig::new(
            CGROUP_ROOT,
            "runtime-isolation-detect",
            64 * 1024 * 1024,
            64,
        ),
        LandlockConfig::new(3, ["/"], ["/workspace"]),
        SeccompPolicy::default(),
        IdentityMap::new(0, 0),
    )
}
