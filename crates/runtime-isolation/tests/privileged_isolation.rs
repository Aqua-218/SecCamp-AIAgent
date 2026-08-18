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
    collections::BTreeSet,
    env,
    ffi::{CString, OsStr, OsString},
    fs,
    io::{Error, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
/// The scenario that must fail before `LimitedTmpfs` and roll back the completed workspace mount.
const ROLE_LIMITED_TMPFS_FAILURE: &str = "limited-tmpfs-failure";
/// The scenario that starts the production isolation launcher and execs this binary again.
const ROLE_LAUNCHER_POST_EXEC: &str = "launcher-post-exec";

/// Selects the debug-only production-backend fault used by the rollback scenario.
const TEST_FAILURE_STEP_ENV: &str = "RUNTIME_ISOLATION_TEST_FAIL_STEP";
/// Requests the fault immediately before the real `LimitedTmpfs` mount operation.
const TEST_FAILURE_LIMITED_TMPFS: &str = "limited-tmpfs";

/// Set only by the launcher to select the hostile workload after `execve`.
const POST_EXEC_ROLE_ENV: &str = "RUNTIME_ISOLATION_POST_EXEC_ROLE";
/// The fixed value accepted by the post-exec workload.
const POST_EXEC_ROLE_VALUE: &str = "hostile-v1";
/// The inherited supervisor control descriptor name used by the launcher contract.
const CONTROL_FD_ENV: &str = "SUPERVISOR_CONTROL_FD";
/// The inherited Broker descriptor name used by the launcher contract.
const BROKER_FD_ENV: &str = "EGRESS_BROKER_FD";
/// The fixed workspace target passed to the hostile workload for this probe.
const WORKSPACE_TARGET_ENV: &str = "RUNTIME_ISOLATION_WORKSPACE_TARGET";
/// A local-only vsock CID supported by the kernel for an in-host connected pair.
const VMADDR_CID_LOCAL: u32 = 1;

/// A nonstandard descriptor deliberately left inheritable to prove the sweep closes it.
const MARKER_FD: i32 = 100;
/// The delegated cgroup v2 hierarchy the probe creates its constrained cgroup under.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// A Landlock read-only path that cannot resolve, used to fail step 10 deterministically.
const ABSENT_LANDLOCK_PATH: &str = "/runtime-isolation-probe-absent";

fn main() {
    if env::var(POST_EXEC_ROLE_ENV).ok().as_deref() == Some(POST_EXEC_ROLE_VALUE) {
        run_post_exec_probe();
        return;
    }
    match env::var(ROLE_ENV) {
        Ok(role) => match role.as_str() {
            ROLE_LAUNCHER_POST_EXEC => run_launcher_probe(),
            _ => run_probe(&role),
        },
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
        std::process::exit(2);
    }
    assert_capability_report(&report);

    verify_enforced_boundary();
    verify_failed_step_reports_and_releases_the_host_cgroup();
    verify_failed_mount_rolls_back_and_leaves_no_residue();
    verify_launcher_post_exec_boundary();
    println!("privileged runtime isolation verification: 4 scenarios passed");
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
    assert_escape_corpus_denied(&child);
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

/// Fails the real backend at `LimitedTmpfs` and observes cleanup outside the child namespace.
fn verify_failed_mount_rolls_back_and_leaves_no_residue() {
    let scenario = Scenario::start(ROLE_LIMITED_TMPFS_FAILURE);

    let parent = scenario.parent_report();
    assert_eq!(
        field(&parent, "startup"),
        "failed",
        "a deterministic LimitedTmpfs fault must not report a started workload: {parent:?}"
    );
    assert_eq!(
        field(&parent, "failed_step"),
        format!("{:?}", IsolationStep::LimitedTmpfs),
        "the launcher must report the production backend's failed mount step"
    );
    assert_eq!(
        field(&parent, "termination_required"),
        "true",
        "the completed root pivot must force child termination after rollback"
    );
    assert_eq!(
        field(&parent, "rollback_failures"),
        "3",
        "only irreversible namespace, identity-map, and rootfs rollback operations may fail; the completed workspace unmount must succeed"
    );
    assert_eq!(
        field(&parent, "child_mount_namespace"),
        "gone",
        "the failed child namespace must be destroyed after its cleanup path"
    );
    assert_eq!(
        field(&parent, "host_mount_residue"),
        "none",
        "completed child mounts must not propagate into the launcher's mount namespace"
    );
    assert!(
        !scenario
            .base
            .join("workspace")
            .join("child-report")
            .exists(),
        "a workload that never completed isolation must not have executed"
    );

    scenario.assert_cgroup_released();
}

/// Drives the deployable launcher through its inherited start gate and a real `execve`.
fn verify_launcher_post_exec_boundary() {
    let scenario = LauncherScenario::start();
    let report = scenario.report();
    if field(&report, "startup") == "unavailable" {
        eprintln!(
            "privileged post-exec launcher verification unavailable: {}",
            field(&report, "reason")
        );
        std::process::exit(2);
    }
    assert_eq!(
        field(&report, "startup"),
        "ready",
        "the production launcher must complete the isolation transaction: {report:?}"
    );
    assert_eq!(
        field(&report, "launcher_exit"),
        "exited:0",
        "the production launcher must reap a successful post-exec workload: {report:?}"
    );
    let rootfs_slash = field(&report, "rootfs_source_slash");
    assert!(
        rootfs_slash == "tested" || rootfs_slash.starts_with("unavailable:"),
        "rootfs source `/` must be tested or explicitly unavailable: {report:?}"
    );
    println!("privileged runtime isolation rootfs source slash: {rootfs_slash}");
    let child = report
        .iter()
        .find_map(|line| line.strip_prefix("child-report="))
        .expect("launcher report must carry the workload report")
        .split('|')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(field(&child, "pid"), "1");
    assert_eq!(
        field(&child, "argv"),
        "literal-shell-metacharacters-preserved"
    );
    assert_eq!(field(&child, "socket"), errno_name(libc::EPERM));
    assert_eq!(field(&child, "unshare"), errno_name(libc::EPERM));
    assert_escape_corpus_denied(&child);
    assert_eq!(field(&child, "workspace_write"), "0");
    assert_eq!(field(&child, "tmpfs_write"), errno_name(libc::EACCES));
    assert_eq!(field(&child, "rootfs_write"), errno_name(libc::EROFS));
    assert_eq!(field(&child, "dev_null"), errno_name(libc::ENOENT));
    assert_eq!(field(&child, "runtime_path"), errno_name(libc::ENOENT));
    assert_eq!(field(&child, "sys_path"), errno_name(libc::ENOENT));
    assert_eq!(field(&child, "capeff"), "0000000000000000");
    assert_eq!(field(&child, "capprm"), "0000000000000000");
    assert_eq!(field(&child, "capbnd"), "0000000000000000");
    assert_eq!(field(&child, "capamb"), "0000000000000000");
    assert_eq!(field(&child, "nonewprivs"), "1");
    assert_eq!(field(&child, "seccomp"), "2");
    assert_eq!(field(&child, "standard_fds"), "null");
    assert_eq!(
        field(&child, "fd_policy"),
        "exact",
        "post-exec descriptor policy report: {child:?}"
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
        let mut command = Command::new(probe);
        command
            .env(ROLE_ENV, self.role)
            .env(BASE_ENV, &self.base)
            .env(CGROUP_ENV, &self.cgroup_name)
            .env_remove(TEST_FAILURE_STEP_ENV);
        if self.role == ROLE_LIMITED_TMPFS_FAILURE {
            command.env(TEST_FAILURE_STEP_ENV, TEST_FAILURE_LIMITED_TMPFS);
        }
        let output = command
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

/// Host-side record for the launcher-backed post-exec scenario.
struct LauncherScenario {
    base: PathBuf,
    cgroup_name: String,
    output: Vec<String>,
}

impl LauncherScenario {
    fn start() -> Self {
        let base = env::temp_dir().join(format!(
            "runtime-isolation-launcher-probe-{}",
            std::process::id()
        ));
        let cgroup_name = format!("runtime-isolation-launcher-probe-{}", std::process::id());
        let mut scenario = Self {
            base,
            cgroup_name,
            output: Vec::new(),
        };
        scenario.execute();
        scenario
    }

    fn execute(&mut self) {
        let probe = env::current_exe().expect("locating this verification target");
        let output = Command::new(probe)
            .env(ROLE_ENV, ROLE_LAUNCHER_POST_EXEC)
            .env(BASE_ENV, &self.base)
            .env(CGROUP_ENV, &self.cgroup_name)
            .env_remove(TEST_FAILURE_STEP_ENV)
            .output()
            .expect("re-executing the launcher-backed probe");
        assert!(
            output.status.success(),
            "launcher-backed probe failed: status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        self.output = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
    }

    fn report(&self) -> Vec<String> {
        self.output.clone()
    }

    fn assert_cgroup_released(&self) {
        let cgroup = Path::new(CGROUP_ROOT).join(&self.cgroup_name);
        assert!(
            !cgroup.exists(),
            "the launcher must remove its constrained cgroup: {}",
            cgroup.display()
        );
    }
}

impl Drop for LauncherScenario {
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
            let child_pid = child.pid().get();
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
            if role == ROLE_LIMITED_TMPFS_FAILURE {
                let child_mount_namespace = Path::new("/proc")
                    .join(child_pid.to_string())
                    .join("ns/mnt");
                lines.push(format!(
                    "child_mount_namespace={}",
                    if child_mount_namespace.exists() {
                        "present"
                    } else {
                        "gone"
                    }
                ));
                lines.push(format!("host_mount_residue={}", host_mount_residue(&base)));
            }
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

/// Runs the production launcher as a child of a private mount namespace.
///
/// The staged rootfs and workspace live on private tmpfs mounts, so this test never writes a host
/// root path. When the host root is already immutable, the same scenario selects the production
/// `rootfs.source == "/"` branch and uses a private workspace under `/var/tmp`.
fn run_launcher_probe() {
    let base = PathBuf::from(env::var(BASE_ENV).expect("launcher probe staging directory"));
    let cgroup_name = env::var(CGROUP_ENV).expect("launcher probe cgroup name");
    match launch_post_exec_workload(&cgroup_name) {
        Ok(report) => {
            let encoded = report.lines().collect::<Vec<_>>().join("|");
            println!("startup=ready");
            println!(
                "rootfs_source_slash={}",
                if root_mount_is_read_only() {
                    "tested"
                } else {
                    "unavailable:host-root-mount-is-writable"
                }
            );
            println!("child-report={encoded}");
            println!("launcher_exit=exited:0");
        }
        Err(LauncherProbeFailure {
            unavailable: true,
            detail,
        }) => {
            println!("startup=unavailable");
            println!("reason={detail}");
        }
        Err(LauncherProbeFailure {
            unavailable: false,
            detail,
        }) => panic!("launcher post-exec probe failed: {detail}"),
    }

    // `base` is intentionally not used as a writable report directory. It is kept in the API so
    // the launcher scenario has the same stable re-exec shape as the direct kernel scenarios.
    let _ = base;
}

#[derive(Debug)]
struct LauncherProbeFailure {
    unavailable: bool,
    detail: String,
}

#[allow(clippy::too_many_lines)]
fn launch_post_exec_workload(cgroup_name: &str) -> Result<String, LauncherProbeFailure> {
    let workload = env::current_exe()
        .map_err(|error| regular_failure(format!("locating post-exec workload binary: {error}")))?;
    let root = prepare_launcher_root(&workload).map_err(unavailable_failure)?;
    let rootfs_source = &root.source;
    let prefix = &root.prefix;
    let workspace_source = &root.workspace_source;
    let workspace_target = &root.workspace_target;
    let control_path = prefix.join("control.sock");
    let control_listener = unix_seqpacket_listener(&control_path).map_err(unavailable_failure)?;
    let (broker_client, broker_peer) = local_vsock_pair().map_err(unavailable_failure)?;
    let launcher = launcher_binary().ok_or_else(|| {
        unavailable_failure("workload-isolation-launcher binary was not built".to_owned())
    })?;

    let mut command = Command::new(launcher);
    command
        .arg("--rootfs-source")
        .arg(rootfs_source)
        .arg("--rootfs-mount-target")
        .arg(prefix.join("rootfs"))
        .arg("--old-root")
        .arg(prefix.join("rootfs").join(".old-root"))
        .arg("--workspace-source")
        .arg(workspace_source)
        .arg("--workspace-target")
        .arg(workspace_target)
        .arg("--tmpfs-target")
        .arg("/tmp")
        .arg("--tmpfs-size-bytes")
        .arg("8388608")
        .arg("--cgroup-root")
        .arg(CGROUP_ROOT)
        .arg("--cgroup-name")
        .arg(cgroup_name)
        .arg("--memory-max-bytes")
        .arg("67108864")
        .arg("--pids-max")
        .arg("64")
        .arg("--host-uid")
        .arg("0")
        .arg("--host-gid")
        .arg("0")
        .arg("--control-socket")
        .arg(&control_path)
        .arg("--egress-broker-fd")
        .arg(broker_client.as_raw_fd().to_string())
        .arg("--egress-broker-session")
        .arg("00112233445566778899aabbccddeeff")
        .arg("--landlock-read-only")
        .arg("/")
        .arg("--landlock-writable")
        .arg(workspace_target)
        .arg("--env")
        .arg(format!("{POST_EXEC_ROLE_ENV}={POST_EXEC_ROLE_VALUE}"))
        .arg("--env")
        .arg(format!(
            "{WORKSPACE_TARGET_ENV}={}",
            workspace_target.display()
        ))
        .arg("--program")
        .arg(workload)
        .arg("--")
        .arg("--literal")
        .arg(";")
        .arg("$(touch /outside)")
        .arg("quoted value");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            regular_failure(format!("spawning workload-isolation-launcher: {error}"))
        })?;
    // Keep the endpoint and its peer alive until the launcher has reaped the workload. The
    // descriptor number itself is deliberately passed as an inherited, non-CLOEXEC fd.
    let _broker_peer = broker_peer;
    let mut start_input = child
        .stdout
        .take()
        .ok_or_else(|| regular_failure("launcher stdout pipe was unavailable".to_owned()))?;
    let mut start_output = child
        .stdin
        .take()
        .ok_or_else(|| regular_failure("launcher stdin pipe was unavailable".to_owned()))?;
    let mut ready = [0_u8; 5];
    start_input.read_exact(&mut ready).map_err(|error| {
        regular_failure(format!("reading launcher start-gate readiness: {error}"))
    })?;
    if ready != *b"ready" {
        return Err(regular_failure(format!(
            "launcher sent malformed start-gate readiness: {ready:?}"
        )));
    }
    start_output
        .write_all(&[1])
        .map_err(|error| regular_failure(format!("releasing launcher start gate: {error}")))?;
    start_output
        .flush()
        .map_err(|error| regular_failure(format!("flushing launcher start gate: {error}")))?;
    let control = accept_seqpacket(control_listener.as_raw_fd())
        .map_err(|error| regular_failure(format!("accepting launcher control channel: {error}")))?;
    let mut isolated = [0_u8; 8];
    start_input.read_exact(&mut isolated).map_err(|error| {
        launcher_child_failure(
            &mut child,
            format!("reading launcher isolated acknowledgement: {error}"),
        )
    })?;
    if isolated != *b"isolated" {
        return Err(regular_failure(format!(
            "launcher sent malformed isolated acknowledgement: {isolated:?}"
        )));
    }
    let report = receive_control_report(control.as_raw_fd()).map_err(|error| {
        regular_failure(format!("receiving post-exec workload report: {error}"))
    })?;
    let status = child.wait().map_err(|error| {
        regular_failure(format!("waiting for workload-isolation-launcher: {error}"))
    })?;
    if !status.success() {
        let stderr = child
            .stderr
            .take()
            .and_then(|mut stream| {
                let mut buffer = String::new();
                stream.read_to_string(&mut buffer).ok().map(|_| buffer)
            })
            .unwrap_or_default();
        return Err(regular_failure(format!(
            "launcher exited with {status}: {stderr}; report={report:?}"
        )));
    }
    Ok(report)
}

#[allow(clippy::needless_pass_by_value)]
fn launcher_child_failure(child: &mut std::process::Child, detail: String) -> LauncherProbeFailure {
    let status = child.wait().ok();
    let stderr = child
        .stderr
        .take()
        .and_then(|mut stream| {
            let mut buffer = String::new();
            stream.read_to_string(&mut buffer).ok().map(|_| buffer)
        })
        .unwrap_or_default();
    regular_failure(format!(
        "{detail}; launcher_status={status:?}; stderr={stderr}"
    ))
}

fn launcher_binary() -> Option<PathBuf> {
    if let Ok(path) = env::var("RUNTIME_ISOLATION_LAUNCHER") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let current = env::current_exe().ok()?;
    let path = current
        .parent()?
        .parent()?
        .join("workload-isolation-launcher");
    path.is_file().then_some(path)
}

fn regular_failure(detail: String) -> LauncherProbeFailure {
    LauncherProbeFailure {
        unavailable: false,
        detail,
    }
}

fn unavailable_failure(detail: String) -> LauncherProbeFailure {
    LauncherProbeFailure {
        unavailable: true,
        detail,
    }
}

/// Performs the hostile checks after the launcher has replaced the isolation child with `execve`.
fn run_post_exec_probe() {
    let control_fd = env::var(CONTROL_FD_ENV)
        .expect("post-exec workload must receive supervisor control fd")
        .parse::<i32>()
        .expect("supervisor control fd must be decimal");
    let broker_fd = env::var(BROKER_FD_ENV)
        .expect("post-exec workload must receive Broker fd")
        .parse::<i32>()
        .expect("Broker fd must be decimal");
    let workspace_target = env::var(WORKSPACE_TARGET_ENV)
        .expect("post-exec workload must receive its workspace target");
    let mut lines = vec![
        format!("pid={}", std::process::id()),
        format!("argv={}", post_exec_arguments_are_literal()),
        format!("control_fd={control_fd}"),
        format!("broker_fd={broker_fd}"),
        format!("inherited_fd={}", errno_name(errno_of_fstat(MARKER_FD))),
        format!("socket={}", errno_name(errno_of_denied_socket())),
        format!("unshare={}", errno_name(errno_of_denied_unshare())),
        format!(
            "dev_null={}",
            errno_name(errno_of_open("/dev/null", libc::O_RDONLY))
        ),
        format!(
            "runtime_path={}",
            errno_name(errno_of_open("/run/lock", libc::O_RDONLY))
        ),
        format!(
            "sys_path={}",
            errno_name(errno_of_open("/sys/kernel", libc::O_RDONLY))
        ),
        format!(
            "tmpfs_write={}",
            errno_name(errno_of_open(
                "/tmp/post-exec-escape",
                libc::O_CREAT | libc::O_WRONLY
            ))
        ),
        format!(
            "rootfs_write={}",
            errno_name(errno_of_open(
                "/etc/post-exec-escape",
                libc::O_CREAT | libc::O_WRONLY
            ))
        ),
        format!(
            "workspace_write={}",
            errno_name(errno_of_open(
                &format!("{workspace_target}/post-exec-write"),
                libc::O_CREAT | libc::O_WRONLY
            ))
        ),
    ];
    lines.extend(escape_corpus_report());
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for (field, label) in [
        ("CapEff:", "capeff"),
        ("CapPrm:", "capprm"),
        ("CapBnd:", "capbnd"),
        ("CapAmb:", "capamb"),
        ("NoNewPrivs:", "nonewprivs"),
        ("Seccomp:", "seccomp"),
    ] {
        lines.push(format!("{label}={}", status_field(&status, field)));
    }
    lines.push(format!("standard_fds={}", standard_descriptors_are_null()));
    lines.push(format!(
        "fd_policy={}",
        exact_inherited_fd_policy(control_fd, broker_fd)
    ));
    let report = lines.join("\n");
    let mut control = unsafe { std::fs::File::from_raw_fd(control_fd) };
    control
        .write_all(report.as_bytes())
        .expect("the post-exec workload must report through the inherited control channel");
    control
        .flush()
        .expect("the post-exec workload must flush its control report");
}

fn post_exec_arguments_are_literal() -> &'static str {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let expected = ["--literal", ";", "$(touch /outside)", "quoted value"];
    if arguments
        .iter()
        .map(OsString::as_os_str)
        .eq(expected.iter().map(OsStr::new))
    {
        "literal-shell-metacharacters-preserved"
    } else {
        "argv-mismatch"
    }
}

fn standard_descriptors_are_null() -> &'static str {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    for descriptor in 0..=2 {
        // SAFETY: `metadata` is writable and the descriptor is one of the three standard slots.
        if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
            return "missing";
        }
        // SAFETY: `fstat` initialized the complete structure on success.
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
            || libc::major(metadata.st_rdev) != 1
            || libc::minor(metadata.st_rdev) != 3
        {
            return "unexpected";
        }
    }
    "null"
}

fn exact_inherited_fd_policy(control_fd: i32, broker_fd: i32) -> String {
    if control_fd < 3 || broker_fd < 3 || control_fd == broker_fd {
        return "unexpected-channel-identity".to_owned();
    }

    // Collect names while the directory enumeration handle is open, then drop that iterator
    // before checking liveness. This removes the transient enumeration fd without assuming a
    // descriptor-number ceiling or relying on readlinkat (which is deliberately constrained by
    // the workload policy).
    let descriptors = {
        let entries = match fs::read_dir("/proc/self/fd") {
            Ok(entries) => entries,
            Err(error) => return format!("fd-enumeration-error-{error}"),
        };
        match entries
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|name| name.to_string_lossy().parse::<i32>().ok())
                .filter(|descriptor| *descriptor >= 3)
                .collect::<Vec<_>>(),
            Err(error) => return format!("fd-enumeration-error-{error}"),
        }
    };
    let observed = descriptors
        .into_iter()
        .filter(|descriptor| errno_of_fstat(*descriptor) == 0)
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([control_fd, broker_fd]);
    if observed == expected {
        "exact".to_owned()
    } else {
        format!("unexpected-fds-{observed:?}-expected-{expected:?}")
    }
}

struct LauncherRoot {
    source: PathBuf,
    prefix: PathBuf,
    workspace_source: PathBuf,
    workspace_target: PathBuf,
}

fn prepare_launcher_root(workload: &Path) -> Result<LauncherRoot, String> {
    // SAFETY: the flag is scalar and the namespace exists only in this re-execed probe process.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "unsharing the probe mount namespace: {}",
            Error::last_os_error()
        ));
    }
    mount_private_for_probe(Path::new("/"))?;
    if root_mount_is_read_only() {
        let prefix = PathBuf::from(format!(
            "/dev/shm/runtime-isolation-launcher-{}",
            std::process::id()
        ));
        let workspace_source = prefix.join("source");
        fs::create_dir_all(&workspace_source)
            .map_err(|error| format!("creating slash-branch workspace source: {error}"))?;
        return Ok(LauncherRoot {
            source: PathBuf::from("/"),
            prefix,
            workspace_source,
            workspace_target: PathBuf::from("/var/tmp"),
        });
    }
    // `/opt` is an existing directory, so mounting a private tmpfs there avoids creating any
    // files on the host root while staging the launcher rootfs.
    mount_tmpfs_for_probe(Path::new("/opt"))?;
    let prefix = PathBuf::from(format!(
        "/opt/runtime-isolation-launcher-{}",
        std::process::id()
    ));
    let rootfs = prefix.join("rootfs");
    let rootfs_mount = prefix.join("mount");
    fs::create_dir_all(&rootfs)
        .map_err(|error| format!("creating private launcher rootfs target: {error}"))?;
    fs::create_dir_all(&rootfs_mount)
        .map_err(|error| format!("creating private launcher mount target: {error}"))?;
    mount_tmpfs_for_probe(&rootfs)?;
    stage_dynamic_workload(&rootfs, workload)?;
    for directory in [
        rootfs.join("workspace"),
        rootfs.join("tmp"),
        rootfs.join("proc"),
        rootfs.join("dev"),
        rootfs.join("etc"),
        rootfs.join(".old-root"),
    ] {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("creating private launcher rootfs directory: {error}"))?;
    }
    fs::create_dir_all(rootfs.join("opt/probe"))
        .map_err(|error| format!("creating private launcher target parent: {error}"))?;
    fs::create_dir_all(rootfs.join("opt/probe/target"))
        .map_err(|error| format!("creating private launcher target: {error}"))?;
    let workspace_source = prefix.join("workspace-source");
    fs::create_dir_all(&workspace_source)
        .map_err(|error| format!("creating private launcher workspace source: {error}"))?;
    mount_tmpfs_for_probe(&workspace_source)?;
    remount_bind_readonly_for_probe(&rootfs)?;
    Ok(LauncherRoot {
        source: rootfs,
        prefix,
        workspace_source,
        workspace_target: PathBuf::from("/opt/probe/target"),
    })
}

fn root_mount_is_read_only() -> bool {
    let path = c_path(Path::new("/"));
    let mut details = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `details` is writable for the syscall output.
    if unsafe { libc::statvfs(path.as_ptr(), details.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: `statvfs` initialized the complete structure on success.
    unsafe { details.assume_init() }.f_flag & libc::ST_RDONLY != 0
}

fn stage_dynamic_workload(rootfs: &Path, workload: &Path) -> Result<(), String> {
    let output = Command::new("ldd")
        .arg(workload)
        .output()
        .map_err(|error| format!("inspecting post-exec workload dependencies with ldd: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "ldd could not inspect post-exec workload: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut dependencies = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let candidate = line
            .split_once("=>")
            .map(|(_, value)| value.split_whitespace().next().unwrap_or_default())
            .filter(|value| value.starts_with('/'))
            .or_else(|| {
                line.split_whitespace()
                    .next()
                    .filter(|value| value.starts_with('/'))
            });
        if let Some(path) = candidate {
            dependencies.push(PathBuf::from(path));
        }
    }
    dependencies.push(workload.to_owned());
    for source in dependencies {
        let relative = source
            .strip_prefix("/")
            .map_err(|_| format!("dependency path was not absolute: {}", source.display()))?;
        let target = rootfs.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "creating staged dependency directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::copy(&source, &target).map_err(|error| {
            format!(
                "copying post-exec dependency {} into {}: {error}",
                source.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

fn mount_private_for_probe(target: &Path) -> Result<(), String> {
    let target = c_path(target);
    // SAFETY: the target pointer is valid for the call and no source/data are used.
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "making probe mounts private: {}",
            Error::last_os_error()
        ))
    }
}

fn mount_tmpfs_for_probe(target: &Path) -> Result<(), String> {
    let target = c_path(target);
    let filesystem = c"tmpfs";
    let data = c"size=16m";
    // SAFETY: all pointers remain valid for the duration of the mount syscall.
    let result = unsafe {
        libc::mount(
            filesystem.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            data.as_ptr().cast(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "mounting private tmpfs at {}: {}",
            target.to_string_lossy(),
            Error::last_os_error()
        ))
    }
}

fn remount_bind_readonly_for_probe(target: &Path) -> Result<(), String> {
    let target = c_path(target);
    // SAFETY: the bind mount is now private and the same target remains valid.
    let remount = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if remount == 0 {
        Ok(())
    } else {
        Err(format!(
            "remounting probe root read-only: {}",
            Error::last_os_error()
        ))
    }
}

fn unix_seqpacket_listener(path: &Path) -> Result<OwnedFd, String> {
    let descriptor = socket_owned(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC)?;
    let address = unix_address(path)?;
    // SAFETY: the address points to a complete sockaddr_un for the duration of the call.
    let result = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            unix_address_length(&address),
        )
    };
    if result != 0 {
        return Err(format!(
            "binding launcher control socket {}: {}",
            path.display(),
            Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor is a valid listening socket.
    if unsafe { libc::listen(descriptor.as_raw_fd(), 1) } != 0 {
        return Err(format!(
            "listening on launcher control socket: {}",
            Error::last_os_error()
        ));
    }
    Ok(descriptor)
}

fn accept_seqpacket(listener: i32) -> Result<OwnedFd, String> {
    // SAFETY: null address storage is accepted when the peer address is not needed.
    let descriptor = unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(format!(
            "accepting launcher control socket: {}",
            Error::last_os_error()
        ))
    } else {
        // SAFETY: `accept4` returned a unique owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn receive_control_report(descriptor: i32) -> Result<String, String> {
    let mut buffer = [0_u8; 16 * 1024];
    // SAFETY: the buffer is writable for its complete length and the descriptor is connected.
    let received = unsafe { libc::recv(descriptor, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if received < 0 {
        return Err(Error::last_os_error().to_string());
    }
    let received = usize::try_from(received).map_err(|_| "negative report length".to_owned())?;
    String::from_utf8(buffer[..received].to_vec())
        .map_err(|error| format!("post-exec report was not UTF-8: {error}"))
}

fn local_vsock_pair() -> Result<(OwnedFd, OwnedFd), String> {
    let listener = socket_owned(libc::AF_VSOCK, libc::SOCK_STREAM)?;
    let mut address = libc::sockaddr_vm {
        svm_family: libc::sa_family_t::try_from(libc::AF_VSOCK).expect("AF_VSOCK fits sa_family_t"),
        svm_reserved1: 0,
        svm_port: 0,
        svm_cid: VMADDR_CID_LOCAL,
        svm_zero: [0; 4],
    };
    // SAFETY: `address` is a complete sockaddr_vm and the listener is valid.
    if unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&raw mut address).cast::<libc::sockaddr>(),
            sockaddr_vm_length(),
        )
    } != 0
    {
        return Err(format!(
            "binding local AF_VSOCK listener: {}",
            Error::last_os_error()
        ));
    }
    let mut length = sockaddr_vm_length();
    // SAFETY: the output address and length are writable and correctly sized.
    if unsafe {
        libc::getsockname(
            listener.as_raw_fd(),
            (&raw mut address).cast::<libc::sockaddr>(),
            &raw mut length,
        )
    } != 0
    {
        return Err(format!(
            "reading local AF_VSOCK port: {}",
            Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor is a valid listening socket.
    if unsafe { libc::listen(listener.as_raw_fd(), 1) } != 0 {
        return Err(format!(
            "listening on local AF_VSOCK: {}",
            Error::last_os_error()
        ));
    }
    let client = socket_owned(libc::AF_VSOCK, libc::SOCK_STREAM)?;
    // SAFETY: `address` contains the listener's assigned local CID and port.
    if unsafe {
        libc::connect(
            client.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            sockaddr_vm_length(),
        )
    } != 0
    {
        return Err(format!(
            "connecting local AF_VSOCK pair: {}",
            Error::last_os_error()
        ));
    }
    // SAFETY: null peer address storage is accepted when no peer metadata is needed.
    let peer = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if peer < 0 {
        return Err(format!(
            "accepting local AF_VSOCK pair: {}",
            Error::last_os_error()
        ));
    }
    // SAFETY: `accept4` returned a unique owned descriptor.
    Ok((client, unsafe { OwnedFd::from_raw_fd(peer) }))
}

fn socket_owned(domain: libc::c_int, socket_type: libc::c_int) -> Result<OwnedFd, String> {
    // SAFETY: domain and type are scalar constants and no pointer is passed.
    let descriptor = unsafe { libc::socket(domain, socket_type, 0) };
    if descriptor < 0 {
        Err(format!(
            "creating socket family {domain}: {}",
            Error::last_os_error()
        ))
    } else {
        // SAFETY: `socket` returned a unique owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn sockaddr_vm_length() -> libc::socklen_t {
    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_vm>())
        .expect("sockaddr_vm size fits socklen_t")
}

fn unix_address(path: &Path) -> Result<libc::sockaddr_un, String> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
        return Err(format!(
            "control socket path is too long: {}",
            path.display()
        ));
    }
    // SAFETY: zero is a valid initial value for sockaddr_un's padding and path bytes.
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family =
        libc::sa_family_t::try_from(libc::AF_UNIX).expect("AF_UNIX fits sa_family_t");
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *slot = byte.cast_signed();
    }
    Ok(address)
}

fn unix_address_length(address: &libc::sockaddr_un) -> libc::socklen_t {
    let offset = std::mem::size_of_val(&address.sun_family);
    libc::socklen_t::try_from(
        offset
            + address
                .sun_path
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(address.sun_path.len())
            + 1,
    )
    .expect("Unix socket address length fits socklen_t")
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

/// Reports mounts under the probe's host-side staging tree, excluding its expected rootfs bind.
///
/// The isolation child makes its mount namespace private before any staged mount is created. A
/// mount appearing here would therefore prove that a rollback or propagation boundary leaked
/// into the launcher's namespace rather than merely showing that the child had a mount briefly.
fn host_mount_residue(base: &Path) -> String {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .expect("reading the launcher's mount table after rollback");
    let expected_rootfs = base.join("rootfs").to_string_lossy().into_owned();
    let base = format!("{}/", base.to_string_lossy());
    let residue = mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .filter(|mountpoint| mountpoint.starts_with(base.as_str()))
        .filter(|mountpoint| *mountpoint != expected_rootfs)
        .collect::<Vec<_>>();
    if residue.is_empty() {
        "none".to_owned()
    } else {
        residue.join(",")
    }
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
    lines.extend(escape_corpus_report());
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

fn escape_corpus_report() -> Vec<String> {
    [
        ("bpf", libc::SYS_bpf),
        ("clone3", libc::SYS_clone3),
        ("io_uring_setup", libc::SYS_io_uring_setup),
        ("open_tree", libc::SYS_open_tree),
        ("pidfd_open", libc::SYS_pidfd_open),
        ("userfaultfd", libc::SYS_userfaultfd),
    ]
    .into_iter()
    .map(|(label, number)| {
        format!(
            "escape_{label}={}",
            errno_name(errno_of_denied_raw_syscall(number))
        )
    })
    .collect()
}

fn errno_of_denied_raw_syscall(number: libc::c_long) -> i32 {
    // Every corpus entry receives deliberately invalid scalar/pointer arguments,
    // so none can commit an effect if the seccomp rule regresses. A surprising
    // nonnegative descriptor is closed before the failed assertion is reported.
    // SAFETY: syscall accepts scalar varargs; the null pointer is never
    // dereferenced in userspace and the kernel validates it.
    let result = unsafe {
        libc::syscall(
            number,
            libc::c_ulong::MAX,
            std::ptr::null::<libc::c_void>(),
            libc::c_ulong::MAX,
            libc::c_ulong::MAX,
            libc::c_ulong::MAX,
            libc::c_ulong::MAX,
        )
    };
    if result >= 0 {
        if let Ok(descriptor) = libc::c_int::try_from(result) {
            // SAFETY: an fd-producing syscall returned this descriptor. EBADF
            // from a non-fd result is harmless in the already-failing branch.
            unsafe { libc::close(descriptor) };
        }
        return 0;
    }
    last_errno()
}

fn assert_escape_corpus_denied(report: &[String]) {
    for label in [
        "escape_bpf",
        "escape_clone3",
        "escape_io_uring_setup",
        "escape_open_tree",
        "escape_pidfd_open",
        "escape_userfaultfd",
    ] {
        assert_eq!(
            field(report, label),
            errno_name(libc::EPERM),
            "the hostile syscall corpus must be denied at {label}: {report:?}"
        );
    }
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
