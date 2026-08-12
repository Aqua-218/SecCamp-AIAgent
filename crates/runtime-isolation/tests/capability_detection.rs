#![allow(missing_docs)]

use runtime_isolation::{
    BindMountConfig, CapabilityReport, CgroupConfig, IdentityMap, IsolationBackend,
    IsolationConfig, LandlockConfig, LinuxBackend, RootfsConfig, SeccompPolicy, TmpfsConfig,
};

fn detection_config() -> IsolationConfig {
    IsolationConfig::new(
        RootfsConfig::new(
            "/var/lib/luna/rootfs",
            "/mnt/luna-rootfs",
            "/mnt/luna-rootfs/.old_root",
        ),
        BindMountConfig::new("/run/luna/capfs", "/workspace"),
        TmpfsConfig::new("/tmp", 8 * 1024 * 1024),
        CgroupConfig::new(
            "/sys/fs/cgroup",
            "luna-capability-detection",
            64 * 1024 * 1024,
            64,
        ),
        LandlockConfig::new(3, ["/"], ["/workspace"]),
        SeccompPolicy::default(),
        IdentityMap::new(0, 0),
    )
}

#[test]
fn privileged_integration_prerequisites_are_reported_without_an_ignored_test() {
    let mut backend = LinuxBackend::new();
    let config = detection_config();
    let report = backend.detect_capabilities(&config);

    if report.is_sufficient(&config) {
        assert!(report.namespaces_available);
        assert!(report.cgroup_v2_available);
        assert!(report.seccomp_available);
        assert!(report.landlock_abi.is_some_and(|abi| abi >= 3));
    } else {
        eprintln!(
            "runtime isolation integration unavailable: {}",
            report_summary(&report)
        );
        assert!(
            !report.reasons.is_empty(),
            "an insufficient capability report must explain the missing prerequisite"
        );
    }
}

fn report_summary(report: &CapabilityReport) -> String {
    report.reasons.join("; ")
}
