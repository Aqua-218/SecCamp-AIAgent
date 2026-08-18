//! Concrete host egress adapters for a production session.
//!
//! The guest never receives DNS, TLS, or credential configuration. This module creates the
//! bounded public HTTPS adapter and, only when explicitly configured, the GitHub adapter that
//! reads its token inside the host process.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

use authority_core::{
    github::GitHubAuthority,
    github::{BranchName, GitHubOperation, GitHubRequest, InstallationId, github_matches},
    repository::RepoId,
    time::MonotonicTime,
};
use egress_broker::{
    github::{
        CredentialHandle, EnvironmentCredentialProvider, GitHubAdapter, GitHubAdapterError,
        GitObjectId, PublishBranchPlan, RustlsGitHubProvider, StaticPublishPlanProvider,
        TypedGitHubAdapter,
    },
    ip_policy::IpPolicy,
    public_fetch::{FetchPolicy, PublicFetcher, RustlsHttpsConnector, SystemResolver},
};
use egress_protocol::session::BrokerRequestId;

use crate::{
    BackendError,
    production_runtime::{PerSessionEgressFactory, PreparedEgressSession, SessionEgressRequest},
};

const PUBLISH_PLAN_MAGIC: &str = "host-publish-plan-v1";
const MAX_PUBLISH_PLAN_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_PUBLISH_PLAN_LINE_BYTES: usize = 1024;
const MAX_PUBLISH_PLANS: usize = 4096;

/// One host-owned, request-bound expected-old/new object transition.
///
/// The request ID is caller-selected by the Broker client and is therefore only an idempotency
/// key. The complete typed request is retained alongside it so an ID collision cannot select a
/// plan for another installation, repository, or branch pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPublishPlanConfig {
    request_id: BrokerRequestId,
    request: GitHubRequest,
    plan: PublishBranchPlan,
}

impl HostPublishPlanConfig {
    /// Creates one validated host plan. Only `PublishBranch` may carry an object transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the typed request is not a `PublishBranch` request.
    pub fn new(
        request_id: BrokerRequestId,
        request: GitHubRequest,
        plan: PublishBranchPlan,
    ) -> Result<Self, PublishPlanConfigError> {
        if request.operation() != GitHubOperation::PublishBranch {
            return Err(PublishPlanConfigError::new(
                "publish plan request operation must be publish-branch",
            ));
        }
        Ok(Self {
            request_id,
            request,
            plan,
        })
    }

    /// Returns the caller-selected idempotency identity.
    #[must_use]
    pub const fn request_id(&self) -> BrokerRequestId {
        self.request_id
    }

    /// Returns the complete typed GitHub request bound to this plan.
    #[must_use]
    pub const fn request(&self) -> &GitHubRequest {
        &self.request
    }

    /// Returns the expected-old/new object transition.
    #[must_use]
    pub const fn plan(&self) -> &PublishBranchPlan {
        &self.plan
    }

    /// Returns whether this plan's complete request is selected by an authority.
    #[must_use]
    pub fn matches_authority(&self, authority: &GitHubAuthority) -> bool {
        github_matches(authority, &self.request)
    }

    fn static_entry(&self) -> (BrokerRequestId, GitHubRequest, PublishBranchPlan) {
        (self.request_id, self.request.clone(), self.plan.clone())
    }
}

/// A malformed or semantically invalid host publish-plan configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishPlanConfigError {
    message: &'static str,
}

impl PublishPlanConfigError {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for PublishPlanConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for PublishPlanConfigError {}

/// Loads a strict owner-readable publish-plan manifest.
///
/// Each non-empty line is exactly:
/// `host-publish-plan-v1<TAB>request-id-hex<TAB>installation<TAB>repository<TAB>publish-branch<TAB>base<TAB>head<TAB>new-object<TAB>expected-old-object`.
/// The file contains no comments or alternate spellings. The final newline is optional.
///
/// # Errors
///
/// Returns a bounded validation error for unsafe file metadata, malformed fields, duplicate
/// request IDs, or a plan that is not a publish-branch transition.
#[allow(clippy::too_many_lines)]
pub fn load_publish_plan_manifest(
    path: impl AsRef<Path>,
) -> Result<Vec<HostPublishPlanConfig>, String> {
    let path = path.as_ref();
    let mut file = open_publish_plan_manifest(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect opened publish-plan manifest: {error}"))?;
    if metadata.len() > MAX_PUBLISH_PLAN_MANIFEST_BYTES as u64 {
        return Err(format!(
            "publish-plan manifest exceeds {MAX_PUBLISH_PLAN_MANIFEST_BYTES} bytes"
        ));
    }
    let expected_len = metadata.len();
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_len)
            .map_err(|_| "publish-plan manifest length does not fit this platform".to_owned())?,
    );
    file.by_ref()
        .take((MAX_PUBLISH_PLAN_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read publish-plan manifest: {error}"))?;
    if bytes.len() as u64 != expected_len {
        return Err("publish-plan manifest changed while it was being read".to_owned());
    }
    if bytes.len() > MAX_PUBLISH_PLAN_MANIFEST_BYTES {
        return Err(format!(
            "publish-plan manifest exceeds {MAX_PUBLISH_PLAN_MANIFEST_BYTES} bytes"
        ));
    }
    validate_open_manifest_unchanged(path, &file, &metadata)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "publish-plan manifest must be UTF-8".to_owned())?;
    if text.is_empty() {
        return Err("publish-plan manifest must contain at least one plan".to_owned());
    }
    let mut plans = Vec::new();
    let mut request_ids = BTreeSet::new();
    let lines = text.split('\n').collect::<Vec<_>>();
    for (line_number, line) in lines.iter().copied().enumerate() {
        if line.contains('\r') {
            return Err(format!(
                "publish-plan manifest line {} must use LF newlines",
                line_number + 1
            ));
        }
        if line.is_empty() {
            if line_number + 1 == lines.len() && text.ends_with('\n') {
                continue;
            }
            return Err(format!(
                "publish-plan manifest line {} is empty",
                line_number + 1
            ));
        }
        if line.len() > MAX_PUBLISH_PLAN_LINE_BYTES {
            return Err(format!(
                "publish-plan manifest line {} exceeds {MAX_PUBLISH_PLAN_LINE_BYTES} bytes",
                line_number + 1
            ));
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 9 || fields.iter().any(|field| field.is_empty()) {
            return Err(format!(
                "publish-plan manifest line {} must contain exactly nine non-empty tab fields",
                line_number + 1
            ));
        }
        if fields[0] != PUBLISH_PLAN_MAGIC || fields[4] != "publish-branch" {
            return Err(format!(
                "publish-plan manifest line {} has an unsupported format or operation",
                line_number + 1
            ));
        }
        let request_id = parse_request_id(fields[1])
            .map_err(|error| format!("publish-plan manifest line {}: {error}", line_number + 1))?;
        if !request_ids.insert(request_id) {
            return Err(format!(
                "publish-plan manifest line {} duplicates a request ID",
                line_number + 1
            ));
        }
        validate_manifest_identifier("installation", fields[2])?;
        validate_manifest_identifier("repository", fields[3])?;
        let base = BranchName::new(fields[5]).map_err(|error| {
            format!(
                "publish-plan manifest line {} has invalid base branch: {error}",
                line_number + 1
            )
        })?;
        let head = BranchName::new(fields[6]).map_err(|error| {
            format!(
                "publish-plan manifest line {} has invalid head branch: {error}",
                line_number + 1
            )
        })?;
        let new_object = parse_object_id(fields[7])
            .map_err(|error| format!("publish-plan manifest line {}: {error}", line_number + 1))?;
        let expected_old_object = parse_object_id(fields[8])
            .map_err(|error| format!("publish-plan manifest line {}: {error}", line_number + 1))?;
        let request = GitHubRequest::new(
            InstallationId::new(fields[2]),
            RepoId::new(fields[3]),
            GitHubOperation::PublishBranch,
            base,
            head,
        );
        let plan = HostPublishPlanConfig::new(
            request_id,
            request,
            PublishBranchPlan::new(new_object, expected_old_object),
        )
        .map_err(|error| error.to_string())?;
        plans.push(plan);
        if plans.len() > MAX_PUBLISH_PLANS {
            return Err(format!(
                "publish-plan manifest exceeds {MAX_PUBLISH_PLANS} plans"
            ));
        }
    }
    if plans.is_empty() {
        return Err("publish-plan manifest must contain at least one plan".to_owned());
    }
    Ok(plans)
}

/// Validates that every configured plan is usable by one selected GitHub authority.
///
/// Plans are deliberately fail-closed: a host cannot silently ignore a plan bound to a
/// different repository, installation, or branch pattern. This also keeps a duplicate request
/// ID from being reduced to a last-write-wins entry when it is converted to the static provider.
///
/// # Errors
///
/// Returns an error when plans are missing, duplicated, or outside the selected authority.
pub fn validate_publish_plans_for_authority(
    authority: &GitHubAuthority,
    plans: Vec<HostPublishPlanConfig>,
) -> Result<Vec<HostPublishPlanConfig>, String> {
    if !authority
        .operations()
        .contains(GitHubOperation::PublishBranch)
    {
        return Err("publish plans require a PublishBranch GitHub authority".to_owned());
    }
    if plans.is_empty() {
        return Err("PublishBranch authority requires at least one publish plan".to_owned());
    }
    let mut request_ids = BTreeSet::new();
    for plan in &plans {
        if !request_ids.insert(plan.request_id()) {
            return Err("publish plans contain duplicate request IDs".to_owned());
        }
        if !plan.matches_authority(authority) {
            return Err(
                "publish plan request does not match the selected GitHub authority".to_owned(),
            );
        }
    }
    Ok(plans)
}

#[cfg(unix)]
fn open_publish_plan_manifest(path: &Path) -> Result<File, String> {
    let descriptor = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| format!("securely open publish-plan manifest: {error}"))?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect opened publish-plan manifest: {error}"))?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != uid {
        return Err(
            "publish-plan manifest must be a singly-linked regular file owned by the daemon user"
                .to_owned(),
        );
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(
            "publish-plan manifest must not be group/world-readable or writable".to_owned(),
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| "publish-plan manifest has no parent directory".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect publish-plan parent: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("publish-plan parent must be an owner-only directory".to_owned());
    }
    validate_open_manifest_unchanged(path, &file, &metadata)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_publish_plan_manifest(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect publish-plan manifest: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("publish-plan manifest must be a regular non-symlink file".to_owned());
    }
    File::open(path).map_err(|error| format!("open publish-plan manifest: {error}"))
}

#[cfg(unix)]
fn validate_open_manifest_unchanged(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|error| format!("reinspect opened publish-plan manifest: {error}"))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect publish-plan manifest path: {error}"))?;
    if path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || opened.nlink() != 1
        || opened.dev() != expected.dev()
        || opened.ino() != expected.ino()
        || opened.len() != expected.len()
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
    {
        return Err("publish-plan manifest changed while it was being read".to_owned());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_open_manifest_unchanged(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|error| format!("reinspect opened publish-plan manifest: {error}"))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("reinspect publish-plan manifest path: {error}"))?;
    if path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || opened.len() != expected.len()
        || path_metadata.len() != opened.len()
    {
        return Err("publish-plan manifest changed while it was being read".to_owned());
    }
    Ok(())
}

fn validate_manifest_identifier(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "publish-plan {label} must be a 1-128 byte canonical identifier"
        ));
    }
    Ok(())
}

fn parse_request_id(value: &str) -> Result<BrokerRequestId, String> {
    if value.len() != 32 || !value.bytes().all(is_lower_hex) {
        return Err("request ID must be exactly 32 lowercase hexadecimal characters".to_owned());
    }
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = (decode_hex(value.as_bytes()[index * 2])? << 4)
            | decode_hex(value.as_bytes()[index * 2 + 1])?;
    }
    Ok(BrokerRequestId::new(bytes))
}

fn parse_object_id(value: &str) -> Result<GitObjectId, String> {
    if !value.bytes().all(is_lower_hex) {
        return Err("Git object IDs must use lowercase hexadecimal characters".to_owned());
    }
    GitObjectId::new(value).map_err(|error| error.to_string())
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn decode_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex value contains a non-hexadecimal byte".to_owned()),
    }
}

/// GitHub credential configuration retained exclusively by the host egress factory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GitHubEgressConfig {
    /// Rejects every GitHub request without reading any credential environment variable.
    #[default]
    Disabled,
    /// Binds the host's `EGRESS_GITHUB_TOKEN` to one exact GitHub installation.
    Environment {
        /// Installation whose requests may use the host-only token.
        installation: InstallationId,
        /// Opaque host bookkeeping identity; this is never a credential value.
        credential_handle: CredentialHandle,
        /// Host-owned, request-bound expected-old/new transitions for `PublishBranch`.
        publish_plans: Vec<HostPublishPlanConfig>,
    },
}

impl GitHubEgressConfig {
    /// Configures the environment-backed host token for exactly one installation.
    #[must_use]
    pub const fn environment(
        installation: InstallationId,
        credential_handle: CredentialHandle,
    ) -> Self {
        Self::environment_with_plans(installation, credential_handle, Vec::new())
    }

    /// Configures an environment-backed host token and request-bound publish plans.
    #[must_use]
    pub const fn environment_with_plans(
        installation: InstallationId,
        credential_handle: CredentialHandle,
        publish_plans: Vec<HostPublishPlanConfig>,
    ) -> Self {
        Self::Environment {
            installation,
            credential_handle,
            publish_plans,
        }
    }
}

/// Standard concrete egress factory for a host daemon.
///
/// Public HTTPS always uses the strict built-in SSRF deny policy, a rustls connector, no proxy,
/// and the broker's bounded fetch policy. GitHub remains disabled until an operator identifies an
/// installation and intentionally supplies `EGRESS_GITHUB_TOKEN` to the daemon process.
#[derive(Debug, Clone, Default)]
pub struct SystemEgressFactory {
    github: GitHubEgressConfig,
}

impl SystemEgressFactory {
    /// Creates a factory with explicit GitHub credential policy.
    #[must_use]
    pub const fn new(github: GitHubEgressConfig) -> Self {
        Self { github }
    }

    /// Creates a public-HTTPS-only factory with GitHub disabled.
    #[must_use]
    pub const fn public_https_only() -> Self {
        Self::new(GitHubEgressConfig::Disabled)
    }
}

impl PerSessionEgressFactory for SystemEgressFactory {
    fn prepare(
        &self,
        request: &SessionEgressRequest,
    ) -> Result<PreparedEgressSession, BackendError> {
        let public = PublicFetcher::new(
            SystemResolver,
            RustlsHttpsConnector::default(),
            IpPolicy::default(),
            FetchPolicy::default(),
        );
        let clock_origin = Instant::now();
        match &self.github {
            GitHubEgressConfig::Disabled => Ok(PreparedEgressSession::new(
                request,
                public,
                DisabledGitHubAdapter,
                move || elapsed_ticks(clock_origin),
            )),
            GitHubEgressConfig::Environment {
                installation,
                credential_handle,
                publish_plans,
            } => {
                let provider = RustlsGitHubProvider::from_environment().map_err(|_| {
                    BackendError::new(
                        "environment-backed GitHub egress requires a valid EGRESS_GITHUB_TOKEN",
                    )
                })?;
                let github = TypedGitHubAdapter::new(
                    provider,
                    EnvironmentCredentialProvider::new(installation.clone(), *credential_handle),
                    StaticPublishPlanProvider::new(
                        publish_plans
                            .iter()
                            .map(HostPublishPlanConfig::static_entry),
                    ),
                );
                Ok(PreparedEgressSession::new(
                    request,
                    public,
                    github,
                    move || elapsed_ticks(clock_origin),
                ))
            }
        }
    }
}

fn elapsed_ticks(origin: Instant) -> MonotonicTime {
    MonotonicTime::from_ticks(u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX))
}

struct DisabledGitHubAdapter;

impl GitHubAdapter for DisabledGitHubAdapter {
    fn execute(
        &mut self,
        _request_id: BrokerRequestId,
        _request: &authority_core::github::GitHubRequest,
        _authority: &authority_core::github::GitHubAuthority,
        _max_response_bytes: u64,
    ) -> Result<egress_broker::github::GitHubResponse, GitHubAdapterError> {
        Err(GitHubAdapterError::NotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use authority_core::{
        github::{
            BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
            GitHubRequest, InstallationId,
        },
        repository::RepoId,
    };
    use egress_broker::github::{GitObjectId, PublishBranchPlan};

    use crate::{
        BrokerSessionId, CapabilityId, ID_BYTES, RequestId, SessionId, SubjectId, VmId,
        WorkspaceId,
        production_runtime::{PerSessionEgressFactory, SessionEgressRequest},
    };

    use super::{
        HostPublishPlanConfig, MAX_PUBLISH_PLAN_LINE_BYTES, SystemEgressFactory,
        load_publish_plan_manifest, validate_publish_plans_for_authority,
    };

    struct TestManifest {
        directory: PathBuf,
        path: PathBuf,
    }

    impl Drop for TestManifest {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn manifest(contents: &str, mode: u32) -> TestManifest {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "host-sessiond-publish-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("create private test directory");
        let path = directory.join("plans.tsv");
        fs::write(&path, contents).expect("write test manifest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("protect test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("set test manifest mode");
        }
        TestManifest { directory, path }
    }

    fn valid_line(request_id: &str) -> String {
        format!(
            "host-publish-plan-v1\t{request_id}\tinstallation-a\tworkspace\tpublish-branch\tmain\tagent/work\t{}\t{}\n",
            "a".repeat(40),
            "b".repeat(40),
        )
    }

    fn authority() -> GitHubAuthority {
        GitHubAuthority::new(
            InstallationId::new("installation-a"),
            RepoId::new("workspace"),
            GitHubOperations::only(GitHubOperation::PublishBranch),
            BranchPattern::Exact(BranchName::new("main").expect("base branch")),
            BranchPattern::Prefix(BranchName::new("agent").expect("head branch")),
        )
    }

    fn plan(request_id: u8, installation: &str) -> HostPublishPlanConfig {
        let request = GitHubRequest::new(
            InstallationId::new(installation),
            RepoId::new("workspace"),
            GitHubOperation::PublishBranch,
            BranchName::new("main").expect("base branch"),
            BranchName::new("agent/work").expect("head branch"),
        );
        HostPublishPlanConfig::new(
            egress_protocol::session::BrokerRequestId::new([request_id; 16]),
            request,
            PublishBranchPlan::new(
                GitObjectId::new("a".repeat(40)).expect("new object"),
                GitObjectId::new("b".repeat(40)).expect("old object"),
            ),
        )
        .expect("publish plan")
    }

    #[test]
    fn public_https_only_prepares_without_a_github_secret() {
        let request = SessionEgressRequest::new(crate::SessionIdentity {
            session_id: SessionId::new([0x11; ID_BYTES]),
            request_id: RequestId::new([0x12; ID_BYTES]),
            vm_id: VmId::new([0x13; ID_BYTES]),
            subject_id: SubjectId::new([0x14; ID_BYTES]),
            workspace_id: WorkspaceId::new([0x15; ID_BYTES]),
            capability_id: CapabilityId::new([0x16; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0x17; ID_BYTES]),
        });

        SystemEgressFactory::public_https_only()
            .prepare(&request)
            .expect("public HTTPS egress must not require a GitHub credential");
    }

    #[test]
    fn publish_manifest_loads_request_bound_object_transition() {
        let file = manifest(&valid_line("00112233445566778899aabbccddeeff"), 0o600);
        let plans = load_publish_plan_manifest(&file.path).expect("valid publish manifest");
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].request().repository().as_str(), "workspace");
        assert_eq!(plans[0].request().head().to_string(), "agent/work");
        assert_eq!(plans[0].plan().new_object().as_str(), &"a".repeat(40));
        validate_publish_plans_for_authority(&authority(), plans)
            .expect("plan must be selected by authority");
    }

    #[test]
    fn publish_manifest_rejects_duplicates_noncanonical_objects_and_unsafe_files() {
        let duplicate = format!(
            "{}{}",
            valid_line("00112233445566778899aabbccddeeff"),
            valid_line("00112233445566778899aabbccddeeff")
        );
        let file = manifest(&duplicate, 0o600);
        assert!(
            load_publish_plan_manifest(&file.path)
                .expect_err("duplicate request IDs must fail")
                .contains("duplicates")
        );

        let malformed = valid_line("00112233445566778899aabbccddeeFF");
        let file = manifest(&malformed, 0o600);
        assert!(load_publish_plan_manifest(&file.path).is_err());

        let file = manifest(&valid_line("00112233445566778899aabbccddeeff"), 0o640);
        assert!(
            load_publish_plan_manifest(&file.path)
                .expect_err("group-readable manifest must fail")
                .contains("group/world")
        );
    }

    #[cfg(unix)]
    #[test]
    fn publish_manifest_rejects_hard_links_and_symlinked_ancestors() {
        use std::os::unix::fs::symlink;

        let hard_linked = manifest(&valid_line("00112233445566778899aabbccddeeff"), 0o600);
        fs::hard_link(&hard_linked.path, hard_linked.directory.join("plans.alias"))
            .expect("create hard-link attack fixture");
        assert!(
            load_publish_plan_manifest(&hard_linked.path)
                .expect_err("multiply linked manifest must fail")
                .contains("singly-linked")
        );

        let linked_ancestor = manifest(&valid_line("10112233445566778899aabbccddeeff"), 0o600);
        let link = linked_ancestor.directory.with_extension("link");
        let _ = fs::remove_file(&link);
        symlink(&linked_ancestor.directory, &link).expect("create ancestor symlink fixture");
        let error = load_publish_plan_manifest(link.join("plans.tsv"))
            .expect_err("a symlink in the manifest path must fail");
        assert!(error.contains("securely open"));
        fs::remove_file(link).expect("remove ancestor symlink fixture");
    }

    #[test]
    fn publish_plan_validation_rejects_missing_and_mismatched_requests() {
        assert!(
            validate_publish_plans_for_authority(&authority(), Vec::new())
                .expect_err("missing plan must fail")
                .contains("at least one")
        );
        assert!(
            validate_publish_plans_for_authority(
                &authority(),
                vec![plan(7, "another-installation")]
            )
            .expect_err("mismatched installation must fail")
            .contains("does not match")
        );
    }

    #[test]
    fn publish_manifest_rejects_oversized_lines() {
        let file = manifest(&"x".repeat(MAX_PUBLISH_PLAN_LINE_BYTES + 1), 0o600);
        assert!(
            load_publish_plan_manifest(&file.path)
                .expect_err("oversized line must fail")
                .contains("exceeds")
        );
    }
}
