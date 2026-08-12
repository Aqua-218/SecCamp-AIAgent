//! Typed GitHub authority bodies, requests, and delegation decisions.
//!
//! This module deliberately models only named GitHub operations. A broker
//! adapter must translate these requests into GitHub API calls; it must not
//! accept arbitrary authenticated HTTP requests.

use std::{error::Error, fmt};

use crate::repository::RepoId;

/// An opaque GitHub App installation identity assigned by the host.
///
/// The value is compared only for exact equality. It is not parsed as a
/// number, owner name, or credential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstallationId(String);

impl InstallationId {
    /// Creates an installation identity from its host-assigned value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying host-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InstallationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One supported GitHub side effect.
///
/// This closed enum is intentionally the only operation universe exposed to
/// the GitHub broker authority. Adding an operation requires an explicit
/// authority and request-model review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GitHubOperation {
    /// Publishes a branch using a non-overwriting expected-old-object check.
    PublishBranch,
    /// Creates a pull request between an authorized head and base branch.
    CreatePullRequest,
}

impl GitHubOperation {
    const fn mask(self) -> u8 {
        1_u8 << (self as u8)
    }
}

/// A set of GitHub operations from the closed [`GitHubOperation`] universe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GitHubOperations(u8);

impl GitHubOperations {
    /// Creates an operation set that permits no requests.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates an operation set containing exactly one operation.
    #[must_use]
    pub const fn only(operation: GitHubOperation) -> Self {
        Self(operation.mask())
    }

    /// Creates an operation set from the supplied operations.
    #[must_use]
    pub fn from_operations(operations: impl IntoIterator<Item = GitHubOperation>) -> Self {
        operations
            .into_iter()
            .fold(Self::empty(), |set, operation| {
                Self(set.0 | operation.mask())
            })
    }

    /// Returns whether this set contains `operation`.
    #[must_use]
    pub const fn contains(self, operation: GitHubOperation) -> bool {
        self.0 & operation.mask() != 0
    }

    /// Returns whether every operation in this set is also in `parent`.
    #[must_use]
    pub const fn is_subset_of(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// A validated Git branch name represented as slash-separated segments.
///
/// Branch authority compares segments instead of raw string prefixes. Thus a
/// prefix for `agent` matches `agent/fix`, but never `agent-evil`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BranchName {
    segments: Vec<String>,
}

impl BranchName {
    /// Creates a validated branch name from a Git branch shorthand.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBranchName`] when `value` is not a safe local branch
    /// shorthand. Fully-qualified refs such as `refs/heads/main` are rejected
    /// so callers cannot accidentally broaden a branch authority's namespace.
    pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidBranchName> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(InvalidBranchName::Empty);
        }
        if value.starts_with('/') || value.ends_with('/') {
            return Err(InvalidBranchName::LeadingOrTrailingSeparator);
        }
        if value.starts_with("refs/") {
            return Err(InvalidBranchName::FullyQualifiedReference);
        }
        if value.starts_with('-') {
            return Err(InvalidBranchName::LeadingDash);
        }
        if value == "@" {
            return Err(InvalidBranchName::ReservedAt);
        }
        if value.ends_with('.') {
            return Err(InvalidBranchName::TrailingDot);
        }
        if value.contains("..") {
            return Err(InvalidBranchName::DoubleDot);
        }
        if value.contains("@{") {
            return Err(InvalidBranchName::ReflogSyntax);
        }

        let segments = value
            .split('/')
            .enumerate()
            .map(|(index, segment)| {
                if segment.is_empty() {
                    return Err(InvalidBranchName::EmptySegment { index });
                }
                if segment.starts_with('.') {
                    return Err(InvalidBranchName::SegmentLeadingDot { index });
                }
                if segment.ends_with('.') {
                    return Err(InvalidBranchName::SegmentTrailingDot { index });
                }
                if segment.ends_with(".lock") {
                    return Err(InvalidBranchName::SegmentLockSuffix { index });
                }
                if segment
                    .chars()
                    .any(|character| character.is_control() || " ~^:?*[\\".contains(character))
                {
                    return Err(InvalidBranchName::ForbiddenCharacter { index });
                }
                Ok(segment.to_owned())
            })
            .collect::<Result<Vec<_>, InvalidBranchName>>()?;

        Ok(Self { segments })
    }

    /// Returns the branch's validated segments in order.
    #[must_use]
    pub const fn as_segments(&self) -> &[String] {
        self.segments.as_slice()
    }

    /// Returns whether this branch equals or descends from `ancestor`.
    #[must_use]
    pub fn is_at_or_below(&self, ancestor: &Self) -> bool {
        self.segments.starts_with(&ancestor.segments)
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.segments.join("/"))
    }
}

/// A branch selector used by GitHub authorities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BranchPattern {
    /// Selects one branch exactly.
    Exact(BranchName),
    /// Selects a branch namespace and every slash-delimited descendant.
    Prefix(BranchName),
}

impl BranchPattern {
    /// Returns the branch name carried by this pattern.
    #[must_use]
    pub const fn branch(&self) -> &BranchName {
        match self {
            Self::Exact(branch) | Self::Prefix(branch) => branch,
        }
    }
}

/// Returns whether `pattern` selects `branch`.
#[must_use]
pub fn branch_matches(pattern: &BranchPattern, branch: &BranchName) -> bool {
    match pattern {
        BranchPattern::Exact(selected) => selected == branch,
        BranchPattern::Prefix(selected) => branch.is_at_or_below(selected),
    }
}

/// Returns whether every branch selected by `child` is also selected by `parent`.
#[must_use]
pub fn branch_below(child: &BranchPattern, parent: &BranchPattern) -> bool {
    match (child, parent) {
        (BranchPattern::Exact(child), BranchPattern::Exact(parent)) => child == parent,
        (
            BranchPattern::Exact(child) | BranchPattern::Prefix(child),
            BranchPattern::Prefix(parent),
        ) => child.is_at_or_below(parent),
        (BranchPattern::Prefix(_), BranchPattern::Exact(_)) => false,
    }
}

/// Describes why a branch shorthand is unsafe for authority comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidBranchName {
    /// The branch name is empty.
    Empty,
    /// The branch name starts or ends with `/`.
    LeadingOrTrailingSeparator,
    /// The branch name is a fully-qualified Git reference.
    FullyQualifiedReference,
    /// The branch name begins with `-`.
    LeadingDash,
    /// The branch name is Git's reserved `@` shorthand.
    ReservedAt,
    /// The branch name ends with `.`.
    TrailingDot,
    /// The branch name contains `..`.
    DoubleDot,
    /// The branch name contains reflog syntax.
    ReflogSyntax,
    /// One slash-delimited segment is empty.
    EmptySegment { index: usize },
    /// One slash-delimited segment begins with `.`.
    SegmentLeadingDot { index: usize },
    /// One slash-delimited segment ends with `.`.
    SegmentTrailingDot { index: usize },
    /// One slash-delimited segment ends with Git's `.lock` suffix.
    SegmentLockSuffix { index: usize },
    /// One slash-delimited segment contains a Git-forbidden character.
    ForbiddenCharacter { index: usize },
}

impl fmt::Display for InvalidBranchName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("branch name must not be empty"),
            Self::LeadingOrTrailingSeparator => {
                formatter.write_str("branch name must not start or end with `/`")
            }
            Self::FullyQualifiedReference => {
                formatter.write_str("branch name must not use the `refs/` namespace")
            }
            Self::LeadingDash => formatter.write_str("branch name must not begin with `-`"),
            Self::ReservedAt => formatter.write_str("branch name must not be `@`"),
            Self::TrailingDot => formatter.write_str("branch name must not end with `.`"),
            Self::DoubleDot => formatter.write_str("branch name must not contain `..`"),
            Self::ReflogSyntax => formatter.write_str("branch name must not contain `@{`"),
            Self::EmptySegment { index } => {
                write!(
                    formatter,
                    "branch segment at index {index} must not be empty"
                )
            }
            Self::SegmentLeadingDot { index } => {
                write!(
                    formatter,
                    "branch segment at index {index} must not begin with `.`"
                )
            }
            Self::SegmentTrailingDot { index } => {
                write!(
                    formatter,
                    "branch segment at index {index} must not end with `.`"
                )
            }
            Self::SegmentLockSuffix { index } => {
                write!(
                    formatter,
                    "branch segment at index {index} must not end with `.lock`"
                )
            }
            Self::ForbiddenCharacter { index } => write!(
                formatter,
                "branch segment at index {index} contains a forbidden Git reference character"
            ),
        }
    }
}

impl Error for InvalidBranchName {}

/// The GitHub operations permitted for one installation, repository, and pair
/// of branch patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitHubAuthority {
    installation: InstallationId,
    repository: RepoId,
    operations: GitHubOperations,
    base: BranchPattern,
    head: BranchPattern,
}

impl GitHubAuthority {
    /// Creates an immutable GitHub authority body.
    #[must_use]
    pub const fn new(
        installation: InstallationId,
        repository: RepoId,
        operations: GitHubOperations,
        base: BranchPattern,
        head: BranchPattern,
    ) -> Self {
        Self {
            installation,
            repository,
            operations,
            base,
            head,
        }
    }

    /// Returns the GitHub App installation governed by this authority.
    #[must_use]
    pub const fn installation(&self) -> &InstallationId {
        &self.installation
    }

    /// Returns the exact repository governed by this authority.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }

    /// Returns the permitted GitHub operations.
    #[must_use]
    pub const fn operations(&self) -> GitHubOperations {
        self.operations
    }

    /// Returns the authorized pull-request base branch pattern.
    #[must_use]
    pub const fn base(&self) -> &BranchPattern {
        &self.base
    }

    /// Returns the authorized publish or pull-request head branch pattern.
    #[must_use]
    pub const fn head(&self) -> &BranchPattern {
        &self.head
    }
}

/// A typed request for one GitHub side effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitHubRequest {
    installation: InstallationId,
    repository: RepoId,
    operation: GitHubOperation,
    base: BranchName,
    head: BranchName,
}

impl GitHubRequest {
    /// Creates a request for one named operation and exact base/head branches.
    #[must_use]
    pub const fn new(
        installation: InstallationId,
        repository: RepoId,
        operation: GitHubOperation,
        base: BranchName,
        head: BranchName,
    ) -> Self {
        Self {
            installation,
            repository,
            operation,
            base,
            head,
        }
    }

    /// Returns the GitHub App installation receiving the request.
    #[must_use]
    pub const fn installation(&self) -> &InstallationId {
        &self.installation
    }

    /// Returns the exact target repository.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }

    /// Returns the named GitHub operation requested.
    #[must_use]
    pub const fn operation(&self) -> GitHubOperation {
        self.operation
    }

    /// Returns the requested pull-request base branch.
    #[must_use]
    pub const fn base(&self) -> &BranchName {
        &self.base
    }

    /// Returns the requested publish or pull-request head branch.
    #[must_use]
    pub const fn head(&self) -> &BranchName {
        &self.head
    }
}

/// Returns whether `authority` permits `request`.
#[must_use]
pub fn github_matches(authority: &GitHubAuthority, request: &GitHubRequest) -> bool {
    authority.installation == request.installation
        && authority.repository == request.repository
        && authority.operations.contains(request.operation)
        && branch_matches(&authority.base, &request.base)
        && branch_matches(&authority.head, &request.head)
}

/// Returns whether `child` satisfies the structural GitHub-delegation rule.
///
/// A successful decision guarantees that every request permitted by `child`
/// is also permitted by `parent`: installation and repository identities are
/// exact, while operations, base branches, and head branches can only narrow.
#[must_use]
pub fn github_body_below(child: &GitHubAuthority, parent: &GitHubAuthority) -> bool {
    child.installation == parent.installation
        && child.repository == parent.repository
        && child.operations.is_subset_of(parent.operations)
        && branch_below(&child.base, &parent.base)
        && branch_below(&child.head, &parent.head)
}

#[cfg(test)]
mod tests {
    use super::{
        BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
        GitHubRequest, InstallationId, InvalidBranchName, branch_below, branch_matches,
        github_body_below, github_matches,
    };
    use crate::repository::RepoId;

    fn branch(value: &str) -> BranchName {
        BranchName::new(value).expect("test branch names must be valid")
    }

    fn installation(value: &str) -> InstallationId {
        InstallationId::new(value)
    }

    fn repository(value: &str) -> RepoId {
        RepoId::new(value)
    }

    fn authority(
        operations: GitHubOperations,
        base: BranchPattern,
        head: BranchPattern,
    ) -> GitHubAuthority {
        GitHubAuthority::new(
            installation("installation-a"),
            repository("repo-a"),
            operations,
            base,
            head,
        )
    }

    fn request(operation: GitHubOperation, base: &str, head: &str) -> GitHubRequest {
        GitHubRequest::new(
            installation("installation-a"),
            repository("repo-a"),
            operation,
            branch(base),
            branch(head),
        )
    }

    #[test]
    fn branch_patterns_match_by_segments_not_raw_string_prefix() {
        let pattern = BranchPattern::Prefix(branch("agent"));

        assert!(branch_matches(&pattern, &branch("agent")));
        assert!(branch_matches(&pattern, &branch("agent/fix")));
        assert!(!branch_matches(&pattern, &branch("agent-evil")));
        assert!(!branch_matches(
            &BranchPattern::Exact(branch("main")),
            &branch("main/fix")
        ));
    }

    #[test]
    fn branch_pattern_containment_only_allows_narrowing() {
        let parent = BranchPattern::Prefix(branch("agent"));

        assert!(branch_below(
            &BranchPattern::Exact(branch("agent/fix")),
            &parent
        ));
        assert!(branch_below(
            &BranchPattern::Prefix(branch("agent/fix")),
            &parent
        ));
        assert!(!branch_below(
            &BranchPattern::Prefix(branch("agent")),
            &BranchPattern::Exact(branch("agent"))
        ));
        assert!(!branch_below(
            &BranchPattern::Exact(branch("agent-evil")),
            &parent
        ));
    }

    #[test]
    fn branch_names_reject_ambiguous_or_nonlocal_ref_syntax() {
        for value in [
            "",
            "/main",
            "main/",
            "refs/heads/main",
            "main..old",
            "main@{1}",
            "main lock",
            "-topic",
            ".topic",
            "topic/.hidden",
            "topic.lock",
        ] {
            assert!(
                BranchName::new(value).is_err(),
                "{value:?} must be rejected"
            );
        }
        assert_eq!(
            BranchName::new("@").unwrap_err(),
            InvalidBranchName::ReservedAt
        );
    }

    #[test]
    fn github_matches_requires_identity_operation_and_both_branches() {
        let authority = authority(
            GitHubOperations::from_operations([
                GitHubOperation::PublishBranch,
                GitHubOperation::CreatePullRequest,
            ]),
            BranchPattern::Exact(branch("main")),
            BranchPattern::Prefix(branch("agent")),
        );

        assert!(github_matches(
            &authority,
            &request(GitHubOperation::CreatePullRequest, "main", "agent/fix"),
        ));
        assert!(!github_matches(
            &authority,
            &request(GitHubOperation::CreatePullRequest, "release", "agent/fix"),
        ));
        assert!(!github_matches(
            &authority,
            &request(GitHubOperation::CreatePullRequest, "main", "other/fix"),
        ));

        let other_installation = GitHubRequest::new(
            installation("installation-b"),
            repository("repo-a"),
            GitHubOperation::CreatePullRequest,
            branch("main"),
            branch("agent/fix"),
        );
        let other_repository = GitHubRequest::new(
            installation("installation-a"),
            repository("repo-b"),
            GitHubOperation::CreatePullRequest,
            branch("main"),
            branch("agent/fix"),
        );
        assert!(!github_matches(&authority, &other_installation));
        assert!(!github_matches(&authority, &other_repository));
    }

    #[test]
    fn github_containment_requires_exact_installation_and_repository_identity() {
        let parent = authority(
            GitHubOperations::from_operations([
                GitHubOperation::PublishBranch,
                GitHubOperation::CreatePullRequest,
            ]),
            BranchPattern::Prefix(branch("release")),
            BranchPattern::Prefix(branch("agent")),
        );
        let child = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Exact(branch("release/current")),
            BranchPattern::Exact(branch("agent/fix")),
        );

        assert!(github_body_below(&child, &parent));

        let other_installation = GitHubAuthority::new(
            installation("installation-b"),
            repository("repo-a"),
            child.operations(),
            child.base().clone(),
            child.head().clone(),
        );
        let other_repository = GitHubAuthority::new(
            installation("installation-a"),
            repository("repo-b"),
            child.operations(),
            child.base().clone(),
            child.head().clone(),
        );
        assert!(!github_body_below(&other_installation, &parent));
        assert!(!github_body_below(&other_repository, &parent));
    }

    #[test]
    fn github_containment_rejects_operation_and_branch_escalation() {
        let parent = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Exact(branch("main")),
            BranchPattern::Prefix(branch("agent")),
        );
        let operation_escalation = authority(
            GitHubOperations::from_operations([
                GitHubOperation::PublishBranch,
                GitHubOperation::CreatePullRequest,
            ]),
            BranchPattern::Exact(branch("main")),
            BranchPattern::Exact(branch("agent/fix")),
        );
        let base_escalation = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Prefix(branch("release")),
            BranchPattern::Exact(branch("agent/fix")),
        );
        let head_escalation = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Exact(branch("main")),
            BranchPattern::Prefix(branch("other")),
        );

        assert!(!github_body_below(&operation_escalation, &parent));
        assert!(!github_body_below(&base_escalation, &parent));
        assert!(!github_body_below(&head_escalation, &parent));
    }

    #[test]
    fn github_containment_is_transitive() {
        let parent = authority(
            GitHubOperations::from_operations([
                GitHubOperation::PublishBranch,
                GitHubOperation::CreatePullRequest,
            ]),
            BranchPattern::Prefix(branch("release")),
            BranchPattern::Prefix(branch("agent")),
        );
        let child = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Prefix(branch("release/current")),
            BranchPattern::Prefix(branch("agent/fix")),
        );
        let leaf = authority(
            GitHubOperations::only(GitHubOperation::CreatePullRequest),
            BranchPattern::Exact(branch("release/current")),
            BranchPattern::Exact(branch("agent/fix/one")),
        );

        assert!(github_body_below(&child, &parent));
        assert!(github_body_below(&leaf, &child));
        assert!(github_body_below(&leaf, &parent));
    }
}
