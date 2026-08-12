//! Contract tests for sequential capability issuance and revocation.
//!
//! Specification: `docs/design/state-and-revocation.md`, section "Delegation".
//! Coverage: subject registration, root issuance, Derive decision conditions,
//! authorization binding, monotone revocation, and failed-transition atomicity.

use authority_core::{
    capability::{
        AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId, weaker_than,
    },
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    github::{
        BranchName, BranchPattern, GitHubAuthority, GitHubOperation, GitHubOperations,
        GitHubRequest, InstallationId,
    },
    handle::{HandleId, ObjectId, OpenHandle},
    http::{
        CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
        HttpFetchRequest, UrlPathPattern,
    },
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        AuthorizationEpoch, CapabilityGrant, CapabilityState, CapabilityStateError,
        HandleCloseStatus, RevocationStatus, StaticAuthorityEnvelope, Subject, SubjectCloseStatus,
        SubjectFinishStatus, SubjectStatus,
    },
    time::{MonotonicTime, TimeWindow},
};

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at))
        .expect("test bounds must form a non-empty time window")
}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("test paths must contain valid segments")
}

fn file_authority(
    effects: impl IntoIterator<Item = FileEffect>,
    path: PathPattern,
) -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::from_effects(effects),
        path,
    ))
}

fn root_subject_id() -> SubjectId {
    SubjectId::new("subject-root")
}

fn child_subject_id() -> SubjectId {
    SubjectId::new("subject-child")
}

fn leaf_subject_id() -> SubjectId {
    SubjectId::new("subject-leaf")
}

fn root_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(
        window(0, 100),
        file_authority(
            [
                FileEffect::ReadData,
                FileEffect::WriteData,
                FileEffect::Rename,
            ],
            PathPattern::Prefix(CanonicalPath::root()),
        ),
    )
}

fn child_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(
        window(10, 90),
        file_authority(
            [FileEffect::ReadData, FileEffect::WriteData],
            PathPattern::Prefix(path(&["src"])),
        ),
    )
}

fn leaf_envelope() -> StaticAuthorityEnvelope {
    StaticAuthorityEnvelope::new(
        window(20, 80),
        file_authority(
            [FileEffect::ReadData],
            PathPattern::Exact(path(&["src", "main.rs"])),
        ),
    )
}

fn root_grant(delegable: bool) -> CapabilityGrant {
    CapabilityGrant::new(
        root_subject_id(),
        window(10, 90),
        file_authority(
            [FileEffect::ReadData, FileEffect::WriteData],
            PathPattern::Prefix(CanonicalPath::root()),
        ),
    )
    .with_delegable(delegable)
}

fn child_grant(delegable: bool) -> CapabilityGrant {
    CapabilityGrant::new(
        child_subject_id(),
        window(20, 80),
        file_authority(
            [FileEffect::ReadData, FileEffect::WriteData],
            PathPattern::Prefix(path(&["src"])),
        ),
    )
    .with_delegable(delegable)
}

fn leaf_grant() -> CapabilityGrant {
    CapabilityGrant::new(
        leaf_subject_id(),
        window(30, 70),
        file_authority(
            [FileEffect::ReadData],
            PathPattern::Exact(path(&["src", "main.rs"])),
        ),
    )
}

fn state_with_subjects() -> CapabilityState {
    let mut state = CapabilityState::new(IssuerId::new("session-issuer"));
    state
        .register_subject(Subject::new(root_subject_id(), root_envelope()))
        .expect("root subject registration must succeed");
    state
        .register_subject(
            Subject::new(child_subject_id(), child_envelope()).with_parent(root_subject_id()),
        )
        .expect("child subject registration must succeed");
    state
        .register_subject(
            Subject::new(leaf_subject_id(), leaf_envelope()).with_parent(child_subject_id()),
        )
        .expect("leaf subject registration must succeed");
    state
}

fn read_request(ticks: u64, segments: &[&str]) -> CapabilityRequest {
    CapabilityRequest::new(
        time(ticks),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::ReadData,
            path(segments),
        )),
    )
}

fn http_authority(
    methods: HttpFetchMethods,
    path: UrlPathPattern,
    max_bytes: u64,
) -> AuthorityBody {
    AuthorityBody::HttpFetch(HttpFetchAuthority::new(
        methods,
        CanonicalHost::new("docs.example").expect("test host must be valid"),
        path,
        max_bytes,
    ))
}

fn http_request(ticks: u64, path: &str) -> CapabilityRequest {
    CapabilityRequest::new(
        time(ticks),
        AuthorityRequest::HttpFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("docs.example").expect("test host must be valid"),
            CanonicalUrlPath::new(path).expect("test URL path must be valid"),
            1_024,
        )),
    )
}

fn branch(value: &str) -> BranchName {
    BranchName::new(value).expect("test branch must be valid")
}

fn github_authority(operations: GitHubOperations, head: BranchPattern) -> AuthorityBody {
    AuthorityBody::GitHub(GitHubAuthority::new(
        InstallationId::new("installation-a"),
        RepoId::new("github.example/acme/workspace"),
        operations,
        BranchPattern::Exact(branch("main")),
        head,
    ))
}

fn github_request(ticks: u64, operation: GitHubOperation, head: &str) -> CapabilityRequest {
    CapabilityRequest::new(
        time(ticks),
        AuthorityRequest::GitHub(GitHubRequest::new(
            InstallationId::new("installation-a"),
            RepoId::new("github.example/acme/workspace"),
            operation,
            branch("main"),
            branch(head),
        )),
    )
}

// Requirement: subject parent links resolve at registration time and subject
// identities are immutable. Category: state/error. Risk: high.
#[test]
fn subject_registration_rejects_unknown_parents_and_duplicate_ids() {
    let mut state = CapabilityState::new(IssuerId::new("session-issuer"));
    let missing_parent = SubjectId::new("subject-missing");
    let child =
        Subject::new(child_subject_id(), child_envelope()).with_parent(missing_parent.clone());

    assert_eq!(
        state.register_subject(child),
        Err(CapabilityStateError::UnknownParentSubject(
            missing_parent.clone()
        ))
    );
    assert_eq!(
        CapabilityStateError::UnknownParentSubject(missing_parent).to_string(),
        "parent subject `subject-missing` is not registered"
    );

    state
        .register_subject(Subject::new(root_subject_id(), root_envelope()))
        .expect("first root registration must succeed");
    assert_eq!(
        state.register_subject(Subject::new(root_subject_id(), root_envelope())),
        Err(CapabilityStateError::DuplicateSubject(root_subject_id()))
    );

    state
        .register_subject(
            Subject::new(child_subject_id(), child_envelope()).with_parent(root_subject_id()),
        )
        .expect("a subject with an existing parent must register");
    assert_eq!(
        state.subject(&child_subject_id()).and_then(Subject::parent),
        Some(&root_subject_id())
    );
}

// Requirement: the state assigns root metadata and must not consume an ID or
// mutate held state on rejection. Category: state/boundary. Risk: critical.
#[test]
fn root_issuance_assigns_metadata_and_is_atomic_on_rejection() {
    let mut state = state_with_subjects();
    let unknown_subject = SubjectId::new("subject-unknown");

    assert_eq!(
        state.issue_root(CapabilityGrant::new(
            unknown_subject.clone(),
            window(10, 20),
            file_authority(
                [FileEffect::ReadData],
                PathPattern::Exact(path(&["src", "main.rs"])),
            ),
        )),
        Err(CapabilityStateError::UnknownSubject(unknown_subject))
    );
    assert_eq!(
        state.issue_root(CapabilityGrant::new(
            root_subject_id(),
            window(0, 101),
            file_authority(
                [FileEffect::ReadData],
                PathPattern::Exact(path(&["src", "main.rs"])),
            ),
        )),
        Err(CapabilityStateError::GrantExceedsEnvelope(root_subject_id()))
    );

    let root_id = state
        .issue_root(root_grant(true))
        .expect("a root inside its subject envelope must be issued");
    let root = state
        .capability(&root_id)
        .expect("the issued root must be stored");

    assert_eq!(root_id.as_str(), "session-issuer:0");
    assert_eq!(root.metadata().id(), &root_id);
    assert_eq!(root.metadata().subject(), &root_subject_id());
    assert_eq!(root.metadata().issuer(), state.issuer());
    assert_eq!(root.metadata().parent(), None);
    assert!(root.metadata().is_delegable());
    assert!(state.is_held_by(&root_subject_id(), &root_id));
    assert!(!state.is_held_by(&child_subject_id(), &root_id));
}

// Requirement: every successful Derive creates an exact parent link and each
// edge narrows authority. Category: state/normal. Risk: critical.
#[test]
fn derive_builds_a_multilevel_non_amplifying_chain() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let child_id = state
        .derive(&root_subject_id(), &root_id, child_grant(true), time(25))
        .expect("narrow child derivation must succeed");
    let leaf_id = state
        .derive(&child_subject_id(), &child_id, leaf_grant(), time(35))
        .expect("narrow leaf derivation must succeed");

    let root = state.capability(&root_id).expect("root must exist");
    let child = state.capability(&child_id).expect("child must exist");
    let leaf = state.capability(&leaf_id).expect("leaf must exist");

    assert_eq!(root_id.as_str(), "session-issuer:0");
    assert_eq!(child_id.as_str(), "session-issuer:1");
    assert_eq!(leaf_id.as_str(), "session-issuer:2");
    assert_eq!(child.metadata().parent(), Some(&root_id));
    assert_eq!(leaf.metadata().parent(), Some(&child_id));
    assert_eq!(child.metadata().subject(), &child_subject_id());
    assert_eq!(leaf.metadata().subject(), &leaf_subject_id());
    assert!(state.is_held_by(&child_subject_id(), &child_id));
    assert!(state.is_held_by(&leaf_subject_id(), &leaf_id));
    assert!(weaker_than(child, root));
    assert!(weaker_than(leaf, child));
    assert!(weaker_than(leaf, root));
}

// Requirement: only the authenticated holder may invoke Derive and the parent
// must exist. Category: authorization/error. Risk: critical.
#[test]
fn derive_rejects_unknown_or_foreign_parent_ids() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let unknown_id = CapId::new("session-issuer:unknown");

    assert_eq!(
        state.derive(
            &root_subject_id(),
            &unknown_id,
            child_grant(false),
            time(25),
        ),
        Err(CapabilityStateError::UnknownCapability(unknown_id))
    );
    assert_eq!(
        state.derive(&child_subject_id(), &root_id, child_grant(false), time(25),),
        Err(CapabilityStateError::ParentNotHeld {
            caller: child_subject_id(),
            parent: root_id,
        })
    );
}

// Requirement: Derive requires a currently active parent chain and an explicit
// delegation right. Category: boundary/security. Risk: critical.
#[test]
fn derive_rejects_inactive_or_non_delegable_parents() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");

    for inactive_time in [9, 90] {
        assert_eq!(
            state.derive(
                &root_subject_id(),
                &root_id,
                child_grant(false),
                time(inactive_time),
            ),
            Err(CapabilityStateError::ParentChainInactive(root_id.clone()))
        );
    }

    state
        .revoke(&root_id)
        .expect("the issued root must be revocable");
    assert_eq!(
        state.derive(&root_subject_id(), &root_id, child_grant(false), time(25),),
        Err(CapabilityStateError::ParentChainInactive(root_id.clone()))
    );

    let mut non_delegable_state = state_with_subjects();
    let non_delegable_id = non_delegable_state
        .issue_root(root_grant(false))
        .expect("non-delegable roots are valid grants");
    assert_eq!(
        non_delegable_state.derive(
            &root_subject_id(),
            &non_delegable_id,
            child_grant(false),
            time(25),
        ),
        Err(CapabilityStateError::ParentNotDelegable(non_delegable_id))
    );
}

// Requirement: child authority must fit both its immediate parent and target
// subject envelope. Category: decision table/security. Risk: critical.
#[test]
fn derive_rejects_parent_or_static_envelope_expansion() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let parent_expansions = [
        CapabilityGrant::new(
            child_subject_id(),
            window(9, 80),
            file_authority(
                [FileEffect::ReadData],
                PathPattern::Exact(path(&["src", "main.rs"])),
            ),
        ),
        CapabilityGrant::new(
            child_subject_id(),
            window(20, 80),
            file_authority(
                [FileEffect::Rename],
                PathPattern::Exact(path(&["src", "main.rs"])),
            ),
        ),
    ];

    for expanded_grant in parent_expansions {
        assert_eq!(
            state.derive(&root_subject_id(), &root_id, expanded_grant, time(25),),
            Err(CapabilityStateError::GrantExceedsParent(root_id.clone()))
        );
    }

    let outside_child_envelope = CapabilityGrant::new(
        child_subject_id(),
        window(20, 80),
        file_authority(
            [FileEffect::ReadData],
            PathPattern::Exact(path(&["docs", "design.md"])),
        ),
    );
    assert_eq!(
        state.derive(
            &root_subject_id(),
            &root_id,
            outside_child_envelope,
            time(25),
        ),
        Err(CapabilityStateError::GrantExceedsEnvelope(
            child_subject_id()
        ))
    );
}

// Requirement: a rejected Derive has no observable state effect, including ID
// allocation. Category: state/error atomicity. Risk: critical.
#[test]
fn rejected_derive_does_not_consume_an_id_or_create_a_holding() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let invalid_grant = CapabilityGrant::new(
        child_subject_id(),
        window(20, 80),
        file_authority(
            [FileEffect::Rename],
            PathPattern::Exact(path(&["src", "main.rs"])),
        ),
    );

    assert_eq!(
        state.derive(&root_subject_id(), &root_id, invalid_grant, time(25),),
        Err(CapabilityStateError::GrantExceedsParent(root_id.clone()))
    );
    assert!(!state.is_held_by(&child_subject_id(), &CapId::new("session-issuer:1")));

    let child_id = state
        .derive(&root_subject_id(), &root_id, child_grant(false), time(25))
        .expect("a valid grant after rejection must still succeed");
    assert_eq!(child_id.as_str(), "session-issuer:1");
}

// Requirement: authorization combines subject binding, held state, ancestor
// validity, and request matching. Category: authorization/security. Risk: critical.
#[test]
fn authorization_rejects_copied_expired_and_out_of_scope_capabilities() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");

    assert!(state.authorizes(
        &root_subject_id(),
        &root_id,
        &read_request(10, &["src", "main.rs"]),
    ));
    assert!(!state.authorizes(
        &child_subject_id(),
        &root_id,
        &read_request(10, &["src", "main.rs"]),
    ));
    assert!(!state.authorizes(
        &root_subject_id(),
        &CapId::new("forged-capability"),
        &read_request(10, &["src", "main.rs"]),
    ));
    assert!(!state.authorizes(
        &root_subject_id(),
        &root_id,
        &read_request(90, &["src", "main.rs"]),
    ));

    let write_request = CapabilityRequest::new(
        time(20),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::Rename,
            path(&["src", "main.rs"]),
        )),
    );
    assert!(!state.authorizes(&root_subject_id(), &root_id, &write_request));
}

// Requirement: revoke is monotone and an inactive ancestor invalidates every
// descendant without deleting audit-visible records. Category: state/security. Risk: critical.
#[test]
fn ancestor_revocation_invalidates_descendants_and_never_reuses_ids() {
    let mut state = state_with_subjects();
    assert_eq!(state.authorization_epoch(), AuthorizationEpoch::default());
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let child_id = state
        .derive(&root_subject_id(), &root_id, child_grant(true), time(25))
        .expect("child derivation must succeed");
    let leaf_id = state
        .derive(&child_subject_id(), &child_id, leaf_grant(), time(35))
        .expect("leaf derivation must succeed");

    assert_eq!(state.revoke(&child_id), Ok(RevocationStatus::NewlyRevoked));
    assert_eq!(state.authorization_epoch().as_u64(), 1);
    assert_eq!(
        state.revoke(&child_id),
        Ok(RevocationStatus::AlreadyRevoked)
    );
    assert_eq!(state.authorization_epoch().as_u64(), 1);
    assert!(state.is_revoked(&child_id));
    assert!(state.is_effectively_active(&root_id, time(40)));
    assert!(!state.is_effectively_active(&child_id, time(40)));
    assert!(!state.is_effectively_active(&leaf_id, time(40)));
    assert!(state.capability(&leaf_id).is_some());
    assert!(!state.authorizes(
        &leaf_subject_id(),
        &leaf_id,
        &read_request(40, &["src", "main.rs"]),
    ));
    assert_eq!(
        state.derive(&child_subject_id(), &child_id, leaf_grant(), time(40),),
        Err(CapabilityStateError::ParentChainInactive(child_id.clone()))
    );

    let next_id = state
        .issue_root(root_grant(false))
        .expect("revocation must not prevent unrelated issuance");
    assert_eq!(next_id.as_str(), "session-issuer:3");
    assert_ne!(next_id, child_id);
    assert_ne!(next_id, leaf_id);

    let unknown = CapId::new("session-issuer:999");
    assert_eq!(
        state.revoke(&unknown),
        Err(CapabilityStateError::UnknownCapability(unknown))
    );
}

// Requirement: beginning shutdown blocks new authority immediately, revokes
// held roots, and never allows a closed subject to run again.
// Category: lifecycle/security. Risk: critical.
#[test]
fn subject_shutdown_is_monotone_and_invalidates_descendants() {
    let mut state = state_with_subjects();
    let root_id = state
        .issue_root(root_grant(true))
        .expect("root issuance must succeed");
    let child_id = state
        .derive(&root_subject_id(), &root_id, child_grant(false), time(25))
        .expect("child derivation must succeed before shutdown");

    assert_eq!(
        state.finish_subject_close(&root_subject_id()),
        Err(CapabilityStateError::SubjectNotClosing(root_subject_id()))
    );
    assert_eq!(
        state.begin_subject_close(&root_subject_id()),
        Ok(SubjectCloseStatus::Started)
    );
    assert_eq!(
        state.subject_status(&root_subject_id()),
        Some(SubjectStatus::Closing)
    );
    assert_eq!(state.authorization_epoch().as_u64(), 1);
    assert!(state.is_revoked(&root_id));
    assert!(!state.is_effectively_active(&child_id, time(30)));
    assert!(!state.authorizes(
        &root_subject_id(),
        &root_id,
        &read_request(30, &["src", "main.rs"]),
    ));
    assert_eq!(
        state.issue_root(root_grant(false)),
        Err(CapabilityStateError::SubjectNotRunning(root_subject_id()))
    );
    assert_eq!(
        state.begin_subject_close(&root_subject_id()),
        Ok(SubjectCloseStatus::AlreadyClosing)
    );
    assert_eq!(state.authorization_epoch().as_u64(), 1);

    assert_eq!(
        state.finish_subject_close(&root_subject_id()),
        Ok(SubjectFinishStatus::Closed)
    );
    assert_eq!(
        state.subject_status(&root_subject_id()),
        Some(SubjectStatus::Closed)
    );
    assert_eq!(
        state.begin_subject_close(&root_subject_id()),
        Ok(SubjectCloseStatus::AlreadyClosed)
    );
    assert_eq!(
        state.finish_subject_close(&root_subject_id()),
        Ok(SubjectFinishStatus::AlreadyClosed)
    );
}

// Requirement: live handles remain subject/object bound, close is idempotent,
// and an issued ID can never name a later handle. Category: state/security. Risk: critical.
#[test]
fn open_handle_registry_rejects_reuse_and_blocks_early_subject_close() {
    let mut state = state_with_subjects();
    let object = ObjectId::new("object-source");
    let root_handle_id = HandleId::new("handle-root");
    let child_handle_id = HandleId::new("handle-child");
    let root_handle = OpenHandle::new(root_handle_id.clone(), root_subject_id(), object.clone());
    let child_handle = OpenHandle::new(child_handle_id.clone(), child_subject_id(), object.clone());

    state
        .register_open_handle(root_handle.clone())
        .expect("a running subject may own a new handle");
    state
        .register_open_handle(child_handle)
        .expect("a second subject may open the same object");
    assert_eq!(state.open_handle(&root_handle_id), Some(&root_handle));
    assert_eq!(state.object_open_handle_count(&object), 2);
    assert_eq!(state.subject_open_handle_count(&root_subject_id()), 1);
    assert_eq!(
        state.register_open_handle(OpenHandle::new(
            root_handle_id.clone(),
            root_subject_id(),
            ObjectId::new("different-object"),
        )),
        Err(CapabilityStateError::HandleIdAlreadyIssued(
            root_handle_id.clone()
        ))
    );

    assert_eq!(
        state.begin_subject_close(&root_subject_id()),
        Ok(SubjectCloseStatus::Started)
    );
    assert_eq!(
        state.finish_subject_close(&root_subject_id()),
        Err(CapabilityStateError::SubjectHasOpenHandles(
            root_subject_id()
        ))
    );
    assert_eq!(
        state.close_handle(&child_subject_id(), &root_handle_id),
        Err(CapabilityStateError::HandleNotOwned {
            caller: child_subject_id(),
            handle: root_handle_id.clone(),
        })
    );
    assert_eq!(state.object_open_handle_count(&object), 2);
    assert_eq!(
        state.close_handle(&root_subject_id(), &root_handle_id),
        Ok(HandleCloseStatus::Closed)
    );
    assert_eq!(
        state.close_handle(&root_subject_id(), &root_handle_id),
        Ok(HandleCloseStatus::AlreadyClosed)
    );
    assert_eq!(
        state.close_handle(&child_subject_id(), &root_handle_id),
        Err(CapabilityStateError::HandleNotOwned {
            caller: child_subject_id(),
            handle: root_handle_id.clone(),
        })
    );
    assert_eq!(state.object_open_handle_count(&object), 1);
    assert_eq!(
        state.register_open_handle(OpenHandle::new(
            root_handle_id.clone(),
            child_subject_id(),
            object,
        )),
        Err(CapabilityStateError::HandleIdAlreadyIssued(root_handle_id))
    );
    assert_eq!(
        state.finish_subject_close(&root_subject_id()),
        Ok(SubjectFinishStatus::Closed)
    );
    let unknown = HandleId::new("handle-unknown");
    assert_eq!(
        state.close_handle(&root_subject_id(), &unknown),
        Err(CapabilityStateError::UnknownHandle(unknown))
    );
}

// Requirement: each tagged authority family must retain the same issuance,
// derivation, authorization, and revoke guarantees as file authority.
// Category: state/security. Risk: critical.
#[test]
fn service_authorities_follow_the_same_lifecycle_rules() {
    let http_parent = http_authority(
        HttpFetchMethods::from_methods([HttpFetchMethod::Get, HttpFetchMethod::Head]),
        UrlPathPattern::Prefix(
            CanonicalUrlPath::new("/guide").expect("test URL path must be valid"),
        ),
        4_096,
    );
    let http_child = http_authority(
        HttpFetchMethods::only(HttpFetchMethod::Get),
        UrlPathPattern::Exact(
            CanonicalUrlPath::new("/guide/start").expect("test URL path must be valid"),
        ),
        1_024,
    );
    let mut http_state = CapabilityState::new(IssuerId::new("http-issuer"));
    http_state
        .register_subject(Subject::new(
            root_subject_id(),
            StaticAuthorityEnvelope::new(window(0, 100), http_parent.clone()),
        ))
        .expect("HTTP subject registration must succeed");
    let http_root = http_state
        .issue_root(
            CapabilityGrant::new(root_subject_id(), window(10, 90), http_parent)
                .with_delegable(true),
        )
        .expect("HTTP root issuance must succeed");
    let http_child_id = http_state
        .derive(
            &root_subject_id(),
            &http_root,
            CapabilityGrant::new(root_subject_id(), window(20, 80), http_child),
            time(25),
        )
        .expect("narrow HTTP child derivation must succeed");
    assert!(http_state.authorizes(
        &root_subject_id(),
        &http_child_id,
        &http_request(30, "/guide/start"),
    ));
    assert_eq!(
        http_state.revoke(&http_root),
        Ok(RevocationStatus::NewlyRevoked)
    );
    assert!(!http_state.authorizes(
        &root_subject_id(),
        &http_child_id,
        &http_request(30, "/guide/start"),
    ));

    let github_parent = github_authority(
        GitHubOperations::from_operations([
            GitHubOperation::PublishBranch,
            GitHubOperation::CreatePullRequest,
        ]),
        BranchPattern::Prefix(branch("agents")),
    );
    let github_child = github_authority(
        GitHubOperations::only(GitHubOperation::CreatePullRequest),
        BranchPattern::Exact(branch("agents/fix")),
    );
    let mut github_state = CapabilityState::new(IssuerId::new("github-issuer"));
    github_state
        .register_subject(Subject::new(
            root_subject_id(),
            StaticAuthorityEnvelope::new(window(0, 100), github_parent.clone()),
        ))
        .expect("GitHub subject registration must succeed");
    let github_root = github_state
        .issue_root(
            CapabilityGrant::new(root_subject_id(), window(10, 90), github_parent)
                .with_delegable(true),
        )
        .expect("GitHub root issuance must succeed");
    let github_child_id = github_state
        .derive(
            &root_subject_id(),
            &github_root,
            CapabilityGrant::new(root_subject_id(), window(20, 80), github_child),
            time(25),
        )
        .expect("narrow GitHub child derivation must succeed");
    assert!(github_state.authorizes(
        &root_subject_id(),
        &github_child_id,
        &github_request(30, GitHubOperation::CreatePullRequest, "agents/fix"),
    ));
    assert!(!github_state.authorizes(
        &root_subject_id(),
        &github_child_id,
        &github_request(30, GitHubOperation::PublishBranch, "agents/fix"),
    ));
    assert_eq!(
        github_state.revoke(&github_child_id),
        Ok(RevocationStatus::NewlyRevoked)
    );
    assert!(!github_state.authorizes(
        &root_subject_id(),
        &github_child_id,
        &github_request(30, GitHubOperation::CreatePullRequest, "agents/fix"),
    ));
}
