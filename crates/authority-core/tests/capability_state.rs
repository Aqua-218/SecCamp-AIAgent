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
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{
        CapabilityGrant, CapabilityState, CapabilityStateError, RevocationStatus,
        StaticAuthorityEnvelope, Subject,
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
    assert_eq!(
        state.revoke(&child_id),
        Ok(RevocationStatus::AlreadyRevoked)
    );
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
