//! Model-based property tests for sequential capability state.
//!
//! Specification: `docs/design/verification.md`, sequential state-machine row.
//! Coverage: generated Derive/revoke sequences are compared with an independent
//! reference model, then every stored edge, holding, envelope, and ancestor
//! revocation invariant is rechecked through the public API.

use std::collections::{BTreeMap, BTreeSet};

use authority_core::{
    capability::{
        AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId, weaker_than,
    },
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use proptest::prelude::*;

const REGISTERED_SUBJECTS: u8 = 4;
const UNKNOWN_SUBJECT: u8 = REGISTERED_SUBJECTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Repository,
    Source,
    Parser,
    MainFile,
    Docs,
}

impl Scope {
    const fn from_index(index: u8) -> Self {
        match index % 5 {
            0 => Self::Repository,
            1 => Self::Source,
            2 => Self::Parser,
            3 => Self::MainFile,
            _ => Self::Docs,
        }
    }

    const fn is_below(self, parent: Self) -> bool {
        match parent {
            Self::Repository => true,
            Self::Source => matches!(self, Self::Source | Self::Parser | Self::MainFile),
            Self::Parser => matches!(self, Self::Parser | Self::MainFile),
            Self::MainFile => matches!(self, Self::MainFile),
            Self::Docs => matches!(self, Self::Docs),
        }
    }

    fn pattern(self) -> PathPattern {
        match self {
            Self::Repository => PathPattern::Prefix(CanonicalPath::root()),
            Self::Source => PathPattern::Prefix(path(&["src"])),
            Self::Parser => PathPattern::Prefix(path(&["src", "parser"])),
            Self::MainFile => PathPattern::Exact(path(&["src", "parser", "main.rs"])),
            Self::Docs => PathPattern::Prefix(path(&["docs"])),
        }
    }

    fn matching_path(self) -> CanonicalPath {
        match self {
            Self::Repository => path(&["README.md"]),
            Self::Source => path(&["src"]),
            Self::Parser => path(&["src", "parser"]),
            Self::MainFile => path(&["src", "parser", "main.rs"]),
            Self::Docs => path(&["docs"]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelWindow {
    not_before: u64,
    expires_at: u64,
}

impl ModelWindow {
    const fn from_index(index: u8) -> Self {
        match index % 4 {
            0 => Self {
                not_before: 10,
                expires_at: 90,
            },
            1 => Self {
                not_before: 20,
                expires_at: 80,
            },
            2 => Self {
                not_before: 9,
                expires_at: 80,
            },
            _ => Self {
                not_before: 20,
                expires_at: 91,
            },
        }
    }

    const fn envelope() -> Self {
        Self {
            not_before: 10,
            expires_at: 90,
        }
    }

    const fn contains(self, ticks: u64) -> bool {
        self.not_before <= ticks && ticks < self.expires_at
    }

    const fn is_below(self, parent: Self) -> bool {
        parent.not_before <= self.not_before && self.expires_at <= parent.expires_at
    }

    fn into_time_window(self) -> TimeWindow {
        window(self.not_before, self.expires_at)
    }
}

#[derive(Debug, Clone)]
enum Command {
    Derive {
        caller: u8,
        parent_slot: u8,
        target: u8,
        scope: Scope,
        validity: ModelWindow,
        delegable: bool,
        now: u64,
    },
    Revoke {
        slot: u8,
    },
}

#[derive(Debug, Clone)]
struct ModelCapability {
    owner: u8,
    parent: Option<u8>,
    scope: Scope,
    validity: ModelWindow,
    delegable: bool,
    revoked: bool,
}

#[derive(Debug)]
struct ReferenceModel {
    capabilities: BTreeMap<u8, ModelCapability>,
    next_slot: u8,
}

impl ReferenceModel {
    fn new() -> Self {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            0,
            ModelCapability {
                owner: 0,
                parent: None,
                scope: Scope::Repository,
                validity: ModelWindow::envelope(),
                delegable: true,
                revoked: false,
            },
        );
        Self {
            capabilities,
            next_slot: 1,
        }
    }

    fn chain_is_active(&self, slot: u8, now: u64) -> bool {
        let mut current = Some(slot);
        let mut visited = BTreeSet::new();

        while let Some(current_slot) = current {
            if !visited.insert(current_slot) {
                return false;
            }
            let Some(capability) = self.capabilities.get(&current_slot) else {
                return false;
            };
            if capability.revoked || !capability.validity.contains(now) {
                return false;
            }
            current = capability.parent;
        }

        true
    }

    fn can_derive(
        &self,
        caller: u8,
        parent_slot: u8,
        target: u8,
        scope: Scope,
        validity: ModelWindow,
        now: u64,
    ) -> bool {
        let Some(parent) = self.capabilities.get(&parent_slot) else {
            return false;
        };
        let Some(target_envelope) = subject_envelope_scope(target) else {
            return false;
        };

        parent.owner == caller
            && self.chain_is_active(parent_slot, now)
            && parent.delegable
            && validity.is_below(parent.validity)
            && scope.is_below(parent.scope)
            && validity.is_below(ModelWindow::envelope())
            && scope.is_below(target_envelope)
    }

    fn derive(
        &mut self,
        target: u8,
        parent_slot: u8,
        scope: Scope,
        validity: ModelWindow,
        delegable: bool,
    ) -> u8 {
        let slot = self.next_slot;
        self.next_slot = self
            .next_slot
            .checked_add(1)
            .expect("generated test sequences cannot exhaust u8 capability slots");
        self.capabilities.insert(
            slot,
            ModelCapability {
                owner: target,
                parent: Some(parent_slot),
                scope,
                validity,
                delegable,
                revoked: false,
            },
        );
        slot
    }
}

fn time(ticks: u64) -> MonotonicTime {
    MonotonicTime::from_ticks(ticks)
}

fn window(not_before: u64, expires_at: u64) -> TimeWindow {
    TimeWindow::new(time(not_before), time(expires_at))
        .expect("model windows must remain non-empty")
}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("model paths must contain valid segments")
}

fn subject_id(index: u8) -> SubjectId {
    SubjectId::new(format!("subject-{index}"))
}

fn capability_id(slot: u8) -> CapId {
    CapId::new(format!("model-issuer:{slot}"))
}

fn authority(scope: Scope) -> AuthorityBody {
    AuthorityBody::File(FileAuthority::new(
        RepoId::new("workspace"),
        FileEffects::only(FileEffect::ReadData),
        scope.pattern(),
    ))
}

const fn subject_envelope_scope(subject: u8) -> Option<Scope> {
    match subject {
        0 => Some(Scope::Repository),
        1 => Some(Scope::Source),
        2 => Some(Scope::Parser),
        3 => Some(Scope::Docs),
        _ => None,
    }
}

fn grant(subject: u8, scope: Scope, validity: ModelWindow, delegable: bool) -> CapabilityGrant {
    CapabilityGrant::new(
        subject_id(subject),
        validity.into_time_window(),
        authority(scope),
    )
    .with_delegable(delegable)
}

fn request(scope: Scope, now: u64) -> CapabilityRequest {
    CapabilityRequest::new(
        time(now),
        AuthorityRequest::File(FileRequest::new(
            RepoId::new("workspace"),
            FileEffect::ReadData,
            scope.matching_path(),
        )),
    )
}

fn state_with_root() -> CapabilityState {
    let mut state = CapabilityState::new(IssuerId::new("model-issuer"));
    let subject_parents = [None, Some(0), Some(1), Some(0)];

    for (subject, parent) in subject_parents.into_iter().enumerate() {
        let subject = u8::try_from(subject).expect("the fixed subject count fits u8");
        let envelope_scope = subject_envelope_scope(subject)
            .expect("every fixed subject must have an envelope scope");
        let mut registration = Subject::new(
            subject_id(subject),
            StaticAuthorityEnvelope::new(
                ModelWindow::envelope().into_time_window(),
                authority(envelope_scope),
            ),
        );
        if let Some(parent) = parent {
            registration = registration.with_parent(subject_id(parent));
        }
        state
            .register_subject(registration)
            .expect("the fixed subject tree must register in parent-first order");
    }

    let root_id = state
        .issue_root(grant(0, Scope::Repository, ModelWindow::envelope(), true))
        .expect("the model root must fit the root subject envelope");
    assert_eq!(root_id, capability_id(0));
    state
}

fn command_strategy() -> impl Strategy<Value = Command> {
    prop_oneof![
        5 => (
            0_u8..=UNKNOWN_SUBJECT,
            0_u8..16,
            0_u8..=UNKNOWN_SUBJECT,
            0_u8..5,
            0_u8..4,
            any::<bool>(),
            prop_oneof![Just(9_u64), Just(30_u64), Just(90_u64)],
        )
            .prop_map(
                |(caller, parent_slot, target, scope, validity, delegable, now)| {
                    Command::Derive {
                        caller,
                        parent_slot,
                        target,
                        scope: Scope::from_index(scope),
                        validity: ModelWindow::from_index(validity),
                        delegable,
                        now,
                    }
                },
            ),
        2 => (0_u8..16).prop_map(|slot| Command::Revoke { slot }),
    ]
}

fn assert_invariants(state: &CapabilityState, model: &ReferenceModel) -> Result<(), TestCaseError> {
    for (&slot, expected) in &model.capabilities {
        let id = capability_id(slot);
        let actual = state
            .capability(&id)
            .ok_or_else(|| TestCaseError::fail(format!("missing issued capability {id}")))?;
        let expected_parent = expected.parent.map(capability_id);

        prop_assert_eq!(actual.metadata().id(), &id);
        prop_assert_eq!(actual.metadata().subject(), &subject_id(expected.owner));
        prop_assert_eq!(actual.metadata().parent(), expected_parent.as_ref());
        prop_assert_eq!(actual.metadata().is_delegable(), expected.delegable);
        prop_assert!(state.is_held_by(&subject_id(expected.owner), &id));
        prop_assert_eq!(state.is_revoked(&id), expected.revoked);

        let registered_subject = state
            .subject(&subject_id(expected.owner))
            .ok_or_else(|| TestCaseError::fail("model owner must remain registered"))?;
        prop_assert!(
            registered_subject
                .envelope()
                .contains(actual.validity(), actual.authority())
        );

        if let Some(parent_id) = expected_parent {
            let parent = state
                .capability(&parent_id)
                .ok_or_else(|| TestCaseError::fail("model parent must remain issued"))?;
            prop_assert!(weaker_than(actual, parent));
        }

        for now in [9_u64, 30, 90] {
            prop_assert_eq!(
                state.is_effectively_active(&id, time(now)),
                model.chain_is_active(slot, now)
            );
        }

        let expected_authorization = model.chain_is_active(slot, 30);
        prop_assert_eq!(
            state.authorizes(
                &subject_id(expected.owner),
                &id,
                &request(expected.scope, 30),
            ),
            expected_authorization
        );
        let other_subject = (expected.owner + 1) % REGISTERED_SUBJECTS;
        prop_assert!(!state.authorizes(
            &subject_id(other_subject),
            &id,
            &request(expected.scope, 30),
        ));
    }

    Ok(())
}

// Requirement: every generated Derive/revoke sequence must refine the simple
// reference model and preserve all issuance invariants. Category: stateful PBT.
// Risk: critical. Mutation targets: omitted holder/delegable/parent/envelope/
// ancestor checks, non-monotone revoke, and reused or skipped successful IDs.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn generated_transitions_match_the_reference_model(
        commands in prop::collection::vec(command_strategy(), 1..64),
    ) {
        let mut state = state_with_root();
        let mut model = ReferenceModel::new();

        for command in commands {
            match command {
                Command::Derive {
                    caller,
                    parent_slot,
                    target,
                    scope,
                    validity,
                    delegable,
                    now,
                } => {
                    let expected = model.can_derive(
                        caller,
                        parent_slot,
                        target,
                        scope,
                        validity,
                        now,
                    );
                    let result = state.derive(
                        &subject_id(caller),
                        &capability_id(parent_slot),
                        grant(target, scope, validity, delegable),
                        time(now),
                    );

                    prop_assert_eq!(result.is_ok(), expected);
                    if expected {
                        let expected_slot = model.derive(
                            target,
                            parent_slot,
                            scope,
                            validity,
                            delegable,
                        );
                        prop_assert_eq!(
                            result.expect("expected successful Derive result"),
                            capability_id(expected_slot)
                        );
                    }
                }
                Command::Revoke { slot } => {
                    let expected = model.capabilities.contains_key(&slot);
                    let result = state.revoke(&capability_id(slot));

                    prop_assert_eq!(result.is_ok(), expected);
                    if let Some(capability) = model.capabilities.get_mut(&slot) {
                        capability.revoked = true;
                    }
                }
            }

            assert_invariants(&state, &model)?;
        }
    }
}
