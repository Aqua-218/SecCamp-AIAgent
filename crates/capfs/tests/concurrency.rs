//! Bounded concurrency contracts for namespace mutations and capability revoke.
//!
//! Specification: `docs/design/implementation-plan.md`, phase 3; and
//! `docs/design/capfs.md`, "rename をどう閉じるか" and "revoke を page
//! cache に抜かせない". Coverage is limited to the in-memory namespace and
//! capability linearization boundary. Real FUSE mount behavior remains in
//! `read_only_fuse.rs`.

use std::{
    convert::Infallible,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use authority_core::{
    capability::{AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId},
    file::{FileAuthority, FileEffect, FileEffects, FileRequest},
    handle::{HandleId, ObjectId, OpenHandle},
    kernel::{CapabilityKernel, EffectCommitError},
    path::{CanonicalPath, PathPattern},
    repository::RepoId,
    state::{CapabilityGrant, CapabilityState, RevocationStatus, StaticAuthorityEnvelope, Subject},
    time::{MonotonicTime, TimeWindow},
};
use capfs::namespace::{NamespaceObjectKind, NamespaceOperationError, NamespaceRegistry};

const RACE_ROUNDS: usize = 32;

struct AuthorityFixture {
    kernel: Arc<CapabilityKernel>,
    subject: SubjectId,
    capability: CapId,
    repository: RepoId,
}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("test paths must be canonical")
}

fn authority_fixture() -> AuthorityFixture {
    let repository = RepoId::new("workspace");
    let subject = SubjectId::new("bounded-race-subject");
    let validity = TimeWindow::new(MonotonicTime::from_ticks(0), MonotonicTime::from_ticks(10))
        .expect("test validity must be non-empty");
    let effects = FileEffects::from_effects([
        FileEffect::ReadData,
        FileEffect::WriteData,
        FileEffect::RemoveFile,
        FileEffect::Rename,
    ]);
    let authority = AuthorityBody::File(FileAuthority::new(
        repository.clone(),
        effects,
        PathPattern::Prefix(CanonicalPath::root()),
    ));
    let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
        "bounded-race-issuer",
    ))));
    kernel
        .register_subject(Subject::new(
            subject.clone(),
            StaticAuthorityEnvelope::new(validity, authority.clone()),
        ))
        .expect("test subject registration must succeed");
    let capability = kernel
        .issue_root(CapabilityGrant::new(subject.clone(), validity, authority))
        .expect("test capability issuance must succeed");

    AuthorityFixture {
        kernel,
        subject,
        capability,
        repository,
    }
}

fn request(repository: &RepoId, effect: FileEffect, path: CanonicalPath) -> CapabilityRequest {
    CapabilityRequest::new(
        MonotonicTime::from_ticks(5),
        AuthorityRequest::File(FileRequest::new(repository.clone(), effect, path)),
    )
}

fn authorize_effect(
    fixture: &AuthorityFixture,
    capability_path: CanonicalPath,
    effect: FileEffect,
    commit: impl FnOnce() -> Result<(), Infallible>,
) -> Result<(), EffectCommitError<Infallible>> {
    let request = request(&fixture.repository, effect, capability_path);
    fixture
        .kernel
        .authorize_and_commit(&fixture.subject, &fixture.capability, &request, |_| {
            commit()
        })
}

fn fresh_namespace() -> (NamespaceRegistry, ObjectId) {
    let registry = NamespaceRegistry::new();
    let object = registry
        .create_object(
            path(&["entry.txt"]),
            NamespaceObjectKind::RegularFile,
            |_| Ok::<_, Infallible>(()),
        )
        .expect("test file should be creatable")
        .object()
        .clone();
    (registry, object)
}

type NamespaceEffectResult = Result<(), NamespaceOperationError<EffectCommitError<Infallible>>>;
type NamespaceCloseResult = Result<(), NamespaceOperationError<()>>;

struct RaceCounters {
    write_commits: Arc<AtomicUsize>,
    rename_commits: Arc<AtomicUsize>,
    unlink_commits: Arc<AtomicUsize>,
    revoke_returned: Arc<AtomicBool>,
    post_revoke_commit: Arc<AtomicBool>,
}

impl RaceCounters {
    fn new() -> Self {
        Self {
            write_commits: Arc::new(AtomicUsize::new(0)),
            rename_commits: Arc::new(AtomicUsize::new(0)),
            unlink_commits: Arc::new(AtomicUsize::new(0)),
            revoke_returned: Arc::new(AtomicBool::new(false)),
            post_revoke_commit: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct RaceBarriers {
    write_started: Arc<Barrier>,
    write_release: Arc<Barrier>,
    racers_ready: Arc<Barrier>,
}

impl RaceBarriers {
    fn new() -> Self {
        Self {
            write_started: Arc::new(Barrier::new(2)),
            write_release: Arc::new(Barrier::new(2)),
            racers_ready: Arc::new(Barrier::new(5)),
        }
    }
}

struct RaceRound {
    fixture: Arc<AuthorityFixture>,
    registry: Arc<NamespaceRegistry>,
    object: ObjectId,
    handle_id: HandleId,
    counters: RaceCounters,
    barriers: RaceBarriers,
}

impl RaceRound {
    fn new(round: usize) -> Self {
        let fixture = Arc::new(authority_fixture());
        let (registry, object) = fresh_namespace();
        let registry = Arc::new(registry);
        let handle_id = HandleId::new(format!("bounded-race-handle-{round}"));
        fixture
            .kernel
            .register_open_handle(OpenHandle::new(
                handle_id.clone(),
                fixture.subject.clone(),
                object.clone(),
            ))
            .expect("test open handle registration must succeed");
        registry
            .open_object(&object, |record| {
                authorize_effect(
                    &fixture,
                    record.path().clone(),
                    FileEffect::ReadData,
                    || Ok(()),
                )
            })
            .expect("the initial open must be authorized");

        Self {
            fixture,
            registry,
            object,
            handle_id,
            counters: RaceCounters::new(),
            barriers: RaceBarriers::new(),
        }
    }

    fn spawn_writer(&self) -> thread::JoinHandle<NamespaceEffectResult> {
        let registry = Arc::clone(&self.registry);
        let fixture = Arc::clone(&self.fixture);
        let object = self.object.clone();
        let started = Arc::clone(&self.barriers.write_started);
        let release = Arc::clone(&self.barriers.write_release);
        let commits = Arc::clone(&self.counters.write_commits);
        let revoke_returned = Arc::clone(&self.counters.revoke_returned);
        let post_revoke = Arc::clone(&self.counters.post_revoke_commit);
        thread::spawn(move || {
            registry.with_object(&object, |record| {
                authorize_effect(
                    &fixture,
                    record.path().clone(),
                    FileEffect::WriteData,
                    || {
                        started.wait();
                        release.wait();
                        if revoke_returned.load(Ordering::Acquire) {
                            post_revoke.store(true, Ordering::Release);
                        }
                        commits.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    },
                )
            })
        })
    }

    fn spawn_closer(&self) -> thread::JoinHandle<NamespaceCloseResult> {
        let registry = Arc::clone(&self.registry);
        let fixture = Arc::clone(&self.fixture);
        let object = self.object.clone();
        let handle_id = self.handle_id.clone();
        let ready = Arc::clone(&self.barriers.racers_ready);
        thread::spawn(move || {
            ready.wait();
            registry.close_object(&object, |_| {
                fixture
                    .kernel
                    .close_handle(&fixture.subject, &handle_id)
                    .map(|_| ())
                    .map_err(|_| ())
            })
        })
    }

    fn spawn_renamer(&self) -> thread::JoinHandle<NamespaceEffectResult> {
        let registry = Arc::clone(&self.registry);
        let fixture = Arc::clone(&self.fixture);
        let ready = Arc::clone(&self.barriers.racers_ready);
        let commits = Arc::clone(&self.counters.rename_commits);
        let revoke_returned = Arc::clone(&self.counters.revoke_returned);
        let post_revoke = Arc::clone(&self.counters.post_revoke_commit);
        thread::spawn(move || {
            ready.wait();
            registry.rename_subtree(&path(&["entry.txt"]), path(&["moved.txt"]), |plan| {
                authorize_effect(&fixture, plan.source().clone(), FileEffect::Rename, || {
                    if revoke_returned.load(Ordering::Acquire) {
                        post_revoke.store(true, Ordering::Release);
                    }
                    commits.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                })
            })
        })
    }

    fn spawn_unlinker(&self) -> thread::JoinHandle<NamespaceEffectResult> {
        let registry = Arc::clone(&self.registry);
        let fixture = Arc::clone(&self.fixture);
        let object = self.object.clone();
        let ready = Arc::clone(&self.barriers.racers_ready);
        let commits = Arc::clone(&self.counters.unlink_commits);
        let revoke_returned = Arc::clone(&self.counters.revoke_returned);
        let post_revoke = Arc::clone(&self.counters.post_revoke_commit);
        thread::spawn(move || {
            ready.wait();
            registry.remove_object(&object, |record| {
                authorize_effect(
                    &fixture,
                    record.path().clone(),
                    FileEffect::RemoveFile,
                    || {
                        if revoke_returned.load(Ordering::Acquire) {
                            post_revoke.store(true, Ordering::Release);
                        }
                        commits.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    },
                )
            })
        })
    }

    fn spawn_revoker(&self) -> thread::JoinHandle<RevocationStatus> {
        let fixture = Arc::clone(&self.fixture);
        let ready = Arc::clone(&self.barriers.racers_ready);
        let returned = Arc::clone(&self.counters.revoke_returned);
        thread::spawn(move || {
            ready.wait();
            let result = fixture
                .kernel
                .revoke(&fixture.capability)
                .expect("test capability revoke must succeed");
            returned.store(true, Ordering::Release);
            result
        })
    }

    fn run(self) {
        let writer = self.spawn_writer();
        self.barriers.write_started.wait();
        let closer = self.spawn_closer();
        let renamer = self.spawn_renamer();
        let unlinker = self.spawn_unlinker();
        let revoker = self.spawn_revoker();
        self.barriers.racers_ready.wait();
        self.barriers.write_release.wait();

        assert_eq!(
            writer.join().expect("writer must not panic"),
            Ok(()),
            "the write must commit before the competing revoke can return"
        );
        closer
            .join()
            .expect("close worker must not panic")
            .expect("the one live open handle must close exactly once");
        let rename_result = renamer.join().expect("rename worker must not panic");
        let unlink_result = unlinker.join().expect("unlink worker must not panic");
        assert!(
            matches!(
                revoker.join().expect("revoke worker must not panic"),
                RevocationStatus::NewlyRevoked
            ),
            "the bounded race must revoke the capability exactly once"
        );

        let write_commits = self.counters.write_commits.load(Ordering::Acquire);
        let rename_commits = self.counters.rename_commits.load(Ordering::Acquire);
        let unlink_commits = self.counters.unlink_commits.load(Ordering::Acquire);
        assert_eq!(write_commits, 1);
        assert!(rename_commits <= 1);
        assert!(unlink_commits <= 1);
        assert!(
            !self.counters.post_revoke_commit.load(Ordering::Acquire),
            "no filesystem effect may reach its executor after revoke returns"
        );
        assert_eq!(
            self.fixture
                .kernel
                .object_open_handle_count(&self.object)
                .expect("authority handle state must remain readable"),
            0,
            "close must retire the authority handle even when revoke races it"
        );
        let committed_effects = self
            .fixture
            .kernel
            .effect_records()
            .expect("audit effect state must remain readable");
        assert_eq!(
            committed_effects.len(),
            2 + rename_commits + unlink_commits,
            "one open, one write, and only committed mutations may appear in the effect journal"
        );

        let snapshot = self
            .registry
            .object_snapshot(&self.object)
            .expect("namespace state must remain readable after the race");
        if unlink_result.is_ok() {
            assert!(
                snapshot.is_none(),
                "successful unlink must remove the object"
            );
        } else if rename_result.is_ok() {
            assert_eq!(
                snapshot
                    .expect("a successful rename without unlink must keep the object")
                    .path(),
                &path(&["moved.txt"])
            );
        } else {
            assert_eq!(
                snapshot
                    .expect("a rejected mutation must leave the object live")
                    .path(),
                &path(&["entry.txt"])
            );
        }
    }
}

// Requirement: an authorized write that reaches its linearization point must
// finish before revoke returns, while later mutations cannot commit through
// the revoked capability. Category: bounded concurrency/security. Risk: critical.
#[test]
fn bounded_write_revoke_open_close_rename_unlink_race_is_linearizable() {
    for round in 0..RACE_ROUNDS {
        RaceRound::new(round).run();
    }
}

// Requirement: a completed revoke must reject open and mutation attempts
// before their backing executors are entered, and failed open must roll back
// the namespace open count. Category: rejection/security. Risk: critical.
#[test]
fn revoke_before_open_rename_and_unlink_fails_closed_without_executor_calls() {
    let fixture = authority_fixture();
    let (registry, object) = fresh_namespace();
    let registry = Arc::new(registry);
    let object_path = path(&["entry.txt"]);
    let rename_path = path(&["moved.txt"]);
    fixture
        .kernel
        .revoke(&fixture.capability)
        .expect("test capability revoke must succeed");

    let open_executor_calls = AtomicUsize::new(0);
    let open_result = registry.open_object(&object, |record| {
        authorize_effect(
            &fixture,
            record.path().clone(),
            FileEffect::ReadData,
            || {
                open_executor_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
    });
    assert!(open_result.is_err(), "revoked open must be rejected");
    assert_eq!(open_executor_calls.load(Ordering::Acquire), 0);
    assert_eq!(
        registry
            .object_snapshot(&object)
            .expect("namespace lookup must succeed")
            .expect("the rejected open must keep the object live")
            .open_handle_count(),
        0,
        "rejected open must roll back its provisional namespace count"
    );

    let rename_executor_calls = AtomicUsize::new(0);
    let rename_result = registry.rename_subtree(&object_path, rename_path, |plan| {
        authorize_effect(&fixture, plan.source().clone(), FileEffect::Rename, || {
            rename_executor_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    });
    assert!(rename_result.is_err(), "revoked rename must be rejected");
    assert_eq!(rename_executor_calls.load(Ordering::Acquire), 0);

    let unlink_executor_calls = AtomicUsize::new(0);
    let unlink_result = registry.remove_object(&object, |record| {
        authorize_effect(
            &fixture,
            record.path().clone(),
            FileEffect::RemoveFile,
            || {
                unlink_executor_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
    });
    assert!(unlink_result.is_err(), "revoked unlink must be rejected");
    assert_eq!(unlink_executor_calls.load(Ordering::Acquire), 0);
    assert!(
        registry
            .object_at_path_snapshot(&object_path)
            .expect("namespace lookup must succeed")
            .is_some(),
        "failed mutations must leave the original path published"
    );
}
