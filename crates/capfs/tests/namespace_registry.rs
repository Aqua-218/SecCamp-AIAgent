//! Contract tests for the VM-wide link-free namespace registry.

use std::{
    convert::Infallible,
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use authority_core::{handle::ObjectId, path::CanonicalPath};
use capfs::namespace::{
    NamespaceError, NamespaceGeneration, NamespaceObjectKind, NamespaceOperationError,
    NamespaceRegistry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackingFailure;

impl fmt::Display for BackingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backing operation stopped before commit")
    }
}

impl Error for BackingFailure {}

fn path(segments: &[&str]) -> CanonicalPath {
    CanonicalPath::new(segments).expect("test paths must be canonical")
}

fn create_object(
    registry: &NamespaceRegistry,
    object_path: CanonicalPath,
    kind: NamespaceObjectKind,
) -> ObjectId {
    registry
        .create_object(object_path, kind, |_| Ok::<_, Infallible>(()))
        .expect("test namespace object should be creatable")
        .object()
        .clone()
}

struct SourceTree {
    registry: NamespaceRegistry,
    parser: ObjectId,
    lexer: ObjectId,
}

fn registry_with_source_tree() -> SourceTree {
    let registry = NamespaceRegistry::new();
    create_object(&registry, path(&["src"]), NamespaceObjectKind::Directory);
    let parser = create_object(
        &registry,
        path(&["src", "parser"]),
        NamespaceObjectKind::Directory,
    );
    let lexer = create_object(
        &registry,
        path(&["src", "parser", "lexer.rs"]),
        NamespaceObjectKind::RegularFile,
    );
    create_object(&registry, path(&["lib"]), NamespaceObjectKind::Directory);
    SourceTree {
        registry,
        parser,
        lexer,
    }
}

// Requirement: every live object has exactly one canonical path, and object
// identities come only from the registry. Category: namespace/security. Risk: critical.
#[test]
fn registry_enforces_unique_paths_parents_and_object_ids() {
    let registry = NamespaceRegistry::new();
    let source_path = path(&["src"]);

    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(0)
    );
    let creation = registry
        .create_object(
            source_path.clone(),
            NamespaceObjectKind::Directory,
            |object| {
                assert_eq!(object.path(), &source_path);
                Ok::<_, Infallible>("created")
            },
        )
        .expect("source directory should be created");
    let source_id = creation.object().clone();
    assert_eq!(creation.value(), &"created");
    assert_eq!(registry.object_count(), Ok(2));
    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(1)
    );
    assert_eq!(
        registry
            .object_at_path_snapshot(&source_path)
            .map(|object| object.map(|record| record.id().clone())),
        Ok(Some(source_id.clone()))
    );

    assert_eq!(
        registry.create_object(
            source_path.clone(),
            NamespaceObjectKind::Directory,
            |_| Ok::<_, Infallible>(()),
        ),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::PathOccupied(source_path.clone())
        ))
    );
    assert_eq!(
        registry.create_object(
            path(&["missing", "orphan"]),
            NamespaceObjectKind::RegularFile,
            |_| Ok::<_, Infallible>(()),
        ),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::MissingParent(path(&["missing"]))
        ))
    );

    create_object(&registry, path(&["file"]), NamespaceObjectKind::RegularFile);
    assert_eq!(
        registry.create_object(
            path(&["file", "child"]),
            NamespaceObjectKind::RegularFile,
            |_| Ok::<_, Infallible>(()),
        ),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::ParentNotDirectory(path(&["file"]))
        ))
    );
}

// Requirement: executor failures never publish new objects or consume their IDs.
// Category: namespace/atomicity. Risk: critical.
#[test]
fn failed_create_leaves_generation_and_identity_unmodified() {
    let registry = NamespaceRegistry::new();
    let object_path = path(&["file"]);
    let mut failed_object = None;

    assert_eq!(
        registry.create_object(
            object_path.clone(),
            NamespaceObjectKind::RegularFile,
            |object| {
                failed_object = Some(object.id().clone());
                Err::<(), _>(BackingFailure)
            },
        ),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(0)
    );
    let failed_object = failed_object.expect("failed executor should observe the staged object");
    assert_eq!(registry.object_snapshot(&failed_object), Ok(None));
    let creation = registry
        .create_object(object_path, NamespaceObjectKind::RegularFile, |_| {
            Ok::<_, Infallible>(())
        })
        .expect("a later create should succeed");
    assert_eq!(creation.object(), &failed_object);
    assert!(
        registry
            .object_snapshot(creation.object())
            .is_ok_and(|value| value.is_some())
    );
}

// Requirement: any live handle in a subtree blocks rename and removal, while
// failed open/close executors roll counts back. Category: namespace/security. Risk: critical.
#[test]
fn live_handles_block_namespace_mutation_and_counts_roll_back() {
    let SourceTree {
        registry, lexer, ..
    } = registry_with_source_tree();
    let source = path(&["src"]);
    let generation_before_open = registry.generation().expect("registry should be readable");

    assert_eq!(
        registry.open_object(&lexer, |_| Err::<(), _>(BackingFailure)),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(
        registry
            .object_snapshot(&lexer)
            .map(|object| object.map(|record| record.open_handle_count())),
        Ok(Some(0))
    );
    registry
        .open_object(&lexer, |_| Ok::<_, Infallible>(()))
        .expect("backing open should increment the count");
    assert_eq!(registry.generation(), Ok(generation_before_open));

    let rename_executor_called = AtomicBool::new(false);
    assert_eq!(
        registry.rename_subtree(&source, path(&["lib", "source"]), |_| {
            rename_executor_called.store(true, Ordering::SeqCst);
            Ok::<_, Infallible>(())
        }),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::OpenHandleInSubtree(lexer.clone())
        ))
    );
    assert!(!rename_executor_called.load(Ordering::SeqCst));
    assert_eq!(
        registry.remove_object(&lexer, |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::OpenHandleInSubtree(lexer.clone())
        ))
    );

    assert_eq!(
        registry.close_object(&lexer, |_| Err::<(), _>(BackingFailure)),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(
        registry
            .object_snapshot(&lexer)
            .map(|object| object.map(|record| record.open_handle_count())),
        Ok(Some(1))
    );
    registry
        .close_object(&lexer, |_| Ok::<_, Infallible>(()))
        .expect("successful close should decrement the count");
    assert_eq!(
        registry.close_object(&lexer, |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::NoOpenHandle(lexer)
        ))
    );
}

// Requirement: subtree rename rebases every descendant only after a successful
// no-replace backing operation. Category: namespace/atomicity. Risk: critical.
#[test]
fn rename_subtree_is_no_replace_and_failure_atomic() {
    let SourceTree {
        registry, lexer, ..
    } = registry_with_source_tree();
    let source = path(&["src", "parser"]);
    let destination = path(&["lib", "parser"]);
    let generation = registry.generation().expect("registry should be readable");

    assert_eq!(
        registry.rename_subtree(&source, destination.clone(), |plan| {
            assert_eq!(plan.source(), &source);
            assert_eq!(plan.destination(), &destination);
            assert_eq!(plan.moved_objects().len(), 2);
            Err::<(), _>(BackingFailure)
        }),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(registry.generation(), Ok(generation));
    assert_eq!(
        registry
            .object_snapshot(&lexer)
            .map(|object| object.map(|record| record.path().clone())),
        Ok(Some(path(&["src", "parser", "lexer.rs"])))
    );

    registry
        .rename_subtree(&source, destination.clone(), |_| Ok::<_, Infallible>(()))
        .expect("closed subtree should rename");
    assert_eq!(
        registry
            .object_snapshot(&lexer)
            .map(|object| object.map(|record| record.path().clone())),
        Ok(Some(path(&["lib", "parser", "lexer.rs"])))
    );
    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(generation.as_u64() + 1)
    );
    assert_eq!(
        registry.rename_subtree(&destination, path(&["lib"]), |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::PathOccupied(path(&["lib"]))
        ))
    );
    assert_eq!(
        registry.rename_subtree(&destination, path(&["lib", "parser", "nested"]), |_| {
            Ok::<(), Infallible>(())
        }),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::DestinationInsideSource
        ))
    );
    assert_eq!(
        registry.rename_subtree(&CanonicalPath::root(), path(&["new-root"]), |_| {
            Ok::<(), Infallible>(())
        }),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::CannotModifyRoot
        ))
    );
}

// Requirement: remove accepts only empty, unopened non-root objects and never
// releases an ObjectId for reuse. Category: namespace/security. Risk: critical.
#[test]
fn remove_requires_an_empty_object_and_reserves_deleted_ids() {
    let SourceTree {
        registry,
        parser,
        lexer,
    } = registry_with_source_tree();

    assert_eq!(
        registry.remove_object(&parser, |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::DirectoryNotEmpty(parser.clone())
        ))
    );
    let generation_before_failure = registry.generation().expect("registry should be readable");
    assert_eq!(
        registry.remove_object(&lexer, |_| Err::<(), _>(BackingFailure)),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(registry.generation(), Ok(generation_before_failure));
    assert!(
        registry
            .object_snapshot(&lexer)
            .is_ok_and(|object| object.is_some())
    );
    registry
        .remove_object(&lexer, |_| Ok::<_, Infallible>(()))
        .expect("leaf file should be removable");
    registry
        .remove_object(&parser, |_| Ok::<_, Infallible>(()))
        .expect("empty directory should be removable");
    assert_eq!(registry.object_snapshot(&lexer), Ok(None));
    let replacement = registry
        .create_object(
            path(&["lib", "replacement.rs"]),
            NamespaceObjectKind::RegularFile,
            |_| Ok::<_, Infallible>(()),
        )
        .expect("replacement file should be creatable")
        .object()
        .clone();
    assert_ne!(replacement, lexer);
    let root = registry
        .object_at_path_snapshot(&CanonicalPath::root())
        .expect("registry should be readable")
        .expect("root should remain live")
        .id()
        .clone();
    assert_eq!(
        registry.remove_object(&root, |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::CannotModifyRoot
        ))
    );
}

// Requirement: an object path stays stable from lookup through the backing
// linearization point. Category: namespace/concurrency. Risk: critical.
#[test]
fn object_operation_holds_read_lock_against_concurrent_rename() {
    let SourceTree {
        registry, lexer, ..
    } = registry_with_source_tree();
    let registry = Arc::new(registry);
    let source = path(&["src", "parser"]);
    let destination = path(&["lib", "parser"]);
    let (reader_entered_sender, reader_entered_receiver) = mpsc::channel();
    let (release_reader_sender, release_reader_receiver) = mpsc::channel();

    let reader_registry = Arc::clone(&registry);
    let reader = thread::spawn(move || {
        reader_registry.with_object(&lexer, |object| {
            assert_eq!(object.path(), &path(&["src", "parser", "lexer.rs"]));
            reader_entered_sender
                .send(())
                .expect("test should observe the held read lock");
            release_reader_receiver
                .recv()
                .expect("test should release the reader");
            Ok::<_, Infallible>(())
        })
    });
    reader_entered_receiver
        .recv()
        .expect("reader should enter its operation");

    let writer_registry = Arc::clone(&registry);
    let (writer_done_sender, writer_done_receiver) = mpsc::channel();
    let writer = thread::spawn(move || {
        let result =
            writer_registry.rename_subtree(&source, destination, |_| Ok::<_, Infallible>(()));
        writer_done_sender
            .send(result)
            .expect("test should receive the writer result");
    });

    assert!(
        writer_done_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "rename must wait while the object path is in use"
    );
    release_reader_sender
        .send(())
        .expect("reader should be releasable");
    assert_eq!(
        reader.join().expect("reader thread should not panic"),
        Ok(())
    );
    assert_eq!(
        writer_done_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("writer should finish after the reader releases"),
        Ok(())
    );
    writer.join().expect("writer thread should not panic");
}
