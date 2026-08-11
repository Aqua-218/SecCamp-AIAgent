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

fn registry_with_source_tree() -> NamespaceRegistry {
    let registry = NamespaceRegistry::new(ObjectId::new("root"));
    registry
        .register_existing_object(
            ObjectId::new("src"),
            path(&["src"]),
            NamespaceObjectKind::Directory,
        )
        .expect("source directory should register");
    registry
        .register_existing_object(
            ObjectId::new("parser"),
            path(&["src", "parser"]),
            NamespaceObjectKind::Directory,
        )
        .expect("parser directory should register");
    registry
        .register_existing_object(
            ObjectId::new("lexer"),
            path(&["src", "parser", "lexer.rs"]),
            NamespaceObjectKind::RegularFile,
        )
        .expect("lexer file should register");
    registry
        .register_existing_object(
            ObjectId::new("lib"),
            path(&["lib"]),
            NamespaceObjectKind::Directory,
        )
        .expect("destination parent should register");
    registry
}

// Requirement: every live object has exactly one canonical path, and neither
// object IDs nor live paths can be reused. Category: namespace/security. Risk: critical.
#[test]
fn registry_enforces_unique_paths_parents_and_object_ids() {
    let registry = NamespaceRegistry::new(ObjectId::new("root"));
    let source_id = ObjectId::new("source");
    let source_path = path(&["src"]);

    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(0)
    );
    assert_eq!(
        registry.create_object(
            source_id.clone(),
            source_path.clone(),
            NamespaceObjectKind::Directory,
            |object| {
                assert_eq!(object.id(), &source_id);
                assert_eq!(object.path(), &source_path);
                Ok::<_, Infallible>("created")
            },
        ),
        Ok("created")
    );
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
        registry.register_existing_object(
            ObjectId::new("other"),
            source_path.clone(),
            NamespaceObjectKind::Directory,
        ),
        Err(NamespaceError::PathOccupied(source_path.clone()))
    );
    assert_eq!(
        registry.register_existing_object(
            source_id.clone(),
            path(&["other"]),
            NamespaceObjectKind::Directory,
        ),
        Err(NamespaceError::ObjectIdAlreadyIssued(source_id))
    );
    assert_eq!(
        registry.register_existing_object(
            ObjectId::new("orphan"),
            path(&["missing", "orphan"]),
            NamespaceObjectKind::RegularFile,
        ),
        Err(NamespaceError::MissingParent(path(&["missing"])))
    );

    registry
        .register_existing_object(
            ObjectId::new("file"),
            path(&["file"]),
            NamespaceObjectKind::RegularFile,
        )
        .expect("root may contain a regular file");
    assert_eq!(
        registry.register_existing_object(
            ObjectId::new("child"),
            path(&["file", "child"]),
            NamespaceObjectKind::RegularFile,
        ),
        Err(NamespaceError::ParentNotDirectory(path(&["file"])))
    );
}

// Requirement: executor failures never publish new objects or consume their IDs.
// Category: namespace/atomicity. Risk: critical.
#[test]
fn failed_create_leaves_generation_and_identity_unmodified() {
    let registry = NamespaceRegistry::new(ObjectId::new("root"));
    let object = ObjectId::new("file");
    let object_path = path(&["file"]);

    assert_eq!(
        registry.create_object(
            object.clone(),
            object_path.clone(),
            NamespaceObjectKind::RegularFile,
            |_| Err::<(), _>(BackingFailure),
        ),
        Err(NamespaceOperationError::Executor(BackingFailure))
    );
    assert_eq!(
        registry.generation().map(NamespaceGeneration::as_u64),
        Ok(0)
    );
    assert_eq!(registry.object_snapshot(&object), Ok(None));
    assert_eq!(
        registry.create_object(
            object.clone(),
            object_path,
            NamespaceObjectKind::RegularFile,
            |_| Ok::<_, Infallible>(()),
        ),
        Ok(())
    );
    assert!(
        registry
            .object_snapshot(&object)
            .is_ok_and(|value| value.is_some())
    );
}

// Requirement: any live handle in a subtree blocks rename and removal, while
// failed open/close executors roll counts back. Category: namespace/security. Risk: critical.
#[test]
fn live_handles_block_namespace_mutation_and_counts_roll_back() {
    let registry = registry_with_source_tree();
    let lexer = ObjectId::new("lexer");
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
    let registry = registry_with_source_tree();
    let source = path(&["src", "parser"]);
    let destination = path(&["lib", "parser"]);
    let lexer = ObjectId::new("lexer");
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
    let registry = registry_with_source_tree();
    let parser = ObjectId::new("parser");
    let lexer = ObjectId::new("lexer");

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
    assert_eq!(
        registry.register_existing_object(
            lexer.clone(),
            path(&["lib", "replacement.rs"]),
            NamespaceObjectKind::RegularFile,
        ),
        Err(NamespaceError::ObjectIdAlreadyIssued(lexer))
    );
    assert_eq!(
        registry.remove_object(&ObjectId::new("root"), |_| Ok::<_, Infallible>(())),
        Err(NamespaceOperationError::Namespace(
            NamespaceError::CannotModifyRoot
        ))
    );
}

// Requirement: an object path stays stable from lookup through the backing
// linearization point. Category: namespace/concurrency. Risk: critical.
#[test]
fn object_operation_holds_read_lock_against_concurrent_rename() {
    let registry = Arc::new(registry_with_source_tree());
    let lexer = ObjectId::new("lexer");
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
