//! Contract tests for subject-local FUSE node identity tables.

use std::{num::NonZeroU64, sync::Arc, thread};

use authority_core::{capability::SubjectId, handle::ObjectId};
use capfs::node::{ForgetOutcome, NodeId, NodeTable, NodeTableError};

fn lookup_count(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("test lookup counts must be non-zero")
}

// Requirement: FUSE_ROOT_ID always names the imported repository root and is
// outside the ordinary lookup/forget lifecycle. Category: identity/security. Risk: critical.
#[test]
fn root_node_is_pinned_to_the_mount_root_object() {
    let subject = SubjectId::new("subject-reader");
    let root_object = ObjectId::new("object-root");
    let table = NodeTable::new(subject.clone(), root_object.clone());

    assert_eq!(NodeId::ROOT.as_u64(), 1);
    assert_eq!(NodeId::new(0), None);
    assert_eq!(table.subject(), &subject);
    assert_eq!(table.resolve(NodeId::ROOT), Ok(root_object.clone()));
    assert_eq!(table.node_count(), Ok(1));

    let repeated_root = table
        .remember_lookup(&root_object)
        .expect("root lookup should preserve the pinned root binding");
    assert_eq!(repeated_root.node(), NodeId::ROOT);
    assert_eq!(repeated_root.lookup_count(), 1);
    assert_eq!(
        table.forget(NodeId::ROOT, lookup_count(1)),
        Err(NodeTableError::CannotForgetRoot)
    );
}

// Requirement: repeated LOOKUP returns one stable live node, FORGET retires it,
// and a retired node number is never rebound. Category: identity/security. Risk: critical.
#[test]
fn lookup_forget_and_relookup_never_reuse_a_node_id() {
    let table = NodeTable::new(SubjectId::new("subject-reader"), ObjectId::new("root"));
    let object = ObjectId::new("object-file");

    let first = table
        .remember_lookup(&object)
        .expect("first lookup should allocate a node");
    let repeated = table
        .remember_lookup(&object)
        .expect("repeated lookup should reuse the live node");
    assert_eq!(first.node(), repeated.node());
    assert_eq!(first.lookup_count(), 1);
    assert_eq!(repeated.lookup_count(), 2);
    assert_eq!(table.resolve(first.node()), Ok(object.clone()));

    let retained = table
        .forget(first.node(), lookup_count(1))
        .expect("partial forget should retain the node");
    let ForgetOutcome::Retained(retained) = retained else {
        panic!("partial forget must not remove the node");
    };
    assert_eq!(retained.node(), first.node());
    assert_eq!(retained.object(), &object);
    assert_eq!(retained.lookup_count(), 1);
    assert_eq!(
        table.forget(first.node(), lookup_count(1)),
        Ok(ForgetOutcome::Removed(object.clone()))
    );
    assert_eq!(
        table.resolve(first.node()),
        Err(NodeTableError::UnknownNode(first.node()))
    );

    let replacement = table
        .remember_lookup(&object)
        .expect("a later lookup should allocate a fresh node");
    assert_ne!(replacement.node(), first.node());
    assert!(replacement.node().as_u64() > first.node().as_u64());
}

// Requirement: a malformed excessive FORGET cannot discard a live mapping or
// reduce its reference count. Category: protocol/fail-closed. Risk: high.
#[test]
fn excessive_forget_is_rejected_without_mutation() {
    let table = NodeTable::new(SubjectId::new("subject-reader"), ObjectId::new("root"));
    let object = ObjectId::new("object-file");
    let binding = table
        .remember_lookup(&object)
        .expect("lookup should allocate a node");
    let node = binding.node();

    assert_eq!(
        table.forget(node, lookup_count(2)),
        Err(NodeTableError::ForgetCountExceedsLookupCount {
            node,
            requested: 2,
            current: 1,
        })
    );
    assert_eq!(table.binding(node), Ok(binding));
    assert_eq!(table.resolve(node), Ok(object));
}

// Requirement: node numbers have mount-local meaning even when two mounts
// happen to allocate the same number. Category: isolation/security. Risk: critical.
#[test]
fn separate_subject_tables_scope_equal_node_numbers_independently() {
    let reader = NodeTable::new(SubjectId::new("reader"), ObjectId::new("reader-root"));
    let writer = NodeTable::new(SubjectId::new("writer"), ObjectId::new("writer-root"));
    let reader_object = ObjectId::new("reader-object");
    let writer_object = ObjectId::new("writer-object");

    let reader_node = reader
        .remember_lookup(&reader_object)
        .expect("reader lookup should allocate a node")
        .node();
    let writer_node = writer
        .remember_lookup(&writer_object)
        .expect("writer lookup should allocate a node")
        .node();

    assert_eq!(reader_node, writer_node);
    assert_eq!(reader.resolve(reader_node), Ok(reader_object));
    assert_eq!(writer.resolve(writer_node), Ok(writer_object));
    assert_ne!(reader.subject(), writer.subject());
}

// Requirement: concurrent successful LOOKUP replies for one object publish one
// node and account for every kernel reference. Category: concurrency. Risk: high.
#[test]
fn concurrent_lookups_share_one_node_and_preserve_every_reference() {
    const LOOKUP_THREADS: usize = 32;

    let table = Arc::new(NodeTable::new(
        SubjectId::new("subject-reader"),
        ObjectId::new("root"),
    ));
    let object = ObjectId::new("object-file");
    let workers = (0..LOOKUP_THREADS)
        .map(|_| {
            let table = Arc::clone(&table);
            let object = object.clone();
            thread::spawn(move || {
                table
                    .remember_lookup(&object)
                    .expect("concurrent lookup should succeed")
                    .node()
            })
        })
        .collect::<Vec<_>>();

    let nodes = workers
        .into_iter()
        .map(|worker| worker.join().expect("lookup worker should not panic"))
        .collect::<Vec<_>>();
    assert!(nodes.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        table
            .binding(nodes[0])
            .map(|binding| binding.lookup_count()),
        Ok(LOOKUP_THREADS as u64)
    );
    assert_eq!(table.node_count(), Ok(2));
}
