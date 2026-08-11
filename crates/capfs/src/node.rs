//! Subject-local FUSE node identities and lookup-reference accounting.

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    num::NonZeroU64,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use authority_core::{capability::SubjectId, handle::ObjectId};

const FIRST_DYNAMIC_NODE_SEQUENCE: u64 = 2;

/// A non-zero inode identity whose meaning is local to one FUSE mount.
///
/// Linux reserves value `1` for the root inode. Dynamic values are allocated
/// monotonically and never rebound during the mount's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(NonZeroU64);

impl NodeId {
    /// The root inode identity required by the FUSE protocol.
    pub const ROOT: Self = Self(NonZeroU64::MIN);

    /// Validates a raw node identity received from the FUSE protocol.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the raw FUSE node identity.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_u64().fmt(formatter)
    }
}

/// One live mount-local node binding and its outstanding LOOKUP references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBinding {
    node: NodeId,
    object: ObjectId,
    lookup_count: u64,
}

impl NodeBinding {
    const fn new(node: NodeId, object: ObjectId) -> Self {
        Self {
            node,
            object,
            lookup_count: 1,
        }
    }

    /// Returns the mount-local node identity.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the VM-wide namespace object identity.
    #[must_use]
    pub const fn object(&self) -> &ObjectId {
        &self.object
    }

    /// Returns the number of successful LOOKUP replies not yet forgotten.
    #[must_use]
    pub const fn lookup_count(&self) -> u64 {
        self.lookup_count
    }
}

/// The result of applying one FUSE FORGET request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgetOutcome {
    /// The node remains live with the returned reduced lookup count.
    Retained(NodeBinding),
    /// The final reference was forgotten and the object was removed from the table.
    Removed(ObjectId),
}

/// A rejected node lookup, allocation, or reference-count transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeTableError {
    /// The table lock was poisoned by a panicking writer.
    LockPoisoned,
    /// No live binding owns the supplied node identity.
    UnknownNode(NodeId),
    /// The monotone node identity sequence has no remaining values.
    NodeIdExhausted,
    /// Another LOOKUP reference would wrap the node's counter.
    LookupCountExhausted(NodeId),
    /// A FORGET request tried to discard more references than are live.
    ForgetCountExceedsLookupCount {
        /// The affected mount-local node.
        node: NodeId,
        /// The number of references supplied by the request.
        requested: u64,
        /// The number of references currently recorded.
        current: u64,
    },
    /// The pinned root mapping cannot enter the ordinary FORGET lifecycle.
    CannotForgetRoot,
    /// The forward and reverse node indexes disagree.
    InvariantViolation,
}

impl fmt::Display for NodeTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("node table lock is poisoned"),
            Self::UnknownNode(node) => write!(formatter, "node `{node}` is not live"),
            Self::NodeIdExhausted => {
                formatter.write_str("mount-local node ID sequence is exhausted")
            }
            Self::LookupCountExhausted(node) => {
                write!(
                    formatter,
                    "node `{node}` cannot accept another LOOKUP reference"
                )
            }
            Self::ForgetCountExceedsLookupCount {
                node,
                requested,
                current,
            } => write!(
                formatter,
                "node `{node}` cannot forget {requested} references while only {current} are live"
            ),
            Self::CannotForgetRoot => formatter.write_str("the root node cannot be forgotten"),
            Self::InvariantViolation => {
                formatter.write_str("node and object indexes are inconsistent")
            }
        }
    }
}

impl Error for NodeTableError {}

#[derive(Debug)]
struct NodeState {
    nodes: BTreeMap<NodeId, NodeBinding>,
    objects: HashMap<ObjectId, NodeId>,
    next_node_sequence: Option<u64>,
}

impl NodeState {
    fn new(root_object: ObjectId) -> Self {
        let root_binding = NodeBinding::new(NodeId::ROOT, root_object.clone());
        let mut nodes = BTreeMap::new();
        nodes.insert(NodeId::ROOT, root_binding);
        let mut objects = HashMap::new();
        objects.insert(root_object, NodeId::ROOT);
        Self {
            nodes,
            objects,
            next_node_sequence: Some(FIRST_DYNAMIC_NODE_SEQUENCE),
        }
    }

    fn allocate(&mut self, object: ObjectId) -> Result<NodeBinding, NodeTableError> {
        let sequence = self
            .next_node_sequence
            .ok_or(NodeTableError::NodeIdExhausted)?;
        let node = NodeId::new(sequence).ok_or(NodeTableError::InvariantViolation)?;
        if self.nodes.contains_key(&node) || self.objects.contains_key(&object) {
            return Err(NodeTableError::InvariantViolation);
        }

        let binding = NodeBinding::new(node, object.clone());
        self.next_node_sequence = sequence.checked_add(1);
        self.nodes.insert(node, binding.clone());
        self.objects.insert(object, node);
        Ok(binding)
    }
}

/// A concurrent `nodeid -> ObjectId` table owned by exactly one subject mount.
///
/// The table records an object only after the adapter has resolved a successful
/// name lookup against the shared namespace registry. Callers must therefore
/// hold the registry read guard through [`Self::remember_lookup`] so a concurrent
/// namespace mutation cannot publish a node for stale path state.
///
/// The root mapping is pinned at [`NodeId::ROOT`]. Other bindings remain live
/// until their LOOKUP reference count reaches zero. Retired node identities are
/// never reused, preventing delayed requests from being rebound to a new object.
#[derive(Debug)]
pub struct NodeTable {
    subject: SubjectId,
    state: RwLock<NodeState>,
}

impl NodeTable {
    /// Creates a table for one authenticated subject and imported root object.
    #[must_use]
    pub fn new(subject: SubjectId, root_object: ObjectId) -> Self {
        Self {
            subject,
            state: RwLock::new(NodeState::new(root_object)),
        }
    }

    /// Returns the subject whose mount owns every node in this table.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Records one successful FUSE LOOKUP reply for a namespace object.
    ///
    /// A live object keeps its current node identity and gains one lookup
    /// reference. The pinned root binding remains at count one. A retired
    /// object receives a fresh, strictly later node identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned, the lookup counter is
    /// exhausted, the node sequence is exhausted, or the indexes disagree.
    pub fn remember_lookup(&self, object: &ObjectId) -> Result<NodeBinding, NodeTableError> {
        let mut state = self.write_state()?;
        if let Some(node) = state.objects.get(object).copied() {
            let binding = state
                .nodes
                .get_mut(&node)
                .ok_or(NodeTableError::InvariantViolation)?;
            if binding.object != *object {
                return Err(NodeTableError::InvariantViolation);
            }
            if node != NodeId::ROOT {
                binding.lookup_count = binding
                    .lookup_count
                    .checked_add(1)
                    .ok_or(NodeTableError::LookupCountExhausted(node))?;
            }
            return Ok(binding.clone());
        }

        state.allocate(object.clone())
    }

    /// Resolves a mount-local node to its VM-wide namespace object identity.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTableError::UnknownNode`] for stale or foreign node values,
    /// or [`NodeTableError::LockPoisoned`] after a writer panic.
    pub fn resolve(&self, node: NodeId) -> Result<ObjectId, NodeTableError> {
        self.binding(node).map(|binding| binding.object)
    }

    /// Returns a point-in-time copy of one live node binding.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTableError::UnknownNode`] for stale or foreign node values,
    /// or [`NodeTableError::LockPoisoned`] after a writer panic.
    pub fn binding(&self, node: NodeId) -> Result<NodeBinding, NodeTableError> {
        self.read_state()?
            .nodes
            .get(&node)
            .cloned()
            .ok_or(NodeTableError::UnknownNode(node))
    }

    /// Applies a non-zero FUSE FORGET count to one ordinary node.
    ///
    /// The method rejects excessive counts without changing either index. When
    /// the final reference is removed, the node becomes permanently stale.
    ///
    /// # Errors
    ///
    /// Returns an error for root, stale nodes, excessive counts, poisoned state,
    /// or disagreement between the forward and reverse indexes.
    pub fn forget(&self, node: NodeId, count: NonZeroU64) -> Result<ForgetOutcome, NodeTableError> {
        if node == NodeId::ROOT {
            return Err(NodeTableError::CannotForgetRoot);
        }

        let mut state = self.write_state()?;
        let binding = state
            .nodes
            .get(&node)
            .cloned()
            .ok_or(NodeTableError::UnknownNode(node))?;
        let requested = count.get();
        if requested > binding.lookup_count {
            return Err(NodeTableError::ForgetCountExceedsLookupCount {
                node,
                requested,
                current: binding.lookup_count,
            });
        }
        if state.objects.get(&binding.object).copied() != Some(node) {
            return Err(NodeTableError::InvariantViolation);
        }

        if requested == binding.lookup_count {
            state.nodes.remove(&node);
            state.objects.remove(&binding.object);
            return Ok(ForgetOutcome::Removed(binding.object));
        }

        let retained = state
            .nodes
            .get_mut(&node)
            .ok_or(NodeTableError::InvariantViolation)?;
        retained.lookup_count -= requested;
        Ok(ForgetOutcome::Retained(retained.clone()))
    }

    /// Returns the root plus the number of ordinary live nodes.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTableError::LockPoisoned`] after a writer panic.
    pub fn node_count(&self) -> Result<usize, NodeTableError> {
        Ok(self.read_state()?.nodes.len())
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, NodeState>, NodeTableError> {
        self.state.read().map_err(|_| NodeTableError::LockPoisoned)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, NodeState>, NodeTableError> {
        self.state.write().map_err(|_| NodeTableError::LockPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{NodeId, NodeTable, NodeTableError};
    use authority_core::{capability::SubjectId, handle::ObjectId};

    fn table() -> NodeTable {
        NodeTable::new(SubjectId::new("subject"), ObjectId::new("root"))
    }

    #[test]
    fn node_sequence_accepts_its_last_value_then_rejects() {
        let table = table();
        table
            .state
            .write()
            .expect("test node table must be writable")
            .next_node_sequence = Some(u64::MAX);

        let last = table
            .remember_lookup(&ObjectId::new("last"))
            .expect("the final node ID should remain usable");
        assert_eq!(last.node().as_u64(), u64::MAX);
        assert_eq!(
            table.remember_lookup(&ObjectId::new("next")),
            Err(NodeTableError::NodeIdExhausted)
        );
        assert_eq!(table.node_count(), Ok(2));
    }

    #[test]
    fn lookup_count_exhaustion_preserves_the_live_binding() {
        let table = table();
        let object = ObjectId::new("object");
        let binding = table
            .remember_lookup(&object)
            .expect("test lookup should allocate a node");
        table
            .state
            .write()
            .expect("test node table must be writable")
            .nodes
            .get_mut(&binding.node())
            .expect("test node should remain live")
            .lookup_count = u64::MAX;

        assert_eq!(
            table.remember_lookup(&object),
            Err(NodeTableError::LookupCountExhausted(binding.node()))
        );
        assert_eq!(
            table
                .binding(binding.node())
                .map(|value| value.lookup_count()),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn writer_panic_poisons_every_later_node_operation() {
        let table = table();
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = table
                .state
                .write()
                .expect("test node table must initially be writable");
            panic!("simulated node writer panic");
        }));

        assert!(panic_result.is_err());
        assert_eq!(table.node_count(), Err(NodeTableError::LockPoisoned));
        assert_eq!(
            table.resolve(NodeId::ROOT),
            Err(NodeTableError::LockPoisoned)
        );
        assert_eq!(
            table.remember_lookup(&ObjectId::new("object")),
            Err(NodeTableError::LockPoisoned)
        );
    }
}
