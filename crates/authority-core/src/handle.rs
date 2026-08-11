//! Session-local identities and records for open filesystem handles.

use std::fmt;

use crate::capability::SubjectId;

/// An opaque handle identity assigned by the trusted filesystem adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandleId(String);

impl HandleId {
    /// Creates a handle identity from its adapter-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying adapter-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HandleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An opaque identity for one object in the shared namespace registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(String);

impl ObjectId {
    /// Creates an object identity from its registry-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying registry-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A live handle bound to its authenticated subject and namespace object.
///
/// The handle carries no cached authority. Every read, write, or metadata
/// operation must be reauthorized against the object's current canonical path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpenHandle {
    id: HandleId,
    subject: SubjectId,
    object: ObjectId,
}

impl OpenHandle {
    /// Creates a handle record after the backing open has succeeded.
    #[must_use]
    pub const fn new(id: HandleId, subject: SubjectId, object: ObjectId) -> Self {
        Self {
            id,
            subject,
            object,
        }
    }

    /// Returns the session-local handle identity.
    #[must_use]
    pub const fn id(&self) -> &HandleId {
        &self.id
    }

    /// Returns the authenticated subject that owns this handle.
    #[must_use]
    pub const fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the shared namespace object referenced by this handle.
    #[must_use]
    pub const fn object(&self) -> &ObjectId {
        &self.object
    }
}

#[cfg(test)]
mod tests {
    use super::{HandleId, ObjectId, OpenHandle};
    use crate::capability::SubjectId;

    #[test]
    fn open_handle_preserves_typed_identities() {
        let handle = OpenHandle::new(
            HandleId::new("handle-7"),
            SubjectId::new("subject-reader"),
            ObjectId::new("object-42"),
        );

        assert_eq!(handle.id().as_str(), "handle-7");
        assert_eq!(handle.subject().as_str(), "subject-reader");
        assert_eq!(handle.object().as_str(), "object-42");
    }
}
