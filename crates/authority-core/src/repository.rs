//! Typed identifiers for repositories governed by capabilities.

use std::fmt;

/// An opaque repository identity used for authority comparisons.
///
/// Repository names and filesystem paths are deliberately not interpreted
/// here. The session host assigns the identity, and authority decisions only
/// compare it for exact equality.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoId(String);

impl RepoId {
    /// Creates a repository identity from its host-assigned value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying host-assigned value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::RepoId;

    #[test]
    fn repository_id_preserves_opaque_host_value() {
        let repository = RepoId::new("session-7:repository-3");

        assert_eq!(repository.as_str(), "session-7:repository-3");
        assert_eq!(repository.to_string(), "session-7:repository-3");
    }
}
