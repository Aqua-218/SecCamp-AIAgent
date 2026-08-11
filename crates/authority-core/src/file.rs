//! File authority types, request semantics, and delegation decisions.

use crate::{
    path::{CanonicalPath, PathPattern, path_below, path_matches},
    repository::RepoId,
};

/// A filesystem effect that can be authorized independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FileEffect {
    /// Reads file contents.
    ReadData,
    /// Lists entries in a directory.
    ListDirectory,
    /// Writes file contents without truncating first.
    WriteData,
    /// Changes a file's length.
    Truncate,
    /// Creates a regular file.
    CreateFile,
    /// Creates a directory.
    CreateDirectory,
    /// Removes a regular file.
    RemoveFile,
    /// Removes a directory.
    RemoveDirectory,
    /// Renames a file or directory.
    Rename,
    /// Changes supported metadata such as mode or timestamps.
    SetMetadata,
}

impl FileEffect {
    const fn mask(self) -> u16 {
        1_u16 << (self as u8)
    }
}

/// A set of permitted file effects.
///
/// A private fixed-width bitset keeps the closed effect universe compact and
/// prevents callers from constructing bits that do not name a [`FileEffect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileEffects(u16);

impl FileEffects {
    /// Creates an effect set that permits no requests.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates an effect set containing exactly one effect.
    #[must_use]
    pub const fn only(effect: FileEffect) -> Self {
        Self(effect.mask())
    }

    /// Creates an effect set from the supplied effects.
    #[must_use]
    pub fn from_effects(effects: impl IntoIterator<Item = FileEffect>) -> Self {
        effects
            .into_iter()
            .fold(Self::empty(), |set, effect| Self(set.0 | effect.mask()))
    }

    /// Returns whether this set contains `effect`.
    #[must_use]
    pub const fn contains(self, effect: FileEffect) -> bool {
        self.0 & effect.mask() != 0
    }

    /// Returns whether this set contains no effects.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether every effect in this set is also in `parent`.
    #[must_use]
    pub const fn is_subset_of(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// The file operations permitted within one repository and path pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileAuthority {
    repository: RepoId,
    effects: FileEffects,
    path: PathPattern,
}

impl FileAuthority {
    /// Creates an immutable file authority body.
    #[must_use]
    pub const fn new(repository: RepoId, effects: FileEffects, path: PathPattern) -> Self {
        Self {
            repository,
            effects,
            path,
        }
    }

    /// Returns the repository governed by this authority.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }

    /// Returns the permitted effects.
    #[must_use]
    pub const fn effects(&self) -> FileEffects {
        self.effects
    }

    /// Returns the governed path pattern.
    #[must_use]
    pub const fn path(&self) -> &PathPattern {
        &self.path
    }
}

/// A single filesystem authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileRequest {
    repository: RepoId,
    effect: FileEffect,
    path: CanonicalPath,
}

impl FileRequest {
    /// Creates a request for one effect on one canonical path.
    #[must_use]
    pub const fn new(repository: RepoId, effect: FileEffect, path: CanonicalPath) -> Self {
        Self {
            repository,
            effect,
            path,
        }
    }

    /// Returns the target repository.
    #[must_use]
    pub const fn repository(&self) -> &RepoId {
        &self.repository
    }

    /// Returns the requested effect.
    #[must_use]
    pub const fn effect(&self) -> FileEffect {
        self.effect
    }

    /// Returns the target path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }
}

/// Returns whether `authority` permits `request`.
#[must_use]
pub fn file_matches(authority: &FileAuthority, request: &FileRequest) -> bool {
    authority.repository == request.repository
        && authority.effects.contains(request.effect)
        && path_matches(&authority.path, &request.path)
}

/// Returns whether `child` satisfies the structural file-delegation rule.
///
/// A successful decision guarantees that every request permitted by `child`
/// is also permitted by `parent`. The rule always requires exact repository
/// identity, effect-set inclusion, and path-pattern containment, including
/// when the child effect set is empty.
#[must_use]
pub fn file_body_below(child: &FileAuthority, parent: &FileAuthority) -> bool {
    child.repository == parent.repository
        && child.effects.is_subset_of(parent.effects)
        && path_below(&child.path, &parent.path)
}

#[cfg(test)]
mod tests {
    use super::{
        FileAuthority, FileEffect, FileEffects, FileRequest, file_body_below, file_matches,
    };
    use crate::{
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
    };

    fn repository(value: &str) -> RepoId {
        RepoId::new(value)
    }

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must contain valid segments")
    }

    fn effects(effects: &[FileEffect]) -> FileEffects {
        FileEffects::from_effects(effects.iter().copied())
    }

    #[test]
    fn file_effects_preserve_membership_and_ignore_duplicates() {
        let effects = FileEffects::from_effects([
            FileEffect::ReadData,
            FileEffect::WriteData,
            FileEffect::ReadData,
        ]);

        assert!(effects.contains(FileEffect::ReadData));
        assert!(effects.contains(FileEffect::WriteData));
        assert!(!effects.contains(FileEffect::Rename));
        assert!(!effects.is_empty());
        assert!(FileEffects::empty().is_empty());
    }

    #[test]
    fn file_effect_subset_handles_empty_equal_and_escalated_sets() {
        let read = FileEffects::only(FileEffect::ReadData);
        let read_write = effects(&[FileEffect::ReadData, FileEffect::WriteData]);

        assert!(FileEffects::empty().is_subset_of(read));
        assert!(read.is_subset_of(read));
        assert!(read.is_subset_of(read_write));
        assert!(!read_write.is_subset_of(read));
    }

    #[test]
    fn file_matches_requires_repository_effect_and_path() {
        let authority = FileAuthority::new(
            repository("workspace"),
            effects(&[FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Prefix(path(&["src"])),
        );
        let cases = [
            (
                FileRequest::new(
                    repository("workspace"),
                    FileEffect::ReadData,
                    path(&["src", "main.rs"]),
                ),
                true,
            ),
            (
                FileRequest::new(
                    repository("workspace"),
                    FileEffect::WriteData,
                    path(&["src"]),
                ),
                true,
            ),
            (
                FileRequest::new(
                    repository("workspace"),
                    FileEffect::Rename,
                    path(&["src", "main.rs"]),
                ),
                false,
            ),
            (
                FileRequest::new(
                    repository("other"),
                    FileEffect::ReadData,
                    path(&["src", "main.rs"]),
                ),
                false,
            ),
            (
                FileRequest::new(
                    repository("workspace"),
                    FileEffect::ReadData,
                    path(&["docs", "design.md"]),
                ),
                false,
            ),
        ];

        for (request, expected) in cases {
            assert_eq!(file_matches(&authority, &request), expected);
        }
    }

    #[test]
    fn file_body_below_enforces_all_three_authority_dimensions() {
        let parent = FileAuthority::new(
            repository("workspace"),
            effects(&[FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Prefix(path(&["src"])),
        );
        let cases = [
            (
                FileAuthority::new(
                    repository("workspace"),
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Exact(path(&["src", "main.rs"])),
                ),
                true,
            ),
            (
                FileAuthority::new(
                    repository("workspace"),
                    effects(&[FileEffect::ReadData, FileEffect::Rename]),
                    PathPattern::Exact(path(&["src", "main.rs"])),
                ),
                false,
            ),
            (
                FileAuthority::new(
                    repository("other"),
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Exact(path(&["src", "main.rs"])),
                ),
                false,
            ),
            (
                FileAuthority::new(
                    repository("workspace"),
                    FileEffects::only(FileEffect::ReadData),
                    PathPattern::Prefix(CanonicalPath::root()),
                ),
                false,
            ),
        ];

        assert!(file_body_below(&parent, &parent));
        for (child, expected) in cases {
            assert_eq!(file_body_below(&child, &parent), expected);
        }
    }

    #[test]
    fn file_body_below_is_transitive() {
        let leaf = FileAuthority::new(
            repository("workspace"),
            FileEffects::only(FileEffect::ReadData),
            PathPattern::Exact(path(&["src", "parser", "lexer.rs"])),
        );
        let parser = FileAuthority::new(
            repository("workspace"),
            effects(&[FileEffect::ReadData, FileEffect::WriteData]),
            PathPattern::Prefix(path(&["src", "parser"])),
        );
        let source = FileAuthority::new(
            repository("workspace"),
            effects(&[
                FileEffect::ReadData,
                FileEffect::WriteData,
                FileEffect::Rename,
            ]),
            PathPattern::Prefix(path(&["src"])),
        );

        assert!(file_body_below(&leaf, &parser));
        assert!(file_body_below(&parser, &source));
        assert!(file_body_below(&leaf, &source));
    }
}
