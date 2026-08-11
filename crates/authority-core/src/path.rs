//! Canonical repository paths and path authority patterns.

use std::{error::Error, fmt};

/// A repository-relative path represented as validated segments.
///
/// The empty path denotes the repository root. Non-empty paths can only be
/// created when every segment is safe for capability comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalPath {
    segments: Vec<String>,
}

impl CanonicalPath {
    /// Creates the canonical path for the repository root.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Creates a canonical path from repository-relative segments.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPathSegment`] for the first segment that is empty,
    /// equals `.` or `..`, or contains `/`, NUL, or `*`.
    pub fn new<I, S>(segments: I) -> Result<Self, InvalidPathSegment>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let segments = segments
            .into_iter()
            .enumerate()
            .map(|(index, segment)| {
                let segment = segment.as_ref();
                validate_segment(index, segment)?;
                Ok(segment.to_owned())
            })
            .collect::<Result<Vec<_>, InvalidPathSegment>>()?;

        Ok(Self { segments })
    }

    /// Returns the validated path segments in order.
    #[must_use]
    pub const fn as_segments(&self) -> &[String] {
        self.segments.as_slice()
    }

    /// Returns whether this path denotes the repository root.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns the immediate parent, or `None` for the repository root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, parent_segments) = self.segments.split_last()?;
        Some(Self {
            segments: parent_segments.to_vec(),
        })
    }

    /// Returns whether this path equals or descends from `ancestor`.
    #[must_use]
    pub fn is_at_or_below(&self, ancestor: &Self) -> bool {
        self.segments.starts_with(&ancestor.segments)
    }

    /// Replaces `source` with `destination` while preserving the relative suffix.
    ///
    /// Returns `None` when this path is outside `source`.
    #[must_use]
    pub fn rebase(&self, source: &Self, destination: &Self) -> Option<Self> {
        let suffix = self.segments.strip_prefix(source.segments.as_slice())?;
        let mut segments = Vec::with_capacity(destination.segments.len() + suffix.len());
        segments.extend(destination.segments.iter().cloned());
        segments.extend(suffix.iter().cloned());
        Some(Self { segments })
    }
}

/// A path selector used by file authorities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathPattern {
    /// Selects exactly one canonical path.
    Exact(CanonicalPath),
    /// Selects a canonical path and every path below it.
    Prefix(CanonicalPath),
}

impl PathPattern {
    /// Returns the canonical path carried by this pattern.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        match self {
            Self::Exact(path) | Self::Prefix(path) => path,
        }
    }
}

/// Returns whether `pattern` selects `path`.
#[must_use]
pub fn path_matches(pattern: &PathPattern, path: &CanonicalPath) -> bool {
    match pattern {
        PathPattern::Exact(selected) => selected == path,
        PathPattern::Prefix(selected) => path.is_at_or_below(selected),
    }
}

/// Returns whether every path selected by `child` is also selected by `parent`.
///
/// An exact pattern can be below an equal exact pattern or a containing prefix.
/// A prefix pattern can only be below another prefix because it always includes
/// possible descendants beyond its own canonical path.
#[must_use]
pub fn path_below(child: &PathPattern, parent: &PathPattern) -> bool {
    match (child, parent) {
        (PathPattern::Exact(child), PathPattern::Exact(parent)) => child == parent,
        (PathPattern::Exact(child) | PathPattern::Prefix(child), PathPattern::Prefix(parent)) => {
            child.is_at_or_below(parent)
        }
        (PathPattern::Prefix(_), PathPattern::Exact(_)) => false,
    }
}

/// Describes why a repository path segment is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidPathSegmentReason {
    /// The segment is empty.
    Empty,
    /// The segment is `.`.
    CurrentDirectory,
    /// The segment is `..`.
    ParentDirectory,
    /// The segment contains `/`.
    ContainsSeparator,
    /// The segment contains a NUL character.
    ContainsNul,
    /// The segment contains `*`.
    ContainsWildcard,
}

impl fmt::Display for InvalidPathSegmentReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expectation = match self {
            Self::Empty => "must not be empty",
            Self::CurrentDirectory => "must not be `.`",
            Self::ParentDirectory => "must not be `..`",
            Self::ContainsSeparator => "must not contain `/`",
            Self::ContainsNul => "must not contain NUL",
            Self::ContainsWildcard => "must not contain `*`",
        };
        formatter.write_str(expectation)
    }
}

/// Reports the position and reason for an invalid repository path segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPathSegment {
    index: usize,
    reason: InvalidPathSegmentReason,
}

impl InvalidPathSegment {
    /// Returns the zero-based index of the invalid segment.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns why the segment is invalid.
    #[must_use]
    pub const fn reason(self) -> InvalidPathSegmentReason {
        self.reason
    }
}

impl fmt::Display for InvalidPathSegment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid repository path segment at index {}: segment {}",
            self.index, self.reason
        )
    }
}

impl Error for InvalidPathSegment {}

fn validate_segment(index: usize, segment: &str) -> Result<(), InvalidPathSegment> {
    let reason = if segment.is_empty() {
        InvalidPathSegmentReason::Empty
    } else if segment == "." {
        InvalidPathSegmentReason::CurrentDirectory
    } else if segment == ".." {
        InvalidPathSegmentReason::ParentDirectory
    } else if segment.contains('/') {
        InvalidPathSegmentReason::ContainsSeparator
    } else if segment.contains('\0') {
        InvalidPathSegmentReason::ContainsNul
    } else if segment.contains('*') {
        InvalidPathSegmentReason::ContainsWildcard
    } else {
        return Ok(());
    };

    Err(InvalidPathSegment { index, reason })
}

#[cfg(test)]
mod tests {
    use super::{CanonicalPath, InvalidPathSegmentReason, PathPattern, path_below, path_matches};

    fn path(segments: &[&str]) -> CanonicalPath {
        CanonicalPath::new(segments).expect("test paths must contain valid segments")
    }

    #[test]
    fn canonical_path_preserves_valid_segments() {
        let path = CanonicalPath::new(["src", "parser", "lexer.rs"])
            .expect("valid segments should create a canonical path");

        assert_eq!(path.as_segments(), ["src", "parser", "lexer.rs"]);
        assert!(!path.is_root());
    }

    #[test]
    fn canonical_path_allows_repository_root() {
        let from_empty_segments = CanonicalPath::new(std::iter::empty::<&str>())
            .expect("an empty path should denote the repository root");

        assert_eq!(from_empty_segments, CanonicalPath::root());
        assert!(from_empty_segments.is_root());
    }

    #[test]
    fn canonical_path_rejects_every_invalid_segment_class() {
        let invalid_segments = [
            ("", InvalidPathSegmentReason::Empty),
            (".", InvalidPathSegmentReason::CurrentDirectory),
            ("..", InvalidPathSegmentReason::ParentDirectory),
            (
                "parser/lexer.rs",
                InvalidPathSegmentReason::ContainsSeparator,
            ),
            ("secret\0name", InvalidPathSegmentReason::ContainsNul),
            ("*.rs", InvalidPathSegmentReason::ContainsWildcard),
        ];

        for (segment, expected_reason) in invalid_segments {
            let error = CanonicalPath::new(["src", segment, "output"])
                .expect_err("an invalid segment must reject the whole path");

            assert_eq!(error.index(), 1);
            assert_eq!(error.reason(), expected_reason);
        }
    }

    #[test]
    fn canonical_path_reports_the_first_invalid_segment() {
        let error = CanonicalPath::new(["src/main.rs", "*"])
            .expect_err("validation should stop at the first invalid segment");

        assert_eq!(error.index(), 0);
        assert_eq!(error.reason(), InvalidPathSegmentReason::ContainsSeparator);
        assert_eq!(
            error.to_string(),
            "invalid repository path segment at index 0: segment must not contain `/`"
        );
    }

    #[test]
    fn canonical_path_exposes_tree_relationships_without_reparsing() {
        let source = path(&["src"]);
        let parser = path(&["src", "parser"]);
        let lexer = path(&["src", "parser", "lexer.rs"]);

        assert_eq!(lexer.parent(), Some(parser.clone()));
        assert_eq!(source.parent(), Some(CanonicalPath::root()));
        assert_eq!(CanonicalPath::root().parent(), None);
        assert!(lexer.is_at_or_below(&source));
        assert!(source.is_at_or_below(&source));
        assert!(!source.is_at_or_below(&parser));
    }

    #[test]
    fn canonical_path_rebases_only_paths_inside_the_source_subtree() {
        let source = path(&["src", "parser"]);
        let destination = path(&["lib", "syntax"]);
        let descendant = path(&["src", "parser", "lexer.rs"]);

        assert_eq!(
            descendant.rebase(&source, &destination),
            Some(path(&["lib", "syntax", "lexer.rs"]))
        );
        assert_eq!(source.rebase(&source, &destination), Some(destination));
        assert_eq!(
            path(&["src", "main.rs"]).rebase(&source, &path(&["lib"])),
            None
        );
    }

    #[test]
    fn path_patterns_retain_their_canonical_paths() {
        let exact_path = CanonicalPath::new(["src", "main.rs"])
            .expect("valid segments should create a canonical path");
        let prefix_path = CanonicalPath::new(["src", "parser"])
            .expect("valid segments should create a canonical path");
        let exact = PathPattern::Exact(exact_path.clone());
        let prefix = PathPattern::Prefix(prefix_path.clone());

        assert_eq!(exact.path(), &exact_path);
        assert_eq!(prefix.path(), &prefix_path);
    }

    #[test]
    fn path_matches_exact_and_prefix_boundaries() {
        let cases = [
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                path(&["src", "main.rs"]),
                true,
            ),
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                path(&["src", "lib.rs"]),
                false,
            ),
            (PathPattern::Prefix(path(&["src"])), path(&["src"]), true),
            (
                PathPattern::Prefix(path(&["src"])),
                path(&["src", "parser", "lexer.rs"]),
                true,
            ),
            (
                PathPattern::Prefix(path(&["src"])),
                path(&["docs", "design.md"]),
                false,
            ),
            (
                PathPattern::Prefix(CanonicalPath::root()),
                path(&["src", "main.rs"]),
                true,
            ),
        ];

        for (pattern, candidate, expected) in cases {
            assert_eq!(path_matches(&pattern, &candidate), expected);
        }
    }

    #[test]
    fn path_below_matches_pattern_set_inclusion() {
        let cases = [
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                PathPattern::Exact(path(&["src", "main.rs"])),
                true,
            ),
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                PathPattern::Exact(path(&["src", "lib.rs"])),
                false,
            ),
            (
                PathPattern::Exact(path(&["src", "parser", "lexer.rs"])),
                PathPattern::Prefix(path(&["src", "parser"])),
                true,
            ),
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                PathPattern::Prefix(path(&["docs"])),
                false,
            ),
            (
                PathPattern::Prefix(path(&["src", "parser"])),
                PathPattern::Prefix(path(&["src"])),
                true,
            ),
            (
                PathPattern::Prefix(path(&["src"])),
                PathPattern::Prefix(path(&["src", "parser"])),
                false,
            ),
            (
                PathPattern::Prefix(path(&["src"])),
                PathPattern::Prefix(path(&["docs"])),
                false,
            ),
            (
                PathPattern::Prefix(path(&["src"])),
                PathPattern::Exact(path(&["src"])),
                false,
            ),
            (
                PathPattern::Exact(path(&["src", "main.rs"])),
                PathPattern::Prefix(CanonicalPath::root()),
                true,
            ),
            (
                PathPattern::Exact(CanonicalPath::root()),
                PathPattern::Prefix(path(&["src"])),
                false,
            ),
            (
                PathPattern::Prefix(CanonicalPath::root()),
                PathPattern::Prefix(CanonicalPath::root()),
                true,
            ),
            (
                PathPattern::Prefix(CanonicalPath::root()),
                PathPattern::Exact(CanonicalPath::root()),
                false,
            ),
        ];

        for (child, parent, expected) in cases {
            assert_eq!(path_below(&child, &parent), expected);
        }
    }

    #[test]
    fn path_below_is_transitive_across_exact_and_prefix_patterns() {
        let leaf = PathPattern::Exact(path(&["src", "parser", "lexer.rs"]));
        let parser = PathPattern::Prefix(path(&["src", "parser"]));
        let source = PathPattern::Prefix(path(&["src"]));

        assert!(path_below(&leaf, &parser));
        assert!(path_below(&parser, &source));
        assert!(path_below(&leaf, &source));
    }
}
