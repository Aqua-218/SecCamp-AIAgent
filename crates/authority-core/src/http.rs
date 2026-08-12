//! Public HTTP fetch authority types and pure authorization decisions.
//!
//! This module deliberately models only the authority-core portion of a
//! public fetch. A caller supplies an already-separated host and origin path;
//! it cannot pass an arbitrary URL, scheme, port, headers, body, or userinfo
//! through this API. The egress broker remains responsible for enforcing
//! HTTPS, port 443, redirect revalidation, DNS/IP policy, TLS, and the actual
//! response-byte limit.

use std::{error::Error, fmt, net::IpAddr};

/// A DNS hostname normalized for exact HTTP authority comparisons.
///
/// Construction accepts ASCII DNS names only. ASCII letters are lowercased and
/// one terminal root dot is removed, so `DOCS.Example.` and `docs.example`
/// name the same host. Empty labels, a second terminal dot, labels longer than
/// 63 bytes, names longer than 253 bytes, leading/trailing label hyphens,
/// non-ASCII input, and IP address literals are rejected. Internationalized
/// hostnames must be converted to their ASCII A-label form before construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHost(String);

impl CanonicalHost {
    /// Canonicalizes and validates a DNS hostname for exact comparison.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCanonicalHost`] when `host` is not an ASCII DNS name
    /// accepted by this authority model.
    pub fn new(host: impl AsRef<str>) -> Result<Self, InvalidCanonicalHost> {
        let host = host.as_ref();
        if !host.is_ascii() {
            return Err(InvalidCanonicalHost::new(
                InvalidCanonicalHostReason::NonAscii,
            ));
        }

        let canonical = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if canonical.is_empty() {
            return Err(InvalidCanonicalHost::new(InvalidCanonicalHostReason::Empty));
        }
        if canonical.len() > 253 {
            return Err(InvalidCanonicalHost::new(
                InvalidCanonicalHostReason::TooLong,
            ));
        }
        if canonical.parse::<IpAddr>().is_ok() {
            return Err(InvalidCanonicalHost::new(
                InvalidCanonicalHostReason::IpAddressLiteral,
            ));
        }

        for (index, label) in canonical.split('.').enumerate() {
            if label.is_empty() {
                return Err(InvalidCanonicalHost::at_label(
                    index,
                    InvalidCanonicalHostReason::EmptyLabel,
                ));
            }
            if label.len() > 63 {
                return Err(InvalidCanonicalHost::at_label(
                    index,
                    InvalidCanonicalHostReason::LabelTooLong,
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(InvalidCanonicalHost::at_label(
                    index,
                    InvalidCanonicalHostReason::LabelEdgeHyphen,
                ));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(InvalidCanonicalHost::at_label(
                    index,
                    InvalidCanonicalHostReason::InvalidLabelCharacter,
                ));
            }
        }

        Ok(Self(canonical))
    }

    /// Returns the lower-case, no-terminal-dot hostname.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The reason a hostname cannot form a [`CanonicalHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCanonicalHostReason {
    /// The hostname has no DNS labels after terminal-dot normalization.
    Empty,
    /// The hostname contains non-ASCII input.
    NonAscii,
    /// The canonical hostname exceeds the DNS presentation limit.
    TooLong,
    /// A label is empty, including one caused by an interior or repeated dot.
    EmptyLabel,
    /// A label exceeds the DNS label limit.
    LabelTooLong,
    /// A label starts or ends with a hyphen.
    LabelEdgeHyphen,
    /// A label contains a character other than ASCII letters, digits, or `-`.
    InvalidLabelCharacter,
    /// The input is an IPv4 or IPv6 address literal rather than a DNS name.
    IpAddressLiteral,
}

impl fmt::Display for InvalidCanonicalHostReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expectation = match self {
            Self::Empty => "must contain at least one DNS label",
            Self::NonAscii => "must contain only ASCII; use an ASCII A-label for IDNs",
            Self::TooLong => "must be at most 253 bytes after terminal-dot normalization",
            Self::EmptyLabel => "must not contain an empty DNS label",
            Self::LabelTooLong => "must be at most 63 bytes",
            Self::LabelEdgeHyphen => "must not start or end with `-`",
            Self::InvalidLabelCharacter => "must contain only ASCII letters, digits, or `-`",
            Self::IpAddressLiteral => "must be a DNS name, not an IP address literal",
        };
        formatter.write_str(expectation)
    }
}

/// Reports why a hostname cannot form a [`CanonicalHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCanonicalHost {
    label_index: Option<usize>,
    reason: InvalidCanonicalHostReason,
}

impl InvalidCanonicalHost {
    const fn new(reason: InvalidCanonicalHostReason) -> Self {
        Self {
            label_index: None,
            reason,
        }
    }

    const fn at_label(label_index: usize, reason: InvalidCanonicalHostReason) -> Self {
        Self {
            label_index: Some(label_index),
            reason,
        }
    }

    /// Returns the zero-based invalid label position, when one applies.
    #[must_use]
    pub const fn label_index(self) -> Option<usize> {
        self.label_index
    }

    /// Returns why hostname construction failed.
    #[must_use]
    pub const fn reason(self) -> InvalidCanonicalHostReason {
        self.reason
    }
}

impl fmt::Display for InvalidCanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.label_index {
            Some(index) => write!(
                formatter,
                "invalid canonical host label at index {index}: label {}",
                self.reason
            ),
            None => write!(formatter, "invalid canonical host: host {}", self.reason),
        }
    }
}

impl Error for InvalidCanonicalHost {}

/// An origin-form URL path represented as validated, non-empty segments.
///
/// The root path is represented by zero segments and rendered as `/`. Every
/// other path is ASCII, begins with exactly one `/`, has no trailing slash,
/// no empty, `.` or `..` segments, no backslash, and no percent encoding,
/// query, or fragment delimiter. Segment characters are the RFC 3986 `pchar`
/// set except `%`. Rejecting alternate spellings rather than decoding or
/// normalizing them ensures a capability comparison never differs from an
/// implicit URL parser's interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalUrlPath {
    segments: Vec<String>,
}

impl CanonicalUrlPath {
    /// Creates the root URL path.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Validates one canonical origin-form URL path.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCanonicalUrlPath`] when `path` is not the one allowed
    /// spelling for an authority path.
    pub fn new(path: impl AsRef<str>) -> Result<Self, InvalidCanonicalUrlPath> {
        let path = path.as_ref();
        if path == "/" {
            return Ok(Self::root());
        }
        if !path.starts_with('/') {
            return Err(InvalidCanonicalUrlPath::new(
                InvalidCanonicalUrlPathReason::MissingLeadingSlash,
            ));
        }
        if path.ends_with('/') {
            return Err(InvalidCanonicalUrlPath::new(
                InvalidCanonicalUrlPathReason::TrailingSlash,
            ));
        }
        if !path.is_ascii() {
            return Err(InvalidCanonicalUrlPath::new(
                InvalidCanonicalUrlPathReason::NonAscii,
            ));
        }

        let segments = path[1..]
            .split('/')
            .enumerate()
            .map(|(index, segment)| {
                validate_url_path_segment(index, segment)?;
                Ok(segment.to_owned())
            })
            .collect::<Result<Vec<_>, InvalidCanonicalUrlPath>>()?;
        Ok(Self { segments })
    }

    /// Returns the validated URL path segments in order.
    #[must_use]
    pub const fn as_segments(&self) -> &[String] {
        self.segments.as_slice()
    }

    /// Returns whether this is the root path.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Returns whether this path equals or descends from `ancestor` at a path
    /// segment boundary.
    #[must_use]
    pub fn is_at_or_below(&self, ancestor: &Self) -> bool {
        self.segments.starts_with(&ancestor.segments)
    }
}

impl fmt::Display for CanonicalUrlPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return formatter.write_str("/");
        }
        for segment in &self.segments {
            formatter.write_str("/")?;
            formatter.write_str(segment)?;
        }
        Ok(())
    }
}

/// A URL-path selector used by HTTP fetch authorities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UrlPathPattern {
    /// Selects exactly one canonical URL path.
    Exact(CanonicalUrlPath),
    /// Selects a canonical URL path and all of its segment descendants.
    Prefix(CanonicalUrlPath),
}

impl UrlPathPattern {
    /// Returns the canonical URL path carried by this pattern.
    #[must_use]
    pub const fn path(&self) -> &CanonicalUrlPath {
        match self {
            Self::Exact(path) | Self::Prefix(path) => path,
        }
    }
}

/// Returns whether `pattern` selects `path`.
#[must_use]
pub fn url_path_matches(pattern: &UrlPathPattern, path: &CanonicalUrlPath) -> bool {
    match pattern {
        UrlPathPattern::Exact(selected) => selected == path,
        UrlPathPattern::Prefix(selected) => path.is_at_or_below(selected),
    }
}

/// Returns whether every path selected by `child` is also selected by `parent`.
#[must_use]
pub fn url_path_below(child: &UrlPathPattern, parent: &UrlPathPattern) -> bool {
    match (child, parent) {
        (UrlPathPattern::Exact(child), UrlPathPattern::Exact(parent)) => child == parent,
        (
            UrlPathPattern::Exact(child) | UrlPathPattern::Prefix(child),
            UrlPathPattern::Prefix(parent),
        ) => child.is_at_or_below(parent),
        (UrlPathPattern::Prefix(_), UrlPathPattern::Exact(_)) => false,
    }
}

/// The reason an origin-form URL path cannot be canonicalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCanonicalUrlPathReason {
    /// The path does not start with `/`.
    MissingLeadingSlash,
    /// A non-root path ends with `/`.
    TrailingSlash,
    /// The path contains non-ASCII input.
    NonAscii,
    /// A segment is empty.
    EmptySegment,
    /// A segment is `.`.
    CurrentDirectory,
    /// A segment is `..`.
    ParentDirectory,
    /// A segment contains a backslash.
    ContainsBackslash,
    /// A segment contains a percent sign and therefore percent encoding.
    ContainsPercentEncoding,
    /// A segment contains `?` and would include a query component.
    ContainsQueryDelimiter,
    /// A segment contains `#` and would include a fragment component.
    ContainsFragmentDelimiter,
    /// A segment contains an ASCII control character.
    ContainsControlCharacter,
    /// A segment contains a character outside the accepted RFC 3986 `pchar`
    /// set (with `%` handled separately).
    ContainsInvalidCharacter,
}

impl fmt::Display for InvalidCanonicalUrlPathReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expectation = match self {
            Self::MissingLeadingSlash => "must start with `/`",
            Self::TrailingSlash => "must not end with `/` unless it is the root path",
            Self::NonAscii => "must contain only ASCII",
            Self::EmptySegment => "must not be empty",
            Self::CurrentDirectory => "must not be `.`",
            Self::ParentDirectory => "must not be `..`",
            Self::ContainsBackslash => "must not contain `\\`",
            Self::ContainsPercentEncoding => "must not contain `%` or percent encoding",
            Self::ContainsQueryDelimiter => "must not contain `?`",
            Self::ContainsFragmentDelimiter => "must not contain `#`",
            Self::ContainsControlCharacter => "must not contain an ASCII control character",
            Self::ContainsInvalidCharacter => {
                "must contain only RFC 3986 path characters without percent encoding"
            }
        };
        formatter.write_str(expectation)
    }
}

/// Reports the position and reason for an invalid canonical URL path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCanonicalUrlPath {
    segment_index: Option<usize>,
    reason: InvalidCanonicalUrlPathReason,
}

impl InvalidCanonicalUrlPath {
    const fn new(reason: InvalidCanonicalUrlPathReason) -> Self {
        Self {
            segment_index: None,
            reason,
        }
    }

    const fn at_segment(segment_index: usize, reason: InvalidCanonicalUrlPathReason) -> Self {
        Self {
            segment_index: Some(segment_index),
            reason,
        }
    }

    /// Returns the zero-based invalid segment position, when one applies.
    #[must_use]
    pub const fn segment_index(self) -> Option<usize> {
        self.segment_index
    }

    /// Returns why URL path construction failed.
    #[must_use]
    pub const fn reason(self) -> InvalidCanonicalUrlPathReason {
        self.reason
    }
}

impl fmt::Display for InvalidCanonicalUrlPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.segment_index {
            Some(index) => write!(
                formatter,
                "invalid canonical URL path segment at index {index}: segment {}",
                self.reason
            ),
            None => write!(
                formatter,
                "invalid canonical URL path: path {}",
                self.reason
            ),
        }
    }
}

impl Error for InvalidCanonicalUrlPath {}

fn validate_url_path_segment(index: usize, segment: &str) -> Result<(), InvalidCanonicalUrlPath> {
    let reason = if segment.is_empty() {
        InvalidCanonicalUrlPathReason::EmptySegment
    } else if segment == "." {
        InvalidCanonicalUrlPathReason::CurrentDirectory
    } else if segment == ".." {
        InvalidCanonicalUrlPathReason::ParentDirectory
    } else if segment.contains('\\') {
        InvalidCanonicalUrlPathReason::ContainsBackslash
    } else if segment.contains('%') {
        InvalidCanonicalUrlPathReason::ContainsPercentEncoding
    } else if segment.contains('?') {
        InvalidCanonicalUrlPathReason::ContainsQueryDelimiter
    } else if segment.contains('#') {
        InvalidCanonicalUrlPathReason::ContainsFragmentDelimiter
    } else if segment.bytes().any(|byte| byte.is_ascii_control()) {
        InvalidCanonicalUrlPathReason::ContainsControlCharacter
    } else if !segment.bytes().all(is_unencoded_url_path_character) {
        InvalidCanonicalUrlPathReason::ContainsInvalidCharacter
    } else {
        return Ok(());
    };

    Err(InvalidCanonicalUrlPath::at_segment(index, reason))
}

fn is_unencoded_url_path_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'.' | b'_' | b'~')
        || matches!(
            byte,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        )
        || matches!(byte, b':' | b'@')
}

/// One public HTTP method that may be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HttpFetchMethod {
    /// Retrieves a response representation.
    Get,
    /// Retrieves response metadata without a response body.
    Head,
}

impl HttpFetchMethod {
    const fn mask(self) -> u8 {
        1_u8 << (self as u8)
    }
}

/// A closed set of permitted HTTP fetch methods.
///
/// The only representable members are [`HttpFetchMethod::Get`] and
/// [`HttpFetchMethod::Head`]; callers cannot construct arbitrary method bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HttpFetchMethods(u8);

impl HttpFetchMethods {
    /// Creates a method set that permits no requests.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates a method set containing exactly one method.
    #[must_use]
    pub const fn only(method: HttpFetchMethod) -> Self {
        Self(method.mask())
    }

    /// Creates a method set from the supplied methods.
    #[must_use]
    pub fn from_methods(methods: impl IntoIterator<Item = HttpFetchMethod>) -> Self {
        methods
            .into_iter()
            .fold(Self::empty(), |set, method| Self(set.0 | method.mask()))
    }

    /// Returns whether this set contains `method`.
    #[must_use]
    pub const fn contains(self, method: HttpFetchMethod) -> bool {
        self.0 & method.mask() != 0
    }

    /// Returns whether this set contains no methods.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether every method in this set is also in `parent`.
    #[must_use]
    pub const fn is_subset_of(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// The public HTTP fetch operations permitted for one host and path pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpFetchAuthority {
    methods: HttpFetchMethods,
    host: CanonicalHost,
    path: UrlPathPattern,
    max_response_bytes: u64,
}

impl HttpFetchAuthority {
    /// Creates an immutable public HTTP fetch authority body.
    #[must_use]
    pub const fn new(
        methods: HttpFetchMethods,
        host: CanonicalHost,
        path: UrlPathPattern,
        max_response_bytes: u64,
    ) -> Self {
        Self {
            methods,
            host,
            path,
            max_response_bytes,
        }
    }

    /// Returns the permitted HTTP methods.
    #[must_use]
    pub const fn methods(&self) -> HttpFetchMethods {
        self.methods
    }

    /// Returns the exact canonical hostname.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Returns the governed URL path pattern.
    #[must_use]
    pub const fn path(&self) -> &UrlPathPattern {
        &self.path
    }

    /// Returns the maximum response bytes accepted for one fetch.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

/// A single public HTTP fetch authorization request.
///
/// `max_response_bytes` is the caller's requested per-response limit. A
/// broker must also enforce that limit while reading the response; a successful
/// authority decision alone does not make an oversized upstream response safe.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpFetchRequest {
    method: HttpFetchMethod,
    host: CanonicalHost,
    path: CanonicalUrlPath,
    max_response_bytes: u64,
}

impl HttpFetchRequest {
    /// Creates a request for one method, host, URL path, and response limit.
    #[must_use]
    pub const fn new(
        method: HttpFetchMethod,
        host: CanonicalHost,
        path: CanonicalUrlPath,
        max_response_bytes: u64,
    ) -> Self {
        Self {
            method,
            host,
            path,
            max_response_bytes,
        }
    }

    /// Returns the requested HTTP method.
    #[must_use]
    pub const fn method(&self) -> HttpFetchMethod {
        self.method
    }

    /// Returns the requested exact canonical hostname.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Returns the requested canonical URL path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalUrlPath {
        &self.path
    }

    /// Returns the requested maximum response bytes.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

/// Returns whether `authority` permits `request`.
#[must_use]
pub fn http_fetch_matches(authority: &HttpFetchAuthority, request: &HttpFetchRequest) -> bool {
    authority.methods.contains(request.method)
        && authority.host == request.host
        && url_path_matches(&authority.path, &request.path)
        && request.max_response_bytes <= authority.max_response_bytes
}

/// Returns whether `child` satisfies the structural HTTP fetch delegation rule.
///
/// A successful decision guarantees that every request permitted by `child`
/// is also permitted by `parent`. It requires method-set inclusion, exact
/// canonical-host equality, URL-path containment, and a no-larger per-response
/// byte limit, including when the child's method set is empty.
#[must_use]
pub fn http_fetch_body_below(child: &HttpFetchAuthority, parent: &HttpFetchAuthority) -> bool {
    child.methods.is_subset_of(parent.methods)
        && child.host == parent.host
        && url_path_below(&child.path, &parent.path)
        && child.max_response_bytes <= parent.max_response_bytes
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
        HttpFetchRequest, InvalidCanonicalHostReason, InvalidCanonicalUrlPathReason,
        UrlPathPattern, http_fetch_body_below, http_fetch_matches, url_path_below,
        url_path_matches,
    };

    fn host(value: &str) -> CanonicalHost {
        CanonicalHost::new(value).expect("test host must be canonicalizable")
    }

    fn path(value: &str) -> CanonicalUrlPath {
        CanonicalUrlPath::new(value).expect("test path must be canonicalizable")
    }

    fn methods(methods: &[HttpFetchMethod]) -> HttpFetchMethods {
        HttpFetchMethods::from_methods(methods.iter().copied())
    }

    #[test]
    fn canonical_host_lowercases_ascii_and_removes_one_terminal_dot() {
        let canonical = host("DOCS.Example.");

        assert_eq!(canonical.as_str(), "docs.example");
        assert_eq!(canonical.to_string(), "docs.example");
        assert_eq!(canonical, host("docs.example"));
    }

    #[test]
    fn canonical_host_rejects_ambiguous_or_non_dns_input() {
        let cases = [
            ("", None, InvalidCanonicalHostReason::Empty),
            (".", None, InvalidCanonicalHostReason::Empty),
            (
                "docs..example",
                Some(1),
                InvalidCanonicalHostReason::EmptyLabel,
            ),
            (
                "-docs.example",
                Some(0),
                InvalidCanonicalHostReason::LabelEdgeHyphen,
            ),
            (
                "docs-.example",
                Some(0),
                InvalidCanonicalHostReason::LabelEdgeHyphen,
            ),
            (
                "docs_example",
                Some(0),
                InvalidCanonicalHostReason::InvalidLabelCharacter,
            ),
            (
                "docs.example:443",
                Some(1),
                InvalidCanonicalHostReason::InvalidLabelCharacter,
            ),
            (
                "docs.example/guide",
                Some(1),
                InvalidCanonicalHostReason::InvalidLabelCharacter,
            ),
            ("docs.exämple", None, InvalidCanonicalHostReason::NonAscii),
            (
                "127.0.0.1",
                None,
                InvalidCanonicalHostReason::IpAddressLiteral,
            ),
            (
                "[::1]",
                Some(0),
                InvalidCanonicalHostReason::InvalidLabelCharacter,
            ),
        ];

        for (input, label_index, reason) in cases {
            let error = CanonicalHost::new(input).expect_err("input must be rejected");
            assert_eq!(error.label_index(), label_index, "input: {input}");
            assert_eq!(error.reason(), reason, "input: {input}");
        }

        let overlong_label = format!("{}.example", "a".repeat(64));
        assert_eq!(
            CanonicalHost::new(overlong_label)
                .expect_err("a label longer than 63 bytes must be rejected")
                .reason(),
            InvalidCanonicalHostReason::LabelTooLong
        );
        let overlong_name = format!("{}.example", "a".repeat(246));
        assert_eq!(
            CanonicalHost::new(overlong_name)
                .expect_err("a name longer than 253 bytes must be rejected")
                .reason(),
            InvalidCanonicalHostReason::TooLong
        );
    }

    #[test]
    fn canonical_url_path_accepts_only_one_safe_spelling() {
        let guide = path("/guide/getting-started");

        assert_eq!(guide.as_segments(), ["guide", "getting-started"]);
        assert_eq!(guide.to_string(), "/guide/getting-started");
        assert_eq!(CanonicalUrlPath::root().to_string(), "/");

        let cases = [
            (
                "guide",
                None,
                InvalidCanonicalUrlPathReason::MissingLeadingSlash,
            ),
            (
                "/guide/",
                None,
                InvalidCanonicalUrlPathReason::TrailingSlash,
            ),
            (
                "//guide",
                Some(0),
                InvalidCanonicalUrlPathReason::EmptySegment,
            ),
            (
                "/./guide",
                Some(0),
                InvalidCanonicalUrlPathReason::CurrentDirectory,
            ),
            (
                "/guide/..",
                Some(1),
                InvalidCanonicalUrlPathReason::ParentDirectory,
            ),
            (
                "/guide\\next",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsBackslash,
            ),
            (
                "/guide%2Fnext",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsPercentEncoding,
            ),
            (
                "/guide?draft",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsQueryDelimiter,
            ),
            (
                "/guide#part",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsFragmentDelimiter,
            ),
            (
                "/guide\u{7f}",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsControlCharacter,
            ),
            (
                "/guide page",
                Some(0),
                InvalidCanonicalUrlPathReason::ContainsInvalidCharacter,
            ),
            ("/café", None, InvalidCanonicalUrlPathReason::NonAscii),
        ];

        for (input, segment_index, reason) in cases {
            let error = CanonicalUrlPath::new(input).expect_err("input must be rejected");
            assert_eq!(error.segment_index(), segment_index, "input: {input:?}");
            assert_eq!(error.reason(), reason, "input: {input:?}");
        }
    }

    #[test]
    fn url_path_patterns_respect_segment_boundaries_and_containment() {
        let docs = UrlPathPattern::Prefix(path("/docs"));
        let guide = UrlPathPattern::Prefix(path("/docs/guide"));
        let guide_index = UrlPathPattern::Exact(path("/docs/guide/index"));
        let similarly_named = path("/docs-old");

        assert!(url_path_matches(&docs, &path("/docs")));
        assert!(url_path_matches(&docs, &path("/docs/guide/index")));
        assert!(!url_path_matches(&docs, &similarly_named));
        assert!(url_path_below(&guide, &docs));
        assert!(url_path_below(&guide_index, &guide));
        assert!(!url_path_below(&docs, &guide));
        assert!(!url_path_below(&guide, &guide_index));
    }

    #[test]
    fn http_fetch_methods_are_closed_sets_with_subset_checks() {
        let get = HttpFetchMethods::only(HttpFetchMethod::Get);
        let get_head = methods(&[HttpFetchMethod::Get, HttpFetchMethod::Head]);

        assert!(get.contains(HttpFetchMethod::Get));
        assert!(!get.contains(HttpFetchMethod::Head));
        assert!(HttpFetchMethods::empty().is_subset_of(get));
        assert!(get.is_subset_of(get_head));
        assert!(!get_head.is_subset_of(get));
    }

    #[test]
    fn http_fetch_matching_requires_every_authority_boundary() {
        let authority = HttpFetchAuthority::new(
            methods(&[HttpFetchMethod::Get, HttpFetchMethod::Head]),
            host("docs.example"),
            UrlPathPattern::Prefix(path("/guide")),
            1024,
        );
        let cases = [
            (
                HttpFetchRequest::new(
                    HttpFetchMethod::Get,
                    host("DOCS.EXAMPLE."),
                    path("/guide/install"),
                    1024,
                ),
                true,
            ),
            (
                HttpFetchRequest::new(
                    HttpFetchMethod::Head,
                    host("docs.example"),
                    path("/guide"),
                    0,
                ),
                true,
            ),
            (
                HttpFetchRequest::new(
                    HttpFetchMethod::Get,
                    host("api.example"),
                    path("/guide/install"),
                    1024,
                ),
                false,
            ),
            (
                HttpFetchRequest::new(
                    HttpFetchMethod::Get,
                    host("docs.example"),
                    path("/guides"),
                    1024,
                ),
                false,
            ),
            (
                HttpFetchRequest::new(
                    HttpFetchMethod::Get,
                    host("docs.example"),
                    path("/guide/install"),
                    1025,
                ),
                false,
            ),
        ];

        for (request, expected) in cases {
            assert_eq!(http_fetch_matches(&authority, &request), expected);
        }
    }

    #[test]
    fn http_fetch_containment_rejects_every_escalation() {
        let parent = HttpFetchAuthority::new(
            methods(&[HttpFetchMethod::Get, HttpFetchMethod::Head]),
            host("docs.example"),
            UrlPathPattern::Prefix(path("/docs")),
            4096,
        );
        let child = HttpFetchAuthority::new(
            HttpFetchMethods::only(HttpFetchMethod::Get),
            host("DOCS.EXAMPLE."),
            UrlPathPattern::Exact(path("/docs/guide")),
            1024,
        );

        assert!(http_fetch_body_below(&child, &parent));
        assert!(http_fetch_body_below(&parent, &parent));

        let escalations = [
            HttpFetchAuthority::new(
                methods(&[HttpFetchMethod::Get, HttpFetchMethod::Head]),
                host("docs.example"),
                UrlPathPattern::Exact(path("/docs/guide")),
                1024,
            ),
            HttpFetchAuthority::new(
                HttpFetchMethods::only(HttpFetchMethod::Get),
                host("api.example"),
                UrlPathPattern::Exact(path("/docs/guide")),
                1024,
            ),
            HttpFetchAuthority::new(
                HttpFetchMethods::only(HttpFetchMethod::Get),
                host("docs.example"),
                UrlPathPattern::Prefix(path("/docs")),
                1024,
            ),
            HttpFetchAuthority::new(
                HttpFetchMethods::only(HttpFetchMethod::Get),
                host("docs.example"),
                UrlPathPattern::Exact(path("/docs/guide")),
                4097,
            ),
        ];

        for escalation in escalations {
            assert!(!http_fetch_body_below(&escalation, &child));
        }
    }
}
