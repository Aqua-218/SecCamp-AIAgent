//! Canonical digests for authority policy exchanged across process boundaries.
//!
//! Rust's `Hash` implementation and debug formatting are intentionally not a
//! wire format. This module owns a versioned, length-delimited encoding so a
//! host grant and an independently constructed guest grant can prove that they
//! describe the same authority without serializing private implementation
//! details or relying on enum layout.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::{
    capability::AuthorityBody,
    file::FileEffects,
    github::{BranchPattern, GitHubOperation, GitHubOperations},
    http::{HttpFetchMethod, HttpFetchMethods, UrlPathPattern},
    path::PathPattern,
    time::TimeWindow,
};

/// Version of the canonical root-policy encoding.
pub const ROOT_POLICY_ENCODING_VERSION: u16 = 1;

/// SHA-256 of one versioned canonical root authority policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityPolicyDigest([u8; 32]);

impl AuthorityPolicyDigest {
    /// Computes the digest that must bind host issuance to guest enforcement.
    #[must_use]
    pub fn for_root(validity: TimeWindow, authority: &AuthorityBody, delegable: bool) -> Self {
        let mut canonical = CanonicalPolicy::new();
        canonical.field_u16(ROOT_POLICY_ENCODING_VERSION);
        canonical.field_u64(validity.not_before().ticks());
        canonical.field_u64(validity.expires_at().ticks());
        canonical.field_u8(u8::from(delegable));
        encode_authority(&mut canonical, authority);
        Self(Sha256::digest(canonical.finish()).into())
    }

    /// Parses exactly 64 lower-case hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuthorityPolicyDigest`] for a wrong length, an
    /// upper-case spelling, or a non-hexadecimal byte.
    pub fn from_hex(value: &str) -> Result<Self, InvalidAuthorityPolicyDigest> {
        if value.len() != 64 {
            return Err(InvalidAuthorityPolicyDigest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (decode_hex(pair[0])? << 4) | decode_hex(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Returns the fixed-width digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the one accepted lower-case hexadecimal spelling.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

impl fmt::Display for AuthorityPolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// A malformed textual authority policy digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAuthorityPolicyDigest;

impl fmt::Display for InvalidAuthorityPolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authority policy digest must be 64 lower-case hexadecimal characters")
    }
}

impl Error for InvalidAuthorityPolicyDigest {}

fn decode_hex(byte: u8) -> Result<u8, InvalidAuthorityPolicyDigest> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(InvalidAuthorityPolicyDigest),
    }
}

fn encode_authority(canonical: &mut CanonicalPolicy, authority: &AuthorityBody) {
    match authority {
        AuthorityBody::File(authority) => {
            canonical.field_u8(1);
            canonical.field_str(authority.repository().as_str());
            canonical.field_u16(file_effect_bits(authority.effects()));
            encode_path_pattern(canonical, authority.path());
        }
        AuthorityBody::HttpFetch(authority) => {
            canonical.field_u8(2);
            canonical.field_u8(http_method_bits(authority.methods()));
            canonical.field_str(authority.host().as_str());
            encode_url_pattern(canonical, authority.path());
            canonical.field_u64(authority.max_response_bytes());
        }
        AuthorityBody::GitHub(authority) => {
            canonical.field_u8(3);
            canonical.field_str(authority.installation().as_str());
            canonical.field_str(authority.repository().as_str());
            canonical.field_u8(github_operation_bits(authority.operations()));
            encode_branch_pattern(canonical, authority.base());
            encode_branch_pattern(canonical, authority.head());
        }
    }
}

fn file_effect_bits(effects: FileEffects) -> u16 {
    crate::file::FileEffect::ALL
        .iter()
        .fold(0_u16, |bits, effect| {
            bits | if effects.contains(*effect) {
                1_u16 << effect.tag()
            } else {
                0
            }
        })
}

fn http_method_bits(methods: HttpFetchMethods) -> u8 {
    u8::from(methods.contains(HttpFetchMethod::Get))
        | (u8::from(methods.contains(HttpFetchMethod::Head)) << 1)
}

fn github_operation_bits(operations: GitHubOperations) -> u8 {
    u8::from(operations.contains(GitHubOperation::PublishBranch))
        | (u8::from(operations.contains(GitHubOperation::CreatePullRequest)) << 1)
}

fn encode_path_pattern(canonical: &mut CanonicalPolicy, pattern: &PathPattern) {
    canonical.field_u8(match pattern {
        PathPattern::Exact(_) => 1,
        PathPattern::Prefix(_) => 2,
    });
    canonical.field_segments(pattern.path().as_segments());
}

fn encode_url_pattern(canonical: &mut CanonicalPolicy, pattern: &UrlPathPattern) {
    canonical.field_u8(match pattern {
        UrlPathPattern::Exact(_) => 1,
        UrlPathPattern::Prefix(_) => 2,
    });
    canonical.field_segments(pattern.path().as_segments());
}

fn encode_branch_pattern(canonical: &mut CanonicalPolicy, pattern: &BranchPattern) {
    canonical.field_u8(match pattern {
        BranchPattern::Exact(_) => 1,
        BranchPattern::Prefix(_) => 2,
    });
    canonical.field_segments(pattern.branch().as_segments());
}

struct CanonicalPolicy(Vec<u8>);

impl CanonicalPolicy {
    fn new() -> Self {
        Self(b"authority-root-policy\0".to_vec())
    }

    fn field_u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn field_u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn field_u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn field_u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn field_str(&mut self, value: &str) {
        self.field_u32(u32::try_from(value.len()).expect("validated authority string fits u32"));
        self.0.extend_from_slice(value.as_bytes());
    }

    fn field_segments(&mut self, segments: &[String]) {
        self.field_u32(u32::try_from(segments.len()).expect("validated segment count fits u32"));
        for segment in segments {
            self.field_str(segment);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::AuthorityPolicyDigest;
    use crate::{
        capability::AuthorityBody,
        file::{FileAuthority, FileEffect, FileEffects},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        time::{MonotonicTime, TimeWindow},
    };

    fn validity() -> TimeWindow {
        TimeWindow::new(MonotonicTime::from_ticks(7), MonotonicTime::from_ticks(19))
            .expect("fixed validity")
    }

    fn authority(effects: FileEffects) -> AuthorityBody {
        AuthorityBody::File(FileAuthority::new(
            RepoId::new("repo"),
            effects,
            PathPattern::Prefix(CanonicalPath::new(["src", "agent"]).expect("canonical test path")),
        ))
    }

    #[test]
    fn canonical_digest_is_stable_and_round_trips_its_only_text_spelling() {
        let digest = AuthorityPolicyDigest::for_root(
            validity(),
            &authority(FileEffects::only(FileEffect::ReadData)),
            false,
        );
        assert_eq!(
            digest.to_hex(),
            "4aa3d09370e2b12bbd6f4eabd239f34dda512cce13c4f023e48f187ecd0a7b12"
        );
        assert_eq!(
            AuthorityPolicyDigest::from_hex(&digest.to_hex()),
            Ok(digest)
        );
        assert!(AuthorityPolicyDigest::from_hex(&digest.to_hex().to_uppercase()).is_err());
        assert!(AuthorityPolicyDigest::from_hex("00").is_err());
    }

    #[test]
    fn every_root_policy_axis_changes_the_digest() {
        let read = authority(FileEffects::only(FileEffect::ReadData));
        let write = authority(FileEffects::only(FileEffect::WriteData));
        let baseline = AuthorityPolicyDigest::for_root(validity(), &read, false);
        let later = TimeWindow::new(MonotonicTime::from_ticks(8), MonotonicTime::from_ticks(19))
            .expect("fixed validity");
        assert_ne!(
            baseline,
            AuthorityPolicyDigest::for_root(later, &read, false)
        );
        assert_ne!(
            baseline,
            AuthorityPolicyDigest::for_root(validity(), &write, false)
        );
        assert_ne!(
            baseline,
            AuthorityPolicyDigest::for_root(validity(), &read, true)
        );
    }

    #[test]
    fn every_file_effect_has_a_distinct_policy_digest() {
        let digests = FileEffect::ALL.map(|effect| {
            AuthorityPolicyDigest::for_root(
                validity(),
                &authority(FileEffects::only(effect)),
                false,
            )
        });
        let unique = digests.into_iter().collect::<HashSet<_>>();
        assert_eq!(unique.len(), FileEffect::ALL.len());
    }
}
