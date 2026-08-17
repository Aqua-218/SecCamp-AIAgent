//! Canonical, bounded CBOR responses for the host egress broker.
//!
//! A response is exactly `[version, request_id, outcome_tag, payload]`.
//! Successful public and GitHub effects have closed payload schemas; rejected
//! effects carry only a stable reason code. Provider diagnostics, credentials,
//! and arbitrary strings never cross this boundary.

use std::{error::Error, fmt, iter::FusedIterator, str};

use authority_core::{
    github::GitHubOperation,
    http::{CanonicalHost, CanonicalUrlPath},
};
use sha2::{Digest, Sha256};

use crate::session::{BrokerRequestId, MAX_CONTROL_FRAME_BYTES};

/// The only accepted response schema version.
pub const BROKER_RESPONSE_VERSION: u64 = 1;
/// Maximum public body admitted across a bounded chunked response.
pub const MAX_PUBLIC_WIRE_BODY_BYTES: u64 = 32 * 1024 * 1024;
/// Historical public-body cap whose canonical response still fits one frame.
pub const LEGACY_SINGLE_RESPONSE_BODY_BYTES: u64 = 512 * 1024;
/// Maximum provider bytes that a GitHub success may report.
pub const MAX_GITHUB_WIRE_RESPONSE_BYTES: u64 = 1024 * 1024;
/// The only accepted response-chunk schema version.
pub const BROKER_RESPONSE_CHUNK_VERSION: u64 = 1;
/// Maximum canonical response bytes accepted during bounded reassembly.
pub const MAX_EXPANDED_CANONICAL_RESPONSE_BYTES: usize =
    32 * 1024 * 1024 + MAX_HOST_BYTES + MAX_PATH_BYTES + 128;
/// Maximum response bytes carried by one canonical chunk envelope.
///
/// The reserved 128 bytes cover the fixed schema, request identity, counters,
/// complete-response digest, and worst-case canonical CBOR length heads. Every
/// encoded chunk therefore remains within [`MAX_CONTROL_FRAME_BYTES`].
pub const MAX_RESPONSE_CHUNK_BYTES: usize = MAX_CONTROL_FRAME_BYTES - 128;

const RESPONSE_ITEMS: u64 = 4;
const RESPONSE_CHUNK_ITEMS: u64 = 7;
const PUBLIC_ITEMS: u64 = 4;
const GITHUB_ITEMS: u64 = 4;
const REQUEST_ID_BYTES: usize = 16;
const RESPONSE_DIGEST_BYTES: usize = 32;
const MAX_HOST_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 8 * 1024;
const MAX_OBJECT_ID_BYTES: usize = 64;
const PUBLIC_SUCCESS: u64 = 0;
const GITHUB_SUCCESS: u64 = 1;
const REJECTED: u64 = 2;

/// A bounded public HTTPS result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicWireResponse {
    status: u16,
    host: CanonicalHost,
    path: CanonicalUrlPath,
    body: Vec<u8>,
}

impl PublicWireResponse {
    /// Creates a public response that fits the control-plane wire policy.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseCborError::InvalidValue`] for a non-HTTP status or
    /// overlong canonical host/path, and [`ResponseCborError::PayloadTooLarge`]
    /// when the body exceeds the response cap.
    pub fn new(
        status: u16,
        host: CanonicalHost,
        path: CanonicalUrlPath,
        body: Vec<u8>,
    ) -> Result<Self, ResponseCborError> {
        if !(100..=599).contains(&status)
            || host.as_str().len() > MAX_HOST_BYTES
            || path.to_string().len() > MAX_PATH_BYTES
        {
            return Err(ResponseCborError::InvalidValue);
        }
        if body.len() > max_public_wire_body_bytes_as_usize() {
            return Err(ResponseCborError::PayloadTooLarge { length: body.len() });
        }
        Ok(Self {
            status,
            host,
            path,
            body,
        })
    }

    /// Returns the final HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the final canonical host after redirects.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Returns the final canonical origin path after redirects.
    #[must_use]
    pub const fn path(&self) -> &CanonicalUrlPath {
        &self.path
    }

    /// Returns the bounded response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A bounded typed GitHub result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubWireResponse {
    operation: GitHubOperation,
    response_bytes: u64,
    pull_request_number: Option<u64>,
    object_id: Option<String>,
}

impl GitHubWireResponse {
    /// Creates a typed GitHub result with operation-specific fields.
    ///
    /// `PublishBranch` requires exactly an object ID. `CreatePullRequest`
    /// requires exactly a non-zero pull-request number.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseCborError::InvalidValue`] for mismatched result fields
    /// or a non-canonical object ID, and
    /// [`ResponseCborError::PayloadTooLarge`] for excessive provider bytes.
    pub fn new(
        operation: GitHubOperation,
        response_bytes: u64,
        pull_request_number: Option<u64>,
        object_id: Option<String>,
    ) -> Result<Self, ResponseCborError> {
        if response_bytes > MAX_GITHUB_WIRE_RESPONSE_BYTES {
            return Err(ResponseCborError::PayloadTooLarge {
                length: usize::try_from(response_bytes).unwrap_or(usize::MAX),
            });
        }
        match operation {
            GitHubOperation::PublishBranch => {
                if pull_request_number.is_some()
                    || !object_id.as_deref().is_some_and(valid_object_id)
                {
                    return Err(ResponseCborError::InvalidValue);
                }
            }
            GitHubOperation::CreatePullRequest => {
                if pull_request_number.is_none_or(|number| number == 0) || object_id.is_some() {
                    return Err(ResponseCborError::InvalidValue);
                }
            }
        }
        Ok(Self {
            operation,
            response_bytes,
            pull_request_number,
            object_id,
        })
    }

    /// Returns the completed closed GitHub operation.
    #[must_use]
    pub const fn operation(&self) -> GitHubOperation {
        self.operation
    }

    /// Returns provider bytes charged to the session budget.
    #[must_use]
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Returns the created pull-request number, when applicable.
    #[must_use]
    pub const fn pull_request_number(&self) -> Option<u64> {
        self.pull_request_number
    }

    /// Returns the published object ID, when applicable.
    #[must_use]
    pub fn object_id(&self) -> Option<&str> {
        self.object_id.as_deref()
    }
}

/// Stable detail-free rejection codes returned to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerWireRejection {
    /// Capability or subject was not authorized.
    NotAuthorized,
    /// Session resource budget rejected the request.
    Budget,
    /// The operation did not match its capability family.
    OperationMismatch,
    /// Public fetch policy or transport rejected the effect.
    PublicFetch,
    /// Typed GitHub policy or provider rejected the effect.
    GitHub,
    /// Post-effect accounting could not be trusted.
    AccountingInvariant,
    /// The attempt could not be journaled, so no effect was attempted.
    AuditUnavailable,
    /// The effect committed but its terminal record could not be persisted.
    CommittedButUnrecorded,
}

impl BrokerWireRejection {
    const fn code(self) -> u64 {
        match self {
            Self::NotAuthorized => 0,
            Self::Budget => 1,
            Self::OperationMismatch => 2,
            Self::PublicFetch => 3,
            Self::GitHub => 4,
            Self::AccountingInvariant => 5,
            Self::AuditUnavailable => 6,
            Self::CommittedButUnrecorded => 7,
        }
    }

    fn from_code(code: u64) -> Result<Self, ResponseCborError> {
        match code {
            0 => Ok(Self::NotAuthorized),
            1 => Ok(Self::Budget),
            2 => Ok(Self::OperationMismatch),
            3 => Ok(Self::PublicFetch),
            4 => Ok(Self::GitHub),
            5 => Ok(Self::AccountingInvariant),
            6 => Ok(Self::AuditUnavailable),
            7 => Ok(Self::CommittedButUnrecorded),
            _ => Err(ResponseCborError::UnknownRejection { received: code }),
        }
    }
}

/// The complete closed response outcome universe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerWireOutcome {
    /// A public HTTPS effect completed.
    Public(PublicWireResponse),
    /// A typed GitHub effect completed.
    GitHub(GitHubWireResponse),
    /// The effect was rejected without exposing sensitive diagnostics.
    Rejected(BrokerWireRejection),
}

/// A request-bound canonical Broker response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBrokerResponse {
    request: BrokerRequestId,
    outcome: BrokerWireOutcome,
}

impl CanonicalBrokerResponse {
    /// Creates a response for one exact request identity.
    #[must_use]
    pub const fn new(request: BrokerRequestId, outcome: BrokerWireOutcome) -> Self {
        Self { request, outcome }
    }

    /// Returns the request identity to which this outcome belongs.
    #[must_use]
    pub const fn request(&self) -> BrokerRequestId {
        self.request
    }

    /// Returns the typed response outcome.
    #[must_use]
    pub const fn outcome(&self) -> &BrokerWireOutcome {
        &self.outcome
    }

    /// Encodes the response in its only accepted CBOR representation.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseCborError::PayloadTooLarge`] if the complete response
    /// cannot fit in one bounded control frame.
    pub fn encode(&self) -> Result<Vec<u8>, ResponseCborError> {
        self.encode_with_limit(MAX_CONTROL_FRAME_BYTES)
    }

    /// Splits this response into its one canonical ordered chunk sequence.
    ///
    /// The SHA-256 digest in every chunk binds the sequence to the complete
    /// canonical response encoding. Each returned chunk encodes within the
    /// unchanged one-MiB control-frame limit.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseChunkError::Response`] when the expanded response is
    /// invalid or exceeds its bounded allocation policy.
    pub fn chunks(&self) -> Result<Vec<CanonicalResponseChunk>, ResponseChunkError> {
        self.chunk_iter()?.collect()
    }

    /// Lazily produces the canonical typed chunk sequence.
    ///
    /// The iterator borrows this response and retains only bounded encoding
    /// metadata. Each call allocates exactly one chunk body; collecting the
    /// iterator is an explicit compatibility choice by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseChunkError::Response`] when the expanded response is
    /// invalid or exceeds its bounded allocation policy.
    pub fn chunk_iter(&self) -> Result<CanonicalResponseChunks<'_>, ResponseChunkError> {
        CanonicalResponseChunks::new(self)
    }

    /// Lazily encodes one canonical chunk payload at a time.
    ///
    /// This is the production streaming path. It hashes the response directly
    /// from its typed fields, then copies each canonical byte into exactly one
    /// bounded chunk envelope. It never materializes the complete expanded
    /// response or a collection containing every chunk.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseChunkError`] when the expanded response metadata or a
    /// generated chunk would violate the canonical wire bounds.
    pub fn encoded_chunk_iter(
        &self,
    ) -> Result<CanonicalResponseChunkPayloads<'_>, ResponseChunkError> {
        CanonicalResponseChunkPayloads::new(self)
    }

    /// Reassembles and decodes one complete ordered response chunk sequence.
    ///
    /// # Errors
    ///
    /// Rejects empty, missing, duplicate, reordered, inconsistently bound,
    /// oversized, length-mismatched, or digest-mismatched sequences before a
    /// response is returned.
    pub fn from_chunks(chunks: &[CanonicalResponseChunk]) -> Result<Self, ResponseChunkError> {
        reassemble_response_chunks(chunks)
    }

    fn encode_with_limit(&self, maximum: usize) -> Result<Vec<u8>, ResponseCborError> {
        let encoding = CanonicalResponseEncoding::new(self);
        let encoded_length = encoding.total_length();
        if encoded_length > maximum {
            return Err(ResponseCborError::PayloadTooLarge {
                length: encoded_length,
            });
        }
        let mut output = Vec::with_capacity(encoded_length);
        encoding.for_each_part(|part| output.extend_from_slice(part));
        debug_assert_eq!(output.len(), encoded_length);
        Ok(output)
    }

    /// Decodes exactly one canonical v1 Broker response.
    ///
    /// # Errors
    ///
    /// Rejects oversized input before field retention, non-canonical CBOR,
    /// invalid typed values, unknown codes, truncation, and trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, ResponseCborError> {
        Self::decode_with_limit(encoded, MAX_CONTROL_FRAME_BYTES)
    }

    fn decode_with_limit(encoded: &[u8], maximum: usize) -> Result<Self, ResponseCborError> {
        if encoded.len() > maximum {
            return Err(ResponseCborError::PayloadTooLarge {
                length: encoded.len(),
            });
        }
        let mut decoder = Decoder::new(encoded);
        decoder.array(RESPONSE_ITEMS)?;
        let version = decoder.unsigned()?;
        if version != BROKER_RESPONSE_VERSION {
            return Err(ResponseCborError::UnsupportedVersion { received: version });
        }
        let request = BrokerRequestId::new(decoder.fixed_bytes::<REQUEST_ID_BYTES>()?);
        let outcome = match decoder.unsigned()? {
            PUBLIC_SUCCESS => BrokerWireOutcome::Public(decoder.public_response()?),
            GITHUB_SUCCESS => BrokerWireOutcome::GitHub(decoder.github_response()?),
            REJECTED => {
                BrokerWireOutcome::Rejected(BrokerWireRejection::from_code(decoder.unsigned()?)?)
            }
            received => return Err(ResponseCborError::UnknownOutcome { received }),
        };
        if !decoder.finished() {
            return Err(ResponseCborError::TrailingBytes);
        }
        Ok(Self { request, outcome })
    }

    #[cfg(test)]
    fn encoded_length(&self) -> usize {
        CanonicalResponseEncoding::new(self).total_length()
    }
}

#[derive(Debug)]
struct CanonicalResponseEncoding<'response> {
    response: &'response CanonicalBrokerResponse,
    path_text: Box<str>,
    total_length: usize,
}

impl<'response> CanonicalResponseEncoding<'response> {
    fn new(response: &'response CanonicalBrokerResponse) -> Self {
        let path_text = match response.outcome() {
            BrokerWireOutcome::Public(public) => public.path().to_string().into_boxed_str(),
            BrokerWireOutcome::GitHub(_) | BrokerWireOutcome::Rejected(_) => Box::default(),
        };
        let mut encoding = Self {
            response,
            path_text,
            total_length: 0,
        };
        let mut total_length = 0_usize;
        encoding.for_each_part(|part| {
            total_length = total_length.saturating_add(part.len());
        });
        encoding.total_length = total_length;
        encoding
    }

    const fn total_length(&self) -> usize {
        self.total_length
    }

    fn digest(&self) -> ResponseDigest {
        let mut digest = Sha256::new();
        self.for_each_part(|part| digest.update(part));
        ResponseDigest(digest.finalize().into())
    }

    fn copy_range(
        &self,
        start: usize,
        length: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), ResponseChunkError> {
        let end = start
            .checked_add(length)
            .filter(|end| *end <= self.total_length)
            .ok_or(ResponseChunkError::InvalidMetadata)?;
        let initial_length = output.len();
        let mut position = 0_usize;
        self.for_each_part(|part| {
            let part_end = position.saturating_add(part.len());
            let overlap_start = start.max(position);
            let overlap_end = end.min(part_end);
            if overlap_start < overlap_end {
                output.extend_from_slice(&part[overlap_start - position..overlap_end - position]);
            }
            position = part_end;
        });
        if output.len().saturating_sub(initial_length) != length {
            return Err(ResponseChunkError::InvalidMetadata);
        }
        Ok(())
    }

    fn for_each_part(&self, mut consumer: impl FnMut(&[u8])) {
        emit_head(&mut consumer, 4, RESPONSE_ITEMS);
        emit_head(&mut consumer, 0, BROKER_RESPONSE_VERSION);
        emit_bytes(&mut consumer, self.response.request.as_bytes());
        match &self.response.outcome {
            BrokerWireOutcome::Public(response) => {
                emit_head(&mut consumer, 0, PUBLIC_SUCCESS);
                emit_head(&mut consumer, 4, PUBLIC_ITEMS);
                emit_head(&mut consumer, 0, u64::from(response.status));
                emit_text(&mut consumer, response.host.as_str());
                emit_text(&mut consumer, &self.path_text);
                emit_bytes(&mut consumer, &response.body);
            }
            BrokerWireOutcome::GitHub(response) => {
                emit_head(&mut consumer, 0, GITHUB_SUCCESS);
                emit_head(&mut consumer, 4, GITHUB_ITEMS);
                emit_head(&mut consumer, 0, github_operation_code(response.operation));
                emit_head(&mut consumer, 0, response.response_bytes);
                emit_optional_unsigned(&mut consumer, response.pull_request_number);
                emit_optional_text(&mut consumer, response.object_id.as_deref());
            }
            BrokerWireOutcome::Rejected(rejection) => {
                emit_head(&mut consumer, 0, REJECTED);
                emit_head(&mut consumer, 0, rejection.code());
            }
        }
    }

    #[cfg(test)]
    fn owned_scratch_bytes(&self) -> usize {
        self.path_text.len()
    }
}

#[derive(Debug)]
struct CanonicalChunkSequence<'response> {
    encoding: CanonicalResponseEncoding<'response>,
    count: u64,
    digest: ResponseDigest,
}

impl<'response> CanonicalChunkSequence<'response> {
    fn new(response: &'response CanonicalBrokerResponse) -> Result<Self, ResponseChunkError> {
        let encoding = CanonicalResponseEncoding::new(response);
        if encoding.total_length() > MAX_EXPANDED_CANONICAL_RESPONSE_BYTES {
            return Err(ResponseChunkError::Response(
                ResponseCborError::PayloadTooLarge {
                    length: encoding.total_length(),
                },
            ));
        }
        let count = canonical_chunk_count(encoding.total_length())?;
        let digest = encoding.digest();
        Ok(Self {
            encoding,
            count,
            digest,
        })
    }

    fn chunk(&self, index: u64) -> Result<CanonicalResponseChunk, ResponseChunkError> {
        let length = canonical_chunk_length(self.encoding.total_length(), index)?;
        let offset = chunk_offset(index)?;
        let mut bytes = Vec::with_capacity(length);
        self.encoding.copy_range(offset, length, &mut bytes)?;
        CanonicalResponseChunk::from_parts(
            self.encoding.response.request,
            index,
            self.count,
            self.encoding.total_length(),
            self.digest,
            bytes,
        )
    }

    fn encoded_chunk(&self, index: u64) -> Result<Vec<u8>, ResponseChunkError> {
        let length = canonical_chunk_length(self.encoding.total_length(), index)?;
        let offset = chunk_offset(index)?;
        let mut output = Vec::with_capacity(length.saturating_add(128));
        write_array(&mut output, RESPONSE_CHUNK_ITEMS);
        write_unsigned(&mut output, BROKER_RESPONSE_CHUNK_VERSION);
        write_bytes(&mut output, self.encoding.response.request.as_bytes());
        write_unsigned(&mut output, index);
        write_unsigned(&mut output, self.count);
        write_unsigned(
            &mut output,
            u64::try_from(self.encoding.total_length())
                .map_err(|_| ResponseChunkError::InvalidMetadata)?,
        );
        write_bytes(&mut output, self.digest.as_bytes());
        write_head(
            &mut output,
            2,
            u64::try_from(length).map_err(|_| ResponseChunkError::InvalidMetadata)?,
        );
        self.encoding.copy_range(offset, length, &mut output)?;
        if output.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ResponseChunkError::EncodedChunkTooLarge {
                length: output.len(),
            });
        }
        Ok(output)
    }
}

/// A bounded lazy iterator over typed canonical response chunks.
#[derive(Debug)]
pub struct CanonicalResponseChunks<'response> {
    sequence: CanonicalChunkSequence<'response>,
    next_index: u64,
}

impl<'response> CanonicalResponseChunks<'response> {
    fn new(response: &'response CanonicalBrokerResponse) -> Result<Self, ResponseChunkError> {
        Ok(Self {
            sequence: CanonicalChunkSequence::new(response)?,
            next_index: 0,
        })
    }

    fn remaining(&self) -> usize {
        usize::try_from(self.sequence.count.saturating_sub(self.next_index)).unwrap_or(usize::MAX)
    }
}

impl Iterator for CanonicalResponseChunks<'_> {
    type Item = Result<CanonicalResponseChunk, ResponseChunkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.sequence.count {
            return None;
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        Some(self.sequence.chunk(index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for CanonicalResponseChunks<'_> {}
impl FusedIterator for CanonicalResponseChunks<'_> {}

/// A bounded lazy iterator over already encoded canonical chunk payloads.
///
/// Each yielded vector is suitable for one control frame and is independent of
/// every other iteration. The iterator itself borrows the typed response body.
#[derive(Debug)]
pub struct CanonicalResponseChunkPayloads<'response> {
    sequence: CanonicalChunkSequence<'response>,
    next_index: u64,
}

impl<'response> CanonicalResponseChunkPayloads<'response> {
    fn new(response: &'response CanonicalBrokerResponse) -> Result<Self, ResponseChunkError> {
        Ok(Self {
            sequence: CanonicalChunkSequence::new(response)?,
            next_index: 0,
        })
    }

    fn remaining(&self) -> usize {
        usize::try_from(self.sequence.count.saturating_sub(self.next_index)).unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    fn owned_scratch_bytes(&self) -> usize {
        self.sequence.encoding.owned_scratch_bytes()
    }
}

impl Iterator for CanonicalResponseChunkPayloads<'_> {
    type Item = Result<Vec<u8>, ResponseChunkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.sequence.count {
            return None;
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        Some(self.sequence.encoded_chunk(index))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for CanonicalResponseChunkPayloads<'_> {}
impl FusedIterator for CanonicalResponseChunkPayloads<'_> {}

/// SHA-256 identity of one complete canonical Broker response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseDigest([u8; RESPONSE_DIGEST_BYTES]);

impl ResponseDigest {
    fn of_canonical_response(encoded: &[u8]) -> Self {
        Self(Sha256::digest(encoded).into())
    }

    /// Returns the complete-response digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RESPONSE_DIGEST_BYTES] {
        &self.0
    }
}

/// One request-bound member of a canonical ordered response sequence.
///
/// Wire form:
/// `[version, request_id, chunk_index, chunk_count, total_length, digest, bytes]`.
/// The digest covers the complete canonical [`CanonicalBrokerResponse`], not
/// merely this chunk. Chunk indices are zero-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResponseChunk {
    request: BrokerRequestId,
    index: u64,
    count: u64,
    total_length: usize,
    digest: ResponseDigest,
    bytes: Vec<u8>,
}

impl CanonicalResponseChunk {
    fn from_parts(
        request: BrokerRequestId,
        index: u64,
        count: u64,
        total_length: usize,
        digest: ResponseDigest,
        bytes: Vec<u8>,
    ) -> Result<Self, ResponseChunkError> {
        let chunk = Self {
            request,
            index,
            count,
            total_length,
            digest,
            bytes,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    /// Returns the request identity shared by the complete chunk sequence.
    #[must_use]
    pub const fn request(&self) -> BrokerRequestId {
        self.request
    }

    /// Returns this chunk's zero-based position.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the canonical number of chunks in the response.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the complete canonical response length.
    #[must_use]
    pub const fn total_length(&self) -> usize {
        self.total_length
    }

    /// Returns the digest of the complete canonical response.
    #[must_use]
    pub const fn digest(&self) -> ResponseDigest {
        self.digest
    }

    /// Returns this chunk's bounded response bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encodes this chunk in its only accepted CBOR representation.
    ///
    /// # Errors
    ///
    /// Rejects invalid metadata or payload length and any result that would
    /// exceed the unchanged control-frame cap.
    pub fn encode(&self) -> Result<Vec<u8>, ResponseChunkError> {
        self.validate()?;
        let mut output = Vec::with_capacity(self.bytes.len().saturating_add(128));
        write_array(&mut output, RESPONSE_CHUNK_ITEMS);
        write_unsigned(&mut output, BROKER_RESPONSE_CHUNK_VERSION);
        write_bytes(&mut output, self.request.as_bytes());
        write_unsigned(&mut output, self.index);
        write_unsigned(&mut output, self.count);
        write_unsigned(
            &mut output,
            u64::try_from(self.total_length).map_err(|_| ResponseChunkError::InvalidMetadata)?,
        );
        write_bytes(&mut output, self.digest.as_bytes());
        write_bytes(&mut output, &self.bytes);
        if output.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ResponseChunkError::EncodedChunkTooLarge {
                length: output.len(),
            });
        }
        Ok(output)
    }

    /// Decodes exactly one bounded canonical response chunk.
    ///
    /// # Errors
    ///
    /// Rejects oversized input before retaining fields, non-canonical CBOR,
    /// invalid metadata, non-canonical chunk sizing, truncation, and trailing
    /// bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, ResponseChunkError> {
        if encoded.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ResponseChunkError::EncodedChunkTooLarge {
                length: encoded.len(),
            });
        }
        let mut decoder = Decoder::new(encoded);
        decoder
            .array(RESPONSE_CHUNK_ITEMS)
            .map_err(ResponseChunkError::Response)?;
        let version = decoder.unsigned().map_err(ResponseChunkError::Response)?;
        if version != BROKER_RESPONSE_CHUNK_VERSION {
            return Err(ResponseChunkError::Response(
                ResponseCborError::UnsupportedVersion { received: version },
            ));
        }
        let request = BrokerRequestId::new(
            decoder
                .fixed_bytes::<REQUEST_ID_BYTES>()
                .map_err(ResponseChunkError::Response)?,
        );
        let index = decoder.unsigned().map_err(ResponseChunkError::Response)?;
        let count = decoder.unsigned().map_err(ResponseChunkError::Response)?;
        let total_length =
            usize::try_from(decoder.unsigned().map_err(ResponseChunkError::Response)?)
                .map_err(|_| ResponseChunkError::InvalidMetadata)?;
        let digest = ResponseDigest(
            decoder
                .fixed_bytes::<RESPONSE_DIGEST_BYTES>()
                .map_err(ResponseChunkError::Response)?,
        );
        let bytes = decoder
            .bytes(MAX_RESPONSE_CHUNK_BYTES)
            .map_err(ResponseChunkError::Response)?
            .to_vec();
        if !decoder.finished() {
            return Err(ResponseChunkError::Response(
                ResponseCborError::TrailingBytes,
            ));
        }
        Self::from_parts(request, index, count, total_length, digest, bytes)
    }

    fn validate(&self) -> Result<(), ResponseChunkError> {
        let expected_count = canonical_chunk_count(self.total_length)?;
        if self.count != expected_count || self.index >= self.count {
            return Err(ResponseChunkError::InvalidMetadata);
        }
        let expected = canonical_chunk_length(self.total_length, self.index)?;
        if self.bytes.len() != expected {
            return Err(ResponseChunkError::InvalidChunkLength {
                index: self.index,
                expected,
                received: self.bytes.len(),
            });
        }
        Ok(())
    }
}

/// Why a canonical response chunk or complete sequence was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseChunkError {
    /// The chunk or reassembled response failed canonical response decoding.
    Response(ResponseCborError),
    /// No first chunk was supplied.
    EmptySequence,
    /// Count, index, total length, or deterministic sizing was impossible.
    InvalidMetadata,
    /// One encoded chunk exceeded the control-frame cap.
    EncodedChunkTooLarge {
        /// Observed encoded bytes.
        length: usize,
    },
    /// A chunk was not bound to the sequence's request identity.
    RequestBindingMismatch {
        /// Chunk carrying the inconsistent request identity.
        index: u64,
    },
    /// Count, total length, or digest differed within one sequence.
    InconsistentMetadata {
        /// Chunk carrying inconsistent metadata.
        index: u64,
    },
    /// The same zero-based chunk index appeared more than once.
    DuplicateChunk {
        /// Duplicated index.
        index: u64,
    },
    /// A required zero-based chunk index was absent.
    MissingChunk {
        /// Missing index.
        index: u64,
    },
    /// Every chunk existed, but the supplied sequence order was not canonical.
    ReorderedChunk {
        /// Index required at this position.
        expected: u64,
        /// Index actually supplied at this position.
        received: u64,
    },
    /// One chunk did not carry its deterministic canonical byte count.
    InvalidChunkLength {
        /// Chunk index.
        index: u64,
        /// Required bytes.
        expected: usize,
        /// Received bytes.
        received: usize,
    },
    /// Concatenated bytes did not equal the declared total length.
    TotalLengthMismatch {
        /// Declared complete-response bytes.
        declared: usize,
        /// Reassembled bytes.
        received: usize,
    },
    /// The complete-response SHA-256 digest did not match.
    DigestMismatch,
    /// The decoded response carried a different request identity.
    ResponseRequestMismatch,
}

impl fmt::Display for ResponseChunkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(error) => error.fmt(formatter),
            Self::EmptySequence => formatter.write_str("Broker response chunk sequence is empty"),
            Self::InvalidMetadata => {
                formatter.write_str("Broker response chunk metadata is invalid")
            }
            Self::EncodedChunkTooLarge { length } => write!(
                formatter,
                "encoded Broker response chunk length {length} exceeds the control-frame bound"
            ),
            Self::RequestBindingMismatch { index } => write!(
                formatter,
                "Broker response chunk {index} is bound to a different request"
            ),
            Self::InconsistentMetadata { index } => write!(
                formatter,
                "Broker response chunk {index} has inconsistent sequence metadata"
            ),
            Self::DuplicateChunk { index } => {
                write!(formatter, "Broker response chunk {index} is duplicated")
            }
            Self::MissingChunk { index } => {
                write!(formatter, "Broker response chunk {index} is missing")
            }
            Self::ReorderedChunk { expected, received } => write!(
                formatter,
                "Broker response chunk {received} is reordered; expected {expected}"
            ),
            Self::InvalidChunkLength {
                index,
                expected,
                received,
            } => write!(
                formatter,
                "Broker response chunk {index} has {received} bytes; expected {expected}"
            ),
            Self::TotalLengthMismatch { declared, received } => write!(
                formatter,
                "Broker response chunks declare {declared} bytes but contain {received}"
            ),
            Self::DigestMismatch => {
                formatter.write_str("Broker response chunk digest does not match")
            }
            Self::ResponseRequestMismatch => {
                formatter.write_str("reassembled Broker response is bound to a different request")
            }
        }
    }
}

impl Error for ResponseChunkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Response(error) => Some(error),
            _ => None,
        }
    }
}

/// Validates and reassembles one complete ordered chunk sequence.
///
/// # Errors
///
/// See [`CanonicalBrokerResponse::from_chunks`].
pub fn reassemble_response_chunks(
    chunks: &[CanonicalResponseChunk],
) -> Result<CanonicalBrokerResponse, ResponseChunkError> {
    let Some(first) = chunks.first() else {
        return Err(ResponseChunkError::EmptySequence);
    };
    first.validate()?;
    let count = usize::try_from(first.count).map_err(|_| ResponseChunkError::InvalidMetadata)?;
    let mut seen = vec![false; count];
    for chunk in chunks {
        chunk.validate()?;
        if chunk.request != first.request {
            return Err(ResponseChunkError::RequestBindingMismatch { index: chunk.index });
        }
        if chunk.count != first.count
            || chunk.total_length != first.total_length
            || chunk.digest != first.digest
        {
            return Err(ResponseChunkError::InconsistentMetadata { index: chunk.index });
        }
        let index =
            usize::try_from(chunk.index).map_err(|_| ResponseChunkError::InvalidMetadata)?;
        if seen[index] {
            return Err(ResponseChunkError::DuplicateChunk { index: chunk.index });
        }
        seen[index] = true;
    }
    if let Some(index) = seen.iter().position(|present| !present) {
        return Err(ResponseChunkError::MissingChunk {
            index: u64::try_from(index).map_err(|_| ResponseChunkError::InvalidMetadata)?,
        });
    }
    for (expected, chunk) in chunks.iter().enumerate() {
        let expected = u64::try_from(expected).map_err(|_| ResponseChunkError::InvalidMetadata)?;
        if chunk.index != expected {
            return Err(ResponseChunkError::ReorderedChunk {
                expected,
                received: chunk.index,
            });
        }
    }
    let received = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
    if received != first.total_length {
        return Err(ResponseChunkError::TotalLengthMismatch {
            declared: first.total_length,
            received,
        });
    }
    let mut encoded = Vec::with_capacity(first.total_length);
    for chunk in chunks {
        encoded.extend_from_slice(&chunk.bytes);
    }
    if ResponseDigest::of_canonical_response(&encoded) != first.digest {
        return Err(ResponseChunkError::DigestMismatch);
    }
    let response =
        CanonicalBrokerResponse::decode_with_limit(&encoded, MAX_EXPANDED_CANONICAL_RESPONSE_BYTES)
            .map_err(ResponseChunkError::Response)?;
    if response.request != first.request {
        return Err(ResponseChunkError::ResponseRequestMismatch);
    }
    Ok(response)
}

/// Why a response is not the single accepted canonical representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCborError {
    /// The input or a declared field exceeds its policy cap.
    PayloadTooLarge {
        /// Observed or declared byte length.
        length: usize,
    },
    /// The encoded item ended before its declared fields.
    Truncated,
    /// A CBOR item used the wrong major type.
    UnexpectedMajorType {
        /// Required CBOR major type.
        expected: u8,
        /// Received CBOR major type.
        received: u8,
    },
    /// An integer or length used a wider-than-minimal encoding.
    NonCanonicalInteger,
    /// Indefinite-length items are forbidden.
    IndefiniteLength,
    /// The fixed schema carried the wrong array length.
    UnexpectedArrayLength {
        /// Required item count.
        expected: u64,
        /// Received item count.
        received: u64,
    },
    /// A fixed identity carried the wrong byte length.
    UnexpectedByteStringLength {
        /// Required byte count.
        expected: usize,
        /// Received byte count.
        received: usize,
    },
    /// The response version is unsupported.
    UnsupportedVersion {
        /// Received version.
        received: u64,
    },
    /// The response outcome code is unknown.
    UnknownOutcome {
        /// Received outcome code.
        received: u64,
    },
    /// The rejection code is unknown.
    UnknownRejection {
        /// Received rejection code.
        received: u64,
    },
    /// A typed status, host, path, GitHub result, UTF-8 field, or optional is invalid.
    InvalidValue,
    /// Bytes remained after the fixed response schema.
    TrailingBytes,
}

impl fmt::Display for ResponseCborError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { length } => write!(
                formatter,
                "Broker response payload length {length} exceeds its configured bound"
            ),
            Self::Truncated => formatter.write_str("Broker response CBOR is truncated"),
            Self::UnexpectedMajorType { expected, received } => write!(
                formatter,
                "Broker response requires CBOR major type {expected}, received {received}"
            ),
            Self::NonCanonicalInteger => {
                formatter.write_str("Broker response uses a non-minimal CBOR integer")
            }
            Self::IndefiniteLength => {
                formatter.write_str("Broker response forbids indefinite-length CBOR")
            }
            Self::UnexpectedArrayLength { expected, received } => write!(
                formatter,
                "Broker response requires {expected} array items, received {received}"
            ),
            Self::UnexpectedByteStringLength { expected, received } => write!(
                formatter,
                "Broker response requires {expected} identity bytes, received {received}"
            ),
            Self::UnsupportedVersion { received } => {
                write!(
                    formatter,
                    "Broker response version {received} is unsupported"
                )
            }
            Self::UnknownOutcome { received } => {
                write!(formatter, "Broker response outcome {received} is unknown")
            }
            Self::UnknownRejection { received } => {
                write!(formatter, "Broker response rejection {received} is unknown")
            }
            Self::InvalidValue => formatter.write_str("Broker response contains an invalid value"),
            Self::TrailingBytes => formatter.write_str("Broker response has trailing bytes"),
        }
    }
}

impl Error for ResponseCborError {}

fn github_operation_code(operation: GitHubOperation) -> u64 {
    match operation {
        GitHubOperation::PublishBranch => 0,
        GitHubOperation::CreatePullRequest => 1,
    }
}

fn github_operation_from_code(code: u64) -> Result<GitHubOperation, ResponseCborError> {
    match code {
        0 => Ok(GitHubOperation::PublishBranch),
        1 => Ok(GitHubOperation::CreatePullRequest),
        received => Err(ResponseCborError::UnknownOutcome { received }),
    }
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn max_public_wire_body_bytes_as_usize() -> usize {
    usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
        .expect("the public wire body cap must fit the decoder address space")
}

fn canonical_chunk_count(total_length: usize) -> Result<u64, ResponseChunkError> {
    if total_length == 0 || total_length > MAX_EXPANDED_CANONICAL_RESPONSE_BYTES {
        return Err(ResponseChunkError::InvalidMetadata);
    }
    let count = total_length.div_ceil(MAX_RESPONSE_CHUNK_BYTES);
    u64::try_from(count).map_err(|_| ResponseChunkError::InvalidMetadata)
}

fn canonical_chunk_length(total_length: usize, index: u64) -> Result<usize, ResponseChunkError> {
    let index = usize::try_from(index).map_err(|_| ResponseChunkError::InvalidMetadata)?;
    let offset = index
        .checked_mul(MAX_RESPONSE_CHUNK_BYTES)
        .ok_or(ResponseChunkError::InvalidMetadata)?;
    let remaining = total_length
        .checked_sub(offset)
        .ok_or(ResponseChunkError::InvalidMetadata)?;
    Ok(remaining.min(MAX_RESPONSE_CHUNK_BYTES))
}

fn chunk_offset(index: u64) -> Result<usize, ResponseChunkError> {
    usize::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(MAX_RESPONSE_CHUNK_BYTES))
        .ok_or(ResponseChunkError::InvalidMetadata)
}

fn write_array(output: &mut Vec<u8>, length: u64) {
    write_head(output, 4, length);
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    write_head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

#[cfg(test)]
fn write_text(output: &mut Vec<u8>, text: &str) {
    write_head(output, 3, text.len() as u64);
    output.extend_from_slice(text.as_bytes());
}

fn write_unsigned(output: &mut Vec<u8>, value: u64) {
    write_head(output, 0, value);
}

fn write_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let (encoded, length) = encoded_head(major, value);
    output.extend_from_slice(&encoded[..length]);
}

fn emit_bytes(consumer: &mut impl FnMut(&[u8]), bytes: &[u8]) {
    emit_head(consumer, 2, bytes.len() as u64);
    consumer(bytes);
}

fn emit_text(consumer: &mut impl FnMut(&[u8]), text: &str) {
    emit_head(consumer, 3, text.len() as u64);
    consumer(text.as_bytes());
}

fn emit_optional_unsigned(consumer: &mut impl FnMut(&[u8]), value: Option<u64>) {
    match value {
        Some(value) => emit_head(consumer, 0, value),
        None => consumer(&[0xf6]),
    }
}

fn emit_optional_text(consumer: &mut impl FnMut(&[u8]), value: Option<&str>) {
    match value {
        Some(value) => emit_text(consumer, value),
        None => consumer(&[0xf6]),
    }
}

fn emit_head(consumer: &mut impl FnMut(&[u8]), major: u8, value: u64) {
    let (encoded, length) = encoded_head(major, value);
    consumer(&encoded[..length]);
}

fn encoded_head(major: u8, value: u64) -> ([u8; 9], usize) {
    let mut encoded = [0_u8; 9];
    if value < 24 {
        encoded[0] = (major << 5) | value.to_be_bytes()[7];
        (encoded, 1)
    } else if let Ok(value) = u8::try_from(value) {
        encoded[..2].copy_from_slice(&[(major << 5) | 24, value]);
        (encoded, 2)
    } else if let Ok(value) = u16::try_from(value) {
        encoded[0] = (major << 5) | 25;
        encoded[1..3].copy_from_slice(&value.to_be_bytes());
        (encoded, 3)
    } else if let Ok(value) = u32::try_from(value) {
        encoded[0] = (major << 5) | 26;
        encoded[1..5].copy_from_slice(&value.to_be_bytes());
        (encoded, 5)
    } else {
        encoded[0] = (major << 5) | 27;
        encoded[1..9].copy_from_slice(&value.to_be_bytes());
        (encoded, 9)
    }
}

struct Decoder<'input> {
    input: &'input [u8],
    cursor: usize,
}

impl<'input> Decoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    const fn finished(&self) -> bool {
        self.cursor == self.input.len()
    }

    fn public_response(&mut self) -> Result<PublicWireResponse, ResponseCborError> {
        self.array(PUBLIC_ITEMS)?;
        let status =
            u16::try_from(self.unsigned()?).map_err(|_| ResponseCborError::InvalidValue)?;
        let host_text = self.text(MAX_HOST_BYTES)?;
        let path_text = self.text(MAX_PATH_BYTES)?;
        let body = self.bytes(max_public_wire_body_bytes_as_usize())?;
        let host = CanonicalHost::new(host_text).map_err(|_| ResponseCborError::InvalidValue)?;
        let path = CanonicalUrlPath::new(path_text).map_err(|_| ResponseCborError::InvalidValue)?;
        PublicWireResponse::new(status, host, path, body.to_vec())
    }

    fn github_response(&mut self) -> Result<GitHubWireResponse, ResponseCborError> {
        self.array(GITHUB_ITEMS)?;
        let operation = github_operation_from_code(self.unsigned()?)?;
        let response_bytes = self.unsigned()?;
        let pull_request_number = self.optional_unsigned()?;
        let object_id = self.optional_text(MAX_OBJECT_ID_BYTES)?.map(str::to_owned);
        GitHubWireResponse::new(operation, response_bytes, pull_request_number, object_id)
    }

    fn array(&mut self, expected: u64) -> Result<(), ResponseCborError> {
        let received = self.head(4)?;
        if received == expected {
            Ok(())
        } else {
            Err(ResponseCborError::UnexpectedArrayLength { expected, received })
        }
    }

    fn unsigned(&mut self) -> Result<u64, ResponseCborError> {
        self.head(0)
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], ResponseCborError> {
        let bytes = self.bytes(N)?;
        if bytes.len() != N {
            return Err(ResponseCborError::UnexpectedByteStringLength {
                expected: N,
                received: bytes.len(),
            });
        }
        bytes.try_into().map_err(|_| ResponseCborError::Truncated)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'input [u8], ResponseCborError> {
        let declared = self.head(2)?;
        let length = usize::try_from(declared)
            .map_err(|_| ResponseCborError::PayloadTooLarge { length: usize::MAX })?;
        if length > maximum {
            return Err(ResponseCborError::PayloadTooLarge { length });
        }
        self.take(length)
    }

    fn text(&mut self, maximum: usize) -> Result<&'input str, ResponseCborError> {
        let declared = self.head(3)?;
        let length = usize::try_from(declared)
            .map_err(|_| ResponseCborError::PayloadTooLarge { length: usize::MAX })?;
        if length > maximum {
            return Err(ResponseCborError::PayloadTooLarge { length });
        }
        str::from_utf8(self.take(length)?).map_err(|_| ResponseCborError::InvalidValue)
    }

    fn optional_unsigned(&mut self) -> Result<Option<u64>, ResponseCborError> {
        if self.peek()? == 0xf6 {
            self.cursor += 1;
            Ok(None)
        } else {
            self.unsigned().map(Some)
        }
    }

    fn optional_text(&mut self, maximum: usize) -> Result<Option<&'input str>, ResponseCborError> {
        if self.peek()? == 0xf6 {
            self.cursor += 1;
            Ok(None)
        } else {
            self.text(maximum).map(Some)
        }
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, ResponseCborError> {
        let initial = self.byte()?;
        let received = initial >> 5;
        if received != expected_major {
            return Err(ResponseCborError::UnexpectedMajorType {
                expected: expected_major,
                received,
            });
        }
        match initial & 0x1f {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => {
                let value = u64::from(self.byte()?);
                (value >= 24)
                    .then_some(value)
                    .ok_or(ResponseCborError::NonCanonicalInteger)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.fixed_raw()?));
                (value > u64::from(u8::MAX))
                    .then_some(value)
                    .ok_or(ResponseCborError::NonCanonicalInteger)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.fixed_raw()?));
                (value > u64::from(u16::MAX))
                    .then_some(value)
                    .ok_or(ResponseCborError::NonCanonicalInteger)
            }
            27 => {
                let value = u64::from_be_bytes(self.fixed_raw()?);
                (value > u64::from(u32::MAX))
                    .then_some(value)
                    .ok_or(ResponseCborError::NonCanonicalInteger)
            }
            31 => Err(ResponseCborError::IndefiniteLength),
            _ => Err(ResponseCborError::InvalidValue),
        }
    }

    fn fixed_raw<const N: usize>(&mut self) -> Result<[u8; N], ResponseCborError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ResponseCborError::Truncated)
    }

    fn peek(&self) -> Result<u8, ResponseCborError> {
        self.input
            .get(self.cursor)
            .copied()
            .ok_or(ResponseCborError::Truncated)
    }

    fn byte(&mut self) -> Result<u8, ResponseCborError> {
        let byte = self.peek()?;
        self.cursor += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], ResponseCborError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ResponseCborError::Truncated)?;
        let bytes = self
            .input
            .get(self.cursor..end)
            .ok_or(ResponseCborError::Truncated)?;
        self.cursor = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use authority_core::{
        github::GitHubOperation,
        http::{CanonicalHost, CanonicalUrlPath},
    };
    use sha2::{Digest, Sha256};

    use super::{
        BROKER_RESPONSE_CHUNK_VERSION, BROKER_RESPONSE_VERSION, BrokerWireOutcome,
        BrokerWireRejection, CanonicalBrokerResponse, CanonicalResponseChunk, GitHubWireResponse,
        LEGACY_SINGLE_RESPONSE_BODY_BYTES, MAX_EXPANDED_CANONICAL_RESPONSE_BYTES,
        MAX_PUBLIC_WIRE_BODY_BYTES, MAX_RESPONSE_CHUNK_BYTES, PUBLIC_ITEMS, PUBLIC_SUCCESS,
        PublicWireResponse, RESPONSE_CHUNK_ITEMS, RESPONSE_ITEMS, ResponseCborError,
        ResponseChunkError, write_array, write_bytes, write_head, write_text, write_unsigned,
    };
    use crate::session::{BrokerRequestId, MAX_CONTROL_FRAME_BYTES};

    fn request() -> BrokerRequestId {
        BrokerRequestId::new([0xab; 16])
    }

    fn public() -> CanonicalBrokerResponse {
        CanonicalBrokerResponse::new(
            request(),
            BrokerWireOutcome::Public(
                PublicWireResponse::new(
                    200,
                    CanonicalHost::new("docs.example").expect("host fixture is canonical"),
                    CanonicalUrlPath::new("/guide").expect("path fixture is canonical"),
                    b"ok".to_vec(),
                )
                .expect("public fixture fits"),
            ),
        )
    }

    fn canonical_public_with_body(body: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        write_array(&mut encoded, RESPONSE_ITEMS);
        write_unsigned(&mut encoded, BROKER_RESPONSE_VERSION);
        write_bytes(&mut encoded, request().as_bytes());
        write_unsigned(&mut encoded, PUBLIC_SUCCESS);
        write_array(&mut encoded, PUBLIC_ITEMS);
        write_unsigned(&mut encoded, 200);
        write_text(&mut encoded, "docs.example");
        write_text(&mut encoded, "/guide");
        write_bytes(&mut encoded, body);
        encoded
    }

    fn public_with_body(body: Vec<u8>) -> CanonicalBrokerResponse {
        CanonicalBrokerResponse::new(
            request(),
            BrokerWireOutcome::Public(
                PublicWireResponse::new(
                    200,
                    CanonicalHost::new("docs.example").expect("host fixture is canonical"),
                    CanonicalUrlPath::new("/guide").expect("path fixture is canonical"),
                    body,
                )
                .expect("public fixture fits"),
            ),
        )
    }

    #[test]
    fn every_outcome_round_trips_through_one_canonical_encoding() {
        let object = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let outcomes = [
            public().outcome().clone(),
            BrokerWireOutcome::GitHub(
                GitHubWireResponse::new(GitHubOperation::PublishBranch, 123, None, Some(object))
                    .expect("publish fixture is valid"),
            ),
            BrokerWireOutcome::GitHub(
                GitHubWireResponse::new(GitHubOperation::CreatePullRequest, 456, Some(42), None)
                    .expect("pull request fixture is valid"),
            ),
            BrokerWireOutcome::Rejected(BrokerWireRejection::NotAuthorized),
            BrokerWireOutcome::Rejected(BrokerWireRejection::Budget),
            BrokerWireOutcome::Rejected(BrokerWireRejection::OperationMismatch),
            BrokerWireOutcome::Rejected(BrokerWireRejection::PublicFetch),
            BrokerWireOutcome::Rejected(BrokerWireRejection::GitHub),
            BrokerWireOutcome::Rejected(BrokerWireRejection::AccountingInvariant),
        ];
        for outcome in outcomes {
            let response = CanonicalBrokerResponse::new(request(), outcome);
            let encoded = response.encode().expect("fixture must encode");
            assert_eq!(CanonicalBrokerResponse::decode(&encoded), Ok(response));
        }
    }

    #[test]
    fn constructor_rejects_public_and_github_boundary_violations() {
        let host = CanonicalHost::new("docs.example").expect("host fixture is canonical");
        let path = CanonicalUrlPath::new("/guide").expect("path fixture is canonical");
        assert_eq!(
            PublicWireResponse::new(99, host, path, Vec::new()),
            Err(ResponseCborError::InvalidValue)
        );
        assert_eq!(
            GitHubWireResponse::new(GitHubOperation::PublishBranch, 1, None, None),
            Err(ResponseCborError::InvalidValue)
        );
        assert_eq!(
            GitHubWireResponse::new(GitHubOperation::CreatePullRequest, 1, Some(0), None),
            Err(ResponseCborError::InvalidValue)
        );
        assert_eq!(
            GitHubWireResponse::new(
                GitHubOperation::PublishBranch,
                1,
                None,
                Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01".to_owned())
            ),
            Err(ResponseCborError::InvalidValue)
        );
    }

    #[test]
    fn public_body_at_wire_cap_has_one_canonical_round_trip() {
        let maximum = usize::try_from(LEGACY_SINGLE_RESPONSE_BODY_BYTES)
            .expect("wire body cap must fit the test address space");
        let body = vec![0xa5; maximum];
        let response = CanonicalBrokerResponse::new(
            request(),
            BrokerWireOutcome::Public(
                PublicWireResponse::new(
                    200,
                    CanonicalHost::new("docs.example").expect("host fixture is canonical"),
                    CanonicalUrlPath::new("/guide").expect("path fixture is canonical"),
                    body.clone(),
                )
                .expect("a body exactly at the wire cap must fit"),
            ),
        );
        let canonical = canonical_public_with_body(&body);

        assert_eq!(response.encode(), Ok(canonical.clone()));
        assert_eq!(CanonicalBrokerResponse::decode(&canonical), Ok(response));
    }

    #[test]
    fn public_body_one_byte_over_expanded_cap_is_rejected_canonically() {
        let length = usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("wire body cap must fit the test address space")
            + 1;
        let body = vec![0xa5; length];
        assert_eq!(
            PublicWireResponse::new(
                200,
                CanonicalHost::new("docs.example").expect("host fixture is canonical"),
                CanonicalUrlPath::new("/guide").expect("path fixture is canonical"),
                body.clone(),
            ),
            Err(ResponseCborError::PayloadTooLarge { length })
        );
    }

    #[test]
    fn expanded_public_response_at_32_mib_streams_with_bounded_iterator_state() {
        let maximum = usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("expanded body cap must fit the test address space");
        let response = public_with_body(vec![0xa5; maximum]);

        assert!(matches!(
            response.encode(),
            Err(ResponseCborError::PayloadTooLarge { .. })
        ));
        let mut payloads = response
            .encoded_chunk_iter()
            .expect("a response at the expanded cap must split lazily");
        let chunk_count = payloads.len();
        assert!(chunk_count > 1);
        assert!(
            payloads.owned_scratch_bytes() <= super::MAX_PATH_BYTES,
            "the iterator may retain bounded path text but never a response-body copy"
        );
        let mut complete_digest = Sha256::new();
        let mut expected_digest = None;
        let mut received = 0_usize;
        for expected in 0..chunk_count {
            let encoded = payloads
                .next()
                .expect("declared chunk must exist")
                .expect("each chunk must encode");
            assert!(encoded.len() <= MAX_CONTROL_FRAME_BYTES);
            let chunk = CanonicalResponseChunk::decode(&encoded).expect("canonical chunk");
            assert_eq!(chunk.index(), expected as u64);
            assert_eq!(chunk.count(), chunk_count as u64);
            assert_eq!(chunk.request(), request());
            assert!(chunk.bytes().len() <= MAX_RESPONSE_CHUNK_BYTES);
            assert_eq!(chunk.total_length(), response.encoded_length());
            assert!(chunk.total_length() <= MAX_EXPANDED_CANONICAL_RESPONSE_BYTES);
            complete_digest.update(chunk.bytes());
            received += chunk.bytes().len();
            assert_eq!(
                *expected_digest.get_or_insert(chunk.digest()),
                chunk.digest()
            );
        }
        assert!(payloads.next().is_none());
        assert_eq!(received, response.encoded_length());
        let calculated_digest: [u8; 32] = complete_digest.finalize().into();
        assert_eq!(
            expected_digest
                .expect("expanded sequence carries a digest")
                .as_bytes(),
            &calculated_digest
        );
    }

    #[test]
    fn lazy_encoded_chunk_payloads_match_typed_chunks_and_round_trip() {
        let response = public_with_body(vec![0x7c; MAX_RESPONSE_CHUNK_BYTES + 17]);
        let encoded = response
            .encoded_chunk_iter()
            .expect("fixture must stream")
            .collect::<Result<Vec<_>, _>>()
            .expect("every lazy chunk must encode");
        let typed = response
            .chunk_iter()
            .expect("fixture must split")
            .collect::<Result<Vec<_>, _>>()
            .expect("every typed chunk must construct");
        let compatibility = typed
            .iter()
            .map(|chunk| chunk.encode().expect("typed chunk must encode"))
            .collect::<Vec<_>>();

        assert_eq!(encoded, compatibility);
        assert_eq!(CanonicalBrokerResponse::from_chunks(&typed), Ok(response));
    }

    #[test]
    fn canonical_chunk_boundaries_round_trip_after_wire_decode() {
        // Requirement: every canonical response split remains request-bound,
        // digest-bound, and byte-identical after each chunk crosses the wire.
        // Boundary classes: empty body, one byte, just below/at/above a chunk
        // payload boundary, and a response spanning three canonical chunks.
        let body_lengths = [
            0,
            1,
            MAX_RESPONSE_CHUNK_BYTES.saturating_sub(256),
            MAX_RESPONSE_CHUNK_BYTES,
            MAX_RESPONSE_CHUNK_BYTES.saturating_add(256),
            MAX_RESPONSE_CHUNK_BYTES
                .saturating_mul(2)
                .saturating_add(17),
        ];

        for (value, body_length) in body_lengths.into_iter().enumerate() {
            let fill = u8::try_from(value).expect("boundary fixture index must fit in one byte");
            let response = public_with_body(vec![fill; body_length]);
            let chunks = response.chunks().expect("bounded response must split");
            assert!(!chunks.is_empty());
            let expected_digest = chunks[0].digest();
            assert!(chunks.iter().all(|chunk| {
                chunk.request() == request()
                    && chunk.digest() == expected_digest
                    && chunk.total_length() > 0
            }));

            let encoded = chunks
                .iter()
                .map(|chunk| chunk.encode().expect("canonical chunk must encode"))
                .collect::<Vec<_>>();
            let decoded = encoded
                .iter()
                .map(|payload| {
                    CanonicalResponseChunk::decode(payload).expect("canonical chunk must decode")
                })
                .collect::<Vec<_>>();
            assert_eq!(decoded, chunks);
            assert_eq!(CanonicalBrokerResponse::from_chunks(&decoded), Ok(response));
        }
    }

    #[test]
    fn reassembly_distinguishes_missing_duplicate_and_reordered_chunks() {
        let response = public_with_body(vec![0x5a; MAX_RESPONSE_CHUNK_BYTES]);
        let chunks = response
            .chunks()
            .expect("fixture must require multiple chunks");
        assert_eq!(chunks.len(), 2);

        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&chunks[..1]),
            Err(ResponseChunkError::MissingChunk { index: 1 })
        );
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&[chunks[0].clone(), chunks[0].clone()]),
            Err(ResponseChunkError::DuplicateChunk { index: 0 })
        );
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&[chunks[1].clone(), chunks[0].clone()]),
            Err(ResponseChunkError::ReorderedChunk {
                expected: 0,
                received: 1
            })
        );
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&[]),
            Err(ResponseChunkError::EmptySequence)
        );
    }

    #[test]
    fn reassembly_verifies_request_binding_metadata_and_final_digest() {
        let response = public_with_body(vec![0x33; MAX_RESPONSE_CHUNK_BYTES]);
        let chunks = response.chunks().expect("fixture must split");

        let mut wrong_chunk_request = chunks.clone();
        wrong_chunk_request[1].request = BrokerRequestId::new([0xcd; 16]);
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&wrong_chunk_request),
            Err(ResponseChunkError::RequestBindingMismatch { index: 1 })
        );

        let mut wrong_digest_metadata = chunks.clone();
        wrong_digest_metadata[1].digest.0[0] ^= 1;
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&wrong_digest_metadata),
            Err(ResponseChunkError::InconsistentMetadata { index: 1 })
        );

        let mut corrupted = chunks.clone();
        let final_byte = corrupted[1]
            .bytes
            .last_mut()
            .expect("final chunk carries response bytes");
        *final_byte ^= 1;
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&corrupted),
            Err(ResponseChunkError::DigestMismatch)
        );

        let mut wrong_response_binding = chunks;
        for chunk in &mut wrong_response_binding {
            chunk.request = BrokerRequestId::new([0xcd; 16]);
        }
        assert_eq!(
            CanonicalBrokerResponse::from_chunks(&wrong_response_binding),
            Err(ResponseChunkError::ResponseRequestMismatch)
        );
    }

    #[test]
    fn chunk_decoder_is_canonical_and_rejects_oversized_declarations() {
        let chunk = public()
            .chunks()
            .expect("small response has one canonical chunk")
            .remove(0);
        let canonical = chunk.encode().expect("fixture must encode");

        let mut nonminimal_version = canonical.clone();
        nonminimal_version[1] = 0x18;
        nonminimal_version.insert(
            2,
            u8::try_from(BROKER_RESPONSE_CHUNK_VERSION).expect("chunk version fits one byte"),
        );
        assert_eq!(
            CanonicalResponseChunk::decode(&nonminimal_version),
            Err(ResponseChunkError::Response(
                ResponseCborError::NonCanonicalInteger
            ))
        );

        let mut oversized_declaration = Vec::new();
        write_array(&mut oversized_declaration, RESPONSE_CHUNK_ITEMS);
        write_unsigned(&mut oversized_declaration, BROKER_RESPONSE_CHUNK_VERSION);
        write_bytes(&mut oversized_declaration, request().as_bytes());
        write_unsigned(&mut oversized_declaration, 0);
        write_unsigned(&mut oversized_declaration, 1);
        write_unsigned(&mut oversized_declaration, 1);
        write_bytes(&mut oversized_declaration, &[0; 32]);
        write_head(
            &mut oversized_declaration,
            2,
            (MAX_RESPONSE_CHUNK_BYTES + 1) as u64,
        );
        assert!(matches!(
            CanonicalResponseChunk::decode(&oversized_declaration),
            Err(ResponseChunkError::Response(
                ResponseCborError::PayloadTooLarge { .. }
            ))
        ));

        assert_eq!(
            CanonicalResponseChunk::decode(&vec![0; MAX_CONTROL_FRAME_BYTES + 1]),
            Err(ResponseChunkError::EncodedChunkTooLarge {
                length: MAX_CONTROL_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_unknown_and_trailing_forms() {
        let canonical = public().encode().expect("fixture must encode");

        let mut nonminimal_version = canonical.clone();
        nonminimal_version[1] = 0x18;
        nonminimal_version.insert(
            2,
            u8::try_from(BROKER_RESPONSE_VERSION).expect("small version"),
        );
        assert_eq!(
            CanonicalBrokerResponse::decode(&nonminimal_version),
            Err(ResponseCborError::NonCanonicalInteger)
        );

        for first in [0x9f, 0xa4, 0xc0, 0xfb] {
            let mut wrong_type = canonical.clone();
            wrong_type[0] = first;
            assert!(CanonicalBrokerResponse::decode(&wrong_type).is_err());
        }

        let mut wrong_version = canonical.clone();
        wrong_version[1] = 2;
        assert_eq!(
            CanonicalBrokerResponse::decode(&wrong_version),
            Err(ResponseCborError::UnsupportedVersion { received: 2 })
        );

        let mut unknown_outcome = canonical.clone();
        unknown_outcome[19] = 9;
        assert_eq!(
            CanonicalBrokerResponse::decode(&unknown_outcome),
            Err(ResponseCborError::UnknownOutcome { received: 9 })
        );

        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            CanonicalBrokerResponse::decode(&trailing),
            Err(ResponseCborError::TrailingBytes)
        );
    }

    #[test]
    fn decoder_rejects_wrong_identity_invalid_utf8_and_declared_oversize() {
        assert!(matches!(
            CanonicalBrokerResponse::decode(&[0x84, 0x01, 0x4f]),
            Err(ResponseCborError::UnexpectedByteStringLength { .. } | ResponseCborError::Truncated)
        ));

        let mut invalid_utf8 = public().encode().expect("fixture must encode");
        let host = invalid_utf8
            .windows("docs.example".len())
            .position(|window| window == b"docs.example")
            .expect("host bytes must be present");
        invalid_utf8[host] = 0xff;
        assert_eq!(
            CanonicalBrokerResponse::decode(&invalid_utf8),
            Err(ResponseCborError::InvalidValue)
        );

        let mut oversized_body_without_payload = vec![0x84, 0x01, 0x50];
        oversized_body_without_payload.extend_from_slice(&[0; 16]);
        oversized_body_without_payload.extend_from_slice(&[
            0, 0x84, 0x18, 200, 0x61, b'h', 0x61, b'/', 0x5a, 0x02, 0x00, 0x00, 0x01,
        ]);
        let oversized_error = CanonicalBrokerResponse::decode(&oversized_body_without_payload)
            .expect_err("declared oversized body must fail before allocation");
        assert!(
            matches!(oversized_error, ResponseCborError::PayloadTooLarge { .. }),
            "unexpected oversized-body error: {oversized_error:?}"
        );

        let over_frame = vec![0; MAX_CONTROL_FRAME_BYTES + 1];
        assert_eq!(
            CanonicalBrokerResponse::decode(&over_frame),
            Err(ResponseCborError::PayloadTooLarge {
                length: MAX_CONTROL_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn decoder_rejects_unknown_rejection_and_malformed_github_result() {
        let response = CanonicalBrokerResponse::new(
            request(),
            BrokerWireOutcome::Rejected(BrokerWireRejection::Budget),
        );
        let mut unknown = response.encode().expect("fixture must encode");
        *unknown.last_mut().expect("rejection code exists") = 9;
        assert_eq!(
            CanonicalBrokerResponse::decode(&unknown),
            Err(ResponseCborError::UnknownRejection { received: 9 })
        );

        let github = CanonicalBrokerResponse::new(
            request(),
            BrokerWireOutcome::GitHub(
                GitHubWireResponse::new(GitHubOperation::CreatePullRequest, 1, Some(1), None)
                    .expect("fixture is valid"),
            ),
        );
        let mut malformed = github.encode().expect("fixture must encode");
        *malformed.last_mut().expect("optional object exists") = 0x60;
        assert_eq!(
            CanonicalBrokerResponse::decode(&malformed),
            Err(ResponseCborError::InvalidValue)
        );
    }
}
