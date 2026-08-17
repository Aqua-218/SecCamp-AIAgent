//! Canonical CBOR schema for one typed Broker request.
//!
//! This module does not use a general-purpose CBOR value model. The Broker
//! accepts only the fixed, definite-length arrays defined here, and rejects
//! non-minimal numeric widths, indefinite lengths, tags, maps, floats, and
//! every unknown operation code. Keeping the accepted grammar this small makes
//! the bytes hashed by the replay guard unambiguous.

use std::{error::Error, fmt, str};

use authority_core::{
    github::{BranchName, GitHubOperation, GitHubRequest, InstallationId},
    http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest},
    repository::RepoId,
};

use crate::{
    operation::BrokerOperation,
    session::{
        BrokerEnvelope, BrokerRequestId, BrokerSessionId, MAX_CONTROL_FRAME_BYTES, PayloadHash,
    },
};

/// The only version accepted by this canonical CBOR schema.
pub const BROKER_CBOR_PROTOCOL_VERSION: u64 = 1;

const OUTER_REQUEST_ITEMS: u64 = 6;
const PUBLIC_FETCH_ITEMS: u64 = 5;
const GITHUB_ITEMS: u64 = 6;
const PUBLIC_FETCH_OPERATION: u64 = 0;
const GITHUB_OPERATION: u64 = 1;
const GET_METHOD: u64 = 0;
const HEAD_METHOD: u64 = 1;
const PUBLISH_BRANCH_OPERATION: u64 = 0;
const CREATE_PULL_REQUEST_OPERATION: u64 = 1;
const SESSION_ID_BYTES: usize = 16;
const REQUEST_ID_BYTES: usize = 16;
const PAYLOAD_HASH_BYTES: usize = 32;

/// One typed Broker request paired with the canonical operation bytes it hashes.
///
/// The outer CBOR request is
/// `[version, session, sequence, request, payload hash, payload]`. `payload`
/// is a byte string containing a second canonical CBOR item that encodes the
/// closed [`BrokerOperation`] union. Its SHA-256 must equal `payload hash` and
/// is bound into the resulting [`BrokerEnvelope`]. Separating the embedded
/// payload avoids a self-referential hash while keeping the operation bytes
/// stable and the on-wire envelope explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBrokerRequest {
    envelope: BrokerEnvelope,
    operation: BrokerOperation,
    canonical_payload: Vec<u8>,
}

impl CanonicalBrokerRequest {
    /// Creates one request and derives its envelope hash from canonical operation bytes.
    #[must_use]
    pub fn new(
        session: BrokerSessionId,
        sequence: u64,
        request: BrokerRequestId,
        operation: BrokerOperation,
    ) -> Self {
        let canonical_payload = encode_operation(&operation);
        let envelope =
            BrokerEnvelope::from_canonical_payload(session, sequence, request, &canonical_payload);
        Self {
            envelope,
            operation,
            canonical_payload,
        }
    }

    /// Decodes exactly one canonical v1 Broker request.
    ///
    /// # Errors
    ///
    /// Rejects over-limit input, non-canonical CBOR, schema mismatches,
    /// invalid authority values, a payload-hash mismatch, and trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, CborError> {
        if encoded.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(CborError::ControlPayloadTooLarge {
                length: encoded.len(),
            });
        }

        let mut decoder = Decoder::new(encoded);
        decoder.array(OUTER_REQUEST_ITEMS)?;
        let version = decoder.unsigned()?;
        if version != BROKER_CBOR_PROTOCOL_VERSION {
            return Err(CborError::UnsupportedProtocolVersion { received: version });
        }
        let session = BrokerSessionId::new(decoder.fixed_bytes::<SESSION_ID_BYTES>()?);
        let sequence = decoder.unsigned()?;
        let request = BrokerRequestId::new(decoder.fixed_bytes::<REQUEST_ID_BYTES>()?);
        let received_payload_hash = decoder.fixed_bytes::<PAYLOAD_HASH_BYTES>()?;
        let canonical_payload = decoder.bytes()?.to_vec();
        decoder.finish()?;

        let operation = decode_operation(&canonical_payload)?;
        let payload_hash = PayloadHash::of_canonical_payload(&canonical_payload);
        if payload_hash.as_bytes() != &received_payload_hash {
            return Err(CborError::PayloadHashMismatch);
        }
        Ok(Self {
            envelope: BrokerEnvelope::from_canonical_payload(
                session,
                sequence,
                request,
                &canonical_payload,
            ),
            operation,
            canonical_payload,
        })
    }

    /// Returns the ordered envelope whose hash binds this exact payload.
    #[must_use]
    pub const fn envelope(&self) -> BrokerEnvelope {
        self.envelope
    }

    /// Returns the closed external operation selected by this request.
    #[must_use]
    pub const fn operation(&self) -> &BrokerOperation {
        &self.operation
    }

    /// Returns the exact canonical operation bytes hashed by the envelope.
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        self.canonical_payload.as_slice()
    }

    /// Encodes the request in its only accepted wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::ControlPayloadTooLarge`] before returning an
    /// over-limit control payload. A caller may then pass the result directly
    /// to [`crate::frame::ControlFrame::new`].
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let mut encoded = Vec::with_capacity(self.canonical_payload.len().saturating_add(64));
        write_array(&mut encoded, OUTER_REQUEST_ITEMS);
        write_unsigned(&mut encoded, BROKER_CBOR_PROTOCOL_VERSION);
        write_bytes(&mut encoded, self.envelope.session().as_bytes());
        write_unsigned(&mut encoded, self.envelope.sequence());
        write_bytes(&mut encoded, self.envelope.request().as_bytes());
        write_bytes(&mut encoded, self.envelope.payload_hash().as_bytes());
        write_bytes(&mut encoded, &self.canonical_payload);
        if encoded.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(CborError::ControlPayloadTooLarge {
                length: encoded.len(),
            });
        }
        Ok(encoded)
    }
}

/// Why bytes cannot be accepted as a canonical Broker CBOR request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// The payload exceeds the control-frame limit before decoding or output.
    ControlPayloadTooLarge {
        /// Number of bytes presented or produced.
        length: usize,
    },
    /// The input ended while decoding a CBOR head or declared content.
    Truncated,
    /// A CBOR item's major type was not the one the fixed schema requires.
    UnexpectedMajorType {
        /// Major type required by the schema.
        expected: u8,
        /// Major type encoded by the peer.
        received: u8,
    },
    /// A numeric value used a longer CBOR representation than necessary.
    NonCanonicalInteger,
    /// Indefinite-length strings, arrays, and maps are never accepted.
    IndefiniteLength,
    /// The CBOR additional-information value is reserved or unsupported.
    UnsupportedAdditionalInformation {
        /// The untrusted five-bit additional-information value.
        additional_information: u8,
    },
    /// An array had a length other than the schema's fixed arity.
    UnexpectedArrayLength {
        /// Array size required at this location.
        expected: u64,
        /// Array size encoded by the peer.
        received: u64,
    },
    /// A fixed-width identity byte string had the wrong number of bytes.
    UnexpectedByteStringLength {
        /// Byte length required by the schema.
        expected: usize,
        /// Byte length encoded by the peer.
        received: u64,
    },
    /// A CBOR text string was not valid UTF-8.
    InvalidUtf8,
    /// The outer schema version is not supported.
    UnsupportedProtocolVersion {
        /// Version encoded by the peer.
        received: u64,
    },
    /// The operation family code is outside the closed union.
    UnknownOperationFamily {
        /// Operation-family code encoded by the peer.
        received: u64,
    },
    /// The public fetch method code is not GET or HEAD.
    UnknownPublicFetchMethod {
        /// Method code encoded by the peer.
        received: u64,
    },
    /// The GitHub operation code is outside the closed provider operation set.
    UnknownGitHubOperation {
        /// Provider operation code encoded by the peer.
        received: u64,
    },
    /// A text field does not satisfy its authority-core canonical validator.
    InvalidAuthorityValue {
        /// Schema field whose value was rejected.
        field: &'static str,
    },
    /// The transmitted hash did not equal SHA-256 of the canonical payload.
    PayloadHashMismatch,
    /// The embedded operation payload itself was not exactly one CBOR item.
    TrailingPayloadBytes,
    /// The outer request carried bytes after the fixed schema completed.
    TrailingRequestBytes,
}

impl fmt::Display for CborError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControlPayloadTooLarge { length } => write!(
                formatter,
                "canonical Broker CBOR payload is {length} bytes and exceeds the {MAX_CONTROL_FRAME_BYTES} byte limit"
            ),
            Self::Truncated => formatter.write_str("canonical Broker CBOR is truncated"),
            Self::UnexpectedMajorType { expected, received } => write!(
                formatter,
                "canonical Broker CBOR requires major type {expected}, received {received}"
            ),
            Self::NonCanonicalInteger => {
                formatter.write_str("canonical Broker CBOR uses a non-minimal integer width")
            }
            Self::IndefiniteLength => {
                formatter.write_str("canonical Broker CBOR does not permit indefinite lengths")
            }
            Self::UnsupportedAdditionalInformation {
                additional_information,
            } => write!(
                formatter,
                "canonical Broker CBOR uses unsupported additional information {additional_information}"
            ),
            Self::UnexpectedArrayLength { expected, received } => write!(
                formatter,
                "canonical Broker CBOR requires an array of {expected} items, received {received}"
            ),
            Self::UnexpectedByteStringLength { expected, received } => write!(
                formatter,
                "canonical Broker CBOR requires a {expected}-byte identity, received {received} bytes"
            ),
            Self::InvalidUtf8 => formatter.write_str("canonical Broker CBOR text is not UTF-8"),
            Self::UnsupportedProtocolVersion { received } => write!(
                formatter,
                "canonical Broker CBOR protocol version {received} is not supported"
            ),
            Self::UnknownOperationFamily { received } => write!(
                formatter,
                "canonical Broker CBOR operation family {received} is not supported"
            ),
            Self::UnknownPublicFetchMethod { received } => write!(
                formatter,
                "canonical Broker CBOR public fetch method {received} is not supported"
            ),
            Self::UnknownGitHubOperation { received } => write!(
                formatter,
                "canonical Broker CBOR GitHub operation {received} is not supported"
            ),
            Self::InvalidAuthorityValue { field } => {
                write!(
                    formatter,
                    "canonical Broker CBOR has an invalid {field} value"
                )
            }
            Self::PayloadHashMismatch => {
                formatter.write_str("canonical Broker CBOR payload hash does not match its payload")
            }
            Self::TrailingPayloadBytes => {
                formatter.write_str("canonical Broker CBOR operation payload has trailing bytes")
            }
            Self::TrailingRequestBytes => {
                formatter.write_str("canonical Broker CBOR request has trailing bytes")
            }
        }
    }
}

impl Error for CborError {}

fn encode_operation(operation: &BrokerOperation) -> Vec<u8> {
    let mut encoded = Vec::new();
    match operation {
        BrokerOperation::PublicFetch(request) => {
            write_array(&mut encoded, PUBLIC_FETCH_ITEMS);
            write_unsigned(&mut encoded, PUBLIC_FETCH_OPERATION);
            write_unsigned(
                &mut encoded,
                match request.method() {
                    HttpFetchMethod::Get => GET_METHOD,
                    HttpFetchMethod::Head => HEAD_METHOD,
                },
            );
            write_text(&mut encoded, request.host().as_str());
            write_text(&mut encoded, &request.path().to_string());
            write_unsigned(&mut encoded, request.max_response_bytes());
        }
        BrokerOperation::GitHub(request) => {
            write_array(&mut encoded, GITHUB_ITEMS);
            write_unsigned(&mut encoded, GITHUB_OPERATION);
            write_text(&mut encoded, request.installation().as_str());
            write_text(&mut encoded, request.repository().as_str());
            write_unsigned(
                &mut encoded,
                match request.operation() {
                    GitHubOperation::PublishBranch => PUBLISH_BRANCH_OPERATION,
                    GitHubOperation::CreatePullRequest => CREATE_PULL_REQUEST_OPERATION,
                },
            );
            write_text(&mut encoded, &request.base().to_string());
            write_text(&mut encoded, &request.head().to_string());
        }
    }
    encoded
}

fn decode_operation(encoded: &[u8]) -> Result<BrokerOperation, CborError> {
    let mut decoder = Decoder::new(encoded);
    let item_count = decoder.array_length()?;
    let family = decoder.unsigned()?;
    let operation = match family {
        PUBLIC_FETCH_OPERATION => decode_public_fetch(&mut decoder, item_count)?,
        GITHUB_OPERATION => decode_github(&mut decoder, item_count)?,
        _ => return Err(CborError::UnknownOperationFamily { received: family }),
    };
    decoder.finish_payload()?;
    Ok(operation)
}

fn decode_public_fetch(
    decoder: &mut Decoder<'_>,
    item_count: u64,
) -> Result<BrokerOperation, CborError> {
    if item_count != PUBLIC_FETCH_ITEMS {
        return Err(CborError::UnexpectedArrayLength {
            expected: PUBLIC_FETCH_ITEMS,
            received: item_count,
        });
    }
    let method = match decoder.unsigned()? {
        GET_METHOD => HttpFetchMethod::Get,
        HEAD_METHOD => HttpFetchMethod::Head,
        received => return Err(CborError::UnknownPublicFetchMethod { received }),
    };
    let host = CanonicalHost::new(decoder.text()?)
        .map_err(|_| CborError::InvalidAuthorityValue { field: "HTTP host" })?;
    let path =
        CanonicalUrlPath::new(decoder.text()?).map_err(|_| CborError::InvalidAuthorityValue {
            field: "HTTP URL path",
        })?;
    let max_response_bytes = decoder.unsigned()?;
    Ok(BrokerOperation::PublicFetch(HttpFetchRequest::new(
        method,
        host,
        path,
        max_response_bytes,
    )))
}

fn decode_github(decoder: &mut Decoder<'_>, item_count: u64) -> Result<BrokerOperation, CborError> {
    if item_count != GITHUB_ITEMS {
        return Err(CborError::UnexpectedArrayLength {
            expected: GITHUB_ITEMS,
            received: item_count,
        });
    }
    let installation = InstallationId::new(decoder.text()?);
    let repository = RepoId::new(decoder.text()?);
    let operation = match decoder.unsigned()? {
        PUBLISH_BRANCH_OPERATION => GitHubOperation::PublishBranch,
        CREATE_PULL_REQUEST_OPERATION => GitHubOperation::CreatePullRequest,
        received => return Err(CborError::UnknownGitHubOperation { received }),
    };
    let base = BranchName::new(decoder.text()?).map_err(|_| CborError::InvalidAuthorityValue {
        field: "GitHub base branch",
    })?;
    let head = BranchName::new(decoder.text()?).map_err(|_| CborError::InvalidAuthorityValue {
        field: "GitHub head branch",
    })?;
    Ok(BrokerOperation::GitHub(GitHubRequest::new(
        installation,
        repository,
        operation,
        base,
        head,
    )))
}

fn write_array(encoded: &mut Vec<u8>, item_count: u64) {
    write_head(encoded, 4, item_count);
}

fn write_bytes(encoded: &mut Vec<u8>, bytes: &[u8]) {
    write_head(encoded, 2, bytes.len() as u64);
    encoded.extend_from_slice(bytes);
}

fn write_text(encoded: &mut Vec<u8>, value: &str) {
    write_head(encoded, 3, value.len() as u64);
    encoded.extend_from_slice(value.as_bytes());
}

fn write_unsigned(encoded: &mut Vec<u8>, value: u64) {
    write_head(encoded, 0, value);
}

fn write_head(encoded: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        encoded.push((major << 5) | u8::try_from(value).expect("small CBOR value must fit"));
    } else if let Ok(value) = u8::try_from(value) {
        encoded.push((major << 5) | 24);
        encoded.push(value);
    } else if let Ok(value) = u16::try_from(value) {
        encoded.push((major << 5) | 25);
        encoded.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        encoded.push((major << 5) | 26);
        encoded.extend_from_slice(&value.to_be_bytes());
    } else {
        encoded.push((major << 5) | 27);
        encoded.extend_from_slice(&value.to_be_bytes());
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

    fn array(&mut self, expected: u64) -> Result<(), CborError> {
        let received = self.array_length()?;
        if received != expected {
            return Err(CborError::UnexpectedArrayLength { expected, received });
        }
        Ok(())
    }

    fn array_length(&mut self) -> Result<u64, CborError> {
        self.head(4)
    }

    fn unsigned(&mut self) -> Result<u64, CborError> {
        self.head(0)
    }

    fn fixed_bytes<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], CborError> {
        let bytes = self.bytes()?;
        if bytes.len() != LENGTH {
            return Err(CborError::UnexpectedByteStringLength {
                expected: LENGTH,
                received: bytes.len() as u64,
            });
        }
        bytes.try_into().map_err(|_| CborError::Truncated)
    }

    fn bytes(&mut self) -> Result<&'input [u8], CborError> {
        let length = usize::try_from(self.head(2)?).map_err(|_| CborError::Truncated)?;
        self.take(length)
    }

    fn text(&mut self) -> Result<&'input str, CborError> {
        let length = usize::try_from(self.head(3)?).map_err(|_| CborError::Truncated)?;
        str::from_utf8(self.take(length)?).map_err(|_| CborError::InvalidUtf8)
    }

    fn finish(&self) -> Result<(), CborError> {
        if self.cursor == self.input.len() {
            Ok(())
        } else {
            Err(CborError::TrailingRequestBytes)
        }
    }

    fn finish_payload(&self) -> Result<(), CborError> {
        if self.cursor == self.input.len() {
            Ok(())
        } else {
            Err(CborError::TrailingPayloadBytes)
        }
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, CborError> {
        let initial = *self.take(1)?.first().ok_or(CborError::Truncated)?;
        let received_major = initial >> 5;
        if received_major != expected_major {
            return Err(CborError::UnexpectedMajorType {
                expected: expected_major,
                received: received_major,
            });
        }
        let additional_information = initial & 0x1f;
        let value = match additional_information {
            value @ 0..=23 => u64::from(value),
            24 => u64::from(*self.take(1)?.first().ok_or(CborError::Truncated)?),
            25 => u64::from(u16::from_be_bytes(self.fixed::<2>()?)),
            26 => u64::from(u32::from_be_bytes(self.fixed::<4>()?)),
            27 => u64::from_be_bytes(self.fixed::<8>()?),
            31 => return Err(CborError::IndefiniteLength),
            received => {
                return Err(CborError::UnsupportedAdditionalInformation {
                    additional_information: received,
                });
            }
        };
        if !uses_minimal_width(additional_information, value) {
            return Err(CborError::NonCanonicalInteger);
        }
        Ok(value)
    }

    fn fixed<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], CborError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| CborError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], CborError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(CborError::Truncated)?;
        let bytes = self
            .input
            .get(self.cursor..end)
            .ok_or(CborError::Truncated)?;
        self.cursor = end;
        Ok(bytes)
    }
}

const fn uses_minimal_width(additional_information: u8, value: u64) -> bool {
    match additional_information {
        0..=23 => true,
        24 => value >= 24,
        25 => value > u8::MAX as u64,
        26 => value > u16::MAX as u64,
        27 => value > u32::MAX as u64,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use authority_core::{
        github::{BranchName, GitHubOperation, GitHubRequest, InstallationId},
        http::{CanonicalHost, CanonicalUrlPath, HttpFetchMethod, HttpFetchRequest},
        repository::RepoId,
    };

    use super::{BROKER_CBOR_PROTOCOL_VERSION, CanonicalBrokerRequest, CborError};
    use crate::{
        operation::BrokerOperation,
        session::{BrokerRequestId, BrokerSessionId, MAX_CONTROL_FRAME_BYTES, PayloadHash},
    };

    fn session(value: u8) -> BrokerSessionId {
        BrokerSessionId::new([value; 16])
    }

    fn request(value: u8) -> BrokerRequestId {
        BrokerRequestId::new([value; 16])
    }

    fn branch(value: &str) -> BranchName {
        BranchName::new(value).expect("test branch must be canonical")
    }

    fn public_fetch() -> BrokerOperation {
        BrokerOperation::PublicFetch(HttpFetchRequest::new(
            HttpFetchMethod::Get,
            CanonicalHost::new("docs.example").expect("test host must be canonical"),
            CanonicalUrlPath::new("/guide/intro").expect("test path must be canonical"),
            1_024,
        ))
    }

    fn github() -> BrokerOperation {
        BrokerOperation::GitHub(GitHubRequest::new(
            InstallationId::new("installation-a"),
            RepoId::new("github.example/acme/workspace"),
            GitHubOperation::CreatePullRequest,
            branch("main"),
            branch("agents/fix"),
        ))
    }

    #[test]
    fn canonical_round_trips_preserve_exact_request_bytes_for_every_operation_family() {
        for operation in [public_fetch(), github()] {
            let request = CanonicalBrokerRequest::new(session(1), 24, request(2), operation);
            let encoded = request.encode().expect("small request must encode");
            let decoded = CanonicalBrokerRequest::decode(&encoded)
                .expect("canonical encoded request must decode");

            assert_eq!(decoded, request);
            assert_eq!(decoded.encode(), Ok(encoded));
            assert_eq!(
                decoded.envelope().payload_hash(),
                PayloadHash::of_canonical_payload(decoded.canonical_payload())
            );
        }
    }

    #[test]
    fn decoder_rejects_noncanonical_cbor_before_any_operation_is_accepted() {
        let request = CanonicalBrokerRequest::new(session(1), 0, request(2), public_fetch());
        let encoded = request.encode().expect("small request must encode");

        let mut non_minimal_sequence = encoded.clone();
        let sequence_offset = 1 + 1 + 17;
        non_minimal_sequence.splice(sequence_offset..=sequence_offset, [0x18, 0x00]);
        assert_eq!(
            CanonicalBrokerRequest::decode(&non_minimal_sequence),
            Err(CborError::NonCanonicalInteger)
        );

        let mut indefinite_outer_array = encoded;
        indefinite_outer_array[0] = 0x9f;
        assert_eq!(
            CanonicalBrokerRequest::decode(&indefinite_outer_array),
            Err(CborError::IndefiniteLength)
        );
    }

    #[test]
    fn decoder_rejects_unknown_or_invalid_closed_operation_values() {
        let mut unknown_family = vec![0x82, 0x02, 0x00];
        assert_eq!(
            super::decode_operation(&unknown_family),
            Err(CborError::UnknownOperationFamily { received: 2 })
        );

        unknown_family[1] = 0;
        assert_eq!(
            super::decode_operation(&unknown_family),
            Err(CborError::UnexpectedArrayLength {
                expected: 5,
                received: 2,
            })
        );

        let invalid_http_path = vec![
            0x85, 0, 0x00, 0x6c, b'd', b'o', b'c', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 0x64, b'/', b'.', b'.', b'/', 0x00,
        ];
        assert_eq!(
            super::decode_operation(&invalid_http_path),
            Err(CborError::InvalidAuthorityValue {
                field: "HTTP URL path",
            })
        );

        let unknown_github_operation = vec![
            0x86, 1, 0x61, b'i', 0x61, b'r', 0x02, 0x64, b'm', b'a', b'i', b'n', 0x64, b'h', b'e',
            b'a', b'd',
        ];
        assert_eq!(
            super::decode_operation(&unknown_github_operation),
            Err(CborError::UnknownGitHubOperation { received: 2 })
        );
    }

    #[test]
    fn fixed_identities_trailing_bytes_and_control_limits_fail_closed() {
        let request = CanonicalBrokerRequest::new(session(1), 1, request(2), public_fetch());

        let mut short_session = request.encode().expect("small request must encode");
        short_session[2] = 0x4f;
        assert_eq!(
            CanonicalBrokerRequest::decode(&short_session),
            Err(CborError::UnexpectedByteStringLength {
                expected: 16,
                received: 15,
            })
        );

        let mut encoded = request.encode().expect("small request must encode");
        encoded.push(0);
        assert_eq!(
            CanonicalBrokerRequest::decode(&encoded),
            Err(CborError::TrailingRequestBytes)
        );

        let mut mismatched_hash = request.encode().expect("small request must encode");
        let payload_hash_offset = 1 + 1 + 17 + 1 + 17 + 2;
        mismatched_hash[payload_hash_offset] ^= 1;
        assert_eq!(
            CanonicalBrokerRequest::decode(&mismatched_hash),
            Err(CborError::PayloadHashMismatch)
        );

        let too_large = vec![0; MAX_CONTROL_FRAME_BYTES + 1];
        assert_eq!(
            CanonicalBrokerRequest::decode(&too_large),
            Err(CborError::ControlPayloadTooLarge {
                length: MAX_CONTROL_FRAME_BYTES + 1,
            })
        );

        assert_eq!(BROKER_CBOR_PROTOCOL_VERSION, 1);
    }
}
