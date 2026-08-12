//! Bounded, closed wire requests for supervisor control operations.

use std::{error::Error, fmt};

use authority_core::capability::SubjectId;
use authority_core::handle::HandleId;

/// Maximum encoded request size accepted by the supervisor boundary.
pub const MAX_WIRE_REQUEST_BYTES: usize = 4 * 1024;

const PROTOCOL_VERSION: u8 = 1;
const CLOSE_SUBJECT_TAG: u8 = 1;
const CLOSE_HANDLE_TAG: u8 = 2;
const HEADER_BYTES: usize = 4;
const MAX_FIELD_BYTES: usize = 256;

/// A closed set of requests accepted from a connected subject.
///
/// The subject fields are retained for protocol diagnostics and compatibility,
/// but dispatch never uses them for authorization. The caller is selected from
/// the authenticated connection identity supplied to the supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRequest {
    /// Ask the caller's subject to shut down.
    CloseSubject {
        /// Untrusted subject claim carried by the request.
        claimed_subject: SubjectId,
    },
    /// Ask the caller's subject to close one of its handles.
    CloseHandle {
        /// Untrusted subject claim carried by the request.
        claimed_subject: SubjectId,
        /// Authority-core handle identity to close.
        handle: HandleId,
    },
}

impl WireRequest {
    /// Encodes a request using the canonical bounded supervisor wire format.
    pub fn encode(&self) -> Result<Vec<u8>, WireEncodeError> {
        let mut body = Vec::new();
        let tag = match self {
            Self::CloseSubject { claimed_subject } => {
                write_string(&mut body, claimed_subject.as_str(), "claimed subject")?;
                CLOSE_SUBJECT_TAG
            }
            Self::CloseHandle {
                claimed_subject,
                handle,
            } => {
                write_string(&mut body, claimed_subject.as_str(), "claimed subject")?;
                write_string(&mut body, handle.as_str(), "handle")?;
                CLOSE_HANDLE_TAG
            }
        };

        let body_length = u16::try_from(body.len()).map_err(|_| WireEncodeError::TooLarge)?;
        let total_length = HEADER_BYTES
            .checked_add(body.len())
            .ok_or(WireEncodeError::TooLarge)?;
        if total_length > MAX_WIRE_REQUEST_BYTES {
            return Err(WireEncodeError::TooLarge);
        }

        let mut encoded = Vec::with_capacity(total_length);
        encoded.extend_from_slice(&[PROTOCOL_VERSION, tag]);
        encoded.extend_from_slice(&body_length.to_be_bytes());
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    /// Decodes one complete request and rejects unknown, malformed, or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireDecodeError> {
        if bytes.len() > MAX_WIRE_REQUEST_BYTES {
            return Err(WireDecodeError::TooLarge {
                actual: bytes.len(),
            });
        }
        if bytes.len() < HEADER_BYTES {
            return Err(WireDecodeError::Truncated);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(WireDecodeError::UnsupportedVersion(bytes[0]));
        }

        let declared_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let actual_body = bytes.len() - HEADER_BYTES;
        if declared_length != actual_body {
            return Err(WireDecodeError::LengthMismatch {
                declared: declared_length,
                actual: actual_body,
            });
        }

        let mut reader = Reader::new(&bytes[HEADER_BYTES..]);
        let request = match bytes[1] {
            CLOSE_SUBJECT_TAG => Self::CloseSubject {
                claimed_subject: SubjectId::new(reader.read_string("claimed subject")?),
            },
            CLOSE_HANDLE_TAG => Self::CloseHandle {
                claimed_subject: SubjectId::new(reader.read_string("claimed subject")?),
                handle: HandleId::new(reader.read_string("handle")?),
            },
            tag => return Err(WireDecodeError::UnknownTag(tag)),
        };
        reader.finish()?;
        Ok(request)
    }
}

/// An encoding failure at the supervisor wire boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEncodeError {
    /// A field is empty and therefore cannot identify a protocol object.
    EmptyField(&'static str),
    /// A field exceeds the bounded wire field size.
    FieldTooLarge(&'static str),
    /// The complete request exceeds the protocol size limit.
    TooLarge,
}

impl fmt::Display for WireEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "wire field `{field}` is empty"),
            Self::FieldTooLarge(field) => {
                write!(
                    formatter,
                    "wire field `{field}` exceeds {MAX_FIELD_BYTES} bytes"
                )
            }
            Self::TooLarge => write!(
                formatter,
                "wire request exceeds {MAX_WIRE_REQUEST_BYTES} bytes"
            ),
        }
    }
}

impl Error for WireEncodeError {}

/// A decoding failure at the supervisor wire boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireDecodeError {
    /// The byte slice is shorter than the fixed header.
    Truncated,
    /// The byte slice exceeds the protocol size limit.
    TooLarge {
        /// Number of bytes supplied by the peer.
        actual: usize,
    },
    /// The protocol version is not accepted.
    UnsupportedVersion(u8),
    /// The body length does not match the complete datagram.
    LengthMismatch {
        /// Body length declared by the peer.
        declared: usize,
        /// Body bytes actually present in the datagram.
        actual: usize,
    },
    /// The operation tag is outside the closed request union.
    UnknownTag(u8),
    /// A field has an invalid length or encoding.
    InvalidField(&'static str),
    /// Bytes remain after the selected typed request has been decoded.
    TrailingBytes,
}

impl fmt::Display for WireDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("wire request is shorter than its header"),
            Self::TooLarge { actual } => write!(
                formatter,
                "wire request has {actual} bytes, maximum is {MAX_WIRE_REQUEST_BYTES}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "wire protocol version {version} is not supported"
                )
            }
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "wire body declares {declared} bytes but contains {actual} bytes"
            ),
            Self::UnknownTag(tag) => write!(formatter, "wire request tag {tag} is not accepted"),
            Self::InvalidField(field) => write!(formatter, "wire field `{field}` is invalid"),
            Self::TrailingBytes => formatter.write_str("wire request contains trailing bytes"),
        }
    }
}

impl Error for WireDecodeError {}

fn write_string(
    output: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), WireEncodeError> {
    if value.is_empty() {
        return Err(WireEncodeError::EmptyField(field));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(WireEncodeError::FieldTooLarge(field));
    }
    let length = u16::try_from(value.len()).map_err(|_| WireEncodeError::FieldTooLarge(field))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, WireDecodeError> {
        let length = self.read_u16(field)?;
        let length = usize::from(length);
        if length == 0 || length > MAX_FIELD_BYTES {
            return Err(WireDecodeError::InvalidField(field));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireDecodeError::InvalidField(field))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireDecodeError::InvalidField(field))?;
        self.offset = end;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireDecodeError::InvalidField(field))
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, WireDecodeError> {
        let end = self
            .offset
            .checked_add(2)
            .ok_or(WireDecodeError::InvalidField(field))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireDecodeError::InvalidField(field))?;
        self.offset = end;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn finish(self) -> Result<(), WireDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireDecodeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_WIRE_REQUEST_BYTES, WireDecodeError, WireEncodeError, WireRequest};
    use authority_core::{capability::SubjectId, handle::HandleId};

    #[test]
    fn wire_round_trip_preserves_closed_variant() {
        let request = WireRequest::CloseHandle {
            claimed_subject: SubjectId::new("claimed-subject"),
            handle: HandleId::new("handle-1"),
        };

        let encoded = request.encode().expect("valid request must encode");
        assert_eq!(WireRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn decoder_rejects_unknown_tag() {
        let encoded = [1, 99, 0, 0];

        assert_eq!(
            WireRequest::decode(&encoded),
            Err(WireDecodeError::UnknownTag(99))
        );
    }

    #[test]
    fn decoder_rejects_oversized_datagram_before_allocating_fields() {
        let bytes = vec![0_u8; MAX_WIRE_REQUEST_BYTES + 1];

        assert_eq!(
            WireRequest::decode(&bytes),
            Err(WireDecodeError::TooLarge {
                actual: MAX_WIRE_REQUEST_BYTES + 1
            })
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes_and_length_mismatch() {
        let mut encoded = WireRequest::CloseSubject {
            claimed_subject: SubjectId::new("subject"),
        }
        .encode()
        .expect("valid request must encode");
        encoded.push(0);
        assert_eq!(
            WireRequest::decode(&encoded),
            Err(WireDecodeError::LengthMismatch {
                declared: 9,
                actual: 10,
            })
        );
    }

    #[test]
    fn encoder_bounds_utf8_fields_by_encoded_bytes() {
        let too_large = authority_core::capability::SubjectId::new("é".repeat(129));
        assert_eq!(
            WireRequest::CloseSubject {
                claimed_subject: too_large,
            }
            .encode(),
            Err(WireEncodeError::FieldTooLarge("claimed subject"))
        );
        assert_eq!(
            WireRequest::CloseHandle {
                claimed_subject: authority_core::capability::SubjectId::new("subject"),
                handle: HandleId::new(""),
            }
            .encode(),
            Err(WireEncodeError::EmptyField("handle"))
        );
    }

    #[test]
    fn decoder_rejects_invalid_utf8_and_truncated_fields() {
        let invalid_utf8 = [1, 1, 0, 3, 0, 1, 0xff];
        assert_eq!(
            WireRequest::decode(&invalid_utf8),
            Err(WireDecodeError::InvalidField("claimed subject"))
        );

        let truncated = [1, 1, 0, 3, 0, 2, b'a'];
        assert_eq!(
            WireRequest::decode(&truncated),
            Err(WireDecodeError::InvalidField("claimed subject"))
        );
    }
}
