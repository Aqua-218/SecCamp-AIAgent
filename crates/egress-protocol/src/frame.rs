//! Bounded length-prefixed control-frame validation.
//!
//! The transport must decode the four-byte length before allocating the
//! payload buffer. Canonical CBOR parsing belongs above this framing layer;
//! this module intentionally treats payload bytes as opaque.

use std::{error::Error, fmt};

use crate::session::MAX_CONTROL_FRAME_BYTES;

/// The fixed big-endian prefix size of a control frame.
pub const CONTROL_FRAME_LENGTH_PREFIX_BYTES: usize = 4;

/// A control-frame payload length that has passed the allocation limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatedFrameLength(usize);

impl ValidatedFrameLength {
    /// Parses and bounds-checks a four-byte network-order payload length.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::FrameTooLarge`] before the caller allocates when
    /// the peer-advertised payload exceeds [`MAX_CONTROL_FRAME_BYTES`].
    pub fn from_network_prefix(
        prefix: [u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES],
    ) -> Result<Self, FrameError> {
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_CONTROL_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge { length });
        }
        Ok(Self(length))
    }

    /// Returns the accepted payload length in bytes.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

/// An opaque control payload with a validated encoded length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    payload: Vec<u8>,
    wire_length: u32,
}

impl ControlFrame {
    /// Creates one bounded opaque control payload.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::FrameTooLarge`] without retaining `payload` when
    /// it exceeds [`MAX_CONTROL_FRAME_BYTES`].
    pub fn new(payload: Vec<u8>) -> Result<Self, FrameError> {
        let length = payload.len();
        if length > MAX_CONTROL_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge { length });
        }
        let wire_length =
            u32::try_from(length).map_err(|_| FrameError::FrameTooLarge { length })?;
        Ok(Self {
            payload,
            wire_length,
        })
    }

    /// Returns the opaque payload bytes for canonical-CBOR verification.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Returns the encoded frame length, including the prefix.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        CONTROL_FRAME_LENGTH_PREFIX_BYTES + self.payload.len()
    }

    /// Encodes the frame with its four-byte big-endian length prefix.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&self.wire_length.to_be_bytes());
        encoded.extend_from_slice(self.payload());
        encoded
    }

    /// Decodes exactly one complete frame from an already buffered byte slice.
    ///
    /// A streaming transport should call [`ValidatedFrameLength::from_network_prefix`]
    /// first, allocate only that bounded number of payload bytes, and then use
    /// [`Self::new`] for the received payload. This helper is for buffered test
    /// inputs and never substitutes for that allocation order.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated prefix/payload, an over-limit length,
    /// or trailing bytes that would otherwise be interpreted as another frame.
    pub fn decode_complete(encoded: &[u8]) -> Result<Self, FrameError> {
        let prefix: [u8; CONTROL_FRAME_LENGTH_PREFIX_BYTES] = encoded
            .get(..CONTROL_FRAME_LENGTH_PREFIX_BYTES)
            .ok_or(FrameError::TruncatedPrefix)?
            .try_into()
            .map_err(|_| FrameError::TruncatedPrefix)?;
        let length = ValidatedFrameLength::from_network_prefix(prefix)?.as_usize();
        let payload = encoded.get(CONTROL_FRAME_LENGTH_PREFIX_BYTES..).ok_or(
            FrameError::TruncatedPayload {
                expected: length,
                actual: 0,
            },
        )?;
        if payload.len() < length {
            return Err(FrameError::TruncatedPayload {
                expected: length,
                actual: payload.len(),
            });
        }
        if payload.len() > length {
            return Err(FrameError::TrailingBytes {
                declared: length,
                trailing: payload.len() - length,
            });
        }
        Self::new(payload.to_vec())
    }
}

/// Why an encoded control frame cannot be safely accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The peer advertised a payload longer than the allocation ceiling.
    FrameTooLarge {
        /// The untrusted length from the frame prefix or local payload.
        length: usize,
    },
    /// The input ended before the fixed prefix was complete.
    TruncatedPrefix,
    /// The input ended before the declared payload length was present.
    TruncatedPayload {
        /// Payload bytes declared by the prefix.
        expected: usize,
        /// Payload bytes actually present after the prefix.
        actual: usize,
    },
    /// The input encoded more than one frame or otherwise carried extra data.
    TrailingBytes {
        /// Payload bytes declared by the prefix.
        declared: usize,
        /// Bytes remaining after the declared payload.
        trailing: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { length } => write!(
                formatter,
                "control frame length {length} exceeds the {MAX_CONTROL_FRAME_BYTES} byte limit"
            ),
            Self::TruncatedPrefix => {
                formatter.write_str("control frame is missing its length prefix")
            }
            Self::TruncatedPayload { expected, actual } => write!(
                formatter,
                "control frame payload is truncated: expected {expected} bytes, received {actual}"
            ),
            Self::TrailingBytes { declared, trailing } => write!(
                formatter,
                "control frame declares {declared} payload bytes but has {trailing} trailing bytes"
            ),
        }
    }
}

impl Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_FRAME_LENGTH_PREFIX_BYTES, ControlFrame, FrameError, ValidatedFrameLength,
    };
    use crate::session::MAX_CONTROL_FRAME_BYTES;

    #[test]
    fn validated_length_rejects_an_oversized_peer_prefix_before_allocation() {
        assert_eq!(
            ValidatedFrameLength::from_network_prefix(
                u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
                    .expect("test limit must fit in u32")
                    .to_be_bytes(),
            ),
            Err(FrameError::FrameTooLarge {
                length: MAX_CONTROL_FRAME_BYTES + 1,
            })
        );
        assert_eq!(
            ValidatedFrameLength::from_network_prefix([0, 0, 0, 0])
                .expect("empty payload must be valid")
                .as_usize(),
            0
        );
    }

    #[test]
    fn frame_round_trip_has_exactly_one_network_order_prefix() {
        let frame = ControlFrame::new(vec![0x82, 0x01, 0x02]).expect("small payload must fit");
        let encoded = frame.encode();

        assert_eq!(encoded.len(), CONTROL_FRAME_LENGTH_PREFIX_BYTES + 3);
        assert_eq!(&encoded[..CONTROL_FRAME_LENGTH_PREFIX_BYTES], &[0, 0, 0, 3]);
        assert_eq!(ControlFrame::decode_complete(&encoded), Ok(frame));
    }

    #[test]
    fn frame_decoder_rejects_truncation_trailing_data_and_oversized_input() {
        assert_eq!(
            ControlFrame::decode_complete(&[0, 0, 0]),
            Err(FrameError::TruncatedPrefix)
        );
        assert_eq!(
            ControlFrame::decode_complete(&[0, 0, 0, 2, 0x01]),
            Err(FrameError::TruncatedPayload {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            ControlFrame::decode_complete(&[0, 0, 0, 1, 0x01, 0x02]),
            Err(FrameError::TrailingBytes {
                declared: 1,
                trailing: 1,
            })
        );
        assert_eq!(
            ControlFrame::decode_complete(
                &u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
                    .expect("test limit must fit in u32")
                    .to_be_bytes(),
            ),
            Err(FrameError::FrameTooLarge {
                length: MAX_CONTROL_FRAME_BYTES + 1,
            })
        );
    }
}
