//! Canonical bounded wire helpers for the local multi-session control socket.

use sha2::{Digest, Sha256};

use crate::control_plane::{
    ControlSessionId, PrincipalId, StartSessionRequest, StopSessionRequest,
};

/// Derives the only principal identity accepted for a kernel-observed Unix peer UID.
#[must_use]
pub fn principal_for_uid(uid: u32) -> PrincipalId {
    let mut digest = Sha256::new();
    digest.update(b"host-controld/principal/uid/v1\0");
    digest.update(uid.to_be_bytes());
    let digest = digest.finalize();
    let mut principal = [0_u8; 16];
    principal.copy_from_slice(&digest[..16]);
    PrincipalId::new(principal)
}

/// Encodes one authenticated start request with its exact two-byte frame length.
#[must_use]
pub fn encode_start(request: StartSessionRequest) -> Vec<u8> {
    let mut body = Vec::with_capacity(50);
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&request.request().as_bytes());
    body.extend_from_slice(&request.tag().as_bytes());
    frame(&body)
}

/// Encodes one authenticated stop request with its exact two-byte frame length.
#[must_use]
pub fn encode_stop(request: StopSessionRequest) -> Vec<u8> {
    let mut body = Vec::with_capacity(66);
    body.extend_from_slice(&[1, 2]);
    body.extend_from_slice(&request.request().as_bytes());
    body.extend_from_slice(&request.tag().as_bytes());
    body.extend_from_slice(&request.session().as_bytes());
    frame(&body)
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 2);
    frame.extend_from_slice(
        &u16::try_from(body.len())
            .expect("control frames are bounded")
            .to_be_bytes(),
    );
    frame.extend_from_slice(body);
    frame
}

/// Successful response decoded from the local controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlResponse {
    /// A worker was durably admitted.
    Started(ControlSessionId),
    /// The exact worker was durably closed.
    Stopped,
    /// Authentication, replay, quota, ownership, health, or persistence denied the request.
    Denied,
}

/// Decodes one complete response body (without the two-byte length prefix).
#[must_use]
pub fn decode_response(body: &[u8]) -> Option<ControlResponse> {
    match body {
        [1, 0] => Some(ControlResponse::Denied),
        [1, 2] => Some(ControlResponse::Stopped),
        [1, 1, session @ ..] if session.len() == 16 => Some(ControlResponse::Started(
            ControlSessionId::new(session.try_into().ok()?),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{ControlAuthenticator, ControlRequestId};

    #[test]
    fn request_frames_and_response_bodies_are_canonical_and_fixed_width() {
        let principal = principal_for_uid(1000);
        let authenticator = ControlAuthenticator::new([7; 32]);
        let start = authenticator.sign_start(principal, ControlRequestId::new([1; 16]));
        assert_eq!(encode_start(start).len(), 52);
        let session = ControlSessionId::new([2; 16]);
        let stop = authenticator.sign_stop(principal, ControlRequestId::new([3; 16]), session);
        assert_eq!(encode_stop(stop).len(), 68);
        let mut response = vec![1, 1];
        response.extend_from_slice(&session.as_bytes());
        assert_eq!(
            decode_response(&response),
            Some(ControlResponse::Started(session))
        );
        assert_eq!(decode_response(&[1, 0]), Some(ControlResponse::Denied));
        assert_eq!(decode_response(&[1, 2]), Some(ControlResponse::Stopped));
        assert_eq!(decode_response(&[1, 2, 0]), None);
    }
}
