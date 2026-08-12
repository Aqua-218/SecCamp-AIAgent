//! Conversion of host session identities into Firecracker guest identities.
//!
//! The guest identity bundle intentionally contains only the five identity
//! domains accepted by Firecracker. The orchestrated session and workspace
//! identities remain host-only domains and are not used as substitutes.

use crate::{ID_BYTES, SessionIdentity};
use firecracker_runtime::{IdentityBundle, IdentityId, RuntimeError};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Converts a session identity into the corresponding Firecracker identity bundle.
///
/// Each source identity is encoded from its fixed bytes as deterministic,
/// lower-case hexadecimal text before Firecracker parses it. The host-only
/// workspace and orchestrated session identities are deliberately excluded;
/// the bundle's session field is sourced from the Broker session identity.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidIdentity`] when any mapped source identity is
/// all zeroes. Returns [`RuntimeError::StaleIdentity`] when mapped domains are
/// not distinct.
pub fn to_firecracker_identity_bundle(
    identity: &SessionIdentity,
) -> Result<IdentityBundle, RuntimeError> {
    let vm_id = to_identity_id(identity.vm_id().as_bytes())?;
    let session_id = to_identity_id(identity.broker_session_id().as_bytes())?;
    let request_id = to_identity_id(identity.request_id().as_bytes())?;
    let subject_id = to_identity_id(identity.subject_id().as_bytes())?;
    let capability_id = to_identity_id(identity.capability_id().as_bytes())?;

    IdentityBundle::new(vm_id, session_id, request_id, subject_id, capability_id)
}

fn to_identity_id(bytes: [u8; ID_BYTES]) -> Result<IdentityId, RuntimeError> {
    IdentityId::from_hex(&to_lower_hex(bytes))
}

fn to_lower_hex(bytes: [u8; ID_BYTES]) -> String {
    let mut encoded = String::with_capacity(ID_BYTES * 2);
    for byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        BrokerSessionId, CapabilityId, RequestId, SessionId, SubjectId, VmId, WorkspaceId,
    };

    fn session_identity() -> SessionIdentity {
        SessionIdentity {
            session_id: SessionId::new([0x1a; ID_BYTES]),
            request_id: RequestId::new([0x2b; ID_BYTES]),
            vm_id: VmId::new([0x3c; ID_BYTES]),
            subject_id: SubjectId::new([0x4d; ID_BYTES]),
            workspace_id: WorkspaceId::new([0x5e; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0x6f; ID_BYTES]),
            capability_id: CapabilityId::new([0xa0; ID_BYTES]),
        }
    }

    #[test]
    fn maps_each_guest_identity_to_its_exact_source_domain() {
        let identity = session_identity();
        let bundle = to_firecracker_identity_bundle(&identity).expect("identity should convert");

        assert_eq!(bundle.vm_id.to_hex(), "3c".repeat(ID_BYTES));
        assert_eq!(bundle.session_id.to_hex(), "6f".repeat(ID_BYTES));
        assert_eq!(bundle.request_id.to_hex(), "2b".repeat(ID_BYTES));
        assert_eq!(bundle.subject_id.to_hex(), "4d".repeat(ID_BYTES));
        assert_eq!(bundle.capability_id.to_hex(), "a0".repeat(ID_BYTES));

        let output_ids = [
            bundle.vm_id.to_hex(),
            bundle.session_id.to_hex(),
            bundle.request_id.to_hex(),
            bundle.subject_id.to_hex(),
            bundle.capability_id.to_hex(),
        ];
        assert_eq!(
            output_ids.iter().collect::<HashSet<_>>().len(),
            output_ids.len()
        );
        assert_ne!(
            bundle.session_id.to_hex(),
            to_lower_hex(identity.session_id().as_bytes())
        );
        assert_ne!(
            bundle.vm_id.to_hex(),
            to_lower_hex(identity.workspace_id().as_bytes())
        );
    }

    #[test]
    fn rejects_all_zero_source_identities() {
        let identity = SessionIdentity {
            session_id: SessionId::new([0; ID_BYTES]),
            request_id: RequestId::new([0; ID_BYTES]),
            vm_id: VmId::new([0; ID_BYTES]),
            subject_id: SubjectId::new([0; ID_BYTES]),
            workspace_id: WorkspaceId::new([0; ID_BYTES]),
            broker_session_id: BrokerSessionId::new([0; ID_BYTES]),
            capability_id: CapabilityId::new([0; ID_BYTES]),
        };

        assert!(matches!(
            to_firecracker_identity_bundle(&identity),
            Err(RuntimeError::InvalidIdentity(_))
        ));
    }
}
