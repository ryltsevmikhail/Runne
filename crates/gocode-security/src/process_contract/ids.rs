//! Opaque identities allocated at the security boundary.

use super::ProcessContractError;

macro_rules! process_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates a non-sentinel opaque identity.
            pub fn new(value: [u8; 16]) -> Result<Self, ProcessContractError> {
                if value == [0; 16] {
                    return Err(ProcessContractError::IntentMalformed);
                }
                Ok(Self(value))
            }

            #[allow(dead_code)]
            pub(super) const fn bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

process_id!(PrincipalId, "Opaque principal identity.");
process_id!(AuthorityId, "Opaque runtime authority identity.");
process_id!(ApprovalId, "Opaque mandatory approval identity.");
process_id!(ApproverId, "Opaque immutable approval-authority identity.");
process_id!(
    ProcessCapabilityId,
    "Opaque runtime-issued process capability identity."
);
process_id!(
    CapabilityGrantId,
    "Opaque accounting capability-grant identity."
);
process_id!(SandboxId, "Opaque sandbox identity.");
process_id!(
    ExecutablePolicyId,
    "Opaque exact executable-policy identity."
);
process_id!(
    AllowedRootId,
    "Opaque exact working-directory root identity."
);
