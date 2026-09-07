use super::{
    allocation::ReservedQualificationBuffers, resources::QualificationVerificationPermit,
    state::PendingServiceQualificationStart, transfer::PendingServiceQualificationFinalize,
};
use zeroize::Zeroizing;

/// Opaque outside-lock ownership returned by every state-removing transition.
#[must_use]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a detached owner would allocate while the future core mutex is held"
)]
pub(super) enum DeferredQualificationRetirement {
    Empty,
    PendingStart(PendingServiceQualificationStart),
    Receiving(ReservedQualificationBuffers),
    PendingFinalize(PendingServiceQualificationFinalize),
    VerificationPermit(QualificationVerificationPermit),
    Payload(Zeroizing<Vec<u8>>),
    ReceivingPayload {
        payload: Zeroizing<Vec<u8>>,
        buffers: ReservedQualificationBuffers,
    },
    ReceivingPayloadPermit {
        payload: Zeroizing<Vec<u8>>,
        buffers: ReservedQualificationBuffers,
        permit: QualificationVerificationPermit,
    },
    PermitPayload {
        payload: Zeroizing<Vec<u8>>,
        permit: QualificationVerificationPermit,
    },
}

impl DeferredQualificationRetirement {
    pub(super) const fn empty() -> Self {
        Self::Empty
    }

    pub(super) const fn pending_start(pending: PendingServiceQualificationStart) -> Self {
        Self::PendingStart(pending)
    }

    pub(super) const fn receiving(buffers: ReservedQualificationBuffers) -> Self {
        Self::Receiving(buffers)
    }

    pub(super) const fn pending_finalize(pending: PendingServiceQualificationFinalize) -> Self {
        Self::PendingFinalize(pending)
    }

    pub(super) const fn permit(permit: QualificationVerificationPermit) -> Self {
        Self::VerificationPermit(permit)
    }

    pub(super) const fn payload(payload: Zeroizing<Vec<u8>>) -> Self {
        Self::Payload(payload)
    }

    pub(super) const fn receiving_payload(
        buffers: ReservedQualificationBuffers,
        payload: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self::ReceivingPayload { payload, buffers }
    }

    pub(super) const fn permit_payload(
        permit: QualificationVerificationPermit,
        payload: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self::PermitPayload { payload, permit }
    }

    pub(super) const fn receiving_payload_permit(
        buffers: ReservedQualificationBuffers,
        payload: Zeroizing<Vec<u8>>,
        permit: QualificationVerificationPermit,
    ) -> Self {
        Self::ReceivingPayloadPermit {
            payload,
            buffers,
            permit,
        }
    }
}
