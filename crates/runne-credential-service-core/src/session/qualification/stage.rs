mod request;

use super::{
    retirement::DeferredQualificationRetirement, state::PendingServiceQualificationStart,
    transfer::PendingServiceQualificationFinalize,
};
use runne_provider::{ServiceQualificationRejectionCode, ServiceQualificationRequestKind};

#[allow(
    unused_imports,
    reason = "Gate A exposes the private stage only to pure tests and the future atomic adapter"
)]
pub(super) use request::stage_qualification_request;

/// Private entropy seam used only by the later host adapter and pure tests.
pub(super) trait QualificationEntropySource {
    fn fill(&self, output: &mut [u8; 32]) -> Result<(), ()>;
}

/// Closed transition result; no reply encoder or authority can escape this boundary.
#[must_use]
pub(super) struct CredentialServiceCoreTransition<T> {
    outcome: T,
    retirement: DeferredQualificationRetirement,
}

impl<T> CredentialServiceCoreTransition<T> {
    pub(super) const fn new(outcome: T) -> Self {
        Self {
            outcome,
            retirement: DeferredQualificationRetirement::empty(),
        }
    }

    pub(super) const fn from_parts(
        outcome: T,
        retirement: DeferredQualificationRetirement,
    ) -> Self {
        Self {
            outcome,
            retirement,
        }
    }

    pub(super) const fn outcome(&self) -> &T {
        &self.outcome
    }

    pub(super) fn into_parts(self) -> (T, DeferredQualificationRetirement) {
        (self.outcome, self.retirement)
    }
}

/// Pure staged outcomes. Allocation and verification are deliberately caller-owned.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing a pending owner would allocate while the future core mutex is held"
)]
pub(super) enum CredentialServiceRuntimeStage {
    Reply {
        kind: ServiceQualificationRequestKind,
        sequence: u64,
        code: ServiceQualificationRejectionCode,
    },
    Progress {
        kind: ServiceQualificationRequestKind,
        sequence: u64,
        next_chunk_index: u16,
        received_release_bytes: u32,
    },
    AllocateQualification(PendingServiceQualificationStart),
    VerifyQualification(PendingServiceQualificationFinalize),
}
