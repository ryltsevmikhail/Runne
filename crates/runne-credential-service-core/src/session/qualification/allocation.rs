use std::time::Instant;
use zeroize::Zeroizing;

use super::binding::QualificationBinding;
use super::state::PendingServiceQualificationStart;

/// Fallible allocation seam; production uses `Vec::try_reserve_exact` only.
pub(super) trait QualificationAllocator {
    fn reserve(&self, buffer: &mut Vec<u8>, bytes: usize) -> Result<(), ()>;
}

pub(super) struct SystemQualificationAllocator;

impl QualificationAllocator for SystemQualificationAllocator {
    fn reserve(&self, buffer: &mut Vec<u8>, bytes: usize) -> Result<(), ()> {
        buffer.try_reserve_exact(bytes).map_err(|_| ())?;
        buffer.resize(bytes, 0);
        Ok(())
    }
}

/// Allocated buffers retain the entire pending reservation until a consuming commit or abort.
#[must_use]
pub(super) struct AllocatedQualificationStart {
    release: Zeroizing<Vec<u8>>,
    admission: Zeroizing<Vec<u8>>,
    pending: PendingServiceQualificationStart,
}

impl AllocatedQualificationStart {
    pub(super) fn new(
        pending: PendingServiceQualificationStart,
        release: Vec<u8>,
        admission: Vec<u8>,
    ) -> Self {
        Self {
            release: Zeroizing::new(release),
            admission: Zeroizing::new(admission),
            pending,
        }
    }

    pub(super) fn into_buffers(self) -> ReservedQualificationBuffers {
        let Self {
            release,
            admission,
            pending,
        } = self;
        ReservedQualificationBuffers {
            release,
            admission,
            release_frame_len: u32::try_from(pending.release_frame_len)
                .expect("pending release length originated as u32"),
            admission_frame_len: pending.admission_bundle_len,
            chunk_count: pending.chunk_count,
            token: pending.token,
            binding: pending.binding,
            deadline: pending.deadline,
            lease: pending.into_lease(),
        }
    }

    #[cfg(test)]
    pub(super) const fn retag_for_test(mut self, token: [u8; 32]) -> Self {
        self.pending.token = token;
        self
    }
}

/// In-map receiving buffers release data before their reservation lease on Drop.
#[must_use]
pub(super) struct ReservedQualificationBuffers {
    pub(super) release: Zeroizing<Vec<u8>>,
    pub(super) admission: Zeroizing<Vec<u8>>,
    pub(super) release_frame_len: u32,
    pub(super) admission_frame_len: usize,
    pub(super) chunk_count: u16,
    pub(super) token: [u8; 32],
    pub(super) binding: QualificationBinding,
    pub(super) deadline: Instant,
    lease: super::resources::QualificationReservationLease,
}
