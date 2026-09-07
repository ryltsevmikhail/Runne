use super::allocation::{
    AllocatedQualificationStart, QualificationAllocator, ReservedQualificationBuffers,
};
use super::binding::QualificationBinding;
use super::resources::{QualificationReservationLease, QualificationResourceBudget};
use super::retirement::DeferredQualificationRetirement;

/// Scalar commitments validated by the typed provider decoder before reservation.
#[derive(Clone, Copy)]
pub(super) struct StartCommitment {
    release_frame_len: u32,
    admission_bundle_len: u32,
    chunk_count: u16,
}

impl StartCommitment {
    #[cfg(test)]
    pub(super) fn for_test(release_frame_len: u32, admission_bundle_len: u32) -> Self {
        Self {
            release_frame_len,
            admission_bundle_len,
            chunk_count: u16::try_from(release_frame_len.saturating_sub(1) / 8_192 + 1)
                .expect("test release length has a bounded chunk count"),
        }
    }

    pub(super) fn is_valid(&self) -> bool {
        (13..=524_300).contains(&self.release_frame_len)
            && (19..=8_192).contains(&self.admission_bundle_len)
            && u16::try_from(self.release_frame_len.saturating_sub(1) / 8_192 + 1)
                .is_ok_and(|expected| self.chunk_count == expected)
    }

    fn reserved_bytes(&self) -> Option<usize> {
        self.is_valid().then_some(())?;
        usize::try_from(self.release_frame_len)
            .ok()?
            .checked_add(usize::try_from(self.admission_bundle_len).ok()?)
    }

    pub(super) const fn from_typed(
        release_frame_len: u32,
        admission_bundle_len: u32,
        _chunk_bytes: u16,
        chunk_count: u16,
    ) -> Self {
        Self {
            release_frame_len,
            admission_bundle_len,
            chunk_count,
        }
    }
}

/// One logical qualification slot. Its reservation lease is outside the state while allocating.
pub(super) struct QualificationState {
    pub(super) phase: QualificationPhase,
}

pub(super) enum QualificationPhase {
    Empty,
    Allocating {
        token: [u8; 32],
        binding: QualificationBinding,
        deadline: std::time::Instant,
        chunk_count: u16,
    },
    Receiving {
        buffers: ReservedQualificationBuffers,
        next_chunk_index: u16,
        received_release_bytes: u32,
    },
    Verifying {
        token: [u8; 32],
        binding: QualificationBinding,
        deadline: std::time::Instant,
    },
}

/// Move-only owner that must outlive the logical `Allocating` slot.
#[must_use]
pub(super) struct PendingServiceQualificationStart {
    pub(super) release_frame_len: usize,
    pub(super) admission_bundle_len: usize,
    pub(super) token: [u8; 32],
    pub(super) binding: QualificationBinding,
    pub(super) deadline: std::time::Instant,
    pub(super) chunk_count: u16,
    lease: QualificationReservationLease,
}

impl PendingServiceQualificationStart {
    #[allow(
        clippy::result_large_err,
        reason = "the allocation caller must receive the complete move-only pending owner"
    )]
    pub(super) fn allocate_with(
        self,
        allocator: &impl QualificationAllocator,
    ) -> Result<AllocatedQualificationStart, Self> {
        let mut release = Vec::new();
        let mut admission = Vec::new();
        if allocator
            .reserve(&mut release, self.release_frame_len)
            .is_err()
            || allocator
                .reserve(&mut admission, self.admission_bundle_len)
                .is_err()
        {
            return Err(self);
        }
        Ok(AllocatedQualificationStart::new(self, release, admission))
    }

    pub(super) fn into_lease(self) -> QualificationReservationLease {
        self.lease
    }

    #[cfg(test)]
    pub(super) const fn retag_for_test(mut self, token: [u8; 32]) -> Self {
        self.token = token;
        self
    }
}

impl QualificationState {
    pub(super) const fn empty() -> Self {
        Self {
            phase: QualificationPhase::Empty,
        }
    }

    pub(super) fn begin(
        &mut self,
        commitment: StartCommitment,
        budget: &QualificationResourceBudget,
    ) -> Result<PendingServiceQualificationStart, ()> {
        if !matches!(self.phase, QualificationPhase::Empty) {
            return Err(());
        }
        let bytes = commitment.reserved_bytes().ok_or(())?;
        let release_frame_len = usize::try_from(commitment.release_frame_len).map_err(|_| ())?;
        let admission_bundle_len =
            usize::try_from(commitment.admission_bundle_len).map_err(|_| ())?;
        let lease = budget.try_acquire_reservation(bytes)?;
        let now = std::time::Instant::now();
        self.phase = QualificationPhase::Allocating {
            token: [0; 32],
            binding: QualificationBinding::zero_for_test(),
            deadline: now,
            chunk_count: commitment.chunk_count,
        };
        Ok(PendingServiceQualificationStart {
            release_frame_len,
            admission_bundle_len,
            token: [0; 32],
            binding: QualificationBinding::zero_for_test(),
            deadline: now,
            chunk_count: commitment.chunk_count,
            lease,
        })
    }

    pub(super) fn begin_with_context(
        &mut self,
        commitment: StartCommitment,
        binding: &QualificationBinding,
        deadline: std::time::Instant,
        token: [u8; 32],
        budget: &QualificationResourceBudget,
    ) -> Result<PendingServiceQualificationStart, ()> {
        if !matches!(self.phase, QualificationPhase::Empty) {
            return Err(());
        }
        let bytes = commitment.reserved_bytes().ok_or(())?;
        let release_frame_len = usize::try_from(commitment.release_frame_len).map_err(|_| ())?;
        let admission_bundle_len =
            usize::try_from(commitment.admission_bundle_len).map_err(|_| ())?;
        let lease = budget.try_acquire_reservation(bytes)?;
        self.phase = QualificationPhase::Allocating {
            token,
            binding: *binding,
            deadline,
            chunk_count: commitment.chunk_count,
        };
        Ok(PendingServiceQualificationStart {
            release_frame_len,
            admission_bundle_len,
            token,
            binding: *binding,
            deadline,
            chunk_count: commitment.chunk_count,
            lease,
        })
    }

    pub(super) fn abort(
        &mut self,
        pending: PendingServiceQualificationStart,
    ) -> DeferredQualificationRetirement {
        let matches = matches!(
            &self.phase,
            QualificationPhase::Allocating { token, .. } if *token == pending.token
        );
        if matches {
            self.phase = QualificationPhase::Empty;
        }
        DeferredQualificationRetirement::pending_start(pending)
    }

    #[allow(
        clippy::result_large_err,
        reason = "a stale allocation must return its full owner without allocating under lock"
    )]
    pub(super) fn commit_allocation(
        &mut self,
        allocated: AllocatedQualificationStart,
    ) -> Result<(), DeferredQualificationRetirement> {
        let buffers = allocated.into_buffers();
        let valid = matches!(
            &self.phase,
            QualificationPhase::Allocating {
                token,
                binding,
                deadline,
                chunk_count,
            } if *token == buffers.token
                && *binding == buffers.binding
                && *deadline == buffers.deadline
                && *chunk_count == buffers.chunk_count
        );
        if !valid {
            return Err(DeferredQualificationRetirement::receiving(buffers));
        }
        self.phase = QualificationPhase::Receiving {
            buffers,
            next_chunk_index: 0,
            received_release_bytes: 0,
        };
        Ok(())
    }

    pub(super) fn retire_receiving(&mut self) -> Option<DeferredQualificationRetirement> {
        let previous = std::mem::replace(&mut self.phase, QualificationPhase::Empty);
        match previous {
            QualificationPhase::Receiving { buffers, .. } => {
                Some(DeferredQualificationRetirement::receiving(buffers))
            }
            phase => {
                self.phase = phase;
                None
            }
        }
    }

    pub(super) fn expire(
        &mut self,
        now: std::time::Instant,
    ) -> Option<DeferredQualificationRetirement> {
        let previous = std::mem::replace(&mut self.phase, QualificationPhase::Empty);
        match previous {
            QualificationPhase::Allocating { deadline, .. }
            | QualificationPhase::Verifying { deadline, .. }
                if now >= deadline =>
            {
                None
            }
            QualificationPhase::Receiving { buffers, .. } if now >= buffers.deadline => {
                Some(DeferredQualificationRetirement::receiving(buffers))
            }
            phase => {
                self.phase = phase;
                None
            }
        }
    }

    #[cfg(test)]
    pub(super) const fn is_allocating(&self) -> bool {
        matches!(self.phase, QualificationPhase::Allocating { .. })
    }
}
