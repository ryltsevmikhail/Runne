use zeroize::Zeroizing;

use super::{
    allocation::ReservedQualificationBuffers,
    binding::QualificationBinding,
    resources::QualificationVerificationPermit,
    retirement::DeferredQualificationRetirement,
    state::{QualificationPhase, QualificationState},
};

#[derive(Clone, Copy)]
pub(super) enum QualificationTransferRejection {
    Denied,
    Expired,
}

pub(super) struct QualificationChunk {
    pub(super) index: u16,
    pub(super) count: u16,
    pub(super) offset: u32,
    pub(super) bytes: Zeroizing<Vec<u8>>,
}

pub(super) struct QualificationFinalize {
    pub(super) release_frame_len: u32,
    pub(super) chunk_count: u16,
    pub(super) admission: Zeroizing<Vec<u8>>,
}

pub(super) struct QualificationTransferFailure {
    pub(super) reason: QualificationTransferRejection,
    pub(super) retirement: DeferredQualificationRetirement,
}

impl QualificationState {
    #[allow(
        clippy::result_large_err,
        reason = "a rejected chunk must detach every owner without allocating under lock"
    )]
    pub(super) fn accept_chunk(
        &mut self,
        binding: &QualificationBinding,
        chunk: QualificationChunk,
        now: std::time::Instant,
    ) -> Result<(u32, DeferredQualificationRetirement), QualificationTransferFailure> {
        let QualificationChunk {
            index,
            count,
            offset,
            bytes,
        } = chunk;
        let previous = std::mem::replace(&mut self.phase, QualificationPhase::Empty);
        let QualificationPhase::Receiving {
            mut buffers,
            mut next_chunk_index,
            mut received_release_bytes,
        } = previous
        else {
            self.phase = previous;
            return Err(QualificationTransferFailure {
                reason: QualificationTransferRejection::Denied,
                retirement: DeferredQualificationRetirement::payload(bytes),
            });
        };
        let final_len = buffers.release_frame_len.saturating_sub(offset);
        let chunk_len = u32::try_from(bytes.len())
            .expect("provider decoder bounds a qualification chunk to u16");
        let expected_chunk_len = if index + 1 == count { final_len } else { 8_192 };
        let valid = buffers.binding.same_transfer(binding)
            && now < buffers.deadline
            && count == buffers.chunk_count
            && index == next_chunk_index
            && offset == u32::from(index) * 8_192
            && chunk_len == expected_chunk_len;
        if !valid {
            let rejection = if now >= buffers.deadline {
                QualificationTransferRejection::Expired
            } else {
                QualificationTransferRejection::Denied
            };
            return Err(QualificationTransferFailure {
                reason: rejection,
                retirement: DeferredQualificationRetirement::receiving_payload(buffers, bytes),
            });
        }
        let start = usize::try_from(offset).expect("qualification offset fits usize");
        let end = start
            .checked_add(bytes.len())
            .expect("validated qualification chunk end fits usize");
        buffers.release[start..end].copy_from_slice(&bytes);
        received_release_bytes = received_release_bytes.saturating_add(
            u32::try_from(bytes.len()).expect("chunk length is bounded by the wire codec"),
        );
        next_chunk_index += 1;
        self.phase = QualificationPhase::Receiving {
            buffers,
            next_chunk_index,
            received_release_bytes,
        };
        Ok((
            received_release_bytes,
            DeferredQualificationRetirement::payload(bytes),
        ))
    }

    #[allow(
        clippy::result_large_err,
        reason = "a rejected Finalize must detach every owner without allocating under lock"
    )]
    pub(super) fn begin_finalize(
        &mut self,
        binding: &QualificationBinding,
        request: QualificationFinalize,
        token: [u8; 32],
        permit: QualificationVerificationPermit,
        now: std::time::Instant,
    ) -> Result<PendingServiceQualificationFinalize, QualificationTransferFailure> {
        let QualificationFinalize {
            release_frame_len,
            chunk_count,
            admission,
        } = request;
        let previous = std::mem::replace(&mut self.phase, QualificationPhase::Empty);
        let QualificationPhase::Receiving {
            mut buffers,
            next_chunk_index,
            received_release_bytes,
        } = previous
        else {
            self.phase = previous;
            return Err(QualificationTransferFailure {
                reason: QualificationTransferRejection::Denied,
                retirement: DeferredQualificationRetirement::permit_payload(permit, admission),
            });
        };
        let valid = buffers.binding.same_transfer(binding)
            && release_frame_len == buffers.release_frame_len
            && chunk_count == buffers.chunk_count
            && next_chunk_index == chunk_count
            && received_release_bytes == release_frame_len
            && admission.len() == buffers.admission_frame_len
            && now < buffers.deadline;
        if !valid {
            let rejection = if now >= buffers.deadline {
                QualificationTransferRejection::Expired
            } else {
                QualificationTransferRejection::Denied
            };
            return Err(QualificationTransferFailure {
                reason: rejection,
                retirement: DeferredQualificationRetirement::receiving_payload_permit(
                    buffers, admission, permit,
                ),
            });
        }
        buffers.admission[..admission.len()].copy_from_slice(&admission);
        let deadline = buffers.deadline;
        self.phase = QualificationPhase::Verifying {
            token,
            binding: *binding,
            deadline,
        };
        Ok(PendingServiceQualificationFinalize {
            token,
            binding: *binding,
            deadline,
            admission_input: admission,
            buffers,
            permit,
        })
    }

    pub(super) fn abort_finalize(
        &mut self,
        pending: PendingServiceQualificationFinalize,
    ) -> DeferredQualificationRetirement {
        if matches!(
            self.phase,
            QualificationPhase::Verifying { token, .. } if token == pending.token
        ) {
            self.phase = QualificationPhase::Empty;
        }
        DeferredQualificationRetirement::pending_finalize(pending)
    }
}

#[must_use]
pub(super) struct PendingServiceQualificationFinalize {
    pub(super) token: [u8; 32],
    pub(super) binding: QualificationBinding,
    pub(super) deadline: std::time::Instant,
    pub(super) admission_input: Zeroizing<Vec<u8>>,
    pub(super) buffers: ReservedQualificationBuffers,
    pub(super) permit: QualificationVerificationPermit,
}

impl QualificationState {
    pub(super) fn retire_receiving_with_payload(
        &mut self,
        payload: Zeroizing<Vec<u8>>,
    ) -> DeferredQualificationRetirement {
        match self.retire_receiving() {
            Some(DeferredQualificationRetirement::Receiving(buffers)) => {
                DeferredQualificationRetirement::receiving_payload(buffers, payload)
            }
            Some(_) => unreachable!("receiving retirement has a receiving owner"),
            None => DeferredQualificationRetirement::payload(payload),
        }
    }
}
