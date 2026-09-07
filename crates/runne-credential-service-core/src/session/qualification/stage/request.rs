use super::{
    CredentialServiceCoreTransition, CredentialServiceRuntimeStage, QualificationEntropySource,
};
use crate::session::qualification::{
    binding::QualificationBinding,
    clocks::{LockedCredentialServiceClocks, QualificationClockSource},
    resources::QualificationResourceBudget,
    retirement::DeferredQualificationRetirement,
    state::{QualificationState, StartCommitment},
    transfer::{QualificationChunk, QualificationFinalize, QualificationTransferRejection},
};
use runne_api::CredentialServiceRegistrationBinding;
use runne_provider::{
    CredentialServiceEpoch, ServiceQualificationRejectionCode, ServiceQualificationRequest,
    ServiceQualificationRequestKind, ServiceQualificationRequestPayload,
};

#[allow(clippy::too_many_arguments)]
pub(in crate::session::qualification) fn stage_qualification_request(
    state: &mut QualificationState,
    last_sequence: &mut u64,
    epoch: &CredentialServiceEpoch,
    registration: &CredentialServiceRegistrationBinding,
    request: ServiceQualificationRequest,
    budget: &QualificationResourceBudget,
    source: &impl QualificationClockSource,
    entropy: &impl QualificationEntropySource,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    let kind = request.kind();
    let clocks = LockedCredentialServiceClocks::sample_pair(source);
    let (common, payload) = request.into_parts();
    let binding = QualificationBinding::from_common(&common);
    if !binding.matches_registration(epoch, registration) {
        return reject_request(
            payload,
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Denied,
        );
    }
    let Ok(deadline) = binding.fresh_deadline(&clocks) else {
        return reject_request(
            payload,
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Expired,
        );
    };
    if binding.sequence <= *last_sequence {
        return reject_request(
            payload,
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Denied,
        );
    }
    *last_sequence = binding.sequence;
    match payload {
        ServiceQualificationRequestPayload::Start {
            release_frame_len,
            chunk_bytes,
            chunk_count,
            admission_bundle_len,
        } => stage_start(
            state,
            &binding,
            deadline,
            kind,
            release_frame_len,
            chunk_bytes,
            chunk_count,
            admission_bundle_len,
            budget,
            entropy,
        ),
        ServiceQualificationRequestPayload::Chunk {
            chunk_index,
            chunk_count,
            offset,
            bytes,
        } => stage_chunk(
            state,
            &binding,
            kind,
            QualificationChunk {
                index: chunk_index,
                count: chunk_count,
                offset,
                bytes,
            },
            clocks.monotonic_now(),
        ),
        ServiceQualificationRequestPayload::Finalize {
            release_frame_len,
            chunk_count,
            admission_bundle,
        } => stage_finalize(
            state,
            &binding,
            kind,
            QualificationFinalize {
                release_frame_len,
                chunk_count,
                admission: admission_bundle,
            },
            budget,
            entropy,
            clocks.monotonic_now(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_start(
    state: &mut QualificationState,
    binding: &QualificationBinding,
    deadline: std::time::Instant,
    kind: ServiceQualificationRequestKind,
    release_frame_len: u32,
    chunk_bytes: u16,
    chunk_count: u16,
    admission_bundle_len: u32,
    budget: &QualificationResourceBudget,
    entropy: &impl QualificationEntropySource,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    let commitment = StartCommitment::from_typed(
        release_frame_len,
        admission_bundle_len,
        chunk_bytes,
        chunk_count,
    );
    if chunk_bytes != 8_192 || !commitment.is_valid() {
        return reject(
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Denied,
        );
    }
    let mut token = [0; 32];
    if entropy.fill(&mut token).is_err() || token == [0; 32] {
        return reject(
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Unavailable,
        );
    }
    match state.begin_with_context(commitment, binding, deadline, token, budget) {
        Ok(pending) => CredentialServiceCoreTransition::new(
            CredentialServiceRuntimeStage::AllocateQualification(pending),
        ),
        Err(()) => reject(
            kind,
            binding.sequence,
            ServiceQualificationRejectionCode::Busy,
        ),
    }
}

fn stage_chunk(
    state: &mut QualificationState,
    binding: &QualificationBinding,
    kind: ServiceQualificationRequestKind,
    chunk: QualificationChunk,
    now: std::time::Instant,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    let next_chunk_index = chunk.index + 1;
    match state.accept_chunk(binding, chunk, now) {
        Ok((received, retirement)) => CredentialServiceCoreTransition::from_parts(
            CredentialServiceRuntimeStage::Progress {
                kind,
                sequence: binding.sequence,
                next_chunk_index,
                received_release_bytes: received,
            },
            retirement,
        ),
        Err(failure) => CredentialServiceCoreTransition::from_parts(
            reject_outcome(kind, binding.sequence, rejection_code(failure.reason)),
            failure.retirement,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_finalize(
    state: &mut QualificationState,
    binding: &QualificationBinding,
    kind: ServiceQualificationRequestKind,
    request: QualificationFinalize,
    budget: &QualificationResourceBudget,
    entropy: &impl QualificationEntropySource,
    now: std::time::Instant,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    let QualificationFinalize {
        release_frame_len,
        chunk_count,
        admission,
    } = request;
    let mut token = [0; 32];
    if entropy.fill(&mut token).is_err() || token == [0; 32] {
        let retirement = state.retire_receiving_with_payload(admission);
        return CredentialServiceCoreTransition::from_parts(
            reject_outcome(
                kind,
                binding.sequence,
                ServiceQualificationRejectionCode::Unavailable,
            ),
            retirement,
        );
    }
    let Ok(permit) = budget.try_acquire_verification_permit() else {
        let retirement = state.retire_receiving_with_payload(admission);
        return CredentialServiceCoreTransition::from_parts(
            reject_outcome(
                kind,
                binding.sequence,
                ServiceQualificationRejectionCode::Busy,
            ),
            retirement,
        );
    };
    match state.begin_finalize(
        binding,
        QualificationFinalize {
            release_frame_len,
            chunk_count,
            admission,
        },
        token,
        permit,
        now,
    ) {
        Ok(pending) => CredentialServiceCoreTransition::new(
            CredentialServiceRuntimeStage::VerifyQualification(pending),
        ),
        Err(failure) => CredentialServiceCoreTransition::from_parts(
            reject_outcome(kind, binding.sequence, rejection_code(failure.reason)),
            failure.retirement,
        ),
    }
}

const fn rejection_code(
    reason: QualificationTransferRejection,
) -> ServiceQualificationRejectionCode {
    match reason {
        QualificationTransferRejection::Denied => ServiceQualificationRejectionCode::Denied,
        QualificationTransferRejection::Expired => ServiceQualificationRejectionCode::Expired,
    }
}

const fn reject(
    kind: ServiceQualificationRequestKind,
    sequence: u64,
    code: ServiceQualificationRejectionCode,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    CredentialServiceCoreTransition::new(reject_outcome(kind, sequence, code))
}

fn reject_request(
    payload: ServiceQualificationRequestPayload,
    kind: ServiceQualificationRequestKind,
    sequence: u64,
    code: ServiceQualificationRejectionCode,
) -> CredentialServiceCoreTransition<CredentialServiceRuntimeStage> {
    let retirement = match payload {
        ServiceQualificationRequestPayload::Start { .. } => {
            DeferredQualificationRetirement::empty()
        }
        ServiceQualificationRequestPayload::Chunk { bytes, .. } => {
            DeferredQualificationRetirement::payload(bytes)
        }
        ServiceQualificationRequestPayload::Finalize {
            admission_bundle, ..
        } => DeferredQualificationRetirement::payload(admission_bundle),
    };
    CredentialServiceCoreTransition::from_parts(reject_outcome(kind, sequence, code), retirement)
}

const fn reject_outcome(
    kind: ServiceQualificationRequestKind,
    sequence: u64,
    code: ServiceQualificationRejectionCode,
) -> CredentialServiceRuntimeStage {
    CredentialServiceRuntimeStage::Reply {
        kind,
        sequence,
        code,
    }
}
