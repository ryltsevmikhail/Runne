use crate::{
    ClientMutationDisposition, RuntimeCommitDisposition, SecurityStateError, V7MutationTransition,
};

type TransitionParts = (
    ClientMutationDisposition,
    Option<RuntimeCommitDisposition>,
    Option<crate::CanonicalMutationOutcome>,
    String,
    i64,
);

pub fn transition_parts(
    transition: V7MutationTransition,
) -> Result<TransitionParts, SecurityStateError> {
    let (next, runtime, outcome, summary, timestamp) = match transition {
        V7MutationTransition::Dispatching { timestamp } => (
            ClientMutationDisposition::Dispatching,
            None,
            None,
            "dispatching".into(),
            timestamp,
        ),
        V7MutationTransition::Observing { timestamp } => (
            ClientMutationDisposition::Observing,
            None,
            None,
            "observing".into(),
            timestamp,
        ),
        V7MutationTransition::NotCommittedRetryable { timestamp } => (
            ClientMutationDisposition::Retryable,
            Some(RuntimeCommitDisposition::NotCommittedRetryable),
            None,
            "not_committed_retryable".into(),
            timestamp,
        ),
        V7MutationTransition::Indeterminate { timestamp } => (
            ClientMutationDisposition::Reconciling,
            Some(RuntimeCommitDisposition::Indeterminate),
            None,
            "indeterminate".into(),
            timestamp,
        ),
        V7MutationTransition::ManualResolution { summary, timestamp } => (
            ClientMutationDisposition::ManualResolution,
            Some(RuntimeCommitDisposition::Indeterminate),
            None,
            summary,
            timestamp,
        ),
        V7MutationTransition::ProhibitedInputRejectedBeforeAdmission { timestamp } => (
            ClientMutationDisposition::ManualResolution,
            Some(RuntimeCommitDisposition::NotCommittedRetryable),
            None,
            "prohibited_input_rejected_before_admission".into(),
            timestamp,
        ),
        V7MutationTransition::CanonicalOutcome {
            outcome,
            summary,
            timestamp,
        } => (
            ClientMutationDisposition::CanonicalOutcome,
            Some(RuntimeCommitDisposition::DurablyRecorded),
            Some(*outcome),
            summary,
            timestamp,
        ),
    };
    if summary.is_empty() || summary.len() > 256 || timestamp > i64::MAX as u64 {
        return Err(SecurityStateError::InvalidTransition);
    }
    Ok((
        next,
        runtime,
        outcome,
        summary,
        i64::try_from(timestamp).map_err(|_| SecurityStateError::InvalidTransition)?,
    ))
}
