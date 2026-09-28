use crate::{
    ClientMutationDisposition, MutationRecord, RuntimeCommitDisposition, SecurityStateError,
};

pub fn validate_record(record: &MutationRecord) -> Result<(), SecurityStateError> {
    let runtime = record.runtime_disposition;
    let command = record.command_ref.is_some();
    let normalized = record.normalized_command.is_some();
    let outcome = record.outcome_ref.is_some();
    let canonical = record.canonical_outcome.is_some();
    let summary = record.recovery_summary.as_str();
    let valid = match record.client_state {
        ClientMutationDisposition::Prepared => {
            runtime.is_none()
                && command
                && normalized
                && !outcome
                && !canonical
                && record.resend_count == 0
                && summary == "prepared"
                && record.updated_at == 0
        }
        ClientMutationDisposition::Dispatching => {
            runtime.is_none() && normalized && command && !outcome && !canonical
        }
        ClientMutationDisposition::Observing => {
            matches!(
                runtime,
                None | Some(RuntimeCommitDisposition::Indeterminate)
            ) && normalized
                && command
                && !outcome
                && !canonical
        }
        ClientMutationDisposition::Retryable => {
            matches!(
                runtime,
                None | Some(
                    RuntimeCommitDisposition::NotCommittedRetryable
                        | RuntimeCommitDisposition::Indeterminate
                )
            ) && normalized
                && command
                && !outcome
                && !canonical
                && record.resend_count <= 1
        }
        ClientMutationDisposition::Reconciling => {
            matches!(
                runtime,
                None | Some(RuntimeCommitDisposition::Indeterminate)
            ) && normalized
                && command
                && !outcome
                && !canonical
        }
        ClientMutationDisposition::CanonicalOutcome => {
            runtime == Some(RuntimeCommitDisposition::DurablyRecorded)
                && normalized
                && command
                && outcome
                && canonical
                && record.canonical_outcome.as_ref().is_some_and(|outcome| {
                    outcome.correlates_to_command(
                        record.normalized_command.as_ref().expect("validated"),
                    )
                })
                && !summary.is_empty()
        }
        ClientMutationDisposition::ManualResolution => {
            !outcome
                && !canonical
                && ((runtime == Some(RuntimeCommitDisposition::Indeterminate)
                    && ((normalized && command && !summary.is_empty())
                        || (!normalized
                            && !command
                            && record.resend_count == 0
                            && summary == "v6_unrecoverable")))
                    || (runtime == Some(RuntimeCommitDisposition::NotCommittedRetryable)
                        && normalized
                        && command
                        && record.resend_count == 0
                        && summary == "prohibited_input_rejected_before_admission"
                        && matches!(
                            record.normalized_command.as_ref(),
                            Some(crate::NormalizedMutationCommand::GenerateText { .. })
                        )))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(SecurityStateError::InvalidTransition)
    }
}
