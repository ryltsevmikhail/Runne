use crate::{
    AnchoredMutationPermit, ClientMutationDisposition, LocalStore, MutationIdentity,
    MutationTransitionMetadata, RuntimeCommitDisposition, SecurityStateError, V7MutationTransition,
};
use runne_secure_store::SecureStore;

impl LocalStore {
    pub fn transition_anchored_mutation_v7(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        transition: V7MutationTransition,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        let prohibited_refusal = matches!(
            &transition,
            V7MutationTransition::ProhibitedInputRejectedBeforeAdmission { .. }
        );
        let (next, runtime, outcome, summary, timestamp) =
            crate::security_mutation_parts::transition_parts(transition)?;
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        let (record, anchor) =
            self.commit_anchored_security_write_with_lock(secure, |transaction, lock| {
                let previous = crate::security_record::load_record(
                    transaction,
                    identity.clone(),
                    lock,
                    context.profile,
                    context.database,
                )?
                .ok_or(SecurityStateError::IdentityConflict)?;
                let command = previous
                    .normalized_command
                    .as_ref()
                    .ok_or(SecurityStateError::InvalidTransition)?;
                if prohibited_refusal
                    && (previous.client_state != ClientMutationDisposition::Dispatching
                        || previous.resend_count != 0
                        || !matches!(
                            command,
                            crate::NormalizedMutationCommand::GenerateText { .. }
                        ))
                {
                    return Err(SecurityStateError::InvalidTransition);
                }
                let transition_allowed = if prohibited_refusal {
                    previous.client_state == ClientMutationDisposition::Dispatching
                } else {
                    generic_transition_allowed(previous.client_state, next)
                };
                if !transition_allowed || !valid_runtime(next, runtime) {
                    return Err(SecurityStateError::InvalidTransition);
                }
                if let Some(outcome) = outcome.as_ref() {
                    if !outcome.correlates_to_command(command) {
                        return Err(SecurityStateError::IdentityConflict);
                    }
                } else if next == ClientMutationDisposition::CanonicalOutcome {
                    return Err(SecurityStateError::InvalidTransition);
                }
                crate::security_record::update_v7_record(
                    transaction,
                    &previous,
                    lock,
                    context.profile,
                    context.database,
                    crate::security_record::V7RecordUpdate {
                        state: next,
                        runtime,
                        canonical_outcome: outcome,
                        summary,
                        timestamp,
                        increment_resend: false,
                    },
                )
            })?;
        Ok(AnchoredMutationPermit { record, anchor })
    }

    pub fn resend_anchored_mutation_v7(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        timestamp: u64,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        let (record, anchor) =
            self.commit_anchored_security_write_with_lock(secure, |transaction, lock| {
                let previous = crate::security_record::load_record(
                    transaction,
                    identity.clone(),
                    lock,
                    context.profile,
                    context.database,
                )?
                .ok_or(SecurityStateError::IdentityConflict)?;
                if previous.client_state != ClientMutationDisposition::Retryable
                    || previous.resend_count != 0
                {
                    return Err(SecurityStateError::InvalidTransition);
                }
                crate::security_record::update_v7_record(
                    transaction,
                    &previous,
                    lock,
                    context.profile,
                    context.database,
                    crate::security_record::V7RecordUpdate {
                        state: ClientMutationDisposition::Dispatching,
                        runtime: None,
                        canonical_outcome: None,
                        summary: "resend".into(),
                        timestamp: i64::try_from(timestamp)
                            .map_err(|_| SecurityStateError::InvalidTransition)?,
                        increment_resend: true,
                    },
                )
            })?;
        Ok(AnchoredMutationPermit { record, anchor })
    }

    /// Legacy metadata cannot establish a normalized v7 command or outcome.
    pub fn prepare_anchored_mutation(
        &mut self,
        secure: &dyn SecureStore,
        _identity: MutationIdentity,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        self.verify_legacy_admission(secure)?;
        Err(SecurityStateError::InvalidTransition)
    }

    /// Legacy metadata cannot establish a normalized v7 command or outcome.
    pub fn transition_anchored_mutation(
        &mut self,
        secure: &dyn SecureStore,
        _identity: MutationIdentity,
        _next_state: ClientMutationDisposition,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        self.verify_legacy_admission(secure)?;
        Err(SecurityStateError::InvalidTransition)
    }

    /// Legacy metadata cannot establish a normalized v7 command or outcome.
    pub fn transition_anchored_mutation_with_metadata(
        &mut self,
        secure: &dyn SecureStore,
        _identity: MutationIdentity,
        _next_state: ClientMutationDisposition,
        metadata: MutationTransitionMetadata,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        self.verify_legacy_admission(secure)?;
        let _ = (
            metadata.runtime(),
            metadata.command(),
            metadata.outcome(),
            metadata.summary(),
            metadata.timestamp(),
        );
        Err(SecurityStateError::InvalidTransition)
    }
}

impl LocalStore {
    fn verify_legacy_admission(
        &mut self,
        secure: &dyn SecureStore,
    ) -> Result<(), SecurityStateError> {
        let profile = self
            .security
            .as_ref()
            .ok_or(SecurityStateError::AdmissionFailed)?
            .profile;
        let lock = secure.acquire_security_profile_lock(profile)?;
        self.verify_anchored_admission(secure, &lock)
    }
}

fn valid_runtime(
    next: ClientMutationDisposition,
    runtime: Option<RuntimeCommitDisposition>,
) -> bool {
    matches!(
        (next, runtime),
        (
            ClientMutationDisposition::Dispatching | ClientMutationDisposition::Observing,
            None
        ) | (
            ClientMutationDisposition::Retryable,
            Some(RuntimeCommitDisposition::NotCommittedRetryable)
        ) | (
            ClientMutationDisposition::Reconciling,
            Some(RuntimeCommitDisposition::Indeterminate)
        ) | (
            ClientMutationDisposition::ManualResolution,
            Some(
                RuntimeCommitDisposition::Indeterminate
                    | RuntimeCommitDisposition::NotCommittedRetryable
            )
        ) | (
            ClientMutationDisposition::CanonicalOutcome,
            Some(RuntimeCommitDisposition::DurablyRecorded)
        )
    )
}

const fn generic_transition_allowed(
    previous: ClientMutationDisposition,
    next: ClientMutationDisposition,
) -> bool {
    previous.transition_to(next)
        && !matches!(
            (previous, next),
            (
                ClientMutationDisposition::Retryable,
                ClientMutationDisposition::Dispatching
            )
        )
}

pub(crate) fn parse_state(value: &str) -> Result<ClientMutationDisposition, SecurityStateError> {
    match value {
        "prepared" => Ok(ClientMutationDisposition::Prepared),
        "dispatching" => Ok(ClientMutationDisposition::Dispatching),
        "observing" => Ok(ClientMutationDisposition::Observing),
        "retryable" => Ok(ClientMutationDisposition::Retryable),
        "reconciling" => Ok(ClientMutationDisposition::Reconciling),
        "canonical_outcome" => Ok(ClientMutationDisposition::CanonicalOutcome),
        "manual_resolution" => Ok(ClientMutationDisposition::ManualResolution),
        _ => Err(SecurityStateError::InvalidTransition),
    }
}

pub(crate) fn state_name(value: ClientMutationDisposition) -> &'static str {
    match value {
        ClientMutationDisposition::Prepared => "prepared",
        ClientMutationDisposition::Dispatching => "dispatching",
        ClientMutationDisposition::Observing => "observing",
        ClientMutationDisposition::Retryable => "retryable",
        ClientMutationDisposition::Reconciling => "reconciling",
        ClientMutationDisposition::CanonicalOutcome => "canonical_outcome",
        ClientMutationDisposition::ManualResolution => "manual_resolution",
    }
}
