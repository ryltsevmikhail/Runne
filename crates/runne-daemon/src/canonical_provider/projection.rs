use super::composition::PROVIDER_POLICY_V1_REVISION;
use super::*;

pub(super) fn project_call(
    store: &StoreTransaction,
    job: &CanonicalProviderExecutionJob,
    profile: &dyn TextProviderProfile,
    provider_id: &str,
    model_id: &str,
    model_revision: &str,
) -> Result<ProviderCall, CanonicalProviderExecutionError> {
    let stream = store
        .load_conversation(job.started.conversation_id)
        .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
    if stream.current_version != job.started.conversation_version {
        return Err(CanonicalProviderExecutionError::Conflict);
    }
    let mut inputs = Vec::new();
    let mut manifest = Sha256::new();
    for event in &stream.events {
        manifest.update(event.integrity_digest().as_bytes());
        match event.payload() {
            ConversationEvent::UserMessageAppended { text, .. } => inputs.push(
                ProviderTextInput::new(ProviderInputRole::User, text.as_str().to_owned())
                    .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            ),
            ConversationEvent::AssistantMessageAppended { text, .. } => inputs.push(
                ProviderTextInput::new(ProviderInputRole::Assistant, text.as_str().to_owned())
                    .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            ),
            ConversationEvent::ConversationCreated { .. }
            | ConversationEvent::ConversationClosed
            | ConversationEvent::GenerationFailed { .. } => {}
        }
    }
    let call_id = ProviderCallId::from_bytes(derived_bytes16(
        b"RUNNE_CANONICAL_PROVIDER_CALL_V1\0",
        job.context.command_id.as_bytes(),
    ));
    ProviderCall::new(
        call_id,
        ModelRef::new(
            ProviderId::new(provider_id).map_err(|_| CanonicalProviderExecutionError::Conflict)?,
            model_id,
            model_revision,
        )
        .map_err(|_| CanonicalProviderExecutionError::Conflict)?,
        manifest.finalize().into(),
        profile.max_output_tokens(),
        serde_json::json!({
            "profile_id": profile.profile_id(),
            "profile_digest": hex::encode(profile.profile_digest()),
            "pricing_revision_digest": hex::encode(profile.pricing_revision_digest()),
        }),
    )
    .and_then(|call| call.with_text_inputs(inputs))
    .map(|call| call.with_required_capabilities(vec![ProviderCapability::Streaming]))
    .map_err(|_| CanonicalProviderExecutionError::Conflict)
}

pub(super) fn provider_idempotency_key(job: &CanonicalProviderExecutionJob) -> String {
    format!(
        "runne-provider-{}",
        hex::encode(derived_bytes16(
            b"RUNNE_PROVIDER_IDEMPOTENCY_V1\0",
            job.context.command_id.as_bytes(),
        ))
    )
}

fn derived_bytes16(domain: &[u8], input: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(input)
        .finalize();
    digest[..16]
        .try_into()
        .expect("SHA-256 prefix has exact length")
}

pub(super) fn policy_binding_digest(
    activation_identity: [u8; 32],
    profile: &dyn TextProviderProfile,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"RUNNE_PROVIDER_POLICY_BINDING_V1\0")
        .chain_update(activation_identity)
        .chain_update(profile.profile_digest())
        .chain_update(PROVIDER_POLICY_V1_REVISION.to_be_bytes())
        .finalize()
        .into()
}

pub(super) fn derived_identity(label: &str, binding: [u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(b"RUNNE_PROVIDER_POLICY_ID_V1\0")
        .chain_update(label.as_bytes())
        .chain_update(binding)
        .finalize();
    format!("provider-{label}-{}", hex::encode(&digest[..16]))
}

pub(super) const fn map_existing_state(
    state: runne_provider::ProviderRepositoryState,
) -> CanonicalProviderExecutionError {
    match state {
        runne_provider::ProviderRepositoryState::RejectedBeforeEffect => {
            CanonicalProviderExecutionError::RejectedBeforeEffect
        }
        runne_provider::ProviderRepositoryState::Dispatching
        | runne_provider::ProviderRepositoryState::Streaming
        | runne_provider::ProviderRepositoryState::TerminalPendingCommit
        | runne_provider::ProviderRepositoryState::Uncertain => {
            CanonicalProviderExecutionError::Uncertain
        }
        runne_provider::ProviderRepositoryState::Settled => {
            CanonicalProviderExecutionError::Conflict
        }
    }
}

pub(super) const fn map_execution_error(
    error: RuntimeProviderExecutionError,
) -> CanonicalProviderExecutionError {
    match error {
        RuntimeProviderExecutionError::JournalCommitLost
        | RuntimeProviderExecutionError::RecoveryFrozen
        | RuntimeProviderExecutionError::JournalKeyUnavailable
        | RuntimeProviderExecutionError::KeyRetentionUnsupported
        | RuntimeProviderExecutionError::JournalCorrupt
        | RuntimeProviderExecutionError::PersistenceUnavailable
        | RuntimeProviderExecutionError::AdapterStreamUnavailable
        | RuntimeProviderExecutionError::TerminalRejected
        | RuntimeProviderExecutionError::PolicyDenied
        | RuntimeProviderExecutionError::PricingUnavailable
        | RuntimeProviderExecutionError::ApplicationUnavailable
        | RuntimeProviderExecutionError::ApplicationConflict => {
            CanonicalProviderExecutionError::Uncertain
        }
    }
}

pub(super) const fn map_admission_error(
    error: ProviderAdmissionError,
) -> CanonicalProviderExecutionError {
    match error {
        ProviderAdmissionError::PostClaimUncertain => CanonicalProviderExecutionError::Uncertain,
        ProviderAdmissionError::AuthorityConflict => CanonicalProviderExecutionError::Conflict,
        ProviderAdmissionError::RepositoryFailure => CanonicalProviderExecutionError::Unavailable,
        ProviderAdmissionError::PolicyDenied
        | ProviderAdmissionError::CapabilityDenied
        | ProviderAdmissionError::CapabilityExpired
        | ProviderAdmissionError::CapabilityRevoked
        | ProviderAdmissionError::ApprovalDenied
        | ProviderAdmissionError::ApprovalExpired
        | ProviderAdmissionError::ApprovalRevoked
        | ProviderAdmissionError::TokenBudgetDenied
        | ProviderAdmissionError::CostBudgetDenied
        | ProviderAdmissionError::PricingRevisionMismatch
        | ProviderAdmissionError::AuthorityDenied
        | ProviderAdmissionError::InvalidSemanticContext
        | ProviderAdmissionError::TokenReservationMismatch
        | ProviderAdmissionError::CostReservationMismatch
        | ProviderAdmissionError::RenderDigestMismatch
        | ProviderAdmissionError::PermitMismatch
        | ProviderAdmissionError::StaleFencingToken
        | ProviderAdmissionError::PrepareRejected => {
            CanonicalProviderExecutionError::RejectedBeforeEffect
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_errors_preserve_pre_effect_and_post_claim_stages() {
        assert_eq!(
            map_admission_error(ProviderAdmissionError::ApprovalDenied),
            CanonicalProviderExecutionError::RejectedBeforeEffect
        );
        assert_eq!(
            map_admission_error(ProviderAdmissionError::PostClaimUncertain),
            CanonicalProviderExecutionError::Uncertain
        );
        assert_eq!(
            map_admission_error(ProviderAdmissionError::RepositoryFailure),
            CanonicalProviderExecutionError::Unavailable
        );
    }

    #[test]
    fn adapter_stream_and_terminal_application_failures_are_post_effect_uncertain() {
        assert_eq!(
            map_execution_error(RuntimeProviderExecutionError::AdapterStreamUnavailable),
            CanonicalProviderExecutionError::Uncertain
        );
        assert_eq!(
            map_execution_error(RuntimeProviderExecutionError::ApplicationUnavailable),
            CanonicalProviderExecutionError::Uncertain
        );
    }

    #[test]
    fn duplicate_nonterminal_states_require_uncertain_reconciliation() {
        for state in [
            runne_provider::ProviderRepositoryState::Dispatching,
            runne_provider::ProviderRepositoryState::Streaming,
            runne_provider::ProviderRepositoryState::TerminalPendingCommit,
            runne_provider::ProviderRepositoryState::Uncertain,
        ] {
            assert_eq!(
                map_existing_state(state),
                CanonicalProviderExecutionError::Uncertain
            );
        }
    }
}
