use super::*;

pub(super) fn initialize(
    execution_store: &SqliteProviderExecutionStore,
    execution: &RuntimeProviderExecution<
        '_,
        dyn ProviderJournalKeyring,
        super::super::runtime_store::DaemonProviderRuntimeStore,
        SharedTextProviderProfile,
    >,
    keyring: &dyn ProviderJournalKeyring,
    profile: &SharedTextProviderProfile,
    credential_status: ProviderCredentialStatus,
    expected_profile_digest: [u8; 32],
    runtime_authority_id: [u8; 16],
) -> Result<(), DaemonError> {
    match execution_store
        .active_journal_key_binding()
        .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?
    {
        Some(_) => {
            execution
                .preflight_existing_active_key(runtime_authority_id, 1)
                .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
        }
        None => {
            RuntimeProviderExecution::<
                dyn ProviderJournalKeyring,
                super::super::runtime_store::DaemonProviderRuntimeStore,
                SharedTextProviderProfile,
            >::create_and_activate_key(execution, runtime_authority_id, 1, 1)
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
        }
    }
    let binding = execution
        .preflight_existing_active_key(runtime_authority_id, 1)
        .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
    execution_store
        .install_online_effect_proof_capability(keyring, binding)
        .map_err(|_| DaemonError::Bootstrap("provider online effect proof unavailable".into()))?;
    let status = keyring
        .provider_journal_key_status(
            runne_secure_store::ProviderJournalKeyRef::new(
                binding.key_id(),
                binding.key_version(),
                binding.runtime_authority_id(),
                binding.database_generation(),
            )
            .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?,
        )
        .map_err(|_| DaemonError::Bootstrap("provider journal key unavailable".into()))?;
    ProviderReadinessEvidence::for_composition(
        profile,
        super::readiness::CompositionReadinessInputs {
            activation_profile_digest: expected_profile_digest,
            retained_key_backend: keyring.retains_multiple_provider_journal_keys(),
            credential_status,
            journal_binding: binding,
            journal_key_status: status,
            runtime_authority_id,
            database_generation: 1,
        },
    )
    .validate_control_plane()
    .map_err(|error| DaemonError::Bootstrap(error.to_string()))
}
