use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget, CredentialFence,
    CredentialLegacyCleanupBinding, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, CredentialTicketAttempt, CredentialVersionRef, ProviderId,
};
use runne_secure_store::{
    ExactAbsenceReadback, NativeLegacySourceReadback, ProviderCredentialAccessPolicy,
    ProviderCredentialReadback,
};

pub(super) fn assert_exact_legacy_source_absent(
    context: &super::support::InnerContext,
) -> Result<(), &'static str> {
    let access = ProviderCredentialAccessPolicy::new(&context.writer(), context.daemon())
        .map_err(|_| "cleanup-readback-access")?;
    let input = ExactAbsenceReadback::new(cleanup_command(context)?)
        .map_err(|_| "cleanup-readback-command")?;
    let observation = NativeLegacySourceReadback::new(access)
        .readback_exact_absence(input)
        .map_err(|_| "cleanup-exact-source-present")?;
    (!observation.present())
        .then_some(())
        .ok_or("cleanup-exact-source-present")
}

fn cleanup_command(
    context: &super::support::InnerContext,
) -> Result<CredentialBrokerCommand, &'static str> {
    type Row = (Vec<u8>, i64, i64, i64, Vec<u8>, i64, i64);
    let row: Row = super::legacy_observations::database(context)?
        .query_row(
            "SELECT import.operation_id, import.expected_lifecycle_revision,
                    import.expected_credential_fence, import.allocated_credential_version,
                    head.legacy_source_binding_digest,
                    cleanup.expected_lifecycle_revision, cleanup.expected_credential_fence
             FROM provider_credential_operations AS import
             JOIN provider_credential_authority_heads AS head ON head.provider_id=import.provider_id
             JOIN provider_credential_operations AS cleanup
                 ON cleanup.operation_id=head.legacy_cleanup_operation_id
             WHERE import.action='MIGRATE_LEGACY' AND import.state='COMPLETED'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(|_| "cleanup-readback-row")?;
    let provider = ProviderId::new("openai").map_err(|_| "cleanup-readback-provider")?;
    let binding = CredentialLegacyCleanupBinding::from_parts(
        operation_id(row.0)?,
        revision(row.1)?,
        fence(row.2)?,
        CredentialVersionRef::new(provider.clone(), positive(row.3)?)
            .map_err(|_| "cleanup-readback-version")?,
        digest(row.4)?,
    );
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes(super::legacy_crash::cleanup_operation_id(context)?)
            .map_err(|_| "cleanup-readback-cleanup-operation")?,
        CredentialTicketAttempt::new(1).map_err(|_| "cleanup-readback-attempt")?,
        provider,
        CredentialOperationAction::LegacySourceCleanup,
        CredentialBrokerTarget::ExactLegacySource(binding),
        revision(row.5)?,
        fence(row.6)?,
        None,
    )
    .map_err(|_| "cleanup-readback-command")
}

fn operation_id(value: Vec<u8>) -> Result<CredentialOperationId, &'static str> {
    CredentialOperationId::from_bytes(
        value
            .as_slice()
            .try_into()
            .map_err(|_| "cleanup-readback-operation")?,
    )
    .map_err(|_| "cleanup-readback-operation")
}

fn digest(value: Vec<u8>) -> Result<CredentialBindingDigest, &'static str> {
    CredentialBindingDigest::from_measured(
        value
            .as_slice()
            .try_into()
            .map_err(|_| "cleanup-readback-digest")?,
    )
    .map_err(|_| "cleanup-readback-digest")
}

fn positive(value: i64) -> Result<u64, &'static str> {
    u64::try_from(value).map_err(|_| "cleanup-readback-positive")
}

fn revision(value: i64) -> Result<CredentialLifecycleRevision, &'static str> {
    CredentialLifecycleRevision::new(positive(value)?).map_err(|_| "cleanup-readback-revision")
}

fn fence(value: i64) -> Result<CredentialFence, &'static str> {
    CredentialFence::new(positive(value)?).map_err(|_| "cleanup-readback-fence")
}
