fn remote_credential_projection(
    transaction: &Transaction<'_>,
    binding: &runne_application::provider::ProviderRemoteAttemptBinding,
) -> Result<runne_application::provider::ProviderRemoteCredentialProjection, ProviderExecutionError>
{
    use runne_application::provider::ProviderRemoteCredentialProjection as Projection;
    let realm = runne_provider::ProviderId::new(binding.credential_realm.clone())
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let safe = match crate::provider::credential_safe_snapshot_in_transaction(transaction, &realm) {
        Ok(safe) => safe,
        Err(runne_provider::CredentialLifecycleError::NotFound) => {
            return Ok(Projection::NotConfigured);
        }
        Err(_) => return Err(ProviderExecutionError::StoreUnavailable),
    };
    if safe.provider() != &realm {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    if !safe.configured() {
        return Ok(Projection::NotConfigured);
    }
    Ok(match safe.readiness() {
        runne_provider::CredentialReadinessDisposition::Ready => Projection::Ready,
        runne_provider::CredentialReadinessDisposition::Missing => Projection::Missing,
        runne_provider::CredentialReadinessDisposition::Stale => Projection::Stale,
        runne_provider::CredentialReadinessDisposition::Unavailable => Projection::Unavailable,
        runne_provider::CredentialReadinessDisposition::Unsupported => Projection::Unsupported,
        runne_provider::CredentialReadinessDisposition::AccessDenied => Projection::AccessDenied,
        runne_provider::CredentialReadinessDisposition::Conflict => Projection::Conflict,
        runne_provider::CredentialReadinessDisposition::InvariantFailure => {
            Projection::InvariantFailure
        }
    })
}
