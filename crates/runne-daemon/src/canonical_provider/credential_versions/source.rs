trait LegacyCredentialSource {
    fn load_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<runne_secure_store::ProviderCredentialSource, runne_secure_store::SecureStoreError>;
}

#[derive(Clone, Copy)]
struct ProvisionActivation {
    owner: [u8; 16],
    fencing_token: u64,
    now: i64,
}

impl LegacyCredentialSource for NativeProviderCredentialStore {
    fn load_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<runne_secure_store::ProviderCredentialSource, runne_secure_store::SecureStoreError>
    {
        self.load_provider_credential_source(provider, access)
    }
}

fn provision_active_from_legacy_source(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    credential_id: ProviderCredentialId,
    activation: ProvisionActivation,
    legacy: &dyn LegacyCredentialSource,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), DaemonError> {
    let source = legacy
        .load_source(credential_id, access)
        .map_err(|_| unavailable())?;
    provision_active_with_material(
        store,
        native,
        provider,
        activation,
        *source.revision().as_bytes(),
        Some((source.material(), access)),
    )
}
