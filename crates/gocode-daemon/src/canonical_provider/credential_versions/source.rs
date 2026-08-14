trait LegacyCredentialSource {
    fn load_source(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<gocode_secure_store::ProviderCredentialSource, gocode_secure_store::SecureStoreError>;
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
    ) -> Result<gocode_secure_store::ProviderCredentialSource, gocode_secure_store::SecureStoreError>
    {
        self.load_provider_credential_source(provider, access)
    }
}

fn provision_active_from_legacy_source(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &dyn NativeProviderCredentialVersionStore,
    provider: &ProviderId,
    activation: ProvisionActivation,
    legacy: &dyn LegacyCredentialSource,
    access: &ProviderCredentialAccessPolicy,
) -> Result<(), DaemonError> {
    let source = legacy
        .load_source(ProviderCredentialId::OpenAi, access)
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
