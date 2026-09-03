use runne_provider::{
    ClaimedWriterAuthorization, CredentialMaterial, CredentialWriterEffectAuthority, ProviderId,
};

use super::super::errors::BrokerError;
use super::super::{BrokeredLegacySourceDeleteInput, BrokeredMigrateLegacyInput};
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialStore, SecureStoreError,
};

/// Narrow legacy-item capability retained beside the credential-service route.
pub trait BrokeredProviderCredentialLegacySource: Send + Sync {
    /// Reads one exact legacy item after the caller consumed claim authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer identity or artifact changed, the
    /// provider is unsupported, or the legacy item cannot be read safely.
    fn load_exact(
        &self,
        input: &BrokeredMigrateLegacyInput,
    ) -> Result<CredentialMaterial, SecureStoreError>;

    /// Deletes only the legacy source after consuming its separate authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the authorization is not exact, the writer
    /// identity or artifact changed, or the provider-scoped item cannot be
    /// deleted safely.
    fn delete_exact(
        &self,
        effects: &CredentialWriterEffectAuthority,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError>;
}

pub(super) struct NativeProviderCredentialLegacySource<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> NativeProviderCredentialLegacySource<N> {
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> BrokeredProviderCredentialLegacySource for NativeProviderCredentialLegacySource<N>
where
    N: ProviderCredentialStore,
{
    fn load_exact(
        &self,
        input: &BrokeredMigrateLegacyInput,
    ) -> Result<CredentialMaterial, SecureStoreError> {
        self.access.validate_writer_current()?;
        self.access.remeasure()?;
        let material = self
            .native
            .load_provider_credential_source(provider(input.command().provider())?, &self.access)?
            .into_material();
        CredentialMaterial::from_bytes(material.into_bytes())
            .map_err(|_| SecureStoreError::InvalidProviderCredential)
    }

    fn delete_exact(
        &self,
        effects: &CredentialWriterEffectAuthority,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        effects
            .authorize(
                authorization,
                input.command().clone(),
                input.binding(),
                input.channel(),
            )
            .map_err(|_| BrokerError::AccessDenied)?;
        self.access.validate_writer_current()?;
        self.access.remeasure()?;
        self.native
            .delete_provider_credential(provider(input.command().provider())?)
    }
}

fn provider(provider: &ProviderId) -> Result<ProviderCredentialId, SecureStoreError> {
    match provider.as_str() {
        "openai" => Ok(ProviderCredentialId::OpenAi),
        "deepseek" => Ok(ProviderCredentialId::DeepSeek),
        _ => Err(SecureStoreError::UnsupportedSecureStoreBackend),
    }
}
