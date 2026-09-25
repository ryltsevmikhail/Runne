use runne_provider::{
    AuthorizedCredentialLegacyRead, ClaimedWriterAuthorization, CredentialLegacyReadVerifier,
    CredentialMaterial, CredentialWriterEffectAuthority, ProviderId,
};

use super::super::BrokeredLegacySourceDeleteInput;
use super::super::errors::BrokerError;
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialStore, SecureStoreError,
};

/// Narrow legacy-item capability retained beside the credential-service route.
///
/// ```compile_fail
/// use runne_secure_store::{BrokeredProviderCredentialLegacySource, BrokeredMigrateLegacyInput};
/// fn plain_input_is_not_read_authority(
///     source: &dyn BrokeredProviderCredentialLegacySource,
///     input: &BrokeredMigrateLegacyInput,
/// ) {
///     let _ = source.load_exact(input);
/// }
/// ```
pub trait BrokeredProviderCredentialLegacySource: Send + Sync {
    /// Reads one exact legacy item after the caller consumed claim authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer identity or artifact changed, the
    /// provider is unsupported, or the legacy item cannot be read safely.
    fn load_exact(
        &self,
        read: AuthorizedCredentialLegacyRead,
    ) -> Result<runne_provider::CredentialLegacySourceMaterial, SecureStoreError>;

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
    verifier: CredentialLegacyReadVerifier,
}

impl<N> NativeProviderCredentialLegacySource<N> {
    pub(super) const fn new(
        native: N,
        access: ProviderCredentialAccessPolicy,
        verifier: CredentialLegacyReadVerifier,
    ) -> Self {
        Self {
            native,
            access,
            verifier,
        }
    }
}

impl<N> BrokeredProviderCredentialLegacySource for NativeProviderCredentialLegacySource<N>
where
    N: ProviderCredentialStore + crate::provider_credential::AuthorizedLegacySourceStore,
{
    fn load_exact(
        &self,
        read: AuthorizedCredentialLegacyRead,
    ) -> Result<runne_provider::CredentialLegacySourceMaterial, SecureStoreError> {
        self.verifier
            .validate(&read)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        self.access.validate_writer_current()?;
        self.access.remeasure()?;
        let source = self
            .native
            .load_authorized_legacy_source(read, &self.access)?;
        let revision = *source.revision().as_bytes();
        CredentialMaterial::from_zeroizing(source.into_material().into_zeroizing())
            .and_then(|material| {
                runne_provider::CredentialLegacySourceMaterial::new(material, revision)
            })
            .map_err(|_| SecureStoreError::InvalidProviderCredential)
    }

    fn delete_exact(
        &self,
        effects: &CredentialWriterEffectAuthority,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        self.verifier
            .validate_effect_context(effects, input.binding(), input.channel())
            .map_err(|_| BrokerError::AccessDenied)?;
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
        let runne_provider::CredentialBrokerTarget::ExactLegacySource(binding) =
            input.command().target()
        else {
            return Err(BrokerError::AccessDenied.into());
        };
        self.native.delete_authorized_legacy_source(
            provider(input.command().provider())?,
            binding,
            &self.access,
        )
    }
}

fn provider(provider: &ProviderId) -> Result<ProviderCredentialId, SecureStoreError> {
    ProviderCredentialId::from_account(provider.as_str())
        .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)
}
