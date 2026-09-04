use super::readback::LegacyCredentialSourceReadback;
use super::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialReadback,
};
use crate::{
    NativeProviderCredentialStore, ProviderCredentialAccessPolicy, ProviderCredentialStatus,
    SecureStoreError,
};

/// Metadata-only legacy inspection; owns no version mutation or dispatch authority.
pub struct NativeLegacySourceReadback {
    native: NativeProviderCredentialStore,
    access: ProviderCredentialAccessPolicy,
}

impl NativeLegacySourceReadback {
    #[must_use]
    pub fn new(access: ProviderCredentialAccessPolicy) -> Self {
        Self {
            native: NativeProviderCredentialStore::new(),
            access,
        }
    }
}

impl ProviderCredentialReadback for NativeLegacySourceReadback {
    fn readback_exact_version(
        &self,
        _: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn readback_exact_absence(
        &self,
        input: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        if input.version_ref().is_some() {
            return Err(SecureStoreError::UnsupportedSecureStoreBackend);
        }
        match self
            .native
            .legacy_source_status(input.command().provider(), &self.access)?
        {
            ProviderCredentialStatus::Missing => input.observe_service_presence(false),
            ProviderCredentialStatus::Configured => input.observe_service_presence(true),
            ProviderCredentialStatus::Unsupported => {
                Err(SecureStoreError::UnsupportedSecureStoreBackend)
            }
        }
    }
}
