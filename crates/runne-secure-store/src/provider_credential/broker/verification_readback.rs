use runne_provider::{
    CredentialVerificationCapability, CredentialVerificationKind, CredentialVerificationLease,
    CredentialVerificationResult,
};

use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, ProviderCredentialStatus, SecureStoreError,
};

pub trait ProviderCredentialVerificationMaterializer: Send + Sync {
    /// Materializes only the version named by a current verification capability.
    ///
    /// # Errors
    ///
    /// Returns a closed stale-capability, access, missing, or backend error.
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

// Staged unwired: the canonical verification-effect boundary is composed in a
// later enrollment task; until then no production constructor exists.
#[allow(dead_code)]
pub(super) trait VerificationNativeMaterializer: Send + Sync {
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

#[allow(dead_code)]
pub(super) struct VerificationMaterializerAdapter<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VerificationMaterializerAdapter<N> {
    #[allow(dead_code)]
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialVerificationMaterializer for VerificationMaterializerAdapter<N>
where
    N: VerificationNativeMaterializer,
{
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.native
            .materialize_for_verification(capability, &self.access)
    }
}

/// Metadata-only local verification for one store-issued lease.
///
/// The port deliberately has no API for loading credential material. Its only
/// input names the exact immutable version accepted by the durable lease CAS.
pub trait ProviderCredentialVerificationReadback: Send + Sync {
    /// Verifies native availability without materializing credential material.
    ///
    /// # Errors
    ///
    /// Returns closed access, corruption, or backend failures.
    fn verify_local(
        &self,
        lease: &CredentialVerificationLease,
    ) -> Result<CredentialVerificationResult, SecureStoreError>;
}

pub(super) struct VersionStoreVerificationReadback<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VersionStoreVerificationReadback<N> {
    pub(super) const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
        Self { native, access }
    }
}

impl<N> ProviderCredentialVerificationReadback for VersionStoreVerificationReadback<N>
where
    N: NativeProviderCredentialVersionStore,
{
    fn verify_local(
        &self,
        lease: &CredentialVerificationLease,
    ) -> Result<CredentialVerificationResult, SecureStoreError> {
        if lease.kind() != CredentialVerificationKind::Local {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        match self
            .native
            .version_status(lease.active_credential_version(), &self.access)?
        {
            ProviderCredentialStatus::Configured => Ok(CredentialVerificationResult::Verified),
            ProviderCredentialStatus::Missing => Ok(CredentialVerificationResult::Failed),
            ProviderCredentialStatus::Unsupported => Ok(CredentialVerificationResult::Unsupported),
        }
    }
}
