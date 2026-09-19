use runne_provider::{
    CredentialEnrollmentStoreAuthority, CredentialVerificationCapability,
    CredentialVerificationKind, CredentialVerificationLease, CredentialVerificationResult,
};

use crate::{
    NativeProviderCredentialStore, NativeProviderCredentialVersionStore,
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, ProviderCredentialStatus,
    SecureStoreError,
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

/// Native boundary for a separately authorized remote verification read.
///
/// Implementations must validate the capability's authority, provider and
/// exact active version before loading any material. The capability is never
/// serialized or replaced by a provider/version string.
pub trait VerificationNativeMaterializer: Send + Sync {
    /// Loads the exact version authorized by `capability`.
    ///
    /// # Errors
    ///
    /// Returns a closed access, stale-capability, missing, or backend error.
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;
}

/// Secure-store adapter that keeps verification capability handling separate
/// from the native backend implementation.
pub struct VerificationMaterializerAdapter<N> {
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> VerificationMaterializerAdapter<N> {
    /// Binds a native verifier to one immutable executable access policy.
    #[must_use]
    pub const fn new(native: N, access: ProviderCredentialAccessPolicy) -> Self {
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
        if capability.lease().kind() != CredentialVerificationKind::Remote
            || capability.lease().active_credential_version().provider()
                != capability.lease().provider()
        {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        self.native
            .materialize_for_verification(capability, &self.access)
    }
}

/// Production reader for a separately issued remote verification capability.
pub struct NativeProviderCredentialVerificationMaterializer {
    native: NativeProviderCredentialStore,
    authority: CredentialEnrollmentStoreAuthority,
    access: ProviderCredentialAccessPolicy,
}

impl NativeProviderCredentialVerificationMaterializer {
    /// Binds the native reader to the enrollment authority that issued leases.
    #[must_use]
    pub fn new(
        authority: CredentialEnrollmentStoreAuthority,
        access: ProviderCredentialAccessPolicy,
    ) -> Self {
        Self {
            native: NativeProviderCredentialStore::new(),
            authority,
            access,
        }
    }
}

impl ProviderCredentialVerificationMaterializer
    for NativeProviderCredentialVerificationMaterializer
{
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        if capability.lease().kind() != CredentialVerificationKind::Remote
            || capability.lease().active_credential_version().provider()
                != capability.lease().provider()
            || !lease_is_current(capability.lease().expires_at_high_water())
            || self
                .authority
                .validate_credential_verification_capability(capability)
                .is_err()
        {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        self.native.load_provider_version_for_verification(
            capability.lease().active_credential_version(),
            &self.access,
        )
    }
}

fn lease_is_current(expires_at: i64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        });
    now < expires_at
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

#[cfg(test)]
#[path = "verification_materializer_tests.rs"]
mod tests;
