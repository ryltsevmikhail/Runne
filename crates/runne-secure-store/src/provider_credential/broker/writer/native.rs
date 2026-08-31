use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use runne_provider::{CredentialAuthorityPair, CredentialWriterAuthorityPair};
use runne_provider::{
    CredentialLifecycleAuthority, CredentialLifecycleError, CredentialNativeCreateValidator,
    CredentialVersionRef, CredentialWriterClaimIssuer, ProviderId,
};

#[cfg(any(test, feature = "test-support"))]
use super::BrokeredProviderCredentialWriterAdapter;
use super::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredProviderCredentialWriterNative, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput,
};
#[cfg(any(test, feature = "test-support"))]
use crate::NativeProviderCredentialStore;
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialStore, SecureStoreError,
};

/// Packaged broker writer authority bundle.
///
/// Production construction stays closed until authenticated broker admission
/// supplies this bundle. Once admitted, it yields only the broker claim issuer
/// and writer port; the paired native authority remains in the private adapter.
/// A normal writer-feature consumer cannot restore the former self-minting path
/// from path-derived ACL expectation data:
///
/// ```compile_fail
/// use runne_secure_store::{
///     NativeProviderCredentialWriters, ProviderCredentialAccessPolicy,
/// };
///
/// fn cannot_self_mint_writer_authority(access: ProviderCredentialAccessPolicy) {
///     let writers = NativeProviderCredentialWriters::new(access);
///     let (_issuer, _effect_capable_writer) = writers.into_parts();
/// }
/// ```
#[cfg_attr(
    not(feature = "test-support"),
    doc = r"The test-only factory is absent from the normal writer-feature API too:

```compile_fail
use runne_secure_store::{NativeProviderCredentialWriters, ProviderCredentialAccessPolicy};

fn test_factory_is_not_production_api(access: ProviderCredentialAccessPolicy) {
    let _ = NativeProviderCredentialWriters::new_for_test(access);
}
```"
)]
pub struct NativeProviderCredentialWriters {
    issuer: CredentialWriterClaimIssuer,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
}

impl NativeProviderCredentialWriters {
    /// Constructs one isolated writer/native authority domain for tests only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(access: ProviderCredentialAccessPolicy) -> Self {
        let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
        let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
        let native = NativeProviderCredentialStore::new_versioned(native_authority);
        let writer = NativeBrokeredProviderCredentialWriter::new(lifecycle, native);
        Self {
            issuer,
            writer: Arc::new(BrokeredProviderCredentialWriterAdapter::new(
                effects, writer, access,
            )),
        }
    }

    /// Separates the broker-side issuer from the only mutation capability.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialWriterClaimIssuer,
        Arc<dyn BrokeredProviderCredentialWriter>,
    ) {
        (self.issuer, self.writer)
    }
}

/// Concrete broker writer over the native immutable-version and legacy stores.
pub struct NativeBrokeredProviderCredentialWriter<N> {
    lifecycle: CredentialLifecycleAuthority,
    native: N,
}

impl<N> NativeBrokeredProviderCredentialWriter<N> {
    pub const fn new(lifecycle: CredentialLifecycleAuthority, native: N) -> Self {
        Self { lifecycle, native }
    }
}

impl<N> NativeBrokeredProviderCredentialWriter<N>
where
    N: NativeProviderCredentialVersionStore + ProviderCredentialStore,
{
    fn create_version(
        &self,
        reference: &CredentialVersionRef,
        source_revision: [u8; 16],
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Self::validate_writer(access)?;
        let source = self
            .lifecycle
            .issue_provision_source(source_revision)
            .map_err(map_lifecycle)?;
        let issuer = self
            .lifecycle
            .native_create_issuer()
            .map_err(map_lifecycle)?;
        let claim = issuer
            .issue_native_create(reference.clone(), &source, Arc::new(BrokerAuthorizedCreate))
            .map_err(map_lifecycle)?;
        drop(issuer);
        self.native.create_version(claim, material, access)
    }

    fn validate_writer(access: &ProviderCredentialAccessPolicy) -> Result<(), SecureStoreError> {
        access.validate_writer_current()?;
        access.remeasure()
    }
}

impl<N> BrokeredProviderCredentialWriterNative for NativeBrokeredProviderCredentialWriter<N>
where
    N: NativeProviderCredentialVersionStore + ProviderCredentialStore,
{
    fn preflight_create_exact(
        &self,
        input: &BrokeredCreateInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let _ = version(input.command().target())?;
        Self::validate_writer(access)
    }

    fn create_exact(
        &self,
        input: &BrokeredCreateInput,
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let reference = version(input.command().target())?;
        self.create_version(
            reference,
            input.command().operation_id().as_bytes(),
            material,
            access,
        )
    }

    fn delete_exact(
        &self,
        input: &BrokeredDeleteInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<runne_provider::NativeCredentialDeletionProof, SecureStoreError> {
        Self::validate_writer(access)?;
        let reference = version(input.command().target())?;
        self.native
            .delete_version(self.lifecycle.issue_gc(reference.clone()))
    }

    fn import_legacy_exact(
        &self,
        input: &BrokeredMigrateLegacyInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let reference = version(input.command().target())?;
        let source = self
            .native
            .load_provider_credential_source(provider(input.command().provider())?, access)?;
        self.create_version(
            reference,
            *source.revision().as_bytes(),
            source.material(),
            access,
        )
    }

    fn delete_legacy_source_exact(
        &self,
        input: &BrokeredLegacySourceDeleteInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Self::validate_writer(access)?;
        self.native
            .delete_provider_credential(provider(input.command().provider())?)
    }

    fn migrate_writer_identity_exact(
        &self,
        _input: &BrokeredWriterIdentityMigrationInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn verify_writer_identity_exact(
        &self,
        _input: &BrokeredWriterIdentityVerificationInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

struct BrokerAuthorizedCreate;

impl CredentialNativeCreateValidator for BrokerAuthorizedCreate {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        Ok(())
    }
}

fn version(
    target: &runne_provider::CredentialBrokerTarget,
) -> Result<&CredentialVersionRef, SecureStoreError> {
    target
        .version_ref()
        .ok_or(SecureStoreError::CredentialAccessDenied)
}

fn provider(provider: &ProviderId) -> Result<ProviderCredentialId, SecureStoreError> {
    match provider.as_str() {
        "openai" => Ok(ProviderCredentialId::OpenAi),
        "deepseek" => Ok(ProviderCredentialId::DeepSeek),
        _ => Err(SecureStoreError::UnsupportedSecureStoreBackend),
    }
}

const fn map_lifecycle(error: CredentialLifecycleError) -> SecureStoreError {
    match error {
        CredentialLifecycleError::StaleLease | CredentialLifecycleError::Conflict => {
            SecureStoreError::CredentialAccessDenied
        }
        CredentialLifecycleError::CorruptState => SecureStoreError::CorruptProviderCredential,
        _ => SecureStoreError::ProviderCredentialOperationFailed,
    }
}
