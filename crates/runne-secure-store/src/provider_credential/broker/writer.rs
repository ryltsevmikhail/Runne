use runne_provider::{
    ClaimedWriterAuthorization, NativeCredentialDeletionProof, PendingCredentialSecretOpening,
    SealedCredentialEnvelope,
};

use super::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput, WriterIdentityMigrationObservation,
};
use crate::{ProviderCredentialAccessPolicy, ProviderCredentialMaterial, SecureStoreError};

#[path = "writer/adapter.rs"]
mod adapter;
mod legacy_source;
#[cfg(test)]
mod legacy_source_tests;
mod native;
#[cfg(all(target_os = "macos", feature = "provider-credential-broker-writer"))]
mod native_authenticated;
mod oauth;
pub use legacy_source::BrokeredProviderCredentialLegacySource;
#[cfg(test)]
pub use native::NativeBrokeredProviderCredentialWriter;
pub use native::{NativeProviderCredentialEffectRoute, NativeProviderCredentialWriters};

pub trait BrokeredProviderCredentialWriter: Send + Sync {
    /// Creates one exact immutable version from one sealed Pair relay.
    ///
    /// ```compile_fail
    /// use runne_provider::ClaimedWriterAuthorization;
    /// use runne_secure_store::{
    ///     BrokeredCreateInput, BrokeredProviderCredentialWriter, ProviderCredentialMaterial,
    /// };
    ///
    /// fn plaintext_create_is_not_available(
    ///     writer: &dyn BrokeredProviderCredentialWriter,
    ///     authorization: ClaimedWriterAuthorization,
    ///     input: BrokeredCreateInput,
    ///     material: ProviderCredentialMaterial,
    /// ) {
    ///     let _ = writer.create_exact(authorization, input, &material);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, conflict, or backend error.
    fn create_sealed_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredCreateInput,
        pending: PendingCredentialSecretOpening,
        envelope: SealedCredentialEnvelope,
    ) -> Result<(), SecureStoreError>;
    /// Deletes one exact immutable version after consuming writer authorization.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, conflict, or backend error.
    fn delete_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredDeleteInput,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError>;
    /// Imports the legacy source into one exact immutable version.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, missing, or backend error.
    fn import_legacy_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredMigrateLegacyInput,
    ) -> Result<(), SecureStoreError>;
    /// Deletes only the legacy source after consuming writer authorization.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, or backend error.
    fn delete_legacy_source_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError>;
    /// Applies the release-bound writer identity migration effect.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, conflict, or backend error.
    fn migrate_writer_identity_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredWriterIdentityMigrationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError>;
    /// Verifies the release-bound replacement writer identity.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, validation, or backend error.
    fn verify_writer_identity_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredWriterIdentityVerificationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError>;
}

pub(super) trait BrokeredProviderCredentialWriterNative: Send + Sync {
    fn preflight_create_exact(
        &self,
        input: &BrokeredCreateInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn create_exact(
        &self,
        input: &BrokeredCreateInput,
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn delete_exact(
        &self,
        input: &BrokeredDeleteInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError>;
    fn import_legacy_exact(
        &self,
        input: &BrokeredMigrateLegacyInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn delete_legacy_source_exact(
        &self,
        input: &BrokeredLegacySourceDeleteInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn migrate_writer_identity_exact(
        &self,
        input: &BrokeredWriterIdentityMigrationInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn verify_writer_identity_exact(
        &self,
        input: &BrokeredWriterIdentityVerificationInput,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
}

pub use adapter::BrokeredProviderCredentialWriterAdapter;

#[cfg(test)]
#[path = "writer/pair_tests.rs"]
mod pair_tests;
