use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialWriterEffectAuthority, NativeCredentialDeletionProof,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
};

use super::errors::BrokerError;
use super::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput, WriterIdentityMigrationObservation,
};
use crate::{ProviderCredentialAccessPolicy, ProviderCredentialMaterial, SecureStoreError};

mod legacy_source;
#[cfg(test)]
mod legacy_source_tests;
mod native;
#[cfg(all(target_os = "macos", feature = "provider-credential-broker-writer"))]
mod native_authenticated;
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

pub(super) struct BrokeredProviderCredentialWriterAdapter<N> {
    effects: CredentialWriterEffectAuthority,
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> BrokeredProviderCredentialWriterAdapter<N> {
    pub(super) const fn new(
        effects: CredentialWriterEffectAuthority,
        native: N,
        access: ProviderCredentialAccessPolicy,
    ) -> Self {
        Self {
            effects,
            native,
            access,
        }
    }
}

impl<N> BrokeredProviderCredentialWriter for BrokeredProviderCredentialWriterAdapter<N>
where
    N: BrokeredProviderCredentialWriterNative,
{
    fn create_sealed_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredCreateInput,
        pending: PendingCredentialSecretOpening,
        envelope: SealedCredentialEnvelope,
    ) -> Result<(), SecureStoreError> {
        self.native.preflight_create_exact(&input, &self.access)?;
        self.effects
            .authorize_and_consume_sealed_pair(
                authorization,
                input.command().clone(),
                input.binding(),
                input.channel(),
                pending,
                envelope,
                |secret| {
                    let material = ProviderCredentialMaterial::new(secret.to_vec())?;
                    self.native.create_exact(&input, &material, &self.access)
                },
            )
            .map_err(|_| BrokerError::AccessDenied)?
    }

    fn delete_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredDeleteInput,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        authorize(
            &self.effects,
            authorization,
            input.command(),
            input.binding(),
            input.channel(),
        )?;
        self.native.delete_exact(&input, &self.access)
    }

    fn import_legacy_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredMigrateLegacyInput,
    ) -> Result<(), SecureStoreError> {
        authorize(
            &self.effects,
            authorization,
            input.command(),
            input.binding(),
            input.channel(),
        )?;
        self.native.import_legacy_exact(&input, &self.access)
    }

    fn delete_legacy_source_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        authorize(
            &self.effects,
            authorization,
            input.command(),
            input.binding(),
            input.channel(),
        )?;
        self.native.delete_legacy_source_exact(&input, &self.access)
    }

    fn migrate_writer_identity_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredWriterIdentityMigrationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError> {
        authorize(
            &self.effects,
            authorization,
            input.command(),
            input.binding(),
            input.channel(),
        )?;
        self.native
            .migrate_writer_identity_exact(&input, &self.access)?;
        Ok(WriterIdentityMigrationObservation::new(input.binding()))
    }

    fn verify_writer_identity_exact(
        &self,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredWriterIdentityVerificationInput,
    ) -> Result<WriterIdentityMigrationObservation, SecureStoreError> {
        authorize(
            &self.effects,
            authorization,
            input.command(),
            input.binding(),
            input.channel(),
        )?;
        self.native
            .verify_writer_identity_exact(&input, &self.access)?;
        Ok(WriterIdentityMigrationObservation::new(input.binding()))
    }
}

fn authorize(
    effects: &CredentialWriterEffectAuthority,
    authorization: ClaimedWriterAuthorization,
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: &BrokerChannelBinding,
) -> Result<(), SecureStoreError> {
    effects
        .authorize(authorization, command.clone(), binding, channel)
        .map(|_| ())
        .map_err(|_| BrokerError::AccessDenied.into())
}

#[cfg(test)]
#[path = "writer/pair_tests.rs"]
mod pair_tests;
