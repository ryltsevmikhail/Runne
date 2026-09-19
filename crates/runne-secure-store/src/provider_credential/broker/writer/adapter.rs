use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialWriterEffectAuthority, NativeCredentialDeletionProof,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
};

use super::super::errors::BrokerError;
use super::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredProviderCredentialWriterNative, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput, WriterIdentityMigrationObservation,
};
use crate::{ProviderCredentialAccessPolicy, ProviderCredentialMaterial, SecureStoreError};

pub struct BrokeredProviderCredentialWriterAdapter<N> {
    effects: CredentialWriterEffectAuthority,
    native: N,
    access: ProviderCredentialAccessPolicy,
}

impl<N> BrokeredProviderCredentialWriterAdapter<N> {
    pub const fn new(
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
                    let material = if matches!(
                        input.command().provider().as_str(),
                        "openai-codex" | "github-copilot"
                    ) {
                        let version = input
                            .command()
                            .target()
                            .version_ref()
                            .ok_or(SecureStoreError::CredentialAccessDenied)?
                            .version();
                        let canonical = super::oauth::canonicalize(
                            input.command().provider().as_str(),
                            version,
                            secret,
                        )?;
                        ProviderCredentialMaterial::new_native_oauth(canonical.to_vec())?
                    } else {
                        ProviderCredentialMaterial::new(secret.to_vec())?
                    };
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
