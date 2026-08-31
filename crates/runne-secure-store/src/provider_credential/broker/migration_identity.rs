use runne_provider::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialOperationAction, CredentialReleaseMigrationBinding, WriterIdentityMigrationPhase,
};

use super::errors::BrokerError;
use crate::SecureStoreError;

pub struct BrokeredWriterIdentityMigrationInput {
    command: CredentialBrokerCommand,
    binding: CredentialReleaseMigrationBinding,
    channel: BrokerChannelBinding,
}

pub struct BrokeredWriterIdentityVerificationInput {
    command: CredentialBrokerCommand,
    binding: CredentialReleaseMigrationBinding,
    channel: BrokerChannelBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterIdentityMigrationObservation {
    binding: CredentialBindingDigest,
}

impl WriterIdentityMigrationObservation {
    pub(super) const fn new(binding: CredentialBindingDigest) -> Self {
        Self { binding }
    }

    #[must_use]
    pub const fn binding(&self) -> CredentialBindingDigest {
        self.binding
    }
}

impl BrokeredWriterIdentityMigrationInput {
    /// Builds an old-writer migration effect input.
    ///
    /// # Errors
    ///
    /// Returns access denied when command and release migration binding differ.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialReleaseMigrationBinding,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        validate(
            &command,
            &binding,
            WriterIdentityMigrationPhase::OldWriterEffect,
        )?;
        Ok(Self {
            command,
            binding,
            channel,
        })
    }

    pub(super) const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    #[allow(clippy::missing_const_for_fn)]
    pub(super) fn binding(&self) -> CredentialBindingDigest {
        self.binding.digest()
    }

    pub(super) const fn channel(&self) -> &BrokerChannelBinding {
        &self.channel
    }
}

impl BrokeredWriterIdentityVerificationInput {
    /// Builds a new-writer verification input.
    ///
    /// # Errors
    ///
    /// Returns access denied when command and release migration binding differ.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialReleaseMigrationBinding,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        validate(
            &command,
            &binding,
            WriterIdentityMigrationPhase::NewWriterVerify,
        )?;
        Ok(Self {
            command,
            binding,
            channel,
        })
    }

    pub(super) const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    #[allow(clippy::missing_const_for_fn)]
    pub(super) fn binding(&self) -> CredentialBindingDigest {
        self.binding.digest()
    }

    pub(super) const fn channel(&self) -> &BrokerChannelBinding {
        &self.channel
    }
}

fn validate(
    command: &CredentialBrokerCommand,
    binding: &CredentialReleaseMigrationBinding,
    phase: WriterIdentityMigrationPhase,
) -> Result<(), SecureStoreError> {
    let action = match phase {
        WriterIdentityMigrationPhase::OldWriterEffect => {
            CredentialOperationAction::WriterIdentityMigrationEffect
        }
        WriterIdentityMigrationPhase::NewWriterVerify => {
            CredentialOperationAction::WriterIdentityMigrationVerify
        }
    };
    let matches_target = matches!(
        command.target(),
        CredentialBrokerTarget::Migration { migration_id, phase: command_phase }
            if *migration_id == binding.migration_id() && *command_phase == phase
    );
    (command.action() == action
        && matches_target
        && command.migration_binding() == Some(binding.digest()))
    .then_some(())
    .ok_or_else(|| BrokerError::AccessDenied.into())
}
