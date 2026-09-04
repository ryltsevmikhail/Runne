use runne_provider::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialOperationAction,
};

use super::errors::BrokerError;
use crate::SecureStoreError;

pub struct BrokeredCreateInput(ExactVersionCommand);
pub struct BrokeredDeleteInput(ExactVersionCommand);
pub struct BrokeredMigrateLegacyInput(ExactVersionCommand);
pub struct BrokeredLegacySourceDeleteInput(ExactLegacySourceCommand);

impl BrokeredCreateInput {
    /// Builds an exact create input bound to a pair command.
    ///
    /// # Errors
    ///
    /// Returns access denied when the command has a different action or target shape.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        ExactVersionCommand::new(command, binding, channel, CredentialOperationAction::Pair)
            .map(Self)
    }
}

impl BrokeredDeleteInput {
    /// Builds an exact revoke or retired-version cleanup input.
    ///
    /// # Errors
    ///
    /// Returns access denied when the command has a different action or target shape.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        ExactVersionCommand::new_any(
            command,
            binding,
            channel,
            &[
                CredentialOperationAction::Revoke,
                CredentialOperationAction::RetiredVersionCleanup,
            ],
        )
        .map(Self)
    }
}

impl BrokeredMigrateLegacyInput {
    /// Builds an exact legacy-import input.
    ///
    /// # Errors
    ///
    /// Returns access denied when the command is not a matching legacy import.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        ExactVersionCommand::new_legacy_import(command, binding, channel).map(Self)
    }
}

impl BrokeredLegacySourceDeleteInput {
    /// Builds an exact legacy-source cleanup input.
    ///
    /// # Errors
    ///
    /// Returns access denied when the command is not a legacy-source cleanup.
    pub fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        ExactLegacySourceCommand::new(command, binding, channel).map(Self)
    }
}

macro_rules! exact_command_accessors {
    ($input:ident) => {
        impl $input {
            pub(super) const fn command(&self) -> &CredentialBrokerCommand {
                self.0.command()
            }
            pub(super) const fn binding(&self) -> CredentialBindingDigest {
                self.0.binding()
            }
            pub(super) const fn channel(&self) -> &BrokerChannelBinding {
                self.0.channel()
            }
        }
    };
}

exact_command_accessors!(BrokeredCreateInput);
exact_command_accessors!(BrokeredDeleteInput);
exact_command_accessors!(BrokeredMigrateLegacyInput);
exact_command_accessors!(BrokeredLegacySourceDeleteInput);

struct ExactVersionCommand {
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
}

impl ExactVersionCommand {
    fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
        action: CredentialOperationAction,
    ) -> Result<Self, SecureStoreError> {
        Self::new_any(command, binding, channel, &[action])
    }

    fn new_any(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
        actions: &[CredentialOperationAction],
    ) -> Result<Self, SecureStoreError> {
        matches!(command.target(), CredentialBrokerTarget::Version(reference)
            if reference.provider() == command.provider())
        .then_some(())
        .filter(|()| actions.contains(&command.action()))
        .ok_or(BrokerError::AccessDenied)?;
        Ok(Self {
            command,
            binding,
            channel,
        })
    }

    fn new_legacy_import(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        matches!(command.target(), CredentialBrokerTarget::LegacyImport(reference)
            if command.action() == CredentialOperationAction::MigrateLegacy
                && reference.provider() == command.provider())
        .then_some(())
        .ok_or(BrokerError::AccessDenied)?;
        Ok(Self {
            command,
            binding,
            channel,
        })
    }

    const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }
    const fn binding(&self) -> CredentialBindingDigest {
        self.binding
    }
    const fn channel(&self) -> &BrokerChannelBinding {
        &self.channel
    }
}

struct ExactLegacySourceCommand {
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
}

impl ExactLegacySourceCommand {
    fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: BrokerChannelBinding,
    ) -> Result<Self, SecureStoreError> {
        (command.action() == CredentialOperationAction::LegacySourceCleanup
            && matches!(
                command.target(),
                CredentialBrokerTarget::ExactLegacySource(_)
            ))
        .then_some(())
        .ok_or(BrokerError::AccessDenied)?;
        Ok(Self {
            command,
            binding,
            channel,
        })
    }

    const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }
    const fn binding(&self) -> CredentialBindingDigest {
        self.binding
    }
    const fn channel(&self) -> &BrokerChannelBinding {
        &self.channel
    }
}
