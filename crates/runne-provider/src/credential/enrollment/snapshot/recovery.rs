use crate::{CredentialBrokerCommand, CredentialBrokerTarget};

use super::super::{
    CredentialEnrollmentError, CredentialOperationAction, CredentialOperationState,
};
use super::CredentialOperationSnapshot;

/// Recovery work for a non-terminal operation requiring reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecoveryWork {
    operation: CredentialOperationSnapshot,
    command: Option<CredentialBrokerCommand>,
}

impl CredentialRecoveryWork {
    /// Accepts only post-claim operations that may require reconciliation.
    pub fn new(operation: CredentialOperationSnapshot) -> Result<Self, CredentialEnrollmentError> {
        if !matches!(
            operation.state(),
            CredentialOperationState::Claimed
                | CredentialOperationState::NativeEffectObserved
                | CredentialOperationState::ReadbackVerified
        ) {
            return Err(CredentialEnrollmentError::InvalidTransition);
        }
        Ok(Self {
            operation,
            command: None,
        })
    }

    /// Returns the immutable operation snapshot.
    pub const fn operation(&self) -> &CredentialOperationSnapshot {
        &self.operation
    }

    /// Binds the exact non-secret broker command for reconciliation.
    pub fn with_command(
        mut self,
        command: CredentialBrokerCommand,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !recovery_command_matches(&self.operation, &command) {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        self.command = Some(command);
        Ok(self)
    }

    /// Returns the exact broker command when recovery constructed one.
    pub const fn command(&self) -> Option<&CredentialBrokerCommand> {
        self.command.as_ref()
    }
}

fn recovery_command_matches(
    operation: &CredentialOperationSnapshot,
    command: &CredentialBrokerCommand,
) -> bool {
    let target = match operation.action() {
        CredentialOperationAction::Pair
        | CredentialOperationAction::Revoke
        | CredentialOperationAction::RetiredVersionCleanup => operation
            .allocated_credential_version()
            .or(operation.target_credential_version())
            .is_some_and(|value| {
                command.target() == &CredentialBrokerTarget::Version(value.clone())
            }),
        CredentialOperationAction::MigrateLegacy => operation
            .allocated_credential_version()
            .is_some_and(|value| {
                command.target() == &CredentialBrokerTarget::LegacyImport(value.clone())
            }),
        CredentialOperationAction::LegacySourceCleanup => {
            command.target() == &CredentialBrokerTarget::LegacySource
        }
        CredentialOperationAction::WriterIdentityMigrationEffect
        | CredentialOperationAction::WriterIdentityMigrationVerify => {
            operation.metadata().migration().is_some_and(|migration| {
                command.target()
                    == &CredentialBrokerTarget::Migration {
                        migration_id: migration.migration_id(),
                        phase: migration.phase(),
                    }
                    && command.migration_binding() == Some(migration.binding_digest())
            })
        }
    };
    target
        && command.operation_id() == operation.operation_id()
        && command.provider() == operation.provider()
        && command.action() == operation.action()
        && command.expected_lifecycle_revision() == operation.lifecycle_revision()
        && command.expected_prior_fence() == operation.fence()
}
