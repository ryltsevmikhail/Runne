use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, WriterIdentityMigrationPhase,
};

/// Closed native-effect target vocabulary for one broker command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialBrokerTarget {
    /// Exact immutable credential version.
    Version(CredentialVersionRef),
    /// Exact immutable destination version for a one-time legacy import.
    LegacyImport(CredentialVersionRef),
    /// The single provider-scoped legacy source location.
    LegacySource,
    /// One exact phase of an identity migration.
    Migration {
        /// Linked durable migration identity.
        migration_id: CredentialOperationId,
        /// Exact native-writer migration phase.
        phase: WriterIdentityMigrationPhase,
    },
}

impl CredentialBrokerTarget {
    /// Returns the version-bearing target when this target has one.
    pub const fn version_ref(&self) -> Option<&CredentialVersionRef> {
        match self {
            Self::Version(reference) | Self::LegacyImport(reference) => Some(reference),
            Self::LegacySource | Self::Migration { .. } => None,
        }
    }
}

/// Canonical non-secret instruction for exactly one native broker effect.
///
/// This type deliberately has no Serde implementation; use
/// [`super::CredentialBrokerCommandCodec`] for its only byte representation.
///
/// ```compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<runne_provider::CredentialBrokerCommand>();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialBrokerCommand {
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    provider: ProviderId,
    action: CredentialOperationAction,
    target: CredentialBrokerTarget,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    migration_binding: Option<CredentialBindingDigest>,
}

impl CredentialBrokerCommand {
    /// Constructs one complete command after closed target and migration checks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        ticket_attempt: CredentialTicketAttempt,
        provider: ProviderId,
        action: CredentialOperationAction,
        target: CredentialBrokerTarget,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        migration_binding: Option<CredentialBindingDigest>,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !target_matches(&provider, action, &target, migration_binding.is_some()) {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            ticket_attempt,
            provider,
            action,
            target,
            expected_lifecycle_revision,
            expected_prior_fence,
            migration_binding,
        })
    }

    /// Returns the exact durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the exact one-shot ticket attempt.
    pub const fn ticket_attempt(&self) -> CredentialTicketAttempt {
        self.ticket_attempt
    }
    /// Returns the intended provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }
    /// Returns the closed native effect action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the exact closed target.
    pub const fn target(&self) -> &CredentialBrokerTarget {
        &self.target
    }
    /// Returns the lifecycle revision expected by the effect.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the provider fence expected by the effect.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the migration binding required by migration actions only.
    pub const fn migration_binding(&self) -> Option<CredentialBindingDigest> {
        self.migration_binding
    }
}

fn target_matches(
    provider: &ProviderId,
    action: CredentialOperationAction,
    target: &CredentialBrokerTarget,
    has_migration_binding: bool,
) -> bool {
    match (action, target) {
        (
            CredentialOperationAction::Pair
            | CredentialOperationAction::Revoke
            | CredentialOperationAction::RetiredVersionCleanup,
            CredentialBrokerTarget::Version(reference),
        ) => reference.provider() == provider && !has_migration_binding,
        (
            CredentialOperationAction::MigrateLegacy,
            CredentialBrokerTarget::LegacyImport(reference),
        ) => reference.provider() == provider && !has_migration_binding,
        (CredentialOperationAction::LegacySourceCleanup, CredentialBrokerTarget::LegacySource) => {
            !has_migration_binding
        }
        (
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialBrokerTarget::Migration {
                phase: WriterIdentityMigrationPhase::OldWriterEffect,
                ..
            },
        )
        | (
            CredentialOperationAction::WriterIdentityMigrationVerify,
            CredentialBrokerTarget::Migration {
                phase: WriterIdentityMigrationPhase::NewWriterVerify,
                ..
            },
        ) => has_migration_binding,
        _ => false,
    }
}
