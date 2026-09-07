use crate::credential::enrollment::CredentialOperationAction;

/// Whether the fixed inherited sealed-secret slot exists for this writer.
///
/// Presence grants no authority and never opens or reads the descriptor. The
/// retained ticket consumes this fact before writing a claim so Pair cannot run
/// without a secret slot and every non-Pair action rejects one.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CredentialSecretInputPresence {
    /// No inherited sealed-secret slot is present.
    Absent,
    /// The inherited sealed-secret slot is present but remains unopened.
    Present,
}

/// Closed command profile accepted by the D1.1a packaged writer.
///
/// This value grants no authority and exposes no ticket or command projection.
/// A later profile must explicitly add its authenticated migration binding
/// contract before writer-identity migration can enter the claim transcript.
#[derive(Clone, Copy)]
pub struct CredentialWriterCommandScopeV1(());

/// Action admitted by the closed D1.1a writer scope.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CredentialWriterCommandKindV1 {
    /// Create one sealed provider credential.
    Pair,
    /// Revoke one credential version.
    Revoke,
    /// Import one credential from the legacy store.
    MigrateLegacy,
    /// Remove one retired credential version.
    RetiredVersionCleanup,
    /// Remove one legacy credential source after migration.
    LegacySourceCleanup,
}

impl CredentialWriterCommandScopeV1 {
    /// Current packaged-writer scope without N-to-N+1 identity migration.
    pub const D1_1A: Self = Self(());

    pub(crate) const fn classify(
        self,
        action: CredentialOperationAction,
    ) -> Option<CredentialWriterCommandKindV1> {
        match action {
            CredentialOperationAction::Pair => Some(CredentialWriterCommandKindV1::Pair),
            CredentialOperationAction::Revoke => Some(CredentialWriterCommandKindV1::Revoke),
            CredentialOperationAction::MigrateLegacy => {
                Some(CredentialWriterCommandKindV1::MigrateLegacy)
            }
            CredentialOperationAction::RetiredVersionCleanup => {
                Some(CredentialWriterCommandKindV1::RetiredVersionCleanup)
            }
            CredentialOperationAction::LegacySourceCleanup => {
                Some(CredentialWriterCommandKindV1::LegacySourceCleanup)
            }
            CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify => None,
        }
    }
}
