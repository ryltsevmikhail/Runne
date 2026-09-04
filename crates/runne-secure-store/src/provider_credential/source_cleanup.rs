use super::ProviderCredentialSourceRevision;
use super::source_update::{
    ProviderCredentialSourceSlot, ProviderCredentialSourceSlotState,
    ProviderCredentialSourceSlotVersion,
};
use crate::SecureStoreError;

/// Reject misplaced and unfinished records before they become deletion candidates.
#[allow(
    clippy::redundant_pub_crate,
    reason = "internal native validation boundary"
)]
pub(crate) fn validate_slot(
    physical: ProviderCredentialSourceSlot,
    recorded: Option<ProviderCredentialSourceSlotVersion>,
) -> Result<(), SecureStoreError> {
    match recorded {
        None if physical == ProviderCredentialSourceSlot::Primary => Ok(()),
        Some(version)
            if version.slot == physical
                && version.state == ProviderCredentialSourceSlotState::Committed
                && version.generation != 0 =>
        {
            Ok(())
        }
        _ => Err(SecureStoreError::CorruptProviderCredential),
    }
}
use runne_provider::{
    CredentialBrokerCommand, CredentialBrokerTarget, CredentialLegacyCleanupBinding,
    CredentialOperationAction, CredentialTicketAttempt,
};

/// Selects only one exact source after the caller has inventoried and validated all slots.
/// The caller retains the Keychain lock and must delete the returned item reference.
#[allow(
    clippy::redundant_pub_crate,
    reason = "native selector is an internal implementation detail"
)]
pub(crate) fn select<T>(
    binding: &CredentialLegacyCleanupBinding,
    mut candidates: Vec<(ProviderCredentialSourceRevision, T)>,
) -> Result<Option<T>, SecureStoreError> {
    if candidates.len() > 1 {
        return Err(SecureStoreError::ProviderCredentialOperationFailed);
    }
    let Some((revision, item)) = candidates.pop() else {
        return Ok(None);
    };
    let import = CredentialBrokerCommand::new(
        binding.import_operation_id(),
        CredentialTicketAttempt::new(1).map_err(|_| SecureStoreError::CorruptProviderCredential)?,
        binding.destination().provider().clone(),
        CredentialOperationAction::MigrateLegacy,
        CredentialBrokerTarget::LegacyImport(binding.destination().clone()),
        binding.import_lifecycle_revision(),
        binding.import_fence(),
        None,
    )
    .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
    let observed = import
        .legacy_source_observation_digest(*revision.as_bytes())
        .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
    if observed != binding.observation_digest() {
        return Err(SecureStoreError::ProviderCredentialOperationFailed);
    }
    Ok(Some(item))
}
